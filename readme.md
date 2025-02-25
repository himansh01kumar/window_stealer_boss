# window_stealer_boss

## Overview
This tool is designed for forensic analysis of system and browser data. It extracts relevant forensic artifacts such as browser credentials, system information, WiFi passwords, and remote desktop connections for investigative purposes.

## Features
- Extracts browser credentials (URLs, usernames, encrypted passwords) from Chromium-based browsers.
- Retrieves system information such as OS details, installed software, network interfaces, and disk partitions.
- Extracts saved WiFi credentials from Windows.
- Gathers RDP connection history.
- Dumps Windows credential manager data.
- Extracts BitLocker recovery keys (if available).
- Collects Discord authentication tokens (for investigative purposes).
- Stores extracted data securely in a structured format.

## Requirements
- Windows OS (Tested on Windows 10/11)
- Python 3.x
- Required Libraries:
  ```bash
  pip install pyzipper pycryptodome pypiwin32 psutil
  ```

## Usage
1. **Run the script**:
   ```bash
   python forensic_tool.py
   ```
2. **Extracted Data Location:**
   - All extracted data is stored in the `Extracted_Data` folder.
   - Data is compressed into a password-protected ZIP file (`Extracted_Data.zip`).

## Ethical & Legal Considerations
- This tool is intended for forensic investigations only.
- Unauthorized use on systems without explicit permission may violate laws.
- Ensure you have proper authorization before running this tool.

## Notes
- The tool does NOT modify or erase system logs to ensure forensic integrity.
- Some functionalities require administrative privileges.

## Disclaimer
This tool is for **educational and forensic research** purposes only. The developer is not responsible for misuse.

"# window_stealer_boss" 
