# GlobalProtectUpdateRoutes.ps1
This PowerShell script automatically configures the routing table to ensure specific domains or IP addresses traffic flows through the VPN or local gateway interface based on user choice.

## Features
- Supports specifying domains and IP addresses through an external configuration file.
- Allows user to choose routing mode:
  1. Specific domains/IPs via VPN, all other traffic via local interface.
  2. Specific domains/IPs via local interface, all other traffic via VPN.
- Supports both IPv4 and IPv6.
- Removes routes from ActiveStore to ensure temporary routing updates.

## Requirements
- Windows 11
- Global Protect VPN (MSFTVPN not supported)
- PowerShell running with Administrator privileges

## Installation
1. **Download the script and configuration file**:
   - `GlobalProtectUpdateRoutes.ps1`
   - `config.json`

2. **Place both files in the same directory**.

## Configuration
Create a `config.json` file in the same directory as the script with the following format:

```json
{
    "domains": [
        "azwfm21pr*****.microsoft.com",
        "api.****.microsoft.com",
        "onesu****.dynamics.com"
    ],
    "ips": [
        "52.114.145.56",
        "2001:4860:4860::8888"
    ]
}
```
- `domains`: A list of domains to be routed.
- `ips`: A list of IP addresses to be routed.

## Usage
1. **Open PowerShell as Administrator**:
   - Search for "PowerShell" in the Start menu.
   - Right-click on "Windows PowerShell" and select "Run as administrator".

2. **Navigate to the directory containing the script and configuration file**:
   ```powershell
   cd path\to\your\script
   ```

3. **Run the script**:
   ```powershell
   .\GlobalProtectUpdateRoutes.ps1
   ```

4. **When prompted, choose the routing mode**:
   - `(1) The domain name or IP specified in the config file goes through VPN, other traffic goes locally.`
   - `(2) The domain name or IP specified in the config file goes through local, other traffic goes through VPN.`
   - `(3) Restart the local network adapter to reset the routing.`
## Notes
- This script must be run after connecting to the VPN.
- All routes added by this script will be removed after disconnecting from the VPN or rebooting.
- The script only updates the ActiveStore and avoids persistent routes to prevent issues on route deletion.

## Contact
- **Author**: Jerry He
- **Date**: 2024-06-12
- **Version**: 1.0

---
**Disclaimer**: Use this script at your own risk. Ensure you understand and test in a controlled environment before deploying in production.
