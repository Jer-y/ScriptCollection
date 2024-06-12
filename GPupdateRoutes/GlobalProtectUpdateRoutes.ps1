#===========================================================
# Script: GlobalProtectUpdateRoutes.ps1
# Description: This script automatically configures the routing table 
#              to ensure specific domains or IP addresses traffic flows 
#              through the VPN or local gateway interface based on user choice.
#
# Author: Jerry He
# Date: 2024-06-12
# Version: 0.2
# 
# Usage: 
#   - Run as Administrator.
#   - Ensure "config.json" with domain and IP details is located in the same directory as the script.
#
# Notes:
#   - This script supports IPv4 and IPv6.
#   - For use with Global Protect VPN (MSFTVPN not supported in this script).
#
# Contact:
#   - Email: jinlh@microsoft.com
# 
#
# Something to note:
# 由于DfM应用了安全规则，只接收来自Corp网络的访问。不得不连接VPN才能访问。而目前VPN没有开启Slit Tunneling，导致所有流量都走VPN，慢得要死。于是就有了这个脚本。
# 请注意，此脚本仅在Windows 11操作系统中完成了测试。且由于不同设备本地环境的特殊性，可能需要根据实际情况进行调整。对特定的环境，不做100%运行保证。
# 此脚本必须在每次连接Global Protect以后运行来修改活动路由（包括断线重连）。为什么不做Persistent Route？如果有人不会删Persistent Route会带来额外的路由问题。保险起见，我决定不做。
#===========================================================

# Function: Get-VpnGateway
# Description: Retrieves the gateway address for the VPN interface (IPv4 and IPv6).
# Parameters:
#   -VpnInterfaceIndex: The interface index of the VPN.
function Get-VpnGateway {
    param (
        [int]$VpnInterfaceIndex
    )

    if ($null -eq $VpnInterfaceIndex) {
        throw "Invalid VpnInterfaceIndex provided"
    }

    $routeIPv4 = $null
    $routeIPv6 = $null

    try {
        $routeIPv4 = Get-NetRoute -InterfaceIndex $VpnInterfaceIndex -DestinationPrefix "0.0.0.0/0" | Where-Object { $_.NextHop -ne "0.0.0.0" } | Select-Object -First 1
    } catch {
        Write-Host "Error retrieving VPN IPv4 route: $_"
    }

    try {
        $routeIPv6 = Get-NetRoute -InterfaceIndex $VpnInterfaceIndex -DestinationPrefix "::/0" | Where-Object { $_.NextHop -ne "::" } | Select-Object -First 1
    } catch {
        Write-Host "Error retrieving VPN IPv6 route: $_"
    }

    if ($routeIPv4 -and $routeIPv4.NextHop) {
        Write-Host "Found VPN IPv4 gateway: $($routeIPv4.NextHop)"
        $defaultGatewayIPv4 = $routeIPv4.NextHop
    } elseif ($routeIPv4 -and $routeIPv4.NextHop -eq "On-link") {
        Write-Host "VPN IPv4 gateway is On-link"
        $defaultGatewayIPv4 = "0.0.0.0"
    } else {
        Write-Host "No VPN IPv4 gateway found."
        $defaultGatewayIPv4 = $null
    }

    if ($routeIPv6 -and $routeIPv6.NextHop) {
        Write-Host "Found VPN IPv6 gateway: $($routeIPv6.NextHop)"
        $defaultGatewayIPv6 = $routeIPv6.NextHop
    } elseif ($routeIPv6 -and $routeIPv6.NextHop -eq "On-link") {
        Write-Host "VPN IPv6 gateway is On-link"
        $defaultGatewayIPv6 = "::"
    } else {
        Write-Host "No VPN IPv6 gateway found."
        $defaultGatewayIPv6 = $null
    }

    return @{ IPv4 = $defaultGatewayIPv4; IPv6 = $defaultGatewayIPv6 }
}

# Function: Read-Configuration
# Description: Reads the configuration file and returns the domains and IPs specified.
function Read-Configuration {
    param (
        [string]$configFilePath
    )

    if (Test-Path $configFilePath -PathType Leaf) {
        $configContent = Get-Content -Path $configFilePath -Raw | ConvertFrom-Json
        return $configContent
    } else {
        Write-Host "Configuration file not found at path: $($configFilePath)" -ForegroundColor Red
        exit 1
    }
}

# Function: Validate-IP
# Description: Validates whether the given IP address is a valid IPv4 or IPv6 address.
# Parameters:
#   -IP: The IP address to validate.
# Returns: True if valid, False otherwise.
function Validate-IP {
    param (
        [string]$IP
    )

    # Use .NET's IPAddress class to validate
    try {
        [void][System.Net.IPAddress]::Parse($IP)
        return $true
    } catch {
        return $false
    }
}

# Function: Get-InterfaceIndexByDescription
# Description: Retrieves the interface index based on a partial match of the interface description.
# Parameters:
#   -description: A partial string to match the interface description.
function Get-InterfaceIndexByDescription {
    param (
        [string]$description
    )

    $interface = Get-NetAdapter | Where-Object { $_.InterfaceDescription -like "*$description*" }
    if ($interface) {
        Write-Host "Found interface '$($interface.Name)' with description containing '$description'. Interface index: $($interface.IfIndex)"
        return $interface.IfIndex
    } else {
        Write-Host "No interface found with description containing '$description'."
        return $null
    }
}

# Function: Get-LocalGateway
# Description: Retrieves the local gateway for the specified interface (IPv4 and IPv6).
# Parameters:
#   -LocalInterfaceIndex: The interface index of the local network.
function Get-LocalGateway {
    param (
        [int]$LocalInterfaceIndex
    )

    if ($null -eq $LocalInterfaceIndex) {
        throw "Invalid LocalInterfaceIndex provided"
    }

    $routeIPv4 = $null
    $routeIPv6 = $null

    try {
        $routeIPv4 = Get-NetRoute -InterfaceIndex $LocalInterfaceIndex -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue | Select-Object -First 1
    } catch {
        Write-Host "Error retrieving local IPv4 route: $_"
    }

    try {
        $routeIPv6 = Get-NetRoute -InterfaceIndex $LocalInterfaceIndex -DestinationPrefix "::/0" -ErrorAction SilentlyContinue | Select-Object -First 1
    } catch {
        Write-Host "Error retrieving local IPv6 route: $_"
    }

    if ($routeIPv4) {
        Write-Host "Found local IPv4 gateway: $($routeIPv4.NextHop)"
        $defaultGatewayIPv4 = $routeIPv4.NextHop
    } else {
        Write-Host "No local IPv4 gateway found."
        $defaultGatewayIPv4 = $null
    }

    if ($routeIPv6) {
        Write-Host "Found local IPv6 gateway: $($routeIPv6.NextHop)"
        $defaultGatewayIPv6 = $routeIPv6.NextHop
    } else {
        Write-Host "No local IPv6 gateway found."
        $defaultGatewayIPv6 = $null
    }

    return @{ IPv4 = $defaultGatewayIPv4; IPv6 = $defaultGatewayIPv6 }
}

# Function: Remove-NetRouteFromActiveStore
# Description: Removes a route from the ActiveStore.
# Parameters:
#   -DestinationPrefix: The destination prefix of the route to remove.
function Remove-NetRouteFromActiveStore {
    param (
        [string]$DestinationPrefix
    )

    # Remove route from ActiveStore
    $routes = Get-NetRoute -DestinationPrefix $DestinationPrefix -PolicyStore ActiveStore -ErrorAction SilentlyContinue
    foreach ($route in $routes) {
        Write-Host "Removing existing route: DestinationPrefix=$DestinationPrefix, InterfaceIndex=$($route.InterfaceIndex)"
        Remove-NetRoute -DestinationPrefix $DestinationPrefix -InterfaceIndex $route.InterfaceIndex -PolicyStore ActiveStore -Confirm:$false
    }
}

# Function: Update-RoutesForInterface
# Description: Updates the routes for a given domain or IP to ensure its traffic goes through either the VPN or local interface.
# Parameters:
#   -Domain: The domain (optional) for which to update the routes.
#   -IP: The IP address (optional) for which to update the routes.
#   -InterfaceIndex: The interface index of the VPN or local network.
#   -NextHop: The next hop gateway (e.g., "0.0.0.0" for VPN or the local gateway address).
function Update-RoutesForInterface {
    param (
        [string]$Domain,
        [string]$IP,
        [int]$InterfaceIndex,
        [string]$NextHop
    )

    if ($Domain) {
        Write-Host "Updating routes for domain: $Domain"

        # Obtain the IP addresses of the domain name for both IPv4 and IPv6
        $addressesIPv4 = [System.Net.Dns]::GetHostAddresses($Domain) | Where-Object { $_.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork } | ForEach-Object { $_.IPAddressToString }
        $addressesIPv6 = [System.Net.Dns]::GetHostAddresses($Domain) | Where-Object { $_.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6 } | ForEach-Object { $_.IPAddressToString }

        Write-Host "$Domain IPv4 addresses: $($addressesIPv4 -join ', ')"
        Write-Host "$Domain IPv6 addresses: $($addressesIPv6 -join ', ')"

        # Configure routing for each IPv4 address
        foreach ($ip in $addressesIPv4) {
            if (Validate-IP $ip) {
                $existingRoute = Get-NetRoute -DestinationPrefix "$ip/32" -InterfaceIndex $InterfaceIndex -ErrorAction SilentlyContinue
                if ($existingRoute) {
                    Write-Host "Route for IP: $ip already exists. Skipping..."
                } else {
                    Write-Host "Adding IPv4 route for IP: $ip via interface index: $InterfaceIndex with next hop: $NextHop"
                    New-NetRoute -DestinationPrefix "$ip/32" -InterfaceIndex $InterfaceIndex -NextHop $NextHop -PolicyStore ActiveStore
                }
            } else {
                Write-Host "Invalid IPv4 address: $ip" -ForegroundColor Red
            }
        }

        # Configure routing for each IPv6 address
        foreach ($ip in $addressesIPv6) {
            if (Validate-IP $ip) {
                $existingRoute = Get-NetRoute -DestinationPrefix "$ip/128" -InterfaceIndex $InterfaceIndex -ErrorAction SilentlyContinue
                if ($existingRoute) {
                    Write-Host "Route for IP: $ip already exists. Skipping..."
                } else {
                    Write-Host "Adding IPv6 route for IP: $ip via interface index: $InterfaceIndex with next hop: $NextHop"
                    New-NetRoute -DestinationPrefix "$ip/128" -InterfaceIndex $InterfaceIndex -NextHop $NextHop -PolicyStore ActiveStore
                }
            } else {
                Write-Host "Invalid IPv6 address: $ip" -ForegroundColor Red
            }
        }
    }

    if ($IP) {
        Write-Host "Updating routes for IP address: $IP"

        if (Validate-IP $IP) {
            if ($IP -match ":") {
                # IPv6 address
                $existingRoute = Get-NetRoute -DestinationPrefix "$IP/128" -InterfaceIndex $InterfaceIndex -ErrorAction SilentlyContinue
                if ($existingRoute) {
                    Write-Host "Route for IP: $IP already exists. Skipping..."
                } else {
                    Write-Host "Adding IPv6 route for IP: $IP via interface index: $InterfaceIndex with next hop: $NextHop"
                    New-NetRoute -DestinationPrefix "$IP/128" -InterfaceIndex $InterfaceIndex -NextHop $NextHop -PolicyStore ActiveStore
                }
            } else {
                # IPv4 address
                $existingRoute = Get-NetRoute -DestinationPrefix "$IP/32" -InterfaceIndex $InterfaceIndex -ErrorAction SilentlyContinue
                if ($existingRoute) {
                    Write-Host "Route for IP: $IP already exists. Skipping..."
                } else {
                    Write-Host "Adding IPv4 route for IP: $IP via interface index: $InterfaceIndex with next hop: $NextHop"
                    New-NetRoute -DestinationPrefix "$IP/32" -InterfaceIndex $InterfaceIndex -NextHop $NextHop -PolicyStore ActiveStore
                }
            }
        } else {
            Write-Host "Invalid IP address: $IP" -ForegroundColor Red
        }
    }
}

# Function: Update-DefaultRoute
# Description: Updates the default route to ensure local traffic goes through the local gateway or VPN gateway based on user choice.
# Parameters:
#   -VpnInterfaceIndex: The interface index of the VPN.
#   -LocalGatewayIPv4: The local network IPv4 gateway.
#   -LocalGatewayIPv6: The local network IPv6 gateway.
#   -LocalInterfaceIndex: The interface index of the local network.
#   -UseVpnAsDefault: Boolean flag to indicate if VPN should be used as the default route.
function Update-DefaultRoute {
    param (
        [int]$VpnInterfaceIndex,
        [string]$LocalGatewayIPv4,
        [string]$LocalGatewayIPv6,
        [int]$LocalInterfaceIndex,
        [bool]$UseVpnAsDefault
    )

    $routeType = ""
    if ($UseVpnAsDefault) {
        $routeType = "VPN"
        # Dynamically get VPN gateways
        $vpnGateways = Get-VpnGateway -VpnInterfaceIndex $VpnInterfaceIndex
        $defaultGatewayIPv4 = $vpnGateways.IPv4
        $defaultGatewayIPv6 = $vpnGateways.IPv6
        $defaultInterfaceIndex = $VpnInterfaceIndex
    } else {
        $routeType = "local"
        $defaultGatewayIPv4 = $LocalGatewayIPv4
        $defaultGatewayIPv6 = $LocalGatewayIPv6
        $defaultInterfaceIndex = $LocalInterfaceIndex
    }

    Write-Host "Updating default route to ensure all other traffic goes through $routeType gateway."

    # Set the IPv4 default route
    if ($defaultGatewayIPv4) {
        # Remove existing conflicting routes
        $defaultRoutesIPv4 = Get-NetRoute -DestinationPrefix "0.0.0.0/0" -PolicyStore ActiveStore -ErrorAction SilentlyContinue
        foreach ($route in $defaultRoutesIPv4) {
            if ($route.InterfaceIndex -ne $defaultInterfaceIndex) {
                Write-Host "Removing conflicting IPv4 default route: InterfaceIndex=$($route.InterfaceIndex)"
                Remove-NetRoute -DestinationPrefix "0.0.0.0/0" -InterfaceIndex $route.InterfaceIndex -PolicyStore ActiveStore -Confirm:$false
            }
        }

        # Add the appropriate default route
        $existingRouteIPv4 = Get-NetRoute -DestinationPrefix "0.0.0.0/0" -PolicyStore ActiveStore | Where-Object { $_.InterfaceIndex -eq $defaultInterfaceIndex }
        if ($null -eq $existingRouteIPv4) {
            Write-Host "Adding IPv4 default route via $routeType gateway."
            New-NetRoute -DestinationPrefix "0.0.0.0/0" -InterfaceIndex $defaultInterfaceIndex -NextHop $defaultGatewayIPv4 -PolicyStore ActiveStore
        } else {
            Write-Host "IPv4 default route via $routeType gateway already exists."
        }
    }

    # Set the IPv6 default route
    if ($defaultGatewayIPv6) {
        # Remove existing conflicting routes
        $defaultRoutesIPv6 = Get-NetRoute -DestinationPrefix "::/0" -PolicyStore ActiveStore -ErrorAction SilentlyContinue
        foreach ($route in $defaultRoutesIPv6) {
            if ($route.InterfaceIndex -ne $defaultInterfaceIndex) {
                Write-Host "Removing conflicting IPv6 default route: InterfaceIndex=$($route.InterfaceIndex)"
                Remove-NetRoute -DestinationPrefix "::/0" -InterfaceIndex $route.InterfaceIndex -PolicyStore ActiveStore -Confirm:$false
            }
        }

        # Add the appropriate default route
        $existingRouteIPv6 = Get-NetRoute -DestinationPrefix "::/0" -PolicyStore ActiveStore | Where-Object { $_.InterfaceIndex -eq $defaultInterfaceIndex }
        if ($null -eq $existingRouteIPv6) {
            Write-Host "Adding IPv6 default route via $routeType gateway."
            New-NetRoute -DestinationPrefix "::/0" -InterfaceIndex $defaultInterfaceIndex -NextHop $defaultGatewayIPv6 -PolicyStore ActiveStore
        } else {
            Write-Host "IPv6 default route via $routeType gateway already exists."
        }
    }
}

# Function: Restart-LocalInterface
# Description: Restarts the specified local network interface.
# Parameters:
#   -LocalInterfaceIndex: The interface index of the local network.
function Restart-LocalInterface {
    param (
        [int]$LocalInterfaceIndex
    )

    $interface = Get-NetAdapter -InterfaceIndex $LocalInterfaceIndex
    if ($interface) {
        Write-Host "Disabling network interface: $($interface.Name)"
        Disable-NetAdapter -Name $interface.Name -Confirm:$false -PassThru | Out-Null

        Start-Sleep -Seconds 5  # Pause for a few seconds before re-enabling

        Write-Host "Enabling network interface: $($interface.Name)"
        Enable-NetAdapter -Name $interface.Name -Confirm:$false -PassThru | Out-Null

        Write-Host "Network interface $($interface.Name) restarted successfully." -ForegroundColor Green
    } else {
        Write-Host "No network interface found with index $LocalInterfaceIndex." -ForegroundColor Red
    }
}

# Function: Restart-LocalNetworkAdapter
# Description: Restarts the local network adapter.
# Parameters:
#   -InterfaceName: The name of the local network adapter.
function Restart-LocalNetworkAdapter {
    param (
        [string]$InterfaceName
    )

    Write-Host "Restarting local network adapter: $InterfaceName"

    try {
        Disable-NetAdapter -Name $InterfaceName -Confirm:$false -ErrorAction Stop
        Start-Sleep -Seconds 3
        Enable-NetAdapter -Name $InterfaceName -Confirm:$false -ErrorAction Stop
        Write-Host "Successfully restarted the local network adapter: $InterfaceName"
    } catch {
        Write-Host "Error restarting the local network adapter: $InterfaceName. $_" -ForegroundColor Red
        throw $_
    }
}


# Main script

Write-Host "Starting configuration of routes..." -ForegroundColor Green

# Start recording detailed logs
Start-Transcript -Path "$PSScriptRoot\DebugLog.txt" -Append

$configFilePath = Join-Path -Path $PSScriptRoot -ChildPath "config.json"
$config = Read-Configuration -configFilePath $configFilePath

# Provide functional options to users
Write-Host "Choose the mode:"
Write-Host "1. <Major Local>The domain name or IP specified in the config file goes through VPN, other traffic goes locally."
Write-Host "2. <Major VPN>The domain name or IP specified in the config file goes through local, other traffic goes through VPN."
Write-Host "3. Restart the local network adapter to reset the routing."
$choice = Read-Host "Enter your choice (1, 2, or 3)"

if ($choice -eq "3") {
    $localInterface = Get-NetAdapter | Where-Object { $_.Status -eq "Up" -and $_.InterfaceDescription -notlike "*Virtual*" -and $_.InterfaceDescription -notlike "*VPN*" } | Select-Object -First 1
    $localInterfaceName = $localInterface.Name
    Write-Host "You chose to restart the local network adapter: $localInterfaceName. This action will disconnect your network temporarily."
    $confirmation = Read-Host "Are you sure you want to continue? (yes/no)"
    if ($confirmation -eq "yes" -or $confirmation -eq "y") {
        Restart-LocalNetworkAdapter -InterfaceName $localInterfaceName
    } else {
        Write-Host "Operation canceled by user." -ForegroundColor Yellow
    }
    Write-Host "Operation completed successfully." -ForegroundColor Green
    Stop-Transcript
    exit 0
}

# The following section is only executed when the user selects 1 or 2.
$vpnInterfaceIndex = Get-InterfaceIndexByDescription -description "Virtual Ethernet"
$localInterface = Get-NetAdapter | Where-Object { $_.Status -eq "Up" -and $_.InterfaceDescription -notlike "*Virtual*" -and $_.InterfaceDescription -notlike "*VPN*" } | Select-Object -First 1
$localInterfaceIndex = $localInterface.IfIndex
$localGateways = Get-LocalGateway -LocalInterfaceIndex $localInterfaceIndex
$localGatewayIPv4 = $localGateways.IPv4
$localGatewayIPv6 = $localGateways.IPv6

if (-not $vpnInterfaceIndex -or -not $localInterfaceIndex -or (-not $localGatewayIPv4 -and -not $localGatewayIPv6)) {
    Write-Host "Failed to dynamically obtain necessary network interface or gateway information." -ForegroundColor Red
    Stop-Transcript
    exit 1
}

if ($choice -eq "1") {
    foreach ($domain in $config.domains) {
        Update-RoutesForInterface -Domain $domain -InterfaceIndex $vpnInterfaceIndex -NextHop "0.0.0.0"
    }
    if ($config.ips.Count -gt 0) {
        foreach ($ip in $config.ips) {
            Update-RoutesForInterface -IP $ip -InterfaceIndex $vpnInterfaceIndex -NextHop "0.0.0.0"
        }
    } else {
        Write-Host "No specific IPs to update via VPN."
    }
    Update-DefaultRoute -VpnInterfaceIndex $vpnInterfaceIndex -LocalGatewayIPv4 $localGatewayIPv4 -LocalGatewayIPv6 $localGatewayIPv6 -LocalInterfaceIndex $localInterfaceIndex -UseVpnAsDefault $false
} elseif ($choice -eq "2") {
    foreach ($domain in $config.domains) {
        Update-RoutesForInterface -Domain $domain -InterfaceIndex $localInterfaceIndex -NextHop $localGatewayIPv4
    }
    if ($config.ips.Count -gt 0) {
        foreach ($ip in $config.ips) {
            Update-RoutesForInterface -IP $ip -InterfaceIndex $localInterfaceIndex -NextHop $localGatewayIPv4
            if ($ip -match ":") {
                Update-RoutesForInterface -IP $ip -InterfaceIndex $localInterfaceIndex -NextHop $localGatewayIPv6
            }
        }
    } else {
        Write-Host "No specific IPs to update via local interface."
    }
    Update-DefaultRoute -VpnInterfaceIndex $vpnInterfaceIndex -LocalGatewayIPv4 $localGatewayIPv4 -LocalGatewayIPv6 $localGatewayIPv6 -LocalInterfaceIndex $localInterfaceIndex -UseVpnAsDefault $true
} else {
    Write-Host "Invalid choice. Exiting..." -ForegroundColor Red
    Stop-Transcript
    exit 1
}

Write-Host "Operation completed successfully." -ForegroundColor Green

# Stop logging
Stop-Transcript