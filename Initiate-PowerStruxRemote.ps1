param (
    [Parameter(Mandatory = $false)]
    [string]$ComputerName = "localhost",
    [Parameter(Mandatory = $false)]
    [string]$ExePath = "C:\Program Files\WindowsPowerShell\Modules\ReportHTML\Initiate-PowerStruxWA.exe",
    [Parameter(Mandatory = $false)]
    $GlobalConfig
)

# Deploy-PowerStruxConfig function: Handles the deployment of the configuration file to the target machine.
Function Deploy-PowerStruxConfig {
    param (
        [Parameter(Mandatory = $true)]
        $ComputerName,
        [Parameter(Mandatory = $true)]
        $ConfigFile
    )
    
    # Ensure that the configuration file is named 'PowerStruxWAConfig.txt'
    if ((Split-Path -Leaf $ConfigFile) -ne "PowerStruxWAConfig.txt") {
    
        Write-Error "The configuration file must be named 'PowerStruxWAConfig.txt'."
        return
    
    }
    
    # Check if the target computer is local or remote.
    $installPath = if ($boolIsLocalHost -eq $TRUE) {
    
        # Define the installation path for the local computer.
        "C:\Program Files\WindowsPowerShell\Modules\ReportHTML"
    
    }
    else {
         
        # Define the installation path for the remote computer.
        "\\$ComputerName\c$\Program Files\WindowsPowerShell\Modules\ReportHTML"
    
    }

    # Check if the installation path exists.
    if (Test-Path -Path $installPath) {
    
        Write-Host "Copying $ConfigFile to $installPath."
    
        try {
    
            # Attempt to copy the config file to the target installation path.
            Copy-Item -Path $ConfigFile -Destination $installPath -Force -ErrorAction Stop
    
        }
        catch {
    
            Write-Error $_
            return
    
        }
    
        # Construct the full path to the copied config file.
        $configFilePath = Join-Path $installPath 'PowerStruxWAConfig.txt'
    
        Write-Host "Confirming that $ConfigFile was successfully copied to $installPath."
            
        # Check if the file was copied successfully.
        if (Test-Path -Path $configFilePath) {
    
            Write-Host "$ConfigFile was successfully copied to $installPath!"
            Write-Host ""
    
        }
        else {
    
            Write-Error "The configuration file was not copied correctly."
            return
    
        }
    
    }
    else {
    
        Write-Error "The script was not able to access $installPath."
        return
    
    }
    
}

# Checks if the remote system is online and WinRM is running
function Test-RemoteConnectivity {
    param ([string]$Target)

    # Ping the target
    if (-not (Test-Connection -ComputerName $Target -Count 1 -Quiet -ErrorAction SilentlyContinue)) {
        Write-Warning "Host [$Target] is unreachable."
        return $false
    }

    try {
        # Check WinRM service
        $winrmService = Get-Service -ComputerName $Target -Name WinRM -ErrorAction Stop
        if ($winrmService.Status -ne 'Running') {
            Write-Host "WinRM is not running on [$Target]. Attempting to start..."
            Start-Service -InputObject $winrmService -ErrorAction Stop
            Start-Sleep -Seconds 3
        }

        $status = (Get-Service -ComputerName $Target -Name WinRM).Status
        if ($status -ne 'Running') {
            Write-Warning "WinRM failed to start on [$Target]."
            return $false
        }
    }
    catch {
        Write-Warning "Could not query or start WinRM on [$Target]: $_"
        return $false
    }

    return $true
}



# === Main Execution Block ===

# Check if a global configuration file ($GlobalConfig) is provided.
if ($GlobalConfig) {

    try {

        # Attempt to deploy the configuration file to the target computer.
        Deploy-PowerStruxConfig -ComputerName $ComputerName -ConfigFile $GlobalConfig -ErrorAction Stop


    }
    catch {

        Write-Host "One or more errors occurred while deploying $GlobalConfig to $ComputerName`: $_"
        return

    }

}


#Create an array that contains the target Computer Name, IP Addresses, and localhost.
Write-Host "Gathering local host information..."
$arrIsLocalHost = @()
$arrIsLocalHost += Get-NetIPAddress | Select-Object -ExpandProperty IPAddress
$arrIsLocalHost += $env:COMPUTERNAME
$arrIsLocalHost += "localhost"

# Determine if the target computer is local or remote
Write-Host "Checking if '$ComputerName' is local or remote..."
$boolIsLocalHost = $arrIsLocalHost.Contains($ComputerName)

if ($boolIsLocalHost -eq $true) {

    Write-Host "'$ComputerName' is the local machine. Launching application locally..."
    try {

        & $ExePath
        Write-Host "Process started successfully."

    }
    catch {

        Write-Error "Failed to start process locally: $_"
        return

    }

}
else {

    Write-Host "'$ComputerName' is a remote machine. Running pre-checks..."
    try {

        if (-not (Test-RemoteConnectivity -Target $ComputerName)) {

            Write-Warning "Remote pre-checks failed. Aborting."
            return

        }

    }
    catch {

        Write-Error "Error during Test-RemoteConnectivity check: $_"
        return

    }

    $configPath = "\\$ComputerName\c$\Program Files\WindowsPowerShell\Modules\ReportHTML\PowerStruxWAConfig.txt"
    Write-Host "Attempting to read configuration from: $configPath"

    try {

        $originalConfig = Get-Content -Path $configPath -ErrorAction Stop
        Write-Host "Configuration read successfully."

    }
    catch {

        Write-Error "Failed to read configuration file: $_"
        return

    }

    if ($originalConfig | Select-String '=\s*"\\\\[^"]+"') {

        Write-Host "UNC paths detected in config. Modifying paths..."
        try {

            $configValues = Invoke-Command -ComputerName $ComputerName -ScriptBlock {

                Write-Host "Processing configuration file on remote system..."
                $importConfig = Get-Content 'C:\Program Files\WindowsPowerShell\Modules\ReportHTML\PowerStruxWAConfig.txt' | ConvertFrom-StringData

                try {

                    $reportLocation = Invoke-Expression $importConfig.ReportLocation
                
                }
                catch {

                    $reportLocation = $importConfig.ReportLocation
                
                }

                try {

                    $reportName = Invoke-Expression $importConfig.ReportName
                
                }
                catch {

                    $reportName = $importConfig.ReportName
                
                }

                $clearLogSecurity = $importConfig.ClearLogSecurity

                $clearLogBackupPathSecurity = ($importConfig.ClearLogBackupPathSecurity).Replace('"', "")

                try {

                    $clearLogBackupFileNameSecurity = Invoke-Expression $importConfig.ClearLogBackupFileNameSecurity
                
                }
                catch {

                    $clearLogBackupFileNameSecurity = $importConfig.ClearLogBackupFileNameSecurity
                
                }

                $clearLogApplication = $importConfig.ClearLogApplication

                $clearLogBackupPathApplication = ($importConfig.ClearLogBackupPathApplication).Replace('"', "")

                try {

                    $clearLogBackupFileNameApplication = Invoke-Expression $importConfig.ClearLogBackupFileNameApplication
                
                }
                catch {

                    $clearLogBackupFileNameApplication = $importConfig.ClearLogBackupFileNameApplication
                
                }

                $clearLogSystem = $importConfig.ClearLogSystem
                
                $clearLogBackupPathSystem = ($importConfig.ClearLogBackupPathSystem).Replace('"', "")
                
                try {
                    
                    $clearLogBackupFileNameSystem = Invoke-Expression $importConfig.ClearLogBackupFileNameSystem
                
                }
                catch {
                   
                    $clearLogBackupFileNameSystem = $importConfig.ClearLogBackupFileNameSystem

                }

                $clearLogPrint = $importConfig.ClearLogPrint
                
                $clearLogBackupPathPrint = ($importConfig.ClearLogBackupPathPrint).Replace('"', "")
                
                try {
                
                    $clearLogBackupFileNamePrint = Invoke-Expression $importConfig.ClearLogBackupFileNamePrint
                
                }
                catch {
                
                    $clearLogBackupFileNamePrint = $importConfig.ClearLogBackupFileNamePrint
                
                }

                [PSCustomObject]@{
                    ReportLocation                    = $reportLocation
                    ReportName                        = $reportName
                    ClearLogSecurity                  = $clearLogSecurity
                    ClearLogBackupPathSecurity        = $clearLogBackupPathSecurity
                    ClearLogBackupFileNameSecurity    = $clearLogBackupFileNameSecurity
                    ClearLogApplication               = $clearLogApplication
                    ClearLogBackupPathApplication     = $clearLogBackupPathApplication
                    ClearLogBackupFileNameApplication = $clearLogBackupFileNameApplication
                    ClearLogSystem                    = $clearLogSystem
                    ClearLogBackupPathSystem          = $clearLogBackupPathSystem
                    ClearLogBackupFileNameSystem      = $clearLogBackupFileNameSystem
                    ClearLogPrint                     = $clearLogPrint
                    ClearLogBackupPathPrint           = $clearLogBackupPathPrint
                    ClearLogBackupFileNamePrint       = $clearLogBackupFileNamePrint
                
                }
            } -ErrorAction Stop
        
        }
        catch {

            Write-Error "Failed to retrieve config values from remote host: $_"
            return
        
        }

        try {
            $modifiedConfig = $originalConfig | ForEach-Object {

                if ($_ -match '=\s*"\\\\[^"]+"') {

                    Write-Host "Replacing UNC path in setting: $_"
                    $_ -replace '=\s*"\\\\[^"]+"', '= "C:\\Program Files\\WindowsPowerShell\\Modules\\ReportHTML"'
                
                }
                else {

                    $_
                
                }
            
            }

            Write-Host "Saving modified configuration to: $configPath"
            $modifiedConfig | Set-Content -Path $configPath -ErrorAction Stop

        }
        catch {

            Write-Error "Failed to modify or write the configuration file: $_"
            return
        
        }

        try {

            Write-Host "Invoking remote execution of PowerStruxWA..."
            Invoke-Command -ComputerName $ComputerName -ScriptBlock {
                param($ExePath)

                Write-Host "Starting process on remote computer..."
                & $ExePath

            } -ArgumentList $ExePath -ErrorAction Stop
            
            Write-Host "Remote process started successfully."
        
        }
        catch {

            Write-Error "Failed to start remote process: $_"
            return
        
        }

        try {

            Write-Host "Restoring original configuration..."
            $originalConfig | Set-Content -Path $configPath -ErrorAction Stop
        
        }
        catch {

            Write-Error "Failed to restore original configuration: $_"
            return
        
        }

        Write-Host "Moving generated reports and log backups if UNC paths were used..."
        try {

            switch ($configValues) {

                { $_.ReportLocation -match '^\\\\' } {

                    Write-Host "Moving report to: $($_.ReportLocation)"
                    Move-Item -Path "\\$ComputerName\c$\Program Files\WindowsPowerShell\Modules\ReportHTML\$($_.ReportName).html" -Destination $_.ReportLocation -Force -ErrorAction Stop
                
                }
                { $_.ClearLogBackupPathSecurity -match '^\\\\' -and $_.ClearLogSecurity -eq 1 } {

                    Write-Host "Moving Security log backup to: $($_.ClearLogBackupPathSecurity)"
                    Move-Item -Path "\\$ComputerName\c$\Program Files\WindowsPowerShell\Modules\ReportHTML\$($_.ClearLogBackupFileNameSecurity)" -Destination $_.ClearLogBackupPathSecurity -Force -ErrorAction Stop
                
                }
                { $_.ClearLogBackupPathApplication -match '^\\\\' -and $_.ClearLogApplication -eq 1 } {

                    Write-Host "Moving Application log backup to: $($_.ClearLogBackupPathApplication)"
                    Move-Item -Path "\\$ComputerName\c$\Program Files\WindowsPowerShell\Modules\ReportHTML\$($_.ClearLogBackupFileNameApplication)" -Destination $_.ClearLogBackupPathApplication -Force -ErrorAction Stop
                
                }
                { $_.ClearLogBackupPathSystem -match '^\\\\' -and $_.ClearLogSystem -eq 1 } {

                    Write-Host "Moving System log backup to: $($_.ClearLogBackupPathSystem)"
                    Move-Item -Path "\\$ComputerName\c$\Program Files\WindowsPowerShell\Modules\ReportHTML\$($_.ClearLogBackupFileNameSystem)" -Destination $_.ClearLogBackupPathSystem -Force -ErrorAction Stop
                
                }
                { $_.ClearLogBackupPathPrint -match '^\\\\' -and $_.ClearLogPrint -eq 1 } {
                    
                    Write-Host "Moving Print log backup to: $($_.ClearLogBackupPathPrint)"
                    Move-Item -Path "\\$ComputerName\c$\Program Files\WindowsPowerShell\Modules\ReportHTML\$($_.ClearLogBackupFileNamePrint)" -Destination $_.ClearLogBackupPathPrint -Force -ErrorAction Stop
                
                }
            
            }
        }
        catch {
            Write-Error "One or more file moves failed: $_"
            return
        }
    }
    else {

        Write-Host "No UNC paths found. Launching PowerStruxWA remotely..."
        try {

            Invoke-Command -ComputerName $ComputerName -ScriptBlock {
                param($ExePath)

                Write-Host "Starting process on remote machine..."
                & $ExePath

            } -ArgumentList $ExePath -ErrorAction Stop
            Write-Host "Remote process started successfully."

        }
        catch {

            Write-Error "Failed to start remote process: $_"
            return

        }
    }
}
# SIG # Begin signature block
# MIIoZwYJKoZIhvcNAQcCoIIoWDCCKFQCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCD1+qQC+WRNMQe8
# 6zhM+kAfoYfHLj9bPTU7OlW4xkmliaCCDZwwggawMIIEmKADAgECAhAIrUCyYNKc
# TJ9ezam9k67ZMA0GCSqGSIb3DQEBDAUAMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQK
# EwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNV
# BAMTGERpZ2lDZXJ0IFRydXN0ZWQgUm9vdCBHNDAeFw0yMTA0MjkwMDAwMDBaFw0z
# NjA0MjgyMzU5NTlaMGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwg
# SW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBDb2RlIFNpZ25pbmcg
# UlNBNDA5NiBTSEEzODQgMjAyMSBDQTEwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAw
# ggIKAoICAQDVtC9C0CiteLdd1TlZG7GIQvUzjOs9gZdwxbvEhSYwn6SOaNhc9es0
# JAfhS0/TeEP0F9ce2vnS1WcaUk8OoVf8iJnBkcyBAz5NcCRks43iCH00fUyAVxJr
# Q5qZ8sU7H/Lvy0daE6ZMswEgJfMQ04uy+wjwiuCdCcBlp/qYgEk1hz1RGeiQIXhF
# LqGfLOEYwhrMxe6TSXBCMo/7xuoc82VokaJNTIIRSFJo3hC9FFdd6BgTZcV/sk+F
# LEikVoQ11vkunKoAFdE3/hoGlMJ8yOobMubKwvSnowMOdKWvObarYBLj6Na59zHh
# 3K3kGKDYwSNHR7OhD26jq22YBoMbt2pnLdK9RBqSEIGPsDsJ18ebMlrC/2pgVItJ
# wZPt4bRc4G/rJvmM1bL5OBDm6s6R9b7T+2+TYTRcvJNFKIM2KmYoX7BzzosmJQay
# g9Rc9hUZTO1i4F4z8ujo7AqnsAMrkbI2eb73rQgedaZlzLvjSFDzd5Ea/ttQokbI
# YViY9XwCFjyDKK05huzUtw1T0PhH5nUwjewwk3YUpltLXXRhTT8SkXbev1jLchAp
# QfDVxW0mdmgRQRNYmtwmKwH0iU1Z23jPgUo+QEdfyYFQc4UQIyFZYIpkVMHMIRro
# OBl8ZhzNeDhFMJlP/2NPTLuqDQhTQXxYPUez+rbsjDIJAsxsPAxWEQIDAQABo4IB
# WTCCAVUwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQUaDfg67Y7+F8Rhvv+
# YXsIiGX0TkIwHwYDVR0jBBgwFoAU7NfjgtJxXWRM3y5nP+e6mK4cD08wDgYDVR0P
# AQH/BAQDAgGGMBMGA1UdJQQMMAoGCCsGAQUFBwMDMHcGCCsGAQUFBwEBBGswaTAk
# BggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMEEGCCsGAQUFBzAC
# hjVodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkUm9v
# dEc0LmNydDBDBgNVHR8EPDA6MDigNqA0hjJodHRwOi8vY3JsMy5kaWdpY2VydC5j
# b20vRGlnaUNlcnRUcnVzdGVkUm9vdEc0LmNybDAcBgNVHSAEFTATMAcGBWeBDAED
# MAgGBmeBDAEEATANBgkqhkiG9w0BAQwFAAOCAgEAOiNEPY0Idu6PvDqZ01bgAhql
# +Eg08yy25nRm95RysQDKr2wwJxMSnpBEn0v9nqN8JtU3vDpdSG2V1T9J9Ce7FoFF
# UP2cvbaF4HZ+N3HLIvdaqpDP9ZNq4+sg0dVQeYiaiorBtr2hSBh+3NiAGhEZGM1h
# mYFW9snjdufE5BtfQ/g+lP92OT2e1JnPSt0o618moZVYSNUa/tcnP/2Q0XaG3Ryw
# YFzzDaju4ImhvTnhOE7abrs2nfvlIVNaw8rpavGiPttDuDPITzgUkpn13c5Ubdld
# AhQfQDN8A+KVssIhdXNSy0bYxDQcoqVLjc1vdjcshT8azibpGL6QB7BDf5WIIIJw
# 8MzK7/0pNVwfiThV9zeKiwmhywvpMRr/LhlcOXHhvpynCgbWJme3kuZOX956rEnP
# LqR0kq3bPKSchh/jwVYbKyP/j7XqiHtwa+aguv06P0WmxOgWkVKLQcBIhEuWTatE
# QOON8BUozu3xGFYHKi8QxAwIZDwzj64ojDzLj4gLDb879M4ee47vtevLt/B3E+bn
# KD+sEq6lLyJsQfmCXBVmzGwOysWGw/YmMwwHS6DTBwJqakAwSEs0qFEgu60bhQji
# WQ1tygVQK+pKHJ6l/aCnHwZ05/LWUpD9r4VIIflXO7ScA+2GRfS0YW6/aOImYIbq
# yK+p/pQd52MbOoZWeE4wggbkMIIEzKADAgECAhAK+QKGTe+/MPpscRiU2yndMA0G
# CSqGSIb3DQEBCwUAMGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwg
# SW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBDb2RlIFNpZ25pbmcg
# UlNBNDA5NiBTSEEzODQgMjAyMSBDQTEwHhcNMjQwODE1MDAwMDAwWhcNMjcwODMw
# MjM1OTU5WjBsMQswCQYDVQQGEwJVUzEVMBMGA1UECBMMUGVubnN5bHZhbmlhMRIw
# EAYDVQQHEwlMYW5jYXN0ZXIxGDAWBgNVBAoTD1NlY3VyZVN0cnV4IExMQzEYMBYG
# A1UEAxMPU2VjdXJlU3RydXggTExDMIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIB
# igKCAYEA4b6Y2BiEX7bdOCFVTQsZogfL0ueF+uYRW8LeVVKPAhUYigg80C+Mopsh
# 9/DIsSYzwEHH/lcvWfRfGJtlEKGKBdDP3gdLbEjgBxrzQbbxycO1SUQaLioHeLA1
# r3E6Nw2fiDwJ7ImxIMG4iwsoo8DbaR22oTi8nH0vEmyXawnGOz5gg9YOoXYtxgmN
# 614JIaOAzjKyZhdSs5NvwOhmT/XWkP4v76l4GuZbCZ0mLBT02iV2ZPjJVzDRSRW+
# 7II0cvp8n/92ZLqVsoi70qENLsmMF7mT3Sp6dHPLlil6o5oU80YrHcxSp8HJkzGe
# ghToTeOAoHjBK2HET+w6ALpJYUrpz1ZK94LTDMiqKMdYRD9z/qq3RnClO2nASBjq
# l1DmxkvrxWiT2kFvGu4maHiwTsxIuRx2EVCgu5Ju6znOAysYEOMZTBEtMSn+GYtK
# qpTiJfmZvGhKEad7tQI0fM4KE0eFeMUbkbiQxmSB8Cm4vgPNFeRkCDzOAH3KlwpH
# b3LANW6jAgMBAAGjggIDMIIB/zAfBgNVHSMEGDAWgBRoN+Drtjv4XxGG+/5hewiI
# ZfROQjAdBgNVHQ4EFgQUJ0oFI6IcLSL2vRvWctc1Q1nqLi4wPgYDVR0gBDcwNTAz
# BgZngQwBBAEwKTAnBggrBgEFBQcCARYbaHR0cDovL3d3dy5kaWdpY2VydC5jb20v
# Q1BTMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDAzCBtQYDVR0f
# BIGtMIGqMFOgUaBPhk1odHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRU
# cnVzdGVkRzRDb2RlU2lnbmluZ1JTQTQwOTZTSEEzODQyMDIxQ0ExLmNybDBToFGg
# T4ZNaHR0cDovL2NybDQuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZEc0Q29k
# ZVNpZ25pbmdSU0E0MDk2U0hBMzg0MjAyMUNBMS5jcmwwgZQGCCsGAQUFBwEBBIGH
# MIGEMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wXAYIKwYB
# BQUHMAKGUGh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0
# ZWRHNENvZGVTaWduaW5nUlNBNDA5NlNIQTM4NDIwMjFDQTEuY3J0MAkGA1UdEwQC
# MAAwDQYJKoZIhvcNAQELBQADggIBALO0iBY6A5vb6JoZRFapFP59aqGkKqTq3J5L
# nwbqb+4xbhUt1oWVaDP7OeMg5uIEavu5JLFhPj3kAQHC5hCc/WED9qPKs+9j5IJT
# n2JMMiNVwc3rtEaKDw+ZU1Pi1nhDqUIIapmFJ1f/DWgj7HXmliyxj7/sgaKzRCLK
# xk5HCA2L4QwQrrVGh8SP0B5J41hEcjAk7TTJmq3+8fha6V/AEvf3jTw0efiq/+3J
# VR+1vsGL2ujEZUMZ/R/V78X93NM3iCJzzW2a6GeqzZh8iClMbuO+mAir68tHdFhF
# j0MwdjlQK+UdkkI+mcjUrrUtqAU3xuafNfyuV+l2WpVi0giajcm1Is4Cpf1u6Pb9
# UzJfIo3/ygKNLiMKfwP4Nm1fW7gwZte+cdjk1erhsQtm9X4TP01ZUD0MVj2cnmK8
# 1lanxnb8J1csheUk9QoMdvDllz1icaIKiwCiQZBGq+5XpUCZqnmpiBrekcPpwGyB
# O82HrNzb0GhsYbcK5jZ98ataad7XJw2tE49LUJAGiv2SP0kYvGzoTJ4zpkEy7Ks/
# EbYAEtRz+o9QmzO3p8kw6MJW7sK28pTUaqXWmYiXz5jMxK+Pz37+Bv+DG8bn942Q
# 4I6pXPpmA/tpBwQrdNhlHvc2eusFQ4F7muO4FioafeH8NXUgvBUjj3i6cR3HZwQV
# Ef4lQCufMYIaITCCGh0CAQEwfTBpMQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGln
# aUNlcnQsIEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0IFRydXN0ZWQgRzQgQ29kZSBT
# aWduaW5nIFJTQTQwOTYgU0hBMzg0IDIwMjEgQ0ExAhAK+QKGTe+/MPpscRiU2ynd
# MA0GCWCGSAFlAwQCAQUAoHwwEAYKKwYBBAGCNwIBDDECMAAwGQYJKoZIhvcNAQkD
# MQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJ
# KoZIhvcNAQkEMSIEIKZpAARSuK7y+AC7maBZu72qBY09KDBSLjiRN61CEIlXMA0G
# CSqGSIb3DQEBAQUABIIBgIB2C90YeoVjlqkBwEMOazaxWu2utMCRU0H2l0Y1CeSF
# g+ug2FtQuP7RzY4lBQpsN61nJPu0XV1OV/mJw2G8bTu4hs3M5LOx1+HDosqt+P7n
# ztoZ99UfWVmu4rcpcxHbSF/g4JLxp+U2uNqeELeXmxM7BhoWDVxLxWhmZxpcM4pf
# HcwNug1GU0noL2xiWcfSIwmt2N3Msmr8hOe3xArAfjHAGS2sJD50kbBDG6er/QhX
# 3XrHd4RIO8c9BMYnbx7DzFOLUOuht76ubznFAtGrtp0/LZYBGtfBVDtx0lCWKO/X
# 47nTQQYbIcCqFz7/IR0tvGEShtfwr8Bi+X4/iFM/ekckpg3FDZNLvIXARL77tGPE
# MDIiXktOjF/k4BZ6F28mTQ256N1QkuvFW1eLiPEb6vOsV/AcsWJwthadrZ/0/2Bl
# YnTAIE8rcQIGScxJjBxQGmLHPLxdu93VOIk400O5dBno9EGVA8d0y3d8B+rf8aNm
# wXZNfxKCmxtZK7OOHduikKGCF3cwghdzBgorBgEEAYI3AwMBMYIXYzCCF18GCSqG
# SIb3DQEHAqCCF1AwghdMAgEDMQ8wDQYJYIZIAWUDBAIBBQAweAYLKoZIhvcNAQkQ
# AQSgaQRnMGUCAQEGCWCGSAGG/WwHATAxMA0GCWCGSAFlAwQCAQUABCCkAr5XzUiI
# wzCDdki3vnbUClKxNg/HrP7OGDDnlO5omwIRAIfMwBBzPNREBxTC6Qi1bmoYDzIw
# MjUwNjE5MTMzNzU2WqCCEzowggbtMIIE1aADAgECAhAKgO8YS43xBYLRxHanlXRo
# MA0GCSqGSIb3DQEBCwUAMGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2Vy
# dCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBp
# bmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBDQTEwHhcNMjUwNjA0MDAwMDAwWhcNMzYw
# OTAzMjM1OTU5WjBjMQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIElu
# Yy4xOzA5BgNVBAMTMkRpZ2lDZXJ0IFNIQTI1NiBSU0E0MDk2IFRpbWVzdGFtcCBS
# ZXNwb25kZXIgMjAyNSAxMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA
# 0EasLRLGntDqrmBWsytXum9R/4ZwCgHfyjfMGUIwYzKomd8U1nH7C8Dr0cVMF3Bs
# fAFI54um8+dnxk36+jx0Tb+k+87H9WPxNyFPJIDZHhAqlUPt281mHrBbZHqRK71E
# m3/hCGC5KyyneqiZ7syvFXJ9A72wzHpkBaMUNg7MOLxI6E9RaUueHTQKWXymOtRw
# JXcrcTTPPT2V1D/+cFllESviH8YjoPFvZSjKs3SKO1QNUdFd2adw44wDcKgH+JRJ
# E5Qg0NP3yiSyi5MxgU6cehGHr7zou1znOM8odbkqoK+lJ25LCHBSai25CFyD23DZ
# gPfDrJJJK77epTwMP6eKA0kWa3osAe8fcpK40uhktzUd/Yk0xUvhDU6lvJukx7jp
# hx40DQt82yepyekl4i0r8OEps/FNO4ahfvAk12hE5FVs9HVVWcO5J4dVmVzix4A7
# 7p3awLbr89A90/nWGjXMGn7FQhmSlIUDy9Z2hSgctaepZTd0ILIUbWuhKuAeNIeW
# rzHKYueMJtItnj2Q+aTyLLKLM0MheP/9w6CtjuuVHJOVoIJ/DtpJRE7Ce7vMRHoR
# on4CWIvuiNN1Lk9Y+xZ66lazs2kKFSTnnkrT3pXWETTJkhd76CIDBbTRofOsNyEh
# zZtCGmnQigpFHti58CSmvEyJcAlDVcKacJ+A9/z7eacCAwEAAaOCAZUwggGRMAwG
# A1UdEwEB/wQCMAAwHQYDVR0OBBYEFOQ7/PIx7f391/ORcWMZUEPPYYzoMB8GA1Ud
# IwQYMBaAFO9vU0rp5AZ8esrikFb2L9RJ7MtOMA4GA1UdDwEB/wQEAwIHgDAWBgNV
# HSUBAf8EDDAKBggrBgEFBQcDCDCBlQYIKwYBBQUHAQEEgYgwgYUwJAYIKwYBBQUH
# MAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBdBggrBgEFBQcwAoZRaHR0cDov
# L2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZEc0VGltZVN0YW1w
# aW5nUlNBNDA5NlNIQTI1NjIwMjVDQTEuY3J0MF8GA1UdHwRYMFYwVKBSoFCGTmh0
# dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRHNFRpbWVTdGFt
# cGluZ1JTQTQwOTZTSEEyNTYyMDI1Q0ExLmNybDAgBgNVHSAEGTAXMAgGBmeBDAEE
# AjALBglghkgBhv1sBwEwDQYJKoZIhvcNAQELBQADggIBAGUqrfEcJwS5rmBB7NEI
# RJ5jQHIh+OT2Ik/bNYulCrVvhREafBYF0RkP2AGr181o2YWPoSHz9iZEN/FPsLST
# wVQWo2H62yGBvg7ouCODwrx6ULj6hYKqdT8wv2UV+Kbz/3ImZlJ7YXwBD9R0oU62
# PtgxOao872bOySCILdBghQ/ZLcdC8cbUUO75ZSpbh1oipOhcUT8lD8QAGB9lctZT
# TOJM3pHfKBAEcxQFoHlt2s9sXoxFizTeHihsQyfFg5fxUFEp7W42fNBVN4ueLace
# Rf9Cq9ec1v5iQMWTFQa0xNqItH3CPFTG7aEQJmmrJTV3Qhtfparz+BW60OiMEgV5
# GWoBy4RVPRwqxv7Mk0Sy4QHs7v9y69NBqycz0BZwhB9WOfOu/CIJnzkQTwtSSpGG
# hLdjnQ4eBpjtP+XB3pQCtv4E5UCSDag6+iX8MmB10nfldPF9SVD7weCC3yXZi/uu
# hqdwkgVxuiMFzGVFwYbQsiGnoa9F5AaAyBjFBtXVLcKtapnMG3VH3EmAp/jsJ3FV
# F3+d1SVDTmjFjLbNFZUWMXuZyvgLfgyPehwJVxwC+UpX2MSey2ueIu9THFVkT+um
# 1vshETaWyQo8gmBto/m3acaP9QsuLj3FNwFlTxq25+T4QwX9xa6ILs84ZPvmpovq
# 90K8eWyG2N01c4IhSOxqt81nMIIGtDCCBJygAwIBAgIQDcesVwX/IZkuQEMiDDpJ
# hjANBgkqhkiG9w0BAQsFADBiMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNl
# cnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSEwHwYDVQQDExhEaWdp
# Q2VydCBUcnVzdGVkIFJvb3QgRzQwHhcNMjUwNTA3MDAwMDAwWhcNMzgwMTE0MjM1
# OTU5WjBpMQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xQTA/
# BgNVBAMTOERpZ2lDZXJ0IFRydXN0ZWQgRzQgVGltZVN0YW1waW5nIFJTQTQwOTYg
# U0hBMjU2IDIwMjUgQ0ExMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA
# tHgx0wqYQXK+PEbAHKx126NGaHS0URedTa2NDZS1mZaDLFTtQ2oRjzUXMmxCqvkb
# sDpz4aH+qbxeLho8I6jY3xL1IusLopuW2qftJYJaDNs1+JH7Z+QdSKWM06qchUP+
# AbdJgMQB3h2DZ0Mal5kYp77jYMVQXSZH++0trj6Ao+xh/AS7sQRuQL37QXbDhAkt
# VJMQbzIBHYJBYgzWIjk8eDrYhXDEpKk7RdoX0M980EpLtlrNyHw0Xm+nt5pnYJU3
# Gmq6bNMI1I7Gb5IBZK4ivbVCiZv7PNBYqHEpNVWC2ZQ8BbfnFRQVESYOszFI2Wv8
# 2wnJRfN20VRS3hpLgIR4hjzL0hpoYGk81coWJ+KdPvMvaB0WkE/2qHxJ0ucS638Z
# xqU14lDnki7CcoKCz6eum5A19WZQHkqUJfdkDjHkccpL6uoG8pbF0LJAQQZxst7V
# vwDDjAmSFTUms+wV/FbWBqi7fTJnjq3hj0XbQcd8hjj/q8d6ylgxCZSKi17yVp2N
# L+cnT6Toy+rN+nM8M7LnLqCrO2JP3oW//1sfuZDKiDEb1AQ8es9Xr/u6bDTnYCTK
# IsDq1BtmXUqEG1NqzJKS4kOmxkYp2WyODi7vQTCBZtVFJfVZ3j7OgWmnhFr4yUoz
# ZtqgPrHRVHhGNKlYzyjlroPxul+bgIspzOwbtmsgY1MCAwEAAaOCAV0wggFZMBIG
# A1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYEFO9vU0rp5AZ8esrikFb2L9RJ7MtO
# MB8GA1UdIwQYMBaAFOzX44LScV1kTN8uZz/nupiuHA9PMA4GA1UdDwEB/wQEAwIB
# hjATBgNVHSUEDDAKBggrBgEFBQcDCDB3BggrBgEFBQcBAQRrMGkwJAYIKwYBBQUH
# MAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBBBggrBgEFBQcwAoY1aHR0cDov
# L2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZFJvb3RHNC5jcnQw
# QwYDVR0fBDwwOjA4oDagNIYyaHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lD
# ZXJ0VHJ1c3RlZFJvb3RHNC5jcmwwIAYDVR0gBBkwFzAIBgZngQwBBAIwCwYJYIZI
# AYb9bAcBMA0GCSqGSIb3DQEBCwUAA4ICAQAXzvsWgBz+Bz0RdnEwvb4LyLU0pn/N
# 0IfFiBowf0/Dm1wGc/Do7oVMY2mhXZXjDNJQa8j00DNqhCT3t+s8G0iP5kvN2n7J
# d2E4/iEIUBO41P5F448rSYJ59Ib61eoalhnd6ywFLerycvZTAz40y8S4F3/a+Z1j
# EMK/DMm/axFSgoR8n6c3nuZB9BfBwAQYK9FHaoq2e26MHvVY9gCDA/JYsq7pGdog
# P8HRtrYfctSLANEBfHU16r3J05qX3kId+ZOczgj5kjatVB+NdADVZKON/gnZruMv
# NYY2o1f4MXRJDMdTSlOLh0HCn2cQLwQCqjFbqrXuvTPSegOOzr4EWj7PtspIHBld
# NE2K9i697cvaiIo2p61Ed2p8xMJb82Yosn0z4y25xUbI7GIN/TpVfHIqQ6Ku/qjT
# Y6hc3hsXMrS+U0yy+GWqAXam4ToWd2UQ1KYT70kZjE4YtL8Pbzg0c1ugMZyZZd/B
# dHLiRu7hAWE6bTEm4XYRkA6Tl4KSFLFk43esaUeqGkH/wyW4N7OigizwJWeukcyI
# PbAvjSabnf7+Pu0VrFgoiovRDiyx3zEdmcif/sYQsfch28bZeUz2rtY/9TCA6TD8
# dC3JE3rYkrhLULy7Dc90G6e8BlqmyIjlgp2+VqsS9/wQD7yFylIz0scmbKvFoW2j
# NrbM1pD2T7m3XDCCBY0wggR1oAMCAQICEA6bGI750C3n79tQ4ghAGFowDQYJKoZI
# hvcNAQEMBQAwZTELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZ
# MBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTEkMCIGA1UEAxMbRGlnaUNlcnQgQXNz
# dXJlZCBJRCBSb290IENBMB4XDTIyMDgwMTAwMDAwMFoXDTMxMTEwOTIzNTk1OVow
# YjELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQ
# d3d3LmRpZ2ljZXJ0LmNvbTEhMB8GA1UEAxMYRGlnaUNlcnQgVHJ1c3RlZCBSb290
# IEc0MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAv+aQc2jeu+RdSjww
# IjBpM+zCpyUuySE98orYWcLhKac9WKt2ms2uexuEDcQwH/MbpDgW61bGl20dq7J5
# 8soR0uRf1gU8Ug9SH8aeFaV+vp+pVxZZVXKvaJNwwrK6dZlqczKU0RBEEC7fgvMH
# hOZ0O21x4i0MG+4g1ckgHWMpLc7sXk7Ik/ghYZs06wXGXuxbGrzryc/NrDRAX7F6
# Zu53yEioZldXn1RYjgwrt0+nMNlW7sp7XeOtyU9e5TXnMcvak17cjo+A2raRmECQ
# ecN4x7axxLVqGDgDEI3Y1DekLgV9iPWCPhCRcKtVgkEy19sEcypukQF8IUzUvK4b
# A3VdeGbZOjFEmjNAvwjXWkmkwuapoGfdpCe8oU85tRFYF/ckXEaPZPfBaYh2mHY9
# WV1CdoeJl2l6SPDgohIbZpp0yt5LHucOY67m1O+SkjqePdwA5EUlibaaRBkrfsCU
# tNJhbesz2cXfSwQAzH0clcOP9yGyshG3u3/y1YxwLEFgqrFjGESVGnZifvaAsPvo
# ZKYz0YkH4b235kOkGLimdwHhD5QMIR2yVCkliWzlDlJRR3S+Jqy2QXXeeqxfjT/J
# vNNBERJb5RBQ6zHFynIWIgnffEx1P2PsIV/EIFFrb7GrhotPwtZFX50g/KEexcCP
# orF+CiaZ9eRpL5gdLfXZqbId5RsCAwEAAaOCATowggE2MA8GA1UdEwEB/wQFMAMB
# Af8wHQYDVR0OBBYEFOzX44LScV1kTN8uZz/nupiuHA9PMB8GA1UdIwQYMBaAFEXr
# oq/0ksuCMS1Ri6enIZ3zbcgPMA4GA1UdDwEB/wQEAwIBhjB5BggrBgEFBQcBAQRt
# MGswJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBDBggrBgEF
# BQcwAoY3aHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0QXNzdXJl
# ZElEUm9vdENBLmNydDBFBgNVHR8EPjA8MDqgOKA2hjRodHRwOi8vY3JsMy5kaWdp
# Y2VydC5jb20vRGlnaUNlcnRBc3N1cmVkSURSb290Q0EuY3JsMBEGA1UdIAQKMAgw
# BgYEVR0gADANBgkqhkiG9w0BAQwFAAOCAQEAcKC/Q1xV5zhfoKN0Gz22Ftf3v1cH
# vZqsoYcs7IVeqRq7IviHGmlUIu2kiHdtvRoU9BNKei8ttzjv9P+Aufih9/Jy3iS8
# UgPITtAq3votVs/59PesMHqai7Je1M/RQ0SbQyHrlnKhSLSZy51PpwYDE3cnRNTn
# f+hZqPC/Lwum6fI0POz3A8eHqNJMQBk1RmppVLC4oVaO7KTVPeix3P0c2PR3WlxU
# jG/voVA9/HYJaISfb8rbII01YBwCA8sgsKxYoA5AY8WYIsGyWfVVa88nq2x2zm8j
# LfR+cWojayL/ErhULSd+2DrZ8LaHlv1b0VysGMNNn3O3AamfV6peKOK5lDGCA3ww
# ggN4AgEBMH0waTELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMu
# MUEwPwYDVQQDEzhEaWdpQ2VydCBUcnVzdGVkIEc0IFRpbWVTdGFtcGluZyBSU0E0
# MDk2IFNIQTI1NiAyMDI1IENBMQIQCoDvGEuN8QWC0cR2p5V0aDANBglghkgBZQME
# AgEFAKCB0TAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQAQQwHAYJKoZIhvcNAQkF
# MQ8XDTI1MDYxOTEzMzc1NlowKwYLKoZIhvcNAQkQAgwxHDAaMBgwFgQU3WIwrIYK
# LTBr2jixaHlSMAf7QX4wLwYJKoZIhvcNAQkEMSIEIJaJ5ElkUWpRjjCzGC5j3pFm
# CV1+g2fvHDNkHAym1FBSMDcGCyqGSIb3DQEJEAIvMSgwJjAkMCIEIEqgP6Is11yE
# xVyTj4KOZ2ucrsqzP+NtJpqjNPFGEQozMA0GCSqGSIb3DQEBAQUABIICADW0eYon
# jIdLXEabrPlJQjTwQiDHOi8FRjHMrbbEuCeZ2vaod66k3Ng5pMqhLrFMYdpBX+K6
# nBBLcPfmhBdOEINJYRlS2bn9BPE28xwjT7hR9WSg9pbvAE9GsABmyu7etc+xSY5u
# WqYZanu3yX920e5E68NqQWDNPw9wY8bxsNel4ejGDMUyR3VsnNWcC+nbHwaaEl7Z
# 5br7UdSN2EGdknJ+zIV1BkeVVaa/d/FQ/Td58tKXGv/L4+03AbajupwVchZaB/Sc
# ySSvN4GyWH6ltT9LquHv+V6sKau/inZcJEYoNiYcRm89aZXpLs3gv9GvXrAncuY+
# i2c+Z/ScA77JC3nh85Unh+6a/IlJN8EzRzBlq0g32fKq8Ruoe+Ma+0SnaZ4c1QQk
# bfv3vrEj4VlEnGQMBPhjiZd2dr70hHghXB1y5TdIV9opyRL6zR3lRbp3PsEHNEEI
# AhX9/LdEcYCBs+t46xu8KIeVmx05PoOmR0jDLg12J2B3ZZ7tE0IZrmBtxk7f12Y1
# F658azmPoD29wlSHeUHu+o6rV6zGmYDPm+5jaZwWMyJ5fCD1ycAtYv7R4tyc0r4M
# CnFcwG0cyxplWeOSThZ8CYhR5EmTKO3sMf9iT+F8DuI/vbT+bAla08yFpgELm0uC
# JbGXzg/Wvk+Cul+/gXrenrXKgVb5ZPmGAs38
# SIG # End signature block
