Function Initiate-PowerStruxRemote {
    <#
.SYNOPSIS
    Initiates the execution of PowerStruxWA on a local or remote computer.

.DESCRIPTION
    This function initiates the execution of PowerStruxWA on a local or remote computer.
    It handles the necessary checks, configurations, and remote connectivity testing before executing PowerStruxWA.

.PARAMETER ComputerName
    Specifies the target computer's hostname. The Default is "localhost".
    
.PARAMETER ExePath
    Specifies the file path of the PowerStruxWA executable. Default is "C:\Program Files\WindowsPowerShell\Modules\ReportHTML\Initiate-PowerStruxWA.exe".

.PARAMETER GlobalConfig
    Specifies the path to a global configuration file (PowerStruxWAConfig.txt) to be deployed on the remote or local machine.
    If this parameter is provided, the configuration file will be copied to the target computer.

.EXAMPLE
    Initiate-PowerStruxRemote -ComputerName "RemoteServer" -ExePath "C:\Path\To\Initiate-PowerStruxWA.exe"
    Initiates the execution of PowerStruxWA on the "RemoteServer" using the specified executable path.
#>

    param (
        [Parameter(Mandatory = $false)]
        $ComputerName = "localhost",
        [Parameter(Mandatory = $false)]
        $ExePath = "C:\Program Files\WindowsPowerShell\Modules\ReportHTML\Initiate-PowerStruxWA.exe",
        [Parameter(Mandatory = $false)]
        $GlobalConfig
    )

    #Create an array that contains the target Computer Name, IP Addresses, and localhost.
    #The array will be compared against the $ComputerName parameter to whether the target is local or remote.
    $arrIsLocalHost = @()
    $arrIsLocalHost += Get-NetIPAddress | Select-Object -ExpandProperty IPAddress
    $arrIsLocalHost += $env:COMPUTERNAME
    $arrIsLocalHost += "localhost"

    # If the target is the local computer then set the $boolIsLocalHost variable to $true, otherwise set it to $false.
    # This allows the script to dynamically assign cmdlet parameters based on local or remote status.
    $boolIsLocalHost = $arrIsLocalHost.Contains($ComputerName)

    # Set unc output path to the default of $false.
    $boolUncOutputPath = $false

    # Deploy-PowerStruxConfig function: Handles the deployment of the configuration file to the target machine.
    Function Deploy-PowerStruxConfig {
        param (
            [Parameter(Mandatory = $false)]
            $ComputerName = "localhost",
            [Parameter(Mandatory = $true)]
            $ConfigFile
        )
    
        # Ensure that the configuration file is named 'PowerStruxWAConfig.txt'
        if ((Split-Path -Leaf $ConfigFile) -ne "PowerStruxWAConfig.txt") {
    
            Write-Error "The configuration file must be named 'PowerStruxWAConfig.txt'."
            return
    
        }
    
        # Check if the target computer is local or remote.
        $installPath = if ($boolIsLocalHost) {
    
            # Define the installation path for the local computer.
            "C:\Program Files\WindowsPowerShell\Modules\ReportHTML"
    
        }
        else {
         
            # Define the installation path for the remote computer.
            "\\$ComputerName\c$\Program Files\WindowsPowerShell\Modules\ReportHTML"
    
        }
    
        # Check if the installation path exists.
        if (Test-Path -Path $installPath) {
    
            Write-Host "Copying $ConfigFile to $installPath." -ForegroundColor Yellow
            Write-Host ""
    
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
    
            Write-Host "Confirming that $ConfigFile was successfully copied to $installPath." -ForegroundColor Yellow
            
            # Check if the file was copied successfully.
            if (Test-Path -Path $configFilePath) {
    
                Write-Host "$ConfigFile was successfully copied to $installPath!" -ForegroundColor Green
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

    # Check if a global configuration file ($GlobalConfig) is provided.
    if ($GlobalConfig) {

        try {

            # Attempt to deploy the configuration file to the target computer.
            Deploy-PowerStruxConfig -ComputerName $ComputerName -ConfigFile $GlobalConfig -ErrorAction Stop


        }
        catch {

            Write-Host "One or more errors occurred while deploying $GlobalConfig to $ComputerName`: $_" -ForegroundColor Red
            return

        }

    }

    #If the target is the local computer then configure variables for local execution, otherwise configure variables for remote execution.
    if ($boolIsLocalHost) {

        #Set the parameters for the 'Invoke-Command' cmdlet.
        $splatInvokeCommand = @{
            ErrorAction = "Stop"            
        }

        Write-Host "Script operations will be performed locally on $env:COMPUTERNAME." -ForegroundColor Yellow
        Write-Host ""

    }
    else {

        #Set the parameters for the 'Invoke-Command' cmdlet.
        $splatInvokeCommand = @{
            ComputerName = $ComputerName
            ErrorAction  = "Stop"            
        }

        Write-Host "Script operations will be performed remotely on $ComputerName." -ForegroundColor Yellow
        Write-Host ""

        Write-Host "Testing remote connectivity to $ComputerName" -ForegroundColor Yellow
        
        #Use ICMP to test the connectivity from the source system to the target system.
        #If the connectivity test fails then terminate execution and report that the target is not reachable.
        if (Test-Connection -ComputerName $ComputerName -Count 1 -Quiet) {

            Write-Host "Remote connectivity test succeeded on $ComputerName." -ForegroundColor Green
            Write-Host ""

        }
        else {

            Write-Host "Remote connectivity test failed on $ComputerName. The system may be offline, unreachable, or ICMP may be disabled." -ForegroundColor Red
            Write-Host ""

            return

        }

    }

    #If the target system is remote ($boolIsLocalHost = $false) then start the WinRM service on the remote target.
    #The WinRM service is required for PSRemoting (Invoke-Command).
    if (!($boolIsLocalHost)) {

        Write-Host "Starting the WinRM service on $ComputerName." -ForegroundColor Yellow

        try {

            #Start the WinRM service on the service on the remote target.
            #If starting the WinRM service on the remote target fails then report the failure and terminate execution.
            Get-Service -ComputerName $ComputerName -Name WinRM -ErrorAction Stop | Start-Service -ErrorAction Stop

            Write-Host "The WinRM service was successfully started on $ComputerName." -ForegroundColor Green
            Write-Host ""

        }
        catch {
        
            Write-Host "Starting WinRM on $ComputerName failed. Please execute PowerStux on $ComputerName manually." -ForegroundColor Red

            return

        }

        try {

            # Check if the configuration file exists on the remote computer.
            if (!(Test-Path -Path "\\$ComputerName\c$\Program Files\WindowsPowerShell\Modules\ReportHTML\PowerStruxWAConfig.txt" -ErrorAction Stop)) {
    
                # If the configuration file is not found, display an error message and instruct the user to run PowerStruxWA manually on the target computer.
                Write-Host "There was an error accessing the configuration file on $ComputerName. Please execute PowerStruxWA on $ComputerName manually." -ForegroundColor Red
    
                # Exit the script.
                return
            }
            else {
                # If the configuration file exists, proceed to retrieve and process report settings.

                $reportNameLocation = Invoke-Command @splatInvokeCommand -ScriptBlock {
        
                    # Import the configuration file to retrieve customized settings.
                    $importConfig = Get-Content 'C:\Program Files\WindowsPowerShell\Modules\ReportHTML\PowerStruxWAConfig.txt' | ConvertFrom-StringData
        
                    # Attempt to define the report storage location using the imported configuration.
                    # Invoke-Expression is used to evaluate the $env:USERPROFILE variable in the configuration file.
                    try {
                        $repLocation = Invoke-Expression $importConfig.ReportLocation
                    }
                    catch {
                        # If there is an error, fall back to the raw configuration value.
                        $repLocation = $importConfig.ReportLocation
                    }
        
                    # Attempt to define the report name using the imported configuration.
                    # Invoke-Expression is used to evaluate date variables like $(Get-Date -Format yyyyMMdd) in the configuration file.
                    try {
                        $repName = Invoke-Expression $importConfig.ReportName
                    }
                    catch {
                        # If there is an error, fall back to the raw configuration value.
                        $repName = $importConfig.ReportName
                    }
        
                    # Create a custom object to store the report name and location.
                    [PSCustomObject]@{
                        ReportName     = $repName + ".html"
                        ReportLocation = $repLocation
                    }
                }
            }

            # Check if the report location path is a UNC path.
            if ($reportNameLocation.ReportLocation -match "^\\\\") {
    
                # If the path is UNC, set a boolean flag and prepare to modify the configuration file.
                $boolUncOutputPath = $true
    
                # Define the path to the configuration file on the remote computer.
                $configFile = "\\$ComputerName\c$\Program Files\WindowsPowerShell\Modules\ReportHTML\PowerStruxWAConfig.txt"
    
                # Read the current configuration file content.
                $currentConfig = Get-Content -Path $configFile
    
                # Modify the configuration content to update the ReportLocation value.
                $newConfig = $currentConfig -replace '^ReportLocation+.+', 'ReportLocation	=	"C:\\Temp"'
    
                # Write the updated configuration content back to the file.
                Set-Content -Path $configFile -Value $newConfig -Force
            }

        }
        catch {

            Write-Host "There was an error accessing the configuration file on $ComputerName. Please execute PowerStruxWA on $ComputerName manually." -ForegroundColor Red

            # Exit the script.
            return

        }

    }

    try {

        #Use the Invoke-Command cmdlet to execute the script block on the target.
        #The Invoke-Command cmdlet enables local and remote command execution.
        Invoke-Command @splatInvokeCommand -ScriptBlock {
            
            Write-Host "Executing PowerStruxWA on $($args[0]). Please be patient." -ForegroundColor Yellow

            #Execute PowerStrux.
            try {

                #Determine if the PowerStruxWA Executable exists within the defined ExePath.
                if (Test-Path -Path $args[1] -ErrorAction Stop) {

                    #Execute PowerStruxWA using the path provided by the user.
                    & $args[1]

                    Write-Host "PowerStruxWA execution succeeded on $($args[0])." -ForegroundColor Green
                    Write-Host ""

                }
                else {

                    Write-Host "PowerStruxWA was not found at $($args[1]). Please provide a valid path to the PowerStruxWA executable on $($args[0]) and rerun the script." -ForegroundColor Red
                    
                    return

                }

            }
            catch {

                Write-Host "PowerStruxWA execution on $($args[0]) failed. Please execute PowerStruxWA on $($args[0]) manually." -ForegroundColor Red

                return

            }

        }  -ArgumentList $ComputerName, $ExePath

    }
    catch {
        
        Write-Host "The attempt to perform Invoke-Command operations on $ComputerName failed. Please execute PowerStruxWA on $ComputerName manually." -ForegroundColor Red
        Write-Host ""

        #Determine if entered ComputerName is an IP Address.
        #PowerShell Remoting using an IP Address may require additional configuration.
        if (([bool]($ComputerName -as [IPAddress])) -and !($boolIsLocalHost)) {

            Write-Host "The remote target was defined as an IP Address. Please rerun the script using the remote target's hostname." -ForegroundColor Red
            Write-Host ""
        
        }

    }

    # Check if the boolean flag indicating a UNC output path is set to true.
    if ($boolUncOutputPath) {

        # Display a message indicating that the script is moving the report file to the UNC path.
        Write-Host "Moving report file from the local system to $($reportNameLocation.ReportLocation)." -ForegroundColor Yellow

        # Move the generated report file from the local 'Temp' directory on the remote computer
        # to the location specified in the ReportLocation property of the reportNameLocation object.
        Move-Item -Path "\\$ComputerName\c$\Temp\$($reportNameLocation.ReportName)" -Destination "$($reportNameLocation.ReportLocation)"

        Write-Host "The report file was successfully moved to $($reportNameLocation.ReportLocation)." -ForegroundColor Green
        Write-Host ""

        # Update the configuration file on the remote computer with the original content
        Set-Content -Path $configFile -Value $currentConfig -Force

    }

    #If the target is remote then stop the WinRM service.
    if (!($boolIsLocalHost)) {

        Write-Host "Stopping the WinRM service on $ComputerName." -ForegroundColor Yellow

        #Stop the WinRM service on the remote target.
        #If stopping the WinRM service on the remote target fails then report the error and proceed.
        try {

            #Stop the WinRM service on the remote target.
            Get-Service -ComputerName $ComputerName -Name WinRM -ErrorAction Stop | Stop-Service -ErrorAction Stop

            Write-Host "The WinRM service was successfully stopped on $ComputerName." -ForegroundColor Green
            Write-Host ""

        }
        catch {
    
            Write-Host "Stopping WinRM on $ComputerName failed." -ForegroundColor Red
            Write-Host ""

        }

    }

    Write-Host "The exeution of PowerStruxWA on $ComputerName is complete!" -ForegroundColor Green
    Write-Host ""

}
# SIG # Begin signature block
# MIIoKQYJKoZIhvcNAQcCoIIoGjCCKBYCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAnUaenCVOgGR/v
# 3o0zkGD/eM2vb0rrhe1fgHDlnHEFlKCCDZwwggawMIIEmKADAgECAhAIrUCyYNKc
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
# Ef4lQCufMYIZ4zCCGd8CAQEwfTBpMQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGln
# aUNlcnQsIEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0IFRydXN0ZWQgRzQgQ29kZSBT
# aWduaW5nIFJTQTQwOTYgU0hBMzg0IDIwMjEgQ0ExAhAK+QKGTe+/MPpscRiU2ynd
# MA0GCWCGSAFlAwQCAQUAoHwwEAYKKwYBBAGCNwIBDDECMAAwGQYJKoZIhvcNAQkD
# MQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJ
# KoZIhvcNAQkEMSIEIFr/Kw0bdH5BWZfIRDC8k9w64IpG/+8ihzH0Y1fXcRdnMA0G
# CSqGSIb3DQEBAQUABIIBgIMzGHtr3KaVtEKQZu0ia9GvRmEhtqiWwQsiDi51YmZm
# aqihX2MGwqUu4Y9fE+d9bpsrWOoAo9ebpwXv48ADtleuAyihItbGHNLLU9C8qigR
# ypskelnKUM8QbshZmq9a7IMfYlnMLq9MCZNZOqJgX7J/yagUcq0mYrBbEerFAZNy
# Rq1PuDGJAwSLBM2+EpR5GInw5Ts8/57IZa5vwEy1rO044X3OIs6GUfhhZ+lLnwAy
# RACDsVGANRuQ8rYVpuAaW97/Kss6AYEq+XEktbsdvl/wUAKikn1wZBY+GrhzHm/G
# x83ua0sl56zekB2pZftexzzLzLLLreg9fOFV5G22bW0CxtAYkv+qcVkdTBhXRtzf
# dnT35FEUhITxpHDtBX4z/8urNVGEHY35vEfe09swr0A4vr9+2xeU1dk/EToVs4pF
# CuZKspnSeC+cTf5y/FUeowffZZaePDXWmD9yNLoteNBYM4+tQO+UZfrYZbLrr3Zk
# LVo3NqKggimwZVcQyh+tl6GCFzkwghc1BgorBgEEAYI3AwMBMYIXJTCCFyEGCSqG
# SIb3DQEHAqCCFxIwghcOAgEDMQ8wDQYJYIZIAWUDBAIBBQAwdwYLKoZIhvcNAQkQ
# AQSgaARmMGQCAQEGCWCGSAGG/WwHATAxMA0GCWCGSAFlAwQCAQUABCA+TrcGvT5j
# xs75wUFw8hp4GVNDkmPxTKOWldWMN7HqqAIQRC16dvO0l7fI32gQqUjeTRgPMjAy
# NTAzMTgxMzQ4NDNaoIITAzCCBrwwggSkoAMCAQICEAuuZrxaun+Vh8b56QTjMwQw
# DQYJKoZIhvcNAQELBQAwYzELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0
# LCBJbmMuMTswOQYDVQQDEzJEaWdpQ2VydCBUcnVzdGVkIEc0IFJTQTQwOTYgU0hB
# MjU2IFRpbWVTdGFtcGluZyBDQTAeFw0yNDA5MjYwMDAwMDBaFw0zNTExMjUyMzU5
# NTlaMEIxCzAJBgNVBAYTAlVTMREwDwYDVQQKEwhEaWdpQ2VydDEgMB4GA1UEAxMX
# RGlnaUNlcnQgVGltZXN0YW1wIDIwMjQwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAw
# ggIKAoICAQC+anOf9pUhq5Ywultt5lmjtej9kR8YxIg7apnjpcH9CjAgQxK+CMR0
# Rne/i+utMeV5bUlYYSuuM4vQngvQepVHVzNLO9RDnEXvPghCaft0djvKKO+hDu6O
# bS7rJcXa/UKvNminKQPTv/1+kBPgHGlP28mgmoCw/xi6FG9+Un1h4eN6zh926SxM
# e6We2r1Z6VFZj75MU/HNmtsgtFjKfITLutLWUdAoWle+jYZ49+wxGE1/UXjWfISD
# mHuI5e/6+NfQrxGFSKx+rDdNMsePW6FLrphfYtk/FLihp/feun0eV+pIF496OVh4
# R1TvjQYpAztJpVIfdNsEvxHofBf1BWkadc+Up0Th8EifkEEWdX4rA/FE1Q0rqViT
# bLVZIqi6viEk3RIySho1XyHLIAOJfXG5PEppc3XYeBH7xa6VTZ3rOHNeiYnY+V4j
# 1XbJ+Z9dI8ZhqcaDHOoj5KGg4YuiYx3eYm33aebsyF6eD9MF5IDbPgjvwmnAalNE
# eJPvIeoGJXaeBQjIK13SlnzODdLtuThALhGtyconcVuPI8AaiCaiJnfdzUcb3dWn
# qUnjXkRFwLtsVAxFvGqsxUA2Jq/WTjbnNjIUzIs3ITVC6VBKAOlb2u29Vwgfta8b
# 2ypi6n2PzP0nVepsFk8nlcuWfyZLzBaZ0MucEdeBiXL+nUOGhCjl+QIDAQABo4IB
# izCCAYcwDgYDVR0PAQH/BAQDAgeAMAwGA1UdEwEB/wQCMAAwFgYDVR0lAQH/BAww
# CgYIKwYBBQUHAwgwIAYDVR0gBBkwFzAIBgZngQwBBAIwCwYJYIZIAYb9bAcBMB8G
# A1UdIwQYMBaAFLoW2W1NhS9zKXaaL3WMaiCPnshvMB0GA1UdDgQWBBSfVywDdw4o
# FZBmpWNe7k+SH3agWzBaBgNVHR8EUzBRME+gTaBLhklodHRwOi8vY3JsMy5kaWdp
# Y2VydC5jb20vRGlnaUNlcnRUcnVzdGVkRzRSU0E0MDk2U0hBMjU2VGltZVN0YW1w
# aW5nQ0EuY3JsMIGQBggrBgEFBQcBAQSBgzCBgDAkBggrBgEFBQcwAYYYaHR0cDov
# L29jc3AuZGlnaWNlcnQuY29tMFgGCCsGAQUFBzAChkxodHRwOi8vY2FjZXJ0cy5k
# aWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkRzRSU0E0MDk2U0hBMjU2VGltZVN0
# YW1waW5nQ0EuY3J0MA0GCSqGSIb3DQEBCwUAA4ICAQA9rR4fdplb4ziEEkfZQ5H2
# EdubTggd0ShPz9Pce4FLJl6reNKLkZd5Y/vEIqFWKt4oKcKz7wZmXa5VgW9B76k9
# NJxUl4JlKwyjUkKhk3aYx7D8vi2mpU1tKlY71AYXB8wTLrQeh83pXnWwwsxc1Mt+
# FWqz57yFq6laICtKjPICYYf/qgxACHTvypGHrC8k1TqCeHk6u4I/VBQC9VK7iSpU
# 5wlWjNlHlFFv/M93748YTeoXU/fFa9hWJQkuzG2+B7+bMDvmgF8VlJt1qQcl7YFU
# MYgZU1WM6nyw23vT6QSgwX5Pq2m0xQ2V6FJHu8z4LXe/371k5QrN9FQBhLLISZi2
# yemW0P8ZZfx4zvSWzVXpAb9k4Hpvpi6bUe8iK6WonUSV6yPlMwerwJZP/Gtbu3CK
# ldMnn+LmmRTkTXpFIEB06nXZrDwhCGED+8RsWQSIXZpuG4WLFQOhtloDRWGoCwwc
# 6ZpPddOFkM2LlTbMcqFSzm4cd0boGhBq7vkqI1uHRz6Fq1IX7TaRQuR+0BGOzISk
# cqwXu7nMpFu3mgrlgbAW+BzikRVQ3K2YHcGkiKjA4gi4OA/kz1YCsdhIBHXqBzR0
# /Zd2QwQ/l4Gxftt/8wY3grcc/nS//TVkej9nmUYu83BDtccHHXKibMs/yXHhDXNk
# oPIdynhVAku7aRZOwqw6pDCCBq4wggSWoAMCAQICEAc2N7ckVHzYR6z9KGYqXlsw
# DQYJKoZIhvcNAQELBQAwYjELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0
# IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTEhMB8GA1UEAxMYRGlnaUNl
# cnQgVHJ1c3RlZCBSb290IEc0MB4XDTIyMDMyMzAwMDAwMFoXDTM3MDMyMjIzNTk1
# OVowYzELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTswOQYD
# VQQDEzJEaWdpQ2VydCBUcnVzdGVkIEc0IFJTQTQwOTYgU0hBMjU2IFRpbWVTdGFt
# cGluZyBDQTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAMaGNQZJs8E9
# cklRVcclA8TykTepl1Gh1tKD0Z5Mom2gsMyD+Vr2EaFEFUJfpIjzaPp985yJC3+d
# H54PMx9QEwsmc5Zt+FeoAn39Q7SE2hHxc7Gz7iuAhIoiGN/r2j3EF3+rGSs+Qtxn
# jupRPfDWVtTnKC3r07G1decfBmWNlCnT2exp39mQh0YAe9tEQYncfGpXevA3eZ9d
# rMvohGS0UvJ2R/dhgxndX7RUCyFobjchu0CsX7LeSn3O9TkSZ+8OpWNs5KbFHc02
# DVzV5huowWR0QKfAcsW6Th+xtVhNef7Xj3OTrCw54qVI1vCwMROpVymWJy71h6aP
# TnYVVSZwmCZ/oBpHIEPjQ2OAe3VuJyWQmDo4EbP29p7mO1vsgd4iFNmCKseSv6De
# 4z6ic/rnH1pslPJSlRErWHRAKKtzQ87fSqEcazjFKfPKqpZzQmiftkaznTqj1QPg
# v/CiPMpC3BhIfxQ0z9JMq++bPf4OuGQq+nUoJEHtQr8FnGZJUlD0UfM2SU2LINIs
# VzV5K6jzRWC8I41Y99xh3pP+OcD5sjClTNfpmEpYPtMDiP6zj9NeS3YSUZPJjAw7
# W4oiqMEmCPkUEBIDfV8ju2TjY+Cm4T72wnSyPx4JduyrXUZ14mCjWAkBKAAOhFTu
# zuldyF4wEr1GnrXTdrnSDmuZDNIztM2xAgMBAAGjggFdMIIBWTASBgNVHRMBAf8E
# CDAGAQH/AgEAMB0GA1UdDgQWBBS6FtltTYUvcyl2mi91jGogj57IbzAfBgNVHSME
# GDAWgBTs1+OC0nFdZEzfLmc/57qYrhwPTzAOBgNVHQ8BAf8EBAMCAYYwEwYDVR0l
# BAwwCgYIKwYBBQUHAwgwdwYIKwYBBQUHAQEEazBpMCQGCCsGAQUFBzABhhhodHRw
# Oi8vb2NzcC5kaWdpY2VydC5jb20wQQYIKwYBBQUHMAKGNWh0dHA6Ly9jYWNlcnRz
# LmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRSb290RzQuY3J0MEMGA1UdHwQ8
# MDowOKA2oDSGMmh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0
# ZWRSb290RzQuY3JsMCAGA1UdIAQZMBcwCAYGZ4EMAQQCMAsGCWCGSAGG/WwHATAN
# BgkqhkiG9w0BAQsFAAOCAgEAfVmOwJO2b5ipRCIBfmbW2CFC4bAYLhBNE88wU86/
# GPvHUF3iSyn7cIoNqilp/GnBzx0H6T5gyNgL5Vxb122H+oQgJTQxZ822EpZvxFBM
# Yh0MCIKoFr2pVs8Vc40BIiXOlWk/R3f7cnQU1/+rT4osequFzUNf7WC2qk+RZp4s
# nuCKrOX9jLxkJodskr2dfNBwCnzvqLx1T7pa96kQsl3p/yhUifDVinF2ZdrM8HKj
# I/rAJ4JErpknG6skHibBt94q6/aesXmZgaNWhqsKRcnfxI2g55j7+6adcq/Ex8HB
# anHZxhOACcS2n82HhyS7T6NJuXdmkfFynOlLAlKnN36TU6w7HQhJD5TNOXrd/yVj
# mScsPT9rp/Fmw0HNT7ZAmyEhQNC3EyTN3B14OuSereU0cZLXJmvkOHOrpgFPvT87
# eK1MrfvElXvtCl8zOYdBeHo46Zzh3SP9HSjTx/no8Zhf+yvYfvJGnXUsHicsJttv
# FXseGYs2uJPU5vIXmVnKcPA3v5gA3yAWTyf7YGcWoWa63VXAOimGsJigK+2VQbc6
# 1RWYMbRiCQ8KvYHZE/6/pNHzV9m8BPqC3jLfBInwAM1dwvnQI38AC+R2AibZ8GV2
# QqYphwlHK+Z/GqSFD/yYlvZVVCsfgPrA8g4r5db7qS9EFUrnEw4d2zc4GqEr9u3W
# fPwwggWNMIIEdaADAgECAhAOmxiO+dAt5+/bUOIIQBhaMA0GCSqGSIb3DQEBDAUA
# MGUxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsT
# EHd3dy5kaWdpY2VydC5jb20xJDAiBgNVBAMTG0RpZ2lDZXJ0IEFzc3VyZWQgSUQg
# Um9vdCBDQTAeFw0yMjA4MDEwMDAwMDBaFw0zMTExMDkyMzU5NTlaMGIxCzAJBgNV
# BAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdp
# Y2VydC5jb20xITAfBgNVBAMTGERpZ2lDZXJ0IFRydXN0ZWQgUm9vdCBHNDCCAiIw
# DQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAL/mkHNo3rvkXUo8MCIwaTPswqcl
# LskhPfKK2FnC4SmnPVirdprNrnsbhA3EMB/zG6Q4FutWxpdtHauyefLKEdLkX9YF
# PFIPUh/GnhWlfr6fqVcWWVVyr2iTcMKyunWZanMylNEQRBAu34LzB4TmdDttceIt
# DBvuINXJIB1jKS3O7F5OyJP4IWGbNOsFxl7sWxq868nPzaw0QF+xembud8hIqGZX
# V59UWI4MK7dPpzDZVu7Ke13jrclPXuU15zHL2pNe3I6PgNq2kZhAkHnDeMe2scS1
# ahg4AxCN2NQ3pC4FfYj1gj4QkXCrVYJBMtfbBHMqbpEBfCFM1LyuGwN1XXhm2Tox
# RJozQL8I11pJpMLmqaBn3aQnvKFPObURWBf3JFxGj2T3wWmIdph2PVldQnaHiZdp
# ekjw4KISG2aadMreSx7nDmOu5tTvkpI6nj3cAORFJYm2mkQZK37AlLTSYW3rM9nF
# 30sEAMx9HJXDj/chsrIRt7t/8tWMcCxBYKqxYxhElRp2Yn72gLD76GSmM9GJB+G9
# t+ZDpBi4pncB4Q+UDCEdslQpJYls5Q5SUUd0viastkF13nqsX40/ybzTQRESW+UQ
# UOsxxcpyFiIJ33xMdT9j7CFfxCBRa2+xq4aLT8LWRV+dIPyhHsXAj6KxfgommfXk
# aS+YHS312amyHeUbAgMBAAGjggE6MIIBNjAPBgNVHRMBAf8EBTADAQH/MB0GA1Ud
# DgQWBBTs1+OC0nFdZEzfLmc/57qYrhwPTzAfBgNVHSMEGDAWgBRF66Kv9JLLgjEt
# UYunpyGd823IDzAOBgNVHQ8BAf8EBAMCAYYweQYIKwYBBQUHAQEEbTBrMCQGCCsG
# AQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wQwYIKwYBBQUHMAKGN2h0
# dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RD
# QS5jcnQwRQYDVR0fBD4wPDA6oDigNoY0aHR0cDovL2NybDMuZGlnaWNlcnQuY29t
# L0RpZ2lDZXJ0QXNzdXJlZElEUm9vdENBLmNybDARBgNVHSAECjAIMAYGBFUdIAAw
# DQYJKoZIhvcNAQEMBQADggEBAHCgv0NcVec4X6CjdBs9thbX979XB72arKGHLOyF
# XqkauyL4hxppVCLtpIh3bb0aFPQTSnovLbc47/T/gLn4offyct4kvFIDyE7QKt76
# LVbP+fT3rDB6mouyXtTP0UNEm0Mh65ZyoUi0mcudT6cGAxN3J0TU53/oWajwvy8L
# punyNDzs9wPHh6jSTEAZNUZqaVSwuKFWjuyk1T3osdz9HNj0d1pcVIxv76FQPfx2
# CWiEn2/K2yCNNWAcAgPLILCsWKAOQGPFmCLBsln1VWvPJ6tsds5vIy30fnFqI2si
# /xK4VC0nftg62fC2h5b9W9FcrBjDTZ9ztwGpn1eqXijiuZQxggN2MIIDcgIBATB3
# MGMxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjE7MDkGA1UE
# AxMyRGlnaUNlcnQgVHJ1c3RlZCBHNCBSU0E0MDk2IFNIQTI1NiBUaW1lU3RhbXBp
# bmcgQ0ECEAuuZrxaun+Vh8b56QTjMwQwDQYJYIZIAWUDBAIBBQCggdEwGgYJKoZI
# hvcNAQkDMQ0GCyqGSIb3DQEJEAEEMBwGCSqGSIb3DQEJBTEPFw0yNTAzMTgxMzQ4
# NDNaMCsGCyqGSIb3DQEJEAIMMRwwGjAYMBYEFNvThe5i29I+e+T2cUhQhyTVhltF
# MC8GCSqGSIb3DQEJBDEiBCAU3Rg5g075fX8qlYaKMkYxJ3T5Z5hyEh2SILRd7VU9
# XDA3BgsqhkiG9w0BCRACLzEoMCYwJDAiBCB2dp+o8mMvH0MLOiMwrtZWdf7Xc9sF
# 1mW5BZOYQ4+a2zANBgkqhkiG9w0BAQEFAASCAgBmwQtZqs21iYJ1SlbHN4CIeHcQ
# qurjkyk3nKMcC/AQWBojAKH7LNR8TwP6hhxAloB1DxT5s5h4q8c8vm1ObU7uuq8e
# e1jVH9NxPP48oKmSpOwV/ZnS3UGnCab6p+tOZuYOVixX8nHKxXBDc0DdNE+tumod
# iF/cpTmh28+DvZZJPMu3gTatofXz+9AaWRCXlI1S/wSVwvnGDH3C2fT7pWJIZ/DF
# jaZIySKfNBqZWW5HiennThbEFYLUoOGcvn1AQ8t+HwKTYsa5WTIa1qfJkL3+/sZE
# NmI/a4ENn2Jbevx5AUxiO6HpGvXHhuJ7NUjXB1GrnZzJGEitJMVpvt1+wgQa4Hn1
# +BItJdSf/QXzFbI2o0yLMydv7kfgXrfJgRsy+jkqP1Po6KN58Cs2sC4WjJQsj27/
# tRJVvewX/3AwAjnzyR1AvPX837mslKSQQOqOPNxHQev5qncd/4nfyJpJv3yDm7is
# 1aJNiM+TV4dZ3D8z870N5f21cHpKuYCEcaSO/RDQVjfB4lqRd0VDaffYow6MNZ4E
# zW7MaQ0K7ngjC0jfgq638WK3pTFA9qAgTXdjA8o1GQDtJAOMTgxZNf802Sfu7Ooz
# FOHV3b2vR0LcTZyBd3bNEXKbzxq9DFmm2vtqEhHdi6nFtSQIOCp9MLLX7y0za5g1
# y2xUsxZX7luAmDo2Iw==
# SIG # End signature block
