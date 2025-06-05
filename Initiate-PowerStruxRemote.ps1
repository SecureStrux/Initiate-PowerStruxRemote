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
    if ($boolIsLocalHost -eq $TRUE) {

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
    if ($boolIsLocalHost -eq $FALSE) {

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
        if (([bool]($ComputerName -as [IPAddress])) -and ($boolIsLocalHost -eq $FALSE)) {

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
    if ($boolIsLocalHost -eq $FALSE) {

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
# MIIoKgYJKoZIhvcNAQcCoIIoGzCCKBcCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBqVv1Derc6PQfH
# iFNzvIBalvdytcqwB/A9MR0IzgIqz6CCDZwwggawMIIEmKADAgECAhAIrUCyYNKc
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
# Ef4lQCufMYIZ5DCCGeACAQEwfTBpMQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGln
# aUNlcnQsIEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0IFRydXN0ZWQgRzQgQ29kZSBT
# aWduaW5nIFJTQTQwOTYgU0hBMzg0IDIwMjEgQ0ExAhAK+QKGTe+/MPpscRiU2ynd
# MA0GCWCGSAFlAwQCAQUAoHwwEAYKKwYBBAGCNwIBDDECMAAwGQYJKoZIhvcNAQkD
# MQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJ
# KoZIhvcNAQkEMSIEIPqSzo87t167vcdLXp8EyOcKsNKJ9dnY3eXm8g35AgVcMA0G
# CSqGSIb3DQEBAQUABIIBgI/8AHDb6BrEPm804oZNSR2znCqlFFOcrpDoWnEoPecc
# K2o94zKWjF4IexMKKUzyg3Q9Y2QXWJLZ5/BxSz3nWYvRGpLMaxq2dSG06Smj3uGC
# Nd2On/XDUIRpZkAgOpY/EnN4a1D8BHL9uyXiuR1dOmpTAK+cKTN3N08onLZ2LSaV
# jOBpnKFJ14ZaS+ao6czjIP4JW5z0UTj8dfqo5r47N1VJV5IjfHPmvhilQqLbD+ry
# ZPILDYkysom0pHgb/mvhcCxDW07fRHzj0I7c19cFUC6cGDdbuHO6SZHqw3rEsNRp
# TM5JCLqP02LLXipN9hrxbcvxTvdK3sMFfkl847Fuql4B3Jct3XzcVyDVS1U9liGo
# mfsJZTj7nyrcsqZtrw+2MScUCTecnzvGxckMtubOHbKiBcQwTLOaahsYPgUyfS3g
# 4MUHaEksctVbHTNBCFyPld7/+Myfi2Eb2avRHAmC7Q5XGTkqQHm1BY8x0mHBPkjP
# HHxQlh0KQA2iraCdmdhJ26GCFzowghc2BgorBgEEAYI3AwMBMYIXJjCCFyIGCSqG
# SIb3DQEHAqCCFxMwghcPAgEDMQ8wDQYJYIZIAWUDBAIBBQAweAYLKoZIhvcNAQkQ
# AQSgaQRnMGUCAQEGCWCGSAGG/WwHATAxMA0GCWCGSAFlAwQCAQUABCAEj1oZyHVN
# dBChJzS2Ooc9CMwiOrh1NC+WmSNNHakrQwIRAOaZKWRKKpq5kq9AqsMJPUYYDzIw
# MjUwNjA1MTYwNjE2WqCCEwMwgga8MIIEpKADAgECAhALrma8Wrp/lYfG+ekE4zME
# MA0GCSqGSIb3DQEBCwUAMGMxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2Vy
# dCwgSW5jLjE7MDkGA1UEAxMyRGlnaUNlcnQgVHJ1c3RlZCBHNCBSU0E0MDk2IFNI
# QTI1NiBUaW1lU3RhbXBpbmcgQ0EwHhcNMjQwOTI2MDAwMDAwWhcNMzUxMTI1MjM1
# OTU5WjBCMQswCQYDVQQGEwJVUzERMA8GA1UEChMIRGlnaUNlcnQxIDAeBgNVBAMT
# F0RpZ2lDZXJ0IFRpbWVzdGFtcCAyMDI0MIICIjANBgkqhkiG9w0BAQEFAAOCAg8A
# MIICCgKCAgEAvmpzn/aVIauWMLpbbeZZo7Xo/ZEfGMSIO2qZ46XB/QowIEMSvgjE
# dEZ3v4vrrTHleW1JWGErrjOL0J4L0HqVR1czSzvUQ5xF7z4IQmn7dHY7yijvoQ7u
# jm0u6yXF2v1CrzZopykD07/9fpAT4BxpT9vJoJqAsP8YuhRvflJ9YeHjes4fduks
# THulntq9WelRWY++TFPxzZrbILRYynyEy7rS1lHQKFpXvo2GePfsMRhNf1F41nyE
# g5h7iOXv+vjX0K8RhUisfqw3TTLHj1uhS66YX2LZPxS4oaf33rp9HlfqSBePejlY
# eEdU740GKQM7SaVSH3TbBL8R6HwX9QVpGnXPlKdE4fBIn5BBFnV+KwPxRNUNK6lY
# k2y1WSKour4hJN0SMkoaNV8hyyADiX1xuTxKaXN12HgR+8WulU2d6zhzXomJ2Ple
# I9V2yfmfXSPGYanGgxzqI+ShoOGLomMd3mJt92nm7Mheng/TBeSA2z4I78JpwGpT
# RHiT7yHqBiV2ngUIyCtd0pZ8zg3S7bk4QC4RrcnKJ3FbjyPAGogmoiZ33c1HG93V
# p6lJ415ERcC7bFQMRbxqrMVANiav1k425zYyFMyLNyE1QulQSgDpW9rtvVcIH7Wv
# G9sqYup9j8z9J1XqbBZPJ5XLln8mS8wWmdDLnBHXgYly/p1DhoQo5fkCAwEAAaOC
# AYswggGHMA4GA1UdDwEB/wQEAwIHgDAMBgNVHRMBAf8EAjAAMBYGA1UdJQEB/wQM
# MAoGCCsGAQUFBwMIMCAGA1UdIAQZMBcwCAYGZ4EMAQQCMAsGCWCGSAGG/WwHATAf
# BgNVHSMEGDAWgBS6FtltTYUvcyl2mi91jGogj57IbzAdBgNVHQ4EFgQUn1csA3cO
# KBWQZqVjXu5Pkh92oFswWgYDVR0fBFMwUTBPoE2gS4ZJaHR0cDovL2NybDMuZGln
# aWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZEc0UlNBNDA5NlNIQTI1NlRpbWVTdGFt
# cGluZ0NBLmNybDCBkAYIKwYBBQUHAQEEgYMwgYAwJAYIKwYBBQUHMAGGGGh0dHA6
# Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBYBggrBgEFBQcwAoZMaHR0cDovL2NhY2VydHMu
# ZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZEc0UlNBNDA5NlNIQTI1NlRpbWVT
# dGFtcGluZ0NBLmNydDANBgkqhkiG9w0BAQsFAAOCAgEAPa0eH3aZW+M4hBJH2UOR
# 9hHbm04IHdEoT8/T3HuBSyZeq3jSi5GXeWP7xCKhVireKCnCs+8GZl2uVYFvQe+p
# PTScVJeCZSsMo1JCoZN2mMew/L4tpqVNbSpWO9QGFwfMEy60HofN6V51sMLMXNTL
# fhVqs+e8haupWiArSozyAmGH/6oMQAh078qRh6wvJNU6gnh5OruCP1QUAvVSu4kq
# VOcJVozZR5RRb/zPd++PGE3qF1P3xWvYViUJLsxtvge/mzA75oBfFZSbdakHJe2B
# VDGIGVNVjOp8sNt70+kEoMF+T6tptMUNlehSR7vM+C13v9+9ZOUKzfRUAYSyyEmY
# tsnpltD/GWX8eM70ls1V6QG/ZOB6b6Yum1HvIiulqJ1Elesj5TMHq8CWT/xrW7tw
# ipXTJ5/i5pkU5E16RSBAdOp12aw8IQhhA/vEbFkEiF2abhuFixUDobZaA0VhqAsM
# HOmaT3XThZDNi5U2zHKhUs5uHHdG6BoQau75KiNbh0c+hatSF+02kULkftARjsyE
# pHKsF7u5zKRbt5oK5YGwFvgc4pEVUNytmB3BpIiowOIIuDgP5M9WArHYSAR16gc0
# dP2XdkMEP5eBsX7bf/MGN4K3HP50v/01ZHo/Z5lGLvNwQ7XHBx1yomzLP8lx4Q1z
# ZKDyHcp4VQJLu2kWTsKsOqQwggauMIIElqADAgECAhAHNje3JFR82Ees/ShmKl5b
# MA0GCSqGSIb3DQEBCwUAMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2Vy
# dCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNVBAMTGERpZ2lD
# ZXJ0IFRydXN0ZWQgUm9vdCBHNDAeFw0yMjAzMjMwMDAwMDBaFw0zNzAzMjIyMzU5
# NTlaMGMxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjE7MDkG
# A1UEAxMyRGlnaUNlcnQgVHJ1c3RlZCBHNCBSU0E0MDk2IFNIQTI1NiBUaW1lU3Rh
# bXBpbmcgQ0EwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDGhjUGSbPB
# PXJJUVXHJQPE8pE3qZdRodbSg9GeTKJtoLDMg/la9hGhRBVCX6SI82j6ffOciQt/
# nR+eDzMfUBMLJnOWbfhXqAJ9/UO0hNoR8XOxs+4rgISKIhjf69o9xBd/qxkrPkLc
# Z47qUT3w1lbU5ygt69OxtXXnHwZljZQp09nsad/ZkIdGAHvbREGJ3HxqV3rwN3mf
# XazL6IRktFLydkf3YYMZ3V+0VAshaG43IbtArF+y3kp9zvU5EmfvDqVjbOSmxR3N
# Ng1c1eYbqMFkdECnwHLFuk4fsbVYTXn+149zk6wsOeKlSNbwsDETqVcplicu9Yem
# j052FVUmcJgmf6AaRyBD40NjgHt1biclkJg6OBGz9vae5jtb7IHeIhTZgirHkr+g
# 3uM+onP65x9abJTyUpURK1h0QCirc0PO30qhHGs4xSnzyqqWc0Jon7ZGs506o9UD
# 4L/wojzKQtwYSH8UNM/STKvvmz3+DrhkKvp1KCRB7UK/BZxmSVJQ9FHzNklNiyDS
# LFc1eSuo80VgvCONWPfcYd6T/jnA+bIwpUzX6ZhKWD7TA4j+s4/TXkt2ElGTyYwM
# O1uKIqjBJgj5FBASA31fI7tk42PgpuE+9sJ0sj8eCXbsq11GdeJgo1gJASgADoRU
# 7s7pXcheMBK9Rp6103a50g5rmQzSM7TNsQIDAQABo4IBXTCCAVkwEgYDVR0TAQH/
# BAgwBgEB/wIBADAdBgNVHQ4EFgQUuhbZbU2FL3MpdpovdYxqII+eyG8wHwYDVR0j
# BBgwFoAU7NfjgtJxXWRM3y5nP+e6mK4cD08wDgYDVR0PAQH/BAQDAgGGMBMGA1Ud
# JQQMMAoGCCsGAQUFBwMIMHcGCCsGAQUFBwEBBGswaTAkBggrBgEFBQcwAYYYaHR0
# cDovL29jc3AuZGlnaWNlcnQuY29tMEEGCCsGAQUFBzAChjVodHRwOi8vY2FjZXJ0
# cy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkUm9vdEc0LmNydDBDBgNVHR8E
# PDA6MDigNqA0hjJodHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVz
# dGVkUm9vdEc0LmNybDAgBgNVHSAEGTAXMAgGBmeBDAEEAjALBglghkgBhv1sBwEw
# DQYJKoZIhvcNAQELBQADggIBAH1ZjsCTtm+YqUQiAX5m1tghQuGwGC4QTRPPMFPO
# vxj7x1Bd4ksp+3CKDaopafxpwc8dB+k+YMjYC+VcW9dth/qEICU0MWfNthKWb8RQ
# TGIdDAiCqBa9qVbPFXONASIlzpVpP0d3+3J0FNf/q0+KLHqrhc1DX+1gtqpPkWae
# LJ7giqzl/Yy8ZCaHbJK9nXzQcAp876i8dU+6WvepELJd6f8oVInw1YpxdmXazPBy
# oyP6wCeCRK6ZJxurJB4mwbfeKuv2nrF5mYGjVoarCkXJ38SNoOeY+/umnXKvxMfB
# wWpx2cYTgAnEtp/Nh4cku0+jSbl3ZpHxcpzpSwJSpzd+k1OsOx0ISQ+UzTl63f8l
# Y5knLD0/a6fxZsNBzU+2QJshIUDQtxMkzdwdeDrknq3lNHGS1yZr5Dhzq6YBT70/
# O3itTK37xJV77QpfMzmHQXh6OOmc4d0j/R0o08f56PGYX/sr2H7yRp11LB4nLCbb
# bxV7HhmLNriT1ObyF5lZynDwN7+YAN8gFk8n+2BnFqFmut1VwDophrCYoCvtlUG3
# OtUVmDG0YgkPCr2B2RP+v6TR81fZvAT6gt4y3wSJ8ADNXcL50CN/AAvkdgIm2fBl
# dkKmKYcJRyvmfxqkhQ/8mJb2VVQrH4D6wPIOK+XW+6kvRBVK5xMOHds3OBqhK/bt
# 1nz8MIIFjTCCBHWgAwIBAgIQDpsYjvnQLefv21DiCEAYWjANBgkqhkiG9w0BAQwF
# ADBlMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQL
# ExB3d3cuZGlnaWNlcnQuY29tMSQwIgYDVQQDExtEaWdpQ2VydCBBc3N1cmVkIElE
# IFJvb3QgQ0EwHhcNMjIwODAxMDAwMDAwWhcNMzExMTA5MjM1OTU5WjBiMQswCQYD
# VQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGln
# aWNlcnQuY29tMSEwHwYDVQQDExhEaWdpQ2VydCBUcnVzdGVkIFJvb3QgRzQwggIi
# MA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC/5pBzaN675F1KPDAiMGkz7MKn
# JS7JIT3yithZwuEppz1Yq3aaza57G4QNxDAf8xukOBbrVsaXbR2rsnnyyhHS5F/W
# BTxSD1Ifxp4VpX6+n6lXFllVcq9ok3DCsrp1mWpzMpTREEQQLt+C8weE5nQ7bXHi
# LQwb7iDVySAdYyktzuxeTsiT+CFhmzTrBcZe7FsavOvJz82sNEBfsXpm7nfISKhm
# V1efVFiODCu3T6cw2Vbuyntd463JT17lNecxy9qTXtyOj4DatpGYQJB5w3jHtrHE
# tWoYOAMQjdjUN6QuBX2I9YI+EJFwq1WCQTLX2wRzKm6RAXwhTNS8rhsDdV14Ztk6
# MUSaM0C/CNdaSaTC5qmgZ92kJ7yhTzm1EVgX9yRcRo9k98FpiHaYdj1ZXUJ2h4mX
# aXpI8OCiEhtmmnTK3kse5w5jrubU75KSOp493ADkRSWJtppEGSt+wJS00mFt6zPZ
# xd9LBADMfRyVw4/3IbKyEbe7f/LVjHAsQWCqsWMYRJUadmJ+9oCw++hkpjPRiQfh
# vbfmQ6QYuKZ3AeEPlAwhHbJUKSWJbOUOUlFHdL4mrLZBdd56rF+NP8m800ERElvl
# EFDrMcXKchYiCd98THU/Y+whX8QgUWtvsauGi0/C1kVfnSD8oR7FwI+isX4KJpn1
# 5GkvmB0t9dmpsh3lGwIDAQABo4IBOjCCATYwDwYDVR0TAQH/BAUwAwEB/zAdBgNV
# HQ4EFgQU7NfjgtJxXWRM3y5nP+e6mK4cD08wHwYDVR0jBBgwFoAUReuir/SSy4Ix
# LVGLp6chnfNtyA8wDgYDVR0PAQH/BAQDAgGGMHkGCCsGAQUFBwEBBG0wazAkBggr
# BgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMEMGCCsGAQUFBzAChjdo
# dHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRBc3N1cmVkSURSb290
# Q0EuY3J0MEUGA1UdHwQ+MDwwOqA4oDaGNGh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNv
# bS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5jcmwwEQYDVR0gBAowCDAGBgRVHSAA
# MA0GCSqGSIb3DQEBDAUAA4IBAQBwoL9DXFXnOF+go3QbPbYW1/e/Vwe9mqyhhyzs
# hV6pGrsi+IcaaVQi7aSId229GhT0E0p6Ly23OO/0/4C5+KH38nLeJLxSA8hO0Cre
# +i1Wz/n096wwepqLsl7Uz9FDRJtDIeuWcqFItJnLnU+nBgMTdydE1Od/6Fmo8L8v
# C6bp8jQ87PcDx4eo0kxAGTVGamlUsLihVo7spNU96LHc/RzY9HdaXFSMb++hUD38
# dglohJ9vytsgjTVgHAIDyyCwrFigDkBjxZgiwbJZ9VVrzyerbHbObyMt9H5xaiNr
# Iv8SuFQtJ37YOtnwtoeW/VvRXKwYw02fc7cBqZ9Xql4o4rmUMYIDdjCCA3ICAQEw
# dzBjMQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xOzA5BgNV
# BAMTMkRpZ2lDZXJ0IFRydXN0ZWQgRzQgUlNBNDA5NiBTSEEyNTYgVGltZVN0YW1w
# aW5nIENBAhALrma8Wrp/lYfG+ekE4zMEMA0GCWCGSAFlAwQCAQUAoIHRMBoGCSqG
# SIb3DQEJAzENBgsqhkiG9w0BCRABBDAcBgkqhkiG9w0BCQUxDxcNMjUwNjA1MTYw
# NjE2WjArBgsqhkiG9w0BCRACDDEcMBowGDAWBBTb04XuYtvSPnvk9nFIUIck1YZb
# RTAvBgkqhkiG9w0BCQQxIgQgWfG6zmyQls3lMA12rqQDDvmu5wrdglr6EFud/VW/
# tNswNwYLKoZIhvcNAQkQAi8xKDAmMCQwIgQgdnafqPJjLx9DCzojMK7WVnX+13Pb
# BdZluQWTmEOPmtswDQYJKoZIhvcNAQEBBQAEggIARYERldGjckE5Abyygw/RvdXp
# zXn+RnuOXHQ/AEaar9aNdJOnd1whQD1W71kSeZ8PrC88q3bvnJrSMJgrPCZPS7Ot
# J8azUwqHY0AAKc3BR7xQG39XGozbqbVwFsVTL1PqKN+iY5BdYMdfq6jklBNIXX8n
# MQ2eINc3yRHDS9eI4JHbfTX3GV9IsjNFu9g9y6mrWrHNehvZxVnhx+icpd0gms6w
# 5mQm8RqOHLR7GPgWNnbVF9d/qjqd47rf6cPQS2zYP0Ur8RHx2CpOrSs0d5MEb6+B
# 7yBfBj8z1rfMTclfqa3OzmCSVXQcPbyKWtLbdK2ksTduqE70SRHyf/qXI2wA4UmH
# /iZ8zUumzV+zZ/DW8gZgrekiFrg4B6QdkNZNxPc/nMaZSJPbeGeoUbs54LwoPICp
# JKGmiS1P+4uV8gFqC4bAA0i4jd3GlRfxWi1RXDffmsXyaQF86Rc/6pJ9ar+CMM63
# az/Gr4Ex+kwSURuwgXMimlEK7AmNv9hQbiPUf5lUztgmMyA6+DX9XkdurNyoX7dK
# awM63GDLB74TJMXVdh4Ji5e2Fvc4Y57KaYc2n/WSz10k4t/bBvrZ4HktQt5wUkC5
# CCdEds3qC2Kit+299vRuDw6r7mdVZiPvmD/BW7FyeTwVD7FTFzsBXWkU5SOYgN2x
# 89eNnpQ8pJqJ5U0qP/s=
# SIG # End signature block
