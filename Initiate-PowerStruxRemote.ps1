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

.EXAMPLE
    Initiate-PowerStruxRemote -ComputerName "RemoteServer" -ExePath "C:\Path\To\Initiate-PowerStruxWA.exe"
    Initiates the execution of PowerStruxWA on the "RemoteServer" using the specified executable path.
#>

    param (
        [Parameter(Mandatory = $false)]
        $ComputerName = "localhost",
        [Parameter(Mandatory = $false)]
        $ExePath = "C:\Program Files\WindowsPowerShell\Modules\ReportHTML\Initiate-PowerStruxWA.exe" 
    )

    #Create an array that contains the target Computer Name, IP Addresses, and localhost.
    #The array will be compared against the $ComputerName parameter to whether the target is local or remote.
    $arrIsLocalHost = @()
    $arrIsLocalHost += Get-NetIPAddress | Select-Object -ExpandProperty IPAddress
    $arrIsLocalHost += $env:COMPUTERNAME
    $arrIsLocalHost += "localhost"

    #If the target is the local computer then set the $boolIsLocalHost variable to $true, otherwise set it to $false.
    #This allows the script to dynamically assign cmdlet parameters based on local or remote status.
    if ($arrIsLocalHost.Contains($ComputerName)) {

        $boolIsLocalHost = $true

    }
    else {

        $boolIsLocalHost = $false

    }

    $boolUncOutputPath = $false

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
# MIIoLwYJKoZIhvcNAQcCoIIoIDCCKBwCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDYzd87u4FA/Daj
# u0emIMeD4uu3UMsXZNbL5qXQfL8e3KCCDZwwggawMIIEmKADAgECAhAIrUCyYNKc
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
# yK+p/pQd52MbOoZWeE4wggbkMIIEzKADAgECAhAH/0yvu7eBded80pbvoD4hMA0G
# CSqGSIb3DQEBCwUAMGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwg
# SW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBDb2RlIFNpZ25pbmcg
# UlNBNDA5NiBTSEEzODQgMjAyMSBDQTEwHhcNMjMwODI5MDAwMDAwWhcNMjQwODMx
# MjM1OTU5WjBsMQswCQYDVQQGEwJVUzEVMBMGA1UECBMMUGVubnN5bHZhbmlhMRIw
# EAYDVQQHEwlMYW5jYXN0ZXIxGDAWBgNVBAoTD1NlY3VyZVN0cnV4IExMQzEYMBYG
# A1UEAxMPU2VjdXJlU3RydXggTExDMIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIB
# igKCAYEAw3iYi9KyJIcnbw+W090KiuCWwoxkM/EHlhr2cR7PMjndrDKxHjKpiC9x
# 5hxPuVwwOTlt0eZNfzu9nPcGobdDQqWO/D8inNksx71yf1KxXPbXtg3Lpbuf9GIC
# MTQDOglYiUKzBEGTAEw+miMsQC0dGZ0MyPTZrZiBNwgUmqfG7tgbT8VaB/jzYOfH
# fD0V0AOgeJId2AFrqSJFlqKS/m7+MJN46qdc/9yFY+RI3s6Dt6tx0yVNEcGn+B4x
# xnYtu+jHlySb2XjDJ92jBv/3L3znmOLaQFuBo4oYzNoeeJl4fQJOTJmo1t/VPZQ4
# Z82IeqZnV7lk5ZEgaS+wNztN4I5TGOwTSi8NQHq2mKzz1P8b0E/uDw7RxV8KRAEk
# oMohB/QvGTeIoXxNPc2cIWrA/abV+a17ca2loD1j+W/fPBEstynTHYN9ISAhpCZA
# OwJTizH9EdwGdej3mAXUhXnqjrxsOF+Q5yGraC3H/mKoVvIWiH5KmihdjV/5Xbza
# MopJLgfJAgMBAAGjggIDMIIB/zAfBgNVHSMEGDAWgBRoN+Drtjv4XxGG+/5hewiI
# ZfROQjAdBgNVHQ4EFgQUYz9Uzgu7PMLJfQEP/3nk4ROVXskwDgYDVR0PAQH/BAQD
# AgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMDMIG1BgNVHR8Ega0wgaowU6BRoE+GTWh0
# dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRHNENvZGVTaWdu
# aW5nUlNBNDA5NlNIQTM4NDIwMjFDQTEuY3JsMFOgUaBPhk1odHRwOi8vY3JsNC5k
# aWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkRzRDb2RlU2lnbmluZ1JTQTQwOTZT
# SEEzODQyMDIxQ0ExLmNybDA+BgNVHSAENzA1MDMGBmeBDAEEATApMCcGCCsGAQUF
# BwIBFhtodHRwOi8vd3d3LmRpZ2ljZXJ0LmNvbS9DUFMwgZQGCCsGAQUFBwEBBIGH
# MIGEMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wXAYIKwYB
# BQUHMAKGUGh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0
# ZWRHNENvZGVTaWduaW5nUlNBNDA5NlNIQTM4NDIwMjFDQTEuY3J0MAkGA1UdEwQC
# MAAwDQYJKoZIhvcNAQELBQADggIBAFXjLbeuGu/aaEkOrKyu1msYK/RWC1mR/734
# nflq0P8+dIca16iAF84b+u2z69j05Vm8atbK/d1Jk5C70RVWPwt2Vp4KMiV370ax
# lMdS9iJKayrBeSUMep4ZMQvEYo5LHN83+1wR1AcpY4G2OZm6c0kBUB1tzXcMYZMm
# JWt07IoeE0Sk+9j/tX/HMZnq0V8RDX0SNJYqEF1vuLB1AQoLA8SrGYtYuN2eRgS7
# IDWD8y5CgWhPwDG7B2F6SAURbvJuk7cSOLuRXrPFyLZRs17Ypillm0xDmiaSKhuC
# 5rS0A1KvmCr4i6sP7s9tcXKM+xQyeELvId/87Bm6Ki2ZvmlY1OKsntH0szC6sEOU
# OD4vCRXFwGXx8PEoMJzdovcCi55V9BhHpOYErgHvj4iPDHH8S6U2rWc43WG18gf+
# 6Jhr8V75ibCL4ZzKT1GLbDkm+rIzKT6aFE1rKISGSuPYOnx431eBcEB6/BOy8rtx
# PWHFCG5RaMp0fTSDZ5USr5KceUnz6pfU3J1rGo0IcbzuwlEd3G2RrnVO3k1CxLsT
# kbMjHNdpATEgjVRbTZSfXMktmCUwIjSiKhWctagf2GRM9XUqMemvVxt6rNprUx7M
# 7TWyUymVHB/Y/hCRYw9t0o3ULq+eM+5VKwtPzxndDUj1++PyilZ7z/zyLszl5UcO
# VsoTSa63MYIZ6TCCGeUCAQEwfTBpMQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGln
# aUNlcnQsIEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0IFRydXN0ZWQgRzQgQ29kZSBT
# aWduaW5nIFJTQTQwOTYgU0hBMzg0IDIwMjEgQ0ExAhAH/0yvu7eBded80pbvoD4h
# MA0GCWCGSAFlAwQCAQUAoHwwEAYKKwYBBAGCNwIBDDECMAAwGQYJKoZIhvcNAQkD
# MQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJ
# KoZIhvcNAQkEMSIEIHJQiI6B24PegQYMCEf0+vADon8bOuiwJV/AbYbSqt/8MA0G
# CSqGSIb3DQEBAQUABIIBgGJ2l9oGdx978lUw/qrXfoN7pjhxqv3sRV3+NyeSh6Ew
# 2D2vzn12JUSvjBYRtY834JXZpQ7aIrT5OJwPZxCHLDKJqEuDgpraKMzKS5jcBlqk
# Zgxxi7tYNHC2PNhcYSUZbyLmp9JDI4UjQwXitHxdTHk7Q94E9jHje6xIyZ3OnQQN
# m5Mxqutymb09Gd9UmFQtSCKL1cTgx+Ml9aE2O0pKsf+7Gt/BZoGMyBfuI4aLFAKM
# gafCP/yynZm0o7B+OUnLdPD2ADCWVH0YodlEYRfbLivn4qdtdM8Qts6YROPbsAei
# H+M+wQaFhpwO7tjhGWLFjALRuUPpZUC8iGawgYKNnDDna/yLYivwNXsDwrfnKXcW
# Hr7DnbBxTq1FkyBoPEg5YtYhtbVrW8OAvtnk76BQDDMfMgF8TptAcTLY69FylFOP
# TXb0C6FPMpe5cPtez473PhAWAWLGjO3UX7yMzHEUnSJGuopNeaQzYk3U8jEBnZ16
# G243jm6Dy8BYzpNB7dwps6GCFz8wghc7BgorBgEEAYI3AwMBMYIXKzCCFycGCSqG
# SIb3DQEHAqCCFxgwghcUAgEDMQ8wDQYJYIZIAWUDBAIBBQAwdwYLKoZIhvcNAQkQ
# AQSgaARmMGQCAQEGCWCGSAGG/WwHATAxMA0GCWCGSAFlAwQCAQUABCC/Wu7Y5t20
# aLfTmkvSpWYQbQdvxruomzA5I+LuRLLT1wIQM7LTvpS9nKA5O3TH6hsNJRgPMjAy
# NDA4MjgxODQ0MTNaoIITCTCCBsIwggSqoAMCAQICEAVEr/OUnQg5pr/bP1/lYRYw
# DQYJKoZIhvcNAQELBQAwYzELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0
# LCBJbmMuMTswOQYDVQQDEzJEaWdpQ2VydCBUcnVzdGVkIEc0IFJTQTQwOTYgU0hB
# MjU2IFRpbWVTdGFtcGluZyBDQTAeFw0yMzA3MTQwMDAwMDBaFw0zNDEwMTMyMzU5
# NTlaMEgxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjEgMB4G
# A1UEAxMXRGlnaUNlcnQgVGltZXN0YW1wIDIwMjMwggIiMA0GCSqGSIb3DQEBAQUA
# A4ICDwAwggIKAoICAQCjU0WHHYOOW6w+VLMj4M+f1+XS512hDgncL0ijl3o7Kpxn
# 3GIVWMGpkxGnzaqyat0QKYoeYmNp01icNXG/OpfrlFCPHCDqx5o7L5Zm42nnaf5b
# w9YrIBzBl5S0pVCB8s/LB6YwaMqDQtr8fwkklKSCGtpqutg7yl3eGRiF+0XqDWFs
# nf5xXsQGmjzwxS55DxtmUuPI1j5f2kPThPXQx/ZILV5FdZZ1/t0QoRuDwbjmUpW1
# R9d4KTlr4HhZl+NEK0rVlc7vCBfqgmRN/yPjyobutKQhZHDr1eWg2mOzLukF7qr2
# JPUdvJscsrdf3/Dudn0xmWVHVZ1KJC+sK5e+n+T9e3M+Mu5SNPvUu+vUoCw0m+Pe
# bmQZBzcBkQ8ctVHNqkxmg4hoYru8QRt4GW3k2Q/gWEH72LEs4VGvtK0VBhTqYggT
# 02kefGRNnQ/fztFejKqrUBXJs8q818Q7aESjpTtC/XN97t0K/3k0EH6mXApYTAA+
# hWl1x4Nk1nXNjxJ2VqUk+tfEayG66B80mC866msBsPf7Kobse1I4qZgJoXGybHGv
# PrhvltXhEBP+YUcKjP7wtsfVx95sJPC/QoLKoHE9nJKTBLRpcCcNT7e1NtHJXwik
# cKPsCvERLmTgyyIryvEoEyFJUX4GZtM7vvrrkTjYUQfKlLfiUKHzOtOKg8tAewID
# AQABo4IBizCCAYcwDgYDVR0PAQH/BAQDAgeAMAwGA1UdEwEB/wQCMAAwFgYDVR0l
# AQH/BAwwCgYIKwYBBQUHAwgwIAYDVR0gBBkwFzAIBgZngQwBBAIwCwYJYIZIAYb9
# bAcBMB8GA1UdIwQYMBaAFLoW2W1NhS9zKXaaL3WMaiCPnshvMB0GA1UdDgQWBBSl
# tu8T5+/N0GSh1VapZTGj3tXjSTBaBgNVHR8EUzBRME+gTaBLhklodHRwOi8vY3Js
# My5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkRzRSU0E0MDk2U0hBMjU2VGlt
# ZVN0YW1waW5nQ0EuY3JsMIGQBggrBgEFBQcBAQSBgzCBgDAkBggrBgEFBQcwAYYY
# aHR0cDovL29jc3AuZGlnaWNlcnQuY29tMFgGCCsGAQUFBzAChkxodHRwOi8vY2Fj
# ZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkRzRSU0E0MDk2U0hBMjU2
# VGltZVN0YW1waW5nQ0EuY3J0MA0GCSqGSIb3DQEBCwUAA4ICAQCBGtbeoKm1mBe8
# cI1PijxonNgl/8ss5M3qXSKS7IwiAqm4z4Co2efjxe0mgopxLxjdTrbebNfhYJwr
# 7e09SI64a7p8Xb3CYTdoSXej65CqEtcnhfOOHpLawkA4n13IoC4leCWdKgV6hCmY
# tld5j9smViuw86e9NwzYmHZPVrlSwradOKmB521BXIxp0bkrxMZ7z5z6eOKTGnai
# aXXTUOREEr4gDZ6pRND45Ul3CFohxbTPmJUaVLq5vMFpGbrPFvKDNzRusEEm3d5a
# l08zjdSNd311RaGlWCZqA0Xe2VC1UIyvVr1MxeFGxSjTredDAHDezJieGYkD6tSR
# N+9NUvPJYCHEVkft2hFLjDLDiOZY4rbbPvlfsELWj+MXkdGqwFXjhr+sJyxB0Joz
# Sqg21Llyln6XeThIX8rC3D0y33XWNmdaifj2p8flTzU8AL2+nCpseQHc2kTmOt44
# OwdeOVj0fHMxVaCAEcsUDH6uvP6k63llqmjWIso765qCNVcoFstp8jKastLYOrix
# RoZruhf9xHdsFWyuq69zOuhJRrfVf8y2OMDY7Bz1tqG4QyzfTkx9HmhwwHcK1ALg
# XGC7KP845VJa1qwXIiNO9OzTF/tQa/8Hdx9xl0RBybhG02wyfFgvZ0dl5Rtztpn5
# aywGRu9BHvDwX+Db2a2QgESvgBBBijCCBq4wggSWoAMCAQICEAc2N7ckVHzYR6z9
# KGYqXlswDQYJKoZIhvcNAQELBQAwYjELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERp
# Z2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTEhMB8GA1UEAxMY
# RGlnaUNlcnQgVHJ1c3RlZCBSb290IEc0MB4XDTIyMDMyMzAwMDAwMFoXDTM3MDMy
# MjIzNTk1OVowYzELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMu
# MTswOQYDVQQDEzJEaWdpQ2VydCBUcnVzdGVkIEc0IFJTQTQwOTYgU0hBMjU2IFRp
# bWVTdGFtcGluZyBDQTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAMaG
# NQZJs8E9cklRVcclA8TykTepl1Gh1tKD0Z5Mom2gsMyD+Vr2EaFEFUJfpIjzaPp9
# 85yJC3+dH54PMx9QEwsmc5Zt+FeoAn39Q7SE2hHxc7Gz7iuAhIoiGN/r2j3EF3+r
# GSs+QtxnjupRPfDWVtTnKC3r07G1decfBmWNlCnT2exp39mQh0YAe9tEQYncfGpX
# evA3eZ9drMvohGS0UvJ2R/dhgxndX7RUCyFobjchu0CsX7LeSn3O9TkSZ+8OpWNs
# 5KbFHc02DVzV5huowWR0QKfAcsW6Th+xtVhNef7Xj3OTrCw54qVI1vCwMROpVymW
# Jy71h6aPTnYVVSZwmCZ/oBpHIEPjQ2OAe3VuJyWQmDo4EbP29p7mO1vsgd4iFNmC
# KseSv6De4z6ic/rnH1pslPJSlRErWHRAKKtzQ87fSqEcazjFKfPKqpZzQmiftkaz
# nTqj1QPgv/CiPMpC3BhIfxQ0z9JMq++bPf4OuGQq+nUoJEHtQr8FnGZJUlD0UfM2
# SU2LINIsVzV5K6jzRWC8I41Y99xh3pP+OcD5sjClTNfpmEpYPtMDiP6zj9NeS3YS
# UZPJjAw7W4oiqMEmCPkUEBIDfV8ju2TjY+Cm4T72wnSyPx4JduyrXUZ14mCjWAkB
# KAAOhFTuzuldyF4wEr1GnrXTdrnSDmuZDNIztM2xAgMBAAGjggFdMIIBWTASBgNV
# HRMBAf8ECDAGAQH/AgEAMB0GA1UdDgQWBBS6FtltTYUvcyl2mi91jGogj57IbzAf
# BgNVHSMEGDAWgBTs1+OC0nFdZEzfLmc/57qYrhwPTzAOBgNVHQ8BAf8EBAMCAYYw
# EwYDVR0lBAwwCgYIKwYBBQUHAwgwdwYIKwYBBQUHAQEEazBpMCQGCCsGAQUFBzAB
# hhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wQQYIKwYBBQUHMAKGNWh0dHA6Ly9j
# YWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRSb290RzQuY3J0MEMG
# A1UdHwQ8MDowOKA2oDSGMmh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2Vy
# dFRydXN0ZWRSb290RzQuY3JsMCAGA1UdIAQZMBcwCAYGZ4EMAQQCMAsGCWCGSAGG
# /WwHATANBgkqhkiG9w0BAQsFAAOCAgEAfVmOwJO2b5ipRCIBfmbW2CFC4bAYLhBN
# E88wU86/GPvHUF3iSyn7cIoNqilp/GnBzx0H6T5gyNgL5Vxb122H+oQgJTQxZ822
# EpZvxFBMYh0MCIKoFr2pVs8Vc40BIiXOlWk/R3f7cnQU1/+rT4osequFzUNf7WC2
# qk+RZp4snuCKrOX9jLxkJodskr2dfNBwCnzvqLx1T7pa96kQsl3p/yhUifDVinF2
# ZdrM8HKjI/rAJ4JErpknG6skHibBt94q6/aesXmZgaNWhqsKRcnfxI2g55j7+6ad
# cq/Ex8HBanHZxhOACcS2n82HhyS7T6NJuXdmkfFynOlLAlKnN36TU6w7HQhJD5TN
# OXrd/yVjmScsPT9rp/Fmw0HNT7ZAmyEhQNC3EyTN3B14OuSereU0cZLXJmvkOHOr
# pgFPvT87eK1MrfvElXvtCl8zOYdBeHo46Zzh3SP9HSjTx/no8Zhf+yvYfvJGnXUs
# HicsJttvFXseGYs2uJPU5vIXmVnKcPA3v5gA3yAWTyf7YGcWoWa63VXAOimGsJig
# K+2VQbc61RWYMbRiCQ8KvYHZE/6/pNHzV9m8BPqC3jLfBInwAM1dwvnQI38AC+R2
# AibZ8GV2QqYphwlHK+Z/GqSFD/yYlvZVVCsfgPrA8g4r5db7qS9EFUrnEw4d2zc4
# GqEr9u3WfPwwggWNMIIEdaADAgECAhAOmxiO+dAt5+/bUOIIQBhaMA0GCSqGSIb3
# DQEBDAUAMGUxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAX
# BgNVBAsTEHd3dy5kaWdpY2VydC5jb20xJDAiBgNVBAMTG0RpZ2lDZXJ0IEFzc3Vy
# ZWQgSUQgUm9vdCBDQTAeFw0yMjA4MDEwMDAwMDBaFw0zMTExMDkyMzU5NTlaMGIx
# CzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3
# dy5kaWdpY2VydC5jb20xITAfBgNVBAMTGERpZ2lDZXJ0IFRydXN0ZWQgUm9vdCBH
# NDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAL/mkHNo3rvkXUo8MCIw
# aTPswqclLskhPfKK2FnC4SmnPVirdprNrnsbhA3EMB/zG6Q4FutWxpdtHauyefLK
# EdLkX9YFPFIPUh/GnhWlfr6fqVcWWVVyr2iTcMKyunWZanMylNEQRBAu34LzB4Tm
# dDttceItDBvuINXJIB1jKS3O7F5OyJP4IWGbNOsFxl7sWxq868nPzaw0QF+xembu
# d8hIqGZXV59UWI4MK7dPpzDZVu7Ke13jrclPXuU15zHL2pNe3I6PgNq2kZhAkHnD
# eMe2scS1ahg4AxCN2NQ3pC4FfYj1gj4QkXCrVYJBMtfbBHMqbpEBfCFM1LyuGwN1
# XXhm2ToxRJozQL8I11pJpMLmqaBn3aQnvKFPObURWBf3JFxGj2T3wWmIdph2PVld
# QnaHiZdpekjw4KISG2aadMreSx7nDmOu5tTvkpI6nj3cAORFJYm2mkQZK37AlLTS
# YW3rM9nF30sEAMx9HJXDj/chsrIRt7t/8tWMcCxBYKqxYxhElRp2Yn72gLD76GSm
# M9GJB+G9t+ZDpBi4pncB4Q+UDCEdslQpJYls5Q5SUUd0viastkF13nqsX40/ybzT
# QRESW+UQUOsxxcpyFiIJ33xMdT9j7CFfxCBRa2+xq4aLT8LWRV+dIPyhHsXAj6Kx
# fgommfXkaS+YHS312amyHeUbAgMBAAGjggE6MIIBNjAPBgNVHRMBAf8EBTADAQH/
# MB0GA1UdDgQWBBTs1+OC0nFdZEzfLmc/57qYrhwPTzAfBgNVHSMEGDAWgBRF66Kv
# 9JLLgjEtUYunpyGd823IDzAOBgNVHQ8BAf8EBAMCAYYweQYIKwYBBQUHAQEEbTBr
# MCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wQwYIKwYBBQUH
# MAKGN2h0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEFzc3VyZWRJ
# RFJvb3RDQS5jcnQwRQYDVR0fBD4wPDA6oDigNoY0aHR0cDovL2NybDMuZGlnaWNl
# cnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElEUm9vdENBLmNybDARBgNVHSAECjAIMAYG
# BFUdIAAwDQYJKoZIhvcNAQEMBQADggEBAHCgv0NcVec4X6CjdBs9thbX979XB72a
# rKGHLOyFXqkauyL4hxppVCLtpIh3bb0aFPQTSnovLbc47/T/gLn4offyct4kvFID
# yE7QKt76LVbP+fT3rDB6mouyXtTP0UNEm0Mh65ZyoUi0mcudT6cGAxN3J0TU53/o
# Wajwvy8LpunyNDzs9wPHh6jSTEAZNUZqaVSwuKFWjuyk1T3osdz9HNj0d1pcVIxv
# 76FQPfx2CWiEn2/K2yCNNWAcAgPLILCsWKAOQGPFmCLBsln1VWvPJ6tsds5vIy30
# fnFqI2si/xK4VC0nftg62fC2h5b9W9FcrBjDTZ9ztwGpn1eqXijiuZQxggN2MIID
# cgIBATB3MGMxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjE7
# MDkGA1UEAxMyRGlnaUNlcnQgVHJ1c3RlZCBHNCBSU0E0MDk2IFNIQTI1NiBUaW1l
# U3RhbXBpbmcgQ0ECEAVEr/OUnQg5pr/bP1/lYRYwDQYJYIZIAWUDBAIBBQCggdEw
# GgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEEMBwGCSqGSIb3DQEJBTEPFw0yNDA4
# MjgxODQ0MTNaMCsGCyqGSIb3DQEJEAIMMRwwGjAYMBYEFGbwKzLCwskPgl3OqorJ
# xk8ZnM9AMC8GCSqGSIb3DQEJBDEiBCBupIgMmg27nxb4cLZ2ARnvd59xyyQsYyQB
# kzHQW1OA7TA3BgsqhkiG9w0BCRACLzEoMCYwJDAiBCDS9uRt7XQizNHUQFdoQTZv
# goraVZquMxavTRqa1Ax4KDANBgkqhkiG9w0BAQEFAASCAgBgwQlJvupGTVfX6kb1
# 8R/GtykPK99ZR3Qpy2N/YJVT2XmKYN7vtk6qu0Z6TZ3uWRlvTXUPTaYyr/hvVMfy
# BTiC0RWU8VKqh1P4kn5E/lGf3JaZO53kT2TfsCj/SheP7RCGd92w47oPM1FfFfAm
# EHwDsqggZcXNpADXNqllEPe8k01oChHzYUcixoTVMM26UCBpQQNOfUzvjdvC+l4d
# ucscqEQj6DI1UYYTUoa+8RwjacV5fR1mRltAEg3GyKuOYv18tiG4FcGoHUZpMzRK
# o0LJ9E0Svw82aCMnQozOUC4e/3hYv2BQe8T8ukmXyZR4rOdidAVCT+PNfgD2dpY9
# x8PSL8o4S9MOtuw21Rp6/z07zAFzXPw4IdOM50kKJjyltGZQkjhLQYqgtKl+LUXc
# bbAUsVC6d2JmUfDXb5NCETPA8H4UDgKluDopokc4MejSV7ji6P6jxeUtwpbehfRo
# DFYYEj9FDI0Sdv4GV3yZljJR6pQzskh+cevclh5X0iNqRgjcRmDPG4tykChyUHKD
# 4gyzeMcEQEp8068iQcAw6Qk0aerrSQVTekapfwuvNQKrDj5WOsYqdtziEJFgK0Vt
# A6ELpvybsXfPaQI1McshbOYp0mSE6ASoJmH6BQHDzdeBPXFKwktsV6XPhOBkuPOi
# I+wwu2CmeaL9aE5DFsEjs/iuiA==
# SIG # End signature block
