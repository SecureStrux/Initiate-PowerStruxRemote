# Initiate-PowerStruxRemote

This PowerShell script is designed to initiate the execution of the `PowerStruxWA` application on either a local or remote computer. Click [here](https://powerstrux.com/) for more information on `PowerStruxWA`.

---

## Requirements

- **Execution Policy**:  
  The PowerShell execution policy must be set to `RemoteSigned` or less restrictive. You can set it by running the following command in PowerShell:

  ```powershell
  Set-ExecutionPolicy RemoteSigned -Scope Process
  
- **Network Access**:  
  For remote execution, the machine running the script must be able to communicate over the network with the target system (i.e., no firewall or network restrictions should block the communication). Required ports include:
  - WinRM (5985/tcp)
  - WinRM (5986/tcp)
  - SMB (445/tcp)
  - NetBIOs (139/tcp)
  - ICMP

- **WinRM Configuration**:  
  On remote machines, WinRM must be properly configured. This includes:
  - The WinRM service must be enabled.
  - The machine must be configured to accept remote PowerShell commands (`Enable-PSRemoting`).

- **Access to `C$` Share**:  
  The script attempts to access `C$\` on remote systems (e.g., `\\$ComputerName\c$`). The user executing the script must have access to the `C$` administrative share on the remote system.

- **File Path Accessibility**:  
  The script assumes that the PowerStruxWA executable and the configuration file (`PowerStruxWAConfig.txt`) are located at predefined paths (`C:\Program Files\WindowsPowerShell\Modules\ReportHTML`). If the paths are different, the script may fail unless those paths are modified.

- **Permissions on the Target System**:  
  The script requires administrative privileges on both the local and remote systems to:
  - Start/stop services (e.g., WinRM).
  - Access administrative shares (`C$`).
  - Execute processes on remote machines via PowerShell Remoting.

- **UNC Path Access**:  
  If the configuration file specifies a UNC path for storing reports, the script assumes that the necessary network paths are accessible. The user executing the script needs appropriate permissions to write to the UNC path.

## Parameters

### `ComputerName`
- **Type**: `String`
- **Description**: Specifies the target computer's hostname. Default is `localhost`.
- **Example**: `"RemoteServer"`

### `ExePath`
- **Type**: `String`
- **Description**: Specifies the file path of the PowerStruxWA executable. Default is `"C:\Program Files\WindowsPowerShell\Modules\ReportHTML\Initiate-PowerStruxWA.exe"`.
- **Example**: `"C:\Path\To\Initiate-PowerStruxWA.exe"`

### `GlobalConfig`
- **Type**: `String`
- **Description**: Specifies the path to a global configuration file (PowerStruxWAConfig.txt) to be deployed on the remote or local machine.
- **Example**: `"C:\Path\To\PowerStruxWAConfig.txt"`
  
## How It Works

1. **Determine Local or Remote Execution**:  
   The script checks if the target computer is the local machine or a remote machine. If the target is remote, it proceeds with the necessary configuration and checks.

2. **Connectivity Test**:  
   If the target is remote, the script tests the connectivity using ICMP. If the connection fails, the script exits with an error message.

3. **WinRM Setup for Remote Machines**:  
   If the target is remote, the script ensures that the WinRM service is running. If not, it attempts to start it. If starting WinRM fails, the script stops.

4. **Configuration File Handling**:  
   The script checks for the existence of the `PowerStruxWAConfig.txt` file on the target system and attempts to read it for configuration data. If the file is missing or unreadable, it asks the user to run `PowerStruxWA` manually.

5. **Report Location Handling**:  
   If the configuration file specifies a UNC path for report storage, the script updates the report location in the configuration file and moves the report to the specified UNC path.

6. **Executing PowerStruxWA**:  
   Once the setup is complete, the script runs the `PowerStruxWA` executable on the target machine. If the executable is missing or fails to run, the script stops and provides an error message.

7. **WinRM Service Cleanup**:  
   After execution, if the target was remote, the script stops the WinRM service on the remote machine.

## Usage

1. Download the repository as a ZIP archive from GitHub.
2. Extract the ZIP archive to a known location (e.g., `C:\Scripts\InitiatePowerStrux`).
3. Open PowerShell **as Administrator**.
4. Change to the extracted directory:
   ```powershell
   Set-Location -Path "C:\Scripts\InitiatePowerStrux"
   ```
5. Run the script with appropriate parameters. Example:
   ```powershell
   .\Initiate-PowerStruxRemote.ps1 -ComputerName "Server01"
   ```
6. Execute the function.

## Examples

### Example 1: Running Locally
```powershell
.\Initiate-PowerStruxRemote.ps1 -ComputerName "localhost" -ExePath "C:\Path\To\PowerStruxWA.exe"
```
This will run the PowerStruxWA application on the local machine.
   
### Example 2: Running Remotely on a Single Machine
```powershell
.\Initiate-PowerStruxRemote.ps1 -ComputerName "Host01"
```
This will run the PowerStruxWA application remotely on `Host01`.

### Example 3: Running Remotely on a Multiple Machines
To target multiple systems, you can create a file named `target-hosts.txt`, which contains a list of hostnames (one per line). Then, use the following command to loop through each hostname and execute the function:

1. Create a `target-hosts.txt` file
 - Example file contents:
   ```
   Host01
   Host02
   Host03
   ```
2. Execute the loop within the open PowerShell session:
    ```powershell
    Get-Content 'C:\Path\To\target-hosts.txt' | ForEach-Object {
        .\Initiate-PowerStruxRemote.ps1 -ComputerName $_ -GlobalConfig "C:\Path\To\PowerStruxWAConfig.txt"
    }
    ```
This command reads each hostname from the target-hosts.txt file and passes it to the Initiate-PowerStruxRemote function for execution. The script will execute based on the variables defined within the `C:\Path\To\PowerStruxWAConfig.txt` global configuration file (`GlobalConfig`).
