<IMAGE>

# Threat Hunt Report: Unauthorized Tor Usage

## Technologies Used
- Azure Virtual Machines – Windows 11 Pro
- Endpoint Detection and Response – Microsoft Defender for Endpoint
- Language – Kusto Query Language, PowerShell
- Tor Browser

##  Scenario

Management has identified potential security violations involving the use of Tor browsers to bypass network controls. This suspicion is based on anomalies in encrypted traffic, connections to known Tor entry nodes, and anonymous reports regarding the access of restricted content. The objective is to identify any unauthorized Tor usage and analyze the associated security risks. Please escalate any confirmed instances of Tor activity to management immediately.

### High-Level Tor-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `Tor` or `Firefox` file events.
- **Check `DeviceProcessEvents`** for clues suggesting it was deployed or utilized.
- **Check `DeviceNetworkEvents`** for indications of egress traffic utilizing known Tor network ports

---

## Steps Taken

### 1. Queried the `DeviceFileEvents` Table

Executed a wild card search for anything in the logs that contains the string “tor” under filename. It appears that the user, “ianwin11pro”, deployed a Tor package that extracted Tor files on the desktop at `2026-01-09T15:18:09.6935327Z`. The user then created `tor-shopping-list.txt` at `2026-01-09T16:24:14.9180089Z`. The events initially occurred at `2026-01-09T15:16:45.5688794Z`.

**Query:**

```kql
DeviceFileEvents  
| where DeviceName == "ian-win11pro"  
| where InitiatingProcessAccountName == "ianwin11pro"  
| where FileName contains "tor"  
| where Timestamp >= datetime(2026-01-09T15:16:45.5688794Z)  
| order by Timestamp desc  
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```
<IMAGE>

---

### 2. Queried the `DeviceProcessEvents` Table

Investigating into the `ProcessCommandLine` logs identified the specific methods of installation. At `2026-01-09T16:11:47.8795211Z`, the user “ianwin11pro” executed the file `tor-browser-windows-x86_64-portable-15.0.3.exe` located in the Downloads folder on the “ian-win11pro” device. Notably, the process was initiated using command-line switches designed to perform a silent installation, effectively obscuring the setup process."

**Query:**

```kql
DeviceProcessEvents  
| where DeviceName == "ian-win11pro"  
| where ProcessCommandLine contains "tor-browser"  
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
<IMAGE>

---

### 3. Queried the `DeviceProcessEvents` Table for Tor Deployment

Further analysis was conducted to verify if the application was launched. Device process logs confirm that user "ian-win11pro" successfully executed the Tor browser starting at `2026-01-09T15:35:06.7684693Z`. Following this initial execution, multiple subsequent instances of `firefox.exe`–from the Tor folder and `tor.exe` were spawned, indicating active and sustained usage of the browser. The last being at `2026-01-09T16:12:57.828087Z`.

**Query:**

```kql
DeviceProcessEvents  
| where DeviceName == "ian-win11pro"  
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")  
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine  
| order by Timestamp desc
```
<IMAGE>

---

### 4. Queried the `DeviceNetworkEvents` Table for Successful Tor Network Connections

Network logs confirm active Tor connectivity. At `2026-01-09T15:38:48.2269957Z`, user "ianwin11pro" on the “ian-win11pro” device established an initial connection to `23.92.34.118` on port `443`. This connection stemmed from the `tor.exe` binary located within the user's Desktop directory at `C:\Users\ianwin11pro\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`. Subsequent outbound traffic was also recorded on port `9150`, `9001`, and `9030`.

**Query:**

```kql
DeviceNetworkEvents  
| where DeviceName == "ian-win11pro"  
| where InitiatingProcessAccountName != "system"  
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")  
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150", "80", "443")  
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath | order by Timestamp desc
```
<IMAGE>

---

## Chronological Event Timeline 

### 1. File Download - Tor Installer

- **Timestamp:** `2026-01-09T15:16:45.5688794Z`
- **Event:** File creation logs indicate that the user "ianwin11pro" acquired the Tor Browser installer, `tor-browser-windows-x86_64-portable-15.0.3.exe`, via download, saving the binary to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\ianwin11pro\Downloads\tor-browser-windows-x86_64-portable-15.0.3.exe`

### 2. Process Execution - Tor Browser Installation

- **Timestamp:** `2026-01-09T16:11:47.8795211Z`
- **Event:** Process execution logs indicate that the user "ianwin11pro" executed the file `tor-browser-windows-x86_64-portable-15.0.3.exe` in silent mode, effectively obscuring the installation process by forcing it to run in the background.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-15.0.3.exe /S`
- **File Path:** `C:\Users\ianwin11pro\Downloads\tor-browser-windows-x86_64-portable-15.0.3.exe`

### 3. Process Execution - Tor Browser Launch

- **Timestamp:** `2026-01-09T15:35:06.7684693Z`
- **Event:** Process analysis confirms that user "ianwin11pro" executed the Tor browser application. This action triggered a substantiated process tree, including `firefox.exe` and `tor.exe`, validating that the browser was successfully initialized and active.
- **Action:** Process creation of Tor browser-related executables detected.
- **File Path:** `C:\Users\ianwin11pro\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection - Tor Network

- **Timestamp:** `2026-01-09T15:38:48.2269957Z`
- **Event:** Network records indicate a successful outbound connection to IP `23.92.34.118` on port `443`, initiated by the `tor.exe` process under user "ianwin11pro". This event positively confirms active communication within the Tor network.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `C:\Users\ianwin11pro\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 5. Additional Network Connections - Tor Browser Activity

- **Timestamps:**
  - `2024-11-08T22:18:08Z` - Connected to `194.164.169.85` on port `443`.
  - `2024-11-08T22:18:16Z` - Local connection to `127.0.0.1` on port `9150`.
 
  - `2026-01-09T15:38:50.9621349Z` - Connected to `185.107.57.66` on port `443`. 
  - `2026-01-09T15:38:50.9740317Z` - Connected to `85.195.253.142` on port `9001`. 
  - `2026-01-09T16:14:33.3077177Z` - Connected to `152.53.115.49` on port `9001`. 
  - `2026-01-09T16:14:37.5635483Z` - Connected to `94.130.52.190` on port `9030`. 
  - `2026-01-09T15:38:50.9621349Z` - Connected to `37.59.175.224` on port `9001`. 
  - `2026-01-09T16:15:34.541804Z` - Connected to `88.198.27.62` on port `443`. 
  - `2026-01-09T15:39:04.9412058Z` - Local connection to `127.0.0.1` on port `9150`.
- **Event:** Observed traffic patterns, characterized by repeated outbound connections, serve as evidence of continuous active browsing by user "ianwin11pro" via the Tor application.
- **Action:** Multiple successful connections detected.

### 6. File Creation - Tor Shopping List

- **Timestamp:** `2026-01-09T16:24:14.9180089Z`
- **Event:** File creation logs reveal that user "ianwin11pro" generated a file named `tor-shopping-list.txt` directly on the Desktop. This artifact serves as contextual evidence, suggesting the user was actively documenting intended transactions within the Tor network.
- **Action:** File creation detected.
- **File Path:** `C:\Users\ianwin11pro\Desktop\tor-shopping-list.txt`

---

## Summary

Investigation confirms user "ianwin11pro" installed and actively used the Tor browser on the "ian-win11pro" device. Evidence includes successful network connections to Tor nodes and the creation of a suspicious text file (`tor-shopping-list.txt`) on the desktop. This pattern indicates intentional circumvention of network controls for anonymous browsing.

---

## Response Taken

Positive confirmation of Tor network activity was established on the endpoint `ian-win11pro` under the user account `ianwin11pro`. In accordance with incident response protocols, immediate containment measures were executed to isolate the device. The user's direct line management has been advised of the violation and subsequent mitigation actions.

---
