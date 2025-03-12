# Windows Sensitive Files List

This document lists sensitive files on **regular Windows computers** and **Windows Domain Controllers**. These files may contain **password hashes, authentication tokens, registry settings, and system configurations** that are valuable for **privilege escalation and lateral movement**.

---

## 🖥️ Regular Windows Computer

### **1. System Information & Enumeration**
- `C:\Windows\System32\license.rtf` – Contains Windows version and license information.
- `C:\Windows\System32\config\SAM` – Stores local user account password hashes (requires SYSTEM access).
- `C:\Windows\System32\config\SYSTEM` – Contains system-wide settings, including encryption keys for some data.
- `C:\Windows\System32\config\SECURITY` – Stores LSA secrets (can contain cached credentials and service account passwords).
- `C:\Windows\System32\config\SOFTWARE` – Stores installed software information, registry settings, and sometimes plaintext credentials.
- `C:\Windows\System32\config\DEFAULT` – Stores the default user settings for new user profiles.

### **2. Credential Storage & Password Files**
#### **Windows Credential Manager & Hashes**
- `C:\Windows\System32\config\SAM` – Stores NTLM hashes of local user accounts.
- `C:\Windows\System32\config\SECURITY` – Contains cached domain credentials and LSA secrets.
- `C:\Windows\System32\config\SYSTEM` – Required to decrypt password hashes from SAM.

#### **RDP & Remote Access Credentials**
- `C:\Users\<username>\AppData\Local\Microsoft\Credentials\` – Stores saved credentials for network authentication.
- `C:\Users\<username>\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\` – May contain recently accessed files and network paths.
- `C:\Windows\System32\mstsc.exe` – The Remote Desktop client (may store session data).
- `C:\Windows\System32\config\Vault` – Stores passwords for Windows Vault.

#### **Web Browsers (Saved Passwords & Cookies)**
- `C:\Users\<username>\AppData\Local\Google\Chrome\User Data\Default\Login Data` – Chrome's saved login credentials (SQLite database).
- `C:\Users\<username>\AppData\Local\Microsoft\Edge\User Data\Default\Login Data` – Edge's saved login credentials.
- `C:\Users\<username>\AppData\Roaming\Mozilla\Firefox\Profiles\*.default\logins.json` – Firefox's saved login credentials.

#### **Wi-Fi Passwords**
- `C:\ProgramData\Microsoft\Wlansvc\Profiles\Interfaces\*` – Stores Wi-Fi network credentials.

### **3. Configuration Files & Logs**
- `C:\inetpub\wwwroot\web.config` – Web application settings, may contain database credentials.
- `C:\Windows\System32\inetsrv\Config\applicationHost.config` – IIS web server settings.
- `C:\Windows\System32\drivers\etc\hosts` – Stores manual IP-to-hostname mappings.
- `C:\Windows\System32\winevt\Logs\Security.evtx` – Stores security-related event logs.
- `C:\Windows\System32\winevt\Logs\Application.evtx` – Stores application event logs.

### **4. Backup & Shadow Copies**
- `C:\Windows\System32\config\RegBack\` – Registry backups.
- `C:\Windows\System32\wbem\Repository\` – Stores WMI repository data, which may contain system information.

### **5. Database & Service Credentials**
- `C:\Program Files\Microsoft SQL Server\MSSQLXX.SQLEXPRESS\MSSQL\DATA\master.mdf` – Stores SQL Server system data, including credentials.
- `C:\ProgramData\MySQL\MySQL Server X.X\data\` – Stores MySQL database files.

### **6. SSH & Remote Access Keys**
- `C:\Users\<username>\.ssh\id_rsa` – Private SSH key.
- `C:\Users\<username>\.ssh\known_hosts` – Trusted SSH hosts.
- `C:\Users\<username>\.ssh\config` – SSH client configuration.

---

## 🏢 Domain Controller (Active Directory) Sensitive Files

### **1. Active Directory (NTDS) Database & Registry**
- `C:\Windows\NTDS\ntds.dit` – Stores Active Directory user accounts and password hashes.
- `C:\Windows\System32\config\SYSTEM` – Required to decrypt the NTDS database.
- `C:\Windows\System32\config\SECURITY` – Contains LSA secrets and cached domain credentials.
- `C:\Windows\System32\GroupPolicy\Registry.pol` – Stores Group Policy registry settings.
- `C:\Windows\SYSVOL\domain\Policies\` – Stores domain-wide policy settings.

### **2. Kerberos Ticket & Domain Authentication**
- `C:\Windows\System32\kdc.log` – Kerberos authentication log.
- `C:\Windows\System32\config\kerberos.dll` – Stores Kerberos authentication information.
- `C:\Windows\SYSVOL\domain\scripts\` – Contains login scripts that may include plaintext passwords.

### **3. Domain Logs & Cached Credentials**
- `C:\Windows\System32\winevt\Logs\Directory Service.evtx` – Logs related to Active Directory events.
- `C:\Windows\System32\winevt\Logs\GroupPolicy.evtx` – Logs changes to Group Policy.

### **4. Domain Controller Backups & Replication Data**
- `C:\Windows\NTDS\edb.chk` – NTDS database checkpoint.
- `C:\Windows\NTDS\edb.log` – AD transaction logs.
- `C:\Windows\System32\wbem\Repository\` – Stores system-wide WMI data.

### **5. Backup & Shadow Copy Attacks**
- `C:\Windows\NTDS\ntds.dit` – Can be extracted using Volume Shadow Copy.
- `C:\Windows\System32\config\SYSTEM` – Required to decrypt NTDS.dit.

### **6. Windows Registry (Sensitive Data)**
#### **Registry Hives to Dump**
```powershell
reg save HKLM\SAM C:\temp\SAM
reg save HKLM\SYSTEM C:\temp\SYSTEM
reg save HKLM\SECURITY C:\temp\SECURITY
reg save HKLM\SOFTWARE C:\temp\SOFTWARE
```
#### **Look for Passwords in Registry**
```powershell
reg query HKLM\SYSTEM\CurrentControlSet\Services\ /s | findstr "Password"
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run /s
```

---

## 📌 Next Steps
- **Dump NTDS.dit & extract domain credentials** with `secretsdump.py`
- **Use Mimikatz** to dump LSASS memory and extract plaintext passwords.
- **Check IIS, SQL, and LDAP configs** for plaintext credentials.
- **Use `tasklist /svc` to list running services** and identify misconfigurations.

