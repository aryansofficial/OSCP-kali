### Nmap Scripts

This is a mark down file just some continence

```
nmap -sP <network>                 # Ping scan (host discovery)
nmap -p- <network>                 # all ports
```

## **Operating System Detection**

```
nmap -O <target> # OS detection 
nmap -A <target> # OS + version + script scan
```

### **Evading Firewalls & IDS**

```
nmap -f <target>                     # Fragmented packets
nmap --mtu 16 <target>                # Custom packet size
nmap -D RND:10 <target>               # Decoy scan
nmap --data-length 200 <target>       # Add payload padding
nmap --spoof-mac 00:11:22:33:44:55 <target>  # MAC spoofing
```

### **Bypassing Firewalls with Source Port**

```
nmap --source-port 53 <target> # Spoof DNS port (bypass filters) nmap --source-port 443 <target> # Spoof HTTPS port
```

### **Scanning with NSE Scripts**

```
nmap --script=vuln <target>           # Scan for vulnerabilities
nmap --script=http-enum <target>      # Enumerate web services
nmap --script=smb-os-discovery <target>  # Discover SMB OS info
nmap --script=smb-vuln-ms17-010 <target> # Check for EternalBlue
```

#### **📌 HTTP (Web)**

- `http-title` → Get the title of the web page.
- `http-enum` → Enumerate common web directories and files.
- `http-server-header` → Get the web server version.
- `http-methods` → Check for risky HTTP methods (e.g., PUT, DELETE).
- `http-phpmyadmin-dir-traversal` → Check for phpMyAdmin directory traversal.
- `http-vuln-cve2017-5638` → Test for Apache Struts RCE.
- `http-sql-injection` → Basic SQL injection test.

#### **📌 SMB (Windows File Sharing)**

- `smb-enum-shares` → List available SMB shares.
- `smb-enum-users` → List SMB users.
- `smb-os-discovery` → Detect OS version via SMB.
- `smb-vuln-ms17-010` → Check for EternalBlue (WannaCry) vulnerability.
- `smb-vuln-ms08-067` → Check for an old remote code execution bug.
- `smb-vuln-ms10-054` → Test for DoS vulnerability.

#### **📌 FTP**

- `ftp-anon` → Check for anonymous access.
- `ftp-bounce` → Check for FTP bounce attacks.
- `ftp-syst` → Get FTP server system details.
- `ftp-vuln-cve2010-4221` → Test for a ProFTPD directory traversal vulnerability.

#### **📌 SSH**

- `ssh-hostkey` → Get the SSH host key.
- `ssh-auth-methods` → List authentication methods allowed.
- `ssh-brute` → Perform SSH brute-force attack.

#### **📌 MySQL**

- `mysql-info` → Get MySQL server info.
- `mysql-databases` → List databases (if access is allowed).
- `mysql-users` → List MySQL users.
- `mysql-empty-password` → Check if root password is empty.

---

#### **📌 RDP (Remote Desktop)**

- `rdp-enum-encryption` → Check for weak RDP encryption.
- `rdp-vuln-ms12-020` → Test for RDP DoS vulnerability.
- `rdp-ntlm-info` → Get NTLM info from RDP service.

#### **📌 Other Useful Scripts**

- `vulners` → Check for vulnerabilities in multiple services.
- `banner` → Grab service banners from open ports.
- `whois-domain` → Get WHOIS info for a domain.
- `ssl-cert` → Get SSL certificate details.
- `dns-brute` → Brute-force DNS subdomains.
- `snmp-brute` → Bruteforce SNMP community strings.

