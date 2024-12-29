# Linux Privilege Escalation for OSCP Exam

## Table of Contents

1. [Introduction](#introduction)
2. [Enumeration](#enumeration)
   - [Basic Commands](#basic-commands)
   - [Tools for Enumeration](#tools-for-enumeration)
3. [Kernel Exploits](#kernel-exploits)
4. [Weak File Permissions](#weak-file-permissions)
   - [Files](#files)
   - [Directories](#directories)
5. [SUID/SGID Binaries](#suidsgid-binaries)
6. [Cron Jobs and Scheduled Tasks](#cron-jobs-and-scheduled-tasks)
7. [Path Abuse](#path-abuse)
8. [Exploiting Writable Configuration Files](#exploiting-writable-configuration-files)
9. [Password Hunting](#password-hunting)
10. [Network Services](#network-services)
11. [Custom Exploits](#custom-exploits)
12. [Checklist for OSCP](#checklist-for-oscp)
13. [References](#references)

## Introduction
Privilege escalation is a critical step in penetration testing. This guide is tailored for OSCP preparation and covers various techniques to escalate privileges on Linux systems.

## Enumeration
Enumeration is key to privilege escalation. Use the following commands and tools:

### Basic Commands
```bash
# System information
echo "Kernel: $(uname -a)"
echo "OS: $(cat /etc/*-release)"

# Users and groups
cat /etc/passwd
cat /etc/group
id
whoami

# Active users
w
who

# Processes
ps aux

# Environment variables
printenv
```

### Tools for Enumeration
- [LinPEAS](https://github.com/carlospolop/PEASS-ng) 
- [LinEnum](https://github.com/rebootuser/LinEnum)
- [Linux Exploit Suggester](https://github.com/mzet-/linux-exploit-suggester)

## Kernel Exploits
Identify kernel version using `uname -r` and search for public exploits:

```bash
searchsploit <kernel_version>
```

Example:
```bash
searchsploit 4.15.0-20-generic
```

## Weak File Permissions

### Files
- Check for sensitive files:
```bash
find / -type f -perm -04000 -ls 2>/dev/null
```

- Look for writable files:
```bash
find / -type f -writable 2>/dev/null
```

### Directories
- Writable directories:
```bash
find / -type d -writable 2>/dev/null
```

## SUID/SGID Binaries
Check for binaries with SUID/SGID permissions:
```bash
find / -perm -4000 2>/dev/null
find / -perm -2000 2>/dev/null
```

Search for exploits:
- [GTFOBins](https://gtfobins.github.io)

## Cron Jobs and Scheduled Tasks
Enumerate cron jobs:
```bash
cat /etc/crontab
ls -la /etc/cron.*
```

## Path Abuse
If a binary is running as root but does not use absolute paths, you can exploit the PATH variable.

Example:
```bash
export PATH=/tmp:$PATH
echo '/bin/bash' > /tmp/ls
chmod +x /tmp/ls
```

## Exploiting Writable Configuration Files
Identify writable configuration files for services:
```bash
find / -name "*.conf" -writable 2>/dev/null
```

Modify configurations to inject malicious commands or code.

## Password Hunting
Search for plaintext passwords in files:
```bash
grep -i password /etc/* 2>/dev/null
grep -i password ~/.* 2>/dev/null
```

Check bash history:
```bash
cat ~/.bash_history
```

## Network Services
Check listening services:
```bash
netstat -tuln
ss -tuln
```

Enumerate running services and associated configurations.

## Custom Exploits
Sometimes, custom scripts or binaries may have vulnerabilities. Review custom software carefully.

## Checklist for OSCP
- Enumerate thoroughly.
- Run LinPEAS or LinEnum.
- Check kernel version and search for exploits.
- Look for SUID/SGID binaries.
- Check cron jobs and PATH abuse.
- Search for writable configuration files.
- Hunt for passwords in files and history.

## References
- [GTFOBins](https://gtfobins.github.io)
- [PEASS-ng](https://github.com/carlospolop/PEASS-ng)
- [Linux Exploit Suggester](https://github.com/mzet-/linux-exploit-suggester)
