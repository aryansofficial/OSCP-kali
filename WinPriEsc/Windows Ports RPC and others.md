Understanding common windows ports and services they run. These are not generally found on linux therefourth was a bit confusing for me.

## 🔍 Nmap Scan Results - Open Ports

| **Port**  | **State** | **Service**       | **Version / Notes** |
|----------|----------|------------------|---------------------|
| **80**   | Open    | **HTTP**          | **GoAhead WebServer** (HP Power Manager Web UI) |
| **135**  | Open    | **MSRPC**         | Microsoft Windows RPC (Remote Procedure Call) |
| **139**  | Open    | **NetBIOS-SSN**   | NetBIOS Session Service (Used for SMB) |
| **445**  | Open    | **SMB**           | Windows SMB (File Sharing & Remote Access) |
| **3389** | Open    | **RDP**           | Remote Desktop Protocol (Has SSL certificate) |
| **3573** | Open    | **tag-ups-1?**    | Unknown (Needs further investigation) |
| **49152** | Open   | **MSRPC**         | Dynamic RPC Endpoint |
| **49153** | Open   | **MSRPC**         | Dynamic RPC Endpoint |
| **49154** | Open   | **MSRPC**         | Dynamic RPC Endpoint |
| **49155** | Open   | **MSRPC**         | Dynamic RPC Endpoint |
| **49158** | Open   | **MSRPC**         | Dynamic RPC Endpoint |
| **49160** | Open   | **MSRPC**         | Dynamic RPC Endpoint |

---

Here 49152-49160 are RPC ports.
Understanding RPC.
Alright, imagine you have a robot friend named Kevin 🦾 who lives in another room. You want Kevin to do things for you, like turn on the lights or play music.

Since Kevin is in another room, you can't just press buttons yourself. Instead, you call out to him and say:
➡️ "Hey Kevin, turn on the lights!"

Kevin listens, understands your request, and does it for you.
🖥 Now, how does this relate to computers?

Kevin = A computer running Windows.
You = Another program or computer.
Your voice = Remote Procedure Call (RPC).

RPC lets one program talk to another program on the same or a different computer and ask it to do something—like start a service, copy a file, or even create a user.
📌 Example: Windows Print Spooler Service

    The Print Spooler service (spoolsv.exe) uses RPC to talk to network printers.
    When you hit "Print" on your computer, your request is sent via RPC to the Print Spooler service.
    The Print Spooler then talks to the printer driver and sends your document for printing.


From this scan we can see that our server is using RCP which means Potato Attacks might be working.
