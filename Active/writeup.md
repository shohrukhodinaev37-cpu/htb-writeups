
<img width="1033" height="221" alt="1" src="https://github.com/user-attachments/assets/063487f0-1bfa-4231-910f-05fdd6b1e55a" />



Active is a Windows machine on Hack The Box that involves Active Directory exploitation. The main goal is to enumerate SMB shares, extract domain credentials, and escalate privileges to gain both user and root access. This box is useful for learning common AD misconfigurations and realistic attack techniques.


Nmap scan

<img width="634" height="615" alt="nmap" src="https://github.com/user-attachments/assets/7afb8d91-5a47-4c49-b07b-5df063a531d7" />

Let's enumerate SMB


<img width="499" height="200" alt="smb" src="https://github.com/user-attachments/assets/e7af1596-99d8-49f8-a681-f48c0c6946f3" />

Enumerate the Replication Share

$ tree active.htb/
active.htb/
├── DfsrPrivate
│   ├── ConflictAndDeleted
│   ├── Deleted
│   └── Installing
├── Policies
│   ├── {31B2F340-016D-11D2-945F-00C04FB984F9}
│   │   ├── GPT.INI
│   │   ├── Group Policy
│   │   │   └── GPE.INI
│   │   ├── MACHINE
│   │   │   ├── Microsoft
│   │   │   │   └── Windows NT
│   │   │   │       └── SecEdit
│   │   │   │           └── GptTmpl.inf
│   │   │   ├── Preferences
│   │   │   │   └── Groups
│   │   │   │       └── Groups.xml
│   │   │   └── Registry.pol
│   │   └── USER
│   └── {6AC1786C-016F-11D2-945F-00C04fB984F9}
│       ├── GPT.INI
│       ├── MACHINE
│       │   └── Microsoft
│       │       └── Windows NT
│       │           └── SecEdit
│       │               └── GptTmpl.inf
│       └── USER
└── scripts

22 directories, 7 files

$ cat Preferences/Groups/Groups.xml
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}"><User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="active.htb\SVC_TGS" image="2" changed="2018-07-18 20:46:06" uid="{EF57DA28-5F69-4530-A59E-AAB58578219D}"><Properties action="U" newName="" fullName="" description="" cpassword="edB<REDACTED>VmQ" changeLogon="0" noChange="1" neverExpires="1" acctDisabled="0" userName="active.htb\SVC_TGS"/></User>
</Groups>
