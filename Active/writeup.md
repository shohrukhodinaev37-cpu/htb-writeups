ACTIVE HTB
<img width="1033" height="221" alt="1" src="https://github.com/user-attachments/assets/063487f0-1bfa-4231-910f-05fdd6b1e55a" />



Active is a Windows machine on Hack The Box that involves Active Directory exploitation. The main goal is to enumerate SMB shares, extract domain credentials, and escalate privileges to gain both user and root access. This box is useful for learning common AD misconfigurations and realistic attack techniques.


Nmap scan

$ sudo nmap 10.10.10.100 -T4 -A -open -p-

<img width="634" height="615" alt="nmap" src="https://github.com/user-attachments/assets/7afb8d91-5a47-4c49-b07b-5df063a531d7" />

Let's enumerate SMB
└─# smbclient -L //10.10.10.100 -N      



<img width="499" height="200" alt="smb" src="https://github.com/user-attachments/assets/e7af1596-99d8-49f8-a681-f48c0c6946f3" />

Enumerate the Replication Share

<img width="661" height="140" alt="rsss" src="https://github.com/user-attachments/assets/dc78fadb-37d8-414b-bedd-8c0a1d28c86a" />



We've found very interesting file Group.xml.

Why this is important

	•	The file reveals group names and members, including privileged groups such as Domain Admins, Enterprise Admins, Backup Operators, or service accounts.
	•	It provides a curated list of usernames and service accounts which are high-value targets for further attacks (password spraying, brute force, Kerberoasting, phishing, AS-REP roast, etc.).
	•	If the file was stored in a publicly readable share (or accessible to low-privileged users), it indicates poor exposure of sensitive AD information and increases the attack surface.

Enumerate downloaded 
file Groups.xml
$ cat Preferences/Groups/Groups.xml

<img width="661" height="140" alt="rsss" src="https://github.com/user-attachments/assets/f40cd140-bc45-44a8-9020-1ca5699e7706" />


