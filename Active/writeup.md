ACTIVE HTB
<img width="1033" height="221" alt="1" src="https://github.com/user-attachments/assets/063487f0-1bfa-4231-910f-05fdd6b1e55a" />



Active is a Windows machine on Hack The Box that involves Active Directory exploitation. The main goal is to enumerate SMB shares, extract domain credentials, and escalate privileges to gain both user and root access. This box is useful for learning common AD misconfigurations and realistic attack techniques.

## Reconnaissance
### Nmap Scan
Nmap scan


$ sudo nmap 10.10.10.100 -T4 -A -open -p-


<img width="634" height="615" alt="nmap" src="https://github.com/user-attachments/assets/7afb8d91-5a47-4c49-b07b-5df063a531d7" />


### SMB Enumeration  
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


## Initial Access
### GPP Password Extraction

Decrypt encrypted password:

└─# gpp-decrypt edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ    
GPPstillStandingStrong2k18

Now we have credentials(svc_tgs:GPPstillStandingStrong2k18)


Confirm credentials:


<img width="658" height="313" alt="3" src="https://github.com/user-attachments/assets/9742fe16-0ae3-408c-94b5-99754f2806ae" />


We have enumerated Users Share and found user.txt



<img width="608" height="113" alt="findusertxt" src="https://github.com/user-attachments/assets/4418333e-4d2f-44ef-952f-ddee2bc742a6" />

## Privilege Escalation  
### Kerberoasting Attack


Check for Kerberoasting:

<img width="676" height="494" alt="4" src="https://github.com/user-attachments/assets/9344416e-d25e-4302-b22b-a45de35d4d00" />

Crack the password hash offline:


<img width="647" height="413" alt="hashcat" src="https://github.com/user-attachments/assets/ab0ef444-1299-4d69-a823-e6acec6686d5" />


Connect as Administrator:

<img width="687" height="288" alt="adminaccess" src="https://github.com/user-attachments/assets/e370f12b-c7a7-416e-a00a-fb7631c6f4c3" />


###Conclusion

The Active machine provided an excellent introduction to common Active Directory misconfigurations and attack vectors. This box demonstrated a realistic attack chain that could occur in enterprise environments where legacy configurations and poor security practices are present.
Key Attack Vectors Exploited

    Group Policy Preferences (GPP) Misconfiguration

        Sensitive credentials stored in Groups.xml with reversible encryption

        Highlighted the dangers of using GPP for password deployment

        CVE-2014-1812 vulnerability allowing easy decryption of passwords

    Kerberoasting Attack

        Service accounts with SPNs configured are vulnerable to offline cracking

        Demonstrated how low-privileged users can extract service account hashes

        Weak service account passwords can lead to domain compromise

    Information Disclosure via SMB

        Anonymous access to SMB shares exposed critical configuration files

        Lack of proper share permissions allowed enumeration of sensitive data

Security Lessons Learned

    GPP Passwords: Never use Group Policy Preferences for password deployment in modern Windows environments

    Service Accounts: Implement strong, complex passwords for service accounts and consider using Group Managed Service Accounts (gMSA)

    Share Permissions: Regularly audit SMB share permissions and restrict anonymous access

    Monitoring: Implement detection for Kerberoasting attempts and unusual SPN requests

    Principle of Least Privilege: Ensure service accounts have only the permissions necessary for their function

Tools & Techniques Mastered

    SMB enumeration with smbclient

    GPP password extraction and decryption

    Kerberoasting with Impacket's GetUserSPNs

    Hash cracking with hashcat

    Windows domain reconnaissance

This machine serves as a perfect example of how multiple minor misconfigurations can chain together to form a complete domain compromise path, emphasizing the importance of comprehensive AD security hardening.
write for my writeup
Conclusion

The Active machine provided a practical demonstration of common Active Directory security misconfigurations that remain prevalent in real-world environments. Through this challenge, we explored a classic attack chain that leveraged multiple vulnerabilities to progress from anonymous access to full domain compromise.
Attack Chain Summary

Our approach followed a systematic path:

    Initial reconnaissance revealed exposed SMB services

    Information disclosure through anonymously accessible shares exposed Group Policy Preferences

    Credential extraction from GPP files provided initial user access

    Kerberoasting leveraged service accounts to obtain crackable hashes

    Privilege escalation was achieved through weak service account passwords

Critical Vulnerabilities Exploited

    Group Policy Preferences (GPP) Misconfiguration: Stored credentials with reversible encryption in accessible locations

    Weak Service Account Passwords: Kerberoastable accounts with easily crackable passwords

    Excessive SMB Permissions: Anonymous access to sensitive shares containing configuration data

Defensive Recommendations

    Eliminate GPP Passwords: Replace Group Policy Preferences with more secure alternatives like Group Managed Service Accounts

    Enforce Strong Password Policies: Implement complex passwords for service accounts, especially those with SPNs

    Restrict SMB Access: Apply principle of least privilege to network shares and disable anonymous enumeration

    Monitor Kerberoasting Activity: Implement detection for unusual SPN ticket requests

    Regular AD Audits: Conduct periodic reviews of service accounts and their permissions

Skills Demonstrated

This challenge reinforced essential penetration testing techniques including SMB enumeration, GPP analysis, Kerberoasting attacks, and hash cracking methodologies. The machine served as an excellent introduction to Active Directory exploitation and highlighted the importance of comprehensive domain security.

The Active box stands as a valuable learning experience for understanding how seemingly minor misconfigurations can chain together to enable complete domain takeover, emphasizing the critical need for defense-in-depth strategies in Windows environments.

