---
hidden: true
icon: desktop
layout:
  title:
    visible: true
  description:
    visible: false
  tableOfContents:
    visible: true
  outline:
    visible: true
  pagination:
    visible: true
---

# Copy of Copy of Cat

<figure><img src="../../.gitbook/assets/Cat.png" alt="" width="563"><figcaption></figcaption></figure>

***

Reconnaissance



```bash
❯ nmap -p- --open -sS --min-rate 1000 -Pn -n 10.10.11.53 -oG allPorts
Starting Nmap 7.95 ( https://nmap.org ) at 2025-02-02 23:39 CET
Nmap scan report for 10.10.11.53
Host is up (0.060s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 15.32 seconds
```





```bash
❯ extractPorts allPorts

[*] Extracting information...

	[*] IP Address: 10.10.11.53
	[*] Open ports: 22,80

[*] Ports copied to clipboard
```





```bash
❯ nmap -sCV -p22,80 10.10.11.53 -A -oN targeted -oX targetedXML
Starting Nmap 7.95 ( https://nmap.org ) at 2025-02-02 23:42 CET
Nmap scan report for cat.htb (10.10.11.53)
Host is up (0.072s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 96:2d:f5:c6:f6:9f:59:60:e5:65:85:ab:49:e4:76:14 (RSA)
|   256 9e:c4:a4:40:e9:da:cc:62:d1:d6:5a:2f:9e:7b:d4:aa (ECDSA)
|_  256 6e:22:2a:6a:6d:eb:de:19:b7:16:97:c2:7e:89:29:d5 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
| http-git: 
|   10.10.11.53:80/.git/
|     Git repository found!
|     Repository description: Unnamed repository; edit this file 'description' to name the...
|_    Last commit message: Cat v1 
|_http-title: Best Cat Competition
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: Apache/2.4.41 (Ubuntu)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running: Linux 4.X|5.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
OS details: Linux 4.15 - 5.19, Linux 5.0 - 5.14
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 80/tcp)
HOP RTT      ADDRESS
1   64.13 ms 10.10.16.1
2   95.83 ms cat.htb (10.10.11.53)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.18 seconds
```





```bash
❯ xsltproc targetedXML > index.html

❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```



<figure><img src="../../.gitbook/assets/imagen (1).png" alt=""><figcaption></figcaption></figure>



```bash
❯ cat /etc/hosts | grep 10.10.11.53
10.10.11.53 cat.htb
```





<figure><img src="../../.gitbook/assets/imagen (2).png" alt=""><figcaption></figcaption></figure>



<figure><img src="../../.gitbook/assets/imagen (3).png" alt=""><figcaption></figcaption></figure>



<figure><img src="../../.gitbook/assets/imagen (5).png" alt=""><figcaption></figcaption></figure>





<figure><img src="../../.gitbook/assets/imagen (4).png" alt=""><figcaption></figcaption></figure>



<figure><img src="../../.gitbook/assets/imagen (6).png" alt=""><figcaption></figcaption></figure>



<figure><img src="../../.gitbook/assets/imagen (7).png" alt=""><figcaption></figcaption></figure>





<figure><img src="../../.gitbook/assets/imagen (8).png" alt=""><figcaption></figcaption></figure>





<figure><img src="../../.gitbook/assets/imagen (9).png" alt=""><figcaption></figcaption></figure>



<figure><img src="../../.gitbook/assets/imagen (10).png" alt=""><figcaption></figcaption></figure>



```bash
❯ dirsearch -u 'http://cat.htb' -i 200 -t 50 2>/dev/null

  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 50 | Wordlist size: 11460

Output File: /home/kali/Desktop/HackTheBox/Linux/Cat/Cat/content/reports/http_cat.htb/_25-02-02_23-55-14.txt

Target: http://cat.htb/

[23:55:14] Starting: 
[23:55:19] 200 -   92B  - /.git/config
[23:55:19] 200 -   73B  - /.git/description
[23:55:19] 200 -    7B  - /.git/COMMIT_EDITMSG
[23:55:20] 200 -   23B  - /.git/HEAD
[23:55:20] 200 -    2KB - /.git/index
[23:55:20] 200 -  240B  - /.git/info/exclude
[23:55:20] 200 -  150B  - /.git/logs/refs/heads/master
[23:55:20] 200 -  150B  - /.git/logs/HEAD
[23:55:20] 200 -   41B  - /.git/refs/heads/master
```



```bash
❯ python3 /opt/GitHack/GitHack.py http://cat.htb/.git/ 2>/dev/null 
```



```bash
❯ tree
.
├── accept_cat.php
├── admin.php
├── config.php
├── contest.php
├── css
│   └── styles.css
├── delete_cat.php
├── img
│   ├── cat1.jpg
│   ├── cat2.png
│   └── cat3.webp
├── img_winners
│   ├── cat1.jpg
│   ├── cat2.png
│   └── cat3.webp
├── index.php
├── join.php
├── logout.php
├── view_cat.php
├── vote.php
├── winners
│   └── cat_report_20240831_173129.php
└── winners.php

5 directories, 19 files
```





{% code title="contest.php" %}
```php
<?php
session_start();

include 'config.php';

// Message variables
$success_message = "";
$error_message = "";

// Check if the user is logged in
if (!isset($_SESSION['username'])) {
    header("Location: /join.php");
    exit();
}

// Function to check for forbidden content
function contains_forbidden_content($input, $pattern) {
    return preg_match($pattern, $input);
}

// Check if the form has been submitted
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    // Capture form data
    $cat_name = $_POST['cat_name'];
    $age = $_POST['age'];
    $birthdate = $_POST['birthdate'];
    $weight = $_POST['weight'];

    $forbidden_patterns = "/[+*{}',;<>()\\[\\]\\/\\:]/";

    // Check for forbidden content
    if (contains_forbidden_content($cat_name, $forbidden_patterns) ||
        contains_forbidden_content($age, $forbidden_patterns) ||
        contains_forbidden_content($birthdate, $forbidden_patterns) ||
        contains_forbidden_content($weight, $forbidden_patterns)) {
        $error_message = "Your entry contains invalid characters.";
    } else {
        // Generate unique identifier for the image
        $imageIdentifier = uniqid() . "_";

        // Upload cat photo
        $target_dir = "uploads/";
        $target_file = $target_dir . $imageIdentifier . basename($_FILES["cat_photo"]["name"]);
        $uploadOk = 1;
        $imageFileType = strtolower(pathinfo($target_file, PATHINFO_EXTENSION));

        // Check if the file is an actual image or a fake file
        $check = getimagesize($_FILES["cat_photo"]["tmp_name"]);
        if($check !== false) {
            $uploadOk = 1;
        } else {
            $error_message = "Error: The file is not an image.";
            $uploadOk = 0;
        }

        // Check if the file already exists
        if (file_exists($target_file)) {
            $error_message = "Error: The file already exists.";
            $uploadOk = 0;
        }

        // Check file size
        if ($_FILES["cat_photo"]["size"] > 500000) {
            $error_message = "Error: The file is too large.";
            $uploadOk = 0;
        }

        // Allow only certain file formats
        if($imageFileType != "jpg" && $imageFileType != "png" && $imageFileType != "jpeg") {
            $error_message = "Error: Only JPG, JPEG, and PNG files are allowed.";
            $uploadOk = 0;
        }

        // Check if $uploadOk is set to 0 by an error
        if ($uploadOk == 0) {
        } else {
            if (move_uploaded_file($_FILES["cat_photo"]["tmp_name"], $target_file)) {
                // Prepare SQL query to insert cat data
                $stmt = $pdo->prepare("INSERT INTO cats (cat_name, age, birthdate, weight, photo_path, owner_username) VALUES (:cat_name, :age, :birthdate, :weight, :photo_path, :owner_username)");
                // Bind parameters
                $stmt->bindParam(':cat_name', $cat_name, PDO::PARAM_STR);
                $stmt->bindParam(':age', $age, PDO::PARAM_INT);
                $stmt->bindParam(':birthdate', $birthdate, PDO::PARAM_STR);
                $stmt->bindParam(':weight', $weight, PDO::PARAM_STR);
                $stmt->bindParam(':photo_path', $target_file, PDO::PARAM_STR);
                $stmt->bindParam(':owner_username', $_SESSION['username'], PDO::PARAM_STR);
                // Execute query
                if ($stmt->execute()) {
                    $success_message = "Cat has been successfully sent for inspection.";
                } else {
                    $error_message = "Error: There was a problem registering the cat.";
                }
            } else {
                $error_message = "Error: There was a problem uploading the file.";
            }
        }
    }
}
?>
```
{% endcode %}





{% code title="admin.php" %}
```php
<?php
session_start();

include 'config.php';

// Check if the user is logged in
if (!isset($_SESSION['username']) || $_SESSION['username'] !== 'axel') {
    header("Location: /join.php");
    exit();
}

// Fetch cat data from the database
$stmt = $pdo->prepare("SELECT * FROM cats");
$stmt->execute();
$cats = $stmt->fetchAll(PDO::FETCH_ASSOC);
?>
```
{% endcode %}



{% code title="config.php" %}
```php
<?php
// Database configuration
$db_file = '/databases/cat.db';

// Connect to the database
try {
    $pdo = new PDO("sqlite:$db_file");
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (PDOException $e) {
    die("Error: " . $e->getMessage());
}
?>
```
{% endcode %}
