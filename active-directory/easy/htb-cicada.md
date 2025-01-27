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

# Cicada

<figure><img src="../../.gitbook/assets/Cicada.png" alt="" width="563"><figcaption></figcaption></figure>

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

<figure><img src="../../.gitbook/assets/572_vmware_TJyWPJfE3z.png" alt="" width="563"><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/confidential-rubber-stamp-free-png.png" alt="" width="428"><figcaption></figcaption></figure>
