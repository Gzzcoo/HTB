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

# EscapeTwo

<figure><img src="../../../../../.gitbook/assets/EscapeTwo.png" alt="" width="563"><figcaption></figcaption></figure>

## Reconnaissance

Realizaremos un reconocimiento con **nmap** para ver los puertos que están expuestos en la máquina **EscapeTwo**.

```bash
nmap -p- --open -sS --min-rate 1000 -Pn -n 10.10.11.51 -oG allPorts
```

<figure><img src="../../../../../.gitbook/assets/3459_vmware_wiOmYgjXg7.png" alt="" width="485"><figcaption></figcaption></figure>

<figure><img src="../../../../../.gitbook/assets/confidential-rubber-stamp-free-png.png" alt="" width="428"><figcaption></figcaption></figure>
