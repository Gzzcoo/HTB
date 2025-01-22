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

# Certified

<figure><img src="../../../../../.gitbook/assets/Certified.png" alt="" width="563"><figcaption></figcaption></figure>

## Reconnaissance

Proceremos a realizar un reconocimiento con **nmap** para ver los puertos que están expuestos en la máquina **Certified**.

```bash
nmap -p- --open -sS --min-rate 1000 -vvv -Pn -n 10.10.11.41 -oG allPortsbas
```

<figure><img src="../../../../../.gitbook/assets/2470_vmware_gTNIKB0MoB.png" alt="" width="434"><figcaption></figcaption></figure>

<figure><img src="../../../../../.gitbook/assets/confidential-rubber-stamp-free-png.png" alt="" width="428"><figcaption></figcaption></figure>
