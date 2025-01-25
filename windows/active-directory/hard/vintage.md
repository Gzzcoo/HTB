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

# Vintage

<figure><img src="../../../.gitbook/assets/Vintage.png" alt="" width="563"><figcaption></figcaption></figure>

## Reconnaissance

Proceremos a realizar un reconocimiento con **nmap** para ver los puertos que están expuestos en la máquina **Vintage**.

```bash
nmap -p- --open -sS --min-rate 1000 -vvv -Pn -n 10.10.11.45 -oG allPorts
```

<figure><img src="../../../.gitbook/assets/2701_vmware_p7xif7Ff0w.png" alt="" width="452"><figcaption></figcaption></figure>

<figure><img src="../../../.gitbook/assets/confidential-rubber-stamp-free-png.png" alt="" width="428"><figcaption></figcaption></figure>
