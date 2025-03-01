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

{% hint style="info" %}
> ⚠️ This box is still active on **`HackTheBox`**. Once retired, this article will be published for public access as per [HackTheBox’s policy on publishing content from their platform](https://help.hackthebox.com/en/articles/5188925-streaming-writeups-walkthrough-guidelines?).
>
> If you need a **hint** or want to **discuss anything related to the box**, feel free to reach out to me on Discord.
{% endhint %}

<figure><img src="../../../.gitbook/assets/confidential-rubber-stamp-free-png.png" alt="" width="428"><figcaption></figcaption></figure>
