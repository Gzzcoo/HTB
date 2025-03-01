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

# Cat

<figure><img src="../../.gitbook/assets/Cat.png" alt="" width="563"><figcaption></figcaption></figure>

***

## Reconnaissance

Realizaremos un reconocimiento con **nmap** para ver los puertos que están expuestos en la máquina **`Cat`**. Este resultado lo almacenaremos en un archivo llamado `allPorts`.

```bash
❯ nmap -p- --open -sS --min-rate 1000 -Pn -n 10.10.11.53 -oG allPorts
Starting Nmap 7.95 ( https://nmap.org ) at 2025-02-02 23:39 CET
Nmap scan report for 10.10.11.53
Host is up (0.060s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 15.32 seconds
```

{% hint style="info" %}
> ⚠️ This box is still active on **`HackTheBox`**. Once retired, this article will be published for public access as per [HackTheBox’s policy on publishing content from their platform](https://help.hackthebox.com/en/articles/5188925-streaming-writeups-walkthrough-guidelines?).
>
> If you need a **hint** or want to **discuss anything related to the box**, feel free to reach out to me on Discord.
{% endhint %}

<figure><img src="../../.gitbook/assets/confidential-rubber-stamp-free-png.png" alt="" width="428"><figcaption></figcaption></figure>
