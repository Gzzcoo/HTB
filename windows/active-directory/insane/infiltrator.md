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

# Infiltrator

<figure><img src="../../../.gitbook/assets/Infiltrator.png" alt="" width="563"><figcaption></figcaption></figure>

## Reconnaissance

Realizaremos un reconocimiento con **nmap** para ver los puertos que están expuestos en la máquina **Infiltrator**. Este resultado lo almacenaremos en un archivo llamado `allPorts`.

```bash
❯ nmap -p- --open -sS --min-rate 1000 -Pn -n 10.10.11.31 -oG allPorts
Starting Nmap 7.95 ( https://nmap.org ) at 2025-01-17 16:04 CET
Nmap scan report for 10.10.11.31
Host is up (0.055s latency).
Not shown: 65513 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE
53/tcp    open  domain
80/tcp    open  http
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
3389/tcp  open  ms-wbt-server
5985/tcp  open  wsman
9389/tcp  open  adws
15220/tcp open  unknown
49666/tcp open  unknown
49688/tcp open  unknown
49690/tcp open  unknown
49692/tcp open  unknown
49723/tcp open  unknown
49740/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 188.34 seconds
```

{% hint style="info" %}
> ⚠️ This box is still active on **`HackTheBox`**. Once retired, this article will be published for public access as per [HackTheBox’s policy on publishing content from their platform](https://help.hackthebox.com/en/articles/5188925-streaming-writeups-walkthrough-guidelines?).
>
> If you need a **hint** or want to **discuss anything related to the box**, feel free to reach out to me on Discord.
{% endhint %}

<figure><img src="../../../.gitbook/assets/confidential-rubber-stamp-free-png.png" alt="" width="428"><figcaption></figcaption></figure>
