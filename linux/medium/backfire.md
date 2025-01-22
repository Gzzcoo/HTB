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

# Backfire

<figure><img src="../../../../.gitbook/assets/Backfire.png" alt="" width="563"><figcaption></figcaption></figure>

***

## Reconnaissance

Realizaremos un reconocimiento con `Nmap` para ver los puertos que están expuestos en la máquina **`Backfire`**. Este resultado lo almacenaremos en un archivo llamado `allPorts`.

```bash
❯ nmap -p- --open -sS --min-rate 1000 -vvv -Pn -n 10.10.11.49 -oG allPorts
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.95 ( https://nmap.org ) at 2025-01-20 19:36 CET
Initiating SYN Stealth Scan at 19:36
Scanning 10.10.11.49 [65535 ports]
Discovered open port 443/tcp on 10.10.11.49
Discovered open port 22/tcp on 10.10.11.49
Discovered open port 8000/tcp on 10.10.11.49
Completed SYN Stealth Scan at 19:37, 11.29s elapsed (65535 total ports)
Nmap scan report for 10.10.11.49
Host is up, received user-set (0.033s latency).
Scanned at 2025-01-20 19:36:58 CET for 11s
Not shown: 65530 closed tcp ports (reset), 2 filtered tcp ports (port-unreach)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE  REASON
22/tcp   open  ssh      syn-ack ttl 63
443/tcp  open  https    syn-ack ttl 63
8000/tcp open  http-alt syn-ack ttl 63

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 11.38 seconds
           Raw packets sent: 65572 (2.885MB) | Rcvd: 65580 (2.624MB)

```

<figure><img src="../../../../.gitbook/assets/confidential-rubber-stamp-free-png.png" alt="" width="428"><figcaption></figcaption></figure>
