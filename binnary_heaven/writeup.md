# 😇 Binary Heaven - TryHackMe Writeup

| Information | Details |
| :--- | :--- |
| **Room Name** | Binary Heaven |
| **Difficulty** | Medium |
| **Link** | [TryHackMe - Binary Heaven](https://tryhackme.com/room/binaryheaven) |

---

## Table of Contents
1.  [Reconnaissance](#1-reconnaissance)
2.  [Binary Analysis](#2-binary-analysis)
    * Angel\_A (Username)
    * Angel\_B (Password)
3.  [Initial Access](#3-initial-access)
4.  [Privilege Escalation](#4-privilege-escalation)
    * Guardian → Binexgod (Buffer Overflow)
    * Binexgod → Root (PATH Hijacking)
5.  [Summary](#5-summary)

---

## 1. Reconnaissance

### Port Scanning with RustScan

We started with a full port scan to identify open services.

```bash
    export RHOSTS=10.10.124.63
    rustscan --ulimit 5000 -t 2000 --range=1-65535 $RHOSTS -- -sC -sV -oN rustscan/rustscan.txt

   PORT   STATE SERVICE REASON         VERSION
   22/tcp open  ssh     syn-ack ttl 63 OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
   | ssh-hostkey: 
   # ... (Host keys omitted for brevity)
   Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
