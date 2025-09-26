# Cybersecurity References 🛡️🔒

![HACKERMANS by numrii](https://cdn.betterttv.net/emote/5b490e73cf46791f8491f6f4/3x.webp)

Welcome to my personal cybersecurity toolkit.

## Table of Contents
- [Guides](#guides)
  - [Internal Pentesting](#internal-pentesting)
    - [Playbooks](#playbooks)
    - [Topics](#topics)
  - [Web Applications](#web-applications)
  - [Tools](#tools)

## [Guides](./Guides)

My personal hacking notes are in the [Guides](./Guides/) directory, which also has a [power commands](./Guides/Power%20Commands/) subdir that covers [PowerShell](./Guides/Power%20Commands/PowerShell/), [scanning](./Guides/Power%20Commands/Scanning/), and [web applications](./Guides/Power%20Commands/Web%20Applications/).

I have a [Useful Repositories document](./Guides/Useful-Repositories.md "Tools and Resources") where I link to the offensive and defensive tools I either use or really like in theory.

Beginners should start with a [guide by Maderas](./Guides/1.%20Overviews/Get_Started-MaderasSecurityArsenal.md).

### Internal Pentesting

I find the [Active Directory Playbook](./Guides/3.%20Gaining%20Access%20and%20Persistence/Post%20Compromise/Active%20Directory%20Playbook.md) and [Pentest Playbook](./Guides/1.%20Overviews/Penetration%20Test%20Playbook.md) to be my favorite resources.

#### Playbooks
- [Penetration Test Playbook](./Guides/1.%20Overviews/Penetration%20Test%20Playbook.md)
- [Active Directory Playbook](./Guides/3.%20Gaining%20Access%20and%20Persistence/Post%20Compromise/Active%20Directory%20Playbook.md)

#### Topics
- [Networking](./Guides/1.%20Overviews/Networking/)
- [Scanning and Enumeration](./Guides/2.%20Scanning%20and%20Enumeration/)
  - [External Reconnaissance](./Guides/2.%20Scanning%20and%20Enumeration/External%20Reconnaissance.md)
  - [Subverting Intrusion Detection Systems w/ Nmap](./Guides/2.%20Scanning%20and%20Enumeration/Subverting%20Intrusion%20Detection%20Systems.md)
- [Gaining Access & Persistence](./Guides/3.%20Gaining%20Access%20and%20Persistence/)
  - [Evasion & Data Exfiltration](./Guides/3.%20Gaining%20Access%20and%20Persistence/Evasion%20and%20Data%20Exfiltration/)
    - [Encrypted Powershell](./Guides/3.%20Gaining%20Access%20and%20Persistence/Evasion%20and%20Data%20Exfiltration/Encrypted%20PowerShell.md)
    - [Abusing WinDef Exclusions to Evade Detection](./Guides/3.%20Gaining%20Access%20and%20Persistence/Evasion%20and%20Data%20Exfiltration/Abusing%20Exclusions%20To%20Evade%20Detection%20_%20Dazzy%20Ddos.pdf)
  - [Initial Foothold](./Guides/3.%20Gaining%20Access%20and%20Persistence/Initial%20Foothold/)
    - [LDAP](./Guides/3.%20Gaining%20Access%20and%20Persistence/Initial%20Foothold/LDAP.md)
    - [MSFVenom Payload Generation](./Guides/3.%20Gaining%20Access%20and%20Persistence/Initial%20Foothold/Payload%20Generation%20-%20MSFVenom.md)
    - [Cloudflare to Bypass Cloudflare](./Guides/3.%20Gaining%20Access%20and%20Persistence/Initial%20Foothold/Using%20Cloudflare%20to%20bypass%20Cloudflare%20–%20Certitude%20Blog.pdf)
  - [Post Compromise](./Guides/3.%20Gaining%20Access%20and%20Persistence/Post%20Compromise/)
    - [Kerberoasting](./Guides/3.%20Gaining%20Access%20and%20Persistence/Post%20Compromise/Kerberoasting/)
      - [Golden, Diamond, & Sapphire Attacks](./Guides/3.%20Gaining%20Access%20and%20Persistence/Post%20Compromise/Kerberoasting/Golden%20Diamond%20and%20Sapphire%20Attacks.md)
      - [Service Principal Name (SPN) Discovery](./Guides/3.%20Gaining%20Access%20and%20Persistence/Post%20Compromise/Kerberoasting/Service%20Principal%20Name%20(SPN)%20Discovery.md)
    - [OS Enumeration](./Guides/3.%20Gaining%20Access%20and%20Persistence/Post%20Compromise/OS%20Enumeration.md)
  - [Windows Persistence](./Guides/3.%20Gaining%20Access%20and%20Persistence/Windows%20Persistence/)
    - [DLL Hijacking](./Guides/3.%20Gaining%20Access%20and%20Persistence/Windows%20Persistence/DLL%20Hijacking/)
      - [DLL Hijacking Overview](./Guides/3.%20Gaining%20Access%20and%20Persistence/Windows%20Persistence/DLL%20Hijacking/DLL%20Hijacking%20Overview.md)
      - [DLL Hijacking Pentest Cheatsheet](./Guides/3.%20Gaining%20Access%20and%20Persistence/Windows%20Persistence/DLL%20Hijacking/DLL%20Hijacking%20Pentest%20Cheat%20Sheet.md)
    - [New User Account](./Guides/3.%20Gaining%20Access%20and%20Persistence/Windows%20Persistence/Create%20New%20User%20Account.md)
    - [Registry Persistence](./Guides/3.%20Gaining%20Access%20and%20Persistence/Windows%20Persistence/Registry%20Persistence.md)



### [Web Applications](./Guides/Power%20Commands/Web%20Applications/)
<!-- <details><summary>More</summary> -->
Documents regarding common web application vulnerabilities, including the OWASP Top Ten. Each note has code examples or injection payloads. <a href="./Guides/Power Commands/Web Applications/XSS.md">XSS</a>, <a href="./Guides/Power Commands/Web Applications/SSRF_bypassFilters.md">SSRF</a>, and <a href="./Guides/Power Commands/Web Applications/CORS.md">CORS</a> are just a few examples. The <a href="./Guides/Power Commands/Web Applications/WebApp-ExploitsChecklist.pdf">WebApp Exploit Checklist</a> is a great visual reference.

<br>
See that directory's <a href="./Guides/Power Commands/Web Applications/README.md">README</a> for more information.
<!-- </details> -->

## [Tools](./Tools)

A collection of my scripts I've found repeated use for in multiple scenarios.

<!-- <details><summary>Personal automation scripts</summary> -->

[directory_visualizer.py](./Tools/directory_visualizer.py): CLI tool that creates a hierarchical visualization of a directory's nested contents.

[`extract_video_audio.py`](./Tools/extract_video_audio.py): CLI tool that creates an MP3 audio file from a MP4 file, or files in a directory.

[`firewall_rules.py`](./Tools/firewall_rules.py): CLI tool that optionally accepts a URL as an argument to download a CSV list of known problematic IP addresses and create block rules for Windows Firewall or `iptables` for Linux. 

> The default URL downloads the "Botnet C2 Indicators of Compromise (IOCs)" from FEODOtracker, which contains "information on tracked botnet c2s but also IP addresses that were acting as a botnet C2 within the **past 30 days**."

[`hashfile_validator.py`](./Tools/hashfile_validator.py): A Windows-exclusive CLI tool that automatically detects and validates cryptographic hash checksums against files. It supports MD5, SHA1, SHA256, SHA384, and SHA512, with optional JSON output and additional file information. The tool uses Windows' built-in Certutil for hash calculation.

[`regex_generator.py`](./Tools/RegexGenerator.py): Generates regex patterns to detect keyword variations, including obfuscated and evasive text, for precise matching.

[`repository_visualizer.py`](./Tools/repository_visualizer.py): A Python script that automatically generates an interactive HTML navigation interface for a GitHub repository's directory structure. Adaptable for any repository. Requires GitHub token.

[`Reset-DockerWslIntergration.ps1`](./Tools/Reset-DockerWslIntegration.ps1): PowerShell script that stops Docker Desktop, Stops WSL, and Unregisters the Docker Destop data.

[sumrecon.sh](./Tools/comprehensive_recon.sh): CLI tool by  that performs comprehensive reconnaissance using assetfinder, amass, certspotter, sublist3r, httprobe, waybackurls, whatweb, nmap, and eyewitness(optional). When I originally added this, I had no idea it's just Grimmie's [sumrecon](https://github.com/Gr1mmie/sumrecon) script.

<!-- </details> -->

## How to Contribute

Please feel encouraged to contribute your own [Guide](./Guides/), automation scripts, or [useful repository link(s)](./Guides/Useful-Repositories.md).

See the [CONTRIBUTING.md](CONTRIBUTING.md) file for guidelines on how to contribute.

## 📜 License

Distributed under the MIT License. See [LICENSE](./LICENSE) for more information.
