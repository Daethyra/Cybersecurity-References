# Useful Repositories

## Table of Contents

- [Offensive](#offensive)
    - [Offensive Tools](#offensive-tools)
    - [Offensive Misc](#offensive-misc)
- [Defensive](#defensive)
    - [Defensive Tools](#defensive-tools)
    - [Defensive Misc](#defensive-misc)
- [Multi-Purpose](#multi-purpose-purple-teaming)
    - [Multi-Purpose Tools](#multi-purpose-tools)
    - [Multi-Purpose Misc](#multi-purpose-misc)

## Offensive

### Offensive Tools

#### [Awesome Hacking](https://github.com/Hack-with-Github/Awesome-Hacking)
- **Description**: A collection of awesome lists for hackers, pentesters & security researchers. By Hack with Github

#### [AutoRecon](https://github.com/Tib3rius/AutoRecon)
- **Description**: AutoRecon is a multi-threaded network reconnaissance tool that performs automated enumeration of services.

#### [find-you](https://github.com/positive-security/find-you)
- **Description**: Find You is a modified version of OpenHaystack that showcases the possibility of building a stealth AirTag clone that bypasses all of Apple's tracking protection features.

#### [HackTricks](https://book.hacktricks.xyz/)
- **Description**: HackTricks is an extensive resource containing cutting-edge hacking techniques, maintained by security researcher Carlos Polop. It covers a vast array of topics including pentesting methodologies, privilege escalation guides for multiple operating systems, network protocols exploitation, web vulnerabilities, wireless hacking techniques, and more. The repository is regularly updated with new attack vectors and is complemented by an online version (book.hacktricks.xyz) for easier navigation. It's particularly valuable for both beginner and experienced pentesters, offering practical examples, commands, and detailed explanations for various attack scenarios.

#### [NBP](https://github.com/NeverWonderLand/NBP)
- **Description**: The New Blood Project (NBP) is a comprehensive resource for learning about hacktivism. It contains various files and documents that cover a wide range of topics including terminal basics, types of penetration testing, tips for penetration testing, file uploads, and more. Additionally, the repository provides links to other resources and channels where users can learn and contribute to the community.

#### [OWASP Web Security Testing Guide](https://github.com/OWASP/wstg)
- **Description**: The WSTG is a "comprehensive Open Source guide to testing the security of web applications and web services." It contains documents for testing in various scenarios, and these documents are easily downloaded if one knows the uniform identifiers. It also has a web security testing checklist in both excel and markdown formats.

#### [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
- **Description**: An extensive and constantly updated repository of payloads, tricks, and techniques useful for exploiting a wide range of vulnerabilities and bypassing security controls. It contains payloads for attacks such as injections (SQL, NoSQL, XPath), XXE, Command Injection, XSS, SSRF, and many others. The repository also offers methods for privilege escalation, post-exploitation, and data exfiltration on various platforms (Windows, Linux, macOS)

#### [ProcessHacker](https://github.com/PKRoma/ProcessHacker)
- **Description**: Process Hacker is a free and open-source process viewer and memory editor with unique features such as powerful process termination and a Regex memory searcher.

#### [ProxyBroker](https://github.com/constverum/ProxyBroker)
- **Description**: ProxyBroker is an open-source tool that asynchronously finds public proxies from multiple sources and concurrently checks them.

#### [recox](https://github.com/samhaxr/recox)
- **Description**: RecoX is an incredibly versatile and powerful tool that is specifically designed to aid in the identification and classification of vulnerabilities within web applications. The script is able to detect vulnerabilities that are not typically included in the OWASP top ten vulnerabilities list, making it a valuable addition to any security professional's toolkit.

#### [SepticX](https://github.com/TheonlyIcebear/SepticX)
- **Description**: SepticX is a post-exploitation tool that is capable of automating a wide range of tasks, including gathering system information, executing system commands, and more.

#### [Shadow Clone](https://github.com/fyoorer/ShadowClone)
- **Description**: ShadowClone allows you to distribute your long running tasks dynamically across thousands of serverless functions and gives you the results within seconds where it would have taken hours to complete.

The following commands are from Shubham Shah's workflow, shown [here](https://youtu.be/0OMmWtU2Y_g?si=bJ2qCwnEXQvp88jP&t=1186).

Obtain live hosts via `httpx`:
```bash
python shadowclone.py -i ~/assets.csv --split 40 -o all-assets-online -c "/go/bin/httpx -l {INPUT}"
```

Check list of online assets for a specific vulnerabilty via `httpx`:
```bash
python shadowclone.py -i assets-online --split 40 -o matched-vulns -c "/go/bin/httpx -l {INPUT} -path '/..\..\..\..\..\..\..\..\..\..\..\..\etc\passwd' -ms 'root:x:0:0' "
```

#### [wesng](https://github.com/bitsadmin/wesng)
- **Description**: Windows Exploit Suggester - Next Generation (WES-NG) is a tool based on the output of Windows' systeminfo utility which provides the list of vulnerabilities the OS is vulnerable to, including any exploits for these vulnerabilities. Every Windows OS between Windows XP and Windows 11, including their Windows Server counterparts, is supported.

#### [xray](https://github.com/evilsocket/xray)
- **Description**: XRay is a tool for network (sub)domain discovery and reconnaissance.

### Offensive Misc

#### [CheatSheet by Dennis Feldbusch](https://github.com/DennisFeldbusch/CheatSheet)
- **Description**: A cheat sheet of useful tools and commonly used commands during pentesting.

#### [OWASP XSS Filter Evasion Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html)
- **Description**: A guide to evading Cross Site Scripting (XSS) filters across multiple contexts. Includes a seemingly exhaustive list of payload examples with various encoding types.

---

## Defensive

### Defensive Tools

#### [awesome-cybersecurity-blueteam](https://github.com/fabacab/awesome-cybersecurity-blueteam)
- **Description**: A curated collection of awesome resources, tools, and other shiny things for cybersecurity blue teams.

#### [freq](https://github.com/MarkBaggett/freq)
- **Description**: A Python toolkit for detecting anomalous text patterns using statistical analysis of character pairs (bigrams). It helps identify obfuscated commands, suspicious inputs, and rare log entries by comparing text against customizable frequency tables.

<details>

**Key Features**: CLI tools (freq.py, freq_sort.py) to score text "normality," build custom baselines, and prioritize log analysis. Optional REST API (freq_server.py) for integration into SIEMs or web apps.

**Use Cases**: Flagging encoded PowerShell commands in logs, detecting rare symbols in SQL queries, validating user input patterns, and identifying low-entropy passwords.

</details>

#### [Pestudio](https://www.winitor.com/)
- **Description**: A tool designed to detect suspicious artifacts within executable files to identify potentially malicious applications. It's particularly useful for initial assessment of suspicious files and malware analysis.

#### [PersistenceSniper](https://github.com/last-byte/PersistenceSniper)
- **Description**: PersistenceSniper is a Powershell module that can be used by Blue Teams, Incident Responders and System Administrators to hunt persistences implanted in Windows machines. It is also available on Powershell Gallery and it is digitally signed with a valid code signing certificate.

### Defensive Misc

#### [awesome-malware-analysis](https://github.com/rshipp/awesome-malware-analysis)
- **Description**: A curated list of awesome malware analysis tools and resources.

#### [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/index.html)
- **Description**: The OWASP Cheat Sheet Series was created to provide a concise collection of high value information on specific application security topics. These cheat sheets were created by various application security professionals who have expertise in specific topics.
  
#### [Stellastra TLS Cipher Suites](https://stellastra.com/cipher-suite)
- **Description**: List of TLS Cipher Suites with breakdown by key exchange mechanism, authentication, cipher, and hash alongside deprecation and vulnerability status.

---

## Multi-Purpose (Purple Teaming)

### Multi-Purpose Tools

#### [Autoruns](https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns)
- **Description**: Part of the Sysinternals suite, Autoruns shows what programs are configured to start up automatically when your system boots. It can be used both defensively to identify malicious persistence and offensively to understand potential persistence locations.

#### [The Book of Secret Knowledge](https://github.com/trimstray/the-book-of-secret-knowledge)
- **Description**: "This repository is a collection of various materials and tools that I use every day in my work. It contains a lot of useful information gathered in one piece. It is an invaluable source of knowledge for me that I often look back on. For everyone, really. Here everyone can find their favourite tastes. But to be perfectly honest, it is aimed towards System and Network administrators, DevOps, Pentesters, and Security Researchers."

#### [PEASS-ng](https://github.com/carlospolop/PEASS-ng)
- **Description**: PEASS-ng (Privilege Escalation Awesome ScriptsSuite) is aimed at detection of security vulnerabilities in local Windows/Linux/OSX environments.

#### [PurplePanda](https://github.com/carlospolop/PurplePanda)
- **Description**: PurplePanda is a post-exploitation tool that contains several modules for various tasks such as keylogging, screen capturing, and more.

### Multi-Purpose Misc

#### [cipher387](https://github.com/cipher387)
- **Description**: Cipher387 is Github user who has a collection of scripts and tools for cybersecurity, including both offensive and defensive resources.

---
