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

#### [NBP](https://github.com/NeverWonderLand/NBP)
- **Description**: The New Blood Project (NBP) is a comprehensive resource for learning about hacktivism. It contains various files and documents that cover a wide range of topics including terminal basics, types of penetration testing, tips for penetration testing, file uploads, and more. Additionally, the repository provides links to other resources and channels where users can learn and contribute to the community.

#### [OWASP Web Security Testing Guide](https://github.com/OWASP/wstg)
- **Description**: The WSTG is a "comprehensive Open Source guide to testing the security of web applications and web services." It contains documents for testing in various scenarios, and these documents are easily downloaded if one knows the uniform identifiers. It also has a web security testing checklist in both excel and markdown formats.

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

#### [PersistenceSniper](https://github.com/last-byte/PersistenceSniper)
- **Description**: PersistenceSniper is a Powershell module that can be used by Blue Teams, Incident Responders and System Administrators to hunt persistences implanted in Windows machines. It is also available on Powershell Gallery and it is digitally signed with a valid code signing certificate.

### Defensive Misc

#### [awesome-malware-analysis](https://github.com/rshipp/awesome-malware-analysis)
- **Description**: A curated list of awesome malware analysis tools and resources.

#### [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/index.html)
- **Description**: The OWASP Cheat Sheet Series was created to provide a concise collection of high value information on specific application security topics. These cheat sheets were created by various application security professionals who have expertise in specific topics.

---

## Multi-Purpose (Purple Teaming)

### Multi-Purpose Tools

#### [The Book of Secret Knowledge](https://github.com/trimstray/the-book-of-secret-knowledge)
- **Description**: This repository is a collection of various materials and tools that I use every day in my work. It contains a lot of useful information gathered in one piece. It is an invaluable source of knowledge for me that I often look back on. For everyone, really. Here everyone can find their favourite tastes. But to be perfectly honest, it is aimed towards System and Network administrators, DevOps, Pentesters, and Security Researchers.

#### [PEASS-ng](https://github.com/carlospolop/PEASS-ng)
- **Description**: PEASS-ng (Privilege Escalation Awesome ScriptsSuite) is aimed at detection of security vulnerabilities in local Windows/Linux/OSX environments.

#### [PurplePanda](https://github.com/carlospolop/PurplePanda)
- **Description**: PurplePanda is a post-exploitation tool that contains several modules for various tasks such as keylogging, screen capturing, and more.

### Multi-Purpose Misc

#### [cipher387](https://github.com/cipher387)
- **Description**: Cipher387 is Github user who has a collection of scripts and tools for cybersecurity, including both offensive and defensive resources.

---