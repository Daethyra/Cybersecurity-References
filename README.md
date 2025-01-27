# Cybersecurity References 🛡️🔒

Welcome to my personal collection of cybersecurity resources, tools, and references.

## 📁 Directory Structure

### [EduDocuments](./EduDocuments)

This directory contains a collection of documents that can be useful for cybersecurity professionals. It includes a variety of documents that can be useful for different purposes.
- [RegulatoryCompliance](./EduDocuments/RegulatoryCompliance)
    - [Security and Privacy Controls for Information Systems and Organizations](./EduDocuments/RegulatoryCompliance//800-53r5/SP_800-53_v5_1-derived-OSCAL.pdf "PDF")
        - [Spreadsheet](./EduDocuments/RegulatoryCompliance/800-53r5/sp800-53r5-control-catalog.xlsx "XLSX")
    - [Implementing the Health Insurance Portability and Accountability Act (HIPAA) Security Rule](./EduDocuments/RegulatoryCompliance/800-66r2/NIST.SP.800-66r2.pdf "PDF")
    - [Protecting Controlled Unclassified Information in Nonfederal Systems and Organizations](./EduDocuments/RegulatoryCompliance/800-171/NIST.SP.800-171r2.pdf "PDF")
        - [Spreadsheet](./EduDocuments/RegulatoryCompliance/800-171/sp800-171r2-security-reqs.xlsx "XLSX")
    - [Framework for Improving Critical Infrastructure Cybersecurity](./EduDocuments/RegulatoryCompliance/NIST.CSWP.04162018.pdf "PDF")
- [Continuous Learning](./EduDocuments/Continuous-Learning/)
    - [Generative AI](./EduDocuments/Continuous-Learning/Generative-AI/)
    - [Privacy](./EduDocuments/Continuous-Learning/Privacy/ "Learn about digital privacy.")
    - [US State Surveillance & Psychological Operations](./EduDocuments/Continuous-Learning/US-State_Surveillance-Psyops/ "Learn about state-sanctioned psyops in the US and abroad.")
- [Starter Penetration Testing Resources by TCM Security](./EduDocuments/Pentest_Resources-TCM_Security/ "Resources for pentesters in the making.")
- [Sample Datasets](./EduDocuments/Sample_Datasets/ "A collection of datasets to practice working on.")

### [CheatSheets](./CheatSheets)

This directory contains various files, notably [Maderas' list of necessary cybersecurity skills](./CheatSheets/Get_Started-MaderasSecurityArsenal.md "Maderas Security Arsenal") for learners. It also has a few [text processing](./CheatSheets/text-processing/ "Directory") reference docs, and a list of [search engines for pentesters](./CheatSheets/Search_Engines_for_Pentesters.jpg "Search Engines for Pentesters").

#### [Web-Applications](./Web-Applications)

Here you'll find documents for common web application vulnerabilities, like those of the OWASP Top Ten. Each document is different, but all of them contain code examples, injection payloads, that could theoretically be used in the wild. [XSS](./Web-Applications/XSS.md), [SSRF], and [CORS](./Web-Applications/CORS.md) are just a few examples. The [WebApp Exploit Checklist](./Web-Applications/WebApp-ExploitsChecklist.pdf) is a great visual reference.

### [Tools](./Tools)

<details><summary>Personal automation scripts</summary>

[`extract_video_audio.py`](./Tools/extract_video_audio.py): CLI tool that creates an MP3 audio file from a MP4 file, or files in a directory.

[`firewall_rules.py`](./Tools/firewall_rules.py): CLI tool that optionally accepts a URL as an argument to download a CSV list of known problematic IP addresses and create block rules for Windows Firewall. 

> The default URL downloads the "Botnet C2 Indicators of Compromise (IOCs)" from FEODOtracker, which contains "information on tracked botnet c2s but also IP addresses that were acting as a botnet C2 within the **past 30 days**."

[`hashfile_validator.py`](./Tools/hashfile_validator.py): A CLI tool that automatically detects and validates cryptographic hash checksums against files. It supports MD5, SHA1, SHA256, SHA384, and SHA512, with optional JSON output and additional file information. The tool uses Windows' built-in Certutil for hash calculation.

[`https_ngrok_config.yml`](./Tools/https_ngrok_config.yml): A sample configuration file that starts an Ngrok HTTPS endpoint w/ OAuth support.

[`regex_generator.py`](./Tools/RegexGenerator.py): Generates regex patterns to detect keyword variations, including obfuscated and evasive text, for precise matching.

[`Reset-DockerWslIntergration.ps1`](./Tools/Reset-DockerWslIntegration.ps1): PowerShell script that stops Docker Desktop, Stops WSL, and Unregisters the Docker Destop data.

[`Useful-Repositories/README.md`](./Useful-Repositories/README.md): A document with links to useful cybersecurity-related GitHub repositories.

</details>

## How to Contribute
This project could be way better than it is, we both know that.

Please consider contributing your own knowledge files, automation scripts, add to the [Useful Repositories README](./Useful-Repositories/README.md), and see the [CONTRIBUTING.md](CONTRIBUTING.md) file for guidelines on how to contribute.

## 📜 License

Distributed under the GNU AGPL-3.0 License. See [LICENSE](./LICENSE) for more information.
