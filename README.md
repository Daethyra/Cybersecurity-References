# Cybersecurity References 🛡️🔒

![HACKERMANS by numrii](https://cdn.betterttv.net/emote/5b490e73cf46791f8491f6f4/3x.webp)

Welcome to my personal cybersecurity toolkit.

## [CheatSheets](./CheatSheets)

This directory contains various files, notably [Maderas' list of necessary cybersecurity skills](./CheatSheets/Get_Started-MaderasSecurityArsenal.md "Maderas Security Arsenal") and [Networking-Basics](./CheatSheets/Networking-Basics/) for learners. 

Beyond that, you'll find more advanced, technically focused reference guides on specific topics. There's a load of information on common web application vulnerabilities and how to exploit them in [Web-Applications](./CheatSheets/Web-Applications/). I'm also in the process of building a collection of [Power-Commands](./CheatSheets/Power-Commands/) for different scenarios, with the goal of having something for every stage of a pentest.

### [Web-Applications](./CheatSheets/Web-Applications/)
<details><summary>More</summary>
Documents regarding common web application vulnerabilities, including the OWASP Top Ten. Each with code examples or injection payloads. <a href="./CheatSheets/Web-Applications/XSS.md">XSS</a>, <a href="./CheatSheets/Web-Applications/SSRF_bypassFilters.md">SSRF</a>, and <a href="./CheatSheets/Web-Applications/CORS.md">CORS</a> are just a few examples. The <a href="./CheatSheets/Web-Applications/WebApp-ExploitsChecklist.pdf">WebApp Exploit Checklist</a> is a great visual reference.
</details>

## [EduDocuments](./EduDocuments)

A collection of documents I found myself referring back to for learning.

<details><summary>More</summary>

<details><summary>Continuous Learning</summary>
<ul style="margin-left: 0; list-style: none">
  <li><a href="./EduDocuments/Continuous-Learning/">Continuous Learning</a>
    <ul style="margin-left: 20px">
      <li><a href="./EduDocuments/Continuous-Learning/Generative-AI/">Generative AI</a></li>
      <li><a href="./EduDocuments/Continuous-Learning/Digital-Privacy-Freedom">Digital Privacy & Freedom</a></li>
      <li><a href="./EduDocuments/Continuous-Learning/US-State_Surveillance-Psyops/">US State Surveillance & Psychological Operations</a></li>
    </ul>
  </li>
  <li><a href="./EduDocuments/Pentest_Resources-TCM_Security/">Starter Penetration Testing Resources by TCM Security</a></li>
  <li><a href="./EduDocuments/Sample_Datasets/">Sample Datasets</a></li>
</ul>
</details>

<details><summary>Regulatory Compliance</summary>
<ul style="margin-left: 0; list-style: none">
  <li><a href="./EduDocuments/RegulatoryCompliance">Regulatory Compliance</a>
    <ul style="margin-left: 20px">
      <li><a href="./EduDocuments/RegulatoryCompliance/800-53r5/SP_800-53_v5_1-derived-OSCAL.pdf">Security and Privacy Controls for Information Systems and Organizations</a>
        <ul style="margin-left: 40px">
          <li><a href="./EduDocuments/RegulatoryCompliance/800-53r5/sp800-53r5-control-catalog.xlsx">Spreadsheet</a></li>
        </ul>
      </li>
      <li><a href="./EduDocuments/RegulatoryCompliance/800-66r2/NIST.SP.800-66r2.pdf">Implementing HIPAA Security Rule</a></li>
      <li><a href="./EduDocuments/RegulatoryCompliance/800-171/NIST.SP.800-171r2.pdf">Protecting Controlled Unclassified Information</a>
        <ul style="margin-left: 40px">
          <li><a href="./EduDocuments/RegulatoryCompliance/800-171/sp800-171r2-security-reqs.xlsx">Spreadsheet</a></li>
        </ul>
      </li>
      <li><a href="./EduDocuments/RegulatoryCompliance/NIST.CSWP.04162018.pdf">Framework for Improving Critical Infrastructure Cybersecurity</a></li>
    </ul>
  </li>
</ul>
</details>

</details>

## [Tools](./Tools)

A collection of my scripts I've found repeated use for in multiple scenarios.

<details><summary>Personal automation scripts</summary>

[`extract_video_audio.py`](./Tools/extract_video_audio.py): CLI tool that creates an MP3 audio file from a MP4 file, or files in a directory.

[`firewall_rules.py`](./Tools/firewall_rules.py): CLI tool that optionally accepts a URL as an argument to download a CSV list of known problematic IP addresses and create block rules for Windows Firewall or `iptables` for Linux. 

> The default URL downloads the "Botnet C2 Indicators of Compromise (IOCs)" from FEODOtracker, which contains "information on tracked botnet c2s but also IP addresses that were acting as a botnet C2 within the **past 30 days**."

[`hashfile_validator.py`](./Tools/hashfile_validator.py): A CLI tool that automatically detects and validates cryptographic hash checksums against files. It supports MD5, SHA1, SHA256, SHA384, and SHA512, with optional JSON output and additional file information. The tool uses Windows' built-in Certutil for hash calculation.

[`https_ngrok_config.yml`](./Tools/https_ngrok_config.yml): A sample configuration file that starts an Ngrok HTTPS endpoint w/ OAuth support.

[`regex_generator.py`](./Tools/RegexGenerator.py): Generates regex patterns to detect keyword variations, including obfuscated and evasive text, for precise matching.

[`repo_structure_visualizer.py`](./Tools/repo_structure_visualizer.py): A Python script that automatically generates an interactive HTML navigation interface for a GitHub repository's directory structure. Adaptable for any repository.

[`Reset-DockerWslIntergration.ps1`](./Tools/Reset-DockerWslIntegration.ps1): PowerShell script that stops Docker Desktop, Stops WSL, and Unregisters the Docker Destop data.

[`Useful-Repositories/README.md`](./Tools/Useful-Repositories.md): A document with links to useful cybersecurity-related GitHub repositories.

</details>

## How to Contribute

Please feel encouraged to contribute your own knowledge files, automation scripts, or useful repository link(s). Links go in the [Useful-Repositories document](./Useful-Repositories/README.md).

See the [CONTRIBUTING.md](CONTRIBUTING.md) file for guidelines on how to contribute.

## 📜 License

Distributed under the MIT License. See [LICENSE](./LICENSE) for more information.
