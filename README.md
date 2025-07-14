# Cybersecurity References 🛡️🔒

![HACKERMANS by numrii](https://cdn.betterttv.net/emote/5b490e73cf46791f8491f6f4/3x.webp)

Welcome to my personal cybersecurity toolkit.

## [Guides](./Guides)

This directory contains various files including my personal hacking notes in numbered folders, [power commands](./Guides/Power%20Commands/) for quick referencing, a [Document](./Guides/Useful-Repositories.md "Tools and Resources") linking to cybersecurity tools and resources, and a [guide by Maderas](./Guides/0.%20Overviews/Get_Started-MaderasSecurityArsenal.md) for beginners.

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

[`https_ngrok_config.yml`](./Tools/https_ngrok_config.yml): A sample configuration file that starts an Ngrok HTTPS endpoint w/ OAuth support.

[`regex_generator.py`](./Tools/RegexGenerator.py): Generates regex patterns to detect keyword variations, including obfuscated and evasive text, for precise matching.

[`repository_visualizer.py`](./Tools/repository_visualizer.py): A Python script that automatically generates an interactive HTML navigation interface for a GitHub repository's directory structure. Adaptable for any repository. Requires GitHub token.

[`Reset-DockerWslIntergration.ps1`](./Tools/Reset-DockerWslIntegration.ps1): PowerShell script that stops Docker Desktop, Stops WSL, and Unregisters the Docker Destop data.

<!-- </details> -->

## How to Contribute

Please feel encouraged to contribute your own [Guide](./Guides/), automation scripts, or [useful repository link(s)](./Guides/Useful-Repositories.md).

See the [CONTRIBUTING.md](CONTRIBUTING.md) file for guidelines on how to contribute.

## 📜 License

Distributed under the MIT License. See [LICENSE](./LICENSE) for more information.
