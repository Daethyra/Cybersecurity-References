# Web App Hacking

Notes on fundamental concepts and online tools and resources.

## Table of Contents

- [Server Side Request Forgery (SSRF)](#server-side-request-forgery-ssrf)

---

## Server Side Request Forgery (SSRF)
**Definition**: A type of security vulnerability that allows an attacker to make requests to internal systems or resources from a server.

What SSRF is *NOT*:
    - A request from the client (ex. a browser)
    - CSRF (Cross-Site Request Forgery): CSRF involves tricking a user into making unwanted requests to another site where they are authenticated.

**Exploiting SSRF Vulnerabilities**:

1. *Internal Network Access*: Craft malicious URLs to access internal network services and resources that are not exposed to the internet.
2. *Sensitive Data Retrieval*: Use SSRF to access internal APIs or services that may return sensitive information, such as configuration files, credentials, or user data.
3. *Port Scanning*: Exploit SSRF to perform port scanning on the internal network, identifying open ports and services that may be vulnerable.
4. *Metadata Services*: In cloud environments, use SSRF to access metadata services (e.g., AWS EC2 metadata service) to retrieve instance credentials and other sensitive information.

**Tools for Exploiting SSRF Vulnerabilities**:
    - [Burp Suite](https://portswigger.net/burp/communitydownload)
    - [Caido](https://caido.io/download)
    - [OWASP ZAP](https://www.zaproxy.org/download/)