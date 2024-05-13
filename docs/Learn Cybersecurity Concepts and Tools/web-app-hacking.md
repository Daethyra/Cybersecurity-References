# Web App Hacking

Notes on fundamental concepts and online tools and resources.

## Table of Contents

- [Server Side Request Forgery (SSRF)](#server-side-request-forgery-ssrf)
    - 

---

## Server Side Request Forgery (SSRF)
**Definition**: A type of security vulnerability that allows an attacker to make requests to internal systems or resources from a server.

### Steps for Indentifying SSRF:
1. Look for places where users can input URLs. This could be integrations with third-party tools, screenshot tools, or PDF generators.
2. Check if the request is being made server-side. You can do this by looking at the IP address that makes the request. If it's the server's IP address, then the request is being made server-side.
3. If the request is being made server-side, try to see if you can access internal resources. This could include reading local files, accessing internal hosts, or sending data.

What SSRF is *NOT*:

    - A request from the client (ex. a browser)
    - CSRF (Cross-Site Request Forgery): CSRF involves tricking a user into making unwanted requests to another site where they are authenticated.

**Exploiting SSRF Vulnerabilities**:

1. *Internal Network Access*: Craft malicious URLs to access internal network services and resources that are not exposed to the internet.
2. *Sensitive Data Retrieval*: Use SSRF to access internal APIs or services that may return sensitive information, such as configuration files, credentials, or user data.
3. *Port Scanning*: Exploit SSRF to perform port scanning on the internal network, identifying open ports and services that may be vulnerable.
4. *Metadata Services*: In cloud environments, use SSRF to access metadata services (e.g., AWS EC2 metadata service) to retrieve instance credentials and other sensitive information.
    - Try querying https://169.254.169.254/metadata
        - Look for metadata keys that you can use to login

**Tools for Exploiting SSRF Vulnerabilities**:
    - [Burp Suite](https://portswigger.net/burp/communitydownload)
    - [Caido](https://caido.io/download)
    - [OWASP ZAP](https://www.zaproxy.org/download/)

## Reconnaissance Tips

### Tools
- Fuzzing w/ [ffuf](https://github.com/ffuf/ffuf) | (Sources: [1](https://youtu.be/0v1CTSyRpMU "NahamSec: What is Fuzzing"), [2](https://youtu.be/YbIEXJhZxUk "NahamSec: Don't Make This Recon Mistake"))
    - 'File' and 'Path' fuzzing
        - Finding Backup logs
            - Use a wordlist of dates (ex. 2022-01-01, 20240101, 2022-01-01T00:00:00, etc.)
            - Use `-e` to search for multiple file extension types (ex. `-e log,txt`)
    - Recursion [1](https://youtu.be/0v1CTSyRpMU?si=0b5i_1Y0PEw06hGS&t=299 "NahamSec: What is Fuzzing")
        - Recursion causes the fuzzer to search for files and folders within any folders it finds within the original target
            - `Found: /admin/`, `Beginning new Search: /admin/*/`
    - Response Codes
        - Search on 200,204,301,302,307,401,403,405,415
            - ffuf argument: `-mc 200,204,301,302,307,401,403,405,415`
        - What to do when all targets return a '200' [(1)](https://youtu.be/0v1CTSyRpMU?si=G8AL5ThITsM6RlFm&t=572 "NahamSec: What is Fuzzing")
            - Filter by file size:
                - Find the repeated values in '200' returns
                    - Exclude on: file size
                        - ffuf argument: `-fs 699`
                    - Exclude on: word count
                        - ffuf argument: `-fw 126`