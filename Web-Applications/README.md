# Web App Hacking Vulnerabilities

This is a living-master-document for the "Web-Applications" subdirectory. Here you'll find more generalized information on identifying and exploiting web vulnerabilities. See the other markdown files in this directory for more specifics and payload examples.

---


## Reconnaissance Tips

- Keep your browser's 'Network' Developer Tool open while broswing a web application to see how the app loads data

### Tools for Exploiting Web Vulnerabilities:
- [Burp Suite](https://portswigger.net/burp/communitydownload)
- [Caido](https://caido.io/download)
- [OWASP ZAP](https://www.zaproxy.org/download/)


## Fuzzing with [ffuf](https://github.com/ffuf/ffuf)
Sources: [1](https://youtu.be/0v1CTSyRpMU "NahamSec: What is Fuzzing"), [2](https://youtu.be/YbIEXJhZxUk "NahamSec: Don't Make This Recon Mistake")
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


## Insecure Direct Object Reference (IDOR)
**Definition**: A type of security vulnerability that "arises when an application uses user-supplied input to access objects directly."[S](https://web.archive.org/web/20240328165820/https://portswigger.net/web-security/access-control/idor "Definition Source")

### Steps for Indentifying IDOR:
1. Notice where user's entered data is reflected in the application
    - Ex. User reviews, profile pictures
2. Look for places where user generated data is directly referenced 
    - URL parameters privilege escalation ex: `?user=10` -> `?user=1`
3. Use a proxy engine to replay/repeat requests that contain static data
    - Ex. Suppose we submit a form to save our address to our profile, our request header contains: `POST /users/1739-3/address HTTP/1.1`, which should stand out as a predictable static value

### Exploiting IDOR Vulnerabilities:
1. *Incrementing/Decrementing Identifiers*: Manually change the identifier values in the URL or request parameters to see if you can access other users' data.
    - Example: If the URL is `https://example.com/account?id=123`, try changing `id=123` to `id=124` or `id=122`.
2. *Predictable Identifiers*: Look for patterns in the identifiers used by the application. If the identifiers follow a predictable sequence (e.g., user IDs increment by 1), you can exploit this by guessing other valid identifiers.
    - Example: If you notice that user IDs are sequential, you can try accessing `https://example.com/account?id=124`, `https://example.com/account?id=125`, etc.
3. *Parameter Manipulation*: Modify request parameters that reference objects directly to see if you can gain unauthorized access. This can include URL parameters, form fields, or JSON payloads.
    - Example: If a form submission includes a hidden field like `<input type="hidden" name="user_id" value="123">`, try changing the value to `124` before submitting the form.


## Server Side Request Forgery (SSRF)
**Definition**: A type of security vulnerability that allows an attacker to make requests to internal systems or resources from a server.

### Steps for Indentifying SSRF:
1. Look for places where users can input URLs. This could be integrations with third-party tools, screenshot tools, or PDF generators.
2. Check if the request is being made server-side. You can do this by looking at the IP address that makes the request. If it's the server's IP address, then the request is being made server-side.
3. If the request is being made server-side, try to see if you can access internal resources. This could include reading local files, accessing internal hosts, or sending data.

What SSRF is *NOT*:

    - A request from the client (ex. a browser)
    - CSRF (Cross-Site Request Forgery): CSRF involves tricking a user into making unwanted requests to another site where they are authenticated.

### Exploiting SSRF Vulnerabilities:

1. *Internal Network Access*: Craft malicious URLs that access internal network services and resources, which are otherwise unaccessible to your external machine.
2. *Sensitive Data Retrieval*: Use SSRF to access internal APIs or services that may return sensitive information, such as configuration files, credentials, or user data.
3. *Port Scanning*: Exploit SSRF to perform port scanning on the internal network, identifying open ports and services that may be vulnerable.
4. *Metadata Services*: In cloud environments, use SSRF to access metadata services (e.g., AWS EC2 metadata service) to retrieve instance credentials and other sensitive information.
    - Try querying https://169.254.169.254/metadata
        - Look for metadata keys that you can use to login