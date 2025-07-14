## Path Traversal Vulnerabilities

Path traversal vulnerabilities arise when an application permits users to specify a path to a file or resource that the application subsequently accesses. This can result in unauthorized access to files, directories, or other resources beyond the intended scope of the application. Exploiting these vulnerabilities enables attackers to read, write, or execute arbitrary files on the server, potentially leading to data theft, data corruption, or remote code execution.

### Understanding Path Traversal

If the application lacks defenses against directory traversal attacks, attackers can manipulate URLs to access sensitive files on the server. For instance, an attacker could request the following URL to retrieve an arbitrary file from the server's filesystem:

`https://insecure-website.com/loadImage?filename=../../../etc/passwd`

### Techniques to Exploit Path Traversal

#### Absolute Path Bypass

By utilizing nested traversal sequences like `....//` or `....\/`, attackers can circumvent security measures that strip inner traversal sequences, reverting to simple traversal sequences.

#### Superfluous Character Stripping

In certain contexts, such as URL paths or the filename parameter of a multipart/form-data request, web servers may remove directory traversal sequences before passing user input to the application. To bypass such sanitization, attackers can employ URL encoding or double URL encoding of the `../` characters, resulting in `%2e%2e%2f` or `%252e%252e%252f`, respectively. Non-standard encodings like `..%c0%af` or `..%ef%bc%8f` may also prove effective.

#### Validation of Start Path

To evade security measures, attackers may attempt to manipulate the start path validation. For instance:

`filename=/var/www/images/../../../etc/passwd`

#### Null Byte Bypass

By appending a null byte (`%00`) to the filename, attackers can deceive the application into processing the file path incorrectly, potentially leading to unauthorized access. For example:

`filename=../../../etc/passwd%00.png`

### Practice Lab

For hands-on experience and further understanding of path traversal vulnerabilities, you can explore the [Practice Lab](https://portswigger.net/web-security/file-path-traversal).