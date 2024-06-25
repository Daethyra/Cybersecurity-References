# Injection Fundamentals

## Overview

[An application is vulnerable to attack when](https://owasp.org/Top10/A03_2021-Injection/#description "Source"):

* User-supplied data is not validated, filtered, or sanitized by the application.

* Dynamic queries or non-parameterized calls without context-aware escaping are used directly in the interpreter.

* Hostile data is used within object-relational mapping (ORM) search parameters to extract additional, sensitive records.

* Hostile data is directly used or concatenated. The SQL or command contains the structure and malicious data in dynamic queries, commands, or stored procedures.

To find injection vulnerabilities, one should test all parameters, headers, URL, cookies, JSON, SOAP, and XML data inputs. It is important to keep an exhaustive list of these input fields for your target and to check them off as you test each one.

It is crucial to recognize that many critical vulnerabilities stem from logic flaws that automated scanners may overlook, or they reside within pages or technologies beyond the scanner's reach.

### Black Box Testing

1. **Mapping the Application**
   - Turn on a web proxy, like OWASP ZAP or Burp Suite.
   - List all potential attack vectors (parameters, headers, URL, cookies, JSON, SOAP, XML).
   - Explore all accessible pages from the attacker-perspective.
   - Identify input vectors interacting with the database.
   - Understand the application's business logic.
   - Discover subdomains and enumerate directories.

2. **Fuzzing the Application**
   - Test for using common injection characters. SQL Ex. `'`, `"`, `--`, `;`
   - Attempt to provoke error messages.
   - Submit boolean conditions like `OR 1=1` and `OR 1=2`.
   - Inject SQL characters into input vectors and observe unusual responses.
   - Test payloads designed to induce time delays and detect response time discrepancies.
   - Experiment with out-of-band connection payloads; confirmation occurs upon server-side HTTP requests or DNS lookups.

### White Box Testing

1. **Enabling Web Server Logging**
   - Errors will surface when SQL injection vulnerabilities exist.

2. **Enabling Database Logging**
   - Monitor database logs to track which characters pass through to the database.

3. **Mapping the Application**
   - Document input vectors and conduct regex searches to identify database access instances.

## Operating Systems Injection Vulnerabilities

### [How to test for OS Injections](https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html#operating-system-commands "Source")

Appending a semicolon to the end of a URL query parameter followed by an operating system command, will execute the command. `%3B` is URL encoded and decodes to semicolon. This is because the `;` is interpreted as a command separator.

Example: `http://sensitive/something.php?dir=%3Bcat%20/etc/passwd`

If the application responds with the output of the `/etc/passwd` file then you know the attack has been successful. Many web application scanners can be used to test for this attack as they inject variations of command injections and test the response.

## Structured Query Language (SQL) Injection Vulnerabilities

### How to Exploit SQL Injection

1. **Testing for Vulnerabilities**
   - Submit SQL-specific characters like `'` or `"` and observe error messages or anomalies.

2. **Exploiting Union-Based SQL Injection**
   - Ensure the number and order of columns remain consistent across queries.
   - Verify data types compatibility.
   - Determine the number of columns queried by the database.
     - Use `ORDER BY` or `UNION SELECT` clauses to incrementally identify the column count.

3. **Exploiting Boolean-Based Blind SQL Injection**
   - Submit boolean condition queries to evaluate responses for True and False.
   - Utilize tools like SQLmap for automated testing.

4. **Exploiting Time-Based Blind SQL Injection**
   - Submit payloads that delay the application for a specified time.
   - Pose TRUE/FALSE questions to extract database data systematically.