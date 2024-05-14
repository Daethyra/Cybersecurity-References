# SQL Injection Fundamentals

It is crucial to recognize that many critical vulnerabilities stem from logic flaws that automated scanners may overlook, or they reside within pages or technologies beyond the scanner's reach.

## Finding SQL Injection Vulnerabilities

### Black Box Testing

1. **Mapping the Application**
   - List all potential attack vectors and send all requests through Burp.
   - Explore all accessible pages from an attacker's perspective.
   - Identify input vectors interacting with the database.
   - Understand the application's business logic.
   - Discover subdomains and enumerate directories.

2. **Fuzzing the Application**
   - Test for common SQL injection characters like `', ", --`.
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

## How to Exploit SQL Injection

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