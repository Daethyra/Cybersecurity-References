# LDAP (Lightweight Directory Access Protocol)
> **`Default Port: 389` `Default Secure Port: 636` `Global Catalog for domain-wide searches: 3268` `Secure Global Catalog: 3269`**

**LDAP (Lightweight Directory Access Protocol)** is a software protocol that enables anyone to **locate** organizations, individuals, and other **resources** such as files and devices in a network, whether on the public Internet or on a corporate intranet. LDAP is a "lightweight" (smaller amount of code) version of Directory Access Protocol (DAP). LDAP operates over TCP/IP. [1]

An LDAP directory can be **distributed** among many servers. Each server can have a **replicated** version of the total directory that is **synchronized** periodically. An LDAP server is called a Directory System Agent (DSA). An LDAP server that receives a request from a user takes responsibility for the request, passing it to other DSAs as necessary, but ensuring a single coordinated response for the user.

An LDAP directory is organized in a simple "tree" hierarchy consisting of the following levels:
- The root directory (the starting place or the source of the tree), which branches out to
- Countries, each of which branches out to
- Organizations, which branch out to
- Organizational units (divisions, departments, and so forth), which branches out to (includes an entry for)
- Individuals (which includes people, files, and shared resources such as printers) [2](https://hacktricks.boitatech.com.br/pentesting/pentesting-ldap)

#### When does LDAP Authentication happen?
Like Kerberos, LDAP is used for authentication in AD environments. However, with LDAP authentication, the **application** directly verifies the user’s credentials. The application has a pair of AD credentials that it can use first to query LDAP and then verify the AD user’s credentials. LDAP authentication is a popular mechanism with third-party (non-Microsoft) applications that integrate with AD.

[LDAP authentication](https://sensu.io/blog/what-is-ldap) involves verifying provided usernames and passwords by connecting with a directory service that uses the LDAP protocol. Some directory-servers that use LDAP in this manner are OpenLDAP, MS Active Directory, and OpenDJ.

Here’s a step-by-step breakdown of the authentication process between a client and an AD integrated printer:
1. The client sends a printing request with their AD username and password.
2. The printer (an LDAP-ready system) uses it’s AD credentials to create an LDAP bind request, which is used to authenticate clients (e.g. users or applications) and is sent to the domain controller (DC).
3. DC provides bind response to indicate if the printer’s authentication was successful.
4. Printer requests LDAP User search, which is used to search a given **LDAP** directory for a unique user**.**
5. DC provides the user search response.
6. The printer performs another LDAP Bind request, but this time with the user’s AD credentials.
7. The DC provides another bind response to indicate if the user is authenticated.
8. Printer then notifies the client if authentication was successful and if the print job was accepted. [6](https://infosecwriteups.com/ldap-in-active-directory-f0de5729f72f)

---
# LDAP Attacks
## Enumeration
### Automated Enumeration w/ NMAP
Scrape **public information**(e.g. domain name)**:**
```
nmap -n -sV --script "ldap* and not brute" <IP> #Using anonymous credentials
```
### Clear text credentials
If LDAP is used without SSL you can **sniff credentials in plain text** in the network.

Also, you can perform a **MITM** attack in the network **between the LDAP server and the client.** Here you can perform a **Downgrade Attack** to force the client to use **clear text credentials** to login.

**If SSL is used** you can try to make **MITM** like the mentioned above but offering a **false certificate**, if the **user accepts it**, you are able to Downgrade the authentication method and see the credentials again.
## Information Dumping
### ldapsearch (Requires null or valid credentials)
You can connect to an LDAP server and perform a search using the `ldapsearch` command. 

Check null credentials or if your credentials are valid:
```
ldapsearch -x -h <IP> -D '' -w '' -b "DC=<1_SUBDOMAIN>,DC=<TDL>"
ldapsearch -x -h <IP> -D '<DOMAIN>\<username>' -w '<password>' -b "DC=<1_SUBDOMAIN>,DC=<TDL>"
```
If the response claims "bind must be completed," your credentials are invalid.

You can extract **everything from a domain** using:
```
ldapsearch -x -h <IP> -D '<DOMAIN>\<username>' -w '<password>' -b "DC=<1_SUBDOMAIN>,DC=<TDL>"
-x Simple Authentication
-h LDAP Server
-D My User
-w My password
-b Base site, all data from here will be given
```
> This same resource link contains a manual LDAP enumeration workflow/methodology that may be useful. [2](https://hacktricks.boitatech.com.br/pentesting/pentesting-ldap)
## LDAP Injection
The following information was pulled from the OWASP Project. [3](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/06-Testing_for_LDAP_Injection)

The Lightweight Directory Access Protocol (LDAP) is used to store information about users, hosts, and many other objects. [LDAP injection](https://wiki.owasp.org/index.php/LDAP_injection) is a server-side attack, which could allow sensitive information about users and hosts represented in an LDAP structure to be disclosed, modified, or inserted. This is done by manipulating input parameters afterwards passed to internal search, add, and modify functions.

A web application could use LDAP in order to let users authenticate or search other users’ information inside a corporate structure. The goal of LDAP injection attacks is to inject LDAP search filters metacharacters in a query which will be executed by the application.

[Rfc2254](https://www.ietf.org/rfc/rfc2254.txt) defines a grammar on how to build a search filter on LDAPv3 and extends [Rfc1960](https://www.ietf.org/rfc/rfc1960.txt) (LDAPv2).

An LDAP search filter is constructed in Polish notation, also known as [Polish notation prefix notation](https://en.wikipedia.org/wiki/Polish_notation).

This means that a pseudo code condition on a search filter like this:
`find("cn=John & userPassword=mypass")`

will be represented as:
`find("(&(cn=John)(userPassword=mypass))")`

Boolean conditions and group aggregations on an LDAP search filter could be applied by using the following metacharacters:

|Metachar|Meaning|
|---|---|
|&|Boolean AND|
|\||Boolean OR|
|!|Boolean NOT|
|=|Equals|
|~=|Approx|
|>=|Greater than|
|<=|Less than|
|*|Any character|
|()|Grouping parenthesis|
More complete examples on how to build a search filter can be found in the related RFC.

A successful exploitation of an LDAP injection vulnerability could allow the tester to:
- Access unauthorized content
- Evade application restrictions
- Gather unauthorized information
- Add or modify Objects inside LDAP tree structure
### Test Objectives
- Identify LDAP injection points.
- Assess the severity of the injection.
#### How to Test
##### Example 1: Search Filters
Let’s suppose we have a web application using a search filter like the following one:
`searchfilter="(cn="+user+")"`

which is instantiated by an HTTP request like this:
`https://www.example.com/ldapsearch?user=John`

If the value `John` is replaced with a `*`, by sending the request:
`https://www.example.com/ldapsearch?user=*`

the filter will look like:
`searchfilter="(cn=*)"`

which matches every object with a ‘cn’ attribute equals to anything.

If the application is vulnerable to LDAP injection, it will display some or all of the user’s attributes, depending on the application’s execution flow and the permissions of the LDAP connected user.

A tester could use a trial-and-error approach, by inserting in the parameter `(`, `|`, `&`, `*` and the other characters, in order to check the application for errors.
##### Example 2: Login
If a web application uses LDAP to check user credentials during the login process and it is vulnerable to LDAP injection, it is possible to bypass the authentication check by injecting an always true LDAP query (in a similar way to SQL and XPATH injection ).

Let’s suppose a web application uses a filter to match LDAP user/password pair.
`searchlogin= "(&(uid="+user+")(userPassword={MD5}"+base64(pack("H*",md5(pass)))+"))";`

By using the following values:
```txt
user=*)(uid=*))(|(uid=*
pass=password
```

the search filter will results in:
`searchlogin="(&(uid=*)(uid=*))(|(uid=*)(userPassword={MD5}X03MO1qnZdYdgyfeuILPmQ==))";`

which is correct and always true. This way, the tester will gain logged-in status as the first user in LDAP tree.
# Resources
1. https://hackviser.com/tactics/pentesting/services/ldap
2. https://hacktricks.boitatech.com.br/pentesting/pentesting-ldap *
3. https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/06-Testing_for_LDAP_Injection
4. https://viperone.gitbook.io/pentest-everything/everything/ports/ldap
5. https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-ldap.html *
6. https://infosecwriteups.com/ldap-in-active-directory-f0de5729f72f
7. Metasploit documentation for LDAP pentesting: https://docs.metasploit.com/docs/pentesting/metasploit-guide-ldap.html

\* == Favorite resource