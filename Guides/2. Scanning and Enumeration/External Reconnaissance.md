# External Recon for Hosts/Domains

| Target Validation(Passive)    | WHOIS, nslookup, dnsrecon, hunter.io, phonebook.cz                                                             |
| ----------------------------- | -------------------------------------------------------------------------------------------------------------- |
| Data Breaches(Passive)        | HaveIBeenPwned, Dehashed, Breach-Parse, WeLeakInfo                                                             |
| Subdomain Enumeration(Active) | Startpage, nmap, crt.sh, amass, theharvester, sublist3r, [autorecon by Grimmie](https://pastebin.com/MhE6zXVt) |
| Fingerprinting(Active)        | Nmap, Wappalyzer, Caido/Burp Suite                                                                             |
## Discovering Email Addresses
### Hunter.io
A website that allows for email address discovery. Entering a domain may return the syntax for the company's email addresses.
> Try searching your own company :3
### Phonebook.cz
Another website allowing email address discovery. This search tool returns email addresses it has on file based on the user's search query, which could then be copy/pasted into a list for use in password spraying.