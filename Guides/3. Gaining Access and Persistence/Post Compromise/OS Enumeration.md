# Linux
## Universally Useful Checks
- sudo permissions: `sudo -l`
- check directory permissions (read/write/executable): [`ls -l | grep [d,-]rwx`](https://unix.stackexchange.com/questions/516511/list-files-and-directories-that-a-user-has-permission-to)
	- change `rwx` to any assortment(e.g., `r--`, `rw-`)
- Search for world-writable directories
```bash
# Find world-writable directories in $PATH
echo $PATH | tr ':' '\n' | xargs -I{} sh -c 'find {} -type d -perm -0002 2>/dev/null'
```
# Windows
## Antivirus
See [[Abusing Exclusions To Evade Detection _ Dazzy Ddos.pdf]]
1. `sc query windefend`
>Query the Service Control Manager for Windows Defender
>>I couldn't find a list of Anti-Virus service names online :(
2. `nxc smb <ip> -u user -p pass -M enum_av`
## Domain SID
1. `nxc ldap DC1.scrm.local -u sqlsvc -p Pegasus60 -k --get-sid`
2. `whoami /user`
3. PowerShell(Requires Active Directory Module)
	1. Direct retrieval: `(Get-ADDomain).DomainSID.Value`
	2. From user object: `(Get-ADUser "Username").SID.AccountDomainSID`

#windows #domain-sid #netexec #antivirus #enumeration