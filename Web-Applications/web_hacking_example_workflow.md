# Web Hacking Example Workflow

- port scan:
	`sudo nmap -sS -Pn -T4 -p- TARGET_IP`
	`sudo nmap -O -A -Pn -T4 -p80,443,etc TARGET_IP`
- notate all input vectors for later injection testing
- notate all technologies from Wappalyzer
- check the source code of every page for javascript links or files, and for comments left by devs
- check sensitive files
	- `robots.txt`
	- `.well-know`
	- `.git`
- brute force login portals with hydra
	- `hydra -L /usr/share/seclists/Usernames/top-usernames-shortlist.txt -P /usr/share/wordlists/rockyou.txt TARGET_IP http-get`