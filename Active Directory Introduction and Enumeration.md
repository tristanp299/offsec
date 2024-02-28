
### Intro
 
- Typical domain controller will also host a DNS server that is authoritative for a given domain.
	- OU (Organizational Unit)
	- OU = file system folder
		- Containers used to store objects
# Manual Enumeration
###  Enumeration Using Legacy Windows Tools
 
Example (assumed breach):
- RDP to target
	- `xfreerdp /u:stephanie /d:corp.com /v:192.168.50.75`
- Net.exe
	- **net user**
		- `net user /domain`
		- (admins tend to add *admin for usernames)
		- `net user jeffadmin /domain`
	- **net group**
		- `net group /domain`
		- `net group “Sales Department” /domain`
 
### Enumerating Active Directory using PowerShell and .NET Classes
 
- Get-ADUser
	- PowerShell cmdlets
	- Only installed by default on domain controllers as part of the Remote Server Administration Tools (RSAT)
		- RSAT is very rarely present on clients in a domain and we must have administrative privileges to install them
		- we can, in principle, import the DLL required for enumeration ourselves, we will look into other options.
- AD enumeration relies on LDAP
	- When a domain machine searches for an object, like a printer, or when we query user or group objects, LDAP is used as the communication channel for the query
		- LDAP is the protocol used to communicate with Active Directory
		- LDAP is not exclusive to AD         
- We'll leverage an Active Directory Services Interface (ADSI) (a set of interfaces built on COM) as an LDAP provider.
	- We need a specific LDAP *AdsPath* in order to communicate with the AD service
	- LDAP path's prototype looks like this:
		-   LDAP://HostName[:PortNumber][/DistinguishedName]
			- Hostname = computer name, IP address or a domain name
			 - Primary Domain Controller (PDC)
				 - DC that holds the most updated information
				  - To find the PDC, we need to find the DC holding the PdcRoleOwner property.
			- Portnumber = optional
		    - DistinguishedName (DN) = unique name identifies an object in AD, including the domain itself.
				- i.e. CN=Stephanie (object),CN=Users (container),DC=corp,DC=com
				- CN = Common Name -> object identifier (distinguished name of the object)
				- DC = Domain Component -> top of an LDAP tree (distinguished name of the domain)
					- Read right to left = top down tree
- Let's begin writing our powershell .NET script by obtaining the required hostname for the PDC.
	- ` [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()`
		- Namespace = System.DirectoryServices.ActiveDirectory
		- Class = Domain
		- Function = GetCurrentDomain()
		- Returns the domain object for the current user
- Automate the script
	- create a variable that will store the domain object
		- ` $domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()`
	- Print variable
		- ` $domainObj`
- Test script
	- bypass the execution policy
		- designed to keep us from accidentally running PowerShell scripts
	- `powershell -ep bypass`
	- `.\enumeration.ps1`
- Extract the value from the PdcRoleOwner property held in our $domainObj variable
	- ` # Store the PdcRoleOwner name to the $PDC variable`
	- `$PDC = $domainObj.PdcRoleOwner.Name`
	-  `$PDC`
- Run script
	- `.\enumeration.ps1`
- Use ADSI directly in PowerShell to retrieve the DN
	- ` ([adsi]'').distinguishedName`
		- Use two single quotes to indicate that the search starts at the top of the AD hierarchy.
-  Add a new variable in our script that will store the DN for the domain
	-  `# Store the Distinguished Name variable into the $DN variable`
	- `$DN = ([adsi]'').distinguishedName`
	- `# Print the $DN variable`
	- `$DN`
- Run
	- `.\enumeration.ps1`
-  Now we must assemble the pieces to build the full LDAP path
           ```$PDC = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().PdcRoleOwner.Name
           $DN = ([adsi]'').distinguishedName 
           $LDAP = "LDAP://$PDC/$DN"
           $LDAP```
 
### Adding Search Functionality to our Script
- So far, our script builds the required LDAP path. Now we can build in search functionality.
-          To do this, we will use two .NET classes that are located in the System.DirectoryServices namespace, more specifically the DirectoryEntry1 and DirectorySearcher2 classes. Let's discuss these before we implement them.
- DirectoryEntry
	- class encapsulates an object in the AD service hierarchy
	- One thing to note with DirectoryEntry is that we can pass it credentials to authenticate to the domain.
	- The DirectorySearcher class performs queries against AD using LDAP.
	- SearchRoot property
		- specify the AD service we want to query
	- Since the DirectoryEntry class encapsulates the LDAP path that points to the top of the hierarchy, we will pass that as a variable to DirectorySearcher.
	- FindAll()
		- returns a collection of all the entries found in AD.
	- implement these two classes into our script
	- ``` $PDC = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().PdcRoleOwner.Name
		$DN = ([adsi]'').distinguishedName 
		$LDAP = "LDAP://$PDC/$DN"
		$direntry = New-Object System.DirectoryServices.DirectoryEntry($LDAP)
		$dirsearcher = New-Object System.DirectoryServices.DirectorySearcher($direntry)
		$dirsearcher.FindAll()```
-   run
	- `.\enumeration.ps1`

- set up a filter that will sift through the samAccountType attribute

- add the filter to the **$dirsearcher.filter**
	- `$dirsearcher.filter="samAccountType=805306368"`
		- 0x30000000 = all user objects

- Final script:
	- ```$PDC = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().PdcRoleOwner.Name
		$DN = ([adsi]'').distinguishedName 
		$LDAP = "LDAP://$PDC/$DN"
		
		$direntry = New-Object System.DirectoryServices.DirectoryEntry($LDAP)
		
		$dirsearcher = New-Object System.DirectoryServices.DirectorySearcher($direntry)
		$dirsearcher.filter="samAccountType=805306368"
		$dirsearcher.FindAll()```
	- Run
		- `.\enumeration.ps1`

- We are very interested in the attributes of each object, which are stored in the Properties field.
- we can store the results we receive from our search in a new variable. We'll iterate through each object and print each property on its own line via a nested loop as shown below.
	- ```$result = $dirsearcher.FindAll()
		Foreach($obj in $result)
		{
	    Foreach($prop in $obj.Properties)
	    {
	        $prop
	    }
	
	    Write-Host "-------------------------------"
		}```
- Run
	- `.\enumeartions.ps1`

- First, we have changed the filter to use the name property to only show information for jeffadmin.
	- `$dirsearcher.filter="name=jeffadmin"`
- Additionally, we have added .memberof to the $prop variable to only display the groups jeffadmin is a member of
	- `$prop.memberof`

- Final Script:
	- ```$dirsearcher = New-Object System.DirectoryServices.DirectorySearcher($direntry)
		$dirsearcher.filter="name=jeffadmin"
		$result = $dirsearcher.FindAll()
		
		Foreach($obj in $result)
		{
		    Foreach($prop in $obj.Properties)
		    {
		        $prop.memberof
		    }
		
		    Write-Host "-------------------------------"
		}```
- Run script:
	`.\enumeration.ps1`

- Have the script accept the samAccountType we wish to enumerate as a command line argument.
	- ```function LDAPSearch {
	    param (
        [string]$LDAPQuery
		    )
	    $PDC = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().PdcRoleOwner.Name
	    $DistinguishedName = ([adsi]'').distinguishedName
	    $DirectoryEntry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$PDC/$DistinguishedName")
	    $DirectorySearcher = New-Object System.DirectoryServices.DirectorySearcher($DirectoryEntry, $LDAPQuery)
	    return $DirectorySearcher.FindAll()
	}```
	
	- To use function, lets import it to memory
		- `Import-Module .\function.ps1`

	- Within PowerShell, we can now use the **LDAPSearch** command (our declared function name) to obtain information from AD		- `LDAPSearch -LDAPQuery "(samAccountType=805306368)"`
	- Can also search directly for an Object Class, which is a component of AD that defines the object type
		- `LDAPSearch -LDAPQuery "(objectclass=group)"`
		- `"(objectclass=Service Personnel)`

- To enumerate every group available in the domain and also display the user members, we can pipe the output into a new variable and use a foreach loop that will print each property for a group.
	- Example: let's focus on the CN and member attributes:
		- ```foreach ($group in $(LDAPSearch -LDAPQuery "(objectCategory=group)")) {$group.properties | select {$_.cn},{$_.member}}```
	- This time, specify *Sales Department*
		- `$sales = LDAPSearch -LDAPQuery "(&(objectCategory=group)(cn=Service Personne))"`
	- print variable
		- `$sales.properties.member`
	- Enumerate *Development Department*
		- `$group = LDAPSearch -LDAPQuery "(&(objectCategory=group)(cn=Development Department*))"`
		- `$group.properties.member`
	- we have another case of a nested group, enumerate `Management Department`
		- `$group = LDAPSearch -LDAPQuery "(&(objectCategory=group)(cn=Management Department*))"`
		- `$group.properties.member`

### AD Enumeration with PowerView

- **PowerView**
	- PowerShell script
	- Enumeration 
	- Installed:
		- **C\Tools**
	- Import to memory:
		- `powershell -ep bypass`
		- `PS C:\Tools> Import-Module .\PowerView.ps1
`
	- All commands:
		- [https://portal.offsec.com/courses/pen-200/books-and-videos/modal/modules/active-directory-introduction-and-enumeration/active-directory-manual-enumeration/ad-enumeration-with-powerview#fn1]
	- also uses .NET classes to obtain the required LDAP path and uses it to communicate with AD

Example:
	- **Get-NetDomain**
		- Domain info
		- `Get-NetDomain`
	- **Get-Netuser**
			- list all users
		- `Get-NetUser | select cn`
		- `Get-NetUser | select cn,pwdlastset,lastlogon`
	- **Get-NetGroup**
		- `Get-NetGroup | select cn`
		- `Get-NetGroup "Sales Department" | select member`

# Manual Enumeration
### Enumerating OS

- **Get-NetComputer**
	- `Get-NetComputer`
	- `Get-NetComputer | select operatingsystem,dnshostname`

### Getting an Overview - Permissions and Logged on Users

-  chained compromise
	- attacker improves access through multiple higher-level accounts to reach a goal
- PowerView's *Find-LocalAdminAccess*
	- scans the network in an attempt to determine if our current user has administrative permissions
	-  relies on the OpenServiceW function --> connects to the Service Control Manager (SCM) on the target machines
	- SCM has database of installed services & drivers on Windows
	- PowerView will attempt to open this database with the SC_MANAGER_ALL_ACCESS access right, which require administrative privileges, 

Exampe:
	-  run **Find-LocalAdminAccess** against corp.com
		- supports parameters such as Computername and Credentials
		- `Find-LocalAdminAccess`

- Alternative ways to obtain information such as which user is logged in to which computer.
		-may be deprecated
	- *NetWkstaUserEnum*
		- requires admin priv
	- *NetSessionEnum*

- **Get-NetSession**
	- uses *NetWkstaUserEnum* and *NetSessionEnum *
	- `Get-NetSession -ComputerName files04 -Verbose`
	- `Get-NetSession -ComputerName web04 -Verbose`
	- `Get-NetSession -ComputerName client74`
	- According to the documentation for NetSessionEnum,3:1 there are five possible query levels: 0,1,2,10,502.
		-Level 0 only returns the name of the computer establishing the session. Levels 1 and 2 return more information but require administrative privileges.
		- This leaves us with Levels 10 and 502. Both should return information such as the name of the computer and name of the user establishing the connection. By default, PowerView uses query level 10 with NetSessionEnum, which should give us the information we are interested in.
		- The permissions required to enumerate sessions with NetSessionEnum are defined in the **SrvsvcSessionInfo** registry key, which is located in the **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\DefaultSecurity** hive.
- In order to view the permissions, we'll use the PowerShell **Get-Acl**
	-  This command will essentially retrieve the permissions for the object we define and print
	- `Get-Acl -Path HKLM:SYSTEM\CurrentControlSet\Services\LanmanServer\DefaultSecurity\ | fl`

- capability SID
	- unforgeable token of authority that grants a Windows component or a Universal Windows Application access to various resources

- Enumerate OS
	- **Net-GetComputer**
		- `Get-NetComputer | select dnshostname,operatingsystem,operatingsystemversion`
- Unable to change registry hive
- *PsLoggedOn* application
	-  will enumerate the registry keys under **HKEY_USERS** to retrieve the security identifiers (SID) of logged-in users and convert the SIDs to usernames.
		- from *SysInternals Suite*
	- Also uses the NetSessionEnum API 
	-  Relies on the Remote Registry service in order to scan the associated key
		- Disabled by default
	-  If it is enabled, the service will stop after ten minutes of inactivity to save resources, but it will re-enable (with an automatic trigger) once we connect with PsLoggedOn
	- Located in: **C:\Tools\PSTools**
	- Run: 
		- `.\PsLoggedon.exe \\files04`
		- `.\PsLoggedon.exwe \\web04`
			- May be false positive (dont know if Remote Registry service is running)
		- `.\PsLoggedon.exe \\client74`

### Enumeration Through Service Principal Names

- *Service Account*
	- services launched by the system itself run in the context
	- LocalSystem, LocalService, and NetworkService, Managed Service Accounts
-  *Service Principal Name* (SPN)
	- identifier that associates a service to a specific service account in AD

- We will again query the DC, this time searching for specific SPNs.
- **setspn.exe**
	- Enumerate SPNs
	- Example (found user = iis_service):
		- `setspn -L iis_service`
			- -L = run against both servers & clients in the domain
Alternative finding SPNs with PowerView
	- `Get-NetUser -SPN | select samaccountname,serviceprincipalname`
- The serviceprincipalname of this account is set to "HTTP/web04.corp.com, HTTP/web04, HTTP/web04.corp.com:80", which is indicative of a web server.
- Let's attempt to resolve web04.corp.com with nslookup:
	- `PS C:\Tools\> nslookup.exe web04.corp.com`

### Enumerating Object Permissions

- *ACE* (Access Control Entries)
	- set of permissions applied to AD object
	- make up *ACL* (Access Control List)

Validation Example:
	1. In an attempt to access the share, the user will send an access token, which consists of the user identity and permissions.
	2.  The target object will then validate the token against the list of permissions (the ACL)
	3.  If the ACL allows the user to access the share, access is granted. Otherwise the request is denied.

List of interesting ACE & descriptions:
	- GenericAll: Full permissions on object
	- GenericWrite: Edit certain attributes on the object
	- WriteOwner: Change ownership of the object
	- WriteDACL: Edit ACE's applied to object
	- AllExtendedRights: Change password, reset password, etc.
	- ForceChangePassword: Password change for object
	- Self (Self-Membership): Add ourselves to for example a group

Mostly interested in:
	- ActiveDirectoryRights 
	- SecurityIdentifier 
Example:
- We can use **Get-ObjectAcl** to enumerate ACEs with PowerView.
	- Ex: `Get-ObjectAcl -Identity stephanie`
- Two SIDs
	- Use PowerView's **Convert-SidToName** command to convert ObjectSID to an actual domain object name:
		- `Convert-SidToName S-1-5-21-1987370270-658905905-1781884369-1104`
		- output -> CORP\stephanie
	- Convert other SID to name
		- `Convert-SidToName S-1-5-21-1987370270-658905905-1781884369-553`
		- output -> CORP\RAS and IAS Servers
			-  the RAS and IAS Servers group has ReadProperty access rights to our user.
- `We can continue to use **Get-ObjectAcl** and select only the properties we are interested in, namely ActiveDirectoryRights and SecurityIdentifier. While the ObjectSID is nice to have, we don't need it when we are enumerating specific objects in AD since it will only contain the SID for the object we are in fact enumerating.`
- `Although we should enumerate all objects the domain, let's start with the Management Department group for now.`
- We will check if any users have GenericAll permissions.
	- `Get-ObjectAcl -Identity "Management Department" | ? {$_.ActiveDirectoryRights -eq "GenericAll"} | select SecurityIdentifier,ActiveDirectoryRights`
		- **-eq** flag to filter the **ActiveDirectoryRights** property
		-  only displaying the values that equal **GenericAll**.
		- then pipe the results into **select**, only displaying the **SecurityIdentifier** and **ActiveDirectoryRights** properties
		- output -> a handful of SIDs

- In this case, we have a total of five objects that have the GenericAll permission on the Management Department object. To make sense of this, let's convert all the SIDs into actual names:
	- ```"S-1-5-21-1987370270-658905905-1781884369-512","S-1-5-21-1987370270-658905905-1781884369-1104","S-1-5-32-548","S-1-5-18","S-1-5-21-1987370270-658905905-1781884369-519" | Convert-SidToName```

- Example use of abusing GenericAll Perms (found out from our user)
	- **add ourselves to Management Group**
		- `net group "Management Department" stephanie /add /domain`
	- verify
		- `Get-NetGroup "Management Department" | select member`
	- clean up after ourselves by removing our user from the group
		- `net group "Management Department" stephanie /del /domain`
	- verify
		- `Get-NetGroup "Management Department" | select member`

### Enumerating Domain Shares

- PowerView's **Find-DomainShare**
	- -*CheckShareAccess*
		- flag to display shares only available to us
	- `Find-DomainShare`

- In this instance, we'll first focus on **SYSVOL**
	- SYSVOL folder:
		- **`%SystemRoot%\SYSVOL\sysvol\domain-name`**
		- **Find-DomainShare | Format-Table -AutoSize**
	- `ls \\dc1.corp.com\sysvol\corp.com\`
	- `ls \\dc1.corp.com\sysvol\corp.com\Policies\`
	- `cat \\dc1.corp.com\sysvol\corp.com\Policies\oldpolicy\old-policy-backup.xml`
		-output -> password 
- Historically, system administrators often changed local workstation passwords through *Group Policy Preferences* (GwePP)
	- the private key for the encryption has been posted on MSDN.
- **gpp-decrypt**
	- decrypt these GPP encrypted passwords
	- `gpp-decrypt "+bsY0V3d4/KgX3VJdO/vyepPfAN1zMFTiQDApgR92JE"`
	- output -> `P@$$w0rd`

- Check out other shares
	- `ls \\FILES04\docshare`
	- `ls \\FILES04\docshare\docs\do-not-share`
	- `cat \\FILES04\docshare\docs\do-not-share\start-email.txt`
	- result -> jeff:HenchmanPutridBonbon11!
		- can use for wordlist

# Active Directory - Automated Enumeration

- *PingCastle*
	- generate gorgeous reports 

### Collecting Data with SharpHound

- *SharpHound*
	- data collection tool
	- We can compile it ourselves, use an already compiled executable, or use it as a PowerShell script
	- Ouput as a zipped json 

- Example:
	- Import module
		- `PS C:\Tools> Import-Module .\Sharphound.ps1`
	- We must first run **Invoke-BloodHound**.
		- `Get-Help Invoke-BloodHound`
		-`Invoke-BloodHound -CollectionMethod All -OutputDirectory C:\Tools\ -OutputPrefix "audit"`
			- ** -CollectionMethod** = describes the various collection methods.
			- **All** = all data
	- collected data location:
		`ls C:\Users\stephanie\Desktop\`
	-  Sharphound created the **bin** cache file to speed up data collection. This is not needed for our analysis and we can safely delete it.
- [Note]:
	- One thing to note is that SharpHound also supports _looping_, which means that the collector will run cyclical queries of our choosing over a period of time.
### Analysing Data using BloodHound
	- In order to use BloodHound, we need to start the *Neo4j* service, which is installed by default. Note that when Bloodhound is installed with APT,2 the Neo4j service is automatically installed as well.
		- Neo4j is essentially an open source graph database (NoSQL) that creates nodes, edges, and properties instead of simple rows and columns.

- Start:
	- `sudo neo4j start`
		- Available:
			- **http://localhost:7474**
		- Default Creds:
			- U:neo4j 
			- P:neo4j
	- `bloodhound` 
- Upload *SharpHound* .zip data
- *More Info*
- *Database  Info*
- *Refresh Database Stats*
- *Analysis*
- *Find all Domain Admins under Domain Information*
- *Shortest Paths*
- *Owned Principals*
	- Must mark any object as *owned* in Bloodhound
		-*Search*
		- *Mark User as Owned*
		- *Mark Computer as Owned*
- *Shortest Paths to Domain Admins from Owned Principals*
		- It's a good idea to mark every object we have access to as owned to improve our visibility into more potential attack vectors. There may be a short path to our goals that hinges on ownership of a particular object.

