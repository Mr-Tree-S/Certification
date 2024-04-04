
# Information Gathering Active

## DNS Enumeration

### host

```bash
for ip in $(cat list.txt); do host $ip.megacorpone.com; done

for ip in $(seq 200 254); do host 51.222.169.$ip; done | grep -v "not found"
```

### dnsenum

```bash
dnsenum megacorpone.com
```

### nslookup

```bash
nslookup -type=TXT info.megacorptwo.com 192.168.50.151
```

## Port Scanning

### nc

```bash
nc -nv -z -w 1 192.168.224.151 1-10000

nc -nv -z -w 1 -u 192.168.224.151 100-200
```

### nmap

#### host discovery

```bash
nmap -sn 192.168.50.1-254 -oG ping-sweep.txt
nmap -sn 172.16.33.0/24
grep Up ping-sweep.txt | cut -d " " -f 2

sudo nmap -p 80 --script http-title.nse  192.168.224.0/24 -oN http-title-N.txt
```

#### port scanning

```bash
sudo nmap -sS 192.168.50.149
nmap -sT -sU 192.168.50.149

for a in $(seq 1 500 65535); do let b=$((a+499)); sleep 2; echo ---$a-$b---; sudo nmap -p $a-$b 192.168.208.211 | grep open; done
```

#### service enumeration

The -A option includes version detection and script scanning, making -sC and -sV unnecessary.

```bash
nmap -p- -A 172.16.33.35 -oN nmap.txt
```

### Test-NetConnection

```powershell
Test-NetConnection -Port 445 192.168.50.151
```

### powershell

```powershell
1..1024 | % {echo ((New-Object Net.Sockets.TcpClient).Connect("192.168.50.151", $_)) "TCP port $_ is open"} 2>$null
```

### directory brute force

#### gobuster

```bash
gobuster dir -u http://172.16.33.9 -w /usr/share/wordlists/dirb/common.txt
```

## search exploit

<https://www.exploit-db.com/>

## Exploit

### searchsploit

```bash
searchsploit syncbreeze
searchsploit -m 49104
```

### metasploit

```bash
search syncbreeze
use exploit/windows/http/syncbreeze_enterprise_get_bof
```

### modify exploit

- protocol, route, url, path, ip, port
- username, password
- request method
- authentication, signed certificate
