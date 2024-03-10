
# Information_Gathering_Active

## host discovery

```bash
nmap -sn 172.16.33.0/24
```

## port scanning

The -A option includes version detection and script scanning, making -sC and -sV unnecessary.

```bash
nmap -sn 172.16.33.0/24
nmap -p- -A 172.16.33.35 -o ./nmap/sr

for a in $(seq 1 500 65535); do let b=$((a+499)); sleep 2; echo ---$a-$b---; sudo nmap -p $a-$b 192.168.208.211 | grep open; done
```

## service enumeration

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
