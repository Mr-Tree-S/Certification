
# Information Gathering

<https://www.megacorpone.com/>

## Passive

### OSINT

<https://osintframework.com/>

### google hacking

<https://www.exploit-db.com/google-hacking-database>

### netcraft

<https://www.netcraft.com/>

### search engine

- shodan
- fofa

### security headers

<https://securityheaders.com/>

### ssl labs

<https://www.ssllabs.com/ssltest/>

### maltego

maltego is a tool for open source intelligence.

### DNS

#### Zone Transfer

```bash
host -l megacorpone.com ns2.megacorpone.com
dig axfr @ns2.megacorpone.com megacorpone.com
```

#### dnsrecon

```bash
dnsrecon -d megacorpone.com -t axfr
```

#### dnsenum

```bash
dnsenum zonetransfer.me
dnsenum megacorpone.com
```

## Active Scanning

### port scanning

#### nmap

```bash
nmap -sn 172.16.33.0/24

nmap -p- 172.16.33.1
nmap -p21,80 -sV -A 172.16.33.1

nmap -p445 --script=smb-os-discovery 172.16.33.1
nmap -v -p139,445 --script=smb-vuln-ms08-067.nse 172.16.33.1

nmap -sV -sC -A -p- -o ./nmap/sr 172.16.33.9

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
