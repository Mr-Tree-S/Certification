
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

## Active

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

### port scanning

#### nmap

```bash
nmap -sn 192.168.18.0/24
nmap -p- 192.168.18.1
nmap -p21,80 -sV -A 192.168.18.1
nmap -p445 --script=smb-os-discovery 192.168.18.1
nmap --script=dns-zone-transfer -p 53 ns2.megacorpone.com
nmap -v -p139,445 --script=smb-vuln-ms08-067.nse 192.168.18.1
nmap -sV -sC -p- -oA ./nmap 172.16.33.35
```

## search exploit

<https://www.exploit-db.com/>

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

## modify exploit

### generial

- protocol
- route
- path
- authentication
- request method
- signed certificate

### specific

- url
- username
- password
- response
- ip & port