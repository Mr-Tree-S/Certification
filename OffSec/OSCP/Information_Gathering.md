
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

使用 -A 参数后，通常可以不再需要 -sC 和 -sV 参数，因为 -A 参数已经包含了服务版本检测和脚本扫描的功能。 -A 参数会启用操作系统检测、版本检测、脚本扫描和traceroute等一系列功能。

```bash
nmap -sn 172.16.33.0/24
nmap -p- -A 172.16.33.35
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
