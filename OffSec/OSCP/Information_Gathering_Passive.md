
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
