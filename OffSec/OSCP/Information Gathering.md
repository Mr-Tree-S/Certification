
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
- censys

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