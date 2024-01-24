
# Phase_2

172.16.33.35
172.16.33.30

172.16.33.55
172.16.33.49
172.16.33.78
172.16.33.79
172.16.33.99
172.16.33.98
172.16.33.103
172.16.33.108
172.16.33.201 (AD)

## 1

### namp

```bash
arp-scan -l
nmap -p- 10.1.8.10 --open --reason
nmap -p21,22,80 -sV -A 10.1.8.10
```

```bash
nmap -sV -sC -p- -oA ./nmap 172.16.33.35
```

### searchsploit

```bash
searchsploit James
searchsploit -m 35513
```

### rbash bypass

ssh

### priviledge escalation

```bash
python -c 'import pty;pty.spawn("/bin/bash")'

stty -a
stty raw -echo
fg
export TERM=xterm
stty rows 38 columns 116
```

```bash
find / -perm -u=s -type f 2>/dev/null
find / -type f -user root -perm -o=w 2>/dev/null | grep -v '/proc/|/sys/'

cat <<< AAA > /opt/tmp.py
```
#### dirtypipe

https://