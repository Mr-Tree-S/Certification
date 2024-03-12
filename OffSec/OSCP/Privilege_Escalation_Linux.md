# Privilege_Escalation_Linux

## reference

<https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/>

### GTFOBins

<https://gtfobins.github.io/>

### PEASS-ng

<https://github.com/carlospolop/PEASS-ng>

## general

- 发行版/内核
- 进程
- cron
- 可写目录，文件 /etc/passwd
- SUID
- 用户主目录
- env PATH
- sudo -s / sudo -l
- getcap

## Information Gathering

```bash
id
hostname
cat /etc/passwd | grep sh$
grep -nri pass . 2>/dev/null

uname -a
searchsploit ubuntu 16.04 kernel

ps -ef
ps aux

ip a
ip r
ss -aptun

sudo iptables -L

crontab -l
ls -al /var/log/cron

find / --witeable -type f -user root -perm -u=x 2>/dev/null
```

## SUID

```bash
find / -perm -u=s -type f 2>/dev/null
```

## capability

```bash
getcap -r / 2>/dev/null
```

## sudo

```bash
sudo -l
```


