# Privilege Escalation Linux

## reference

<https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/>

### GTFOBins

<https://gtfobins.github.io/>

### PEASS-ng

<https://github.com/carlospolop/PEASS-ng>

## full shell

### rbash bypass

```bash
ssh mindy@172.16.33.35 "export TERM=xterm; python -c 'import pty; pty.spawn(\"/bin/bash\")'"
P@55W0rd1!2@
```

### full pty

```bash
bash

stty -a
speed 38400 baud; rows 48; columns 176; line = 0;

control + z
stty raw -echo
fg
```

if use rbash bypass to get a ssh shell, we get a full pty now!!! and don't need to use the following command.

```bash
export SHELL=bash
export TERM=xterm
stty rows 48 columns 176
```

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
for i in $(find / -perm -u=s -type f 2>/dev/null); do strings $i 2>/dev/null | grep -i "OS{"; done
```

## capability

```bash
getcap -r / 2>/dev/null
```

## sudo

```bash
sudo -l
```
