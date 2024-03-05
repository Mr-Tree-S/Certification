# Privilege_Escalation_Linux

## reference

<https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/>

### gtfobins.github.io

<https://gtfobins.github.io/>

## Information Gathering

```bash
id
hostname
cat /etc/passwd | grep sh$
grep -Ri pass . 2>/dev/null

cat /etc/os-release
searchsploit ubuntu 16.04 kernel
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

## Tips

- linpeas
