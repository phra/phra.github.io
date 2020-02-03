---
layout: default
---

_**Feb XX, 2020**_

# x0rro -- A PE/ELF/MachO Crypter for x86 and x86_64 Based on Radare2

Often AV software relies on simple signatures to detect malicious software and I needed an automated tool in order to confirm this behaviour and be able to quickly produce a working bypass. That's why I wrote [x0rro](https://github.com/phra/x0rro), a simple crypter based on [Radare2](https://rada.re/n/) that supports both x86 and x86_64 architectures for PE, ELF and MachO executable formats.

_asciinema_

## Design

Let's identify our requirements in order to kick off the design phase.

As our ideal use case, we want to be able to take an existing executable that prints the string _Hello World!_ to stdout and produce a variant that doesn't include anymore the string in the binary itself but still correctly prints it.

Our goal is to be able to quickly produce variations of the same binary while maintaining its original behaviour.

As a requirement, we would like to implement a solution that supports multiple operating systems and architectures.

We also want to be able to select which sections of the executable binary we want to alter, potentially selecting only portions of specific sections.

As a nice to have, we would like to avoid including specific libraries to deal with single executable formats and keep the codebase as much generic as we can.

Since we want to achieve a simple signature bypass, we won't include any kind of anti-debug or anti-sandbox features in our crypter.

## Research & Development

In order to fulfill our requirements, I decided to implement a software based on [Radare2](https://rada.re/n/), the _Libre and Portable Reverse Engineering Framework_.

I chose [TypeScript](https://www.typescriptlang.org/) as language and [NodeJS](https://nodejs.org) as runtime.

[R2Pipe](https://github.com/radareorg/radare2-r2pipe) can be used to communicate with Radare2 and there are bindings available for the major languages, including JavaScript (NodeJS) and Python.

For some functionalities there are currently missing in Radare2, such as adding segments/sections and changing their permission, we will resort on the Python library [LIEF](https://lief.quarkslab.com/doc/latest/api/python/index.html).

## x0rro

[back](../)
