---
layout: default
---

_**Nov 15, 2019**_

# x86 ASCII AND-SUB Encoder

I wrote a JavaScript x86 ASCII AND-SUB encoder and since it's just JavaScript we can run it in the browser! 🚀

## Try it out

Value to encode in EAX: <input name="value" id="value" type="text" value="0xdeadbeef" placeholder="0xdeadbeef"> <button onclick="encode(document.querySelector('#value').value)">ENCODE</button>

Output:

<div style="background-color: black; padding: 10px;">
    <code id="code">
    </code>
</div>

Shellcode to encode (address of encoder in EAX): <input name="shellcode" id="shellcode" type="text" value="\xb8\xef\xbe\xad\xde" placeholder="\xb8\xef\xbe\xad\xde"> <button onclick="encode2(document.querySelector('#shellcode').value)">ENCODE</button>

Output:

<div style="background-color: black; padding: 10px;">
    <code id="code2">
    </code>
</div>

<script>
"use strict";
// 0x20 - 0x7f
const FULL_ALPHA_CHARS = "\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e";
// reserved filename chars on windows
// 0x00-0x1F 0x7F " (0x22) * (0x2a) / (0x2f) : (0x3a) < (0x3c) > (0x3e) ? (0x3f) \ (0x5c) | (0x7c)
const FILENAME_CHARS = "\x20\x21\x23\x24\x25\x26\x27\x28\x29\x2b\x2c\x2d\x2e\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3b\x3d\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7d\x7e";
function hex(a) {
    return '0x' + a.toString(16).padStart(8, '0');
}
function and(a, b) {
    return a & b;
}
function or(a, b) {
    return a | b;
}
function add(a, b) {
    return Uint32Array.from([a + b])[0];
}
function sub(a, b) {
    return Uint32Array.from([a - b])[0];
}
function parseShellcode(shellcode) {
    let output = '';
    output += shellcode
        .split('\\x')
        .filter(a => a)
        .map(c => String.fromCharCode(parseInt(c, 16)))
        .join('');
    return output;
}
function getSingleZeroAndEax2(allowedChars) {
    const allowedCharsArray = allowedChars.split('');
    for (let i = 0; i < allowedCharsArray.length; i++) {
        for (let j = 0; j < allowedCharsArray.length; j++) {
            if (and(allowedCharsArray[i].charCodeAt(0), allowedCharsArray[j].charCodeAt(0)) === 0x0) {
                return [allowedCharsArray[i].charCodeAt(0), allowedCharsArray[j].charCodeAt(0)];
            }
        }
    }
    throw new Error('getSingleZeroAndEax2: combination not found');
}
function getZeroAndEax2(allowedChars, length = 4) {
    const [a, b] = getSingleZeroAndEax2(allowedChars);
    let c = a, d = b;
    for (let i = 0; i < length; i++) {
        c = (c << 8) | a;
        d = (d << 8) | b;
    }
    return [c, d];
}
function getSingleSubEncode(value, previousRemainder, allowedChars) {
    const allowedCharsArray = allowedChars.split('');
    for (let i = 0; i < allowedCharsArray.length; i++) {
        for (let j = 0; j < allowedCharsArray.length; j++) {
            for (let k = 0; k < allowedCharsArray.length; k++) {
                let a = allowedCharsArray[i].charCodeAt(0), b = allowedCharsArray[j].charCodeAt(0), c = allowedCharsArray[k].charCodeAt(0);
                let res = sub(sub(sub(0, a), b), c);
                if (and(res, 0xff) === value) {
                    return [a, b, c, add(sub(0xff, res), previousRemainder) >> 8];
                }
            }
        }
    }
    throw new Error('getSingleSubEncode: combination not found');
}
function getSubEncode(value, allowedChars, length = 4) {
    let remaining = value, remainder = 0, a = 0, b = 0, c = 0;
    for (let i = 0; i < length; i++) {
        const current = and(add(remaining, remainder), 0x00000000000000ff);
        const [d, e, f, r] = getSingleSubEncode(current, remainder, allowedChars);
        a = (d << (8 * i)) | a;
        b = (e << (8 * i)) | b;
        c = (f << (8 * i)) | c;
        remaining = remaining >> 8;
        remainder = r;
    }
    return [a, b, c];
}
function encodeValueInEAX(value) {
    const [a, b] = getZeroAndEax2(FILENAME_CHARS);
    const [c, d, e] = getSubEncode(value, FILENAME_CHARS);
    let output = '';
    output += `and eax, ${hex(a)}\n`;
    output += `and eax, ${hex(b)} ; eax = ${hex(and(a, b))}\n`;
    output += `sub eax, ${hex(c)}\n`;
    output += `sub eax, ${hex(d)}\n`;
    output += `sub eax, ${hex(e)} ; eax = ${hex(sub(sub(sub(0, c), d), e))}\n`;
    return output;
}

function addToEAX(value) {
    const [c, d, e] = getSubEncode(value, FILENAME_CHARS);
    let output = '';
    output += `sub eax, ${hex(c)}\n`;
    output += `sub eax, ${hex(d)}\n`;
    output += `sub eax, ${hex(e)} ; eax += ${hex(sub(sub(sub(0, c), d), e))}\n`;
    return output;
}

function encodeShellcode(shellcode) {
    const paddedShellcode = shellcode.padEnd(shellcode.length + (4 - (shellcode.length % 4)), '\x42')
    const reversedShellcode = paddedShellcode.split('').reverse().join('')
    let output = ''
    let stubLength = 0

    output += `ADD_EAX_PLACEHOLDER`
    stubLength += 15
    output += "push eax\n" // \x51
    stubLength += 1
    output += "pop esp\n" // \x5c
    stubLength += 1

    for (let i = 0; i < reversedShellcode.length; i += 4) {
        let value = 0
        for (let j = 0; j < 4; j++) {
            value = (value << 8) | reversedShellcode.substr(i + j, 1).charCodeAt(0)
        }

        output += encodeValueInEAX(value)
        output += `push eax\n` // \x50
        stubLength += 26
    }

    output = output.replace('ADD_EAX_PLACEHOLDER', addToEAX(stubLength + reversedShellcode.length))
    output += 'dec ecx\n'.repeat(reversedShellcode.length) // \x49 NOPs to be filled with decoded shellcode
    return output
}

function encode(value) {
    value = value || '0xdeadbeef'
    let output = encodeValueInEAX(value)
    document.querySelector('#code').innerText = output
}

function encode2(shellcode) {
    shellcode = shellcode || '\\xb8\\xef\\xbe\\xad\\xde'
    let output = encodeShellcode(parseShellcode(shellcode))
    document.querySelector('#code2').innerText = output
}

encode()
encode2()

</script>

## Source Code (for Node.js)

Usage: `ts-node index.ts 0xdeadbeef`

Source:

```typescript
// 0x20 - 0x7f
const FULL_ALPHA_CHARS = "\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e"

// reserved filename chars on windows
// 0x00-0x1F 0x7F " (0x22) * (0x2a) / (0x2f) : (0x3a) < (0x3c) > (0x3e) ? (0x3f) \ (0x5c) | (0x7c)
const FILENAME_CHARS = "\x20\x21\x23\x24\x25\x26\x27\x28\x29\x2b\x2c\x2d\x2e\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3b\x3d\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7d\x7e"

function hex(a: number) {
    return '0x' + a.toString(16).padStart(8, '0')
}

function and(a: number, b: number) {
    return a & b
}

function or(a: number, b: number) {
    return a | b
}

function add(a: number, b: number) {
    return Uint32Array.from([a + b])[0]
}

function sub(a: number, b: number) {
    return Uint32Array.from([a - b])[0]
}

function parseShellcode(shellcode: string): string {
    let output = ''
    output += shellcode
        .split('\\x')
        .filter(a => a)
        .map(c => String.fromCharCode(parseInt(c, 16)))
        .join('')
    return output
}

function getSingleZeroAndEax2(allowedChars: string): [number, number] {
    const allowedCharsArray = allowedChars.split('')
    for (let i = 0; i < allowedCharsArray.length; i++) {
        for (let j = 0; j < allowedCharsArray.length; j++) {
            if (and(allowedCharsArray[i].charCodeAt(0), allowedCharsArray[j].charCodeAt(0)) === 0x0) {
                return [allowedCharsArray[i].charCodeAt(0), allowedCharsArray[j].charCodeAt(0)]
            }
        }
    }

    throw new Error('getSingleZeroAndEax2: combination not found')
}

function getZeroAndEax2(allowedChars: string, length = 4): [number, number] {
    const [a, b] = getSingleZeroAndEax2(allowedChars)
    let c = a, d = b
    for (let i = 0; i < length; i++) {
        c = (c << 8) | a
        d = (d << 8) | b
    }

    return [c, d]
}

function getSingleSubEncode(value: number, previousRemainder: number, allowedChars: string): [number, number, number, number] {
    const allowedCharsArray = allowedChars.split('')
    for (let i = 0; i < allowedCharsArray.length; i++) {
        for (let j = 0; j < allowedCharsArray.length; j++) {
            for (let k = 0; k < allowedCharsArray.length; k++) {
                let a = allowedCharsArray[i].charCodeAt(0),
                    b = allowedCharsArray[j].charCodeAt(0),
                    c = allowedCharsArray[k].charCodeAt(0)

                let res = sub(sub(sub(0, a), b), c)

                if (and(res, 0xff) === value) {
                    return [a, b, c, add(sub(0xff, res), previousRemainder) >> 8]
                }
            }
        }
    }

    throw new Error('getSingleSubEncode: combination not found')
}

function getSubEncode(value: number, allowedChars: string, length = 4): [number, number, number] {
    let remaining = value,
        remainder = 0,
        a = 0,
        b = 0,
        c = 0

    for (let i = 0; i < length; i++) {
        const current = and(add(remaining, remainder), 0x00000000000000ff)
        const [d, e, f, r] = getSingleSubEncode(current, remainder, allowedChars)
        a = (d << (8 * i)) | a
        b = (e << (8 * i)) | b
        c = (f << (8 * i)) | c

        remaining = remaining >> 8
        remainder = r
    }

    return [a, b, c]
}

function encodeValueInEAX(value: number): string {
    const [a, b] = getZeroAndEax2(FILENAME_CHARS)
    const [c, d, e] = getSubEncode(value, FILENAME_CHARS)
    let output = ''
    output += `and eax, ${hex(a)}\n`
    output += `and eax, ${hex(b)} ; eax = ${hex(and(a, b))}\n`
    output += `sub eax, ${hex(c)}\n`
    output += `sub eax, ${hex(d)}\n`
    output += `sub eax, ${hex(e)} ; eax = ${hex(sub(sub(sub(0, c), d), e))}\n`
    return output
}

function addToEAX(value: number): string {
    const [c, d, e] = getSubEncode(value, FILENAME_CHARS)
    let output = ''
    output += `sub eax, ${hex(c)}\n`
    output += `sub eax, ${hex(d)}\n`
    output += `sub eax, ${hex(e)} ; eax += ${hex(sub(sub(sub(0, c), d), e))}\n`
    return output
}

function encodeShellcode(shellcode: string) {
    const paddedShellcode = shellcode.padEnd(shellcode.length + (4 - (shellcode.length % 4)), '\x42')
    const reversedShellcode = paddedShellcode.split('').reverse().join('')
    let output = ''
    let stubLength = 0

    output += `ADD_EAX_PLACEHOLDER`
    stubLength += 15
    output += "push eax\n" // \x51
    stubLength += 1
    output += "pop esp\n" // \x5c
    stubLength += 1

    for (let i = 0; i < reversedShellcode.length; i += 4) {
        let value = 0
        for (let j = 0; j < 4; j++) {
            value = (value << 8) | reversedShellcode.substr(i + j, 1).charCodeAt(0)
        }

        output += encodeValueInEAX(value)
        output += `push eax\n` // \x50
        stubLength += 26
    }

    output = output.replace('ADD_EAX_PLACEHOLDER', addToEAX(stubLength + reversedShellcode.length))
    output += 'dec ecx\n'.repeat(reversedShellcode.length) // \x49 NOPs to be filled with decoded shellcode
    console.log(`payload length: ${stubLength * 2 + reversedShellcode.length}`)
    return output
}

let shellcode = ''
// metasm > jmp eax
//shellcode += '\xff\xe0'

// metasm > mov eax, 0x11223344
//shellcode += '\xb8\x44\x33\x22\x11'
shellcode += '\\xb8\\x44\\x33\\x22\\x11'

console.log(encodeValueInEAX(0xdeadbeef))

console.log(encodeShellcode(parseShellcode(shellcode)))
```

[back](../)
