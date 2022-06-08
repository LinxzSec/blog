---
title: NetSecFocus BSides Cymru AES Challenge
date: 2019-08-31
tags: ["ctf"]
hide:
    - navigation
---

## Introduction

Tunny from NetSecFocus released a CTF challenge in order to win a ticket for BSides Cymru, as the chalelnge was cryptography related I decided to give it a go, a link to the challenge can be found [here](https://github.com/NetSec-Focus/bsides-cymru-ctf)

# Enumeration

First, we need to work out what the challenge entails, we are told we need to decrypt two binary files and let NSF know what they say. We are also given a bash script of how the files were encrypted, let's take a look.

```bash
#!/bin/bash

usage ./cyfuno.sh file file

#tidy up files - work on this later
#head -n 4 file1 > discard.txt
#tail -n +5 file1 > 1.bin
'

#create unique passwords

pass1="$(openssl rand -base64 16)"
pass2="$(openssl rand -base64 16)"

#create unique IVs
iv1="$(openssl rand -hex 8)"
iv2="$(openssl rand -hex 8)"

#echo $pass1
#echo $pass2
#echo $iv1
#echo $iv2

#encrypt files with the unique passwords and IVs
openssl enc -AES-128-CTR -S "$iv1" -pass "pass:$pass1" -in "$1" -out "$1.enc"
openssl enc -AES-128-CTR -S "$iv1" -pass "pass:$pass1" -in "$2" -out "$2.enc"
```

The script passes two files, then some interesting "file tidy up" takes place. From here, the script genreates two passwords of 16 byte length using the `rand()` function in OpenSSL and outputs them in Base64 format. Then we use `rand()` again to generate two IVs of 8 byte length in hex format. If we analyse this, we should first recognise that an 8 byte IV is not correct. It should be 16 bytes to match the block size.

Next, we see that the files we provide are encrypted using AES-128 in Counter mode, taking the IV we generated and using it as a salt for the password that we generated and then outputs the encrypted file. If you look closely we see a major problem; both files reu-use the IV & the passwod! When using AES in CTR mode you should **never** reuse the IV or the key!

Continuing on with the enumeration process, we now have spotted the vulnerability - the encrypted files are the victim of IV & key-reuse, however we still don't know what the first part of the script is doing. We also have an additional file we did not mention, `discard.txt` if we open this file it features some rather weird content and I must admit, this puzzled me for quite a while.

```
P6
# 
1000 1000
255
```

I couldn't work out what this was. I'd never seen it before, it just looked like junk, but after **extensive** Googling, I figured it out. if we script back to the bash script for a moment, we see that the content for this file comes from the use of `head -n 4 file1 > discard.txt` by putting this together along with the content from `discard.txt` I managed to find [this post on crypto stack exchange](https://crypto.stackexchange.com/questions/63145/variation-on-the-ecb-penguin-problem?rq=1) - of course! The ECB penguin problem.

# Attack

So, you might be wondering why re-using an IV or key in AES-CTR is so bad. In short; the attacker can XOR together the two ciphertexts and it recovers the plaintext. Here's the math for that. CTR mode is computed as:

$$ C = P \oplus F(Key, IV) $$

The problem here is that if you encrypt two plaintexts with the same key & IV the attacker is left with two pairs

$$ C_1 = P_1 \oplus F(Key, IV)\ \quad C_2 = P_2 \oplus F(Key, IV)\ $$

As long as we have the values $ C_1 $ and $C_2$ then we can compute the following:

$$ C_1 \oplus C_2 = P_1 \oplus P_2 $$