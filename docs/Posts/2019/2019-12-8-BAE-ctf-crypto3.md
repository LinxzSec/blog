---
title: BAE x BSides Chelt CTF
date: 2019-12-08
tags: ["ctf"]
hide:
    - navigation
---

## Introduction

BAE hosted a CTF the day before BSides Cheltenham. I played with my friends. There was a crypto challenge which I saw a number of people struggling with.

The challenge only got three solved in total, I was the first to solve it, so I thought I'd make a writeup of how I did it.

# The Challenge

The challenge was reminiscient of the ECB penguin problem in the sense that we had two picture files in .bmp format, one was given unencrypted and the other was encrypted. The respective file names were: `banner.bmp` and `newbanner.bmp.aes` We were given a text file called `description.txt` with the following content:

???+ quote 
    The administrator of a popular cricketing website was recently updating images on their homepage. During the updates, they accidentally uploaded an image we believe may help the England squad continue their domination of the sport. Unfortunately, the image is encrypted. We do still have a copy of the image that was replaced, if it’s any help. Original file: banner.bmp New file: newbanner.bmp.aes He will have used a strong encryption key and we don’t have time to brute-force it, but we’re not sure what encryption mode he’s used. He does seem pretty obsessed with the English Cricket Board! Is there any way you can get the information we need?

Our goal was to somehow decrypt the .bmp file and retrieve the flag. It's actually quite simple and doesn't involve much crypto at all.

```
hexdump -C banner.bmp | head -n2
00000000  42 4d 76 5c 02 00 00 00  00 00 36 04 00 00 28 00  |BMv\......6...(.|
00000010  00 00 5b 05 00 00 70 00  00 00 01 00 08 00 00 00  |..[...p.........|
```

As shown, the image has a header: `BM` this is expected. Let's now issue the same command on the encrypted file.

```
hexdump -C newbanner.bmp.aes | head -n2
00000000  0e a4 77 dd 6a 96 6a 76  c0 f3 69 18 ac 55 91 e4  |..w.j.jv..i..U..|
00000010  2e 98 dc 4f bc 65 b3 8a  27 bc 6f 67 6f 2c a9 ab  |...O.e..'.ogo,..|
```

No header. Let's try simply adding the header to the encrypted file using `dd` as shown below:

```
dd if=banner.bmp of=newbanner.aes.bmp bs=1 count=54 conv=notrunc
```

Now if we open the encrypted image, the header has been added and we have the flag inside the image.