---
title: HackSys Extreme Vulnerable Driver 3 - Double Fetch
date: 2022-05-21
tags: ["windows-kernel-exploitation"]
hide:
    - navigation
---

## Introduction

This post is part of a series on Hacksys Extreme Vulnerable Driver, if you have not read my [previous post](/Posts/2022-05-14-HEVD3-StackOverflow/) I would suggest reading it unless you're already familiar with kernel exploitation on Windows.

In this post we will be exploring a Double Fetch vulnerability. - we assume that you already have an environment setup to follow along. However, if you don't have an environment setup in this post we use:

- Windows 10 Pro x64 RS1
- HEVD 3.00

If you are not sure how to setup a kernel debugging environment you can find plenty of posts of the process online, we will not cover the process in this post.

<hr>

# Double Fetch

Before covering the vulnerability lets first talk a bit about what a Double Fetch bug actually is. In short a Double Fetch is a specific type of time-of-check to time-of-use bug. The general cause is when a process reads an untrusted variable more than once without re-verifying any checks of the variable on the second read. These bugs are very common in shared memory interfaces. I would highly recommend you read the [research report](https://research.nccgroup.com/2022/03/28/whitepaper-double-fetch-vulnerabilities-in-c-and-c/) by Nick Dunn from NCC Group.

# Reversing the Driver

In this post we will assume that you have read the [previous post](https://linxz.tech/post/hevd/2022-05-14-hevd3-stackbufferoverflow/) in which we explore a simple stack buffer overflow in HEVD, if you have not read that post I'd recommend you read it as it is a nice introduction to driver exploitation on Windows.

As noted in the previous post the IRP handler is located at `sub_140085078` however we will refer to this function as `IrpDeviceIoCtlHandler` going forward.