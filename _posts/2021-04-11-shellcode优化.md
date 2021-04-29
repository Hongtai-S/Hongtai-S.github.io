---
layout:     post
title:      0day漏洞学习（五）：总结shellcode的一些优化技术
subtitle:   让注入的代码更能稳定运行
date:       2021-04-11
author:     Hongtai S
header-img: img/1.jpg
catalog: true
tags:
    - 漏洞
    - 二进制
    - shellcode
---

#### 1. 防止shellcode中的push操作破坏自身

（1）减少shellcode的占用空间，增加下方的空间。

（2）使用“跳板”，让压栈数据位于shellcode上方。

#### 2. 动态定位API

使用Dependency Walker计算的API入口地址与实际入口地址可能有所差异，想要动态定位API地址可采取以下方法：

（1）首先通过段选择字FS在内存中找到当前的线程环境块TEB。 

（2）线程环境块偏移位置为0x30的地方存放着指向进程环境块PEB的指针。 

（3）进程环境块中偏移位置为0x0C的地方存放着指向PEB_LDR_DATA结构体的指针，其中，存放着已经被进程装载的动态链接库的信息。 

（4）PEB_LDR_DATA结构体偏移位置为0x1C的地方存放着指向模块初始化链表的头指针 InInitializationOrderModuleList。 

（5） 模块初始化链表InInitializationOrderModuleList中按顺序存放着PE装入运行时初始化模块的信息，第一个链表结点是ntdll.dll，第二个链表结点就是kernel32.dll。 

（6）找到属于kernel32.dll的结点后，在其基础上再偏移0x08就是kernel32.dll在内存中的加载基地址。 

（7）从kernel32.dll的加载基址算起，偏移0x3C的地方就是其PE头。 

（8）PE头偏移0x78的地方存放着指向函数导出表的指针。 

![定位API.PNG](https://i.loli.net/2021/04/11/Z9GAvntuMkmCdH7.png)

#### 3. 执行完shellcode要正常退出进程

调用kernel32.dll的ExitProcess（）

#### 4.  防检测、防输入限制

有些字符串会对NULL限制，如字符串截断符，或者只能输入可见字符的ASCII码值，需要对shellcode进行编码编码解码过程如下：

编码技术

![编码.PNG](https://i.loli.net/2021/04/11/DZeflJ8SKr9mFXu.png)

解码技术

![解码.PNG](https://i.loli.net/2021/04/11/SIJN2yhC8jVDHwa.png)
                                                                             