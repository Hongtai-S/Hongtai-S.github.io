---
layout:     post
title:      0day漏洞学习：一个小crack实验
subtitle:   一个小crack。
date:       2021-04-07
author:     Hongtai S
header-img: img/post-bg-article.jpg
catalog: true
tags:
    - 漏洞
    - 二进制
    - PE文件
---

首先是一段用C编写的密码验证小程序：
```cpp,c
#include<stdio.h>
#include<string.h>
#define PASSWORD "1234567"
int verify_password(char *password)
{
	int authenticated;
	authenticated = strcmp(password,PASSWORD);
	return authenticated;
}

int main()
{
	int valid_flag = 0;
	char password[1024];
	while(1)
	{
		printf("Please input password:");
		scanf("%s",password);
		valid_flag = verify_password(password);
		if (valid_flag)
		{
			printf("incorrect password!\n\n");
		}
		else
		{
			printf("Congratulation!passed!\n");
			break;
		}
	}
	return 0;
}

```

正确输入密码“1234567”才能通过验证。

![1.PNG](https://i.loli.net/2021/04/07/AycqhLTwNJB3OVn.png)

完全由代码`if (valid_flag)`判断，将编译好的可执行文件直接拖入IDA，会显示出文件执行流程图。找到if判断指令。

![IDA.PNG](https://i.loli.net/2021/04/07/Cfbs19Dt7kBi5vQ.png)

按一下空格，跳转到指令对应地址0x004010D5

![ida2.PNG](https://i.loli.net/2021/04/07/3z8w1WGvgcDAx4I.png)

if语句通过jz实现，因此该条指令很可能是验证语句

将可执行文件拖入ollydbg，ctrl + G搜索这条指令的地址0x0x004010D5

找到后将双击指令，将jz修改为jnz，也就是将验证条件取反，原来程序是“当密码是1234567时验证通过”，现在程序是“当密码**不是**1234567时验证通过”

![olly-jnz.PNG](https://i.loli.net/2021/04/07/wmuyeaHUjLMcYBi.png)

此时输入1234567，程序反而显示密码错误，而输入其他密码，程序通过验证。

![result.PNG](https://i.loli.net/2021/04/07/AkDnBPoGOqXuWlt.png)








