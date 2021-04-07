---
layout:     post
title:      0day漏洞学习：栈溢出突破密码验证
subtitle:   一个小crack。
date:       2021-04-07
author:     Hongtai S
header-img: img/post-bg-article.jpg
catalog: true
tags:
    - 漏洞
    - 二进制
---
# 利用栈溢出漏洞突破密码验证程序 #


## 栈结构 ##

在调用函数时，内存会创建栈结构存储函数之间的调用关系，调用结束时使程序执行流回到母函数中继续执行。栈的布局如下：

| ....... |
| 局部变量3 |
| 局部变量2 |
| 局部变量1 |
| EBP |
| 返回地址 |
| ....... |

## 突破验证 ##

程序代码在crack实验的基础上稍作修改，以人为构造出栈溢出漏洞

```cpp,c
#include<stdio.h>
#include<string.h>
#define PASSWORD "1234567"

int verify_password(char *password)
{
	int authenticated;
	char buffer[8];
	authenticated = strcmp(password,PASSWORD);
	strcpy(buffer,password);
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

当调用verify_password时，内存栈布局如下：

| char buffer[0~3] |
| char buffer[4~7] |
| int authenticated(0x00000001) |
| 上一个栈针的EBP |
| 返回地址 |
| 形参password |
| ....... |

由于buffer是字符串数据类型，字符串最后必为字符截断符NULL(0x00)，当输入的buffer超过了7个字符后，刚好字符串截断符把authenticated的最后两位(0x01)覆盖为(0x00)，使得验证通过。

![栈溢出.PNG](https://i.loli.net/2021/04/07/7l3fF249CjvsnRc.png)

按照正常思路，只有输入1234567才能

当输入“qqqqqqq”七个q时，栈的局部变量情况如下：

|局部变量|相对地址|偏移3|偏移2|偏移1|偏移0|
|buffer[0~3]|0x00|0x71|0x71|0x71|0x71|
|buffer[4~7]|0x04|0x00|0x71|0x71|0x71|
|authenticated|0x08|0x00|0x00|0x00|0x01|

![栈局部变量.PNG](https://i.loli.net/2021/04/07/UVuSHbBEqpiQ1Oc.png)


当输入“qqqqqqqq”八个q时，栈的局部变量情况如下：

|局部变量|相对地址|偏移3|偏移2|偏移1|偏移0|
|buffer[0~3]|0x00|0x71|0x71|0x71|0x71|
|buffer[4~7]|0x04|0x71|0x71|0x71|0x71|
|authenticated|0x08|0x00|0x00|0x00|**0x00**|

![stack_overflow.PNG](https://i.loli.net/2021/04/07/bsXtk9JDnCOPr32.png)

这时字符串截断符将authenticated的值覆盖为0，通过栈溢出漏洞成功突破验证。






