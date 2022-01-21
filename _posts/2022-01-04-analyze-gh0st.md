---
layout:     post
title:      恶意软件分析（一）：Gh0st分析
subtitle:   典型远程控制恶意软件
date:       2022-01-04
author:     Hongtai S
header-img: img/16.jpg
catalog: true
tags:
    - 逆向
    - 二进制
    - 恶意代码分析
---
# 样本基本信息

样本文件名称：23c55e32ba9a9ebf54fb47cd198a4d73.bin

样本文件类型：使用exeinfope查看文件类型：

![1.png](https://s2.loli.net/2022/01/21/ObYNJVxCujr1GFZ.png)

样本无壳，使用VC++ 6.0编写。

# 样本行为分析

## 注册表自启动

修改HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run\loveqq键值为1

![2.png](https://s2.loli.net/2022/01/21/QWpVsOBn3P97FKL.png)

## 创建互斥体

创建名为“192.168.22.111”的互斥体

![3.png](https://s2.loli.net/2022/01/21/t1bS9yu62jKXIiG.png)

# 样本功能分析

## 1. 获取主机磁盘驱动器信息

相关函数：sub_405A80

![4.png](https://s2.loli.net/2022/01/21/uWhtQ3lH2SziB4Z.png)
![5.png](https://s2.loli.net/2022/01/21/L1u7BAFvP62ZkoU.png)

首先通过GetLogicalDriveStringsA()函数获取主机所有逻辑驱动器的根驱动器路径，通过GetVolumeInformationA()检索文件系统和卷的信息，GetDriveTypeA()确定磁盘驱动器类型。

## 2. 获取屏幕截图

相关函数：sub_40C520

![6.png](https://s2.loli.net/2022/01/21/4idM6jJpcYOBUhR.png)
![7.png](https://s2.loli.net/2022/01/21/k4rQjGectW1wR27.png)
![8.png](https://s2.loli.net/2022/01/21/BgZwlvkox83cbY6.png)

GetDesktopWindow()获取桌面窗口句柄，GetSystemMetrics()获取主显示屏的宽度和高度，CreateDIBSection()创建一个设备无关的位图(DIB)。

## 3. 弹出自定义内容的对话框

相关函数：sub_407340

![9.png](https://s2.loli.net/2022/01/21/hB7TofyON6VU9zc.png)

MessageBoxA()弹出对话框。

## 4. 击键记录

相关函数：sub_40A540

![10.png](https://s2.loli.net/2022/01/21/wRUAJKW6uY7kPGE.png)
![11.png](https://s2.loli.net/2022/01/21/TsXlSM8nYrcqbuk.png)
![12.png](https://s2.loli.net/2022/01/21/ezonYwQMu5pLIsk.png)
![13.png](https://s2.loli.net/2022/01/21/m16JqbOhU3IxpQB.png)

GetAsyncKeyState(v2)获取虚拟键的按键状态，v2来源于dword_476878，dword_476878处记录了各个虚拟键码。

## 5. 录音功能

相关函数：sub_4012C0

![14.png](https://s2.loli.net/2022/01/21/dxRfIetE9TYZjyq.png)

waveInGetNumDevs()检查主机中是否存在波形音频输入设备，waveInOpen()打开波形音频设备，waveInStart()开启录音。

## 6. 调整当前恶意进程权限

相关函数：sub_408000

![15.png](https://s2.loli.net/2022/01/21/km3ySdbAFluNarU.png)

GetCurrentProcess()获取当前进程的句柄，OpenProcessToken()打开当前进程令牌，AdjustTokenPrivileges()调整新的权限。

## 7. 创建用户

相关函数：sub_409B90

![16.png](https://s2.loli.net/2022/01/21/GnkrXsuI1WS9ejc.png)

NetUserAdd()创建用户，NetLocalGroupAddMembers()将创建的用户添加到用户组中。

## 8. 关闭连接共享和防火墙服务

相关函数：sub_4091D0

![17.png](https://s2.loli.net/2022/01/21/cwRyFvsqXhldrQo.png)

WinExec()函数执行“cmd /c net stop sharedaccess”命令，关闭连接共享和防火墙服务。

## 9. 创建隐藏的cmd.exe进程

相关函数：sub_40DA10

![18.png](https://s2.loli.net/2022/01/21/AIYtSlCT5bP8KjE.png)

CreateProcessA()创建名为cmd.exe的进程，并且StartupInfo.wShowWindow设置为0，不显示窗口。

## 10. 关闭、重启或注销系统

相关函数：sub_40F1A0

![19.png](https://s2.loli.net/2022/01/21/OpskhDXZixjq9Ag.png)

## 11. 从指定的url下载文件，并执行该文件

相关函数：sub_407AD0

![20.png](https://s2.loli.net/2022/01/21/Nim83QOAByhWuTE.png)

URLDownloadToFileA()下载文件后将其保存在WinSta0\\Default，CreateProcessA()执行该文件。

## 12. 从指定url连接下载、保存并执行文件，并退出本进程

相关函数：sub_407BF0

![21.png](https://s2.loli.net/2022/01/21/k6yTxunP9IM7AwF.png)
![22.png](https://s2.loli.net/2022/01/21/ZDVBXKmWvdYz8C4.png)
![23.png](https://s2.loli.net/2022/01/21/JdEsWH2P6r4KC7X.png)

sub_40F6C0()函数从指定的url中下载文件，下载的文件保存到WinSta0\\Default中，CreateProcessA()创建进程执行该文件。若成功执行，则关闭本进程。

## 13. 清空有"Security"、"System"、"Application"名字的事件日志

相关函数：sub_407F10

![24.png](https://s2.loli.net/2022/01/21/c5OYUMx3CmujGSV.png)

OpenEventLogA()打开日志，ClearEventLogA()清理日志，CloseEventLog()关闭日志。

## 14. 获取所有进程路径

相关函数：sub_40EE30

![25.png](https://s2.loli.net/2022/01/21/oQWmf4L9bdqPE2g.png)

CreateToolhelp32Snapshot()为所有进程建立快照，Process32First()、Process32Next()遍历全部进程句柄，GetModuleFileNameExA()获取进程路径。

## 15. 获取全部可见窗口的创建者Id和标题名

相关函数：sub_40F2D0

![26.png](https://s2.loli.net/2022/01/21/o5UbCZ4M2kO8xsh.png)
![27.png](https://s2.loli.net/2022/01/21/u7iVgAebJFOx2Ll.png)

GetWindowTextA()获取窗口标题文本，IsWindowVisible()判断窗口的可见性，GetWindowThreadProcessId()获取创建窗口的进程线程Id。

## 16. 控制鼠标和键盘

相关函数：sub_40C140

![28.png](https://s2.loli.net/2022/01/21/zf7C8oeEZxhSunb.png)
![29.png](https://s2.loli.net/2022/01/21/VqaEp6X2IGRZzbw.png)
![30.png](https://s2.loli.net/2022/01/21/EJzjB758hFoiKPf.png)

SetCursorPos()控制鼠标移动至屏幕指定坐标，mouse_event()控制鼠标按键和滚轮。MapVirtualKeyA()将虚拟键码映射成扫描码，keybd_event()控制按键和抬键。