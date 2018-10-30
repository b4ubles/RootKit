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

### 1.3. 隐藏内核模块列表

编译client后，运行 ``./client show``

### 1.3. 获取root权限

编译client后，运行 ``./client root``

## 1.4 实现功能及其原理

### 隐藏内核模块列表

+ 断链法
+ 隐藏 /sys/module
+ 隐藏 /proc/modules

### Root后门

hook kill的syscall，当接受到特定信号的时候，给予对应的权限

### 开机自启

向 ``/etc/rc3.d`` 目录下增加加载内核模块的语法

