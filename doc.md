## 1. 说明文档

### 1.1. 安装Rootkit

```bash
sudo apt-get install linux-headers-$(uname -r)
chmod +x install.sh
sudo ./install.sh
```

### 1.2. 删除Rootkit

```bash
chmod +x remove.sh
sudo ./remove.sh
```

### 1.3 文件结构

- client.c rootkit交互客户端
- install.sh 安装脚本
- remove.sh 卸载脚本
- Makefile 编译配置文件
- rootkit.c 源代码

### 1.3 实现功能

- 隐藏内核模块列表
- Root后门

### 1.4 使用方式

#### 1.4. 隐藏内核模块列表

编译client后，运行 ``./client show``

#### 1.4. 获取root权限

编译client后，运行 ``./client root``

