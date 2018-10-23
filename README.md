# RootKit

## 1. 作业要求

要求以实现rootkit的常见功能为主，如

+ 进程隐藏
+ 文件隐藏
+ 端口隐藏
+ 内核模块列表隐藏
+ Root用户后门
+ 感染系统进程实现自启
+ 绕过系统防御

提交

+ 程序及其源码
+ 说明文档
+ 演示截图或录屏
+ 汇报ppt

## 2. 说明文档

### 2.1. Install

```bash
sudo apt-get install linux-headers-$(uname -r)
chmod +x install.sh
sudo ./install.sh
```

### 2.2. Remove

```bash
chmod +x remove.sh
sudo ./remove.sh
```

### 2.3 文件结构

- install.sh 安装脚本
- remove.sh 卸载脚本
- Makefile 编译配置文件
- rootkit.c 源代码

## 3. 原理

### 3.1. 可装载内核模块（LKM）

在Linux系统中，如果想在内核中运行代码，可以借助于可装载内核模块（LKM）。将自定义的模块加载到内核。一些有用的内核符号就会被内核导出，便能够去使用它们，或者也可以通过 ``kallsyms_lookup_name`` 函数来获取。

Linux模块需要用 ``module_init`` 函数注册模块初始化函数，这个函数会在模块加载时由系统调用；用 ``module_exit`` 函数注册模块卸载函数，这个函数会在模块卸载时被调用。

其加载的主要流程如下：

1. 将模块的可执行文件复制到内核申请的临时镜像中

2. 建立一个structmodule结构体指针，指向模块编译时生成的 ``__this_module`` 结构体，这个结构体初始化了模块初始化函数和卸载函数等成员

3. 将临时镜像中的各个段复制到永久镜像中，永久镜像的地址保存在 ``structmodule`` 结构体中

4. 将 ``structmodule`` 结构体加入到内核模块链表中；

5. 根据永久镜像的起始地址和各个段的偏移重定向代码段中的指针

6. 向sys文件系统注册模块信息

7. 释放临时镜像

8. 执行模块通过 ``module_init`` 函数注册的初始化函数的代码

### 3.2. 系统调用

在内核之中，存在一个系统调用表。其中的系统调用编号（系统调用发生时rax的值）是其Handler在其表中的偏移量。在Windows系统中，由于PatchGuard内核保护系统的存在，系统调用表是无法接触到的。但在Linux系统中可以避开它。

需要注意的是，如果将系统调用表弄乱，会造成非常严重的问题，所以要考虑将Hook放置在其他地方。

系统调用表位于 ``sys_call_table`` ，是系统内核的一块区间，其作用是将调用号和服务连接起来，当系统调用某一个进程时，就会通过 ``sys_call_table`` 查找到该程序。

Linux发起系统调用的流程是：

1. 在用户态发起系统调用请求
2. 进程切换到内核态
3. 找到 ``sys_call_table`` 中与系统调用号对应的函数
4. 执行内核函数
5. 返回到用户态

根据进程切换到内核态所执行指令的不同系统调用可分为 ``int 0x80`` 模式、 ``sysenter`` 模式和 ``syscall`` 模式三种。

``int 0x80`` 中断模式是最古老的模式，它通过用户态进程使用int指令发起0x80中断的方式进入内核态，由相应的内核中断处理函数找到 ``sys_call_table`` 中的函数并执行。

进程使用 ``sysenter`` 指令也可以切换到内核态，且效率比int 0x80方式更高。在CPU支持 ``sysenter`` 的情况下，系统调用由 ``sysenter`` 指令实现。

在32位系统中Linux使用 ``int 0x80`` 和 ``sysenter`` 切换到内核态，在64位环境下使用的时 ``syscall`` 指令。

### 3.3. Hook

系统调用表是只读的，当在内核中的时候，这并不会成为较大的阻碍因素。在内核中，CR0是一个控制寄存器，可以修改处理器的操作方式。其中的第16位是写保护标志所在的位置，如果该标志为0，CPU就可以让内核写入只读页。Linux为我们提供了两个很有帮助的函数，可以用于修改CR0寄存器，分别是write_cr0和read_cr0。

因此可以通过 ``write_cr0(read_cr0() & (~WRITE_PROTECT_FLAG));`` 关闭写保护机制，修改后通过 ``write_cr0(read_cr0() | WRITE_PROTECT_FLAG);`` 将其重新打开。

### 3.4. 模块列表隐藏

lsmod命令是通过 ``/proc/modules`` 来获取当前系统模块信息的。而 ``/proc/modules`` 中的当前系统模块信息是内核利用 ``struct modules`` 结构体的表头遍历内核模块链表、从所有模块的 ``struct module`` 结构体中获取模块的相关信息来得到的。

结构体 ``struct module`` 在内核中代表一个内核模块。通过 ``insmod`` 把编写的内核模块插入内核时，模块便与一个 ``struct module`` 结构体相关联，并成为内核的一部分。

所有的内核模块都被维护在一个全局链表中，链表头是一个全局变量 ``struct module *modules`` 。任何一个新创建的模块，都会被加入到这个链表的头部，通过 ``modules->next`` 即可引用到。为了让模块在 ``lsmod`` 命令中的输出里消失掉，需要使用 ``list_del_init`` 在这个链表内删除rootkit的模块。

### 3.5. 进程隐藏

Linux系统中获取进程信息时使用 ``openat`` 系统调用获取 ``/proc`` 下的文件，然后读取对应PID的 ``/proc/PID/status`` , ``/proc/PID/stat`` , and ``/proc/PID/cmdline``.

用来查询文件信息的系统调用是 ``sys_getdents`` ，这一点可以通过 ``strace`` 来观察到，例如 ``strace ls`` 将列出命令 ``ls`` 用到的系统调用，从中可以发现ls是通过 ``getdents`` 系统调用来操作的，对应于内核里的 ``sys_getedents`` 来执行。

当查询文件或者目录的相关信息时，Linux系统用 ``sys_getedents`` 来执行相应的查询操作，并把得到的信息传递给用户空间运行的程序，所以如果修改该系统调用，去掉结果中与某些特定文件的相关信息，那么所有利用该系统调用的程序将看不见该文件，从而达到了隐藏的目的。

sys_getdents的原型为：

```c
int sys_getdents(unsigned int fd, struct dirent *dirp,unsigned int count)
```

其中fd为指向目录文件的文件描述符，该函数根据fd所指向的目录文件读取相应dirent结构，并放入dirp中，其中count为dirp中返回的数据量，正确时该函数返回值为填充到dirp的字节数。

### 3.6. 开机自启

方法一，修改初始化配置文件

```
/etc/modules-load.d/*.conf
/run/modules-load.d/*.conf
/usr/lib/modules-load.d/*.conf
```

方法二，修改[modprobe.d](http://man7.org/linux/man-pages/man5/modprobe.d.5.html)，当一个模块正常加载时，加载rootkit

方法三，修改[modules.dep](http://man7.org/linux/man-pages/man5/modules.dep.5.html)，使得内核模块为另一个模块的依赖项

## 4. 相关API

### 4.1 命令

+ insmod 加载内核模块
+ rmmod 卸载内核模块
+ lsmod 列出当前模块
+ dmesg 获取内核模块信息
+ strace 列出系统调用
+ ps 列出进程列表，检查是否隐藏成功
+ ls 列出文件列表，检查是否隐藏成功
+ netstat 列出文件列表，检查是否隐藏成功

### 4.2 库函数

+ kallsyms_lookup_name 寻找未导出的内核函数
+ kmalloc 内核空间malloc
+ kfree 内核空间free
+ list_del 内核删除元素
+ rcu_read_lock 声明了一个读端的临界区
+ rcu_read_unlock 解除
+ put_task_struct 释放内核线程的task_struct
+ queue_work 把函数插入到工作队列
+ spin_lock 在短期间内进行轻量级的锁定
+ rdmsrl 获取system_call地址
+ prepare_kernel_cred 创建凭证权限
+ commit_creds 应用凭证权限
+ nf_register_net_hook 网络钩子
+ preempt_enable 允许抢占
+ preempt_disable 禁止抢占

### 4.3 宏

+ asmlinkage 函数定义前加该宏表示这些函数通过堆栈而不是通过寄存器传递参数
+ for_each_process 宏循环控制语句，扫描整个进程链表
+ get_task_struct 获取进程信息
+ THIS_MODULE 获取当前内核模块

## 5. 参考

## 5.1. 参考文献

+ Linux设备驱动程序(第三版)
+ 深入Linux内核架构

## 5.2. 参考链接

+ [the Research Rootkit project](https://github.com/NoviceLive/research-rootkit)
+ [Reptile](https://github.com/f0rb1dd3n/Reptile)
+ [Sample Rootkit for Linux](https://github.com/ivyl/rootkit)
+ [Linux rootkit for Ubuntu 16.04 and 10.04, both i386 and amd64](https://github.com/nurupo/rootkit)
+ [hiding with a linux rootkit](https://0x00sec.org/t/hiding-with-a-linux-rootkit/4532)
+ [Linux Rootkit之二：Linux模块加载与信息隐藏](https://blog.csdn.net/u011130578/article/details/46523949)
+ [深入理解 Linux 的 RCU 机制](https://cloud.tencent.com/developer/article/1006204)
+ [入门学习linux内核提权](https://xz.aliyun.com/t/2054)
