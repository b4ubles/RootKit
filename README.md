# RootKit

要求以实现rootkit的常见功能为主，如

+ 进程隐藏
+ 文件隐藏
+ 端口隐藏
+ Root用户后门
+ 感染系统进程实现自启
+ 绕过系统防御

提交

+ 程序及其源码
+ 说明文档
+ 演示截图或录屏
+ 汇报ppt

## Install

```
sudo apt-get install linux-headers-$(uname -r)
```

## 原理

### 进程隐藏

Linux系统中用来查询文件信息的系统调用是 ``sys_getdents`` ，这一点可以通过strace来观察到，例如strace ls将列出命令ls用到的系统调用，从中可以发现ls是通过 ``getdents`` 系统调用来操作的，对应于内核里的 ``sys_getedents`` 来执行。

当查询文件或者目录的相关信息时，Linux系统用 ``sys_getedents`` 来执行相应的查询操作，并把得到的信息传递给用户空间运行的程序，所以如果修改该系统调用，去掉结果中与某些特定文件的相关信息，那么所有利用该系统调用的程序将看不见该文件，从而达到了隐藏的目的。

sys_getdents的原型为：

```c
int sys_getdents(unsigned int fd, struct dirent *dirp,unsigned int count)
```

其中fd为指向目录文件的文件描述符，该函数根据fd所指向的目录文件读取相应dirent结构，并放入dirp中，其中count为dirp中返回的数据量，正确时该函数返回值为填充到dirp的字节数。
