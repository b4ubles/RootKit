.PHONY: all

# obj-m 表示编译成模块
obj-m += rootkit.o

KERNEL_DIR = /lib/modules/`uname -r`/build
PWD = $(shell pwd)

all: rootkit

rootkit:
	clang client.c -o client
	$(MAKE) -C $(KERNEL_DIR) SUBDIRS=$(PWD)

clean:
	rm -rf *.o *.ko *.symvers *.mod.* *.order .tmp_versions *cmd
