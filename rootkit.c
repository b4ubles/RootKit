#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kallsyms.h>
#include <linux/string.h>
#include <linux/fs.h>
#include <linux/init.h>        
#include <asm/special_insns.h>
 
static int lkm_init(void)
{
    printk("rootkit module loaded\n");
    return 0;    
}
 
static void lkm_exit(void)
{
    printk("rootkit module removed\n");
}
 
module_init(lkm_init);
module_exit(lkm_exit);
