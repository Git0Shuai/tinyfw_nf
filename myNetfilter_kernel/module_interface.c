// FileName: myNetfil ter_kernel/module_interface.c 
// Describe: 实现内核模块面向用户程序的接口
// Note: 代码基于LWFW。代码用于《网络安全课程设计》

#include <linux/kernel.h>  
#include <linux/init.h>  
#include <linux/module.h>  
#include <linux/string.h>  
#include <linux/kmod.h>  
#include <asm-generic/uaccess.h>        /// copy_to_user  copy_from user
#include <asm/unistd.h>  
#include <linux/fs.h>
#include <linux/device.h>
#include <linux/cdev.h>           /// struct cdev  
#include <linux/slab.h>

#include "common.h"
#include "module_interface.h"
#include "rule_list_manage.h"
#include "filter_action.h"

#define IO_BUFF_SIZE 4096   

static int g_device_status = 0;
static int g_dev_major = 0;
static struct cdev g_cdev_m;
static char *g_io_buff = NULL;
extern struct RuleList g_rule_list;

int ModuleOpen(struct inode *inode, struct file *file);
int ModuleRelease(struct inode *inode, struct file *file);
ssize_t ModuleRead(struct file *filp, char *buf, size_t count, loff_t *f_pos);
ssize_t ModuleWrite(struct file *filp, const char *user_buf, 
        size_t count, loff_t *f_pos);
long ModuleIoctl(struct file *file, unsigned int cmd, unsigned long arg);

static struct file_operations file_ops = {
    .open = ModuleOpen,
    .release = ModuleRelease,
    .read = ModuleRead,
    .write = ModuleWrite,
    .unlocked_ioctl = ModuleIoctl,
};

/*
 * 打开设备文件时调用。
 * 计数，保证同一时间只有一个用户态进程控向内核发送过滤规则。
 */
int ModuleOpen(struct inode *inode, struct file *file) {
    if(g_device_status) {
        return -EBUSY;
    }
    else {
        g_device_status = 1;
        return 0;
    }

    printk("device open SUCCEED!\n");
    return 0;
}

int ModuleRelease(struct inode *inode, struct file *file) {
    g_device_status ^= g_device_status;

    printk("device close SUCCEED!\n");
    return 0;
}

ssize_t ModuleRead(struct file *file, char *buf, size_t count, loff_t *f_pos) {
    unsigned long size;
    long iRet;
    char *cur_pointer;
    struct RuleNode *cur_node;
    
    cur_pointer = g_io_buff;
    for(cur_node = g_rule_list.head; cur_node !=  NULL; cur_node = cur_node->next) {
        if(cur_pointer - g_io_buff > IO_BUFF_SIZE - 80) {
            /* NO enough buff left */
            sprintf(cur_pointer, "More Rules ...\n");
            break;
        }
        ReadRule(&cur_pointer, cur_node);
    }
    *(cur_pointer++) = '\0';

    size = (cur_pointer - g_io_buff)/sizeof(char);
    iRet = copy_to_user(buf, g_io_buff, size);
    if(iRet != 0) {
        printk("copy_to_user FAILED");
        return -EFAULT;
    }
    
    printk("read rule SUCCEED!\n");
    return 0;
}

ssize_t ModuleWrite(struct file *filp, const char *buf, 
        size_t count, loff_t *f_pos) {
    struct RuleNode *new_node;
    int iRet;

    iRet = copy_from_user(g_io_buff, buf, count);
    if(iRet != 0) {
        printk("copy_from_user FAILED\n");
        return -EFAULT;
    }

    new_node = ParseRule(g_io_buff);
    if(new_node == NULL) {
        printk("ParseRule FAILED\n");
        return -EFAULT;
    }
    RuleInsert(new_node);

    printk("write rule SUCCEED!\n");
    return 0;
}

long ModuleIoctl(struct file *file, unsigned int cmd, unsigned long arg) {
    //TODO:
    // operation except set or read rule list

    return 0;
}

/* 
 * ModuleInit函数，模块加载时调用。
 * 1. 创建用于和用户态进程通信的设备节点。
 * 2. 初始化规则表（空表）；
 * 3. 设置默认策略为允许；
 * 4. 挂在netfilter的hook函数；
 */
int ModuleInit(void) {
    int iRet, err;
    dev_t devno, devno_m;

    //setp1: regist cdev
    iRet = alloc_chrdev_region(&devno, 0, 1, MODULE_NAME);
    g_dev_major = MAJOR(devno);
    if(iRet < 0) {
        return iRet;
    }
    devno_m = MKDEV(g_dev_major, 0);
    printk("cdev regest succeed! \nmajor: %d\nminor: %d\n",
            MAJOR(devno_m), MINOR(devno_m));
    cdev_init(&g_cdev_m, &file_ops);
    g_cdev_m.owner = THIS_MODULE;
    g_cdev_m.ops = &file_ops;
    err = cdev_add(&g_cdev_m, devno_m, 1);
    if(err) {
        printk("cdev add error!\n");
    }

    g_device_status ^= g_device_status;
    g_io_buff = (char*)kmalloc(IO_BUFF_SIZE*sizeof(char), GFP_KERNEL);
    if(g_io_buff == NULL) {
        printk("alloc io buffer FAILED!\n");
        cdev_del(&g_cdev_m);
        unregister_chrdev_region(MKDEV(g_dev_major, 0), 1);
        return -1;
    }
    printk("cdev regist succeed!\n");

    //setp2: init rule list
    RuleListInit();

    //step3: regist hook
    RegistHook(); 

    printk("Module install succeed!\n");
    return 0;
}

/*
 * ModuleExit函数，模块卸载时调用
 * 1. 取消挂在在hook函数；
 * 2. 释放规则表所占用的内存；
 * 3. 删除用于与用户态进程通信的设备节点。
 */
void ModuleExit(void) {
    //setp1: remove hook
    RemoveHook();
    
    //setp2: delete cdev
    cdev_del(&g_cdev_m);
    unregister_chrdev_region(MKDEV(g_dev_major, 0), 1);

    //step3: clean up rule_list
    RuleListCleanup();
    
    printk("Module unistall succeed!\n");
} 

module_init(ModuleInit);
module_exit(ModuleExit);


inline void Debug(const char *DebugStr) {
#ifdef MYFW_DEBUG
    printk("%s", DebugStr);
#endif
    return;    
}

