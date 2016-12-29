// FileName: myNetfilter_kernel/filter_action.c 
// Describe: 实现挂钩函数
// Note: 代码基于LWFW。代码用于《网络安全课程设计》

#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/socket.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

#include "../common.h"
#include "filter_action.h"

static struct nf_hook_ops nf_reg;
static int active = 0;

unsigned int NFHookFunc(unsigned int hooknum,
                    struct sk_buff *skb,
                    const struct net_device *in,
                    const struct net_device *out,
                    int (*okfn)(struct sk_buff *)) {
    
}

void RegistHook() {
    nf_reg.hook = NFHookFunc;    //hook FUNC
    nf_reg.owner = THIS_MODULE;
    nf_reg.pf = PF_INET;         //IPv4 packages
    nf_reg.hooknum = NF_INET_PRE_ROUTING; //hook at the first stage
    nf_reg.priority = NF_IP_PRI_FIRST;

    nf_register_hook(&nf_reg);
    printf("netfilter hook regist SUCCEED!\n");

    return ;
}

void RemoveHook() {
    nf_unregister_hook(&nf_reg);
    printf("netfilter hook unregister SUCCEED!\n");

    return ;
}

inline void StartFilter() {
    active = 0xffff;

    return ;
}

inline void ShutdownFilter() {
    active ^= active;

    return ;
}
           
