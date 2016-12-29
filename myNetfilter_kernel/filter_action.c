// FileName: myNetfilter_kernel/filter_action.c 
// Describe: 实现挂钩函数
// Note: 代码基于LWFW。代码用于《网络安全课程设计》

#include <linux/socket.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#include "../common.h"
#include "filter_action.h"
#include "rule_list_manage.h"

extern struct RuleList g_rule_list;
static struct nf_hook_ops nf_reg;
static int active = 0;

unsigned int NFHookFunc(unsigned int hooknum,
                    struct sk_buff *skb,
                    const struct net_device *in,
                    const struct net_device *out,
                    int (*okfn)(struct sk_buff *)) {
    struct iphdr *iph;
    struct tcphdr *tcph;
    struct udphdr *udph;
    //struct icmp *icmph //no need to get icmp header
    struct RuleNode package_node;
    struct RuleNode *rule_partten;
    if(!active) { //works only when activate
        return NF_ACCEPT;
    }

    //any NULL pointer, return accept
    if(!skb) return NF_ACCEPT;
    if(!(iph = ip_hdr(skb))) return NF_ACCEPT;

    //get and set protocol
    switch(iph->protocol) {
        case IPPROTO_ICMP:
            package_node.type = PACKAGE_TYPE_ICMP;
            break;
        case IPPROTO_TCP:
            package_node.type = PACKAGE_TYPE_TCP;
            break;
        case IPPROTO_UDP:
            package_node.type = PACKAGE_TYPE_UDP;
            break;
        default:    // default rule or just accept ?
            return NF_ACCEPT;
    }

    //get and set ip
    package_node.srcip = ((iph->saddr) & 0xff) << 24
                       | ((iph->saddr) & 0xff00) << 8
                       | ((iph->saddr) & 0xff0000) >> 8
                       | ((iph->saddr) & 0xff000000) >> 24;
    package_node.dstip = ((iph->daddr) & 0xff) << 24
                       | ((iph->daddr) & 0xff00) << 8
                       | ((iph->daddr) & 0xff0000) >> 8
                       | ((iph->daddr) & 0xff000000) >> 24;

    if(package_node.type != PACKAGE_TYPE_ICMP) {
    //NOT a ICMP package set port
        if(package_node.type == PACKAGE_TYPE_TCP) {
            if(!(tcph = tcp_hdr(skb))) {
                return NF_ACCEPT;
            }
            package_node.srcport = ((tcph->source) & 0xff) << 8
                                 | ((tcph->source) & 0xff00) >> 8;
            package_node.dstport = ((tcph->dest) & 0xff) << 8
                                 | ((tcph->dest) & 0xff00) >> 8;
        }
        else { //only UDP packages will come hear
            if(!(udph = udp_hdr(skb))) {
                return NF_ACCEPT;
            }
            package_node.srcport = ((udph->source) & 0xff) << 8
                                 | ((udph->source) & 0xff00) >> 8;
            package_node.dstport = ((udph->dest) & 0xff) << 8
                                 | ((udph->dest) & 0xff00) >> 8;
        
        }
    }

    //match rule
    for(rule_partten = g_rule_list.head; rule_partten != NULL; 
            rule_partten = rule_partten->next) {
        if(RuleMatch(rule_partten, &package_node)) {//one match RETURN;
            if(rule_partten->rule == RULE_PERMIT) {
                printk("match rule accept\n");
                printk("%s: %u.%u.%u.%u:%u  %u.%u.%u.%u:%u", in->name,
                       package_node.srcip >> 24,  (package_node.srcip >> 16) & 0xff, 
                       (package_node.srcip >> 8) & 0xff, package_node.srcip & 0xff,
                       package_node.srcport,
                       package_node.dstip >> 24,  (package_node.dstip >> 16) & 0xff, 
                       (package_node.dstip >> 8) & 0xff, package_node.dstip & 0xff,
                       package_node.dstport);

                return NF_ACCEPT;
            }
            else {
                printk("match rule reject\n");
                printk("%s: %u.%u.%u.%u:%u  %u.%u.%u.%u:%u", in->name,
                       package_node.srcip >> 24,  (package_node.srcip >> 16) & 0xff, 
                       (package_node.srcip >> 8) & 0xff, package_node.srcip & 0xff,
                       package_node.srcport,
                       package_node.dstip >> 24,  (package_node.dstip >> 16) & 0xff, 
                       (package_node.dstip >> 8) & 0xff, package_node.dstip & 0xff,
                       package_node.dstport);

                return NF_DROP;
            }
        }
    }

    if(g_rule_list.default_rule == RULE_PERMIT) {
        return NF_ACCEPT;
    }

    return NF_DROP;
}

void RegistHook() {
    nf_reg.hook = NFHookFunc;    //hook FUNC
    nf_reg.owner = THIS_MODULE;
    nf_reg.pf = PF_INET;         //IPv4 packages
    nf_reg.hooknum = NF_INET_PRE_ROUTING; //hook at the first stage
    nf_reg.priority = NF_IP_PRI_FIRST;
    
    active = 0;
    nf_register_hook(&nf_reg);
    printk("netfilter hook regist SUCCEED!\n");

    return ;
}

void RemoveHook() {
    nf_unregister_hook(&nf_reg);
    printk("netfilter hook unregister SUCCEED!\n");

    return ;
}

inline void StartFilter() {
    active = 0xffff;

    return ;
}

inline void ShutdownFilter() {
    active = 0;

    return ;
}
           
