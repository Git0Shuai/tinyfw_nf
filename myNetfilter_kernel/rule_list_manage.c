// FileName: myNetfilter_kernel/rule_list_manage.c 
// Describe: 管理（增、删、查、改）规则列表
// Note: 代码基于LWFW。代码用于《网络安全课程设计

#include <linux/slab.h>

#include "../common.h"
#include "rule_list_manage.h"

struct RuleList g_rule_list; 

void RuleListInit(void) {
    g_rule_list.head = NULL;
    g_rule_list.tail = NULL;
    g_rule_list.length = 0;
    g_rule_list.default_rule = RULE_PERMIT;
}

void RuleListCleanup(void) {
    struct RuleNode *temp;
    for(temp = g_rule_list.head; temp != NULL; temp = g_rule_list.head) {
        g_rule_list.head = temp->next;
        kfree(temp);
    } 
    RuleListInit();
}

void RuleInsert(struct RuleNode *rnode) {
    if(g_rule_list.tail == NULL) {
        g_rule_list.tail = rnode;
    }
    rnode->next = g_rule_list.head;
    g_rule_list.head = rnode;

    ++g_rule_list.length;
}

void RuleAppend(struct RuleNode *rnode) {
    rnode->next = NULL;
    if(g_rule_list.head == NULL) {
        g_rule_list.head = g_rule_list.tail = rnode;
    }
    else {
        g_rule_list.tail->next = rnode;
        g_rule_list.tail = rnode;
    }

    ++g_rule_list.length;
}

int RuleDelete(const struct RuleNode *node_pattern) {
    struct RuleNode *pre_node;
    int count = 0;

    while(g_rule_list.head != NULL && RuleMatch(node_pattern, g_rule_list.head)) {
        pre_node = g_rule_list.head;
        g_rule_list.head = pre_node->next;
        kfree(pre_node);       
        --g_rule_list.length;
        ++count;
    }
    for(pre_node = g_rule_list.head; pre_node != NULL && pre_node->next != NULL; 
            pre_node = pre_node->next) {
        if(RuleMatch(node_pattern, pre_node->next)) {
            pre_node->next = pre_node->next->next;
            kfree(pre_node->next);
            --g_rule_list.length;
            ++count;
        }
    }
    
    return count;
}

int RuleMatch(const struct RuleNode *node_pattern, const struct RuleNode *rnode) {
    if((node_pattern->type == PACKAGE_TYPE_ANY || node_pattern->type == rnode->type)
            && (node_pattern->srcip == IP_ANY 
                 || (node_pattern->srcip & node_pattern->srcmask)
                     == (rnode->srcip & node_pattern->srcmask))
            && (node_pattern->dstip == IP_ANY 
                 || (node_pattern->dstip & node_pattern->dstmask) 
                     == (rnode->dstip & node_pattern->dstmask))) {
        if(rnode->type == PACKAGE_TYPE_ICMP) { //if ICMP packages, here match SUCCEED!
            return 1;
        }
        else if ((node_pattern->srcport == PORT_ANY || node_pattern->srcport == rnode->srcport)
                && (node_pattern->dstport == PORT_ANY || node_pattern->dstport == rnode->dstport)){
            return 1; //NOT ICMP, check port
        }
    }
    
    return 0; //match FAILED!
}

int GetIpPort(unsigned int *ip, unsigned int *ipmask, unsigned int *port, const char **p_cur) {
    unsigned int temp;
    const char *cur = *p_cur;
    int i, j;

    *ip = 0;
    while(*cur == ' ' || *cur == '\t') {
        ++cur;
    }
    if(*cur != 'A') {
        for(j = 3; j > 0; --j) {
            for(i = 0, temp = 0; i < 3 && *cur >= '0' && *cur <= '9'; ++i, ++cur) {
                temp *= 10;
                temp += (*cur) - '0';
            }
            if(*cur != '.' || temp > 0xff) { //点分十进制每段不大于255(0xff)
                return -1;
            }
            *ip |= (temp << (8*j));
            ++cur;
        }
        for(i = 0, temp = 0; i < 3 && *cur >= '0' && *cur <= '9'; ++i, ++cur) {
            temp *= 10;
            temp += (*cur) - '0';
        }
        if(*cur != '/' || temp > 0xff) {
            return -1;
        }
        *ip |= temp;
        ++cur;

        for(i = 0, temp = 0; i < 2 && *cur >= '0' && *cur <= '9'; ++i, ++cur) {
            temp *= 10;
            temp += (*cur) - '0';
        }
        if(temp > 32) { //IPv4 屏蔽字表示成十进制时不应大于32
            return -1;
        }
        *ipmask = 0xffffffff;
        *ipmask <<= 32 - temp;
        *ip &= *ipmask;
    }
    else {
        *ip = IP_ANY;
        *ipmask = 0;
        ++cur;
    }

    if(*cur++ != ':') {
        return -1;
    }
    if(*cur != 'A') {
        for(i = 0, temp = 0; i < 8 && *cur >= '0' && *cur <= '9'; ++i, ++cur) {
            temp *= 10;
            temp += (*cur) - '0';
        }
        *port = temp;
    }
    else {
        *port = PORT_ANY;
        ++cur;
    }

    *p_cur = cur;
    return 0;
}

/*
 * 规则由字符串描述，解析规则如下：
 * 1. 所有规则包含字符 0~9、'A'、'I'、'T'、'U'、'P'、'R'、'/'、'.'、':'
 * 2. 规则包含4个字段: 报文类型、源IP-PORT、目的IP-PORT、策略。
 * 3. 各个字段由空格隔开,所有不合法格式将导致失败，函数不检查规则描述合理性。
 * 4. 报文类型字段取值: A:任意类型 I:ICMP T:TCP U:UDP
 * 5. 源IP-PORT字段格式: "IP/mask:PORT" 必须指定mask（没有取32）,IP和PORT可为'A'
 * 6. 策略字段取值 P:PERMIT R:REJECT
 * 
 * 返回值: 
 *  成功返回解析得到RuleNode指针,其内存动态分配,内存释放由调用方管理
 *  失败返回NULL       
 */
struct RuleNode *ParseRule(const char *rnode) {
    const char *cur;
    int iRet;
    struct RuleNode *new_node;

    new_node = (struct RuleNode *)kmalloc(sizeof(struct RuleNode), GFP_KERNEL);
    if(new_node == NULL) {
        return NULL;
    }

    //set type
    cur = rnode;
    while(*cur == ' ' || *cur == '\t') {
        ++cur;
    }
    switch(*cur) {
        case 'A':
            new_node->type = PACKAGE_TYPE_ANY;
            break;
        case 'I':
            new_node->type = PACKAGE_TYPE_ICMP;
            break;
        case 'T':
            new_node->type = PACKAGE_TYPE_TCP;
            break;
        case 'U':
            new_node->type = PACKAGE_TYPE_UDP;
            break;
        default:
            kfree(new_node);
            return NULL;
    }
    ++cur;
    if(*cur != ' ' && *cur != '\t') {
        kfree(new_node);
        return NULL;
    }

    //set src   eg. 123.234.111.0/24:1234 
    iRet = GetIpPort(&(new_node->srcip), &(new_node->srcmask), &(new_node->srcport), &cur);
    if(iRet != 0 || (*cur != ' ' && *cur != '\t')) {
        kfree(new_node);
        return NULL;
    }
    
    //set dst  same as set src
    iRet = GetIpPort(&(new_node->dstip), &(new_node->dstmask), &(new_node->dstport), &cur);
    if(iRet != 0 || (*cur != ' ' && *cur != '\t')) {
        kfree(new_node);
        return NULL;
    }

    //set rule
    while(*cur == ' ' || *cur == '\t') {
        ++cur;
    }
    switch(*cur) {
        case 'P':
            new_node->rule = RULE_PERMIT;
            break;
        case 'R':
            new_node->rule = RULE_REJECT;
            break;
        default:
            kfree(new_node);
            return NULL;
    }
    
    return new_node;
}

int IpPort2Str(char **o_strbuf, unsigned int ip, unsigned int ipmask, unsigned int port) {
    char *cur = *o_strbuf;
    char temp[32];
    char *pointer = &(temp[0]);
    int i, k;
    if(port == PORT_ANY) {
        *(++pointer) = 'A';
    }
    else {
        while(port != 0) {
            *(++pointer) = '0' + port%10;
            port /= 10;
        }
    }

    *(++pointer) = ':';

    if(ip == IP_ANY) {
        *(++pointer) = 'A';
    }
    else {
        if(ipmask != 0) {
            int local_temp = 0;
            /* ipmask 存储为屏蔽字而非10进制,先转化 */
             while(ipmask != 0) {
                 ipmask <<= 1;
                 ++local_temp;
             }
             while(local_temp != 0) {
                 *(++pointer) = '0' + local_temp%10;
                 local_temp /= 10;
             }
        }
        else {
            *(++pointer) = '0';
        }

        *(++pointer) = '/';
        
        for(i = 0; i < 3; ++i) {
            k = ((ip >> (8*i)) & 0xff); 
            if(k != 0) {
                while(k != 0) {
                    *(++pointer) = '0' + k%10;
                    k /= 10;
                }
            }
            else {
                *(++pointer) = '0';
            }
            *(++pointer) = '.';
        }
        ip >>= 24;
        if(ip != 0) {
            while(ip != 0) {
                *(++pointer) = '0' + ip%10;
                ip /= 10;
            }
        }
        else {
            *(++pointer) = '0';
        }
    }
    while(pointer != &(temp[0])) {
        *(cur++) = *(pointer--);
    }
    *(cur++) = ' ';

    *o_strbuf = cur;
    return 0;
}


/*
 * 将规则节点转化成以'\n'结尾的可读字符串
 */
int ReadRule(char **o_strbuf, const struct RuleNode *rnode) {
    char *cur = *o_strbuf;
    int iRet;

    switch(rnode->type) {
        case PACKAGE_TYPE_ANY:
            *cur = 'A';
            break;
        case PACKAGE_TYPE_TCP:
            *cur = 'T';
            break;
        case PACKAGE_TYPE_UDP:
            *cur = 'U';
            break;
        case PACKAGE_TYPE_ICMP:
            *cur = 'I';
            break;
        default:
            return -1;
    }
    ++cur;
    *cur = ' ';
    ++cur;

    iRet = IpPort2Str(&cur, rnode->srcip, rnode->srcmask, rnode->srcport);
    if(iRet != 0) {
        return -1;
    }
    *(cur++) = ' ';

    iRet = IpPort2Str(&cur, rnode->dstip, rnode->dstmask, rnode->dstport);
    if(iRet != 0) {
        return -1;
    }
    *(cur++) = ' ';

    switch(rnode->rule) {
        case RULE_PERMIT:
            *cur = 'P';
            break;
        case RULE_REJECT:
            *cur = 'R';
            break;
        default:
            return -1;
    }
    *(++cur) = '\n';
    ++cur;

    *o_strbuf = cur;
    return 0;
}

