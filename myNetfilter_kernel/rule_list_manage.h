#ifndef RULE_LIST_MANAGE
#define RULE_LIST_MANAGE

enum Rule{
    RULE_PERMIT,  
    RULE_REJECT
};

enum PackageType {
    PACKAGE_TYPE_ANY, //匹配所有类型
    PACKAGE_TYPE_TCP,
    PACKAGE_TYPE_UDP,
    PACKAGE_TYPE_ICMP
};

//分别用于匹配任意IP 和 任意PORT
enum {
    IP_ANY, 
    PORT_ANY
};

struct RuleNode {
    enum Rule rule;
    enum PackageType type;
    unsigned int srcip;
    unsigned int srcmask;
    unsigned int dstip;
    unsigned int dstmask;
    unsigned int srcport;
    unsigned int dstport;
    struct RuleNode *next;
};

struct RuleList {
    enum Rule default_rule; //不匹配任意一条规则时的默认规则
    unsigned int length;
    struct RuleNode *head;
    struct RuleNode *tail;
};

void RuleListInit(void);
void RuleListCleanup(void);
void RuleInsert(struct RuleNode *);
void RuleAppend(struct RuleNode *);
int RuleDelete(const struct RuleNode *);
int RuleMatch(const struct RuleNode *, const struct RuleNode *);
struct RuleNode *ParseRule(const char *);
int ReadRule(char **o_strbuf, const struct RuleNode *);

#endif

