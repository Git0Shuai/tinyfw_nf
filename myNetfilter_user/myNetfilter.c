// 实现访问字符设备的用户态程序
//

#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../common.h"

#define IO_BUFF_SIZE 4096

static char *io_buff = NULL;

void PrintHelpMsg() {
    printf("client of tinyfw_nf. version 1.0.\n");
    printf("\n");
    printf("Usage:\n");
    printf("  tinyfw_nf [cmd [args...]]\n");
    printf("\n");
    printf("Cmd:\n");
    printf("  help          show this help page.\n");
    printf("  start         start the firewall.\n");
    printf("  shutdown      shutdown the firewall.\n");
    printf("  list          show current rules.\n");
    printf("  conf          read rule list file and reset rules.\n");
    printf("                a file path args is needed.\n");
    printf("  default       set default rules.\n");
    printf("                ONLY 'P' or 'R' as args is accepted.\n");
    printf("                P--PERMIT  R--REJECT\n");
    printf("  add           add a rule.\n");
    printf("                a rule description args is needed!\n");
    printf("  del           delete a rule.\n");
    printf("                a num is needed to locate rule.\n");
    printf("                you can get the num by using list cmd\n");
    printf("\n");
    printf("Note:\n");
    printf("  How to write rule description:\n");
    printf("    1. a rule description includes 4 parts just like below:\n");
    printf("         <type> <srcip>/<mask>:<port> <dstip>/<dstmask>:<port> <rule>\n");
    printf("    2. <type> = T|U|I|A (TCP|UDP|ICMP|ANY);\n");

    printf("    4. <ip>/<mask> = ip/mask as usual or 'A' fro ANY IP;\n");
    printf("    5. <port> = port as usual or 'A' for ANY port.\n");
    printf("\n");
}

int DoList(int fd) {
    long def_rule;

    if(ioctl(fd, IO_CTRL_GET_DEF, &def_rule) == -1) {
        printf("get default rule FAILED!\n");
    }
    if(def_rule == IO_CTRL_PERMIT) {
        printf("\ndefault rule PERMIT!\n\n");
    }
    else { //def_rule == IO_CTRL_REJECT
        printf("\ndefault rule REJECT!\n\n");
    }

    if(read(fd, io_buff, IO_BUFF_SIZE) == -1) {
        return -1;
    }   
    printf("%s\n", io_buff);

    printf("list rules OK!\n");
    return 0;    
}

int DoConf(int fd, const char *str_arg) {
    FILE *fp;
    int succ = 0;
    int fail = 0;
    
    printf("open config file ");
    if((fp = fopen(str_arg, "rb")) == NULL) {
        printf("FAILED!\n");
        return -1;
    }
    printf("OK!\n");
    
    if(ioctl(fd, IO_CTRL_CLE) == -1) {
        printf("clean up old rule list FAILED!\n");
        return -1;
    }
    printf("clean up old rule list SUCCEED!\n");

    while(fgets(io_buff, IO_BUFF_SIZE, fp) != NULL) {
        char *temp = io_buff;

        //为了格式化输出，去掉尾部换行符。
        while(*temp != '\n') ++temp;
        *temp = '\0';

        printf("set rule \"%s\"... ", io_buff);
        if(write(fd, io_buff, IO_BUFF_SIZE) == -1) {
            printf("FAILED!\n");
            ++fail;
        }
        else {
            printf("OK!\n");
            ++succ;
        }
    }

    printf("read %d rules and %d rules set succeed!\n", fail+succ, succ);
    return 0;    
}

int DoDefault(int fd, const char *str_arg) {
    if(*str_arg == 'P') {
        if(ioctl(fd, IO_CTRL_DEF, IO_CTRL_PERMIT) != -1) {
            printf("set default rule as PERMIT! SUCCEED!\n");
            return 0;
        }
    }
    else if (*str_arg == 'R') {
        if(ioctl(fd, IO_CTRL_DEF, IO_CTRL_REJECT) != -1) {
            printf("set default rule as REJECT! SUCCEED!\n");
            return 0;
        }
    }

    printf("set default rule FAILED!\n");
    return -1;
}

int DoDelete(int fd, const char *str_arg) {
    int num = 0;

    while(*str_arg >= '0' && *str_arg <= '9' && num < 100) {
        num *= 10;
        num += *str_arg - '0';
        ++str_arg;
    }
    if(num > 100) {
        printf("this number is larger than 100! delete FAILED!\n");
        return -1;
    }
    if(ioctl(fd, IO_CTRL_DEL, num) == -1) {
        printf("delete rule FAILED!\n");
        return -1;
    }

    printf("delete rule OK!\n");
    return 0;
}

int main(int argc, char *argv[]) {
    int fd;
   
    if(argc < 2) {
       printf("CMD is needed at least!\n\n");
       PrintHelpMsg();
       return -1;
    };

    if(strcmp(argv[1], "help") == 0) {
        PrintHelpMsg();
        return 0;
    }
    
    printf("open char device: ");
    fd = open("/dev/myntfw", O_RDWR);
    if(fd < 0) {
        printf("FAILED!\n");
        return -1;
    }
    printf("OK!\n");
    //一次执行一个命令程序即退出，没有必要显示关闭或文件描述符

    printf("alloc io buffer: ");
    io_buff = (char *)malloc(sizeof(char)*4096);
    if(io_buff == NULL) {
        printf("FAILED!\n");
        return -1;
    }
    printf("OK!\n");
    //一次执行一个命令程序即退出，没有必要显示free动态分配的内存
    
    if(strcmp(argv[1], "start") == 0) {
        if(ioctl(fd, IO_CTRL_START) == -1) {
            printf("start FAILED!\n");
            return -1;
        }
    }
    else if(strcmp(argv[1], "shutdown") == 0) {
        if(ioctl(fd, IO_CTRL_SHUTDOWN) == -1) {
            printf("shutdown FAILED!\n");
            return -1;
        }
    }
    else if(strcmp(argv[1], "list") == 0) {
        return DoList(fd);
    }
    else if(argc < 3) { //除了此前处理的cmd，其他cmd需要额外参数
        printf("invalid cmd or an argument is need!\n\n");
        PrintHelpMsg();
        return -1;
    }
    else {
        if(strcmp(argv[1], "conf") == 0) {
            return DoConf(fd, argv[2]);
        }
        else if(strcmp(argv[1], "default") == 0) {
            return DoDefault(fd, argv[2]);
        }
        else if(strcmp(argv[1], "del") == 0) {
            return DoDelete(fd, argv[2]);
        }
        else if(strcmp(argv[1], "add") == 0) {
            strcpy((char *)io_buff, argv[2]);
            if(ioctl(fd, IO_CTRL_ADD, io_buff) == -1) {
                printf("add rule FAILED!\n");
                return -1;
            }
            printf("add rule OK!\n");
        }
        else { //其他命令提示错误
            printf("invalid cmd!\n\n");
            PrintHelpMsg();
            return -1;
        }
    }

    return 0;
}

