#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>

int main() {
    int fd, iRet;
    char *read_buff;

    read_buff = (char *)malloc(sizeof(char)*4096);
    fd = open("/dev/myntfw", O_RDONLY);
    printf("read test:\n");
    iRet = read(fd, read_buff, 4096);
    if(iRet < 0) {
        printf("read FAILED!\n");
        return -1;
    }
    read_buff[4095] = '\0';
    printf("%s", read_buff);

    return 0;
}

