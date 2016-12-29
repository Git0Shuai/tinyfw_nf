#ifndef COMMON_H
#define COMMON_H

#define MODULE_NAME  "myfw"

//ioctrl CMD
#define IO_CTRL_START 1
#define IO_CTRL_SHUT 2
#define IO_CTRL_DEF 3
#define IO_CTRL_ADD 4
#define IO_CTRL_DEL 5
#define IO_CTRL_CLE 6
#define IO_CTRL_GET_DEF 7

//ioctrl ARGS
#define IO_CTRL_PERMIT 11
#define IO_CTRL_REJECT 12

inline void Debug(const char *DbgStr);

#endif

