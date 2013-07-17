#ifndef _IPSNATCHER_H
#define _IPSNATCHER_H

#define MAXPACKBUFF         40960

#define PROTOCOL            0
#define INTERVAL            1
#define ENDCOUNT            2

// IP protocols follow in.h
#define ICMP                1
#define IGMP                2
#define TCP                 6
#define UDP                 17

// Ethernet protocols follow ethernet.h

#define ALLPROTOCOL         100
#define DEFAULTPROTO_ALL    100

#define LEAGLOPT            201
#define ILLEGALOPT          202

//存放需要赋值的参数
typedef union _option_value {
  int protocol;
  unsigned long interval;
  unsigned long endcount;
  Boolean print_data;    //print_data 不需要赋值，这里只是占位符，为了对称而已。
} Option_Value;

typedef struct _cmd_opt {
  Option_Value rightopt;    //存储对应参数的值，如果参数不需要赋值，就不会放入node结构体
  Boolean status;   //被赋值则为TRUE，否则FALSE
} Cmd_Opt;

#endif

