#ifndef _IPSNATCHER_H
#define _IPSNATCHER_H

#define MAXPACKBUFF         40960

#define PROTOCOL            0
#define INTERVAL            1
#define ENDCOUNT            2

#define TCP                 3
#define UDP                 4
#define ICMP                5
#define ALLPROTOCOL         6
#define DEFAULTPROTO_ALL    7

#define LEAGLOPT            8
#define ILLEGALOPT          9

//存放需要赋值的参数
typedef union _node {
  int protocol;
  unsigned long interval;
  unsigned long endcount;
  Boolean  print_data;    //print_data 不需要赋值，这里只是占位符，为了对称而已。
} node;

typedef struct _cmd_opt {
  node rightopt;    //存储对应参数的值，如果参数不需要赋值，就不会放入node结构体
  Boolean status;   //被赋值则为TRUE，否则FALSE
} Cmd_Opt;

#endif

