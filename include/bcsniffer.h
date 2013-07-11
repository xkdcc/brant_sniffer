#ifndef _IPSNATCHER_H
#define _IPSNATCHER_H

#define MAXPACKBUFF 		40960

#define PROTOCOL 			0
#define INTERVAL 			1
#define ENDCOUNT 			2

#define TCP					3
#define UDP					4
#define ICMP					5
#define ALLPROTOCOL 		6
#define DEFAULTPROTO_ALL	7

#define LEAGLOPT			8
#define ILLEGALOPT			9

//存放需要赋值的参数
typedef union UNION_OPTION {
  int protocol;
  unsigned long interval;
  unsigned long endcount;
} OPTION;

enum ENUM_TORF {
  TRUE = 1, FALSE = 0
};
typedef enum ENUM_TORF BOOLEAN;

typedef struct _OPT_VALUE_STATUS {
  OPTION rightopt;	//存储对应参数的值
  BOOLEAN status;		//被赋值则为TRUE，否则FALSE
} OPT_VALUE_STATUS;

#endif

