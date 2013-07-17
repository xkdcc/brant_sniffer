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

//�����Ҫ��ֵ�Ĳ���
typedef union _option_value {
  int protocol;
  unsigned long interval;
  unsigned long endcount;
  Boolean print_data;    //print_data ����Ҫ��ֵ������ֻ��ռλ����Ϊ�˶Գƶ��ѡ�
} Option_Value;

typedef struct _cmd_opt {
  Option_Value rightopt;    //�洢��Ӧ������ֵ�������������Ҫ��ֵ���Ͳ������node�ṹ��
  Boolean status;   //����ֵ��ΪTRUE������FALSE
} Cmd_Opt;

#endif

