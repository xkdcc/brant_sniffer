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

//�����Ҫ��ֵ�Ĳ���
typedef union _node {
  int protocol;
  unsigned long interval;
  unsigned long endcount;
  Boolean  print_data;    //print_data ����Ҫ��ֵ������ֻ��ռλ����Ϊ�˶Գƶ��ѡ�
} node;

typedef struct _cmd_opt {
  node rightopt;    //�洢��Ӧ������ֵ�������������Ҫ��ֵ���Ͳ������node�ṹ��
  Boolean status;   //����ֵ��ΪTRUE������FALSE
} Cmd_Opt;

#endif

