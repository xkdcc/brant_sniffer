/*******************************************************************************
 Copyright (C), 2007-2010, �³�(CC).
 Program Name:        bcsniffer
 Program Desc:        bcsniffer��������ļ�
 File name:           bcsniffer.c
 Author:              �³�
 Version:             1.0.2
 Date:                2007��06��21��
 Description:         ��[Program Desc]
 Others:
 1.  �÷����
 /bcsniffer [ѡ��]  [ֵ]
 <>��ʾ�ò�������ָ��ֵ
 <>����|������ֵ����ʾ�����Ŀ�ʹ��ֵ
 -i  --interface <interface name>  ָ��Ҫ�������������ƽ���ץ����
 -p  --protocol  <TCP | UDP | ICMP | DEFAULTPROTO_ALL>  ָ��Э�飬TCP/UDP/ICMP��Ĭ��Ϊ���С�
 -s  --stat ָ��stat�󣬳�����ץ��ʱ�����Դ��ַ��Ŀ�ĵ�ַ����ͳ�ƣ����ڽ���ʱ���ÿ��Դ��ַ��Ŀ�ĵ�ַ�İ������ֽڡ�
 -n  --count  <count> ָ��count�󣬳�����ץ��count���Զ��˳��� ��ָ��count������Ĭ�ϣ���ͣץ����
 -h    ��ð���
 -?    ��ð���
 �����в����κβ���ʱ���᲻ͣץ����ʹ��(CTRL + C)��������ʱ����������ݡ�

 TODO-List:
 (1)ָ���������м���
 (2)������Э��ŷ���,�ٸ��ݵ�ַ����ͳ��.
 ���ڵ�״����,�����ICMP֮��Э��ֻ��һ����ַ��,û��ͳ������
 File List:      bcsniffer.c       bcsniffer.h
 linkedop.c        linkedop.h
 netop.c           netop.h
 printmsg.c        printmsg.h
 common.c          common.h
 Makefile

 Function List:    �μ�ͷ�ļ�����

 History:
 1.     Date:    2006-02-10
 Author:  �³�
 Modification:
 ��ɶ������в��������Ե��ж�,ʵ��:
 1)�����в���ʶ����˳���޹�,�ж�����,�������γɹ淶,�Ժ�ĳ�����Խ��
 2)����ò��������ݽṹ
 3)������ָ��Э��������Сд�޹�
 2.     Date:    2006-02-13
 Author:  �³�
 Modification:
 1)������������û��ĳ����ֵʱ,����û�жԸò�����ֵ��BUG
 2)���Ӳ����ж����,�����в�����ֵ��������
 3)ʹ�þֲ���������ȫ�ֱ���opts
 4)����ͷ�ļ������ò���������������ö��޷�ͨ�������������:
 �����ж��ļ������ö�����ʵ���ļ��м���.
 5)Ҫ��ֹ���֣�--protocol 1 -p 1�������Ϸ�������������ͬ���壬
 һ��һ�̵����----����JudgeArgument�����ṹ��OPTIONʵ��
 3.     Date:    2008-10-01
 Author:  �³�
 Modification:
 1)����-i�������޸�ԭ����-i����Ϊ-s���޸�ע�ͣ���δ�κδ��룻
 2)����Ŀ¼�ṹ������ipsnatcher.c��.c�ļ����ƶ���libs�µ���ӦĿ¼��
 ipsnatcher.c�ƶ���srcĿ¼

 *******************************************************************************/

#include <stdlib.h>                    //����UNIX�����Ͷ���ȣ���u_char/u_int32_t
#include <stdio.h>
#include <unistd.h>  
#include <signal.h>
#include <getopt.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>                //��������ͷ�ļ�Ϊ����socket׼��
#include <ctype.h>                     //����isdigit����
#include <netinet/ip.h>                //����struct iphdr�Ƚṹ
#include <netinet/tcp.h>               //����struct tcphdr�Ƚṹ
#include <netinet/udp.h>               //����struct udphdr�Ƚṹ  
#include <arpa/inet.h>  
#include <netinet/if_ether.h>          //����struct ether_arp�Ƚṹ
#include "common.h"
#include "bcsniffer.h"
#include "netop.h"
#include "listop.h"
#include "printmsg.h"

#ifdef _DEBUG
#undef _DEBUG
#endif

#define LOG_FILE            "bcsniffer.log"

static char buf[MAXPACKBUFF];
static int blb = 0;                     //��Ϊ������endcount����ʱ�����������
//����֮ǰ�����interval��������������blbΪ1����ʶ�˳�����ʱ�����ٱ�������
static int iCatchCountInAlarm = 0;       //���趨�ĳ�ʱʱ���ڣ�ץ���İ�����
//�����ʱ��iCatchCountInAlarmΪ0����ǿ�����ץ��ʧ�ܵ���Ϣ��

struct statTable *head;
struct statTable *search;              //(1)��ʶ�ҵ���λ�� (2)���ڿ����½ڵ�ı���
struct statTable *tail;                //βָ��ʼ��ָ�����һ���ڵ�

OPT_VALUE_STATUS opts[3];                 //�ж��ٸ���Ҫ��ֵ�Ĳ������ж��ٸ�opts

//�ж�Я���Ĳ����Ƿ�Ϊ�Ϸ�������
//���أ��ɹ�    0    ʧ��        -1
int ConvertoDigital(char *optarg, int optarglen, long *value) {
  while ((optarglen > 0) && (isdigit(optarg[--optarglen]))) {
  }

  if (optarglen == 0) {
    *value = atol(optarg);
    return 0;
  }
  else {
    return -1;
  }
}

//ת���ַ���Ϊ��д
//���أ��ɹ���0   ʧ�ܣ�-1��
int StrtoUpper(char * str) {
  while (*str != '\0') {
    *str = toupper(*str);
    str++;
  }
  return 0;
}

//�жϲ���Я����ֵ�Ƿ�Ϸ�,����ȫ�ֱ���opts���и�ֵ
//���أ��ɹ���0   ʧ�ܣ�-1��
int SetValueFromCmd(char *optarg, int *option_index, OPT_VALUE_STATUS opts[]) {
  //������ShowUsage����GetCommondLine��
  int ret = -1;
  long argumentvalue = -1;  //����Я����ֵ

  //(1)Ҫ����Я���Ĳ������кϷ����飬�������./ipsnatcher --protocol --interval�����������
  //�磺���������Ҫ�����֣�������������ж��Ƿ����ַ�0~9�ķ�Χ�ڣ��ܷ�ת��Ϊ�Ϸ����֣�����Ƿ�
  //option_indexΪ0ʱ,������������֤,��Ϊ��Э�������ַ���
  if (*option_index != 0) {
    /*#ifdef _DEBUG
     printf("argument:%d\n", atoi(optarg));
     #endif*/

    ret = ConvertoDigital(optarg, strlen(optarg), &argumentvalue);
    if (ret == -1)        //����ת��Ϊ�Ϸ�����
        {
      printf("\nconvertodigital result =%c or %d\n", ret, ret);
      return -1;
    }
  }
  else {
    /*#ifdef _DEBUG
     printf("argument:%s\n", optarg);
     #endif*/
  }

  //�Դ���Ĳ������и�ֵ
  //ͬʱ:(2)���������ͬ�����ѡ���Գ�ѡ��Ͷ�ѡ��ķ�ʽͬʱ����,������:�������ݽṹ�е�statusԪ��.
  //��ʵ�����ڱ�����ÿ��������Ҫ����ֵ������˵������(1)�Ѿ�������(2)��ҪԤ�������
  //ֻ�е������Ĳ���ֵ��Ҫ�������֣���������-����--����ʱ��(2)����ʾ��(2)����Ҫ
  StrtoUpper(optarg);
  switch (*option_index) {
  case 0:
    if (FALSE == opts[0].status) {
      if (!strncmp("TCP", optarg, 10))
        opts[0].rightopt.protocol = TCP;
      else if (!strncmp("UDP", optarg, 10))
        opts[0].rightopt.protocol = UDP;
      else if (!strncmp("ICMP", optarg, 10))
        opts[0].rightopt.protocol = ICMP;
      else if (!strncmp("ALLPROTOCOL", optarg, 20))
        opts[0].rightopt.protocol = ALLPROTOCOL;
      else
        return -1;

      /*#ifdef _DEBUG
       printf("protocol:%d   arg:%s\n", opts[0].rightopt.protocol, optarg);
       #endif*/
    }
    else {
      printf("protocol: maybe the long opt and short opt appearence both\n");
      return -1;
    }
    break;
  case 1:
    if (FALSE == opts[1].status) {
      opts[1].rightopt.interval = argumentvalue;

      /*#ifdef _DEBUG
       printf("interval:%ld\n", opts[1].rightopt.interval);
       #endif */
    }
    else {
      printf("interval: maybe the long opt and short opt appearence both\n");
      return -1;
    }
    break;
  case 2:
    if (FALSE == opts[2].status) {
      opts[2].rightopt.endcount = argumentvalue;

      /*#ifdef _DEBUG
       printf("count:%ld\n", opts[2].rightopt.endcount);
       #endif*/
    }
    else {
      printf("count: maybe the long opt and short opt appearence both\n");
      return -1;
    }
    break;
  default:
    printf("option_index err!option_index=%d\n", *option_index);
    return -1;
  }
  opts[*option_index].status = TRUE;

  //(3)����Ҫ�����������:
  //����һ������������ֺϷ��Ĳ���:
  // 1. ./progname -D ����./progname -d ����./progname --delrecord
  // 2. ./progname -A 12 ����./progname -a 123 ����./progname --addrecord  123

  //(4)������ַ��볤�ַ��ĵ�һ����ĸ��ͬ�����-delrecor��Ϊ��-d(-D)�����

  return 0;
}

//��ò���
//���أ��ɹ�    0        ʧ��        -1
int GetCommandLine(int argc, char *argv[], BOOLEAN *pNoopt) {
  int c;
  int optloopcount = 0;  //������ѭ���Ĵ���
  int option_index = -1;
  int ret = -1;

  //���ܰѳ�ʼ���Ĵ������ȫ��:(�ᱨ��
  //�����������6��
  //���ò�����Ĭ��ֵ
  opts[0].rightopt.protocol = DEFAULTPROTO_ALL;
  opts[0].status = FALSE;
  opts[1].rightopt.interval = 10;
  opts[1].status = FALSE;
  opts[2].rightopt.endcount = 100;
  opts[2].status = FALSE;

  opterr = 0; //ʹϵͳ���Զ���ӡ�����������Ϣ
  optind = 0;

  /*ÿ��������Ҫ*/
  if (argc == 1) {
    *pNoopt = TRUE;
    //�����в�����Ĭ��ֵ
    opts[0].rightopt.protocol = DEFAULTPROTO_ALL;
    opts[0].status = TRUE;
    opts[1].rightopt.interval = 10;
    opts[1].status = TRUE;
    opts[2].rightopt.endcount = 0; //����ץ��
    opts[2].status = TRUE;

    return 0;
  }

  while (optloopcount < argc - 1) { //��Ȼgetopt_longҪ������ÿ�������󷵻�-1��ѭ���ִ�����-1��������԰�ȫ�˳�
                                    //���������ǻ���Ϊ���Է���һ������loopcount����ѭ���Ĵ�����ͬʱΪ���ж��Ƿ񡣡���

    static struct option long_options[] = { { "protocol", 1, 0, 0 }, {
        "interval", 1, 0, 0 }, { "count", 1, 0, 0 }, { 0, 0, 0, 0 } };
    c = getopt_long(argc, argv, "p:e:n:?h", long_options, &option_index);

    if (option_index == -1 && c == '?') //�����жϲ�ƥ��ĳ�ѡ����в�ƥ��ĳ�ѡ��ʱ��option_indexΪ-1��
                                        //���ǵ�Ϊƥ���ƥ��Ķ�ѡ��ʱ��option_index����-1������Ҫ�����ж��Ƿ�ƥ���ѡ��
                                        //����ǲ�ƥ��Ķ�ѡ�getopt_long���أ�
        {
      /*#ifdef DEBUG
       printf("non matches getopt_long ret -1\n");
       #endif*/

      ShowUsage();
      return -1;
    }

    switch (c) {
    case -1:
      /*#ifdef _DEBUG
       printf("c==-1\n");
       #endif*/

      /*ÿ��������Ҫ*/
      if (optind == argc)  //������ж������в�����������case,��ʱ�Ѳ�������while������,
                           //��ִ�к���Ĵ���.�����ڷ���������main
          {
        break;
      }
      else {
        ShowUsage();
        return -1;
      }
    case 0:
      /*#ifdef DEBUG
       printf ("option %s.option_index:%d", long_options[option_index].name, option_index);
       #endif*/

      //�жϲ���Я����ֵ�Ƿ�Ϸ�
      ret = SetValueFromCmd(optarg, &option_index, opts);
      if (ret) {
        ShowUsage();
        return -1;
      }

      /*#ifdef DEBUG
       if (optarg)            //��Ҫ���ںϷ��ж�֮��
       printf (" with arg %s", optarg);
       printf ("\n");
       #endif*/

      break;
    case 'p':
      /*#ifdef DEBUG
       printf ("option p--protocol with value ");
       #endif*/

      option_index = 0; //����Ҫ������ֵ����Ϊʶ��Ϊ��ѡ��Ļ���option_index��-1
      ret = SetValueFromCmd(optarg, &option_index, opts);
      if (ret) {
        ShowUsage();
        return -1;
      }

      /*if(optarg)            //��Ҫ���ںϷ��ж�֮��
       printf ("%s", optarg);
       printf ("\n");*/
      break;
    case 'e':
      /*#ifdef DEBUG
       printf ("option e--interval with value");
       #endif*/

      option_index = 1;
      ret = SetValueFromCmd(optarg, &option_index, opts);
      if (ret) {
        ShowUsage();
        return -1;
      }

      /*if (optarg)            //��Ҫ���ںϷ��ж�֮��
       printf ("%s", optarg);
       printf ("\n");*/

      break;
    case 'n':
      /*#ifdef DEBUG
       printf ("option n--count with value");
       #endif*/

      option_index = 2;
      ret = SetValueFromCmd(optarg, &option_index, opts);
      if (ret) {
        ShowUsage();
        return -1;
      }

      /*if (optarg)            //��Ҫ���ںϷ��ж�֮��
       printf ("%s", optarg);
       printf ("\n");*/

      break;
    case '?': /*ÿ��������Ҫ*/        //���������ƥ��Ķ�ѡ����ߡ�����
    case 'h': /*ÿ��������Ҫ*/
    default: /*ÿ��������Ҫ*/
      /*#ifdef DEBUG
       printf("? h else *** \n");
       #endif*/

      ShowUsage();
      return -1; //ע����뷵��
    }
    optloopcount++;
  }

  //��������û��ָ���Ĳ������и�Ĭ��ֵ
  if (FALSE == opts[0].status) {
    opts[0].rightopt.protocol = DEFAULTPROTO_ALL;
    opts[0].status = TRUE;
    printf("\nprotocol not assigned in cmd.Set default: DEFAULTPROTO_ALL.");
  }
  if (FALSE == opts[1].status) {
    opts[1].rightopt.interval = 10;
    opts[1].status = TRUE;
    printf("\ninterval not assigned in cmd.Set default: 10.");
  }
  if (FALSE == opts[2].status) {
    opts[2].rightopt.endcount = 0;
    opts[2].status = TRUE;
    printf("\nendcount not assigned in cmd.Set default: 0.");
  }
  printf("\n");

  return 0;
}

//��ʱ��û��ץ����ʱ�������Ϣ��
void Print_CatchNull(int signo) {
  if (iCatchCountInAlarm == 0) {
    system("echo -n .");
  }
  else {
    iCatchCountInAlarm = 0;
  }
}

//�������������ñ������������
void Catch_Ctrl_C(int signo) {
  if (!blb) {
    bianli(head, search);
  }
  exit(0);
}

//���������Ϣ
void D_Printf_Tcp(const int len, struct ip *p1, struct iphdr *p2,
    struct tcphdr *p3) {
  printf("r:%d\n", len);
  printf("ether_header:%ld\n", sizeof(struct ether_header));
  printf("ethhdr:%ld\n", sizeof(struct ethhdr));
  printf("ip->ip_len:%d\n", p1->ip_len);
  printf("ntohs(ip->ip_len):%d\n", ntohs(p1->ip_len));
  printf("iph->tot_len:%d\n", p2->tot_len);
  printf("ntohs(piph->tot_len):%d\n", ntohs(p2->tot_len));
  printf("ptcp->doff:%d\n", p3->doff);
}

//���������Ϣ
void D_Printf_Udp(const int len, struct ip *p1, struct iphdr *p2) {
  printf("r:%d\n", len);
  printf("ether_header:%ld\n", sizeof(struct ether_header));
  printf("ethhdr:%ld\n", sizeof(struct ethhdr));
  printf("ip->ip_len:%d\n", p1->ip_len);
  printf("ntohs(ip->ip_len):%d\n", ntohs(p1->ip_len));
  printf("piph->tot_len:%d\n", p2->tot_len);
  printf("ntohs(piph->tot_len):%d\n", ntohs(p2->tot_len));
}

int main(int argc, char *argv[]) {
  struct sockaddr_in addr;
  struct ether_header *peth;    //��̫��֡��ͷָ��
  struct ether_arp *parph;      //ARP��ͷ
  struct ip *pip;
  struct iphdr *piph;           //IPͷ�ṹ
  struct tcphdr *ptcp;          //TCPͷ�ṹ
  struct udphdr *pudp;          //UDPͷ�ṹ

  BOOLEAN noopt = FALSE;          //��¼����ִ���Ƿ���������в���,û������Ĭ�ϲ�������ִ��

  int proto = DEFAULTPROTO_ALL;   //����������ʹ�þֲ���������ȫ�ֱ���opts,
                                  //һ��Ϊ����д����,
                                  //���Ǳ���ȫ�ֱ�����ʹ��,��Ȼopts�ڸ�ֵ��Ӧ�ò������д����޸���,����Ϊ���Է���һ.
  unsigned long interval = 10;    //��¼����������ݵĴ������
  unsigned long count = 0;        //��¼ץ���Ĵ���

  int sock;                     //����socket����
  int r;                        //reve�ķ���ֵ
  int len;                      //sizeof(addr)��ȡ��ַ����recv��
  char *ptemp;                  //��Ҫ��ָ�룡
  unsigned int ptype;           //�жϲ��Э�����ͱ�������ARP����IP��
  u_char * data;                //���ݰ�����ָ��

  struct sigaction actInterrupt;
  struct sigaction actAlarm;

  head = tail = search = NULL;  //��ʼ������ָ��
  memset(buf, 0, MAXPACKBUFF);

  //�жϲ����Ϸ���
  GetCommandLine(argc, argv, &noopt);

  //����������������ս��
  if (TRUE == noopt) {
    printf("\nnone opt get, assign default value:\n");
  }
  else if (FALSE == noopt) {
    printf("\nopt  value list below:\n");
  }

  if (TRUE == opts[0].status)
    printf("protocol:%d    ", opts[0].rightopt.protocol);
  if (TRUE == opts[1].status)
    printf("interval:%ld    ", opts[1].rightopt.interval);
  if (TRUE == opts[2].status)
    printf("count:%ld", opts[2].rightopt.endcount);

  printf("\n");

  proto = opts[0].rightopt.protocol;
  interval = opts[1].rightopt.interval;
  count = opts[2].rightopt.endcount;
  len = sizeof(addr);

  //�����ж��źŵ��źŴ���
  actInterrupt.sa_handler = Catch_Ctrl_C;
  sigemptyset(&actInterrupt.sa_mask);
  actInterrupt.sa_flags = 0;
  sigaddset(&actInterrupt.sa_mask, SIGINT);
  //�����ް�ץ��ʱ���źŴ���
  actAlarm.sa_handler = Print_CatchNull;
  sigemptyset(&actAlarm.sa_mask);
  actAlarm.sa_flags = 0;
  sigaddset(&actAlarm.sa_mask, SIGALRM);

  if ((sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1) //����ԭʼ�׽���socket
      {
    showErr("socket", 1);
  }

  //��������eth0Ϊ����ģʽ,��ִ��system�鿴���
  set_promisc("eth0", sock);        //eth0Ϊ��������
  system("ifconfig");

  for (;;) {
    alarm(1);
    //ÿ��ѭ�������źŴ���
    if (sigaction(SIGALRM, &actAlarm, NULL ) < 0) {
      printf("signal SIGIALRM error!\n");
      exit(1);
    }

    if (sigaction(SIGINT, &actInterrupt, NULL ) < 0) {
      printf("signal SIGINT error!\n");
      exit(1);
    }

    //�������ж��Ƿ�ץ����
    if ((r = recvfrom(sock, (char *) buf, sizeof(buf), 0,
        (struct sockaddr *) &addr, &len)) > 0) {
      iCatchCountInAlarm++;
    }
    else {
      //???������???(1)��������printf���'.',���������ʱ�����ӡ��'.',ֻ�е�CTRL+C��Ż��ӡ����
      //???������???(2)�ǵ�û��ʹ�ó�ʱ����ʱ,recvfrom��һֱ����,Ҳ���ǲ���ִ���������д���;��ʹ�ú�,����ִ��!
      //???������???(3)ʹ��syncû����!Ҳ�����ӡ���ַ�'.'
      //printf(".");
      //sync();
      //printf("\n");
      iCatchCountInAlarm = 0; //Ϊ�����'.',��Print_CatchNull�е�else��iCatchCountInAlarm��0��˫�ر���.
      continue;
    }

    printf("\n%ld ", ++count);
    print_time();
    printf("%dB ", r);

    ptemp = buf;             //��ʼ��ָ��ptemp
    peth = (struct ether_header *) ptemp;
    ptype = ntohs(peth->ether_type);                   //����̫��֡���Э������

    if ((ptype == ETHERTYPE_ARP) || (ptype == ETHERTYPE_REVARP))    //�ж���ʲô��
        {
      parph = (struct ether_arp *) (ptemp + sizeof(struct ether_header));
      print_arp_rarp(parph, ptype);
    }
    else if (ptype == ETHERTYPE_IP)                      //�����IP���ݰ�
    {
      ptemp += sizeof(struct ether_header);        //ָ�����ether_header�ĳ���
      pip = (struct ip *) ptemp;
      piph = (struct iphdr *) ptemp;                 //piphָ��ip���ͷ
      //��ӡipͷ��Ϣ
      printf_ip(piph);
      printf("checksum %d ", checksumip((u_int16_t *) pip, 4 * pip->ip_hl));

      //id�� ʶ��IP���ݱ��ı�ţ���ʶ�ֶ�Ψһ�ر�ʶ�������͵�ÿһ��
      //���ݱ���ͨ��ÿ����һ�ݱ�������ֵ�ͻ��1
      //frag_off;     3/16 1λΪ0��ʾ����飬2λΪ0��ʾ��������飬3λΪ1��ʾ������
      //13/8 ��Ƭ��ԭ�����е�λ��
      //��������ֵδ�����������˷�����IPͷ���ֶ�

      /*#ifdef _DEBUG
       printf("Before add!\n");
       printf("show inet_ntoa(*(struct in_addr*)&(piph->saddr)):%s\n", inet_ntoa(*(struct in_addr*)&(piph->saddr)));
       printf("show inet_ntoa(*(struct in_addr*)&(piph->daddr)):%s\n", inet_ntoa(*(struct in_addr*)&(piph->daddr)));
       #endif  */

      //��statTable�ṹ����в���
      //���Ƚ��в��ң�����ͷָ��
      //���Һ������ж��������Ƿ�Ϊ�գ�Ϊ�տ϶�û�ҵ�������-1
      if (!searchT(piph, (struct statTable **) &search, head))     //�ҵ�����0
          {
#ifdef _DEBUG
        printf("search->sip:%s, search->dip:%s\n", search->sip, search->dip);
#endif
        progreBP(r, search);       //�ۼ�
      }
      else {
        if ((search = malloc(sizeof(struct statTable))) < 0) {
          printf("Out of memory!\n");
          continue;
        }
        addfulT(piph, r, search);  //��ӽڵ�
        //�ƶ�ָ��
        if (head == NULL ) {
          /*#ifdef _DEBUG
           printf("Head is NULL!\n");
           #endif*/

          tail = head = search;
        }
        else {
          tail->next = search;
          tail = search;
        }
      }

      ptemp += (piph->ihl << 2);               //�ƶ�ptemp��iph�ṹ��

      switch (piph->protocol)                   //���ݲ�ͬЭ���ж�ָ������
      {
      case IPPROTO_TCP:
#ifdef _DEBUG
        //D_Printf_Tcp(r, pip, piph, ptcp);
#endif
        printf_tcp(ptemp, piph, ptcp, data);
        break;

      case IPPROTO_UDP:
#ifdef _DEBUG
        //D_Printf_Udp(r, pip, piph);
#endif
        printf_udp(ptemp, piph, pudp, data);
        break;

      case IPPROTO_ICMP:
        printf("%s \n", inet_ntoa(*(struct in_addr*) &(piph->saddr)));
        break;

      case IPPROTO_IGMP:
        printf("IGMP \n");
        break;

      default:
        printf("Unkown protocol %d\n", piph->protocol);
        break;
      }                   //end switch
    }                   //end if
    else
      printf("\nUnkown package,protocol type:%d\n", ptype);

    //�ж�interval����
    if ((opts[1].rightopt.interval != 0)
        && (count % opts[1].rightopt.interval == 0)) {
      bianli(head, search);
      blb = 1;
    }
    //�ж�endcount����
    if ((opts[2].rightopt.endcount != 0)
        && (count == opts[2].rightopt.endcount)) {
      if (!blb) {
        bianli(head, search);
      }
      exit(0);
    }
    sleep(1);
    blb = 0;
  }                   //end for
  printf("\n");
}

