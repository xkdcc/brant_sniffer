/*******************************************************************************
 Copyright (C), 2007-2010, Brant Chen (xkdcc@163.com, brantchen2008@gmail.com).
 Program Name:        bcsniffer
 Program Desc:        Similar to other sniffer but with some great features for
 my sake :)
 File name:           bcsniffer.c
 Author:              Brant Chen (brantchen2008@gmail.com)
 Version:             1.0.2
 Date:                Started from June 21, 2007
 Description:         Refer to [Program Desc]
 Others:
 1.  Usage
 /bcsniffer [options]  [value]
 <>��ʾ�ò�������ָ��ֵ
 <>����|������ֵ����ʾ�����Ŀ�ʹ��ֵ
 -i  --interface <interface name>  ָ��Ҫ�������������ƽ���ץ����
 -p  --protocol  <TCP | UDP | ICMP | DEFAULTPROTO_ALL>  ָ��Э�飬TCP/UDP/ICMP��Ĭ��Ϊ���С�
 -s  --stat ָ��stat�󣬳�����ץ��ʱ�����Դ��ַ��Ŀ�ĵ�ַ����ͳ�ƣ����ڽ���ʱ���ÿ��Դ��ַ��Ŀ�ĵ�ַ�İ������ֽڡ�
 -n  --count  <count> ָ��count�󣬳�����ץ��count���Զ��˳��� ��ָ��count������Ĭ�ϣ���ͣץ����
 -h    ��ð���
 -?    ��ð���
 �����в����κβ���ʱ���᲻ͣץ����ʹ��(CTRL + C)��������ʱ����������ݡ�

 TODO:
 (1)ָ���������м�������ʵ��-i
 (2)�Ѷ˿ںż�������statistic��
 (3)Review checksum_ip

 History:
 1.     Date:    2006-02-10
 Author:  Brant Chen
 Modification:
 ��ɶ������в��������Ե��ж�,ʵ��:
 1)�����в���ʶ����˳���޹�,�ж�����,�������γɹ淶,�Ժ�ĳ�����Խ��
 2)����ò��������ݽṹ
 3)������ָ��Э��������Сд�޹�
 2.     Date:    2006-02-13
 Author:  Brant Chen
 Modification:
 1)������������û��ĳ����ֵʱ,����û�жԸò�����ֵ��BUG
 2)���Ӳ����ж����,�����в�����ֵ��������
 3)ʹ�þֲ���������ȫ�ֱ���opts
 4)����ͷ�ļ������ò���������������ö��޷�ͨ�������������:
 �����ж��ļ������ö�����ʵ���ļ��м���.
 5)Ҫ��ֹ���֣�--protocol 1 -p 1�������Ϸ�������������ͬ���壬
 һ��һ�̵����----����JudgeArgument�����ṹ��OPTIONʵ��
 3.     Date:    2008-10-01
 Author:  Brant Chen
 Modification:
 1)����-i�������޸�ԭ����-i����Ϊ-s���޸�ע�ͣ���δ�κδ��룻
 2)����Ŀ¼�ṹ������bcsniffer.c��.c�ļ����ƶ���libs�µ���ӦĿ¼��
 bcsniffer.c�ƶ���srcĿ¼
 4.     Date:    2013-07-11
 Author:  Brant Chen
 Modification:
 1) Change program name from ipsnatchter to bcsniffer.
 2) Fix some Makefile bugs and compile successfully on Ubuntu 12.04 LTS.
 3) Using git for version control.

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
//��Ϊ������endcount����ʱ�����������
//����֮ǰ�����interval��������������blbΪ1����ʶ�˳�����ʱ�����ٱ�������
static int blb = 0;
//���趨�ĳ�ʱʱ���ڣ�ץ���İ�����
//�����ʱ��catch_count_in_alarmΪ0����ǿ�����ץ��ʧ�ܵ���Ϣ��
static int catch_count_in_alarm = 0;

struct pkg_list *head;
struct pkg_list *search;         //(1)��ʶ�ҵ���λ�� (2)���ڿ����½ڵ�ı���
struct pkg_list *tail;           //βָ��ʼ��ָ�����һ���ڵ�

Cmd_Opt opts[4];                 //�ж��ٸ���Ҫ���õĲ������ж��ٸ�opts

void show_usage() {
  printf("\nUsage:./bcsniffer [Option] ... [Value]...\n"
      "-p --protocol <TCP|UDP|ICMP> \n"
      "   specify protocol to catch.\n"
      "-e --interval <Interval> \n"
      "   output linked list when finish snatching packages by default.\n"
      "-n --endcount <Endcount> \n"
      "   exit when specified how many packages user want. \n"
      "   bcsniffer wont't stop by default if without -n.\n"
      "-x --display \n"
      "   display the TCP/UDP data in hex and printable characters. \n\n");
}

//�жϲ���Я����ֵ(�����*optarg��)�Ƿ�Ϸ�,����ȫ�ֱ���opts���и�ֵ
//���أ��ɹ���0   ʧ�ܣ�-1��
int set_value_from_cmd(char *optarg, int *option_index, Cmd_Opt opts[]) {
  //������show_usage����GetCommondLine��
  int ret = -1;
  long value = -1;  //����Я����ֵ

  //(1)Ҫ����Я���Ĳ������кϷ����飬�������./bcsniffer --protocol --interval�����������
  //�磺���������Ҫ�����֣�������������ж��Ƿ����ַ�0~9�ķ�Χ�ڣ��ܷ�ת��Ϊ�Ϸ����֣�����Ƿ�
  //option_indexΪ0ʱ,������������֤,��Ϊ��Э�������ַ���
  if (*option_index != 0 && optarg != NULL) {
    /*#ifdef _DEBUG
     printf("argument:%d\n", atoi(optarg));
     #endif*/

    ret = convert_to_digital(optarg, strlen(optarg), &value);
    if (ret == -1) {       //����ת��Ϊ�Ϸ�����
      printf("\n convert to digital result =%c or %d\n", ret, ret);
      return -1;
    }
  }
  else {
    /*#ifdef _DEBUG
     printf("argument:%s\n", optarg);
     #endif*/
    if (*option_index==3) { // means "-x" option
      opts[3].status = TRUE;
      opts[3].rightopt.print_data = TRUE;
    }
    return 0;
  }

  //�Դ���Ĳ������и�ֵ
  //ͬʱ:(2)���������ͬ�����ѡ���Գ�ѡ��Ͷ�ѡ��ķ�ʽͬʱ����,
  //������:�������ݽṹ�е�statusԪ��.
  //��ʵ�����ڱ�����ÿ��������Ҫ����ֵ������˵������(1)�Ѿ�������(2)��ҪԤ�������
  //ֻ�е������Ĳ���ֵ��Ҫ�������֣���������-����--����ʱ���ڶ������ʾ����������
  str_to_upper(optarg);
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
      opts[1].rightopt.interval = value;

      /*#ifdef _DEBUG
       printf("interval:%ld\n", opts[1].rightopt.interval);
       #endif */
    }
    else {
      printf("interval: maybe the long opt and short opt appearance both\n");
      return -1;
    }
    break;
  case 2:
    if (FALSE == opts[2].status) {
      opts[2].rightopt.endcount = value;

      /*#ifdef _DEBUG
       printf("count:%ld\n", opts[2].rightopt.endcount);
       #endif*/
    }
    else {
      printf("count: maybe the long opt and short opt appearance both\n");
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
int get_command_line_option(int argc, char *argv[], Boolean *pNoopt) {
  int c;
  int opt_loop_count = 0;  //������ѭ���Ĵ���
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
  opts[3].rightopt.print_data = FALSE; //Don't print the data in package by default
  opts[3].status = FALSE;

  opterr = 0; //ʹϵͳ���Զ���ӡ�����������Ϣ
  optind = 0;

  /*ÿ��������Ҫ*/
  if (argc == 1) {
    *pNoopt = TRUE;
    //����ز�����Ĭ��ֵ
    opts[2].rightopt.endcount = 0; //����ץ��
    opts[2].status = TRUE;

    return 0;
  }

  //��Ȼgetopt_longҪ������ÿ�������󷵻�-1��ѭ���ִ�����-1��������԰�ȫ�˳�
  //���������ǻ���Ϊ���Է���һ������loopcount����ѭ���Ĵ�����ͬʱΪ���ж��Ƿ񡣡���
  while (opt_loop_count < argc - 1) {

    static struct option long_options[] = { { "protocol", 1, 0, 0 }, {
        "interval", 1, 0, 0 }, { "count", 1, 0, 0 }, { "display", 0, 0, 0 },
        { 0, 0, 0, 0 } };
    c = getopt_long(argc, argv, "p:e:n:x?h", long_options, &option_index);

    //�����жϲ�ƥ��ĳ�ѡ����в�ƥ��ĳ�ѡ��ʱ��option_indexΪ-1��
    //���ǵ�Ϊƥ���ƥ��Ķ�ѡ��ʱ��option_index����-1������Ҫ�����ж��Ƿ�ƥ���ѡ��
    //����ǲ�ƥ��Ķ�ѡ�getopt_long���أ�
    if (option_index == -1 && c == '?') {
      /*#ifdef DEBUG
       printf("non matches getopt_long ret -1\n");
       #endif*/

      show_usage();
      exit(1);
    }

    switch (c) {
    case -1:
      /*#ifdef _DEBUG
       printf("c==-1\n");
       #endif*/

      /*ÿ��������Ҫ*/
      //������ж������в�����������case,��ʱ�Ѳ�������while������,
      //��ִ�к���Ĵ���.�����ڷ���������main
      if (optind == argc) {
        break;
      }
      else {
        show_usage();
        exit(1);
      }
    case 0:
      /*#ifdef DEBUG
       printf ("option %s.option_index:%d", long_options[option_index].name, option_index);
       #endif*/

      //�жϲ���Я����ֵ�Ƿ�Ϸ�����ֵ
      ret = set_value_from_cmd(optarg, &option_index, opts);
      if (ret) {
        show_usage();
        exit(1);
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
      ret = set_value_from_cmd(optarg, &option_index, opts);
      if (ret) {
        show_usage();
        exit(1);
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
      ret = set_value_from_cmd(optarg, &option_index, opts);
      if (ret) {
        show_usage();
        exit(1);
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
      ret = set_value_from_cmd(optarg, &option_index, opts);
      if (ret) {
        show_usage();
        exit(1);
      }

      /*if (optarg)            //��Ҫ���ںϷ��ж�֮��
       printf ("%s", optarg);
       printf ("\n");*/

      break;
    case 'x':
      //#ifdef DEBUG
      printf ("option x, optarg:%s, option_index:%d", optarg, option_index);
       //#endif

      option_index = 3;
      ret = set_value_from_cmd(optarg, &option_index, opts);
      if (ret) {
        show_usage();
        exit(1);
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

      show_usage();
      exit(1);
    }
    opt_loop_count++;
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
void print_msg_while_catch_nothing(int signo) {
  int ret = 0;
  if (catch_count_in_alarm == 0) {
    ret = system("echo -n .");
  }
  else {
    catch_count_in_alarm = 0;
  }
}

//�������������ñ������������
void before_interupt(int signo) {
  if (!blb) {
    traversal_list(head, search);
  }
  exit(0);
}

//���������Ϣ
void print_tcp_in_detail(const int len, struct ip *p1, struct iphdr *p2,
    struct tcphdr *p3) {
  printf("r:%d\n", len);
  printf("ether_header:%ld\n", (long int)sizeof(struct ether_header));
  printf("ethhdr:%ld\n", (long int)sizeof(struct ethhdr));
  printf("ip->ip_len:%d\n", p1->ip_len);
  printf("ntohs(ip->ip_len):%d\n", ntohs(p1->ip_len));
  printf("iph->tot_len:%d\n", p2->tot_len);
  printf("ntohs(piph->tot_len):%d\n", ntohs(p2->tot_len));
  printf("ptcp->doff:%d\n", p3->doff);
}

//���������Ϣ
void print_udp_in_detail(const int len, struct ip *p1, struct iphdr *p2) {
  printf("r:%d\n", len);
  printf("ether_header:%ld\n", (long int)sizeof(struct ether_header));
  printf("ethhdr:%ld\n", (long int)sizeof(struct ethhdr));
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

  Boolean noopt = FALSE;          //��¼����ִ���Ƿ���������в���,û������Ĭ�ϲ�������ִ��

  int proto = DEFAULTPROTO_ALL;   //����������ʹ�þֲ���������ȫ�ֱ���opts,
                                  //һ��Ϊ����д����,
                                  //���Ǳ���ȫ�ֱ�����ʹ��,��Ȼopts�ڸ�ֵ��Ӧ�ò������д����޸���,����Ϊ���Է���һ.
  unsigned long interval = 10;    //��¼����������ݵĴ������
  unsigned long count = 0;        //��¼ץ���Ĵ���

  int sock;                     //����socket����
  int r;                        //recv����ֵ
  int len;                      //sizeof(addr)��ȡ��ַ����recv��
  char *ptemp;                  //��Ҫ��ָ�룡
  unsigned int ptype;           //�жϲ��Э�����ͱ�������ARP����IP��
  int ret = 0;

  struct sigaction sig_interrupt_action;
  struct sigaction sig_alarm_action;

  head = tail = search = NULL;  //��ʼ������ָ��
  memset(buf, 0, MAXPACKBUFF);

  //�жϲ����Ϸ���
  get_command_line_option(argc, argv, &noopt);

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
  count = 0;
  len = sizeof(addr);

  //�����ж��źŵ��źŴ���
  sig_interrupt_action.sa_handler = before_interupt;
  sigemptyset(&sig_interrupt_action.sa_mask);
  sig_interrupt_action.sa_flags = 0;
  sigaddset(&sig_interrupt_action.sa_mask, SIGINT);

  //�����ް�ץ��ʱ���źŴ���
  sig_alarm_action.sa_handler = print_msg_while_catch_nothing;
  sigemptyset(&sig_alarm_action.sa_mask);
  sig_alarm_action.sa_flags = 0;
  sigaddset(&sig_alarm_action.sa_mask, SIGALRM);

  //����ԭʼ�׽���socket
  if ((sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1) {
    print_msg_for_last_errno("socket", 1);
  }

  //��������eth0Ϊ����ģʽ,��ִ��system�鿴�����eth0Ϊ��������
  set_promisc("eth0", sock);
  // Just get ret to avoid compile warning, like:
  // ���棺 ���������� warn_unused_result ���Եġ�system���ķ���ֵ [-Wunused-result]
  ret = system("ifconfig");

  for (;;) {
    alarm(1);
    //ÿ��ѭ�������źŴ���
    if (sigaction(SIGALRM, &sig_alarm_action, NULL ) < 0) {
      printf("signal SIGIALRM error!\n");
      exit(1);
    }

    if (sigaction(SIGINT, &sig_interrupt_action, NULL ) < 0) {
      printf("signal SIGINT error!\n");
      exit(1);
    }

    //�������ж��Ƿ�ץ����
    if ((r = recvfrom(sock, (char *) buf, sizeof(buf), 0,
        (struct sockaddr *) &addr, &len)) > 0) {
      catch_count_in_alarm++;
    }
    else {
      //Ϊ�����'.',��print_msg_while_catch_nothing�е�else��catch_count_in_alarm
      //��0��˫�ر���.
      catch_count_in_alarm = 0;
      continue;
    }

    printf("\n[%3ld] ", ++count);
    print_time();
    printf("Package total length:[%d Byte] ", r);

    ptemp = buf;             //��ʼ��ָ��ptemp
    peth = (struct ether_header *) ptemp;
    ptype = ntohs(peth->ether_type);               //����̫��֡���Э������

    //�ж���ʲôЭ��İ�
    if ((ptype == ETHERTYPE_ARP) || (ptype == ETHERTYPE_REVARP)) {
      parph = (struct ether_arp *) (ptemp + sizeof(struct ether_header));
      print_arp_rarp(parph, ptype);
    }
    else if (ptype == ETHERTYPE_IP) {       //�����IP���ݰ�
      ptemp += sizeof(struct ether_header); //ָ�����ether_header�ĳ��ȣ�4�ֽ�
      pip = (struct ip *) ptemp;
      piph = (struct iphdr *) ptemp;        //piphָ��ip���ͷ
      //��ӡipͷ��Ϣ
      printf_ip_header(piph);
      //printf("struct ip ip_sum:%d\n", pip->ip_sum);
      //printf("checksum %d ", checksum_ip((u_int16_t *) pip, 4 * pip->ip_hl));

      /*#ifdef _DEBUG
       printf("Before add!\n");
       printf("show inet_ntoa(*(struct in_addr*)&(piph->saddr)):%s\n", inet_ntoa(*(struct in_addr*)&(piph->saddr)));
       printf("show inet_ntoa(*(struct in_addr*)&(piph->daddr)):%s\n", inet_ntoa(*(struct in_addr*)&(piph->daddr)));
       #endif  */

      //��pkg_list������в���
      //���Ƚ��в��ң�����ͷָ��
      //���Һ������ж��������Ƿ�Ϊ�գ�Ϊ�տ϶�û�ҵ�������-1���ҵ�����0
      if (!search_ip_in_list(piph, (struct pkg_list **) &search, head)) {
#ifdef _DEBUG
        printf("search->sip:%s, search->dip:%s\n", search->sip, search->dip);
#endif
        sum_element_in_list(r, search);       //�ۼ�
      }
      else {
        if ((search = malloc(sizeof(struct pkg_list))) < 0) {
          printf("Out of memory!\n");
          continue;
        }
        add_node_to_list(piph, r, search);  //��ӽڵ�
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

      //ihl��IP header length
      //<<2�൱�ڳ���4��ΪʲôptempҪ�Ƶ�ihl*4��λ�ã�
      //ŶҲ�����ˣ���Ϊihl��4bit������Ƕ�����1111����ʮ����15��
      //��ÿ��1����4Byte������IP��ͷ����󳤶���15*4=60�ֽڡ�
      //�μ�http://blog.csdn.net/achejq/article/details/7040687
      ptemp += (piph->ihl << 2);

      switch (piph->protocol)                   //���ݲ�ͬЭ���ж�ָ������
      {
      case IPPROTO_TCP:
#ifdef _DEBUG
        //print_tcp_in_detail(r, pip, piph, ptcp);
#endif
        printf_tcp(ptemp, piph, opts[3].rightopt.print_data);
        break;

      case IPPROTO_UDP:
#ifdef _DEBUG
        //print_udp_in_detail(r, pip, piph);
#endif
        printf_udp(ptemp, piph, opts[3].rightopt.print_data);
        break;

      case IPPROTO_ICMP:
        printf("%s \n", inet_ntoa(*(struct in_addr*) &(piph->saddr)));
        break;

      case IPPROTO_IGMP:
        printf("IGMP \n");
        break;

      default:
        printf("Unknown protocol %d\n", piph->protocol);
        break;
      }                   //end switch
    }                   //end if
    else
      printf("\nUnknown package,protocol type:%d\n", ptype);

    //�ж�interval����
    if ((opts[1].rightopt.interval != 0)
        && (count % opts[1].rightopt.interval == 0)) {
      traversal_list(head, search);
      blb = 1;
    }
    //�ж�endcount����
    if ((opts[2].rightopt.endcount > 0)
        && (count == opts[2].rightopt.endcount)) {
      if (!blb) {
        traversal_list(head, search);
      }
      exit(0);
    }
    //sleep(1);
    blb = 0;
  }                   //end for
  printf("\n");
}

