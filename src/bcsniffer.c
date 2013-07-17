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
 bcsniffer [options]  [value]
 <>��ʾ�ò�������ָ��ֵ
 <>����|������ֵ����ʾ�����Ŀ�ʹ��ֵ
 -i  --interface <interface name>  ָ��Ҫ�������������ƽ���ץ����
 -p  --protocol  <TCP | UDP | ICMP | DEFAULTPROTO_ALL>  ָ��Э�飬TCP/UDP/ICMP��Ĭ��Ϊ���С�
 -e  --interval <Interval> ÿץ��interval�����������һ��ͳ��ժҪ��
 -n  --endcount  <endcount> ָ��endcount�󣬳�����ץ��endcount���Զ��˳��� ��ָ��
 endcount����ͣץ��������Ĭ�����á�
 -h    ��ð���
 -?    ��ð���
 �����в����κβ���ʱ���᲻ͣץ����ʹ��(CTRL + C)��������ʱ����������ݡ�

 TODO:
 (1)Some times bcsniffer crashed only with -x.
 (2)ָ���������м�������ʵ��-i
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
 1) Change ipsnatchter to bcsniffer
 2) Fix some Makefile bugs and compile successfully on Ubuntu 12.04 LTS.
 3) Using git for version control.
 5.     Date:    2013-07-17
 Author:  Brant Chen
 Modification:
 1. include\bcsniffer.h:
    1) Align protocol macros to header.
    2) Refactor typedef union _node to _option_value, and add Boolean print_data to it.
    3) Move enum Trur_False to include\common.h
 2. include\common.h
    1) Move enum Trur_False from include\bcsniffer.h to include\common.h
    2) Refactor struct pkg_lit name to struct node name and add s_port/d_port to it.
 3. include\listop.h
    1) Align function statement to lib\data_struct_lib\listop.c.
 4. include\printmsg.h
    1) Align function statement to lib\display_lib\printmsg.c.
 5. lib\common_lib\common.c
    1) Just format.
 6. lib\data_struct_lib\listop.c
    1) Add two new include headers for tcphdr and udphdr.
    2) Add new function: search_and_add_node. It would encapsulate the calls to search_node_in_list, sum_package_amount_in_list and add_node_to_list. Originally, the functionalities were put in src\bcsniffer.c. That's cumbersome.
    3) In order to distinguish port per protocol and stat them, I appended more arguments to almost functions in listop.c and added more code to process different protocols and ports.
 7. lib\display_lib\printmsg.c
    1) Add code for deal with print port.
 8. lib\netop_lib\netop.c
    1) Few small changes.
 9. src\bcsniffer.c
    1) Refactor some variables.
    2) Add code to process command line option -p for port.
    3) Remove code whose responsibilities are set default value for opts, which are redundant.
 10. Remove all #ifdef DEBUG and debug print sentences and format code.

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

#define LOG_FILE            "bcsniffer.log"

static char buf[MAXPACKBUFF];
//��Ϊ������endcount����ʱ�����������
//����֮ǰ�����interval��������������blbΪ1����ʶ�˳�����ʱ�����ٱ�������
static Boolean have_traversal_list_by_interval = FALSE;
static Boolean have_traversal_list_by_endcount = FALSE;
//���趨�ĳ�ʱʱ���ڣ�ץ���İ�����
//�����ʱ��catch_count_in_alarmΪ0����ǿ�����ץ��ʧ�ܵ���Ϣ��
static int catch_count_in_alarm = 0;

struct node *head;
struct node *search;         //(1)��ʶ�ҵ���λ�� (2)���ڿ����½ڵ�ı���
struct node *tail;           //βָ��ʼ��ָ�����һ���ڵ�

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
  if (*option_index != 0 && optarg != NULL ) {
    ret = convert_to_digital(optarg, strlen(optarg), &value);
    if (ret == -1) {       //����ת��Ϊ�Ϸ�����
      printf("\n convert to digital result =%c or %d\n", ret, ret);
      return -1;
    }
  }
  else if (*option_index == 3 && optarg == NULL ) { // This is for -x, since no value request, so optarg should NULL
    opts[3].status = TRUE;
    opts[3].rightopt.print_data = TRUE;
    return 0;
  }

  //�Դ���Ĳ������и�ֵ
  //ͬʱ:(2)���������ͬ�����ѡ���Գ�ѡ��Ͷ�ѡ��ķ�ʽͬʱ����,
  //������:�������ݽṹ�е�statusԪ��.
  //��ʵ�����ڱ�����ÿ��������Ҫ����ֵ������˵������(1)�Ѿ�������(2)��ҪԤ�������
  //ֻ�е������Ĳ���ֵ��Ҫ�������֣���������-����--����ʱ���ڶ������ʾ����������
  str_to_upper(optarg); // This is just for string value. Like -p tcp.
  switch (*option_index) {
  case 0:
    if (FALSE == opts[0].status) {
      if (!strncmp("TCP", optarg, 3)) {
        opts[0].rightopt.protocol = TCP;
      }
      else if (!strncmp("UDP", optarg, 3)) {
        opts[0].rightopt.protocol = UDP;
      }
      else if (!strncmp("ICMP", optarg, 4)) {
        opts[0].rightopt.protocol = ICMP;
      }
      else if (!strncmp("ALLPROTOCOL", optarg, 20)) {
        opts[0].rightopt.protocol = ALLPROTOCOL;
      }
      else {
        return -1;
      }
    }
    else {
      printf("protocol: maybe the long opt and short opt appearence both\n");
      return -1;
    }
    break;
  case 1:
    if (FALSE == opts[1].status) {
      opts[1].rightopt.interval = value;    }
    else {
      printf("interval: maybe the long opt and short opt appearance both\n");
      return -1;
    }
    break;
  case 2:
    if (FALSE == opts[2].status) {
      opts[2].rightopt.endcount = value;
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
  //���ò�����Ĭ��ֵ����ʱstatus��False���Ժ���и�ֵ�󣬾���Ҫ����ΪTrue
  opts[0].rightopt.protocol = DEFAULTPROTO_ALL;
  opts[0].status = FALSE;
  opts[1].rightopt.interval = 10;
  opts[1].status = FALSE;
  opts[2].rightopt.endcount = 0;
  opts[2].status = FALSE;
  opts[3].rightopt.print_data = FALSE; //Don't print the data in package by default
  opts[3].status = FALSE;

  opterr = 0; //ʹϵͳ���Զ���ӡ�����������Ϣ
  optind = 0;

  /*ÿ��������Ҫ�����ھ��췵��*/
  if (argc == 1) {
    *pNoopt = TRUE;
    opts[0].status = opts[1].status = opts[2].status = opts[3].status = TRUE;

    return 0;
  }

  //��Ȼgetopt_longҪ������ÿ�������󷵻�-1��ѭ���ִ�����-1��������԰�ȫ�˳�
  //���������ǻ���Ϊ���Է���һ������loopcount����ѭ���Ĵ�����ͬʱΪ���ж��Ƿ񡣡���
  while (opt_loop_count < argc - 1) {

    static struct option long_options[] = { { "protocol", 1, 0, 0 }, {
        "interval", 1, 0, 0 }, { "count", 1, 0, 0 }, { "display", 0, 0, 0 }, {
        0, 0, 0, 0 } };
    c = getopt_long(argc, argv, "p:e:n:x?h", long_options, &option_index);

    //�����жϲ�ƥ��ĳ�ѡ����в�ƥ��ĳ�ѡ��ʱ��option_indexΪ-1��
    //���ǵ�Ϊƥ���ƥ��Ķ�ѡ��ʱ��option_index����-1������Ҫ�����ж��Ƿ�ƥ���ѡ��
    //����ǲ�ƥ��Ķ�ѡ�getopt_long���أ�
    if (option_index == -1 && c == '?') {
      show_usage();
      exit(1);
    }

    switch (c) {
    case -1:
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
      //�жϲ���Я����ֵ�Ƿ�Ϸ�����ֵ
      ret = set_value_from_cmd(optarg, &option_index, opts);
      if (ret) {
        show_usage();
        exit(1);
      }
      break;
    case 'p':
      option_index = 0; //����Ҫ������ֵ����Ϊʶ��Ϊ��ѡ��Ļ���option_index��-1
      ret = set_value_from_cmd(optarg, &option_index, opts);
      if (ret) {
        show_usage();
        exit(1);
      }
      break;
    case 'e':
      option_index = 1;
      ret = set_value_from_cmd(optarg, &option_index, opts);
      if (ret) {
        show_usage();
        exit(1);
      }
      break;
    case 'n':
      option_index = 2;
      ret = set_value_from_cmd(optarg, &option_index, opts);
      if (ret) {
        show_usage();
        exit(1);
      }
      break;
    case 'x':
      option_index = 3;
      ret = set_value_from_cmd(optarg, &option_index, opts);
      if (ret) {
        show_usage();
        exit(1);
      }
      break;
    case '?': /*ÿ��������Ҫ*/        //���������ƥ��Ķ�ѡ����ߡ�����
    case 'h': /*ÿ��������Ҫ*/
    default: /*ÿ��������Ҫ*/
      show_usage();
      exit(1);
    }
    opt_loop_count++;
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
  if (!have_traversal_list_by_interval && !have_traversal_list_by_endcount) {
    traversal_list(head, search);
  }
  exit(0);
}

//���������Ϣ
void print_tcp_in_detail(const int len, struct ip *p1, struct iphdr *p2,
    struct tcphdr *p3) {
  printf("r:%d\n", len);
  printf("ether_header:%ld\n", (long int) sizeof(struct ether_header));
  printf("ethhdr:%ld\n", (long int) sizeof(struct ethhdr));
  printf("ip->ip_len:%d\n", p1->ip_len);
  printf("ntohs(ip->ip_len):%d\n", ntohs(p1->ip_len));
  printf("iph->tot_len:%d\n", p2->tot_len);
  printf("ntohs(piph->tot_len):%d\n", ntohs(p2->tot_len));
  printf("ptcp->doff:%d\n", p3->doff);
}

//���������Ϣ
void print_udp_in_detail(const int len, struct ip *p1, struct iphdr *p2) {
  printf("r:%d\n", len);
  printf("ether_header:%ld\n", (long int) sizeof(struct ether_header));
  printf("ethhdr:%ld\n", (long int) sizeof(struct ethhdr));
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

  printf("protocol:%d    \n", opts[0].rightopt.protocol);
  printf("interval:%ld    \n", opts[1].rightopt.interval);
  printf("count:%ld\n", opts[2].rightopt.endcount);
  printf("display:%d\n", opts[3].rightopt.print_data);
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
        (struct sockaddr *) &addr, &len)) <= 0) {
      //Ϊ�����'.',��print_msg_while_catch_nothing�е�else��catch_count_in_alarm
      //��0��˫�ر���.
      catch_count_in_alarm = 0;
      continue;
    }

    ptemp = buf;                            //��ʼ��ָ��ptemp
    peth = (struct ether_header *) ptemp;
    ptype = ntohs(peth->ether_type);        //����̫��֡���Э������

    //Only print ARP/RARP if ALLPROTOCOL | DEFAULTPROTO_ALL
    if (((ptype == ETHERTYPE_ARP) || (ptype == ETHERTYPE_REVARP))
        && ((opts[0].rightopt.protocol == ALLPROTOCOL)
            || (opts[0].rightopt.protocol == DEFAULTPROTO_ALL))) {
      catch_count_in_alarm++;
      parph = (struct ether_arp *) (ptemp + sizeof(struct ether_header));
      printf("\n[%3ld] ", ++count);
      print_time();
      printf("Package total length:[%d Byte] ", r);
      print_arp_rarp(parph, ptype);
    }
    else if (ptype == ETHERTYPE_IP) {       //�����IP���ݰ�
      ptemp += sizeof(struct ether_header); //ָ�����ether_header�ĳ��ȣ�4�ֽ�
      pip = (struct ip *) ptemp;
      piph = (struct iphdr *) ptemp;        //piphָ��ip���ͷ
      //Print IP header information if not specify protocol from cmd line, like
      //TCP/UDP...
      if (opts[0].rightopt.protocol == ALLPROTOCOL
          || opts[0].rightopt.protocol == DEFAULTPROTO_ALL) {
        catch_count_in_alarm++;
        printf("\n[%3ld] ", ++count);
        print_time();
        printf("Package total length:[%d Byte] ", r);
        printf_ip_header(piph);
      }

      //ihl��IP header length
      //<<2�൱�ڳ���4��ΪʲôptempҪ�Ƶ�ihl*4��λ�ã�
      //ŶҲ�����ˣ���Ϊihl��4bit������Ƕ�����1111����ʮ����15��
      //��ÿ��1����4Byte������IP��ͷ����󳤶���15*4=60�ֽڡ�
      //�μ�http://blog.csdn.net/achejq/article/details/7040687
      ptemp += (piph->ihl << 2);

      //���ݲ�ͬЭ���ж�ָ������
      if (piph->protocol == IPPROTO_TCP
          && (opts[0].rightopt.protocol == TCP
              || opts[0].rightopt.protocol == ALLPROTOCOL
              || opts[0].rightopt.protocol == DEFAULTPROTO_ALL)) {

        ret = search_and_add_node(piph, ptemp, (struct node **) &search,
            (struct node **) &head, (struct node **) &tail, r, IPPROTO_TCP);
        if (ret == -1) {
          printf("[ERR] search_and_add_node failed. Protocol: TCP.\n\n");
          exit(-1);
        }
        if (opts[0].rightopt.protocol == TCP) {
          catch_count_in_alarm++;
          printf("\n[%3ld] ", ++count);
          print_time();
          printf("Package total length:[%d Byte] ", r);
        }
        printf_tcp(ptemp, piph, opts[3].rightopt.print_data);
      }
      else if (piph->protocol == IPPROTO_UDP
          && (opts[0].rightopt.protocol == UDP
              || opts[0].rightopt.protocol == ALLPROTOCOL
              || opts[0].rightopt.protocol == DEFAULTPROTO_ALL)) {
        ret = search_and_add_node(piph, ptemp, (struct node **) &search,
            (struct node **) &head, (struct node **) &tail, r, IPPROTO_UDP);
        if (ret == -1) {
          printf("[ERR] search_and_add_node failed. Protocol: UDP.\n\n");
          exit(-1);
        }
        if (opts[0].rightopt.protocol == UDP) {
          catch_count_in_alarm++;
          printf("\n[%3ld] ", ++count);
          print_time();
          printf("Package total length:[%d Byte] ", r);
        }
        printf_udp(ptemp, piph, opts[3].rightopt.print_data);
      }
      else if (piph->protocol == IPPROTO_ICMP
          && (opts[0].rightopt.protocol == ICMP
              || opts[0].rightopt.protocol == ALLPROTOCOL
              || opts[0].rightopt.protocol == DEFAULTPROTO_ALL)) {
        ret = search_and_add_node(piph, ptemp, (struct node **) &search,
            (struct node **) &head, (struct node **) &tail, r, -1);
        if (ret == -1) {
          printf("[ERR] search_and_add_node failed. Protocol: ICMP.\n\n");
          exit(-1);
        }
        if (opts[0].rightopt.protocol == ICMP) {
          catch_count_in_alarm++;
          printf("\n[%3ld] ", ++count);
          print_time();
          printf("Package total length:[%d Byte] ", r);
        }
        printf("ICMP:%s \n", inet_ntoa(*(struct in_addr*) &(piph->saddr)));
      }
      else if (piph->protocol == IPPROTO_IGMP
          && (opts[0].rightopt.protocol == IGMP
              || opts[0].rightopt.protocol == ALLPROTOCOL
              || opts[0].rightopt.protocol == DEFAULTPROTO_ALL)) {
        ret = search_and_add_node(piph, ptemp, (struct node **) &search,
            (struct node **) &head, (struct node **) &tail, r, -1);
        if (ret == -1) {
          printf("[ERR] search_and_add_node failed. Protocol: IGMP.\n\n");
          exit(-1);
        }
        if (opts[0].rightopt.protocol == IGMP) {
          catch_count_in_alarm++;
          printf("\n[%3ld] ", ++count);
          print_time();
          printf("Package total length:[%d Byte] ", r);
        }
        printf("IGMP \n");
      }
      else if (opts[0].rightopt.protocol == ALLPROTOCOL
          || opts[0].rightopt.protocol == DEFAULTPROTO_ALL) {
        ret = search_and_add_node(piph, ptemp, (struct node **) &search,
            (struct node **) &head, (struct node **) &tail, r, -1);
        if (ret == -1) {
          printf("[ERR] search_and_add_node failed. Protocol: Unknown.\n\n");
          exit(-1);
        }
        printf("Unknown protocol %d\n", piph->protocol);
      }                   //end analyse, we can't go to next else.
//      else {
//
//      }
    } //else if (ptype == ETHERTYPE_IP) {       //�����IP���ݰ�
    else if (opts[0].rightopt.protocol == ALLPROTOCOL
        || opts[0].rightopt.protocol == DEFAULTPROTO_ALL) {
      printf("\nUnknown package,protocol type:%d\n", ptype);
    }

    //�ж�interval����
    if ((opts[1].rightopt.interval != 0)
        && (count % opts[1].rightopt.interval == 0)) {
      // Only traversal_list if we caught package (that is count !=0) and
      // the package match the protocol we specified.
      if (count != 0
          && ((piph->protocol == (opts[0].rightopt.protocol)
              || (opts[0].rightopt.protocol == ALLPROTOCOL)
              || (opts[0].rightopt.protocol == DEFAULTPROTO_ALL)))) {
        traversal_list(head, search);
        have_traversal_list_by_interval = TRUE;
      }
    }
    //�ж�endcount����
    if ((opts[2].rightopt.endcount > 0)
        && (count == opts[2].rightopt.endcount)) {
      if (!have_traversal_list_by_interval) {
        traversal_list(head, search);
        have_traversal_list_by_endcount = TRUE;
        exit(0);
      }
      else {
        have_traversal_list_by_endcount = TRUE;
        //If go to here, means we have run traversal_list, now just need exit.
        exit(0);
      }
    }
    //sleep(1);
    have_traversal_list_by_interval = FALSE;
    have_traversal_list_by_endcount = FALSE;
  }                   //end for
  printf("\n");
}

