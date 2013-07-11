/*******************************************************************************
 Copyright (C), 2007-2010, 陈超(CC).
 Program Name:        bcsniffer
 Program Desc:        bcsniffer程序的主文件
 File name:           bcsniffer.c
 Author:              陈超
 Version:             1.0.2
 Date:                2007年06月21日
 Description:         见[Program Desc]
 Others:
 1.  用法简介
 /bcsniffer [选项]  [值]
 <>表示该参数必须指定值
 <>中用|隔开的值，表示参数的可使用值
 -i  --interface <interface name>  指定要监听的网卡名称进行抓包。
 -p  --protocol  <TCP | UDP | ICMP | DEFAULTPROTO_ALL>  指定协议，TCP/UDP/ICMP。默认为所有。
 -s  --stat 指定stat后，程序在抓包时会根据源地址、目的地址进行统计，并在结束时输出每对源地址、目的地址的包数和字节。
 -n  --count  <count> 指定count后，程序在抓包count后自动退出； 不指定count，采用默认，不停抓包。
 -h    获得帮助
 -?    获得帮助
 命令行不带任何参数时，会不停抓包，使用(CTRL + C)结束程序时输出链表内容。

 TODO-List:
 (1)指定网卡进行监听
 (2)把链表按协议号分类,再根据地址进行统计.
 现在的状况是,如果是ICMP之类协议只有一个地址的,没有统计流量
 File List:      bcsniffer.c       bcsniffer.h
 linkedop.c        linkedop.h
 netop.c           netop.h
 printmsg.c        printmsg.h
 common.c          common.h
 Makefile

 Function List:    参见头文件声明

 History:
 1.     Date:    2006-02-10
 Author:  陈超
 Modification:
 完成对命令行参数完整性的判断,实现:
 1)命令行参数识别与顺序无关,判断无误,并基本形成规范,以后的程序可以借鉴
 2)定义好参数的数据结构
 3)命令行指定协议参数与大小写无关
 2.     Date:    2006-02-13
 Author:  陈超
 Modification:
 1)修正当命令行没有某参数值时,程序没有对该参数赋值的BUG
 2)增加参数判断完后,将所有参数的值输出的语句
 3)使用局部变量代替全局变量opts
 4)关于头文件会引用不当会引起多重引用而无法通过编译的问题解决:
 把所有对文件的引用都放在实现文件中即可.
 5)要防止出现：--protocol 1 -p 1即两个合法参数，但是相同含义，
 一长一短的情况----函数JudgeArgument借助结构体OPTION实现
 3.     Date:    2008-10-01
 Author:  陈超
 Modification:
 1)增加-i参数，修改原来的-i参数为-s，修改注释；并未任何代码；
 2)整理目录结构，将除ipsnatcher.c的.c文件都移动到libs下的相应目录；
 ipsnatcher.c移动到src目录

 *******************************************************************************/

#include <stdlib.h>                    //包含UNIX的类型定义等，如u_char/u_int32_t
#include <stdio.h>
#include <unistd.h>  
#include <signal.h>
#include <getopt.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>                //上述两个头文件为函数socket准备
#include <ctype.h>                     //包含isdigit函数
#include <netinet/ip.h>                //定义struct iphdr等结构
#include <netinet/tcp.h>               //定义struct tcphdr等结构
#include <netinet/udp.h>               //定义struct udphdr等结构  
#include <arpa/inet.h>  
#include <netinet/if_ether.h>          //定义struct ether_arp等结构
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
static int blb = 0;                     //因为程序由endcount结束时，会遍历链表，
//而在之前如果由interval遍历了链表，则置blb为1，标识退出程序时不用再遍历链表
static int iCatchCountInAlarm = 0;       //在设定的超时时间内，抓到的包数。
//如果超时后iCatchCountInAlarm为0，则强制输出抓包失败的信息。

struct statTable *head;
struct statTable *search;              //(1)标识找到的位置 (2)用于开辟新节点的变量
struct statTable *tail;                //尾指针始终指向最后一个节点

OPT_VALUE_STATUS opts[3];                 //有多少个需要赋值的参数就有多少个opts

//判断携带的参数是否为合法的数字
//返回：成功    0    失败        -1
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

//转换字符串为大写
//返回；成功：0   失败：-1；
int StrtoUpper(char * str) {
  while (*str != '\0') {
    *str = toupper(*str);
    str++;
  }
  return 0;
}

//判断参数携带的值是否合法,并对全局变量opts进行赋值
//返回；成功：0   失败：-1；
int SetValueFromCmd(char *optarg, int *option_index, OPT_VALUE_STATUS opts[]) {
  //把所有ShowUsage放在GetCommondLine中
  int ret = -1;
  long argumentvalue = -1;  //参数携带的值

  //(1)要根据携带的参数进行合法检验，避免出现./ipsnatcher --protocol --interval的情况！！！
  //如：如果参数需要是数字，则遍历参数，判断是否在字符0~9的范围内，能否转换为合法数字；否则非法
  //option_index为0时,不进行数字验证,因为是协议名称字符串
  if (*option_index != 0) {
    /*#ifdef _DEBUG
     printf("argument:%d\n", atoi(optarg));
     #endif*/

    ret = ConvertoDigital(optarg, strlen(optarg), &argumentvalue);
    if (ret == -1)        //不能转化为合法数字
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

  //对传入的参数进行赋值
  //同时:(2)避免出现相同意义的选项以长选项和短选项的方式同时出现,处理方法:设置数据结构中的status元素.
  //其实，对于本程序每个参数都要带数值参数来说，步骤(1)已经避免了(2)需要预防的情况
  //只有当所跟的参数值不要求是数字，而可能与-或者--混淆时，(2)才显示出(2)的需要
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

  //(3)还需要处理这种情况:
  //比如一个程序接受两种合法的参数:
  // 1. ./progname -D 或者./progname -d 或者./progname --delrecord
  // 2. ./progname -A 12 或者./progname -a 123 或者./progname --addrecord  123

  //(4)处理短字符与长字符的第一个字母相同，会把-delrecor认为是-d(-D)的情况

  return 0;
}

//获得参数
//返回：成功    0        失败        -1
int GetCommandLine(int argc, char *argv[], BOOLEAN *pNoopt) {
  int c;
  int optloopcount = 0;  //控制总循环的次数
  int option_index = -1;
  int ret = -1;

  //不能把初始化的代码放在全局:(会报警
  //本来想把下述6行
  //设置参数的默认值
  opts[0].rightopt.protocol = DEFAULTPROTO_ALL;
  opts[0].status = FALSE;
  opts[1].rightopt.interval = 10;
  opts[1].status = FALSE;
  opts[2].rightopt.endcount = 100;
  opts[2].status = FALSE;

  opterr = 0; //使系统不自动打印参数错误的信息
  optind = 0;

  /*每个程序都需要*/
  if (argc == 1) {
    *pNoopt = TRUE;
    //对所有参数赋默认值
    opts[0].rightopt.protocol = DEFAULTPROTO_ALL;
    opts[0].status = TRUE;
    opts[1].rightopt.interval = 10;
    opts[1].status = TRUE;
    opts[2].rightopt.endcount = 0; //不断抓包
    opts[2].status = TRUE;

    return 0;
  }

  while (optloopcount < argc - 1) { //虽然getopt_long要查找完每个参数后返回-1，循环又处理了-1的情况可以安全退出
                                    //函数，但是还是为了以防万一，用了loopcount控制循环的次数；同时为了判断是否。。。

    static struct option long_options[] = { { "protocol", 1, 0, 0 }, {
        "interval", 1, 0, 0 }, { "count", 1, 0, 0 }, { 0, 0, 0, 0 } };
    c = getopt_long(argc, argv, "p:e:n:?h", long_options, &option_index);

    if (option_index == -1 && c == '?') //用于判断不匹配的长选项。当有不匹配的长选项时，option_index为-1，
                                        //但是当为匹配或不匹配的短选项时，option_index仍是-1。所以要额外判断是否匹配短选项
                                        //如果是不匹配的短选项，getopt_long返回？
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

      /*每个程序都需要*/
      if (optind == argc)  //如果是判断完所有参数，则跳出case,此时已不能满足while的条件,
                           //会执行后面的代码.不急于返回主函数main
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

      //判断参数携带的值是否合法
      ret = SetValueFromCmd(optarg, &option_index, opts);
      if (ret) {
        ShowUsage();
        return -1;
      }

      /*#ifdef DEBUG
       if (optarg)            //需要放在合法判断之后
       printf (" with arg %s", optarg);
       printf ("\n");
       #endif*/

      break;
    case 'p':
      /*#ifdef DEBUG
       printf ("option p--protocol with value ");
       #endif*/

      option_index = 0; //必须要主动赋值，因为识别为短选项的话，option_index是-1
      ret = SetValueFromCmd(optarg, &option_index, opts);
      if (ret) {
        ShowUsage();
        return -1;
      }

      /*if(optarg)            //需要放在合法判断之后
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

      /*if (optarg)            //需要放在合法判断之后
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

      /*if (optarg)            //需要放在合法判断之后
       printf ("%s", optarg);
       printf ("\n");*/

      break;
    case '?': /*每个程序都需要*/        //如果遇到不匹配的短选项或者‘？’
    case 'h': /*每个程序都需要*/
    default: /*每个程序都需要*/
      /*#ifdef DEBUG
       printf("? h else *** \n");
       #endif*/

      ShowUsage();
      return -1; //注意必须返回
    }
    optloopcount++;
  }

  //将命令行没有指定的参数进行赋默认值
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

//超时后，没有抓到包时输出的信息。
void Print_CatchNull(int signo) {
  if (iCatchCountInAlarm == 0) {
    system("echo -n .");
  }
  else {
    iCatchCountInAlarm = 0;
  }
}

//结束函数，调用遍历链表函数输出
void Catch_Ctrl_C(int signo) {
  if (!blb) {
    bianli(head, search);
  }
  exit(0);
}

//输出调试信息
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

//输出调试信息
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
  struct ether_header *peth;    //以太网帧报头指针
  struct ether_arp *parph;      //ARP报头
  struct ip *pip;
  struct iphdr *piph;           //IP头结构
  struct tcphdr *ptcp;          //TCP头结构
  struct udphdr *pudp;          //UDP头结构

  BOOLEAN noopt = FALSE;          //记录程序执行是否带有命令行参数,没有则按照默认参数配置执行

  int proto = DEFAULTPROTO_ALL;   //在主函数中使用局部变量代替全局变量opts,
                                  //一是为了书写方便,
                                  //二是避免全局变量的使用,虽然opts在赋值后应该不会再有代码修改它,但是为了以防万一.
  unsigned long interval = 10;    //记录输出链表内容的次数间隔
  unsigned long count = 0;        //记录抓包的次数

  int sock;                     //建立socket连接
  int r;                        //reve的返回值
  int len;                      //sizeof(addr)，取地址用于recv中
  char *ptemp;                  //重要的指针！
  unsigned int ptype;           //判断层次协议类型变量（如ARP或者IP）
  u_char * data;                //数据包数据指针

  struct sigaction actInterrupt;
  struct sigaction actAlarm;

  head = tail = search = NULL;  //初始化链表指针
  memset(buf, 0, MAXPACKBUFF);

  //判断参数合法性
  GetCommandLine(argc, argv, &noopt);

  //输出参数分析的最终结果
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

  //设置中断信号的信号处理
  actInterrupt.sa_handler = Catch_Ctrl_C;
  sigemptyset(&actInterrupt.sa_mask);
  actInterrupt.sa_flags = 0;
  sigaddset(&actInterrupt.sa_mask, SIGINT);
  //设置无包抓到时的信号处理
  actAlarm.sa_handler = Print_CatchNull;
  sigemptyset(&actAlarm.sa_mask);
  actAlarm.sa_flags = 0;
  sigaddset(&actAlarm.sa_mask, SIGALRM);

  if ((sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1) //建立原始套接字socket
      {
    showErr("socket", 1);
  }

  //设置网卡eth0为混杂模式,并执行system查看结果
  set_promisc("eth0", sock);        //eth0为网卡名称
  system("ifconfig");

  for (;;) {
    alarm(1);
    //每次循环建立信号处理
    if (sigaction(SIGALRM, &actAlarm, NULL ) < 0) {
      printf("signal SIGIALRM error!\n");
      exit(1);
    }

    if (sigaction(SIGINT, &actInterrupt, NULL ) < 0) {
      printf("signal SIGINT error!\n");
      exit(1);
    }

    //输出语句判断是否抓到包
    if ((r = recvfrom(sock, (char *) buf, sizeof(buf), 0,
        (struct sockaddr *) &addr, &len)) > 0) {
      iCatchCountInAlarm++;
    }
    else {
      //???有问题???(1)如果下面的printf输出'.',则程序运行时不会打印出'.',只有当CTRL+C后才会打印出来
      //???有问题???(2)记得没有使用超时控制时,recvfrom会一直阻塞,也就是不会执行下面两行代码;但使用后,它会执行!
      //???有问题???(3)使用sync没有用!也不会打印出字符'.'
      //printf(".");
      //sync();
      //printf("\n");
      iCatchCountInAlarm = 0; //为了输出'.',和Print_CatchNull中的else把iCatchCountInAlarm置0是双重保险.
      continue;
    }

    printf("\n%ld ", ++count);
    print_time();
    printf("%dB ", r);

    ptemp = buf;             //初始化指针ptemp
    peth = (struct ether_header *) ptemp;
    ptype = ntohs(peth->ether_type);                   //从以太网帧获得协议名称

    if ((ptype == ETHERTYPE_ARP) || (ptype == ETHERTYPE_REVARP))    //判断是什么包
        {
      parph = (struct ether_arp *) (ptemp + sizeof(struct ether_header));
      print_arp_rarp(parph, ptype);
    }
    else if (ptype == ETHERTYPE_IP)                      //如果是IP数据包
    {
      ptemp += sizeof(struct ether_header);        //指针后移ether_header的长度
      pip = (struct ip *) ptemp;
      piph = (struct iphdr *) ptemp;                 //piph指向ip层的头
      //打印ip头信息
      printf_ip(piph);
      printf("checksum %d ", checksumip((u_int16_t *) pip, 4 * pip->ip_hl));

      //id， 识别IP数据报的编号，标识字段唯一地标识主机发送的每一份
      //数据报。通常每发送一份报文它的值就会加1
      //frag_off;     3/16 1位为0表示有碎块，2位为0表示是最后的碎块，3位为1表示接收中
      //13/8 分片在原分组中的位置
      //以上两个值未作分析，至此分析完IP头的字段

      /*#ifdef _DEBUG
       printf("Before add!\n");
       printf("show inet_ntoa(*(struct in_addr*)&(piph->saddr)):%s\n", inet_ntoa(*(struct in_addr*)&(piph->saddr)));
       printf("show inet_ntoa(*(struct in_addr*)&(piph->daddr)):%s\n", inet_ntoa(*(struct in_addr*)&(piph->daddr)));
       #endif  */

      //对statTable结构表进行操作
      //首先进行查找，传递头指针
      //查找函数中判断了链表是否为空，为空肯定没找到，返回-1
      if (!searchT(piph, (struct statTable **) &search, head))     //找到返回0
          {
#ifdef _DEBUG
        printf("search->sip:%s, search->dip:%s\n", search->sip, search->dip);
#endif
        progreBP(r, search);       //累加
      }
      else {
        if ((search = malloc(sizeof(struct statTable))) < 0) {
          printf("Out of memory!\n");
          continue;
        }
        addfulT(piph, r, search);  //添加节点
        //移动指针
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

      ptemp += (piph->ihl << 2);               //移动ptemp到iph结构后

      switch (piph->protocol)                   //根据不同协议判断指针类型
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

    //判断interval参数
    if ((opts[1].rightopt.interval != 0)
        && (count % opts[1].rightopt.interval == 0)) {
      bianli(head, search);
      blb = 1;
    }
    //判断endcount参数
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

