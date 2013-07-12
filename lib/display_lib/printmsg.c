/***********************************************************
 Copyright (C), 2005, Chen Chao
 File name:      printmsg.c
 Author:  Chen Chao      Version: 1.0    Date: 2005.10
 Description:    bcsniffer程序的输出操作函数实现文件
 Others:
 Function List:
 History:
 1. Date:2006-2-13
 Author:cc
 Modification:
 (1)在函数printf_tcp中省略对TCP携带的数据长度的计算和输出,并没有什么意义
 printf_ip中去除对ip层数据长度pip->tot_len的显示,用户应该只关心总的大小
 2. Date:2006-2-14
 Author:cc
 Modification:
 (1)在函数print_time中将时间输出格式完善为00:00:00,方法是使用%02,0是flag标记,当参数不足2时,用0填充
 (2)增加disp_hex函数
 **************************************************************/

#ifdef _DEBUG
#undef _DEBUG
#endif

#include <stdlib.h>                  //包含UNIX的类型定义等，如u_char/u_int32_t
#include <stdio.h>
#include <stdio.h>
#include <time.h>
#include <ctype.h>                   //定义isprint函数
#include <netinet/ip.h>              //定义struct iphdr等结构
#include <netinet/tcp.h>             //定义struct tcphdr等结构
#include <netinet/udp.h>             //定义struct udphdr等结构  
#include <arpa/inet.h>  
#include <netinet/if_ether.h>        //定义struct ether_arp等结构
#include "../../include/common.h"
#include "../../include/netop.h"
#include "../../include/printmsg.h"


//输出MAC地址函数
void print_mac(u_char *sha) {
  int i;
  for (i = 0; i < 5; ++i)
    printf("%02x:", sha[i]);
  printf("%02x", sha[i]);
}

//输出IP地址的函数
void print_ipaddr(u_char *ipadd) {
  int i;
  for (i = 0; i < 3; ++i)
    printf("%d.", ipadd[i]);
  printf("%d", ipadd[i]);
}

//打印抓包时间
void print_time() {
  //localtime将tt指向的time_t结构的信息换成真实世界中的日期时间表示
  //结果由tm结构的指针ptm返回
  char *wday[] = { "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" };
  time_t tt;
  struct tm *ptm;
  time(&tt);
  ptm = localtime(&tt);
  printf("Time:[%s,%02d:%02d:%02d] ", wday[ptm->tm_wday], ptm->tm_hour, ptm->tm_min,
      ptm->tm_sec);
}

//打印arp或rarp信息
void print_arp_rarp(struct ether_arp *p, unsigned int flag) {
  switch (flag) {
  case ETHERTYPE_ARP:
    printf("ARP ");
    break;
  case ETHERTYPE_REVARP:
    printf("RARP ");
    break;
  default:
    printf("Unkown package!\n");
    return;
  }
  print_mac((u_char *) &(p->arp_sha));
  printf("(");
  print_ipaddr((u_char *) &(p->arp_spa));
  printf(")->");
  print_mac((u_char *) &(p->arp_tha));
  printf("(");
  print_ipaddr((u_char *) &(p->arp_tpa));
  printf(")\n");
}

//分析tos服务类型
void printf_ip(struct iphdr *pip) {
  printf("IP ");    //为了和Time显示在同一行,更醒目
  printf("\nIP header:%dB ver:%d ttl:%d ", pip->ihl, pip->version, pip->ttl);
  switch (pip->tos) {
  case MINDELAY:
    printf("Minidelay ");
    break;
  case MAXTHROUGHPUT:
    printf("Max-Throughput ");
    break;
  case HISECURITY:
    printf("Highest-security ");
    break;
  case MINCOST:
    printf("Minicost ");
    break;
  default:
#ifdef _DEBUG
    //printf("None bit of the tos set!\n");
#endif

    break;
  }
  //从IP协议头中分析协议名字
  get_protocol_name(pip->protocol);
}

//打印TCP信息
void printf_tcp(char *p, struct iphdr *pip, struct tcphdr *pt, u_char *d) {
  pt = (struct tcphdr *) p;       //ptcp指向tcp头部

  /* inet_ntoa--------将网络二进制的数组转换成网络地址 */
  printf("\n[%15s]:[%6d] -> ", inet_ntoa(*(struct in_addr*) &(pip->saddr)),
      ntohs(pt->source));
  printf("[%15s]:[%6d] ", inet_ntoa(*(struct in_addr*) &(pip->daddr)),
      ntohs(pt->dest));

  printf("seq: %10d ", pt->seq);
  printf("ack_seq: %10d ", pt->ack_seq);
  printf("\n");

  d = (u_char *) (p + 4 * pt->doff);
  //TCP携带的数据长度,不删除这行的原因使为了以后不用查就知道如何计算TCP的数据长度
  //printf("%dB\n\n",ntohs(pip->tot_len)-4*pip->ihl-4*pt->doff);
}

//打印UDP信息
void printf_udp(char *p, struct iphdr *pip, struct udphdr *pu, u_char *d) {
  pu = (struct udphdr *) p;        //ptcp指向udp头部

  printf("\n[15%s]:[%6d] -> ", inet_ntoa(*(struct in_addr*) &(pip->saddr)),
      ntohs(pu->source));
  printf("[%15s]:[%6d]\n", inet_ntoa(*(struct in_addr*) &(pip->daddr)),
      ntohs(pu->dest));

  d = (u_char *) (p + 8);
  disp_hex("UDP: ", d, ntohs(pu->len));
  printf("\n");
}

