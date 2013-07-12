/***********************************************************
 Copyright (C), 2005, Chen Chao (brantchen2008@gmail.com)
 File name:      listop.c
 Author:  Chen Chao      Version: 1.0    Date: 2005.10
 Description:    bcsniffer程序的链表操作函数实现文件
 Others:
 Function List:
 History:
 1. Date:2006-2-14
 Author: brant
 Modification:
 (1) 修改BUG:函数searchT的参数 struct pkg_list *search改为struct pkg_list **search,
 这样才能修改search的位置,从而使统计正确.
 2. Date:2013-7-12
 Author: brant
 Modification:
 (1) 遇到见奇怪的事，使用%15s依次打印s->sip和s->dip，如果sip比dip长，那么就正确，格
 式就 是整齐的，如下：
 [ 10.200.108.195]
 [   172.29.34.64]
 如果反过来，就会出现下面的情况：
 [ 172.29.34.64]
 [ 10.200.108.195]
为了fix，本来准备自己打印差的两个空格，但是新增代码进行gdb时，发现了root cause，就是
在aa_node_to_list时没有进行memset！搞定！
**************************************************************/

#ifdef _DEBUG
#undef _DEBUG
#endif

#include <stdlib.h>            //包含UNIX的类型定义等，如u_char/u_int32_t
#include <stdio.h>
#include <string.h>
#include <sys/socket.h> 
#include <arpa/inet.h> 
#include <netinet/in.h>        //上述3个头文件定义了inet_aton等函数
#include <netinet/ip.h>        //定义struct iphdr等结构
#include "../../include/common.h"
#include "../../include/listop.h"

//查找IP是否已存在
//遍历链表，返回0表示找到，search指针指向新位置；没有则返回－1
int search_ip_in_list(struct iphdr *piph, struct pkg_list **search, struct pkg_list *h) {
  //查找
  for (*search = h; *search != NULL ; *search = (*search)->next) {
    if (!strcmp(inet_ntoa(*(struct in_addr*) &(piph->saddr)), (*search)->sip)
        && !strcmp(inet_ntoa(*(struct in_addr*) &(piph->daddr)),
            (*search)->dip))  //如果相等
            {
#ifdef _DEBUG
      printf("searched!\nsip:%s dip:%s\n", (*search)->sip, (*search)->dip);
#endif
      return 0; //找到并返回
    }
    else
      continue;
  }

#ifdef _DEBUG
  printf("Not searched!\n");
#endif

  return -1;
}

//添加整个新的元素进入statTable
//成功返回0；否则恢复指针，返回-1,
int add_node_to_list(struct iphdr *piph, int byteslen, struct pkg_list *s) {
  //依次把新的元素赋值
#ifdef _DEBUG
  //printf("strlen(inet_ntoa(*(struct in_addr*)&(piph->saddr)))::::%d\n", strlen(inet_ntoa(*(struct in_addr*)&(piph->saddr))));
  //printf("strlen(inet_ntoa(*(struct in_addr*)&(piph->daddr)))::::%d\n", strlen(inet_ntoa(*(struct in_addr*)&(piph->daddr))));
#endif

  if (s != NULL ) {
    memset(s->sip, 0, 16);
    memset(s->dip, 0, 16);
    strncpy(s->sip, inet_ntoa(*(struct in_addr*) &(piph->saddr)),
        strlen(inet_ntoa(*(struct in_addr*) &(piph->saddr))));
    strncpy(s->dip, inet_ntoa(*(struct in_addr*) &(piph->daddr)),
        strlen(inet_ntoa(*(struct in_addr*) &(piph->daddr))));

#ifdef _DEBUG
    printf("In add \n");
    printf("strlen:%d\n", strlen(inet_ntoa(*(struct in_addr*) &(piph->saddr))));
    printf("show s->sip:[%-25s]\n", s->sip);
    printf("show inet_ntoa(*(struct in_addr*)&(piph->saddr)):%s\n", inet_ntoa(*(struct in_addr*)&(piph->saddr)));

    printf("strlen:%d\n", strlen(inet_ntoa(*(struct in_addr*) &(piph->daddr))));
    printf("show s->dip:[%-25s]\n", s->dip);
    printf("show inet_ntoa(*(struct in_addr*)&(piph->daddr)):%s\n", inet_ntoa(*(struct in_addr*)&(piph->daddr)));
#endif
    s->bcount = byteslen;
    s->packcount = 1;
    s->next = NULL;           //新加入的节点的next指针指向尾指针，为空

#ifdef _DEBUG
    printf("add new node succ\n");
#endif

    return 0;
  }
  else {
#ifdef _DEBUG
    printf("add new node fail\n");
#endif
    return -1;
  }
}

//traversal_list by search pointer
void traversal_list(struct pkg_list *h, struct pkg_list *s) {

  if (!s) {
    printf("\nNothing catched :(\n");
	exit(1);
  }
  s = h;

  printf("\n");
  printf(""
"============================ Statistics  =======================================\n\n"
        );
  while (s) {
    printf("[%15s] -> [%15s] [%d] package Total:[%6d] Byte\n", s->sip, s->dip,
        s->packcount, s->bcount);
    s = s->next;
  }
  printf("\n");
  printf(""
"=========================== End Statistics  ====================================\n"
          );
}

//累加字节总量和包总量,BP表示byte和package
//成功返回0；否则恢复计数，返回-1
int sum_element_in_list(int byteslen, struct pkg_list *search) {
  if (search != NULL ) {
#ifdef _DEBUG
    printf("byteslen:%d sip:%s dip:%s\n", byteslen, search->sip, search->dip);
#endif

    search->bcount += byteslen;
    search->packcount++;

    return 0;
  }
  else
    return -1;
}

