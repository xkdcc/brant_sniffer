/***********************************************************
 Copyright (C), 2005, Chen Chao
 File name:      linkedlistop.c
 Author:  Chen Chao      Version: 1.0    Date: 2005.10
 Description:    ipsnatcher程序的链表操作函数实现文件
 Others:
 Function List:
 History:
 1. Date:2006-2-14
 Author:cc
 Modification:
 (1)修改BUG:函数searchT的参数 struct statTable *search改为struct statTable **search,
 这样才能修改search的位置,从而使统计正确.
 2. ...
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
int searchT(struct iphdr *piph, struct statTable **search, struct statTable *h) {
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
int addfulT(struct iphdr *piph, int byteslen, struct statTable *s) {
  //依次把新的元素赋值
#ifdef _DEBUG
  //printf("strlen(inet_ntoa(*(struct in_addr*)&(piph->saddr)))::::%d\n", strlen(inet_ntoa(*(struct in_addr*)&(piph->saddr))));
  //printf("strlen(inet_ntoa(*(struct in_addr*)&(piph->daddr)))::::%d\n", strlen(inet_ntoa(*(struct in_addr*)&(piph->daddr))));
#endif

  if (s != NULL ) {
    strncpy(s->sip, inet_ntoa(*(struct in_addr*) &(piph->saddr)),
        strlen(inet_ntoa(*(struct in_addr*) &(piph->saddr))));
    strncpy(s->dip, inet_ntoa(*(struct in_addr*) &(piph->daddr)),
        strlen(inet_ntoa(*(struct in_addr*) &(piph->daddr))));

#ifdef _DEBUG
    printf("In add \n");
    printf("show s->sip:%s\n", s->sip);
    printf("show inet_ntoa(*(struct in_addr*)&(piph->saddr)):%s\n", inet_ntoa(*(struct in_addr*)&(piph->saddr)));
    printf("show s->dip:%s\n", s->dip);
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

//用search指针遍历链表
void bianli(struct statTable *h, struct statTable *s) {
  s = h;

  printf("\n");
  while (s) {
    printf("%s->%s %dpackage Total:%dB\n", s->sip, s->dip, s->packcount,
        s->bcount);
    s = s->next;
  }
  printf("\n");
}

//累加字节总量和包总量,BP表示byte和package
//成功返回0；否则恢复计数，返回-1
int progreBP(int byteslen, struct statTable *search) {
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

