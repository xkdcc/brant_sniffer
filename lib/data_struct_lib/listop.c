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
 (1) 遇到见奇怪的事，使用%15s依次打印s->sip和s->d_ip，如果sip比dip长，那么就正确，格
 式就 是整齐的，如下：
 [ 10.200.108.195]
 [   172.29.34.64]
 如果反过来，就会出现下面的情况：
 [ 172.29.34.64]
 [ 10.200.108.195]
 为了fix，本来准备自己打印差的两个空格，但是新增代码进行gdb时，发现了root cause，就是
 在aa_node_to_list时没有进行memset！搞定！
 **************************************************************/

#include <stdlib.h>            //包含UNIX的类型定义等，如u_char/u_int32_t
#include <stdio.h>
#include <string.h>
#include <sys/socket.h> 
#include <arpa/inet.h> 
#include <netinet/in.h>        //上述3个头文件定义了inet_aton等函数
#include <netinet/ip.h>        //定义struct iphdr等结构
#include <netinet/tcp.h>       //定义struct tcphdr等结构
#include <netinet/udp.h>       //定义struct udphdr等结构
#include "../../include/common.h"
#include "../../include/listop.h"

// Called:
// search_node_in_list, add_node_to_list, sum_package_amount_in_list.
int search_and_add_node(struct iphdr *piph, char *p, struct node **search,
    struct node **head, struct node **tail, int package_total_length,
    int protocol) {
  //对pkg_list链表进行操作
  //首先进行查找，传递头指针
  //查找函数中判断了链表是否为空，为空肯定没找到，返回-1，找到返回0
  if (!search_node_in_list(piph, p, search, head, protocol)) {
    sum_package_amount_in_list(package_total_length, *search);       //累加
  }
  else {
    if ((*search = malloc(sizeof(struct node))) < 0) {
      printf("Out of memory!\n");
      return -1;
    }
    memset(*search, 0, sizeof(struct node));
    add_node_to_list(piph, p, package_total_length, *search, protocol);  //添加节点
    //移动指针
    if (*head == NULL ) {
      *tail = *head = *search;
    }
    else {
      (*tail)->next = *search;
      *tail = *search;
    }
  }

  return 0;

}

//查找IP and Port是否match
//遍历链表，返回0表示找到，search指针指向新位置；没有则返回－1
int search_node_in_list(struct iphdr *piph, char *p, struct node **search,
    struct node **h, int protocol) {

  //查找
  for (*search = *h; *search != NULL ; *search = (*search)->next) {
    if (protocol != IPPROTO_TCP && protocol != IPPROTO_UDP) {
      if (!strcmp(inet_ntoa(*(struct in_addr*) &(piph->saddr)), (*search)->s_ip)
          && !strcmp(inet_ntoa(*(struct in_addr*) &(piph->daddr)),
              (*search)->d_ip)) { //If IP match
        return 0; //找到并返回
      }
      else {
        continue;
      }
    }
    else {
      if (protocol == IPPROTO_TCP) {
        struct tcphdr *pt;
        pt = (struct tcphdr *) p;
        if (!strcmp(inet_ntoa(*(struct in_addr*) &(piph->saddr)),
            (*search)->s_ip)
            && !strcmp(inet_ntoa(*(struct in_addr*) &(piph->daddr)),
                (*search)->d_ip) && (*search)->s_port == ntohs(pt->source)
            && (*search)->d_port == ntohs(pt->dest)) { //If IP and port match
          return 0; //找到并返回
        }
        else {
          continue;
        }
      } // TCP
      else if (protocol == IPPROTO_UDP) {
        struct udphdr *pu;
        pu = (struct udphdr*) p;
        if (!strcmp(inet_ntoa(*(struct in_addr*) &(piph->saddr)),
            (*search)->s_ip)
            && !strcmp(inet_ntoa(*(struct in_addr*) &(piph->daddr)),
                (*search)->d_ip) && (*search)->s_port == ntohs(pu->source)
            && (*search)->d_port == ntohs(pu->dest)) { //If IP and port match
          return 0; //找到并返回
        }
        else {
          continue;
        }
      } //UDP
    } //TCP and UDP
  } //For
  return -1;
}

//添加整个新的元素进入statTable
//成功返回0；否则恢复指针，返回-1,
int add_node_to_list(struct iphdr *piph, char *p, int byteslen, struct node *s,
    int protocol) {
//依次把新的元素赋值
  if (s != NULL ) {
    strncpy(s->s_ip, inet_ntoa(*(struct in_addr*) &(piph->saddr)),
        strlen(inet_ntoa(*(struct in_addr*) &(piph->saddr))));
    strncpy(s->d_ip, inet_ntoa(*(struct in_addr*) &(piph->daddr)),
        strlen(inet_ntoa(*(struct in_addr*) &(piph->daddr))));

    if (protocol != IPPROTO_TCP && protocol != IPPROTO_UDP) {
      s->s_port = s->d_port = -1;
    }
    else {
      if (protocol == IPPROTO_TCP) {
        struct tcphdr *pt;
        pt = (struct tcphdr*) p;
        s->s_port = ntohs(pt->source);
        s->d_port = ntohs(pt->dest);
      }
      else if (protocol == IPPROTO_UDP) {
        struct udphdr *pu;
        pu = (struct udphdr*) p;
        s->s_port = ntohs(pu->source);
        s->d_port = ntohs(pu->dest);
      }
    }

    s->total_byte_size = byteslen;
    s->package_amount = 1;
    s->next = NULL;           //新加入的节点的next指针指向尾指针，为空

    return 0;
  }
  else {
    return -1;
  }
}

//traversal_list by search pointer
void traversal_list(struct node *h, struct node *s) {

  if (!s) {
    printf("\nNothing catched :(\n");
    exit(1);
  }
  s = h;

  printf("\n");
  printf(
      ""
          "============================ Statistics  =======================================\n\n");
  while (s) {
    if (s->s_port == -1 && s->d_port == -1) {
      printf("[%15s] -> [%15s] Package amount:[%5d] Total size:[%6d] Byte\n",
          s->s_ip, s->d_ip, s->package_amount, s->total_byte_size);
    }
    else {
      printf(
          "[%15s][%5d] -> [%15s][%5d] Package amount:[%5d] Total size:[%6d] Byte\n",
          s->s_ip, s->s_port, s->d_ip, s->d_port, s->package_amount,
          s->total_byte_size);
    }
    s = s->next;
  }
  printf("\n");
  printf(
      ""
          "=========================== End Statistics  ====================================\n");
}

//累加字节总量和包总量,BP表示byte和package
//成功返回0；否则恢复计数，返回-1
int sum_package_amount_in_list(int byteslen, struct node *search) {
  if (search != NULL ) {
    search->total_byte_size += byteslen;
    search->package_amount++;

    return 0;
  }
  else
    return -1;
}

