/***********************************************************
 Copyright (C), 2005, Chen Chao
 File name:      netop.c
 Author:  Chen Chao      Version: 1.0    Date: 2005.10
 Description:    bcsniffer程序的网络操作函数实现文件
 Others:
 History:
 1. Date:06-02-13
 Author:cc
 Modification:
 (1)在analAboveProto函数中省略protocol->p_proto(int)的输出,因为作为用户并不关心协议的编号;
 省略protocol->p_aliases[0]的输出,因为有name输出,没必要再输出别名

 2. ...
 **************************************************************/

#include <stdlib.h>            //包含UNIX的类型定义等，如u_char/u_int32_t
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>         //定义ioctl函数
#include <netinet/ip.h>        //定义struct iphdr等结构
#include <netdb.h>             //定义getprotobyname等函数 
#include <net/if.h>            //定义struct ifreq等结构，还有IFF_PROMISC等宏
#include "../../include/common.h"
#include "../../include/netop.h"

/*修改网卡成PROMISC(混杂)模式*/
int set_promisc(char *nif, int sock) {
  struct ifreq ifr;

  //ifr.ifr_name----- Interface name, e.g. "eth0".
  strncpy(ifr.ifr_name, nif, strlen(nif) + 1);
  if ((ioctl(sock, SIOCGIFFLAGS, &ifr) == -1)) { //获得flag
    print_msg_for_last_errno("ioctl", 2);
  }

  ifr.ifr_flags |= IFF_PROMISC;                  //重置flag标志

  if (ioctl(sock, SIOCSIFFLAGS, &ifr) == -1) {   //改变模式

    print_msg_for_last_errno("ioctl", 3);
  }
  else {
    printf("\nModify eth0 to promisc success!\n");
  }

  return 0;
}

//计算checksum函数
u_int16_t checksum_ip(u_int16_t *buffer, int size) {
  unsigned long cksum = 0;

  while (size > 1) {
    cksum += *buffer++;
    size -= sizeof(u_int16_t);
  }
  if (size) {
    cksum += *(u_int16_t *) buffer;
  }

  cksum = (cksum >> 16) + (cksum & 0xffff);
  cksum += (cksum >> 16);

  return (u_int16_t) (~cksum);
}

//由IP头中protocol元素的值获得协议名称
int get_protocol_name(int numProto) {
  struct protoent *protocol;
  protocol = getprotobynumber(numProto);
  if (protocol == (struct protoent *) NULL ) {
    perror("Analyse the protocol failed!");
    return -1;
  }

  printf("%s \n", protocol->p_name);
  return 0;
}

