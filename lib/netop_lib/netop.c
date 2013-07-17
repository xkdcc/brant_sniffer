/***********************************************************
 Copyright (C), 2005, Chen Chao
 File name:      netop.c
 Author:  Chen Chao      Version: 1.0    Date: 2005.10
 Description:    bcsniffer����������������ʵ���ļ�
 Others:
 History:
 1. Date:06-02-13
 Author:cc
 Modification:
 (1)��analAboveProto������ʡ��protocol->p_proto(int)�����,��Ϊ��Ϊ�û���������Э��ı��;
 ʡ��protocol->p_aliases[0]�����,��Ϊ��name���,û��Ҫ���������

 2. ...
 **************************************************************/

#include <stdlib.h>            //����UNIX�����Ͷ���ȣ���u_char/u_int32_t
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>         //����ioctl����
#include <netinet/ip.h>        //����struct iphdr�Ƚṹ
#include <netdb.h>             //����getprotobyname�Ⱥ��� 
#include <net/if.h>            //����struct ifreq�Ƚṹ������IFF_PROMISC�Ⱥ�
#include "../../include/common.h"
#include "../../include/netop.h"

/*�޸�������PROMISC(����)ģʽ*/
int set_promisc(char *nif, int sock) {
  struct ifreq ifr;

  //ifr.ifr_name----- Interface name, e.g. "eth0".
  strncpy(ifr.ifr_name, nif, strlen(nif) + 1);
  if ((ioctl(sock, SIOCGIFFLAGS, &ifr) == -1)) { //���flag
    print_msg_for_last_errno("ioctl", 2);
  }

  ifr.ifr_flags |= IFF_PROMISC;                  //����flag��־

  if (ioctl(sock, SIOCSIFFLAGS, &ifr) == -1) {   //�ı�ģʽ

    print_msg_for_last_errno("ioctl", 3);
  }
  else {
    printf("\nModify eth0 to promisc success!\n");
  }

  return 0;
}

//����checksum����
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

//��IPͷ��protocolԪ�ص�ֵ���Э������
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

