/***********************************************************
 Copyright (C), 2005, Chen Chao
 File name:      linkedlistop.c
 Author:  Chen Chao      Version: 1.0    Date: 2005.10
 Description:    ipsnatcher����������������ʵ���ļ�
 Others:
 Function List:
 History:
 1. Date:2006-2-13
 Author:cc
 Modification:
 (1)�ں���printf_tcp��ʡ�Զ�TCPЯ�������ݳ��ȵļ�������,��û��ʲô����
 printf_ip��ȥ����ip�����ݳ���pip->tot_len����ʾ,�û�Ӧ��ֻ�����ܵĴ�С
 2. Date:2006-2-14
 Author:cc
 Modification:
 (1)�ں���print_time�н�ʱ�������ʽ����Ϊ00:00:00,������ʹ��%02,0��flag���,����������2ʱ,��0���
 (2)����disp_hex����
 **************************************************************/

#ifdef _DEBUG
#undef _DEBUG
#endif

#include <stdlib.h>                  //����UNIX�����Ͷ���ȣ���u_char/u_int32_t
#include <stdio.h>
#include <stdio.h>
#include <time.h>
#include <ctype.h>                   //����isprint����
#include <netinet/ip.h>              //����struct iphdr�Ƚṹ
#include <netinet/tcp.h>             //����struct tcphdr�Ƚṹ
#include <netinet/udp.h>             //����struct udphdr�Ƚṹ  
#include <arpa/inet.h>  
#include <netinet/if_ether.h>        //����struct ether_arp�Ƚṹ
#include "../../include/common.h"
#include "../../include/netop.h"
#include "../../include/printmsg.h"

/*���ַ���������16���Ƶķ�ʽ��ӡ����
 ����: *prompt:��ӡ֮ǰ����ʾ��Ϣ
 *buf:��Ҫ��ӡ���ַ���
 len:��Ҫ��ӡ�ĳ���*/
void disp_hex(unsigned char *prompt, unsigned char *buff, int len) {
  int c, i;

  printf("\n[%s] [Length = %d]\n", prompt, len);
  c = 0;
  for (i = 0; i < len; i++) {
    printf("%2x ", buff[i]);
    c++;
    if (!((i + 1) % LINE) || i == len - 1) {
      int j;
      if (c != LINE) {
        for (j = c; LINE - j; j++)
          printf("   ");
      }
      printf(" | ");
      for (j = 0; j < c; j++) {
        if (isprint(buff[i-c+j]))
          printf("%c", buff[i - c + j]);
        else
          printf(" ");
      }
      printf("\n");
      c = 0;
    }
  }
}

//���MAC��ַ����
void print_mac(u_char *sha) {
  int i;
  for (i = 0; i < 5; ++i)
    printf("%02x:", sha[i]);
  printf("%02x", sha[i]);
}

//���IP��ַ�ĺ���
void print_ipaddr(u_char *ipadd) {
  int i;
  for (i = 0; i < 3; ++i)
    printf("%d.", ipadd[i]);
  printf("%d", ipadd[i]);
}

//��ӡץ��ʱ��
void print_time() {
  //localtime��ttָ���time_t�ṹ����Ϣ������ʵ�����е�����ʱ���ʾ
  //�����tm�ṹ��ָ��ptm����
  char *wday[] = { "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" };
  time_t tt;
  struct tm *ptm;
  time(&tt);
  ptm = localtime(&tt);
  printf("%s,%02d:%02d:%02d ", wday[ptm->tm_wday], ptm->tm_hour, ptm->tm_min,
      ptm->tm_sec);
}

//��ӡarp��rarp��Ϣ
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

//����tos��������
void printf_ip(struct iphdr *pip) {
  printf("IP ");	//Ϊ�˺�Time��ʾ��ͬһ��,����Ŀ
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
  //��IPЭ��ͷ�з���Э������
  analAboveProto(pip->protocol);
}

//��ӡTCP��Ϣ
void printf_tcp(char *p, struct iphdr *pip, struct tcphdr *pt, u_char *d) {
  pt = (struct tcphdr *) p;       //ptcpָ��tcpͷ��

  /* inet_ntoa--------����������Ƶ�����ת���������ַ */
  printf("\n%s:%d->", inet_ntoa(*(struct in_addr*) &(pip->saddr)),
      ntohs(pt->source));
  printf("%s:%d ", inet_ntoa(*(struct in_addr*) &(pip->daddr)),
      ntohs(pt->dest));

  printf("%-5d ", pt->seq);
  printf("%-5d ", pt->ack_seq);
  printf("\n");

  d = (u_char *) (p + 4 * pt->doff);
  //TCPЯ�������ݳ���,��ɾ�����е�ԭ��ʹΪ���Ժ��ò��֪����μ���TCP�����ݳ���
  //printf("%dB\n\n",ntohs(pip->tot_len)-4*pip->ihl-4*pt->doff);
}

//��ӡUDP��Ϣ
void printf_udp(char *p, struct iphdr *pip, struct udphdr *pu, u_char *d) {
  pu = (struct udphdr *) p;        //ptcpָ��udpͷ��

  printf("\n%s:%d->", inet_ntoa(*(struct in_addr*) &(pip->saddr)),
      ntohs(pu->source));
  printf("%s:%d\n", inet_ntoa(*(struct in_addr*) &(pip->daddr)),
      ntohs(pu->dest));

  d = (u_char *) (p + 8);
  disp_hex("UDP:", d, ntohs(pu->len));
  printf("\n");
}
