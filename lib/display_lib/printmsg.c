/***********************************************************
 Copyright (C), 2005, Chen Chao
 File name:      printmsg.c
 Author:  Chen Chao      Version: 1.0    Date: 2005.10
 Description:    bcsniffer����������������ʵ���ļ�
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
  printf("Time:[%s,%02d:%02d:%02d] ", wday[ptm->tm_wday], ptm->tm_hour,
      ptm->tm_min, ptm->tm_sec);
}

//��ӡarp��rarp��Ϣ
void print_arp_rarp(struct ether_arp *p, unsigned int flag) {
  switch (flag) {
  case ETHERTYPE_ARP:
    printf("Protocol:[ARP] ");
    break;
  case ETHERTYPE_REVARP:
    printf("Protocol:[RARP] ");
    break;
  default:
    printf("Unknown protocol!\n");
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
void printf_ip_header(struct iphdr *pip) {
  printf("Protocol:[IP] ");    //Ϊ�˺�Time��ʾ��ͬһ��,����Ŀ
  printf("\nIP header:[%d Byte] ver:[%d] ttl:[%d] ", pip->ihl, pip->version,
      pip->ttl);
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
    break;
  }
  //��IPЭ��ͷ�з���Э������
  get_protocol_name(pip->protocol);
}

//��ӡTCP��Ϣ
void printf_tcp(char *p, struct iphdr *piph, Boolean print_data) {
  struct tcphdr *pt;          //TCPͷ�ṹ
  u_char *d;

  d = NULL;
  pt = (struct tcphdr *) p;       //ptcpָ��tcpͷ��

  /* inet_ntoa--------����������Ƶ�����ת���������ַ */
  printf("\n[%15s]:[Port: %-6d] -> ",
      inet_ntoa(*(struct in_addr*) &(piph->saddr)), ntohs(pt->source));
  printf("[%15s]:[Port: %-6d] ", inet_ntoa(*(struct in_addr*) &(piph->daddr)),
      ntohs(pt->dest));

  printf("seq:[%10d] ", pt->seq);
  printf("ack_seq:[%10d] ", pt->ack_seq);
  printf("\n");

  // doff��TCP��ͷ/4����ʵ�ʵ�TCP��ͷ����Ϊdoff*4
  d = (u_char *) (p + 4 * pt->doff);
  //TCPЯ�������ݳ���,��ɾ�����е�ԭ��ʹΪ���Ժ��ò��֪����μ���TCP�����ݳ���
  //tot_len��ʾIP���ܳ���Total Length��������16���ء�
  //���ֽ�Ϊ��λ�����IP���ĳ��� (����ͷ��������)������IP����󳤶�65535�ֽڡ�
  //IP���ܳ�-IP��ͷ-TCP��ͷ������TCPЯ�������ݳ���
  if (print_data) {
    disp_hex("TCP:", d, ntohs(piph->tot_len) - 4 * piph->ihl - 4 * pt->doff);
  }
  printf("\n");
}

//��ӡUDP��Ϣ
void printf_udp(char *p, struct iphdr *piph, Boolean print_data) {
  struct udphdr *pu;          //UDPͷ�ṹ
  u_char *d;

  d = NULL;
  pu = (struct udphdr *) p;        //ptcpָ��udpͷ��

  printf("\n[15%s]:[Port: %-6d] -> ",
      inet_ntoa(*(struct in_addr*) &(piph->saddr)), ntohs(pu->source));
  printf("[%15s]:[Port: %-6d]\n", inet_ntoa(*(struct in_addr*) &(piph->daddr)),
      ntohs(pu->dest));

  d = (u_char *) (p + 8);
  if (print_data) {
    disp_hex("UDP: ", d, ntohs(pu->len));
  }
  printf("\n");
}

