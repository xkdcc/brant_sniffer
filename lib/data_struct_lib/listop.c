/***********************************************************
 Copyright (C), 2005, Chen Chao (brantchen2008@gmail.com)
 File name:      listop.c
 Author:  Chen Chao      Version: 1.0    Date: 2005.10
 Description:    bcsniffer����������������ʵ���ļ�
 Others:
 Function List:
 History:
 1. Date:2006-2-14
 Author: brant
 Modification:
 (1) �޸�BUG:����searchT�Ĳ��� struct pkg_list *search��Ϊstruct pkg_list **search,
 ���������޸�search��λ��,�Ӷ�ʹͳ����ȷ.
 2. Date:2013-7-12
 Author: brant
 Modification:
 (1) ��������ֵ��£�ʹ��%15s���δ�ӡs->sip��s->d_ip�����sip��dip������ô����ȷ����
 ʽ�� ������ģ����£�
 [ 10.200.108.195]
 [   172.29.34.64]
 ������������ͻ��������������
 [ 172.29.34.64]
 [ 10.200.108.195]
 Ϊ��fix������׼���Լ���ӡ��������ո񣬵��������������gdbʱ��������root cause������
 ��aa_node_to_listʱû�н���memset���㶨��
 **************************************************************/

#include <stdlib.h>            //����UNIX�����Ͷ���ȣ���u_char/u_int32_t
#include <stdio.h>
#include <string.h>
#include <sys/socket.h> 
#include <arpa/inet.h> 
#include <netinet/in.h>        //����3��ͷ�ļ�������inet_aton�Ⱥ���
#include <netinet/ip.h>        //����struct iphdr�Ƚṹ
#include <netinet/tcp.h>       //����struct tcphdr�Ƚṹ
#include <netinet/udp.h>       //����struct udphdr�Ƚṹ
#include "../../include/common.h"
#include "../../include/listop.h"

// Called:
// search_node_in_list, add_node_to_list, sum_package_amount_in_list.
int search_and_add_node(struct iphdr *piph, char *p, struct node **search,
    struct node **head, struct node **tail, int package_total_length,
    int protocol) {
  //��pkg_list������в���
  //���Ƚ��в��ң�����ͷָ��
  //���Һ������ж��������Ƿ�Ϊ�գ�Ϊ�տ϶�û�ҵ�������-1���ҵ�����0
  if (!search_node_in_list(piph, p, search, head, protocol)) {
    sum_package_amount_in_list(package_total_length, *search);       //�ۼ�
  }
  else {
    if ((*search = malloc(sizeof(struct node))) < 0) {
      printf("Out of memory!\n");
      return -1;
    }
    memset(*search, 0, sizeof(struct node));
    add_node_to_list(piph, p, package_total_length, *search, protocol);  //��ӽڵ�
    //�ƶ�ָ��
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

//����IP and Port�Ƿ�match
//������������0��ʾ�ҵ���searchָ��ָ����λ�ã�û���򷵻أ�1
int search_node_in_list(struct iphdr *piph, char *p, struct node **search,
    struct node **h, int protocol) {

  //����
  for (*search = *h; *search != NULL ; *search = (*search)->next) {
    if (protocol != IPPROTO_TCP && protocol != IPPROTO_UDP) {
      if (!strcmp(inet_ntoa(*(struct in_addr*) &(piph->saddr)), (*search)->s_ip)
          && !strcmp(inet_ntoa(*(struct in_addr*) &(piph->daddr)),
              (*search)->d_ip)) { //If IP match
        return 0; //�ҵ�������
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
          return 0; //�ҵ�������
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
          return 0; //�ҵ�������
        }
        else {
          continue;
        }
      } //UDP
    } //TCP and UDP
  } //For
  return -1;
}

//��������µ�Ԫ�ؽ���statTable
//�ɹ�����0������ָ�ָ�룬����-1,
int add_node_to_list(struct iphdr *piph, char *p, int byteslen, struct node *s,
    int protocol) {
//���ΰ��µ�Ԫ�ظ�ֵ
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
    s->next = NULL;           //�¼���Ľڵ��nextָ��ָ��βָ�룬Ϊ��

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

//�ۼ��ֽ������Ͱ�����,BP��ʾbyte��package
//�ɹ�����0������ָ�����������-1
int sum_package_amount_in_list(int byteslen, struct node *search) {
  if (search != NULL ) {
    search->total_byte_size += byteslen;
    search->package_amount++;

    return 0;
  }
  else
    return -1;
}

