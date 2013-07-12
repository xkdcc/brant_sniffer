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
 (1) ��������ֵ��£�ʹ��%15s���δ�ӡs->sip��s->dip�����sip��dip������ô����ȷ����
 ʽ�� ������ģ����£�
 [ 10.200.108.195]
 [   172.29.34.64]
 ������������ͻ��������������
 [ 172.29.34.64]
 [ 10.200.108.195]
Ϊ��fix������׼���Լ���ӡ��������ո񣬵��������������gdbʱ��������root cause������
��aa_node_to_listʱû�н���memset���㶨��
**************************************************************/

#ifdef _DEBUG
#undef _DEBUG
#endif

#include <stdlib.h>            //����UNIX�����Ͷ���ȣ���u_char/u_int32_t
#include <stdio.h>
#include <string.h>
#include <sys/socket.h> 
#include <arpa/inet.h> 
#include <netinet/in.h>        //����3��ͷ�ļ�������inet_aton�Ⱥ���
#include <netinet/ip.h>        //����struct iphdr�Ƚṹ
#include "../../include/common.h"
#include "../../include/listop.h"

//����IP�Ƿ��Ѵ���
//������������0��ʾ�ҵ���searchָ��ָ����λ�ã�û���򷵻أ�1
int search_ip_in_list(struct iphdr *piph, struct pkg_list **search, struct pkg_list *h) {
  //����
  for (*search = h; *search != NULL ; *search = (*search)->next) {
    if (!strcmp(inet_ntoa(*(struct in_addr*) &(piph->saddr)), (*search)->sip)
        && !strcmp(inet_ntoa(*(struct in_addr*) &(piph->daddr)),
            (*search)->dip))  //������
            {
#ifdef _DEBUG
      printf("searched!\nsip:%s dip:%s\n", (*search)->sip, (*search)->dip);
#endif
      return 0; //�ҵ�������
    }
    else
      continue;
  }

#ifdef _DEBUG
  printf("Not searched!\n");
#endif

  return -1;
}

//��������µ�Ԫ�ؽ���statTable
//�ɹ�����0������ָ�ָ�룬����-1,
int add_node_to_list(struct iphdr *piph, int byteslen, struct pkg_list *s) {
  //���ΰ��µ�Ԫ�ظ�ֵ
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
    s->next = NULL;           //�¼���Ľڵ��nextָ��ָ��βָ�룬Ϊ��

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

//�ۼ��ֽ������Ͱ�����,BP��ʾbyte��package
//�ɹ�����0������ָ�����������-1
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

