/***********************************************************
 Copyright (C), 2005, Chen Chao
 File name:      linkedlistop.c
 Author:  Chen Chao      Version: 1.0    Date: 2005.10
 Description:    ipsnatcher����������������ʵ���ļ�
 Others:
 Function List:
 History:
 1. Date:2006-2-14
 Author:cc
 Modification:
 (1)�޸�BUG:����searchT�Ĳ��� struct statTable *search��Ϊstruct statTable **search,
 ���������޸�search��λ��,�Ӷ�ʹͳ����ȷ.
 2. ...
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
int searchT(struct iphdr *piph, struct statTable **search, struct statTable *h) {
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
int addfulT(struct iphdr *piph, int byteslen, struct statTable *s) {
  //���ΰ��µ�Ԫ�ظ�ֵ
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

//��searchָ���������
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

//�ۼ��ֽ������Ͱ�����,BP��ʾbyte��package
//�ɹ�����0������ָ�����������-1
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

