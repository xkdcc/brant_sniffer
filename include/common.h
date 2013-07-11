/***********************************************************
 Copyright (C), 2005, Chen Chao
 File name:      common.h
 Author:  Chen Chao      Version: 1.0    Date: 2005.10
 Description:    ipsnatcher����Ĺ���ͷ�ļ�
 Others:         ����ͳ�ƽṹ,��������ṹ
 ����һ�����󣬲����б����Ƿ��м�¼��û������Ӳ��ۼ��ֽںͰ�������
 �Ѵ������ۼ��ֽںͰ�����
 History:
 1. Date:
 Author:
 Modification:
 **************************************************************/
#ifndef _COMMON_H
#define _COMMON_H

#ifdef __cplusplus
extern "C" {
#endif

#ifndef _DEBUG
//#define _DEBUG
#endif

struct statTable {
  u_char sip[16];        //ԴIP
  u_char dip[16];        //Ŀ��IP
  u_int32_t bcount;         //�ֽ�����
  u_int32_t packcount;      //������
  struct statTable *next;
};

void ShowUsage();
void showErr(char *why, int n);

#ifdef __cplusplus
}
#endif

#endif
