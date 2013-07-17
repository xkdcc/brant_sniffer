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

enum True_False {
  TRUE = 1, FALSE = 0
};
typedef enum True_False Boolean;

#ifdef __cplusplus
extern "C" {
#endif

#ifndef _DEBUG
//#define _DEBUG
#endif

#define LINE  16

struct node {
  u_char s_ip[16];        //source IP
  u_char d_ip[16];        //destination IP
  u_int16_t s_port;
  u_int16_t d_port;
  u_int32_t total_byte_size;  //����IP���͵����ֽ�����
  u_int32_t package_amount;   //������
  struct node *next;
};

void disp_hex(unsigned char *prompt, unsigned char *buff, int len);
int convert_to_digital(char *optarg, int optarglen, long *value);
int str_to_upper(char * str);
void print_msg_for_last_errno(char *msg, int n);

#ifdef __cplusplus
}
#endif

#endif
