/***********************************************************
 Copyright (C), 2005, Chen Chao
 File name:      common.h
 Author:  Chen Chao      Version: 1.0    Date: 2005.10
 Description:    ipsnatcher程序的公共头文件
 Others:         流量统计结构,采用链表结构
 分析一个包后，查找列表中是否有记录，没有则添加并累加字节和包数量；
 已存在则累加字节和包数量
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

#define LINE  16

struct pkg_list {
  u_char sip[16];        //source IP
  u_char dip[16];        //destination IP
  u_int32_t bcount;      //字节总量
  u_int32_t packcount;   //包总量
  struct pkg_list *next;
};

void disp_hex(unsigned char *prompt, unsigned char *buff, int len);
int convert_to_digital(char *optarg, int optarglen, long *value);
int str_to_upper(char * str);
void print_msg_for_last_errno(char *msg, int n);

#ifdef __cplusplus
}
#endif

#endif
