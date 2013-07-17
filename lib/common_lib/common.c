/***********************************************************
 Copyright (C), 2005, Chen Chao
 File name:      common.c
 Author:  Chen Chao      Version: 1.0    Date: 2005.10
 Description:    bcsniffer����Ĺ�������ʵ���ļ�
 Others:
 Function List:
 History:
 1. Date:
 Author:
 Modification:
 (1)
 2. ...
 **************************************************************/

#include <stdlib.h>        //����UNIX�����Ͷ���ȣ���u_char/u_int32_t
#include <stdio.h>

#include "../../include/common.h"

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
        if (isprint(buff[i - c + j]))
          printf("%c", buff[i - c + j]);
        else
          printf(" ");
      }
      printf("\n");
      c = 0;
    }
  }
}

//�ж�Я���Ĳ����Ƿ�Ϊ�Ϸ�������
//���أ��ɹ�    0    ʧ��        -1
int convert_to_digital(char *optarg, int optarglen, long *value) {
  while ((optarglen > 0) && (isdigit(optarg[--optarglen]))) {
  }

  if (optarglen == 0) {
    *value = atol(optarg);
    return 0;
  }
  else {
    return -1;
  }
}

//ת���ַ���Ϊ��д
//���أ��ɹ���0   ʧ�ܣ�-1��
int str_to_upper(char * str) {
  while (*str != '\0') {
    *str = toupper(*str);
    str++;
  }
  return 0;
}

/*������Ϣ*/
void print_msg_for_last_errno(char *msg, int n) {
  perror(msg);
  exit(n);
}

