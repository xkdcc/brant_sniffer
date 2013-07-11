/***********************************************************
 Copyright (C), 2005, Chen Chao
 File name:      common.c
 Author:  Chen Chao      Version: 1.0    Date: 2005.10
 Description:    ipsnatcher程序的公共函数实现文件
 Others:
 Function List:
 History:
 1. Date:
 Author:
 Modification:
 (1)
 2. ...
 **************************************************************/

#ifdef _DEBUG
#undef _DEBUG
#endif

#include <stdlib.h>        //包含UNIX的类型定义等，如u_char/u_int32_t
#include <stdio.h>

#include "../../include/common.h"

void ShowUsage() {
  printf("\nUsage:./ipsnatchter [Option] ... [Value]...\n");
  printf("-p  --protocl   <TCP|UDP|ICMP>    specify protocol to catch.\n");
  printf(
      "-e  --interval  <Interval>        output linked list when finish snatching \
                                       packeges by default.\n");
  printf(
      "-n  --endcount  <Endcount>        exit when spefic snatch packeges times \
                                         and none stop by default.\n \n");
}

/*出错信息*/
void showErr(char *why, int n) {
  perror(why);
  exit(n);
}

