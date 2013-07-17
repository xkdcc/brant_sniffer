#ifndef _PRINTMSG_H
#define _PRINTMSG_H

//tos…Ë÷√
#ifndef MINDELAY 
#define MINDELAY     0x10
#endif
#ifndef MAXTHROUGHPUT 
#define MAXTHROUGHPUT 0x08
#endif  
#ifndef HISECURITY
#define HISECURITY    0x06
#endif  
#ifndef MINCOST
#define MINCOST       0x04
#endif 

void print_mac(u_char *sha);
void print_ipaddr(u_char *ipadd);
void print_time();
void print_arp_rarp(struct ether_arp *p, unsigned int flag);
void printf_ip_header(struct iphdr *pip);
void printf_tcp(char *p, struct iphdr *pip, Boolean print_data);
void printf_udp(char *p, struct iphdr *pip, Boolean print_data);

#endif
