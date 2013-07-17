#ifndef _NETOP_H
#define _NETOP_H

int set_promisc(char *nif, int sock);
u_int16_t checksum_ip(u_int16_t *buffer, int size);
int get_protocol_name(int numProto);

#endif
