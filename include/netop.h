#ifndef _NETOP_H
#define _NETOP_H

int set_promisc(char *nif, int sock);
u_int16_t checksumip(u_int16_t *buffer, int size);
int analAboveProto(int numProto);

#endif
