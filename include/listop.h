#ifndef _LINKEDLISTOP_H
#define _LINKEDLISTOP_H

int searchT(struct iphdr *piph, struct statTable **search, struct statTable *h);
void bianli(struct statTable *h, struct statTable *s);
int addfulT(struct iphdr *piph, int byteslen, struct statTable *s);
int progreBP(int byteslen, struct statTable *search);

#endif
