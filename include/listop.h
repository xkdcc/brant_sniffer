#ifndef _LINKEDLISTOP_H
#define _LINKEDLISTOP_H

int search_ip_in_list(struct iphdr *piph, struct pkg_list **search, struct pkg_list *h);
void traversal_list(struct pkg_list *h, struct pkg_list *s);
int add_node_to_list(struct iphdr *piph, int byteslen, struct pkg_list *s);
int sum_element_in_list(int byteslen, struct pkg_list *search);

#endif
