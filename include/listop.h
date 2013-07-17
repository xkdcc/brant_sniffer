#ifndef _LINKEDLISTOP_H
#define _LINKEDLISTOP_H

int search_and_add_node(struct iphdr *piph, char *p, struct node **search,
    struct node **head, struct node **tail, int package_total_length,
    int protocol);
int search_node_in_listsearch_node_in_list(struct iphdr *piph, char *p,
    struct node **search, struct node **h, int protocol);
void traversal_list(struct node *h, struct node *s);
int add_node_to_list(struct iphdr *piph, char *p, int byteslen, struct node *s,
    int protocol);
int sum_element_in_list(int byteslen, struct node *search);

#endif
