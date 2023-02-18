#ifndef _TRIE_H_

#define _TRIE_H_

#include <stdlib.h>

#define IPV4_SIZE 32



struct ip_trie_node {

    void *element;

    struct ip_trie_node *st, *dr;

};

typedef struct ip_trie_node *ip_trie;







ip_trie create_trie(); // creaza un trie nou



int add_to_trie(ip_trie trie,int ip, int mask, void *elem); 

// adauga un element in trie

// intoarce 0 pentru success si -1 pentru esec



void *find_in_trie(ip_trie trie, int ip, int mask);

// cauta un element in trie cu o anumita adresa ip

// intoarce pointer la element pentru success

// intoarce NULL pentru esec





void *longest_prefix_match(ip_trie trie, int ip);

// cauta elementul din trie cu cea mai buna potrivire de prefix

// intoarce pointer la element pentru success

// intoarce NULL pentru esec







#endif // _TRIE_H