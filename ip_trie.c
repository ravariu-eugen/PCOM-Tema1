#include "ip_trie.h"


int mask_size(int mask) {
    // intoarce lungimea mastii

    int s = 0;
    for(int i = 0; i < IPV4_SIZE; i++)
        s += (mask&(1<<i)) != 0;

    return s;
}

ip_trie create_trie(){
    ip_trie tire = malloc(sizeof(struct ip_trie_node));
    tire->dr = tire->st =tire->element = NULL;
    return tire;
}

int add_to_trie(ip_trie trie,int ip, int mask, void *elem){

    int mask_s = mask_size(mask);

    ip_trie curr = trie;
    if(curr == NULL)
            return -1;

    ip = ntohl(ip);

    for(int i=IPV4_SIZE - 1; i >= IPV4_SIZE - mask_s; i--){
        // generam calea pana la pozitia corespunzatoare prefixului
        if((ip & (1<<i)) == 0){
            if(curr->st == NULL){
                curr->st = create_trie(); 
            }
            curr = curr->st;
        }else{
            if(curr->dr == NULL){
                curr->dr = create_trie();
            }
            curr = curr->dr;
        }

        if(curr == NULL) // daca esueaza o alocare
            return -1;
    }
    curr->element = elem; // pune elementul in nod
    return 0;
}

void *find_in_trie(ip_trie trie, int ip, int mask){
    // intoarce elementul cu un anumit prefix si lungime a mastii
    int mask_s = mask_size(mask);

    ip_trie curr = trie;
    ip = ntohl(ip);

    for(int i=IPV4_SIZE - 1; i >= IPV4_SIZE - mask_s; i--){
        if((ip & (1<<i)) == 0){
            if(curr->st == NULL)
                return NULL;
            curr = curr->st;
        }else{
            if(curr->dr == NULL)
                return NULL;
            curr = curr->dr;
        }
    }
    return curr->element;
}

void *longest_prefix_match(ip_trie trie, int ip){

    ip_trie curr = trie;        // pozitia curenta in arbore
    ip_trie best_match = trie;  // pozitia de prefix maxim din arbore ce contine un element
                                // (->element != NULL)
    ip = ntohl(ip);
    for(int i=IPV4_SIZE - 1; i >= 0; i--){
        if((ip & (1<<i)) == 0){
            if(curr->st == NULL)
                break;
            curr = curr->st;
        }else{
            if(curr->dr == NULL)
                break;
            curr = curr->dr;
        }

        if(curr->element != NULL) // am gasit un prefix valid mai lung
            best_match = curr;
    }
    return best_match->element;
}
