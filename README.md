322CB - Ravariu Eugen-Cristian

Structuri folosite:

ip_trie - creaza un arbore binar ce poate memora fiecare prefix IPv4 posibil
            structura unui nod:
                - element - elementul asociat prefixului
                - st - subarborele stang
                - dr - subarborele drept
            lungimea prefixului este data de adancimea in arbore
            prefixul unui nod se obtine din drumul parcurs pana la acesta:
                - incepem cu un prefix de lungime 0
                - daca o luam pe ramura stanga, adaugam 0 la cel mai semnificativ bit nefolosit
                - daca o luam pe ramura dreapta, adaugam 1 la cel mai semnificativ bit nefolosit

packet - pentru construirea pachetelor am folosit functiile:
            create_ARP_packet
                - creaza un pachet ARP
            create_ethernet_packet
                - creaza un pachet cu header de ethernet si 
                    cu payload pachetul primit ca argument 
            create_IPv4_packet
                - creaza un pachet cu header de IPv4 si 
                    cu payload pachetul primit ca argument
            create_ICMP_packet
                - creaza un pachet cu header ICMP si
                    cu payload header-ul frame-ul IPv4 si
                    primii 64 de biti din datagrama originala
                    (vedeti RFC 792)

Subpuncte rezolvate:

1) Protocolul arp
    Cache-ul arp a fost implementat folosinds structura ip_trie, 
fiind folosita ca un map ip->MAC(char * la sir de 6 bytes)
    Cand primesc un ARP REPLY, verific daca pot trimite varful cozii;
daca nu mai astept sa vina reply-ul(daca se intampla ca ARP Reply-ul
de la al doilea pachet trimis sa ajunga mai repede decat cel de la primul;
odata ce vine primul reply, ambele sunt trimise)

2) Procesul de dirijare
    
3) Longest Prefix Match eficient
    pentru a memora tabela de rutare, folosesc structura ip_trie, 
fiind folosita ca un map (ip, mask)->route_table_entry
4) Protocolul ICMP

5) BONUS: actualizarea sumei de control incrementale
    Pentru aceasta folosesc formula descrisa in RFC 1624 cand se modifica ttl
