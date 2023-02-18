#include "queue.h"
#include "skel.h"
#include "list.h"
#include "ip_trie.h"
#include <limits.h>
#define MAC_BYTES 6
#define IPV4_BYTES 4
#define IPV4_PROTOCOL_ICMP 1
#define ARP_REQUEST 1
#define ARP_REPLY 	2	
#define ETHERTYPE_IPV4 	0x0800
#define ETHERTYPE_ARP 	0x0806
#define FULL_MASK -1

uint16_t c1sum(uint16_t a, uint16_t b){ // calculeaza suma complement 1
	int s = a + b;
	return (s&0xffff) + (s>>16);
}

uint16_t update_checksum(uint16_t checksum, uint16_t initial_value, uint16_t final_value){ 
	// aplica formula de actualizare incrementala din RFC 1624
	return ~(c1sum(c1sum(~checksum, ~initial_value), final_value));
}

int check_mac(char *mac_h, char *mac_p){
	// verifica daca adresa mac mac_p este egala cu mac_h sau ca este adresa broadcast
	// daca da, atunci pachetul este adresat host-ului
	int is_broadcast = 1;
	int is_equal = 1;
	for(int i = 0; i < MAC_BYTES; i++){
		if(mac_h[i] != mac_p[i]) is_equal = 0;
		if((uint8_t)mac_p[i] != 255) is_broadcast = 0;
	}
	return is_equal || is_broadcast;
}

void packet_dump(packet *packet){ // afiseaza continutul unui pachet
	for(int i = 0; i < packet->len; i++){
						printf("%02x ", (char)packet->payload[i]);
						if(i%8==7)
							printf("\n");
					}
					printf("\n");
}

packet *create_ethernet_packet(char *daddr, char *saddr, uint16_t ether_type, packet *payload){
	// creaza un pachet cu header ethernet L2
	packet *pack = malloc(sizeof(packet));
	
	struct ether_header *ether_hdr = (struct ether_header *)pack->payload;
	memcpy(ether_hdr->ether_dhost, daddr, MAC_BYTES); // adresa MAC destinatie
	memcpy(ether_hdr->ether_shost, saddr, MAC_BYTES); // adresa MAC sursa
	ether_hdr->ether_type = htons(ether_type); // tipul pachetului
	memcpy(pack->payload + sizeof(struct ether_header), payload->payload, payload->len);
	pack->len = payload->len + sizeof(struct ether_header); // lungimea pachetului creat



	return pack;

}

packet *create_IPv4_packet(int s_addr, int d_addr, uint8_t protocol, packet *payload){
	// creaza un pachet cu header IPv4
	packet *pack = malloc(sizeof(packet));
	struct iphdr *ip_header = (struct iphdr *)pack->payload;
	ip_header->version = 4;
	ip_header->ihl = 5;
	ip_header->tos = 0;
	ip_header->tot_len = htons(sizeof(struct iphdr) + payload->len); 
	pack->len = sizeof(struct iphdr) + payload->len; //lungime pachet


	ip_header->id = 0;
	ip_header->frag_off = 0;
	ip_header->ttl = 64;
	ip_header->protocol = protocol;
	ip_header->check = 0;
	ip_header->saddr = s_addr;
	ip_header->daddr = d_addr;

	memcpy(((char *)pack->payload) + sizeof(struct iphdr), payload->payload, payload->len);

	ip_header->check = ip_checksum((uint8_t *)pack->payload, pack->len);
	return pack;

}

packet *create_ARP_packet(uint16_t op,char *sha, int spa, char *tha, int tpa){
	// creaza un pachet cu header ARP
	packet *pack = malloc(sizeof(packet));
	struct arp_header *arp = (struct arp_header *)pack->payload;
	arp->htype = htons(1); 	// ethernet
	arp->ptype = htons(2048);	// IPv4
	arp->hlen = MAC_BYTES; 		// mac length
	arp->plen = IPV4_BYTES; 		// ip length
	arp->op = htons(op); 		// request/reply
	if(sha!=NULL)
		memcpy(arp->sha, sha, MAC_BYTES);
	else
		memset(arp->sha, 0, MAC_BYTES);
	arp->spa = spa;
	if(tha!=NULL)
		memcpy(arp->tha, tha, MAC_BYTES);
	else
		memset(arp->tha, 0, MAC_BYTES);
	arp->tpa = tpa;
	
	pack->len = sizeof(struct arp_header); // lungimea pachetului creat
	
	return pack;
}

packet *create_ICMP_packet(uint8_t type, uint8_t code, char *original_ip_packet) {
	// creaza un pachet cu header ICMP
	packet *pack = malloc(sizeof(packet));
	struct icmphdr *header = (struct icmphdr *)pack->payload;
	header->type = type; // tipuri folosite: 0,3,8,11
	header->code = code;
	header->checksum = 0;
	struct iphdr *iphdr = (struct iphdr *)original_ip_packet;
	int len = iphdr->ihl * 4 + 8; // nr de bytes de luat din pachetul original
	switch(type){
		default: header->un.gateway = 0; break;
	}

	// copiem din pachetul original
	memcpy(pack->payload + sizeof(struct icmphdr), original_ip_packet, len); 
	// lungimea finala a pachetului
	pack->len = len + sizeof(struct icmphdr);

	header->checksum = icmp_checksum((uint16_t *) pack->payload, pack->len);

	return pack;
}

void print_mac(uint8_t *mac){
	printf("%hhu:%hhu:%hhu:%hhu:%hhu:%hhu", mac[0],mac[1],mac[2], mac[3],mac[4],mac[5]);
}


int main(int argc, char *argv[])
{
	packet m;
	int rc;
	// Do not modify this line
	init(argc - 2, argv + 2);
	ip_trie arp_cache = create_trie(); // cache-ul arp
	struct route_table_entry *rtable = malloc(sizeof(struct route_table_entry) * 80000);
	ip_trie route_trie = create_trie(); //tabela de rutare
	queue packet_queue = queue_create(); // coada de pachete
	
	int table_size = read_rtable(argv[1], rtable);
	for(int i = 0; i < table_size; i++){
		add_to_trie(route_trie, rtable[i].prefix, rtable[i].mask, rtable + i);
	}
	char broadcast[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
	while (1) {
		rc = get_packet(&m);
		DIE(rc < 0, "get_packet");
		/* TODO */

		int input_interface = m.interface; 	// get interface mac address
		char interface_mac[6]; 
		get_interface_mac(input_interface, (uint8_t *)interface_mac);

		struct in_addr interface_addr;		// get interface ip address
		inet_aton(get_interface_ip(m.interface), &interface_addr);
		int interface_ip = interface_addr.s_addr;

		
		struct ether_header *ether_hdr = (struct ether_header *)m.payload;
		
		if(strncmp(interface_mac, (char *)ether_hdr->ether_shost, MAC_BYTES) == 0) // mesaj de la el insusi
			continue;
		if(check_mac(interface_mac, (char *)ether_hdr->ether_dhost) == 0) // nu e adresata routerului
			continue;
		printf("type: %x \n", ntohs(ether_hdr->ether_type));
		int eth_offset = sizeof(struct ether_header);
		if(ether_hdr->ether_type == htons(ETHERTYPE_IPV4)){ // IPv4
			printf("__IPv4__\n");

			struct iphdr *ip_hdr = (struct iphdr *)(m.payload + eth_offset);

			// verificare checksum
			short check_sum = ip_checksum((uint8_t *)ip_hdr, ntohs(ip_hdr->tot_len));
			if(check_sum != 0){
				printf("CORRUPT: %x\n", ntohs(check_sum));
				continue; // pachet corupt
			}
			
			// check if destination
			int dest_ip = ip_hdr->daddr;
			if(dest_ip == interface_ip){ // message for router
				if(ip_hdr->protocol == 1){ // ICMP
					int ip_offset = ip_hdr->ihl * 4 + eth_offset;
					struct icmphdr *icmp_header = (struct icmphdr *)(m.payload + ip_offset);
					if(icmp_header->type == 8) // echo message
					{	printf("echo_ICMP\n");
						// transformare echo message in echo reply
						icmp_header->type = 0; // echo reply
						ip_hdr->daddr = ip_hdr->saddr;
						ip_hdr->saddr = dest_ip;
						ip_hdr->ttl = 64 + 1;
						icmp_header->checksum = 0;
						icmp_header->checksum = icmp_checksum((uint16_t *)icmp_header, m.len - sizeof(struct ether_header) - ip_hdr->ihl*4);
						ip_hdr->check = 0;
						ip_hdr->check = ip_checksum((uint8_t *)ip_hdr, m.len - sizeof(struct ether_header));
					}
				}
				else{ // unknown protocol
					printf("UNKNOWN_PROTOCOL\n");
					continue;
				}
			}

			
			int old_val = *(uint16_t *)(&ip_hdr->ttl);
			ip_hdr->ttl--; // decrement ttl
			int new_val = *(uint16_t *)(&ip_hdr->ttl);
			ip_hdr->check = update_checksum(ip_hdr->check, old_val, new_val);// update checksum
			
			if(ip_hdr->ttl <= 0){ // time exceeded
				printf("TIME_EXCEEDED\n");
				// creaza pachetul nou
				packet *timeout_icmp = create_ICMP_packet(ICMP_TIME_EXCEEDED, 0, (char *)ip_hdr);
				packet *timeout_ip = create_IPv4_packet(interface_ip, ip_hdr->saddr, IPV4_PROTOCOL_ICMP, timeout_icmp);
				packet *timeout_eth = create_ethernet_packet(broadcast, interface_mac, ETHERTYPE_IPV4, timeout_ip);

				m = *timeout_eth; // arunca pachetul original

				free(timeout_icmp);
				free(timeout_ip);
				free(timeout_eth);
			}

			struct route_table_entry *entry = (struct route_table_entry *) longest_prefix_match(route_trie, ip_hdr->daddr);
				// gasire drum spre destinatie
			if(entry == NULL){ // destination unreachable
				printf("DESTINATION_UNREACHABLE\n");
				// creaza pachetul nou
				packet *unreach_icmp = create_ICMP_packet(ICMP_DEST_UNREACH, 0, (char *)ip_hdr);
				packet *unreach_ip = create_IPv4_packet(interface_ip, ip_hdr->saddr, IPV4_PROTOCOL_ICMP, unreach_icmp);
				packet *unreach_eth = create_ethernet_packet(broadcast, interface_mac, ETHERTYPE_IPV4, unreach_ip);

				// gaseste drum spre sursa
				entry = (struct route_table_entry *) longest_prefix_match(route_trie, ip_hdr->saddr);
					
				m = *unreach_eth; // arunca pachetul original
				
				free(unreach_icmp);
				free(unreach_ip);
				free(unreach_eth);
				
			}
	 
			
			
			int next_hop_ip = entry->next_hop;
			char source_mac[6];				// get interface mac address
			get_interface_mac(entry->interface, (uint8_t *)source_mac);
			struct in_addr source_addr;		// get interface ip address
			inet_aton(get_interface_ip(entry->interface), &source_addr);
			int source_ip = source_addr.s_addr;
			
			char *dest_mac = (char *)find_in_trie(arp_cache, next_hop_ip, FULL_MASK);
			if(dest_mac == NULL){ // send an ARP REQUEST
				printf("ARP_REQUEST\n");
				// add packet to queue
				packet *q_packet = (packet *) malloc(sizeof(packet));
				memcpy(q_packet, &m, sizeof(packet));
				q_packet->interface = ip_hdr->daddr; 
				// folosim campul de 4 bytes interface al structurii pachet pentru a memora
				// adresa ip a destinatiei
				queue_enq(packet_queue, q_packet);

				// make ARP packet
				packet *arp = create_ARP_packet(ARP_REQUEST, source_mac, source_ip, NULL, next_hop_ip);
				packet *arp_eth = create_ethernet_packet(broadcast, source_mac, ETHERTYPE_ARP, arp);
				
				m = *arp_eth; // arunca pachetul original
				dest_mac = broadcast; // schimba destinatia
				free(arp);
				free(arp_eth);
			}

			// update L2
			printf("SEND\n");
			m.interface = entry->interface;
			memcpy(ether_hdr->ether_shost, source_mac, MAC_BYTES);
			memcpy(ether_hdr->ether_dhost, dest_mac, MAC_BYTES);

			rc = send_packet(&m);
			DIE(rc < 0, "send_packet");
			continue;
		}else if(ether_hdr->ether_type == htons(ETHERTYPE_ARP)){ 
			printf("ARP\n");
			struct arp_header *arp_hdr = (struct arp_header *)
										(m.payload + sizeof(struct ether_header));
			if(ntohs(arp_hdr->op) == ARP_REQUEST){ 
				printf("ARP_REQUEST\n");
				// modificam request-ul in reply
				arp_hdr->op = htons(ARP_REPLY);
				memcpy(arp_hdr->tha, arp_hdr->sha, MAC_BYTES);
				int aux = arp_hdr->spa;
				arp_hdr->spa = arp_hdr->tpa;
				arp_hdr->tpa = aux;
				memcpy(arp_hdr->sha, interface_mac, MAC_BYTES);
				struct ether_header *eth_hdr = (struct ether_header *) m.payload;
				memcpy(eth_hdr->ether_dhost, arp_hdr->tha, MAC_BYTES);
				memcpy(eth_hdr->ether_shost, arp_hdr->sha, MAC_BYTES);
				printf("SEND_REPLY");
				rc = send_packet(&m);
				DIE(rc < 0, "send_packet");

			}
			else if(ntohs(arp_hdr->op) == ARP_REPLY){ 
				printf("ARP_REPLY\n");
				// adugam adresa primita in arp_cache
				char *added_mac = malloc(MAC_BYTES);

				memcpy(added_mac, arp_hdr->sha, MAC_BYTES);
				char *old_mac = (char *)find_in_trie(arp_cache, arp_hdr->spa, FULL_MASK);
				// daca mai exista o adresa mac asociata ip-ului, o inlocuim
				if(old_mac != NULL) 
					free(old_mac);
				add_to_trie(arp_cache, arp_hdr->spa, FULL_MASK, added_mac);
				while(!queue_empty(packet_queue)){
					packet *pack = packet_queue->head->element;
					struct route_table_entry *entry = (struct route_table_entry *)longest_prefix_match(route_trie, pack->interface);

					int next_hop_ip = entry->next_hop;
					
					char source_mac[6];				// get interface mac 
					get_interface_mac(entry->interface, source_mac);
					struct in_addr source_addr;		// get interface ip 
					inet_aton(get_interface_ip(entry->interface), &source_addr);
					int source_ip = source_addr.s_addr;


					char *dest_mac = (char *)find_in_trie(arp_cache, next_hop_ip, FULL_MASK);
					// daca inca nu are adresa mac, il lasam in coada
					if(dest_mac == NULL){ 
						break;
					}
					queue_deq(packet_queue); // eliminam pachetul din coada

					// update L2
					printf("SEND\n");
					pack->interface = entry->interface;
					ether_hdr = pack->payload;
					memcpy(ether_hdr->ether_shost, source_mac, MAC_BYTES);
					memcpy(ether_hdr->ether_dhost, dest_mac, MAC_BYTES);
					
					rc = send_packet(pack);
					DIE(rc < 0, "send_packet");
					free(pack);
				}
			}else{ // operatie invalida
				printf("INVALID\n");
			}

		} else{// protocol invalid
			printf("INVALID\n");
		}




		
	}
}
