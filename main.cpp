#include <arpa/inet.h>
#include <iostream>
#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <errno.h>
#include <libnet.h>
#include <pcap.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <net/if.h>
#include <unistd.h>

using namespace std;

#define ETH_LEN 14

struct ARP {
	uint16_t hd_type;
	uint16_t protocol;
	uint8_t hd_size;
	uint8_t protocol_size;
	uint16_t opcode;
	uint8_t sender_mac[6];
	uint32_t sender_ip;
	uint8_t target_mac[6];
	uint32_t target_ip;
};

void print_mac(uint8_t *mac) {
	    printf("%02x:%02x:%02x:%02x:%02x:%02x\n",mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
}

void get_sender_mac(char * uc_Mac, char *iface) {
    int fd;
    
    struct ifreq ifr;
    char *mac;
    
    fd = socket(AF_INET, SOCK_DGRAM, 0);

    ifr.ifr_addr.sa_family = AF_INET;
    strncpy((char *)ifr.ifr_name , (const char *)iface , IFNAMSIZ-1);

    ioctl(fd, SIOCGIFHWADDR, &ifr);

    close(fd);
    
    mac = (char *)ifr.ifr_hwaddr.sa_data;
    
    //display mac address
	sprintf((char *)uc_Mac,(const char *)"%.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n" , mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

}

void get_target_mac(pcap_t *handle, char *mac) {
	while (true) {
		struct pcap_pkthdr *header;
		const u_char* packet;
		int res = pcap_next_ex(handle, &header, &packet);
		if (res == 0) continue;
		if (res == -1 || res == -2) break;

		libnet_ethernet_hdr *eth = (struct libnet_ethernet_hdr*) packet;
/*
		if (ntohs(eth->ether_type) == 0x0806) {
			ARP *arp = (struct ARP*) &packet[ETH_LEN];
			if (arp->target_mac == reinterpret_cast<uint8_t*>(mac))
				print_mac(arp->sender_mac);
		}
	}
*/
	}
}


void usage() {
	printf("syntax: send_arp <interface> <sender_ip> <target_ip>\n");
	printf("sample: send_arp ens33 192.168.0.254 192.168.2.236\n");
}

int main(int argc, char *argv[]) {
	if (argc != 4) {
		usage();
		return -1;
	}
	char *iface = argv[1];
    char sender_mac[6] = {0};
	char target_mac[6] = {0};
    
	uint32_t sender_ip = inet_addr(argv[2]);
	uint32_t target_ip = inet_addr(argv[3]);
	
	get_sender_mac(iface, sender_mac);

	char errbuf[PCAP_ERRBUF_SIZE] = {0};
	pcap_t* handle = pcap_open_live(iface, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "couldn't open device %s-- %s\n", iface, errbuf);
		return -1;
	}
	
	get_target_mac(handle, sender_mac);
}
