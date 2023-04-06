#include "proto_structures.h"
ipv4_addr::ipv4_addr(uint32_t x){
	word=htonl(x);
}
ipv4_addr::ipv4_addr(const std::string& x){
	std::istringstream ss(x);
	char _;
	for(int i=0;i<siz;i++){
		if(i)ss>>_;
		int tmp;ss>>tmp;
		addr[i]=tmp;
	}
}
ipv4_addr::ipv4_addr(const char *x){
	for(int i=0;i<siz;i++){
		int n;
		sscanf(x,"%hhd%n",addr+i,&n);
		x+=n+1;
	}
}
ipv4_addr::operator std::string() const{
	std::ostringstream ss;
	for(int i=0;i<siz;i++){
		if(i)ss<<'.';
		int tmp=addr[i];
		ss<<tmp;
	}
	return ss.str();
}

mac_addr::mac_addr(const std::string& x){
	std::istringstream ss(x);ss>>std::hex;
	char _;
	for(int i=0;i<siz;i++){
		if(i)ss>>_;
		int tmp;ss>>tmp;
		addr[i]=tmp;
	}
}
mac_addr::mac_addr(const char *x){
	for(int i=0;i<siz;i++){
		int n;
		sscanf(x,"%hhx%n",addr+i,&n);
		x+=n+1;
	}
}
mac_addr::operator std::string() const{
	std::ostringstream ss;ss<<std::hex;
	for(int i=0;i<siz;i++){
		if(i)ss<<'-';
		int tmp=addr[i];
		ss<<tmp;
	}
	return ss.str();
}

ethernet_packet::ethernet_packet(const mac_addr& src):src(src){
	memset(&dst,-1,sizeof dst);
}
ethernet_packet::operator const uint8_t*() const{
	return (uint8_t*)this;
}

arp_eth_ipv4::arp_eth_ipv4():l2addr_siz(mac_addr::siz),l3addr_siz(ipv4_addr::siz){
	ethtype=htons(0x0806);
	l2type=htons(0x0001);
	l3type=htons(0x0800);
}
arp_eth_ipv4::arp_eth_ipv4(const mac_addr& src,const ipv4_addr& sip,const ipv4_addr& tip):ethernet_packet(src),l2addr_siz(mac_addr::siz),l3addr_siz(ipv4_addr::siz),smac(src),sip(sip),tip(tip){
	ethtype=htons(0x0806);
	l2type=htons(0x0001);
	l3type=htons(0x0800);
	arptype=htons(0x0001);
	memset(&dmac,0,sizeof dmac);
}
arp_eth_ipv4::arp_eth_ipv4(const mac_addr& src,const mac_addr& dst,const ipv4_addr& sip,const ipv4_addr& tip):ethernet_packet(src,dst),l2addr_siz(mac_addr::siz),l3addr_siz(ipv4_addr::siz),smac(src),dmac(dst),sip(sip),tip(tip){
	ethtype=htons(0x0806);
	l2type=htons(0x0001);
	l3type=htons(0x0800);
	arptype=htons(0x0002);
}

