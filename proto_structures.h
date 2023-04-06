#pragma once

#include <cstdint>
#include <iostream>
#include <sstream>
#include <cstring>
#include <netinet/in.h>

union __attribute__((packed)) ipv4_addr{
	static constexpr uint16_t ethtype=0x0800;
	static constexpr int siz=4;
	uint8_t addr[4];
	uint32_t word;
	ipv4_addr(){}
	ipv4_addr(uint32_t x);
	ipv4_addr(const std::string& x);
	ipv4_addr(const char *x);
	operator std::string() const;
};

struct __attribute__((packed)) mac_addr{
	static constexpr int siz=6;
	uint8_t addr[6];
	mac_addr(){}
	mac_addr(const std::string& x);
	mac_addr(const char *x);
	operator std::string() const;
};

struct __attribute__((packed)) ethernet_packet{
	mac_addr dst;
	mac_addr src;
	uint16_t ethtype;
	ethernet_packet(){}
	ethernet_packet(const mac_addr& src);
	ethernet_packet(const mac_addr& src,const mac_addr& dst):src(src),dst(dst){}
	operator const uint8_t*() const;
};

struct __attribute__((packed)) arp_eth_ipv4:public ethernet_packet{
	uint16_t l2type;
	uint16_t l3type;
	uint8_t l2addr_siz;
	uint8_t l3addr_siz;
	uint16_t arptype;
	mac_addr smac;
	ipv4_addr sip;
	mac_addr dmac;
	ipv4_addr tip;
	arp_eth_ipv4();
	arp_eth_ipv4(const mac_addr& src,const ipv4_addr& sip,const ipv4_addr& tip); // request
	arp_eth_ipv4(const mac_addr& src,const mac_addr& dst,const ipv4_addr& sip,const ipv4_addr& tip); // reply
};
