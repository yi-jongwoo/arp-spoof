#include "local_address.h"
mac_addr get_mac_addr(const char *dev){
	std::ifstream fs(std::string("/sys/class/net/")+dev+"/address");
	if(!fs.is_open()){
		printf("can\'t access %s\n",dev);
	}
	std::string s;fs>>s;
	mac_addr res(s);
	return res;
}
ipv4_addr get_ipv4_addr(const char *dev){
	int fd=socket(AF_INET,SOCK_DGRAM,0);
	struct ifreq ifr;
	ifr.ifr_addr.sa_family=AF_INET;
	strncpy(ifr.ifr_name,dev,IFNAMSIZ-1);
	ioctl(fd,SIOCGIFADDR,&ifr);
	return ipv4_addr(inet_ntoa(((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr));
}
