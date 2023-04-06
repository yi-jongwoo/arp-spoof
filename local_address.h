#pragma once

#include <fstream>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>
#include "proto_structures.h"
mac_addr get_mac_addr(const char *dev);
ipv4_addr get_ipv4_addr(const char *dev);
