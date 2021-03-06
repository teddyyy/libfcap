#ifndef __FCAP_H__
#define __FCAP_H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <pcap.h>

struct monitor_fn_t *_mfn;
struct mif *_mi_in, *_mi_out;
struct tif *_ti_in, *_ti_out;

// Default value
#define PG_NAME					"fcapd"
#define DEFAULT_WIRELESS_IFACE  "mon0"
#define DEFAULT_ESSID           "hoge"
#define DEFAULT_CHANNEL         36
#define DEFAULT_MAC_ADDRESS		"aa:bb:cc:dd:ee:00"
#define DEFAULT_AP_MSGS_PORT   	55550 

// Mac address
#define MACADDR(m) (m)[0], (m)[1], (m)[2], (m)[3], (m)[4], (m)[5]
#define MACADDR_TYPE(x) u_int8_t x[6]
#define MACADDR_TYPE_SZ (sizeof(u_int8_t)*6)
#define MAC_ADDRESS_NULL (u_int8_t *) "\0\0\0\0\0\0"
#define f_MACADDR "%02X:%02X:%02X:%02X:%02X:%02X"

// IP address
#define IPADDR_TYPE(x) u_int8_t x[4]
#define IPADDR_TYPE_SZ (sizeof(u_int8_t)*4)

// Data rate
#define EID_SUPPORTED_RATES_LENGHT 8
#define EID_SUPPORTED_RATES_EXT_LENGHT 4
#define RATE_6M 6000000
#define RATE_9M 9000000
#define RATE_12M 12000000
#define RATE_18M 18000000
#define RATE_24M 24000000
#define RATE_36M 36000000
#define RATE_48M 48000000
#define RATE_54M 54000000

// Beacon
#define BEACON_INTERVAL 0x064
#define BEACON_INTERVAL_TIMER (BEACON_INTERVAL*1000)

#define CSASENDOFFER        0x10
#define CSAASSOCOFFER      	0x11                                                 
#define CSACOMPLETE         0x20
#define CSAASSOCED          0x21
#define CSASWITCHCOUNT		10

struct devices {
	pcap_t *fd_in;
	pcap_t *fd_out;
	
	int ti_in, ti_out;
} dev;

struct csahdr {
    u_int8_t type;
    u_int8_t channel;
    MACADDR_TYPE(tgt_addr);
};

struct config_values {
	MACADDR_TYPE(mac_address);
   	IPADDR_TYPE(ip_address);
   	IPADDR_TYPE(netmask);
   	char essid[120];
   	char essid_prefix[120];
   	char wifi_iface[10];
	int channel;
	int ap_msg_port;
} config;

int init_fcap(int argc, char** argv, int channel);
#endif
