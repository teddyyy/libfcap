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
#define DEFAULT_WIRELESS_IFACE  "mon0"
#define DEFAULT_ESSID           "hoge"
#define DEFAULT_CHANNEL         36
#define DEFAULT_IP_ADDRESS      "10.0.0.1"
#define DEFAULT_MAC_ADDRESS      "aa:bb:cc:dd:ee:00"

// Mac address
#define MACADDR(m) (m)[0], (m)[1], (m)[2], (m)[3], (m)[4], (m)[5]
#define MACADDR_TYPE(x) u_int8_t x[6]
#define MACADDR_TYPE_SZ (sizeof(u_int8_t)*6)
#define MAC_ADDRESS_NULL (u_int8_t *) "\0\0\0\0\0\0"

// IP address
#define IPADDR_TYPE(x) u_int8_t x[4]
#define IPADDR_TYPE_SZ (sizeof(u_int8_t)*4)

// Data rate
#define EID_SUPPORTED_RATES_LENGHT 8
#define RATE_1M 1000000
#define RATE_2M 2000000
#define RATE_5_5M 5500000
#define RATE_11M 11000000
#define RATE_6M 6000000
#define RATE_9M 9000000
#define RATE_12M 12000000
#define RATE_18M 18000000
#define RATE_24M 24000000
#define RATE_36M 36000000
#define RATE_48M 48000000
#define RATE_54M 54000000

#define IEEE80211_LLC_SNAP   \
"\x08\x00\x00\x00\xDD\xDD\xDD\xDD\xDD\xDD\xBB\xBB\xBB\xBB\xBB\xBB" \
    "\xCC\xCC\xCC\xCC\xCC\xCC\xE0\x32\xAA\xAA\x03\x00\x00\x00\x08\x00"

// Beacon
#define BEACON_INTERVAL 0x064
#define BEACON_INTERVAL_TIMER (BEACON_INTERVAL*1000)

struct devices 
{
	//int fd_in, arptype_out;
	//int fd_out, arptype_out;

	pcap_t *fd_in;
	pcap_t *fd_out;
	
	int ti_in, ti_out;
} dev;


struct config_values
{
	MACADDR_TYPE(mac_address);
   	IPADDR_TYPE(ip_address);
   	char essid[120];
   	char essid_prefix[120];
   	char wifi_iface[10];
   	int verbose;
   	int channel;
} config;

/* Access point structure */
struct ap_conf
{
	MACADDR_TYPE(bssid);
    MACADDR_TYPE(mac_address);
    IPADDR_TYPE(ip_address);
    unsigned char essid[33];
    int channel;
    int freq;
    int rate;
    int tx_power;
    unsigned short interval;
    u_int16_t capability;
    u_int64_t timestamp;
    int seq_ctrl; // we must track sequence number in a per-AP basis, if possible
    int nbpackets_ti;
    u_char rates_supp[EID_SUPPORTED_RATES_LENGHT];
};

struct monitor_fn_t {
	/* Device functions for received packets */
	void (*assoc_response)(struct monitor_fn_t *mfn, 
							u_char *pkt, int len, int rssi);
	void (*reassoc_response)(struct monitor_fn_t *mfn, 	
							u_char *pkt, int len, int rssi);
	void (*probe_response)(struct monitor_fn_t *mfn, 
							u_char *pkt, int len, int rssi);
	void (*authentication)(struct monitor_fn_t *mfn, 
							u_char *pkt, int len, int rssi);
	void (*beacon)(struct monitor_fn_t *mfn, 
							u_char *pkt, int len, int rssi);
	void (*data)(struct monitor_fn_t *mfn, 
							u_char *pkt, int len, int rssi);
	void (*ti_receive)(struct monitor_fn_t *mfn, 
							u_char *pkt, int len);

	void (*wifi_periodic)(struct monitor_fn_t *mfn, 
							u_char *pkt, int len);
	void (*wifi_ap_beacon)(struct monitor_fn_t *mfn);

	int (*recv_mi_wireless_frame)(struct monitor_fn_t *mfn, 
							u_char *pkt, int len, struct mif *mi, int rssi);
	int (*recv_ti_wireless_frame)(struct monitor_fn_t *mfn, 
							u_char *pkt, int len, struct mif *mi);

	void (*monitor_free)(struct monitor_fn_t *mfn);
   	void (*free)(struct monitor_fn_t *mfn);

   	void *mfn_priv;
   	struct tif *dv_ti;
   	struct mif *dv_mi;
   	void *evtimer;
   	int time_beacon;
	int rate;
};

int init_fcap(int argc, char** argv);
#endif
