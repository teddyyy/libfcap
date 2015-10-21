#include <event.h>
#include <signal.h>
#include <pcap.h>
#include <pthread.h>

#include "fcap.h"
#include "core.h"
#include "common.h"
#include "interface.h"
#include "tun.h"
#include "monitor.h"

/* global value */
time_t init_timer = 0;
struct event_base* eb = NULL;

void sigint_handler()
{
	if (eb) 
		event_base_free(eb);

	if (_mi_out > 0)
		mi_close(_mi_out);
	
	if (_ti_out > 0)
		ti_close(_ti_out);

	if (_mfn)
		_mfn->free(_mfn);

	exit (0);
}

static int recv_frame_tun_to_mon(struct monitor_fn_t *mfn, u_char *pkt,
                                            int len, struct mif *mi)
{
	/*  802.11 header for sending operations, reusable */
    unsigned char h80211[4096];
	int offset = 0;

	printf("%s\n", __func__);
	if (len < 38) 
		return -1;

	struct ap_conf *ap = (struct ap_conf *) mfn->mfn_priv;

	int packet_length = len;

	memcpy(h80211, IEEE80211_LLC_SNAP, 32);
	memcpy(h80211 + 32, pkt + 14, packet_length - 14);

	/* Ether type */
    memcpy(h80211 + 30, pkt + 12, sizeof(u_int16_t));
    offset += sizeof(u_int16_t);

	u_int16_t ether_type;
    memcpy(&ether_type, pkt + 12, 2);
    ether_type = ntohs(ether_type);

    h80211[1] |= 0x02; /* FC_DATA_DATA */

	memcpy(h80211 + 10, ap->bssid, MACADDR_TYPE_SZ); /* BSSID */

	memcpy(h80211 + 16, pkt + 6, 6); /* SRC_MAC */
    memcpy(h80211 + 4, pkt, 6); /* DST_MAC */

    packet_length += (32 - 14); /* 32=IEEE80211+LLC/SNAP; 14=SRC_MAC+DST_MAC+TYPE */

	mi_send_frame(h80211, packet_length, RATE_54M/500000);

	return 0;
}


void ap_init(struct ap_conf *ap, struct config_values *config)
{
	printf("%s\n", __func__);
   	memset(ap, 0, sizeof(struct ap_conf));

   	memcpy(ap->bssid, config->mac_address, MACADDR_TYPE_SZ);
   	memcpy(ap->mac_address, config->mac_address, MACADDR_TYPE_SZ);
   	memcpy(ap->essid, config->essid, strlen(config->essid));
   	memcpy(ap->ip_address, config->ip_address, IPADDR_TYPE_SZ);
   	ap->channel = config->channel;

   	ap->interval = 0x064;
   	ap->capability = 0x401;
   	ap->seq_ctrl = 0;

   	int i = 0;
   	memset(ap->rates_supp, 0, sizeof(ap->rates_supp));
   	memset(ap->rates_supp + i++, RATE_1M/500000 | 0x80, 1);
   	memset(ap->rates_supp + i++, RATE_2M/500000 | 0x80, 1);
   	memset(ap->rates_supp + i++, RATE_5_5M/500000 | 0x80, 1);
   	memset(ap->rates_supp + i++, RATE_11M/500000 | 0x80, 1);
   	memset(ap->rates_supp + i++, RATE_18M/500000, 1);
   	memset(ap->rates_supp + i++, RATE_24M/500000, 1);
   	memset(ap->rates_supp + i++, RATE_36M/500000, 1);
   	memset(ap->rates_supp + i++, RATE_54M/500000, 1);
}

struct monitor_fn_t *init_function(struct config_values *config)
{
	struct monitor_fn_t *mfn;
	struct ap_conf *ap;

	printf("%s\n", __func__);
	mfn = mfn_alloc(sizeof(struct ap_conf));

	if (!mfn)
		return NULL;
/*
	mfn->assoc_response = ap_assoc_response;
	mfn->reassoc_response = ap_reassoc_response;
	mfn->probe_response = ap_probe_response;
	mfn->authentication = ap_authentication;
	mfn->beacon = ap_beacon;
	mfn->data = ap_data;
	mfn->ti_receive = ap_ti_receive;

*/
	mfn->recv_ti_wireless_frame = recv_frame_tun_to_mon;
	mfn->time_beacon = BEACON_INTERVAL_TIMER;

	ap = (struct ap_conf*) mfn->mfn_priv;
	ap_init(ap, config);

	return mfn;
}

/*  main entry */
int init_fcap(int argc, char** argv)
{
	pthread_t th;
	struct event evti, evtimer;
	struct timeval tv;

	printf("%s\n", __func__);

	init_timer = time(NULL);

	signal(SIGINT, sigint_handler);

	/* set default config value */
	memset(&config, '\0', sizeof(struct config_values));
	strcpy(config.wifi_iface, DEFAULT_WIRELESS_IFACE);
	printf("%s\n", config.wifi_iface);
    config.channel = DEFAULT_CHANNEL;
	printf("%d\n", config.channel);
    ato_ip_address(config.ip_address, DEFAULT_IP_ADDRESS);
	printf("%s\n", DEFAULT_IP_ADDRESS);
	strcpy(config.essid, DEFAULT_ESSID);
	printf("%s\n", config.essid);
	ato_mac_address(config.mac_address, DEFAULT_MAC_ADDRESS);
	printf("%s\n", DEFAULT_MAC_ADDRESS);

    /* open output and input interface */
	_mi_out = (struct mif *)mi_open(config.wifi_iface);
	if (!_mi_out)
		return 1;
	dev.fd_out = mi_fd(_mi_out);

	/* Same interface for input and output */
    _mi_in = _mi_out;
    dev.fd_in = dev.fd_out;

	/* open output and input tap interface */
    _ti_out = (struct tif *) ti_open(NULL);
    if (!_ti_out)
       	return 1;
    dev.ti_out = tun_fd(_ti_out);

	/* Same interface for input and output */
    _ti_in = _ti_out;
    dev.ti_in = dev.ti_out;

	// set mac address and interface up
	ti_set_mac(_ti_in, config.mac_address);
	ti_set_up(_ti_in);

	/* drop privileges */
    setuid(getuid());

    if (dev.fd_in == NULL) {
      	perror("open");
     	exit (1);
    }

	_mfn = (struct monitor_fn_t *)init_function(&config);
	_mfn->dv_ti = _ti_out;

	// start posix thread
	pthread_create(&th, NULL, frame_monitor, NULL);
	
	/* Initalize the event library */
    eb = event_init();

	/* Initalize events */
    event_set(&evti, dev.ti_in, EV_READ, ti_recv_frame, &evti);

	/* Add it to the active events, without a timeout */
    event_add(&evti, NULL);

	if (_mfn->time_beacon) {
		evtimer_set(&evtimer, periodic_func, &evtimer);
		tv.tv_usec = _mfn->time_beacon;
       	tv.tv_sec = 0;
       	evtimer_add(&evtimer, &tv);
    }

	event_dispatch();
	pthread_join(th, NULL);

	return 0;
}
