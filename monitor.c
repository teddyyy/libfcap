#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

#include "include/ieee802_11.h"

#include "fcap.h"
#include "core.h"
#include "monitor.h"
#include "mlme.h"

static void mon_periodic_beacon(struct monitor_fn_t *mfn)
{
	struct ap_conf *ap = (struct ap_conf*) mfn->mfn_priv;
	u_char h80211[4096];
	int len = 0;

	memset(h80211, 0, 4096);

	len = ieee80211_framectrl_build(h80211, len, BROADCAST, 
						ap->mac_address, ap->bssid, 
						ap_get_seq_ctrl(ap), 0x8000, 314);

	len = ieee80211_mgmt_build(h80211, len, 0x80,
						ap->channel, ap->essid, ap->capability,
						ap->rates_supp, ap->rates_supp_ext);

	core_mi_send_frame(h80211, len, RATE_6M/500000);

}

static void mon_csa_beacon(struct monitor_fn_t *mfn,
							MACADDR_TYPE(addr), u_int8_t channel)
{
	struct ap_conf *ap = (struct ap_conf*) mfn->mfn_priv;
	u_char h80211[4096];
	int len = 0;
	int switch_count = CSASWITCHCOUNT;

	memset(h80211, 0, 4096);

	while (switch_count > 0) {
		len = ieee80211_framectrl_build(h80211, len, addr,
							ap->mac_address, ap->bssid, 
							ap_get_seq_ctrl(ap), 0x8000, 314);
	
		len = ieee80211_mgmt_build(h80211, len, 0x80,
        	                ap->channel, ap->essid, ap->capability,
            	            ap->rates_supp, ap->rates_supp_ext);

		h80211[len++] = 37;					// element id
		h80211[len++] = 3;					// length
		h80211[len++] = 0;					// channel switch mode
		h80211[len++] = channel;			// new channel number
		h80211[len++] = switch_count;		// new channel number

		core_mi_send_frame(h80211, len, RATE_6M/500000);

		switch_count--;
	}

	return;
}

static int proto80211_packet_recv(struct monitor_fn_t *mfn, 
									const u_char *pkt, int len, 
									struct mif *mi, int rssi, int subtype)
{
	if (len >= 24) {
		switch(subtype) {
		case 0x00:
			handle_assoc_request(mfn, pkt, len, rssi);
			break;
		case 0x20:
			handle_reassoc_request(mfn, pkt, len, rssi);
			break;
		case 0x40:
			handle_probe_request(mfn, pkt, len, rssi);
			break;
		case 0xB0:
			handle_auth_frame(mfn, pkt, len, rssi);
			break;
		case 0x08:
			handle_data_frame(mfn, pkt, len, rssi);
			break;
		}
	}

	return 0;
}

static struct monitor_fn_t *mfn_alloc(int size)
{
	struct monitor_fn_t *mfn;
   	void *priv;

   	/* Allocate wif & private state */
   	mfn = malloc(sizeof(struct monitor_fn_t));
   	if (!mfn)
       	return NULL;
   	memset(mfn, 0, sizeof(struct monitor_fn_t));

   	if (size) {
       	priv = malloc(size);
       	if (!priv) {
           		free(mfn);
           		return NULL;
       	}
       	memset(priv, 0, size);
       	mfn->mfn_priv = priv;
   	}

   	mfn->mon_frame_handler = proto80211_packet_recv;

   	return mfn;
}

static int recv_frame_tun_to_mon(struct monitor_fn_t *mfn, u_char *pkt,
                                            int len, struct mif *mi)
{
    /*  802.11 header for sending operations, reusable */
    unsigned char h80211[4096];

    if (len < 38)
        return -1;

    struct ap_conf *ap = (struct ap_conf *) mfn->mfn_priv;

    int packet_length = len;

    memcpy(h80211, IEEE80211_LLC_SNAP, 32); // copy IEEE80211 + LLC
    memcpy(h80211 + 32, pkt + 14, packet_length - 14); // frame body without etherframe header
    memcpy(h80211 + 30, pkt + 12, sizeof(u_int16_t)); // ether type

    u_int16_t ether_type;
    memcpy(&ether_type, pkt + 12, 2);
    ether_type = ntohs(ether_type);

	if (ether_type == 0x86dd)
		return -1;

    h80211[1] |= 0x02; /* FC_DATA_DATA */

    memcpy(h80211 + 10, ap->bssid, MACADDR_TYPE_SZ); /* BSSID */
    memcpy(h80211 + 16, pkt + 6, 6); /* SRC_MAC */
    memcpy(h80211 + 4, pkt, 6); /* DST_MAC */

    packet_length += (32 - 14); /* 32=IEEE80211+LLC/SNAP; 14=SRC_MAC+DST_MAC+TYPE */

    core_mi_send_frame(h80211, packet_length, RATE_54M/500000);

    return 0;
}

static void ap_init(struct ap_conf *ap, struct config_values *config)
{
	printf("%s\n", __func__);
   	memset(ap, 0, sizeof(struct ap_conf));

   	memcpy(ap->bssid, config->mac_address, MACADDR_TYPE_SZ);
   	memcpy(ap->mac_address, config->mac_address, MACADDR_TYPE_SZ);
   	memcpy(ap->essid, config->essid, strlen(config->essid));
   	memcpy(ap->ip_address, config->ip_address, IPADDR_TYPE_SZ);
   	ap->channel = config->channel;

   	ap->interval = 0x064;
   	ap->capability = 0x2100;
   	ap->seq_ctrl = 0;

   	int i = 0;
   	memset(ap->rates_supp, 0, sizeof(ap->rates_supp));
   	memset(ap->rates_supp + i++, RATE_6M/500000, 1);
   	memset(ap->rates_supp + i++, RATE_9M/500000, 1);
   	memset(ap->rates_supp + i++, RATE_12M/500000, 1);
   	memset(ap->rates_supp + i++, RATE_18M/500000, 1);
   	memset(ap->rates_supp + i++, RATE_24M/500000, 1);
   	memset(ap->rates_supp + i++, RATE_36M/500000, 1);
   	memset(ap->rates_supp + i++, RATE_48M/500000, 1);
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

	mfn->periodic_beacon = mon_periodic_beacon;
	mfn->csa_beacon	= mon_csa_beacon;
	mfn->mon_tx_tun_frame = recv_frame_tun_to_mon;
	mfn->time_beacon = BEACON_INTERVAL_TIMER;

	ap = (struct ap_conf*) mfn->mfn_priv;
	ap_init(ap, config);

	return mfn;
}

