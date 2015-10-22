#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#include "ieee802_11.h"

#include "fcap.h"
#include "core.h"
#include "monitor.h"

static int proto80211_packet_recv(struct monitor_fn_t *mfn, u_char *pkt, 
							int len, struct mif *mi, int rssi)
{
	/*  802.11 header */
	struct mgmt_header_t *header = (struct mgmt_header_t *) pkt;

	switch(FC_TYPE(header->fc)) {
		case T_MGMT:
			switch (FC_SUBTYPE(header->fc)) {
				case ST_PROBE_REQUEST:
					printf("probe req\n");
					break;
			}
		case T_CTRL:
			switch (FC_SUBTYPE(header->fc)) {
				case CTRL_ACK:
					printf("ctrl ack\n");
					break;
			}
        case T_DATA:
			switch (FC_SUBTYPE(header->fc)) {
				case DATA_DATA:
					printf("data data\n");
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
   	//mfn->wifi_packet_ti_recv = proto80211_packet_ti_recv;
   	//mfn->free = wfn_free;

   	return mfn;
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

	mfn->mon_tx_tun_frame = recv_frame_tun_to_mon;
	mfn->time_beacon = BEACON_INTERVAL_TIMER;

	ap = (struct ap_conf*) mfn->mfn_priv;
	ap_init(ap, config);

	return mfn;
}

