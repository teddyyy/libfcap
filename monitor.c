#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

#include "ieee802_11.h"

#include "fcap.h"
#include "core.h"
#include "monitor.h"

static int ap_get_seq_ctrl(struct ap_conf *ap)
{
    int s = ap->seq_ctrl++;
    ap->seq_ctrl %= 4096;
    return s;
}

static int ieee80211_mgmt_build(u_char *pkt, int length, int subtype, 
								int channel, unsigned char *essid, 
								u_int16_t capability, u_char *rates_supp, 
								u_char *rates_supp_ext)
{
    int data_length = 0;
    unsigned short interval;
    struct timeval tv1;
    u_int64_t timestamp = 0;
    int i;

    /*  setting pointer to the beginning of the packet */
    unsigned char *p = (unsigned char *) pkt + length;

    switch (subtype) {
    
        case ST_ASSOC_REQUEST:
            /*  Capability: 2 bytes */
            memcpy(p + data_length, &capability, sizeof(capability));
            data_length += sizeof(capability);
            /*  interval */
            interval = BEACON_INTERVAL;
            p[data_length++] = interval & 0xFF;
            p[data_length++] = (interval >> 8) & 0xFF;
            break;
		case ST_PROBE_REQUEST:
            break;
        case 0x80:
            /*  fixed information first */
            memcpy(p + data_length, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 12); 
        
            gettimeofday(&tv1, NULL);
            timestamp = tv1.tv_usec; //tv1.tv_sec*1000000 + 
        
            for (i = 0; i < 8; i++) 
                p[i + data_length] = (timestamp >> (i*8)) & 0xFF;
        
            /*  interval */
            interval = BEACON_INTERVAL;
            p[data_length+8] = interval & 0xFF;
            p[data_length+9] = (interval >> 8) & 0xFF;
        
            /*  end fixed info */
            data_length += 10;
        
            /*  Capability: 2 bytes */
            memcpy(p + data_length, &capability, sizeof(capability));
            data_length += sizeof(capability);
        
            break;
    }
    
    /*  ESSID */
    int len = strlen((char*)essid);
    p[data_length++] = ELEMENT_ID_SSID; 
    p[data_length++] = len; /* essid tag  */
    if (len) 
    {
        memcpy(p + data_length, essid, len); /* actual essid */
        data_length += len;
    }

	/*  Supported rates */
    memset(p + data_length++, ELEMENT_ID_SUPPORTED_RATES, 1); 
    memset(p + data_length++, EID_SUPPORTED_RATES_LENGHT, 1); 
    memcpy(p + data_length, rates_supp, EID_SUPPORTED_RATES_LENGHT); 
    data_length += EID_SUPPORTED_RATES_LENGHT;
    
    /*  Channel Tag */
    if (channel)
    {
        memset(p + data_length++, ELEMENT_ID_CHANNEL, 1); /* channel tag  */
        memset(p + data_length++, sizeof(char), 1); 
        memset(p + data_length++, channel, 1); 
    }

    /*  Extended supported rates */
    memset(p + data_length++, ELEMENT_ID_EXT_SUPPORTED_RATES, 1); 
	memset(p + data_length++, EID_SUPPORTED_RATES_EXT_LENGHT, 1); 
    memcpy(p + data_length, rates_supp_ext, EID_SUPPORTED_RATES_EXT_LENGHT); 
    data_length += EID_SUPPORTED_RATES_EXT_LENGHT;

    return length + data_length;
}


static int ieee80211_framectrl_build(u_char *pkt, int len, 
			u_char *addr1, u_char *addr2, u_char *addr3, 
			u_int16_t sc, u_int16_t fc, u_int16_t duration)
{
    struct mgmt_header_t *header = (struct mgmt_header_t *) pkt;
    header->fc = 0x8000; 
    header->duration = duration;
    header->seq_ctrl = sc; //sequence_ctrl; madwifi-ng does it for us!
    memcpy(header->da, addr1, 6); 
    memcpy(header->sa, addr2, 6); 
    memcpy(header->bssid, addr3, 6); 

    return len + sizeof(struct mgmt_header_t);
}


static void mon_periodic_beacon(struct monitor_fn_t *mfn)
{
	struct ap_conf *ap = (struct ap_conf*) mfn->mfn_priv;
	u_char h80211[4096];
	int len = 0;

	memset(h80211, 0, 4096);

	len = ieee80211_framectrl_build(h80211, len, BROADCAST, 
						ap->mac_address, ap->bssid, 
						ap_get_seq_ctrl(ap), FC_MGMT_BEACON, 314);

	len = ieee80211_mgmt_build(h80211, len, 0x80,
						ap->channel, ap->essid, ap->capability,
						ap->rates_supp, ap->rates_supp_ext);

	core_mi_send_frame(h80211, len, RATE_6M/500000);

}

static int proto80211_packet_recv(struct monitor_fn_t *mfn, 
									const u_char *pkt, int len, 
									struct mif *mi, int rssi)
{
	/*  802.11 header */
	struct mgmt_header_t *header = (struct mgmt_header_t *) pkt;

	if (len >= 24) {

		switch (FC_SUBTYPE(header->fc)) {
        case 0x0:
            printf("Recdived frame type is association request ");
			printf("bssid:"f_MACADDR"\t dst: "f_MACADDR"\t src: "f_MACADDR"\n",
                                            MACADDR(header->bssid),
                                            MACADDR(header->da), MACADDR(header->sa));
            break;
        case 0x1:
            printf("Recdived frame type is association response ");
            printf("bssid:"f_MACADDR"\t dst: "f_MACADDR"\t src: "f_MACADDR"\n",
                                            MACADDR(header->bssid),
                                            MACADDR(header->da), MACADDR(header->sa));
            break;
        case 0x4:
            printf("Recdived frame type is probe request ");
            printf("bssid:"f_MACADDR"\t dst: "f_MACADDR"\t src: "f_MACADDR"\n",
                                            MACADDR(header->bssid),
                                            MACADDR(header->da), MACADDR(header->sa));
            break;
        case 0x5:
            printf("Recdived frame type is probe response ");
            printf("bssid:"f_MACADDR"\t dst: "f_MACADDR"\t src: "f_MACADDR"\n",
                                            MACADDR(header->bssid),
                                            MACADDR(header->da), MACADDR(header->sa));
            break;
        case 0x8:
            printf("Recdived frame type is beacon ");
            printf("bssid:"f_MACADDR"\t dst: "f_MACADDR"\t src: "f_MACADDR"\n",
                                            MACADDR(header->bssid),
                                            MACADDR(header->da), MACADDR(header->sa));
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

	mfn->periodic_beacon = mon_periodic_beacon;
	mfn->mon_tx_tun_frame = recv_frame_tun_to_mon;
	mfn->time_beacon = BEACON_INTERVAL_TIMER;

	ap = (struct ap_conf*) mfn->mfn_priv;
	ap_init(ap, config);

	return mfn;
}

