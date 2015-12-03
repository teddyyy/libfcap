#include <string.h>
#include <arpa/inet.h>
#include <syslog.h>

#include "fcap.h"
#include "include/ieee802_11.h"
#include "monitor.h"
#include "utils.h"
#include "core.h"
#include "mlme.h"

int ap_get_seq_ctrl(struct ap_conf *ap)
{
    int s = ap->seq_ctrl++;
    ap->seq_ctrl %= 4096;
    return s;
}

struct sta_info* ap_search_client(struct ap_conf *ap, MACADDR_TYPE(mac_address))
{
    struct sta_info *c = ap->clist.first;
    
    /* Search client */
    if (c) {
        while (c && !is_same_mac(mac_address, c->mac_address)) 
			c = c->next;
    }

    return c;
}

void ap_update_client_rxinfo(struct ap_conf *ap, MACADDR_TYPE(mac_address), int rate, int rssi)
{
    struct sta_info *c = ap_search_client(ap, mac_address);
    if (c) {
		c->rate = rate;
        c->rssi = rssi;
    }   
}

static struct sta_info* ap_client_create(MACADDR_TYPE(mac_address))
{
    struct sta_info* c = (struct sta_info*) malloc (sizeof(struct sta_info));
    bzero(c, sizeof(struct sta_info));
    memcpy(c->mac_address, mac_address, 6); 

    return c;
}

static struct sta_info* ap_add_client(struct ap_conf *ap, MACADDR_TYPE(mac_address), MACADDR_TYPE(bssid))
{
    struct sta_info *client = ap_client_create(mac_address);
    memcpy(client->bssid, bssid, 6); 

	if (ap->clist.count == 0) 
    	ap->clist.first = client;    
	else 
    	ap->clist.last->next = client;    

    ap->clist.last = client;
    ap->clist.current = client;
	ap->clist.count++;

    return client;
}

int ap_auth_client(struct ap_conf *ap, MACADDR_TYPE(mac_address), MACADDR_TYPE(bssid))
{
    /* Check if client is already in the list */
    struct sta_info *c = ap_search_client(ap, mac_address);

    if (!c)
        c = ap_add_client(ap, mac_address, bssid);

    c->state = STA_AUTH_SUCCESS;
    memcpy(c->bssid, bssid, MACADDR_TYPE_SZ);

    return 1;
}

static int ap_assoc_client(struct ap_conf *ap, MACADDR_TYPE(mac_address), MACADDR_TYPE(bssid))
{
    /* Check if client is already authorized */
    struct sta_info *c = ap_search_client(ap, mac_address);
    if (!c || c->state <  STA_AUTH_SUCCESS)
        return 0;
       
    c->state = STA_ASSOC_SUCCESS;
    return 1;
}

static void ap_client_destroy(struct sta_info *client)
{
    if (client)
        free(client);
    client = NULL;
}

int ap_delete_client(struct ap_conf *ap, MACADDR_TYPE(mac_address))
{
    struct sta_info *c = ap->clist.first;
    struct sta_info *prev = NULL;

    /* Search client */
    if (c) {
        while (c && !is_same_mac(mac_address, c->mac_address)) {
            prev = c;
            c = c->next;
        }
    }

    if (c && is_same_mac(mac_address, c->mac_address)) {
        /* Arrange pointers */
        if (ap->clist.first == c) {
            ap->clist.first = c->next;
            ap->clist.current = ap->clist.first;
        }

        /* Client could be the only one */
        if (ap->clist.last == c) {
            ap->clist.last = prev;
            ap->clist.current = prev;
        }

        /* Client is in the middle */
        if (prev) {
            prev->next = c->next;
            ap->clist.current = prev;
        }
	
		ap->clist.count--;
        ap_client_destroy(c);

        return 1;
    }

    return 0;
}


void ap_free(struct ap_conf *ap)                                                          
{
    struct sta_info *c, *f;
    c = ap->clist.first;
    while (c)  {
        f = c;
        c = f->next;
        ap_client_destroy(f);
    }   
}


int ieee80211_assoc_build(u_char *pkt, int length, u_int16_t capability, 
							u_int16_t status, u_int16_t aid, u_char *rates_supp, 
							u_char *rates_supp_ext)
{
    int data_length = 0;
    unsigned char *p = (unsigned char *) pkt + length;

    /*  Capability: 2 bytes */
    memcpy(p + data_length, (unsigned char *) &capability, 2);
    data_length += 2;

    /*  Status code: 2 bytes */
    memcpy(p + data_length, (unsigned char *) &status, 2);
    data_length += 2;

    /* AID: 2 bytes */
    memcpy(p + data_length, (unsigned char *) &aid, 2);
    data_length += 2;

    /*  Supported rates */
    memset(p + data_length++, ELEMENT_ID_SUPPORTED_RATES, 1);
    memset(p + data_length++, sizeof(rates_supp), 1);
    memcpy(p + data_length, rates_supp, 1);
    data_length += sizeof(rates_supp);

    /*  Extended supported rates */
    memset(p + data_length++, ELEMENT_ID_EXT_SUPPORTED_RATES, 1);
    memset(p + data_length++, sizeof(rates_supp_ext), 1);
    memcpy(p + data_length, rates_supp_ext, 1);
    data_length += sizeof(rates_supp_ext);

    return length + data_length;
}

int ieee80211_auth_build(u_char *pkt, int length, u_int16_t auth_algo, 
						 u_int16_t auth_seq, u_int16_t status)
{
    int data_length = 0;
    unsigned char *p = (unsigned char *) pkt + length;

    /*  Authentification system */
    memcpy(p + data_length, (unsigned char *) &auth_algo, 2);
    data_length += 2;
    memcpy(p + data_length, (unsigned char *) &auth_seq, 2);
    data_length += 2;
    memcpy(p + data_length, (unsigned char *) &status, 2);
    data_length += 2;

    return length + data_length;
}

int ieee80211_mgmt_build(u_char *pkt, int length, int subtype,
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
        default:
            /*  fixed information first */
            memcpy(p + data_length, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 12);

            gettimeofday(&tv1, NULL);
            timestamp = tv1.tv_usec; //tv1.tv_sec*1000000 +
			for (i = 0; i < 8; i++)
                p[i + data_length] = (timestamp >> (i * 8)) & 0xFF;

            /*  interval */
            interval = BEACON_INTERVAL;
            p[data_length + 8] = interval & 0xFF;
            p[data_length + 9] = (interval >> 8) & 0xFF;

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
    if (len) {
        memcpy(p + data_length, essid, len); /* actual essid */
        data_length += len;
    }

    /*  Supported rates */
    memset(p + data_length++, ELEMENT_ID_SUPPORTED_RATES, 1);
    memset(p + data_length++, EID_SUPPORTED_RATES_LENGHT, 1);
    memcpy(p + data_length, rates_supp, EID_SUPPORTED_RATES_LENGHT);
    data_length += EID_SUPPORTED_RATES_LENGHT;

    /*  Channel Tag */
/*
    if (channel) {
        memset(p + data_length++, ELEMENT_ID_CHANNEL, 1); 
        memset(p + data_length++, sizeof(char), 1);
        memset(p + data_length++, channel, 1);
    }
*/

	//data_length += 1;

    return length + data_length;
}


int ieee80211_framectrl_build(u_char *pkt, int len,
            u_char *addr1, u_char *addr2, u_char *addr3,
            u_int16_t sc, u_int16_t fc, u_int16_t duration)
{
    struct mgmt_header_t *header = (struct mgmt_header_t *) pkt;
    header->fc = fc;
    header->duration = duration;
    header->seq_ctrl = sc; //sequence_ctrl; madwifi-ng does it for us!
    memcpy(header->da, addr1, 6);
    memcpy(header->sa, addr2, 6);
    memcpy(header->bssid, addr3, 6);

    return len + sizeof(struct mgmt_header_t);
}

void parse_mgmt_frame_body(const u_char *pkt, int len, 
							struct mgmt_body_t *body)
{
	int i;
	const u_char *p;
	u_char *f;
	u_char *tag = NULL;

	p = pkt + sizeof(struct mgmt_header_t);

	memset(body, '\0', sizeof(struct mgmt_body_t));
	memset(&body->ssid, '\0', sizeof(struct ssid_t));

	while (p < (pkt + len)) {
		u_char tag_num = p[0];
		u_char tag_len = p[1];
		tag = (u_char *)(p + 2);
		f = NULL;

		switch (tag_num) {
        case ELEMENT_ID_SSID:
			memcpy(&body->ssid.ssid, tag, tag_len);
            body->ssid.element_id = ELEMENT_ID_SSID;
            body->ssid.length = tag_len;
			break;
		default:
            f = NULL;
            break;
        }

        for (i = 0; f != NULL && i < tag_len; i++, f++) 
            *f = *(tag + i);
        
        p += 2 + tag_len;
        f = NULL;
    }
}

void handle_assoc_request(struct monitor_fn_t *mfn, const u_char *pkt, 
							int len, int rate, int rssi)
{
	struct mgmt_header_t *header = (struct mgmt_header_t *)pkt;
	struct ap_conf *ap = (struct ap_conf *)mfn->mfn_priv;

	if (is_same_mac(ap->mac_address, header->bssid)) {
        u_char h80211[4096];
        int pktlen = 0;
	
		printf("ST_ASSOC\tsmac: "f_MACADDR", dmac: "f_MACADDR", bssid: "f_MACADDR"\n", 
			MACADDR(header->sa), MACADDR(header->da), MACADDR(header->bssid));

		u_int16_t status = IEEE80211_STATUS_SUCCESS;
        u_int16_t aid = 0x0100;

        memset(h80211, 0, 4096);
        pktlen = ieee80211_framectrl_build(h80211, pktlen, header->sa, 
											ap->mac_address, ap->bssid, 
											ap_get_seq_ctrl(ap), 
											0x1000, 314);

		if (!ap_assoc_client(ap, header->sa, header->bssid)) {
			printf("not found authed client\n");
            status = IEEE80211_STATUS_UNSPECIFIED;
		}

		pktlen = ieee80211_assoc_build(h80211, pktlen, ap->capability, status,
										aid, ap->rates_supp, ap->rates_supp_ext);

		core_mi_send_frame(h80211, pktlen, RATE_6M/500000);

		syslog(LOG_DEBUG, "assoicated: "f_MACADDR" signal: % ddB Rate: %2d.%dMbps", 
				MACADDR(header->sa), rssi, rate / 2, 5 * (rate & 1));
	}
}

void handle_disassoc_request(struct monitor_fn_t *mfn, const u_char *pkt, 
								int len, int rssi)                        
{
    struct mgmt_header_t *header = (struct mgmt_header_t *) pkt;
    struct ap_conf *ap = (struct ap_conf *) mfn->mfn_priv;

    if (is_same_mac(ap->mac_address, header->bssid)) {
        printf("DISASSOC "f_MACADDR"", MACADDR(header->sa));
		ap_delete_client(ap, header->sa);
		syslog(LOG_DEBUG, "disassoicated: "f_MACADDR"", MACADDR(header->sa));
    }   
}

void handle_reassoc_request(struct monitor_fn_t *mfn, const u_char *pkt, 
							int len, int rate, int rssi)
{
	struct mgmt_header_t *header = (struct mgmt_header_t *)pkt;
	struct ap_conf *ap = (struct ap_conf *)mfn->mfn_priv;

	printf("ST_REASSOC\tsmac: "f_MACADDR", dmac: "f_MACADDR", bssid: "f_MACADDR"\n", 
			MACADDR(header->sa), MACADDR(header->da), MACADDR(header->bssid));

	struct sta_info *c = ap_search_client(ap, header->sa);

	if (is_same_mac(ap->mac_address, header->bssid) && c) {
		//ap_delete_client(ap, header->sa);
		handle_assoc_request(mfn, pkt, len, rate, rssi);
	}
}
     

void handle_auth_frame(struct monitor_fn_t *mfn, const u_char *pkt, 
							int len, int rssi)
{
	struct mgmt_header_t *header = (struct mgmt_header_t *)pkt;
	struct ap_conf *ap = (struct ap_conf *)mfn->mfn_priv;	

	printf("ST_AUTH\tsmac: "f_MACADDR", dmac: "f_MACADDR", bssid: "f_MACADDR"\n", 
			MACADDR(header->sa), MACADDR(header->da), MACADDR(header->bssid));

	if (is_same_mac(header->bssid, ap->mac_address) 
		&& !is_same_mac(header->sa, ap->mac_address)) {

		/* Add station to authorizated list */
        ap_auth_client(ap, header->sa, header->bssid);

		u_char h80211[4096];
		int pktlen = 0;

		memset(h80211, 0, 4096);
		pktlen = ieee80211_framectrl_build(h80211, pktlen, 
											header->sa, ap->mac_address, 
											ap->bssid, ap_get_seq_ctrl(ap), 
											0xb000, 314);

		pktlen = ieee80211_auth_build(h80211, pktlen, AUTH_ALGO_OPEN_SYSTEM,
										0x200, IEEE80211_STATUS_SUCCESS);

		core_mi_send_frame(h80211, pktlen, RATE_6M/500000);
	}
}
void handle_deauth_frame(struct monitor_fn_t *mfn, const u_char *pkt, 
							int len, int rssi)
{
	struct mgmt_header_t *header = (struct mgmt_header_t *)pkt;
	struct ap_conf *ap = (struct ap_conf *) mfn->mfn_priv;

	printf("ST_DEAUTH\tsmac: "f_MACADDR", dmac: "f_MACADDR", bssid: "f_MACADDR"\n", 
			MACADDR(header->sa), MACADDR(header->da), MACADDR(header->bssid));

	struct sta_info *c = ap_search_client(ap, header->sa);
    if (c)
        ap_delete_client(ap, header->sa);
          
	syslog(LOG_DEBUG, "deauthenticated: "f_MACADDR"", MACADDR(header->sa));
}

void handle_probe_request(struct monitor_fn_t *mfn, const u_char *pkt, 
							int len, int rssi)
{
	struct mgmt_header_t *header = (struct mgmt_header_t *)pkt;
	struct ap_conf *ap = (struct ap_conf *)mfn->mfn_priv;

	struct mgmt_body_t body_fields;
	parse_mgmt_frame_body(pkt, len, &body_fields);

	if (!body_fields.ssid.length || 
		((is_same_ssid(body_fields.ssid.ssid, ap->essid)) && 
		is_same_mac(header->bssid, BROADCAST))) {

		u_char h80211[4096];
		int pktlen = 0;

		memset(h80211, 0, 4096);
		pktlen = ieee80211_framectrl_build(h80211, pktlen, 
											header->sa, ap->mac_address, 
											ap->bssid, ap_get_seq_ctrl(ap), 
											0x5000, 314);

		pktlen = ieee80211_mgmt_build(h80211, pktlen, 0x50,
                        					ap->channel, ap->essid, ap->capability,
                        					ap->rates_supp, ap->rates_supp_ext);

		core_mi_send_frame(h80211, pktlen, RATE_6M/500000);
	}
}

void handle_data_frame(struct monitor_fn_t *mfn, const u_char *pkt,
                            int len, int rate, int rssi)
{
    struct mgmt_header_t *header = (struct mgmt_header_t *)pkt;
    struct ap_conf *ap = (struct ap_conf *)mfn->mfn_priv;

	if (is_same_mac(header->da, ap->mac_address) || (is_same_mac(header->da, BROADCAST))
		|| is_same_mac(header->bssid, ap->mac_address)) {
		
		u_int16_t fc = header->fc;
        fc = (fc & ~FC_TO_DS_BIT) | FC_FROM_DS_BIT;
        header->fc = fc;

		unsigned char h80211[4096];
        int trailer = 0;
        int offset = 0;
        u_int16_t ether_type;

		/* Destination mac address */
        memcpy(h80211, header->bssid, MACADDR_TYPE_SZ);
        offset += MACADDR_TYPE_SZ;
		/* Source mac address */
        memcpy(h80211 + offset, header->sa, MACADDR_TYPE_SZ);
        offset += MACADDR_TYPE_SZ;
		/* Ether type */
        memcpy(h80211 + offset, pkt + sizeof(struct mgmt_header_t) + 6, sizeof(u_int16_t));
        offset += sizeof(u_int16_t);

		memcpy(&ether_type, pkt + sizeof(struct mgmt_header_t) + 6, 2); 
        ether_type = ntohs(ether_type);

		// discard ipv6 packet
		if (ether_type == 0x86dd)
			return; 

		if (len <= sizeof(struct mgmt_header_t) + 8)
            return;	

		/* Copy frame body */
        memcpy(h80211 + 14, pkt + sizeof(struct mgmt_header_t) + 8, 
				len - (sizeof(struct mgmt_header_t) + 8));
        len = len- sizeof(struct mgmt_header_t) - 8 + 14; 

		/* ethernet frame must be atleast 60 bytes without fcs */
        if (len < 60) {
            trailer = 60 - len;
            bzero(h80211 + len, trailer);
            len += trailer;
        }   

		core_ti_send_frame(h80211, len);

		if (is_same_mac(header->da, ap->mac_address)) {
			ap_update_client_rxinfo(ap, header->sa, rate, rssi);
		}
	}
}
