#include <stdlib.h>
#include <string.h>

#include "ieee802_11.h"
#include "fcap.h"
#include "monitor.h"

int proto80211_packet_recv(struct monitor_fn_t *mfn, u_char *pkt, 
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

struct monitor_fn_t *mfn_alloc(int size)
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

   	//mfn->wifi_packet_recv = proto80211_packet_recv;
   	//mfn->wifi_packet_ti_recv = proto80211_packet_ti_recv;
   	//mfn->free = wfn_free;

   	return mfn;
}
