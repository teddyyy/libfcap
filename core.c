#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <arpa/inet.h>  
#include <event.h>
#include <errno.h>
#include <fcntl.h>

#include "fcap.h"
#include "core.h"
#include "interface.h"
#include "tun.h"
#include "monitor.h"
#include "mlme.h"
#include "include/radiotap.h"
#include "include/ieee802_11.h"

struct event_arg {
	struct event ev;
	void *arg;
};

int setnonblock(int fd)
{
    int flags;

    flags = fcntl(fd, F_GETFL);
    if (flags < 0)  return flags;
    flags |= O_NONBLOCK;
    if (fcntl(fd, F_SETFL, flags) < 0) return -1; 

    return 0;
}


// pkt encapsulated radiotap header
int core_mi_send_frame(void *buf, size_t count, int rate)
{
	struct mif *mi = _mi_out;
	struct tx_info txinfo;

	txinfo.ti_rate = rate;

	if (mi->write(mi, buf, count, &txinfo) < 0)
		return -1;

	return 0;
}


// pktin --> mon --> frame translate --> tap
static void core_mi_recv_frame(const struct pcap_pkthdr *pkthdr, const u_char *pkt)
{
   	int ret, subtype, len;
	struct ieee80211_radiotap_iterator rti;
	u16 hlen;
	struct rx_info ri;
	struct mif *mi = _mi_in;
	const u_char *p, *rtpkt = pkt;

	if (pkthdr->len < 62)
		return;

	// restore pointer and length
	p = rtpkt;
	len = pkthdr->caplen;

	// extract radiotap headder
	hlen = rtpkt[2] + (rtpkt[3] << 8);

	ieee80211_radiotap_iterator_init(&rti, 
		(struct ieee80211_radiotap_header *)rtpkt, pkthdr->len - (hlen + HEADERLENGTH));
	
	while ((ret = ieee80211_radiotap_iterator_next(&rti)) == 0) {
            switch (rti.this_arg_index) {
            case IEEE80211_RADIOTAP_RATE:
                ri.rate = (*rti.this_arg);
                break;

            case IEEE80211_RADIOTAP_CHANNEL:
                ri.channel = le16_to_cpu(*((u16 *)rti.this_arg));
                break;
	
			case IEEE80211_RADIOTAP_DBM_ANTSIGNAL:
				ri.power = (*rti.this_arg);
				break;

			case IEEE80211_RADIOTAP_DBM_ANTNOISE:
				ri.noise = (*rti.this_arg);
				break;
			 case IEEE80211_RADIOTAP_FLAGS:
				if (*rti.this_arg & IEEE80211_RADIOTAP_F_FCS)
					len -= 4;
				if (*rti.this_arg & IEEE80211_RADIOTAP_F_RX_BADFCS)
					return;
				
				break;
            }
	}

	// extract subtype field
	subtype = p[hlen];

	//if ((subtype == 0xb0) || (subtype == 0x00) || (subtype == 0x20))
	//	p += 25;	

	// decap radiotap header
	p += rti.max_length;
	len -= rti.max_length;

	if (_mfn->mon_frame_handler) {
		_mfn->rate = ri.rate;
		_mfn->mon_frame_handler(_mfn, p, len, mi, ri.rate, ri.power, subtype);
	}

}

// pkt encapsulated ether header
int core_ti_send_frame(void *buf, size_t count)
{
	struct tif *ti = _ti_in;

	if (ti->write(ti, buf, count) < 0) 
		return -1;

	return 0;
}

// pktin --> tap --> frame translate --> mon
void core_ti_recv_frame(int fd, short event, void *arg)
{
	unsigned char buf[4096];
   	int len;
   	struct event *ev = arg;

	event_add(ev, NULL);

	struct mif *mi = _mi_in;
	struct tif *ti = _mfn->dv_ti;

	len = ti->read(ti, buf, sizeof(buf));

	if (_mfn->mon_tx_tun_frame)
		_mfn->mon_tx_tun_frame(_mfn, buf, len, mi);
}

/* Periodic function */
void periodic_func(int fd, short event, void *arg)
{
	struct timeval tv;
	struct event_arg *evarg = arg;

	if (_mfn->time_beacon) {
		tv.tv_usec = _mfn->time_beacon % 1000000;
		tv.tv_sec = _mfn->time_beacon / 1000000;
		evtimer_add(&evarg->ev, &tv);
   	}

	if (_mfn->periodic_beacon)
		_mfn->periodic_beacon(_mfn);
}

static int ap_recv_message(int fd)
{
	int ret;
	u_char buf[2048];
	struct csahdr *csahdr;
	struct ap_conf *ap = (struct ap_conf*)_mfn->mfn_priv;
	struct sta_info *c;

 	if (setnonblock(fd) < 0)
        fprintf(stderr, "Failed to set nonblock\n");

	memset(buf, 0, sizeof(buf));
    ret = read(fd, buf, sizeof(buf));
    if (ret <= 0) {
        fprintf(stderr, "failed to read fd\n");
        return -1;
    }

	csahdr = (struct csahdr *)buf;

	printf("new channel  %d\n", csahdr->channel);
    printf("type %x\n", csahdr->type);
	printf("target mac address  "f_MACADDR"\n", MACADDR(csahdr->tgt_addr));

	if (csahdr->type == CSASENDOFFER) {
		if (_mfn->csa_beacon) {
			printf("offer1\n");
			_mfn->csa_beacon(_mfn, csahdr->tgt_addr, csahdr->channel);
			csahdr->type = CSACOMPLETE;
			write(fd, csahdr, sizeof(struct csahdr));

			c = ap_search_client(ap, csahdr->tgt_addr);
    		if (c) {
        		ap_delete_client(ap, csahdr->tgt_addr);
				syslog(LOG_DEBUG, "deauthenticated: "f_MACADDR"", MACADDR(csahdr->tgt_addr)); 
			}
		}
	} 
	else if (csahdr->type == CSAASSOCOFFER) {
		printf("offer2\n");
		ap_auth_client(ap, csahdr->tgt_addr, ap->bssid); 
		syslog(LOG_DEBUG, "assoicated: "f_MACADDR"", MACADDR(csahdr->tgt_addr)); 

		csahdr->type = CSAASSOCED;
		write(fd, csahdr, sizeof(struct csahdr));
	}

	close(fd);

	return -1;
}

void ap_msg_accept(int fd, short event, void *arg)
{
	int ctrler_fd;
	struct sockaddr_in ctrler_addr;
	socklen_t len = sizeof(ctrler_addr);

	ctrler_fd = accept(fd, (struct sockaddr *)&ctrler_addr, &len);
	if (ctrler_fd == -1) {
		fprintf(stderr, "Accept failed\n");
		return;
	}

	printf("%s\n", inet_ntoa(ctrler_addr.sin_addr));

	ap_recv_message(ctrler_fd);

	close(ctrler_fd);
}

void* frame_monitor(void* arg)
{
	struct pcap_pkthdr *hdr;
	const u_char *pkt;
	int ret;

	printf("%s\n", __func__);

	for (;;) {
		ret = pcap_next_ex(dev.fd_in, &hdr, &pkt);

		if (ret == -2)
			break;

		if (ret == -1) {
			fprintf(stderr, "pcap_next_ex failure\n");
			break;
		}

		if (ret == 1) 
			core_mi_recv_frame(hdr, pkt);	
	}	

	return 0;
}

void *push_sta_info(void *arg)
{

	while (1) {
		if (_mfn->mfn_priv) {
			struct ap_conf *ap = (struct ap_conf *)_mfn->mfn_priv;
			struct sta_info *c = ap->clist.first;

			if (c) {
				printf("%s\n", __func__);
				while (c && c->rssi != 0) {
					syslog(LOG_DEBUG, "data: "f_MACADDR" signal: % ddB Rate: %2d.%dMbps",
                				MACADDR(c->mac_address), c->rssi, c->rate / 2, 5 * (c->rate & 1));
					c = c->next;
				}
			}

			sleep (20);
		}
	}

	return 0;
}
