#include <stdio.h>
#include <stdlib.h>
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

	//printf("RX: Rate: %2d.%dMbps, Freq: %dMHz, Signal:% ddBm, Noise: %ddBm\n",
	//		ri.rate / 2, 5*(ri.rate & 1), ri.channel, ri.power, ri.noise);

	if (_mfn->mon_frame_handler) {
		_mfn->rate = ri.rate;
		_mfn->mon_frame_handler(_mfn, p, len, mi, ri.power, subtype);
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

static void ap_recv_message(struct sockaddr_in addr, u_char *buf, int len)
{
	struct csahdr *csahdr;
	csahdr = (struct csahdr *)buf;

	printf("new channel  %d\n", csahdr->channel);
    printf("type %x\n", csahdr->type);
	printf("target mac address  "f_MACADDR"\n", MACADDR(csahdr->tgt_addr));

	if (csahdr->type == CSAOFFER)
		if (_mfn->csa_beacon)
			_mfn->csa_beacon(_mfn, csahdr->tgt_addr, csahdr->channel);
		
	return;
}

void ap_msg_accept(int fd, short event, void *arg)
{
	int ret, ctrler_fd;
	struct sockaddr_in ctrler_addr;
	socklen_t len = sizeof(ctrler_addr);
	u_char buf[2048];

	ctrler_fd = accept(fd, (struct sockaddr *)&ctrler_addr, &len);
	if (ctrler_fd == -1) {
		fprintf(stderr, "Accept failed\n");
		return;
	}

	printf("%s\n", inet_ntoa(ctrler_addr.sin_addr));

	if (setnonblock(ctrler_fd) < 0)
		fprintf(stderr, "Failed to set client socket\n");

	memset(buf, 0, sizeof(buf));
	ret = read(ctrler_fd, buf, sizeof(buf));
	if (ret <= 0) {
		fprintf(stderr, "failed to read fd\n");
		return;
	}

	ap_recv_message(ctrler_addr, buf, sizeof(buf));

	close (ctrler_fd);	
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
