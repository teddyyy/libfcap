#include <stdio.h>
#include <stdlib.h>
#include <net/ethernet.h>
#include <event.h>
#include <errno.h>

#include "fcap.h"
#include "core.h"
#include "interface.h"
#include "tun.h"
#include "radiotap.h"

struct event_arg {
	struct event ev;
	void *arg;
};

/* Monitor interface frame send/recv function */
// pkt encapsulated 802.11 header
int mi_send_frame(void *buf, size_t count, int rate)
{
	struct mif *mi = _mi_out;
	struct tx_info txinfo;

	txinfo.ti_rate = rate;

	if (mi->write(mi, buf, count, &txinfo) < 0)
		return -1;

	return 0;
}

// pktin --> mon --> frame translate --> tap
void mi_recv_frame(u_char *argc, const struct pcap_pkthdr *pkthdr, const u_char *pkt)
{
	unsigned char buf[4096];
   	int n, len, bytes, n80211HeaderLength = HEADERLENGTH;
	struct ieee80211_radiotap_iterator rti;
	u16 hlen;
	struct rx_info ri;
	struct mif *mi = _mi_in;
	const u_char *rtpkt = pkt;

	// extract radiotap headder
	// based on packetspammer by andy green
	hlen = rtpkt[2] + (rtpkt[3] << 8);

	bytes = pkthdr->len - (hlen + n80211HeaderLength);

	ieee80211_radiotap_iterator_init(&rti, 
		(struct ieee80211_radiotap_header *)rtpkt, bytes);
	
	while ((n = ieee80211_radiotap_iterator_next(&rti)) == 0) {

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

            }
	}
	printf("RX: Rate: %2d.%dMbps, Freq: %dMHz, Signal:% ddBm, Noise: %ddBm\n",
			ri.rate / 2, 5*(ri.rate & 1), ri.channel, ri.power, ri.noise);

	len = pkthdr->len;
/*
	if (_mfn->recv_mi_wireless_frame) {
		_mfn->rate = ri.rate;
		_mfn->recv_mi_wireless_frame(_mfn, buf, len, mi, ri.power);
	}
*/
	proto80211_packet_recv(_mfn, buf, len, mi, ri.power);
}

/* Tap interface frame send/recv function */
// pkt encapsulated ether header
int ti_send_frame(void *buf, size_t count)
{
	struct tif *ti = _ti_in;

	if (ti->write(ti, buf, count) < 0) 
		return -1;

	return 0;
}

// pktin --> tap --> frame translate --> mon
void ti_recv_frame(int fd, short event, void *arg)
{
	unsigned char buf[4096];
   	int len;
   	struct event *ev = arg;

	printf("%s\n", __func__);
	event_add(ev, NULL);

	struct mif *mi = _mi_in;
	struct tif *ti = _mfn->dv_ti;

	len = ti->read(ti, buf, sizeof(buf));

	if (_mfn->recv_ti_wireless_frame)
		_mfn->recv_ti_wireless_frame(_mfn, buf, len, mi);
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

	if (_mfn->wifi_ap_beacon)
		_mfn->wifi_ap_beacon(_mfn);
}

void* frame_monitor(void* arg)
{
	printf("%s\n", __func__);
	pcap_loop(dev.fd_in, -1, mi_recv_frame, NULL);

	return 0;
}