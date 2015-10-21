#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "interface.h"

struct priv_if {
   	pcap_t *fd_in;
   	pcap_t *fd_out;

	int rate;
};

void *mi_priv(struct mif *mi)
{
   	return mi->mi_priv;
}

void mi_close(struct mif *mi)
{
	struct priv_if *pi = mi_priv(mi);

   	if (pi->fd_in)
       	pcap_close(pi->fd_in);
   	if (pi->fd_out)
       	pcap_close(pi->fd_out);
}

static int mi_read(struct mif *mi, unsigned char *buf, 
					int count, struct rx_info *ri)
{
	printf("%s\n", __func__);
	return 0;
}

static int mi_write(struct mif *mi, unsigned char *buf, 
					int count, struct tx_info *ti)
{
	struct priv_if *dev = mi_priv(mi);
	unsigned char tmpbuf[4096];
	unsigned char rate;
	int ret;

	unsigned char u8aRadiotap[] = {
        0x00, 0x00, /*  <-- radiotap version */
        0x09, 0x00, /*  <- radiotap header length */
        0x04, 0x00, 0x00, 0x00, /*  <-- bitmap */
        0x00, /*  <-- rate */
    };

	printf("%s\n", __func__);
	if ((unsigned) count > sizeof(tmpbuf)-22) return -1;

	if (ti) 
        rate = ti->ti_rate;
    else
        rate = dev->rate;

    u8aRadiotap[8] = rate;

	memcpy(tmpbuf, u8aRadiotap, sizeof (u8aRadiotap));
    memcpy(tmpbuf + sizeof (u8aRadiotap), buf, count);
    count += sizeof (u8aRadiotap);

    buf = tmpbuf;

	ret = pcap_inject(dev->fd_out, buf, count);

	return ret;
}

pcap_t* mi_fd(struct mif *mi)
{
    struct priv_if *pi = mi_priv(mi);

    return pi->fd_in;
}

struct mif *mi_alloc(int sz)
{
   	struct mif *mi;
   	void *priv;

   	/* Allocate wif & private state */
   	mi = malloc(sizeof(*mi));
   	if (!mi)
       	return NULL;
   	memset(mi, 0, sizeof(*mi));

   	priv = malloc(sz);
   	if (!priv) {
       	free(mi);
       	return NULL;
   	}

   	memset(priv, 0, sz);
   	mi->mi_priv = priv;

   	return mi;
}

struct mif *mi_open(char *iface)
{
	struct mif *mi;	
	struct priv_if *pi;
	pcap_t *p;
	int linktype;
	char *filter_str = "";
	struct bpf_program bpfprogram;
	char errbuf[PCAP_ERRBUF_SIZE];

	printf("%s\n", __func__);

	/* setup mi struct */
	mi = mi_alloc(sizeof(*pi));
	if (!mi)
		return NULL;

	mi->close = mi_close;
	mi->read  = mi_read;
	mi->write = mi_write;

	p = pcap_open_live(iface, 1500, 1, 20, errbuf);
	if (p == NULL) {
		printf("Unable to open interface %s in pcap: %s\n", iface, errbuf);
		return NULL;
	}

	linktype = pcap_datalink(p);
	switch (linktype) {
	case DLT_IEEE802_11_RADIO:
		mi->ieee80211_len = 0x18;
		filter_str = "not ( wlan type mgt subtype beacon ) and ((ether dst host aa:bb:cc:dd:ee:00) or (ether dst host ff:ff:ff:ff:ff:ff))";
		break;
	}

	if (pcap_compile(p, &bpfprogram, filter_str, 1, 0) == -1) {
		puts(pcap_geterr(p));	
		return NULL;
	} else {
		if (pcap_setfilter(p, &bpfprogram) == -1) {
			puts(pcap_geterr(p));	
			return NULL;
		}
		pcap_freecode(&bpfprogram);
	}

	pi = mi_priv(mi);
	pi->fd_in = p;
	pi->fd_out = pi->fd_in;

	return mi;
}
