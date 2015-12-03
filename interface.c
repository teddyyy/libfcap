#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "interface.h"

struct priv_if {
   	pcap_t *fd_in;
   	pcap_t *fd_out;
	int rate;
};

static void *mi_priv(struct mif *mi)
{
   	return mi->mi_priv;
}

static void mi_close(struct mif *mi)
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
        0x00, 0x00, //  <-- radiotap version 
        0x09, 0x00, //  <- radiotap header length
        0x04, 0x00, 0x00, 0x00, //  <-- bitmap 
        0x00, //  <-- rate 
    };

	if ((unsigned) count > sizeof(tmpbuf) - 22) 
		return -1;

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
	if (ret == -1)
		pcap_perror(dev->fd_out, 0);

	return ret;
}

pcap_t* mi_fd_in(struct mif *mi)
{
    struct priv_if *pi = mi_priv(mi);

    return pi->fd_in;
}

pcap_t* mi_fd_out(struct mif *mi)
{
    struct priv_if *pi = mi_priv(mi);

    return pi->fd_out;
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
	pcap_t *pkt_in, *pkt_out;
	char errbuf[PCAP_ERRBUF_SIZE];

	/* setup mi struct */
	mi = mi_alloc(sizeof(*pi));
	if (!mi)
		return NULL;

	mi->read  = mi_read;
	mi->write = mi_write;
	mi->close = mi_close;

	// for pkt in
	pkt_in = pcap_open_live(iface, 4096, 1, 10, errbuf);
	if (pkt_in == NULL) {
		printf("Unable to open interface %s in pcap: %s\n", iface, errbuf);
		return NULL;
	}

	if (pcap_datalink(pkt_in) != DLT_IEEE802_11_RADIO) {
		printf("Device %s doesn't provide 80211 radiotap header\n", iface);
		return NULL;
	}  

	if (pcap_setnonblock(pkt_in, 1, errbuf) == -1) {
		printf("Device %s doesn't set non-blocking mode\n", iface);
		return NULL;
	}

	// for pkt out
	pkt_out = pcap_open_live(iface, 4096, 1, 10, errbuf);
	if (pkt_out == NULL) {
		printf("Unable to open interface %s in pcap: %s\n", iface, errbuf);
		return NULL;
	}

	pi = mi_priv(mi);
	pi->fd_in = pkt_in;
	pi->fd_out = pkt_out;

	return mi;
}
