#include <net/if.h>
#include <pcap.h>

struct tx_info {
   	unsigned int ti_rate;
};

struct rx_info {
   	u_int64_t mactime;
   	int32_t power;
   	int32_t noise;
    u_int32_t channel;
   	u_int32_t freq;
   	u_int32_t rate;
  	u_int32_t antenna;
} __packed;

struct mif {
	int (*read)(struct mif *mi, unsigned char *h80211, 
				int len, struct rx_info *ri);
	int (*write)(struct mif *mi, unsigned char *h80211, 
				int len, struct tx_info *ti);

	void *mi_priv;
	char mi_interface[IFNAMSIZ];
	pcap_t *pcap_dev;
	int ieee80211_len;
};

struct mif *mi_open(char *iface);
void mi_close(struct mif *mi);
pcap_t* mi_fd(struct mif *mi);
