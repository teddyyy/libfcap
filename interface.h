#include <net/if.h>
#include <pcap.h>

struct tx_info {
   	unsigned int ti_rate;
};

struct rx_info {
   	u_int64_t mactime;
   	int8_t power;
   	int8_t noise;
    u_int32_t channel;
   	u_int32_t freq;
   	u_int32_t rate;
  	u_int32_t antenna;
	int flags;
} __packed;

struct mif {
	int (*read)(struct mif *mi, unsigned char *h80211, 
				int len, struct rx_info *ri);
	int (*write)(struct mif *mi, unsigned char *h80211, 
				int count, struct tx_info *ti);
	void (*close)(struct mif *mi);
	void *mi_priv;
	char mi_interface[IFNAMSIZ];
};

struct mif *mi_open(char *iface);
pcap_t* mi_fd_in(struct mif *mi);
pcap_t* mi_fd_out(struct mif *mi);
