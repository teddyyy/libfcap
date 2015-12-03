#include <net/if.h>

struct tif {
	int (*read)(struct tif *ti, void *buf, int len);
    int (*write)(struct tif *ti, void *buf, int len);
	void (*close)(struct tif *ti);
	int (*fd)(struct tif *ti);
    void *ti_priv;
};

int tun_fd(struct tif *ti);
struct tif *ti_open(char *iface);
int ti_set_mac(struct tif *ti, unsigned char *mac);
int ti_set_up(struct tif *ti);
