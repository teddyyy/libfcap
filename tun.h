#include <net/if.h>

struct tif {
	int (*read)(struct tif *ti, void *buf, int len);
    int (*write)(struct tif *ti, void *buf, int len);
	int (*fd)(struct tif *ti);
    void *tif_priv;
};

int tun_fd(struct tif *ti);
struct tif *ti_open(char *iface);
void ti_close(struct tif *ti);
int ti_set_mac(struct tif *ti, unsigned char *mac);
int ti_set_up(struct tif *ti);
