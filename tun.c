#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <errno.h>
#include <linux/if_tun.h>
#include <net/if_arp.h>

#include "tun.h"

struct priv_tun_if {
   	int     fd;
   	struct ifreq    ti_ifr;
   	int     ti_ioctls;
   	char    ti_name[IFNAMSIZ];
};

static void *ti_priv(struct tif *ti)
{
   	return ti->tif_priv;
}

static char *ti_name(struct tif *ti)
{
    struct priv_tun_if *priv = ti_priv(ti);

    return priv->ti_name;
}

int ti_set_mac(struct tif *ti, unsigned char *mac)
{
    struct priv_tun_if *priv = ti_priv(ti);

	printf("%s\n", __func__);

    memcpy(priv->ti_ifr.ifr_hwaddr.sa_data, mac, 6);
    priv->ti_ifr.ifr_hwaddr.sa_family = ARPHRD_ETHER;

    if (ioctl(priv->ti_ioctls, SIOCSIFHWADDR, &priv->ti_ifr) < 0) {
		perror("ioctl");
		return -1;
	}
	
	return 0;
}

int ti_set_up(struct tif *ti)
{
    struct priv_tun_if *priv = ti_priv(ti);
    struct ifreq ifreq;
    int flags;

	printf("%s\n", __func__);

    memset(&ifreq,0,sizeof(struct ifreq));
    strncpy(ifreq.ifr_name, ti_name(ti), IFNAMSIZ);

     /*  get flags */
    if (ioctl(priv->ti_ioctls, SIOCGIFFLAGS, (caddr_t) &ifreq) < 0) {
        perror("ioctl");
        return -1;
    }

    flags = ifreq.ifr_flags & 0xffff;
    memset(&ifreq, 0, sizeof(ifreq));
    strncpy(ifreq.ifr_name, ti_name(ti), IFNAMSIZ);

    flags = flags | IFF_UP; /*  UP and RUNNING */

    ifreq.ifr_flags = flags & 0xffff;

    /*  set flags */
    if (ioctl(priv->ti_ioctls, SIOCSIFFLAGS, (caddr_t) &ifreq) < 0) {
        perror("ioctl");
        return -1;
    }

    return 0;
}

static int ti_open_iface(struct tif *ti, char *name)
{
    int fd_tap;
    struct ifreq if_request;
    struct priv_tun_if *priv = ti_priv(ti);

    fd_tap = open("/dev/net/tun", O_RDWR);
    if (fd_tap < 0) {
        printf("error opening tap device: %s", strerror(errno));
        return -1;
    }

    memset(&if_request, 0, sizeof(if_request));
    if_request.ifr_flags = IFF_TAP | IFF_NO_PI;
    strncpy(if_request.ifr_name, "tap%d", IFNAMSIZ);

    if (ioctl(fd_tap, TUNSETIFF, (void *)&if_request) < 0) {
        printf("error creating tap interface: %s\n", strerror(errno));
        close(fd_tap);
        return -1;
    }

    strncpy(priv->ti_name, if_request.ifr_name, IFNAMSIZ);
    strncpy(priv->ti_ifr.ifr_name, priv->ti_name,
            sizeof(priv->ti_ifr.ifr_name) - 1);

    if ((priv->ti_ioctls = socket(PF_INET, SOCK_DGRAM, 0)) == -1) {
        priv->ti_ioctls = 0;
        close(fd_tap);
    	return -1;
    }

    return fd_tap;
}

static int ti_fd(struct tif *ti)
{
   	struct priv_tun_if *priv = ti_priv(ti);

   	return priv->fd;
}

void ti_do_free(struct tif *ti)
{
   	void *priv = ti_priv(ti);

   	free(priv);
   	free(ti);
}

static int ti_read(struct tif *ti, void *buf, int len)
{
	int size;
   	
	size = read(ti_fd(ti), buf, len);

   	return size;
}

static int ti_write(struct tif *ti, void *buf, int len)
{
   	return write(ti_fd(ti), buf, len);
}


void ti_close(struct tif *ti)
{
   	struct priv_tun_if *priv = ti_priv(ti);

   	close(priv->fd);
   	close(priv->ti_ioctls);
   	ti_do_free(ti);
}

static struct tif *ti_alloc(int sz)
{
    struct tif *ti;
    void *priv;

    /* Allocate tif & private state */
    ti = malloc(sizeof(*ti));
    if (!ti)
        return NULL;
    memset(ti, 0, sizeof(*ti));

    priv = malloc(sz);
    if (!priv) {
        free(ti);
        return NULL;
    }
    memset(priv, 0, sz);
    ti->tif_priv = priv;

    return ti;
}

int tun_fd(struct tif *ti)
{
    return ti->fd(ti);
}

struct tif *ti_open(char *iface)
{
	struct tif *ti;
   	struct priv_tun_if *priv;
	int fd;

	printf("%s\n", __func__);

	/* setup ti struct */
    ti = ti_alloc(sizeof(*priv));
    if (!ti)
        return NULL;
	ti->read = ti_read;	
	ti->write = ti_write;
	ti->fd	= ti_fd;
	
	/* setup iface */
    fd = ti_open_iface(ti, iface);
	if (fd == -1) {
        ti_do_free(ti);
        return NULL;
    }

	/* setup private state */
	priv = ti_priv(ti);
    priv->fd = fd;

	return ti;
}
