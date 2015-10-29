#include <event.h>
#include <signal.h>
#include <pcap.h>
#include <pthread.h>

#include "fcap.h"
#include "core.h"
#include "utils.h"
#include "interface.h"
#include "tun.h"
#include "monitor.h"

/* global value */
time_t init_timer = 0;
struct event_base* eb = NULL;

static void sigint_handler()
{
	if (eb) 
		event_base_free(eb);

	if (_mi_out > 0)
		mi_close(_mi_out);
	
	if (_ti_out > 0)
		ti_close(_ti_out);

	if (_mfn)
		_mfn->free(_mfn);

	exit (0);
}

/*  main entry */
int init_fcap(int argc, char** argv)
{
	pthread_t th;
	struct event evti, evtimer;
	struct timeval tv;

	printf("%s\n", __func__);

	init_timer = time(NULL);

	signal(SIGINT, sigint_handler);

	/* set default config value */
	memset(&config, '\0', sizeof(struct config_values));
	strcpy(config.wifi_iface, DEFAULT_WIRELESS_IFACE);
	printf("%s\n", config.wifi_iface);
    config.channel = DEFAULT_CHANNEL;
	printf("%d\n", config.channel);
    ato_ip_address(config.ip_address, DEFAULT_IP_ADDRESS);
	printf("%s\n", DEFAULT_IP_ADDRESS);
	strcpy(config.essid, DEFAULT_ESSID);
	printf("%s\n", config.essid);
	ato_mac_address(config.mac_address, DEFAULT_MAC_ADDRESS);
	printf("%s\n", DEFAULT_MAC_ADDRESS);

    /* open output and input interface */
	_mi_out = (struct mif *)mi_open(config.wifi_iface);
	if (!_mi_out)
		return 1;
	dev.fd_out = mi_fd_out(_mi_out);
	dev.fd_in = mi_fd_in(_mi_out);

	/* Same interface for input and output */
    _mi_in = _mi_out;

	/* open output and input tap interface */
    _ti_out = (struct tif *) ti_open(NULL);
    if (!_ti_out)
       	return 1;
    dev.ti_out = tun_fd(_ti_out);

	/* Same interface for input and output */
    _ti_in = _ti_out;
    dev.ti_in = dev.ti_out;

	// set mac address and interface up
	ti_set_mac(_ti_in, config.mac_address);
	ti_set_up(_ti_in);

	/* drop privileges */
    setuid(getuid());

    if (dev.fd_in == NULL) {
      	perror("open");
     	exit (1);
    }

	_mfn = (struct monitor_fn_t *)init_function(&config);
	_mfn->dv_ti = _ti_out;

	// start posix thread
	pthread_create(&th, NULL, frame_monitor, NULL);
	
	/* Initalize the event library */
    eb = event_init();

	/* Initalize events */
    event_set(&evti, dev.ti_in, EV_READ, core_ti_recv_frame, &evti);

	/* Add it to the active events, without a timeout */
    event_add(&evti, NULL);

	if (_mfn->time_beacon) {
		evtimer_set(&evtimer, periodic_func, &evtimer);
		tv.tv_usec = _mfn->time_beacon;
       	tv.tv_sec = 0;
       	evtimer_add(&evtimer, &tv);
   }

	event_dispatch();
	pthread_join(th, NULL);

	return 0;
}
