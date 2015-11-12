/* Access point structure */
struct ap_conf
{
    MACADDR_TYPE(bssid);
    MACADDR_TYPE(mac_address);
    IPADDR_TYPE(ip_address);
    unsigned char essid[33];
    int channel;
    int freq;
    int rate;
    int tx_power;
    unsigned short interval;
    u_int16_t capability;
    u_int64_t timestamp;
    int seq_ctrl; // we must track sequence number in a per-AP basis, if possible
    u_char rates_supp[EID_SUPPORTED_RATES_LENGHT];
	u_char rates_supp_ext[EID_SUPPORTED_RATES_EXT_LENGHT];
};

struct monitor_fn_t {
    int (*mon_frame_handler)(struct monitor_fn_t *mfn,
								const u_char *pkt, int len, 
								struct mif *mi, int rssi, int subtype);
    int (*mon_tx_tun_frame)(struct monitor_fn_t *mfn,
								u_char *pkt, int len, struct mif *mi);

    void (*periodic_beacon)(struct monitor_fn_t *mfn);
    void (*csa_beacon)(struct monitor_fn_t *mfn, MACADDR_TYPE(addr), u_int8_t channel);

    void (*monitor_free)(struct monitor_fn_t *mfn);
    void (*free)(struct monitor_fn_t *mfn);

    void *mfn_priv;
    struct tif *dv_ti;
    struct mif *dv_mi;
    void *evtimer;
    int time_beacon;
    int rate;
};

struct monitor_fn_t *init_function(struct config_values *config);
