enum {
	STA_AUTH_SUCCESS 	= 0x02,
	STA_ASSOC_SUCCESS	= 0x04,
};

/* Per station info structure */
struct sta_info 
{
	MACADDR_TYPE(mac_address);	
    MACADDR_TYPE(bssid);
	int channel;
	int rate;
	int rssi;
	unsigned long long pkt_bytes;
	int state;  
	struct sta_info *next;  
};

struct client_list 
{
    struct sta_info *first;
    struct sta_info *last;
    struct sta_info *current;
	int count;
};

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
	struct client_list clist;
    u_char rates_supp[EID_SUPPORTED_RATES_LENGHT];
	u_char rates_supp_ext[EID_SUPPORTED_RATES_EXT_LENGHT];
};

struct monitor_fn_t {
    int (*mon_frame_handler)(struct monitor_fn_t *mfn,
								const u_char *pkt, int len, 
								struct mif *mi, int rate, int rssi, int subtype);
    int (*mon_tx_tun_frame)(struct monitor_fn_t *mfn,
								u_char *pkt, int len, struct mif *mi);

    void (*periodic_beacon)(struct monitor_fn_t *mfn);
    void (*csa_beacon)(struct monitor_fn_t *mfn, MACADDR_TYPE(addr), u_int8_t channel);
	void (*free)(struct monitor_fn_t *mfn);

    void *mfn_priv;
    struct tif *dv_ti;
    struct mif *dv_mi;
    void *evtimer;
    int time_beacon;
    int rate;
};

struct monitor_fn_t *init_function(struct config_values *config);
