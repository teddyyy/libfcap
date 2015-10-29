int ap_get_seq_ctrl(struct ap_conf *ap);
int ieee80211_mgmt_build(u_char *pkt, int length, int subtype,
                        int channel, unsigned char *essid,
                        u_int16_t capability, u_char *rates_supp,
                        u_char *rates_supp_ext);
int ieee80211_framectrl_build(u_char *pkt, int len,
            u_char *addr1, u_char *addr2, u_char *addr3,
            u_int16_t sc, u_int16_t fc, u_int16_t duration);
void handle_probe_request(struct monitor_fn_t *mfn, const u_char *pkt, int len, int rssi);
void handle_auth_frame(struct monitor_fn_t *mfn, const u_char *pkt, int len, int rssi);
void handle_assoc_request(struct monitor_fn_t *mfn, const u_char *pkt, int len, int rssi);
void handle_reassoc_request(struct monitor_fn_t *mfn, const u_char *pkt, int len, int rssi);
void handle_data_frame(struct monitor_fn_t *mfn, const u_char *pkt, int len, int rssi);
