void ato_mac_address(MACADDR_TYPE(macaddr), char *s);
void ato_ip_address(IPADDR_TYPE(ipaddr), char *s);
int is_same_ssid(u_char *a, u_char *b);
int is_same_mac(MACADDR_TYPE(a), MACADDR_TYPE(b));
void log_open(const char* name);
void log_write(int priority, const char* const message);
void log_close();
