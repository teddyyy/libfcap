#include <string.h>
#include <sys/types.h>
#include <syslog.h>

#include "fcap.h"
#include "utils.h"

static int _sthexa_to_int(char c)
{
    if ('0' <= c && c <= '9')
        return c - '0' ;
    if ('A' <= c && c <= 'F')
        return c - 'A' + 10;
    if ('a' <= c && c <= 'f')
        return c - 'a' + 10;
    return 0;
}

int is_same_mac(MACADDR_TYPE(a), MACADDR_TYPE(b))
{
    if (a == NULL || b == NULL)
        return 0;
    /* MAC addresses are 6 bytes long */
    return (memcmp(a, b, 6 * sizeof(u_int8_t)) == 0);
}

int is_same_ssid(u_char *a, u_char *b)
{
    if (strlen((char *)a) != strlen((char *)b))
        return 0;
    return (memcmp(a, b, strlen((char *)a)*sizeof(u_char)) == 0);
}

void ato_mac_address(MACADDR_TYPE(macaddr), char *s)
{
    /* s = "XX:XX:XX:XX:XX:XX" */
    int i;
    for (i = 0; i < 6; i++) {
        macaddr[i] = _sthexa_to_int(s[3*i])*0x10 + _sthexa_to_int(s[3*i + 1]);
    }
}

void ato_ip_address(IPADDR_TYPE(ipaddr), char *s)
{
    /* s = "192.168.1.13" */
    int i = 0, j = 0;
    int len = strlen(s);

    while (i < len) {
        ipaddr[j] = 0;
        while (s[i] != '.' && i < len)
        {
            ipaddr[j] = ipaddr[j]*10 + (s[i] - '0');
            i++;
        }
        i++; j++;
    }
}

void log_open(const char* name) 
{
    openlog(name, LOG_PID, LOG_USER);
}

void log_write(int priority, const char* const message) 
{
    syslog(priority, "%s", message);
}

void log_close() 
{
    closelog();
}

