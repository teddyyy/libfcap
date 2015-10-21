#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdarg.h>
#include <pcap.h>
#include <endian.h>
#include <stdint.h>

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef u32 __le32;

#define HEADERLENGTH 0x18

#if __BYTE_ORDER == __LITTLE_ENDIAN
#define le16_to_cpu(x) (x)
#define le32_to_cpu(x) (x)
#else
#define le16_to_cpu(x) ((((x)&0xff)<<8)|(((x)&0xff00)>>8))
#define le32_to_cpu(x) \
((((x)&0xff)<<24)|(((x)&0xff00)<<8)|(((x)&0xff0000)>>8)|(((x)&0xff000000)>>24))
#endif
#define unlikely(x) (x)

void* frame_monitor(void* arg);
void mi_recv_frame(u_char *argc, const struct pcap_pkthdr *pkthdr, const u_char *pkt);
void ti_recv_frame(int fd, short event, void *arg);
void periodic_func(int fd, short event, void *arg);
