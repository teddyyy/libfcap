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

void* frame_monitor(void* arg);
int core_mi_send_frame(void *buf, size_t count, int rate);
void core_ti_recv_frame(int fd, short event, void *arg);
int core_ti_send_frame(void *buf, size_t count);
void periodic_func(int fd, short event, void *arg);
