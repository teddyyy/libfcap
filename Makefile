# Command
CC		= mips-openwrt-linux-gcc
AR		= mips-openwrt-linux-ar

TARGET	= libfcap.a

# Object
OBJS 	= init.o core.o interface.o tun.o utils.o monitor.o radiotap.o mlme.o
SRCS 	= $(OBJS:.o=.c)

# Path
INC_PATH	= /home/teddy/openwrt/staging_dir/target-mips_34kc_uClibc-0.9.33.2/usr/include/
LB_PATH 	= /home/teddy/openwrt/staging_dir/target-mips_34kc_uClibc-0.9.33.2/usr/lib/

# Flag
CFLAGS 		= -g -Wall
LDFLAGS 	= -levent -lpcap -lpthread

.SUFFIXES:
.SUFFIXES: .o .c

all:	$(TARGET)

.c.o:
	$(CC) $(CFLAGS) -I$(INC_PATH) -c $<

$(TARGET):	$(OBJS)
	$(AR) ruc $(TARGET) $(OBJS)
	rm -f $(OBJS)

clean:
	rm -f $(OBJS) $(TARGET)
