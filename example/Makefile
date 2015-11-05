TARGET = fcapd
OBJS	= fcapd.o
LIBDIR	= ../
LIB	= $($LIBDIR)/libfcap.a

SRCS = $(OBJS:.o=.c)

CC 	= mips-openwrt-linux-gcc

GFLAGS  = -O -Wall -g
CFLAGS  = -I$(LIBDIR)
LFLAGS  = -L$(LIBDIR) -lfcap -L/home/teddy/openwrt/staging_dir/target-mips_34kc_uClibc-0.9.33.2/usr/lib/ -levent -lpcap -lpthread

.SUFFIXES:
.SUFFIXES: .o .c

all :		$(TARGET)

.c.o :
		$(CC) $(GFLAGS) $(CFLAGS) -c $<

$(TARGET) :	$(OBJS) $(LIB)
		$(CC) $(OBJS) $(GFLAGS) $(LFLAGS) -o $@

$(LIB) :
		cd $(LIBDIR) ; $(MAKE)

clean :
		rm -f $(OBJS) $(TARGET)
