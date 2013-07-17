DEFAULT_INCLUDES = -I$(top_srcdir)/include -I/usr/local/bsp/include -I./include 
AM_CFLAGS = -Wall
AM_LDFLAGS = -rpath  /usr/local/bsp/lib  -rpath $(libdir)

bin_PROGRAMS = bcsniffer

bcsniffer_SOURCES = bcsniffer.c
bcsniffer_LDADD = -lpthread -L/usr/local/bsp/lib/ -lbspcommon -lbspnetop -lbsplistop -lbspdisplay
bcsniffer_LDFLAGS =
bcsniffer_CFLAGS =
