bspincludedir = $(top_srcdir)/include
bspinclude_HEADERS =  

DEFAULT_INCLUDES = -I$(top_srcdir)/include -I/usr/local/bsp/include
AM_CFLAGS = 
AM_LDFLAGS =  -rpath $(libdir) /usr/local/bsp/lib

lib_LTLIBRARIES = libbspcommon.la

libbspcommon_la_SOURCES = common.c 
libbspcommon_la_CFLAGS = -shared 
libbspcommon_la_LIBADD = 
libbspcommon_la_LDFLAGS = 


