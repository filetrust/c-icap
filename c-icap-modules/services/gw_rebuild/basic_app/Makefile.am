AM_CPPFLAGS = -I$(top_srcdir) -I$(top_srcdir)/include

bin_PROGRAMS = basic_app

CONFIGDIR = @CONFDIR@
cicapdatadir=@DATADIR@
cicapmoduledir=@MODSDIR@

CONFS = gw_rebuild.conf

basic_app_LDADD = @MODULES_LIBADD@ @UTILITIES_LIBADD@ -lglasswall.classic
basic_app_LDFLAGS = -module -avoid-version
basic_app_CFLAGS =
basic_app_SOURCES = rebuild_app.c gwfiletypes.c glasswall_sdk.c

EXTRA_DIST = gwfilestatus.h filetypes.h gwfiletypes.h glasswall_sdk.h 