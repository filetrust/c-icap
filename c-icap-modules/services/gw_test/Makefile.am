AM_CPPFLAGS = -I$(top_srcdir) -I$(top_srcdir)/include
CONFIGDIR = @CONFDIR@
cicapdatadir=@DATADIR@
cicapmoduledir=@MODSDIR@
cicapmodule_LTLIBRARIES=gw_test.la

CONFS = gw_test.conf

gw_test_la_LIBADD = @MODULES_LIBADD@ -lglasswall.classic
gw_test_la_LDFLAGS = -module -avoid-version
gw_test_la_CFLAGS =
gw_test_la_SOURCES = gw_test.c gw_body.c gwfiletypes.c glasswall_sdk.c

TMPLS = templates/en/POLICY_ISSUE templates/en-US/POLICY_ISSUE

install-data-local:
	for f in $(CONFS); do \
		$(INSTALL) $(srcdir)/$$f $(DESTDIR)$(CONFIGDIR)/$$f.default; \
		if test ! -f $(DESTDIR)$(CONFIGDIR)/$$f; then $(INSTALL) $(srcdir)/$$f $(DESTDIR)$(CONFIGDIR)/$$f; fi \
	done
	$(mkinstalldirs) $(DESTDIR)$(cicapdatadir)/templates/gw_test/en/
	for f in $(TMPLS); do $(INSTALL) $(srcdir)/$$f $(DESTDIR)$(cicapdatadir)/templates/gw_test/en/; done

EXTRA_DIST = gw_test.h gw_test.conf gwfile.h gw_body.h gwfilestatus.h filetypes.h gwfiletypes.h glasswall_sdk.h $(TMPLS)
