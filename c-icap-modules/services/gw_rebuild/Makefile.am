AM_CPPFLAGS = -I$(top_srcdir) -I$(top_srcdir)/include
CONFIGDIR = @CONFDIR@
cicapdatadir=@DATADIR@
cicapmoduledir=@MODSDIR@
cicapmodule_LTLIBRARIES=gw_rebuild.la

SUBDIRS = basic_app

CONFS = gw_rebuild.conf

gw_rebuild_la_LDFLAGS = -module -avoid-version
gw_rebuild_la_CFLAGS =
gw_rebuild_la_SOURCES = gw_rebuild.c gw_body.c

TMPLS = templates/en/POLICY_ISSUE templates/en-US/POLICY_ISSUE

install-data-local:
	for f in $(CONFS); do \
		$(INSTALL) $(srcdir)/$$f $(DESTDIR)$(CONFIGDIR)/$$f.default; \
		if test ! -f $(DESTDIR)$(CONFIGDIR)/$$f; then $(INSTALL) $(srcdir)/$$f $(DESTDIR)$(CONFIGDIR)/$$f; fi \
	done
	$(mkinstalldirs) $(DESTDIR)$(cicapdatadir)/templates/gw_rebuild/en/
	for f in $(TMPLS); do $(INSTALL) $(srcdir)/$$f $(DESTDIR)$(cicapdatadir)/templates/gw_rebuild/en/; done

EXTRA_DIST = gw_rebuild.h gw_rebuild.conf gw_body.h $(TMPLS)
