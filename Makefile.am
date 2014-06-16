pamlibdir = @pammoddir@
pam_hbac_conf_dir = $(sysconfdir)

AM_CFLAGS =
if HAVE_GCC
AM_CFLAGS += -Wall -Wshadow -Wstrict-prototypes -Wpointer-arith \
	     -Wcast-qual -Wcast-align -Wwrite-strings \
	     -Werror-implicit-function-declaration
endif

ACLOCAL_AMFLAGS = -I m4 -I .
###############################
# Global compilation settings #
# ###############################
#
AM_CPPFLAGS = \
	      -Wall \
	      -I$(srcdir)/src \
	      -I. \
	      -DPAM_HBAC_CONF_DIR=\"$(pam_hbac_conf_dir)\"

### PAM-HBAC
pamlib_LTLIBRARIES = pam_hbac.la
pam_hbac_la_SOURCES = \
		     src/pam_hbac.c \
		     src/pam_hbac_search.c \
		     src/pam_hbac_ipa.c \
		     src/pam_hbac_config.c

pam_hbac_la_LDFLAGS = \
		     -lldap \
		     -lpam \
		     -module \
		     -avoid-version
#if GNU_LD
#pam_hbac_la_LDFLAGS += \
#		     -Wl,--version-script,$(srcdir)/src/pam_hbac.exports
#endif

dist_noinst_HEADERS = \
		      src/pam_hbac.h

### Unit tests
config_tests_SOURCES = \
		      src/tests/config-tests.c \
		      src/pam_hbac_config.c
config_tests_CFLAGS = \
		      $(AM_CFLAGS) \
		      $(CMOCKA_CFLAGS)
config_tests_LDADD = \
		     $(CMOCKA_LIBS)

if HAVE_CMOCKA
    check_PROGRAMS = config-tests
endif

TESTS = config-tests

### Interactive test program
noinst_PROGRAMS = pam_test_client
pam_test_client_SOURCES = src/tests/pam_test_client.c
pam_test_client_LDFLAGS = -lpam -lpam_misc

### Targets
tests: all $(check_PROGRAMS)

debug:
if HAVE_GCC
    AM_CFLAGS += -DPAM_DEBUG
endif
	$(MAKE) all
