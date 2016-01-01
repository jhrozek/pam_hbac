pamlibdir = @pammoddir@
pam_hbac_conf_dir = $(sysconfdir)

AM_CFLAGS =
if HAVE_GCC
AM_CFLAGS += -Wall -Wshadow -Wstrict-prototypes -Wpointer-arith \
	     -Wcast-qual -Wcast-align -Wwrite-strings \
	     -Werror-implicit-function-declaration
endif
PAM_MISC_LIBS=@PAM_MISC_LIBS@

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
		     src/pam_hbac_obj.c \
		     src/pam_hbac_config.c \
		     src/pam_hbac_entry.c \
		     src/pam_hbac_rules.c \
		     src/pam_hbac_ldap.c \
		     src/pam_hbac_eval_req.c \
		     src/pam_hbac_dnparse.c \
		     src/pam_hbac_utils.c \
		     $(NULL)

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

libipa_wrap_tests_SOURCES = \
	src/tests/libipa_wrap_tests.c \
	src/pam_hbac_libipa_wrap.c \
	$(NULL)
libipa_wrap_tests_CFLAGS = \
	$(AM_CFLAGS) \
	$(CMOCKA_CFLAGS) \
	$(NULL)
libipa_wrap_tests_LDADD = \
	-lldap \
	$(CMOCKA_LIBS) \
	$(NULL)

if HAVE_CMOCKA
    check_PROGRAMS = \
	config-tests \
	libipa-wrap-tests \
	$(NULL)
endif

TESTS = config-tests

### Interactive test program
noinst_PROGRAMS = pam_test_client
pam_test_client_SOURCES = src/tests/pam_test_client.c
pam_test_client_LDFLAGS = -lpam $(PAM_MISC_LIBS)

### Targets
tests: all $(check_PROGRAMS)

debug:
if HAVE_GCC
    AM_CFLAGS += -DPAM_DEBUG
endif
	$(MAKE) all
