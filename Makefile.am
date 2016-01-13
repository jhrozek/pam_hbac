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
		     -llber \
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
TESTS_ENVIRONMENT = \
	CWRAP_TEST_SRCDIR=$(abs_srcdir)/src/tests/cwrap \
	. $(srcdir)/src/tests/cwrap_test_setup.sh; \
	$(NULL)

config_tests_SOURCES = \
		      src/tests/config-tests.c \
		      src/pam_hbac_config.c
config_tests_CFLAGS = \
		      $(AM_CFLAGS) \
		      $(CMOCKA_CFLAGS)
config_tests_LDADD = \
		     $(CMOCKA_LIBS)

utils_tests_SOURCES = \
	src/tests/utils_tests.c \
	src/pam_hbac_utils.c \
	$(NULL)
utils_tests_CFLAGS = \
	$(AM_CFLAGS) \
	$(CMOCKA_CFLAGS) \
	$(NULL)
utils_tests_LDADD = \
	$(CMOCKA_LIBS) \
	$(NULL)

entry_tests_SOURCES = \
	src/tests/entry_tests.c \
	src/tests/mock_entry.c \
	src/pam_hbac_entry.c \
	$(NULL)
entry_tests_CFLAGS = \
	$(AM_CFLAGS) \
	$(CMOCKA_CFLAGS) \
	$(NULL)
entry_tests_LDADD = \
	-lldap \
	-llber \
	$(CMOCKA_LIBS) \
	$(NULL)

dnparse_tests_SOURCES = \
	src/tests/dnparse_tests.c \
	src/pam_hbac_dnparse.c \
	$(NULL)
dnparse_tests_CFLAGS = \
	$(AM_CFLAGS) \
	$(CMOCKA_CFLAGS) \
	$(NULL)
dnparse_tests_LDADD = \
	-lldap \
	-llber \
	$(CMOCKA_LIBS) \
	$(NULL)

eval_req_tests_SOURCES = \
	src/tests/eval_req_tests.c \
	src/pam_hbac_eval_req.c \
	src/tests/mock_entry.c \
	src/tests/mock_user.c \
	src/pam_hbac_obj.c \
	src/pam_hbac_entry.c \
	src/pam_hbac_dnparse.c \
	src/pam_hbac_utils.c \
	src/pam_hbac_ldap.c \
	$(NULL)
eval_req_tests_CFLAGS = \
	$(AM_CFLAGS) \
	$(CMOCKA_CFLAGS) \
	$(NULL)
eval_req_tests_LDADD = \
	-lldap \
	-llber \
	$(CMOCKA_LIBS) \
	$(NULL)

ldap_tests_SOURCES = \
	src/tests/ldap_tests.c \
	src/pam_hbac_ldap.c \
	src/pam_hbac_entry.c \
	src/pam_hbac_utils.c \
	$(NULL)
ldap_tests_CFLAGS = \
	$(AM_CFLAGS) \
	$(CMOCKA_CFLAGS) \
	$(NULL)
ldap_tests_LDFLAGS = \
	-Wl,-wrap,ldap_sasl_bind_s \
	-Wl,-wrap,ldap_unbind_ext \
	-Wl,-wrap,ldap_search_ext_s \
	-Wl,-wrap,ldap_first_message \
	-Wl,-wrap,ldap_next_message \
	-Wl,-wrap,ldap_msgtype \
	-Wl,-wrap,ldap_count_entries \
	-Wl,-wrap,ldap_get_values_len \
	-Wl,-wrap,ldap_first_attribute \
	-Wl,-wrap,ldap_first_attribute \
	-Wl,-wrap,ldap_next_attribute \
	-Wl,-wrap,ldap_memfree \
	-Wl,-wrap,ber_free \
	$(NULL)
ldap_tests_LDADD = \
	-lldap \
	-llber \
	$(CMOCKA_LIBS) \
	$(NULL)

obj_tests_SOURCES = \
	src/tests/obj_tests.c \
	src/tests/mock_entry.c \
	src/pam_hbac_obj.c \
	src/pam_hbac_entry.c \
	src/pam_hbac_utils.c \
	src/pam_hbac_ldap.c \
	$(NULL)
obj_tests_CFLAGS = \
	$(AM_CFLAGS) \
	$(CMOCKA_CFLAGS) \
	$(NULL)
obj_tests_LDFLAGS = \
	-Wl,-wrap,ph_search \
	$(NULL)
obj_tests_LDADD = \
	-lldap \
	-llber \
	$(CMOCKA_LIBS) \
	$(NULL)

if HAVE_CMOCKA
    check_PROGRAMS = \
	config-tests \
	utils-tests \
	entry-tests \
	dnparse-tests \
	eval_req-tests \
	ldap-tests \
	obj-tests \
	$(NULL)
endif

TESTS = $(check_PROGRAMS)

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
