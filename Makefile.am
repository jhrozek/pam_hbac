pamlibdir = @pammoddir@
pam_hbac_conf_dir = $(sysconfdir)

UNICODE_LIBS=@UNICODE_LIBS@

AM_CFLAGS =
if HAVE_GCC
AM_CFLAGS += -Wall -Wshadow -Wstrict-prototypes -Wpointer-arith \
	     -Wcast-qual -Wcast-align -Wwrite-strings \
	     -Werror-implicit-function-declaration \
	     $(GLIB2_CFLAGS) \
	     $(NULL)
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
		     src/libhbac/hbac_evaluator.c \
		     src/libhbac/sss_utf8.c \
		     $(NULL)

pam_hbac_la_LDFLAGS = \
		     $(UNICODE_LIBS) \
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
		      src/pam_hbac.h \
		      src/pam_hbac_compat.h \
		      src/pam_hbac_dnparse.h \
		      src/pam_hbac_entry.h \
		      src/pam_hbac_ldap.h \
		      src/pam_hbac_obj.h \
		      src/pam_hbac_obj_int.h \
		      src/libhbac/ipa_hbac.h \
		      src/libhbac/sss_utf8.h \
		      src/libhbac/sss_compat.h \
		      src/tests/common_mock.h \
		      src/tests/ph_tests.h \
		      $(NULL)

dist_noinst_DATA = \
		      src/tests/configs/good1.conf \
		      src/tests/configs/eqwsp.conf \
		      src/tests/configs/lwsp.conf \
		      src/tests/configs/twsp.conf \
		      src/tests/configs/noeq.conf \
		      src/tests/configs/trailing_empty_lines.conf \
		      src/tests/configs/empty_lines.conf \
		      src/tests/cwrap/passwd \
		      src/tests/cwrap/group \
		      $(NULL)

dist_noinst_SCRIPTS = \
		      ci/semaphoreci.sh \
		      ci/coverity.sh \
		      src/tests/cwrap_test_setup.sh \
		      $(NULL)

# Documentation
dist_doc_DATA = \
		COPYING \
		README.md \
		doc/README.FreeBSD \
		doc/README.RHEL-5 \
		doc/README.RHEL-6 \
		$(NULL)

### Unit tests
TESTS_ENVIRONMENT = \
	CWRAP_TEST_SRCDIR=$(abs_srcdir)/src/tests/cwrap \
	. $(srcdir)/src/tests/cwrap_test_setup.sh; \
	$(NULL)

@VALGRIND_CHECK_RULES@

config_tests_SOURCES = \
		      src/tests/config-tests.c \
		      src/pam_hbac_config.c \
		      src/pam_hbac_utils.c \
		      $(NULL)
config_tests_CFLAGS = \
		      $(AM_CFLAGS) \
		      $(CMOCKA_CFLAGS) \
		      -DTEST_CONF_DIR=\"$(abs_srcdir)/\" \
		      $(NULL)
config_tests_LDADD = \
		     -lpam \
		     $(CMOCKA_LIBS) \
		     $(NULL)

utils_tests_SOURCES = \
	src/tests/utils_tests.c \
	src/pam_hbac_utils.c \
	$(NULL)
utils_tests_CFLAGS = \
	$(AM_CFLAGS) \
	$(CMOCKA_CFLAGS) \
	$(NULL)
utils_tests_LDADD = \
	-lpam \
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
	src/tests/test_helpers.c \
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
	-lpam \
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
	-Wl,-wrap,ldap_get_dn \
	-Wl,-wrap,ldap_memfree \
	-Wl,-wrap,ber_free \
	-Wl,-wrap,ldap_start_tls \
	-Wl,-wrap,ldap_get_option \
	-Wl,-wrap,ldap_result \
	-Wl,-wrap,ldap_parse_result \
	-Wl,-wrap,ldap_tls_inplace \
	-Wl,-wrap,ldap_install_tls \
	$(NULL)
ldap_tests_LDADD = \
	-lldap \
	-llber \
	-lpam \
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
	-lpam \
	$(CMOCKA_LIBS) \
	$(NULL)

rules_tests_SOURCES = \
	src/tests/rules_tests.c \
	src/tests/mock_entry.c \
	src/tests/test_helpers.c \
	src/pam_hbac_rules.c \
	src/pam_hbac_utils.c \
	src/pam_hbac_entry.c \
	src/pam_hbac_dnparse.c \
	src/libhbac/hbac_evaluator.c \
	src/libhbac/sss_utf8.c \
	$(NULL)
rules_tests_CFLAGS = \
	$(AM_CFLAGS) \
	$(CMOCKA_CFLAGS) \
	$(NULL)
rules_tests_LDFLAGS = \
	-Wl,-wrap,ph_search \
	$(NULL)
rules_tests_LDADD = \
	-lldap \
	-llber \
	-lpam \
	$(CMOCKA_LIBS) \
	$(UNICODE_LIBS) \
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
	rules-tests \
	$(NULL)
endif

SUBDIRS = . src/intgtests

TESTS = $(check_PROGRAMS)

### Interactive test program
noinst_PROGRAMS = pam_test_client
pam_test_client_SOURCES = src/tests/pam_test_client.c
pam_test_client_LDFLAGS = -lpam $(PAM_MISC_LIBS)

### Packaging
EXTRA_DIST = \
	rpm/pam_hbac.spec \
	$(NULL)

### Man pages
if HAVE_MANPAGES
SUBDIRS += doc
endif

### Targets
tests: all $(check_PROGRAMS)

intgcheck:
	(cd src/intgtests && $(MAKE) $(AM_MAKEFLAGS) $@) || exit 1;
