TESTS_ENVIRONMENT = \
	PAM_HBAC_ABS_PATH=$(abs_top_builddir)/.libs/pam_hbac.so \
	INTGTEST_DATADIR=$(abs_builddir) \
	NSS_WRAPPER_DATADIR=$(srcdir)/nss_data \
	. $(srcdir)/intgtest_runner.sh; \
	$(NULL)

dist_noinst_DATA = \
		   nss_data/passwd \
		   nss_data/group \
		   $(NULL)

dist_noinst_SCRIPTS = \
		      intgtest_runner.sh \
		      test_pam_hbac.py \
		      $(NULL)

INTG_TESTS = $(NULL)

if HAVE_PAM_WRAPPER
INTG_TESTS += \
	test_pam_hbac.py \
	$(NULL)
endif

intgcheck: $(INTG_TESTS)
	PAM_HBAC_ABS_PATH=$(abs_top_builddir)/.libs/pam_hbac.so \
	INTGTEST_DATADIR=$(abs_builddir) \
	NSS_WRAPPER_DATADIR=$(srcdir)/nss_data \
	. $(srcdir)/intgtest_runner.sh $(srcdir)/test_pam_hbac.py; \
	$(NULL)
