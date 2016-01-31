TESTS_ENVIRONMENT = \
	PAM_HBAC_ABS_PATH=$(abs_builddir)/.libs/pam_hbac.so \
	INTGTEST_DATADIR=$(abs_builddir)/intgtests
	. $(srcdir)/src/intgtests/intgtest_runner.sh; \
	$(NULL)

INTG_TESTS = $(NULL)

if HAVE_PAM_WRAPPER
INTG_TESTS += \
	test_pam_hbac.py \
	$(NULL)
endif

TESTS = $(INTG_TESTS)

tests: $(INTG_TESTS)
