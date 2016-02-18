AC_PREREQ(2.59)

m4_include([version.m4])
m4_include([external/attribute.m4])
m4_include([external/libcmocka.m4])
m4_include([external/cwrap.m4])

AC_INIT([pam_hbac],
        VERSION_NUMBER,
        [jakub.hrozek@posteo.se])

AC_CONFIG_AUX_DIR([build])

AM_INIT_AUTOMAKE([-Wall foreign subdir-objects])
m4_ifdef([AM_PROG_AR], [AM_PROG_AR])
AM_PROG_AR
AC_PROG_CC_C99
AM_PROG_CC_C_O
AC_DISABLE_STATIC
AC_PROG_INSTALL
AC_PROG_LIBTOOL
AC_CONFIG_MACRO_DIR([m4])

m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES])

AM_CONDITIONAL([HAVE_GCC], [test "$ac_cv_prog_gcc" = yes])
CC_ATTRIBUTE_NONNULL
CC_ATTRIBUTE_UNUSED

#Check for PAM headers
AC_CHECK_HEADERS([security/pam_appl.h security/pam_modules.h],
    [AC_CHECK_LIB([pam], [pam_get_item],
        [PAM_LIBS="-lpam"],
        [AC_MSG_ERROR([PAM must support pam_get_item])])],
    [AC_MSG_ERROR([PAM development libraries not installed])]
)

AC_CHECK_HEADERS([security/pam_ext.h security/pam_modutil.h])
AC_CHECK_HEADERS([security/pam_misc.h security/_pam_macros.h])
AC_CHECK_HEADERS([security/openpam.h],,,[
      #ifdef HAVE_SECURITY_PAM_APPL_H
      #include <security/pam_appl.h>
      #endif
    ])

AC_CHECK_LIB([pam_misc], [misc_conv],
    [PAM_MISC_LIBS="-lpam_misc"])
AC_SUBST(PAM_MISC_LIBS)

dnl save LIBS to restore later
save_LIBS="$LIBS"
LIBS="$PAM_LIBS"

dnl Check for optional PAM fnuctions
AC_CHECK_FUNCS(pam_syslog pam_vsyslog)

dnl restore LIBS
LIBS="$save_LIBS"

#Set the PAM module install path
AC_ARG_ENABLE([pammoddir], [AS_HELP_STRING([--enable-pammoddir],
              [Where to install pam modules ($libdir/security)])],
              [pammoddir=$enableval],
              [pammoddir=$libdir/security])
AC_SUBST(pammoddir)

# Optional build dependencies - Unit tests
AM_CHECK_CMOCKA
AM_CHECK_NSS_WRAPPER
AM_CHECK_PAM_WRAPPER

AC_CONFIG_HEADER(config.h)
AC_CONFIG_FILES([Makefile src/intgtests/Makefile src/intgtests/test_pam_services/ph_test_svc])
AC_OUTPUT

