AC_PREREQ(2.59)

m4_include([version.m4])
m4_include([src/conf_macros.m4])
m4_include([src/build_macros.m4])
m4_include([external/libcmocka.m4])
m4_include([external/cwrap.m4])
m4_include([external/a2x.m4])

AC_INIT([pam_hbac],
        VERSION_NUMBER,
        [jakub.hrozek@posteo.se])

AC_CONFIG_AUX_DIR([build])

AM_INIT_AUTOMAKE([-Wall foreign subdir-objects])
m4_ifdef([AM_PROG_AR], [AM_PROG_AR])
AM_PROG_CC_C_O
AC_DISABLE_STATIC
AC_PROG_INSTALL
AC_PROG_LIBTOOL
AC_CONFIG_MACRO_DIR([m4])

m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES])

AM_CONDITIONAL([HAVE_GCC], [test "$ac_cv_prog_gcc" = yes])

#Check for PAM headers
AC_CHECK_HEADERS([security/pam_appl.h])
AC_CHECK_HEADERS([security/pam_modules.h],,,[
      #ifdef HAVE_SECURITY_PAM_APPL_H
      #include <security/pam_appl.h>
      #endif
    ])

AC_CHECK_LIB([pam], [pam_get_item],
             [PAM_LIBS="-lpam"],
             [AC_MSG_ERROR([PAM must support pam_get_item])])

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

dnl check for LDAP libraries
AC_CHECK_HEADERS([lber.h])
AC_CHECK_HEADERS([ldap.h],
                 [],
                 AC_MSG_ERROR([could not locate <ldap.h>]),
                 [ #if HAVE_LBER_H
                   #include <lber.h>
                   #endif
                 ])

#Set the PAM module install path
WITH_PAM_MOD_DIR

# Detect the selected Unicode library
WITH_UNICODE_LIB
if test x$unicode_lib = xlibunistring; then
    m4_include([external/libunistring.m4])
    AC_DEFINE_UNQUOTED(HAVE_LIBUNISTRING, 1, [Using libunistring for unicode])
    UNICODE_LIBS=$UNISTRING_LIBS
else
    m4_include([external/glib.m4])
    AC_DEFINE_UNQUOTED(HAVE_GLIB2, 1, [Using glib2 for unicode])
    UNICODE_LIBS=$GLIB2_LIBS
fi
AC_SUBST(UNICODE_LIBS)

# Optional build dependencies - man pages generation
CHECK_ASCIIDOC_TOOLS
AM_CONDITIONAL([HAVE_MANPAGES], [test "x$A2X" != "x"])

# Optional build dependencies - Unit tests
AM_CHECK_CMOCKA
AM_CHECK_NSS_WRAPPER
AM_CHECK_PAM_WRAPPER

AC_CONFIG_HEADER(config.h)
AC_CONFIG_FILES([Makefile
                 doc/Makefile
                 src/intgtests/Makefile
                 src/intgtests/test_pam_services/ph_test_svc])
AC_OUTPUT

