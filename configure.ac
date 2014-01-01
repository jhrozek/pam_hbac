AC_PREREQ(2.59)

m4_include([version.m4])
m4_include([external/attribute.m4])
m4_include([external/libcmocka.m4])

AC_INIT([libpam_hbac],
        VERSION_NUMBER,
        [jakub.hrozek@gmail.com])

AC_CONFIG_AUX_DIR([build])

AM_INIT_AUTOMAKE([-Wall foreign subdir-objects])
m4_pattern_allow([AM_PROG_AR])
AM_PROG_AR
AM_PROG_CC_C_O
AC_DISABLE_STATIC
AC_PROG_INSTALL
AC_PROG_LIBTOOL
AC_CONFIG_MACRO_DIR([m4])

m4_pattern_allow([AM_SILENT_RULES])
AM_SILENT_RULES

AM_CONDITIONAL([HAVE_GCC], [test "$ac_cv_prog_gcc" = yes])
CC_ATTRIBUTE_NONNULL
CC_ATTRIBUTE_UNUSED

#Check for PAM headers
AC_CHECK_HEADERS([security/pam_ext.h security/pam_modules.h],
                 [AC_CHECK_LIB(pam, pam_get_item, [ PAM_LIBS="-lpam" ], [AC_MSG_ERROR([PAM must support pam_get_item])])],
                 [AC_MSG_ERROR([PAM development libraries not installed])]
                )

#Set the PAM module install path
AC_ARG_ENABLE([pammoddir], [AS_HELP_STRING([--enable-pammoddir],
              [Where to install pam modules ($libdir/security)])],
              [pammoddir=$enableval],
              [pammoddir=$libdir/security])
AC_SUBST(pammoddir)

# Optional build dependencies - Unit tests
AM_CHECK_CMOCKA

AC_CONFIG_HEADER(config.h)
AC_CONFIG_FILES([Makefile])
AC_OUTPUT

