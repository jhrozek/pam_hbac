AC_PREREQ(2.59)

m4_include([version.m4])
m4_include([external/attribute.m4])

AC_INIT([libpam_hbac],
        VERSION_NUMBER,
        [jakub.hrozek@gmail.com])

AC_CONFIG_AUX_DIR([build])

AM_INIT_AUTOMAKE([-Wall foreign subdir-objects])
AM_PROG_CC_C_O
AC_DISABLE_STATIC
AC_PROG_INSTALL
AC_PROG_LIBTOOL
AC_CONFIG_MACRO_DIR([m4])

m4_pattern_allow([AM_SILENT_RULES])
AM_SILENT_RULES


AM_CONDITIONAL([HAVE_GCC], [test "$ac_cv_prog_gcc" = yes])
AC_CACHE_CHECK([whether compiler supports __attribute__((unused))],
                pam_hbac_cv_attribute_unused,
                [AC_COMPILE_IFELSE(
                    [AC_LANG_SOURCE([__attribute__((unused)) static void cleanup(void) { }])],
                    pam_hbac_cv_attribute_unused=yes)
                ])

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

# Unit tests
PKG_CHECK_MODULES([CHECK], [check >= 0.9.5], [have_check=1], [have_check=])
if test x$have_check = x; then
    AC_MSG_WARN([Without the 'CHECK' libraries, you will be unable to run all tests in the 'make check' suite])
else
    AC_CHECK_HEADERS([check.h],,AC_MSG_ERROR([Could not find CHECK headers]))
fi
AM_CONDITIONAL([HAVE_CHECK], [test x$have_check != x])

AC_CONFIG_HEADER(config.h)
AC_CONFIG_FILES([Makefile])
AC_OUTPUT

