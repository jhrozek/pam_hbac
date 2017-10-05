AC_DEFUN([WITH_UNICODE_LIB],
  [ AC_ARG_WITH([unicode-lib],
                [AC_HELP_STRING([--with-unicode-lib=<library>],
                                [Which library to use for unicode processing (libunistring, glib2) [glib2]]
                               )
                ]
               )
    unicode_lib="glib2"
    if test x"$with_unicode_lib" != x; then
        unicode_lib=$with_unicode_lib
    fi

    if test x"$unicode_lib" != x"libunistring" -a x"$unicode_lib" != x"glib2"; then
        AC_MSG_ERROR([Unsupported unicode library])
    fi

    AM_CONDITIONAL([WITH_LIBUNISTRING], test x"$unicode_lib" = x"libunistring")
    AM_CONDITIONAL([WITH_GLIB], test x"$unicode_lib" = x"glib2")
  ])

AC_DEFUN([WITH_PAM_MOD_DIR],
  [ AC_ARG_WITH([pammoddir],
                [AC_HELP_STRING([--with-pammoddir=<path>],
                                [Where to install pam modules ($libdir/security)]
                               )
                ]
               )

    pammoddir="${libdir}/security"
    if test x"$with_pammoddir" != x; then
        pammoddir=$with_pammoddir
    fi
    AC_SUBST(pammoddir)
  ])

dnl Man pages generation can be disabled on platforms where the a2x binary is not usable
AC_DEFUN([ENABLE_MAN_PAGES],
  [ AC_ARG_ENABLE([man-pages],
                  AS_HELP_STRING([--disable-man-pages], [Do not build man pages]),
                  [enable_man_pages=$enableval],
                  [enable_man_pages="yes"])
    AM_CONDITIONAL([BUILD_MAN_PAGES], test x"$enable_man_pages" = x"yes")
  ])
