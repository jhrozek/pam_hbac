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
