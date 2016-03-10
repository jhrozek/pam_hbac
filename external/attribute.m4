AC_DEFUN([CC_ATTRIBUTE_PRINTF], [
    AC_CACHE_CHECK([whether compiler supports __attribute__((format))],
                ph_cv_attribute_format,
                [AC_COMPILE_IFELSE(
                        [AC_LANG_SOURCE(
                            [void debug_fn(const char *format, ...) __attribute__ ((format (printf, 1, 2)));]
                        )],
                        [ph_cv_attribute_format=yes],
                        [
                            AC_MSG_RESULT([no])
                            AC_MSG_WARN([compiler does NOT support __attribute__((format))])
                        ])
                ])

    if test x"$ph_cv_attribute_format" = xyes ; then
    AC_DEFINE(HAVE_FUNCTION_ATTRIBUTE_FORMAT, 1,
                [whether compiler supports __attribute__((format))])
    fi
])
