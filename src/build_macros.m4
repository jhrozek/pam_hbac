dnl PH_AC_EXPAND_LIB_DIR() prepare variable sss_extra_libdir,
dnl variable will contain expanded version of string "$libdir"
dnl therefore this variable can be safely added to LDFLAGS as
dnl "-L$sss_extra_libdir ".
dnl
dnl Taken from SSSD sources
AC_DEFUN([PH_AC_EXPAND_LIB_DIR],
[
    AC_REQUIRE([AC_LIB_PREPARE_PREFIX])
    dnl By default, look in $includedir and $libdir.
    AC_LIB_WITH_FINAL_PREFIX([
        eval additional_libdir=\"$libdir\"
    ])
    sss_extra_libdir="$additional_libdir"
])
