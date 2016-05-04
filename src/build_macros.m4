dnl PH_AC_EXPAND_LIB_DIR() prepare variable ph_extra_libdir,
dnl variable will contain expanded version of string "$libdir"
dnl if autotools macro AC_LIB_PREPARE_PREFIX is available.
dnl it shoudl be part of package gettext.
dnl therefore this variable can be safely added to LDFLAGS as
dnl "-L$ph_extra_libdir ".
dnl
dnl Taken from SSSD sources
AC_DEFUN([PH_AC_EXPAND_LIB_DIR],
[m4_ifdef([AC_LIB_PREPARE_PREFIX],
    [AC_REQUIRE([AC_LIB_PREPARE_PREFIX])
    dnl By default, look in $includedir and $libdir.
    AC_LIB_WITH_FINAL_PREFIX([
        eval additional_libdir=\"$libdir\"
    ])
    ph_extra_libdir="$additional_libdir"],
    [ph_extra_libdir=""]
)])
