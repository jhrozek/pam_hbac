# Original author - Diego "Flameeyes" Pettenò - http://dev.gentoo.org/~flameeyes/

AC_DEFUN([CC_ATTRIBUTE_NONNULL], [
 AC_CACHE_CHECK([if compiler supports __attribute__((nonnull()))],
     [cc_cv_attribute_nonnull],
     [AC_COMPILE_IFELSE([
        AC_LANG_SOURCE([
         void some_function(void *foo, void *bar) __attribute__((nonnull()));
         void some_function(void *foo, void *bar) { } ])
         ],
         [cc_cv_attribute_nonnull=yes],
         [cc_cv_attribute_nonnull=no])
     ])
 
 if test "x$cc_cv_attribute_nonnull" = "xyes"; then
     AC_DEFINE([SUPPORT_ATTRIBUTE_NONNULL], 1, [Define this if the compiler supports the nonnull attribute])
     $1
 else
     true
     $2
 fi
])

AC_DEFUN([CC_ATTRIBUTE_UNUSED], [
 AC_CACHE_CHECK([if compiler supports __attribute__((unused))],
     [cc_cv_attribute_unused],
     [AC_COMPILE_IFELSE([
        AC_LANG_SOURCE([
         void some_function(void *foo, __attribute__((unused)) void *bar); ])
         ],
         [cc_cv_attribute_unused=yes],
         [cc_cv_attribute_unused=no])
     ])
 
 if test "x$cc_cv_attribute_unused" = "xyes"; then
     AC_DEFINE([SUPPORT_ATTRIBUTE_UNUSED], 1, [Define this if the compiler supports the unused attribute])
     $1
 else
     true
     $2
 fi
])

