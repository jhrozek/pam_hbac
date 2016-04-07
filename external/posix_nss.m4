AC_DEFUN([AM_CHECK_POSIX_GETPWNAM],
[
    AC_CACHE_CHECK([for posix getpwnam_r],
                   ac_cv_func_posix_getpwnam_r,
                   [AC_TRY_RUN([
#include <errno.h>
#include <pwd.h>
    int main () {
        char buffer[10000];
        struct passwd pwd, *pwptr = &pwd;
        int error;
        errno = 0;
        error = getpwnam_r ("", &pwd, buffer,
                            sizeof (buffer), &pwptr);
    return (error < 0 && errno == ENOSYS)
            || error == ENOSYS;
    }
                   ],
                   [ac_cv_func_posix_getpwnam_r=yes],
                   [ac_cv_func_posix_getpwnam_r=no])])

    if test "$ac_cv_func_posix_getpwnam_r" = yes; then
        AC_DEFINE([HAVE_POSIX_GETPWNAM_R], [],
                  [Have POSIX function getpwnam_r])
    else
        AC_CACHE_CHECK([for nonposix getpwnam_r],
                       ac_cv_func_nonposix_getpwnam_r,
                       [AC_TRY_LINK([#include <pwd.h>],
                                     [char buffer[10000];
                                      struct passwd pwd;
                                      getpwnam_r ("", &pwd, buffer,
                                                     sizeof (buffer));],
                        [ac_cv_func_nonposix_getpwnam_r=yes],
                        [ac_cv_func_nonposix_getpwnam_r=no])])

        if test "$ac_cv_func_nonposix_getpwnam_r" = yes; then
            AC_DEFINE([HAVE_NONPOSIX_GETPWNAM_R], [],
                      [Have non-POSIX function getpwnam_r])
        fi
    fi
])

AC_DEFUN([AM_CHECK_POSIX_GETGRGID],
[
    AC_CACHE_CHECK([for posix getgrgid_r],
                   ac_cv_func_posix_getgrgid_r,
                   [AC_TRY_RUN([
#include <errno.h>
#include <grp.h>
    int main () {
        char buffer[10000];
        struct group grp, *grptr = &grp;
        int error;
        errno = 0;
        error = getgrgid_r ("", &grp, buffer,
                            sizeof (buffer), &grptr);
    return (error < 0 && errno == ENOSYS)
            || error == ENOSYS;
    }
                   ],
                   [ac_cv_func_posix_getgrgid_r=yes],
                   [ac_cv_func_posix_getgrgid_r=no])])

    if test "$ac_cv_func_posix_getgrgid_r" = yes; then
        AC_DEFINE([HAVE_POSIX_GETGRGID_R], [],
                  [Have POSIX function getgrgid_r])
    else
        AC_CACHE_CHECK([for nonposix getgrgid_r],
                       ac_cv_func_nonposix_getgrgid_r,
                       [AC_TRY_LINK([#include <grp.h>],
                                     [char buffer[10000];
                                      struct group grp;
                                      getgrgid_r ("", &grp, buffer,
                                                     sizeof (buffer));],
                        [ac_cv_func_nonposix_getgrgid_r=yes],
                        [ac_cv_func_nonposix_getgrgid_r=no])])

        if test "$ac_cv_func_nonposix_getgrgid_r" = yes; then
            AC_DEFINE([HAVE_NONPOSIX_GETGRGID_R], [],
                      [Have non-POSIX function getgrgid_r])
        fi
    fi
])
