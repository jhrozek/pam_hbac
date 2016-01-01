/*
    Copyright (C) 2014 Jakub Hrozek <jakub.hrozek@gmail.com>

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef __PAM_HBAC_COMPAT_H__
#define __PAM_HBAC_COMPAT_H__

#include <security/pam_appl.h>

#ifdef HAVE_SECURITY__PAM_MACROS_H
# include <security/_pam_macros.h>
#endif /* HAVE_SECURITY__PAM_MACROS_H */

#ifndef _pam_overwrite
#define _pam_overwrite(x)        \
do {                             \
     register char *__xx__;      \
     if ((__xx__=(x)))           \
          while (*__xx__)        \
               *__xx__++ = '\0'; \
} while (0)
#endif /* _pam_overwrite */

#ifndef _pam_overwrite_n
#define _pam_overwrite_n(x,n)   \
do {                             \
     register char *__xx__;      \
     register unsigned int __i__ = 0;    \
     if ((__xx__=(x)))           \
        for (;__i__<n; __i__++) \
            __xx__[__i__] = 0; \
} while (0)
#endif /* _pam_overwrite_n */

#ifndef D
#define D(x)   do { } while (0)
#endif /* D */

#ifdef HAVE_SECURITY_PAM_MODUTIL_H
# include <security/pam_modutil.h>
#endif /* HAVE_SECURITY_PAM_MODUTIL_H */

#ifdef HAVE_SECURITY_PAM_EXT_H
# include <security/pam_ext.h>
#endif /* HAVE_SECURITY_PAM_EXT_H */

#ifdef HAVE_SECURITY_OPENPAM_H
# include <security/openpam.h>
#endif /* HAVE_SECURITY_OPENPAM_H */

#ifndef HAVE_PAM_VSYSLOG
#define pam_vsyslog(pamh, priority, fmt, vargs) \
    vsyslog((priority), (fmt), (vargs))
#endif /* HAVE_PAM_VSYSLOG */

#ifndef HAVE_PAM_SYSLOG
#define pam_syslog(pamh, priority, fmt, vargs) \
    syslog((priority), (fmt), (vargs))
#endif /* HAVE_PAM_VSYSLOG */

#ifndef PAM_BAD_ITEM
# define PAM_BAD_ITEM PAM_USER_UNKNOWN
#endif /* PAM_BAD_ITEM */

#ifndef HOST_NAME_MAX
#define HOST_NAME_MAX 255
#endif /* HOST_NAME_MAX */

#endif /* __PAM_HBAC_COMPAT_H__ */


