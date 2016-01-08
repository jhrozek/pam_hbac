/*
    Copyright (C) 2015 Jakub Hrozek <jakub.hrozek@posteo.se>

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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>

#include <errno.h>
#include "pam_hbac.h"
#include "pam_hbac_entry.h"
#include "pam_hbac_obj.h"
#include "pam_hbac_obj_int.h"

struct ph_attr *
mock_ph_attr(const char *name, ...)
{
    va_list ap;
    char *nc;
    const char *v = NULL;
    struct berval *bv;
    struct berval **vals = NULL;

    va_start(ap, name);
    while ((v = va_arg(ap, const char *)) != NULL) {
        bv = ber_bvstrdup(v);
        if (bv == NULL) {
            ber_bvecfree(vals);
            return NULL;
        }
        ber_bvecadd(&vals, bv);
    }
    va_end(ap);

    nc = ldap_strdup(name);
    if (nc == NULL) {
        ber_bvecfree(vals);
        return NULL;
    }

    return ph_attr_new(nc, vals);
}
