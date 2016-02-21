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

struct ph_user *
mock_user_obj(const char *name,
              ...)
{
    struct ph_user *user;
    va_list ap;
    va_list ap_copy;
    const char *v;
    size_t num_groups = 0;
    size_t i;

    va_copy(ap_copy, ap);

    va_start(ap_copy, name);
    while ((v = va_arg(ap_copy, const char *)) != NULL) {
        num_groups++;
    }
    va_end(ap_copy);

    user = malloc(sizeof(struct ph_user));
    if (user == NULL) {
        return NULL;
    }

    user->name = strdup(name);
    if (user->name == NULL) {
        ph_free_user(user);
        return NULL;
    }

    user->group_names = calloc(num_groups + 1, sizeof(const char *));
    if (user->group_names == NULL) {
        ph_free_user(user);
        return NULL;
    }

    va_start(ap, name);
    for (i=0; (v = va_arg(ap, const char *)) != NULL; i++) {
        user->group_names[i] = strdup(v);
        if (user->group_names[i] == NULL) {
            ph_free_user(user);
            return NULL;
        }
    }
    va_end(ap);

    return user;
}
