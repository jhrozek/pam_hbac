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

#define _GNU_SOURCE

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

#include "pam_hbac.h"

void free_string_clist(const char **list)
{
    size_t i;

    if (list == NULL) {
        return;
    }

    for (i = 0; list[i]; i++) {
        free_const(list[i]);
    }
    free(list);
}

void free_string_list(char **list)
{
    size_t i;

    if (list == NULL) {
        return;
    }

    for (i = 0; list[i]; i++) {
        free(list[i]);
    }
    free(list);
}

