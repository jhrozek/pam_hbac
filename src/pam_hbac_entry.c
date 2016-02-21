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

#include <ldap.h>
#include <stdlib.h>
#include <errno.h>

#include "pam_hbac.h"
#include "pam_hbac_entry.h"

/* entry attribute */
struct ph_attr *
ph_attr_new(char *name, struct berval **vals)
{
    struct ph_attr *a;

    if (name == NULL || vals == NULL) {
        return NULL;
    }

    a = malloc(sizeof(struct ph_attr));
    if (a == NULL) {
        return NULL;
    }

    a->name = name;
    a->vals = vals;
    a->nvals = ldap_count_values_len(a->vals);

    return a;
}

void
ph_attr_free(struct ph_attr *a)
{
    if (a == NULL) {
        return;
    }

    ldap_value_free_len(a->vals);
    ldap_memfree(a->name);
    free(a);
}

/* search entry */
struct ph_entry *
ph_entry_alloc(size_t num_attrs)
{
    struct ph_entry *e;

    e = malloc(sizeof(struct ph_entry));
    if (e == NULL) {
        return NULL;
    }

    e->num_attrs = num_attrs;
    e->attrs = calloc(num_attrs, sizeof(struct ph_attr *));
    if (e->attrs == NULL) {
        free(e);
        return NULL;
    }

    return e;
}

void
ph_entry_free(struct ph_entry *e)
{
    size_t i;

    if (e == NULL) {
        return;
    }

    if (e->attrs) {
        for (i=0; i < e->num_attrs; i++) {
            ph_attr_free(e->attrs[i]);
        }
    }

    free(e->attrs);
    free(e);
}

/* FIXME - we should reverse the order of params to look more
 * like calloc()
 */
struct ph_entry **
ph_entry_array_alloc(size_t num_entry_attrs,
                     size_t num_entries)
{
    struct ph_entry **e;
    size_t i;

    e = calloc(num_entries + 1, sizeof(struct ph_entry *));
    if (e == NULL) {
        return NULL;
    }

    for (i = 0; i < num_entries; i++) {
        e[i] = ph_entry_alloc(num_entry_attrs);
        if (e[i] == NULL) {
            ph_entry_array_free(e);
            return NULL;
        }
    }

    return e;
}

int
ph_entry_set_attr(struct ph_entry *e,
                  struct ph_attr *a,
                  size_t attr_index)
{
    if (e == NULL || e->attrs == NULL) {
        return EINVAL;
    }

    if (attr_index >= e->num_attrs) {
        return EINVAL;
    }

    e->attrs[attr_index] = a;
    return 0;
}

size_t
ph_num_entries(struct ph_entry **entry_list)
{
    size_t num;

    if (entry_list == NULL) {
        return 0;
    }

    for (num = 0; entry_list[num]; num++) ;

    return num;
}

struct ph_attr *
ph_entry_get_attr(struct ph_entry *e,
                  size_t attr_index)
{
    struct ph_attr *a;

    if (e == NULL || e->attrs == NULL) {
        return NULL;
    }

    if (attr_index >= e->num_attrs) {
        return NULL;
    }

    a = e->attrs[attr_index];
    if (a == NULL) {
        return NULL;
    }

    return a;
}

void ph_entry_array_free(struct ph_entry **entry_list)
{
    size_t i;

    if (entry_list == NULL) {
        return;
    }

    for (i = 0; entry_list[i]; i++) {
        ph_entry_free(entry_list[i]);
    }
    free(entry_list);
}

void ph_entry_array_shallow_free(struct ph_entry **entry_list)
{
    free(entry_list);
}
