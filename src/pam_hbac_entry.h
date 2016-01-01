/*
    Copyright (C) 2016 Jakub Hrozek <jakub.hrozek@posteo.se>

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

#ifndef __PAM_HBAC_ENTRY_H__
#define __PAM_HBAC_ENTRY_H__

#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>

/* This is a header that should be included in modules that deal with
 * entries from LDAP before their conversion to 'native' HBAC structures.
 */
/* FIXME - should we make this struct opaque? */
struct ph_attr {
    char *name;
    struct berval **vals;
    size_t nvals;
};

struct ph_attr *ph_attr_new(char *name, struct berval **vals);
void ph_attr_free(struct ph_attr *a);

struct ph_entry;

struct ph_entry *ph_entry_array_new(size_t num_entry_attrs, size_t num_entries);
struct ph_entry *ph_entry_array_el(struct ph_entry *head, size_t entry_idx);
size_t ph_num_entries(struct ph_entry *head);
int ph_entry_set_attr(struct ph_entry *e, struct ph_attr *a, size_t index);
struct ph_attr *ph_entry_get_attr_val(struct ph_entry *e, size_t attr_index);
void ph_entry_array_free(struct ph_entry *head);

#endif /* __PAM_HBAC_ENTRY_H__ */
