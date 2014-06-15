/*
    Copyright (C) 2012 Jakub Hrozek <jakub.hrozek@gmail.com>

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

#include "dlinklist.h"
#include "pam_hbac.h"

/* Helper functions */
bool
ph_ldap_entry_has_oc(LDAP *ld, LDAPMessage *entry, const char *oc)
{
    int i;
    struct berval **vals;

    vals = ldap_get_values_len(ld, entry, PAM_HBAC_ATTR_OC);
    if (vals == NULL) {
        D(("No objectclass? Corrupt entry\n"));
        return false;
    }

    for (i = 0; vals[i] != NULL; i++) {
        if (strcmp(vals[i]->bv_val, oc) == 0) {
            break;
        }
    }
    ldap_value_free_len(vals);

    if (vals[i] == NULL) {
        /* Could not find the expected objectclass */
        D(("Could not find objectclass %s\n", oc));
        return false;
    }

    return true;
}

int
ph_want_attr(const char *attr, struct ph_search_ctx *obj)
{
    int i;

    for (i = 0; i < obj->num_attrs; i++) {
        if (strcmp(obj->attrs[i], attr) == 0) {
            return i;
        }
    }

    return -1;
}

/* entry attribute */
struct ph_attr {
    char *name;
    struct berval **vals;
    size_t nvals;
};

struct ph_attr *
ph_attr_new(char *name, struct berval **vals)
{
    struct ph_attr *a;

    a = malloc(sizeof(struct ph_attr));
    if (!a) return NULL;

    /* FIXME - should we deepcopy? */
    a->name = name;
    a->vals = vals;
    a->nvals = ldap_count_values_len(a->vals);

    return a;
}

void
ph_attr_debug(struct ph_attr *a)
{
    size_t i;

    if (!a || a->vals == NULL || a->nvals == 0) return;

    for (i = 0; i < a->nvals; i++) {
        D(("%s: %s\n", a->name, a->vals[i]->bv_val));
    }
}

void
ph_attr_free(struct ph_attr *a)
{
    if (!a) return;

    ldap_value_free_len(a->vals);
    ldap_memfree(a->name);
    free(a);
}

/* search entry */
struct ph_entry {
    struct ph_entry *next;
    struct ph_entry *prev;

    struct ph_search_ctx *obj;
    struct ph_attr **attrs;
};

struct ph_entry *
ph_entry_new(struct ph_search_ctx *obj)
{
    struct ph_entry *e;

    e = calloc(1, sizeof(struct ph_entry));
    if (!e) return NULL;

    e->obj = obj;
    e->attrs = calloc(e->obj->num_attrs, sizeof(struct ph_attr *));
    if (e->attrs == NULL) {
        free(e);
        return NULL;
    }

    return e;
}

void
ph_entry_debug(struct ph_entry *e)
{
    int i;

    if (!e || !e->attrs || !e->obj) return;

    for (i = 0; i < e->obj->num_attrs; i++) {
        ph_attr_debug(e->attrs[i]);
    }
}

int
ph_entry_set_attr(struct ph_entry *e, struct ph_attr *a, int index)
{
    if (!e || !e->attrs) return EINVAL;

    e->attrs[index] = a;
    return 0;
}

void
ph_entry_add(struct ph_entry **head, struct ph_entry *e)
{
    DLIST_ADD(*head, e);
}

size_t
ph_num_entries(struct ph_entry *head)
{
    size_t num = 0;
    struct ph_entry *e;

    for (e = head; e != NULL; e = e->next) num++;

    return num;
}

struct berval **
ph_entry_get_attr_val(struct ph_entry *e, int attr)
{
    struct ph_attr *a;
    if (!e || !e->attrs) return NULL;

    /* FIXME - split to a separate func? */
    a = e->attrs[attr];
    if (!a) return NULL;

    return a->vals;
}

void
ph_entry_free(struct ph_entry *e)
{
    size_t i;

    if (!e) return;

    if (e->obj == NULL || e->attrs == NULL) {
        /* Corrupt entry? Shouldn't happen */
        free(e);
        return;
    }

    for (i=0; i < e->obj->num_attrs; i++) {
        ph_attr_free(e->attrs[i]);
    }

    free(e->attrs);
    free(e);
}

/* This is what we build the request from */
struct ph_member_obj {
    char *name;
    char **memberofs;
};

struct ph_member_obj *
ph_member_obj_new(char *name)
{
    struct ph_member_obj *o;

    o = calloc(1, sizeof(struct ph_member_obj));
    if (!o) return NULL;

    o->name = name;
    o->memberofs = calloc(1, sizeof(const char *));
    if (!o->memberofs) {
        free(o);
        return NULL;
    }

    return o;
}

void
ph_member_obj_debug(struct ph_member_obj *o)
{
    int i;

    if (!o || !o->name) return;

    if (!o->memberofs || o->memberofs[0] == NULL) {
        D(("%s is not a member of any groups\n", o->name));
    } else {
        for (i = 0; o->memberofs[i]; i++) {
            D(("%s is a member of %s\n", o->name, o->memberofs[i]));
        }
    }
}

void
ph_member_obj_free(struct ph_member_obj *o)
{
    int i;

    if (!o) return;

    if (o->memberofs) {
        for (i = 0; o->memberofs[i]; i++) {
            free(o->memberofs[i]);
        }
    }

    free(o->memberofs);
    free(o);
}
