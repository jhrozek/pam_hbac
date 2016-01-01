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

#define _GNU_SOURCE

#include <stdio.h>
#include <sys/time.h>

#include "pam_hbac_ldap.h"

static int
internal_search(LDAP *ld,
                int timeout,
                const char *search_base,
                const char * const attrs[],
                const char *filter,
                LDAPMessage **res)
{
    int ret;
    struct timeval tv;
    LDAPMessage *msg;

    ret = gettimeofday(&tv, NULL);
    if (ret < 0) {
        ret = errno;
        goto done;
    }
    tv.tv_sec += timeout;

    /* FIXME - test timeout */
#if 0
    D(("searching with filter: %s\n", filter));
#endif
    ret = ldap_search_ext_s(ld, search_base, LDAP_SCOPE_SUBTREE, filter,
                            discard_const(attrs), 0, NULL, NULL, &tv, 0, &msg);
    if (ret != LDAP_SUCCESS) {
#if 0
        D(("ldap_search_ext_s failed: %s", ldap_err2string(ret)));
#endif
        /* FIXME - better errcode? */
        ret = EIO;
        goto done;
    }

    ret = 0;
    *res = msg;
done:
    return ret;
}

static bool
entry_has_oc(LDAP *ld, LDAPMessage *entry, const char *oc)
{
    int i;
    struct berval **vals;

    vals = ldap_get_values_len(ld, entry, PAM_HBAC_ATTR_OC);
    if (vals == NULL) {
#if 0
        D(("No objectclass? Corrupt entry\n"));
#endif
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
#if 0
        D(("Could not find objectclass %s\n", oc));
#endif
        return false;
    }

    return true;
}

static int
want_attrname(const char *attr, struct ph_search_ctx *obj)
{
    int i;

    for (i = 0; i < obj->num_attrs; i++) {
        if (strcmp(obj->attrs[i], attr) == 0) {
            return i;
        }
    }

    return -1;
}

static int
parse_entry(LDAP *ld,
            LDAPMessage *entry,
            struct ph_search_ctx *obj,
            struct ph_entry *pentry)
{
    BerElement *ber;
    char *a;
    struct berval **vals;
    struct ph_attr *attr;
    int index;
    int ret;

    /* check objectclass first */
    if (!entry_has_oc(ld, entry, obj->oc)) {
        return ENOENT;
    }

    /* Process the rest of the attributes */
    for (a = ldap_first_attribute(ld, entry, &ber);
         a != NULL;
         a = ldap_next_attribute(ld, entry, ber)) {

        index = want_attrname(a, obj);
        if (index == -1) {
            ldap_memfree(a);
            continue;
        }

        vals = ldap_get_values_len(ld, entry, a);
        attr = ph_attr_new(a, vals);
        if (attr == NULL) {
            ldap_memfree(a);
            ldap_value_free_len(vals);
            return ENOMEM;
        }
        /* attr owns vals and a now */

        ret = ph_entry_set_attr(pentry, attr, index);
        if (ret) {
            ph_attr_free(attr);
            return ret;
        }
    }

    if (ber != NULL) {
        ber_free(ber, 0);
    }

    return 0;
}

static int
parse_message(LDAP *ld, LDAPMessage *msg, struct ph_search_ctx *s,
              struct ph_entry **_entries)
{
    int num_entries;
    LDAPMessage *ent;
    int ent_type;
    int ret;
    struct ph_entry *entries = NULL;
    struct ph_entry *pentry = NULL;
    size_t entry_idx = 0;

    num_entries = ldap_count_entries(ld, msg);
#if 0
    D(("Found %d entries\n", num_entries));
#endif

    entries = ph_entry_array_new(s->num_attrs, num_entries);
    if (entries == NULL) {
        return ENOMEM;
    }

    /* Iterate through the results. */
    for (ent = ldap_first_message(ld, msg);
         ent != NULL;
         ent = ldap_next_message(ld, ent)) {
        /* Determine what type of message was sent from the server. */
        ent_type = ldap_msgtype(ent);
        switch (ent_type) {
            case LDAP_RES_SEARCH_ENTRY:
                /* The result is an entry. */
                pentry = ph_entry_array_el(entries, entry_idx);
                if (pentry == NULL) {
                    continue;
                }

                ret = parse_entry(ld, ent, s, pentry);
                if (ret != 0) {
                    /* This is safe b/c we don't support deny fules */
                    continue;
                }
                entry_idx++;
                break;
            case LDAP_RES_SEARCH_REFERENCE:
#if 0
                D(("No support for referrals.."));
#endif
                break;
            case LDAP_RES_SEARCH_RESULT:
                /* The result is the final result sent by the server. */
                break;
            default:
#if 0
                D(("Unexpected message type %d, ignoring\n", ent_type));
#endif
                break;
        }
    }

    *_entries = entries;
    return 0;
}

static char *
compose_search_filter(struct ph_search_ctx *s,
                      const char *obj_filter)
{
    int ret;
    char *oc_filter = NULL;
    char *filter = NULL;

    ret = asprintf(&oc_filter, "(objectclass=%s)", s->oc);
    if (ret < 0) {
        return NULL;
    }

    if (obj_filter != NULL) {
        /* FIXME - check if the obj_filter is enclosed in () */
        ret = asprintf(&filter, "(&%s(%s))", oc_filter, obj_filter);
        free(oc_filter);
        if (ret < 0) {
            free(filter);
            return NULL;
        }
    } else {
        filter = oc_filter;
    }

    return filter;
}

int
ph_search(LDAP *ld,
          struct pam_hbac_config *conf,
          struct ph_search_ctx *s,
          const char *obj_filter,
          struct ph_entry **_pentry)
{
    LDAPMessage *res = NULL;
    char *search_base = NULL;
    char *filter = NULL;
    int ret;
    struct ph_entry *pentry;

    ret = asprintf(&search_base, "%s,%s", s->sub_base, conf->search_base);
    if (ret < 0) {
        ret = ENOMEM;
        goto done;
    }

    filter = compose_search_filter(s, obj_filter);
    if (filter == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = internal_search(ld, conf->timeout, search_base, s->attrs,
                          filter, &res);
    if (ret != 0) {
        goto done;
    }

    ret = parse_message(ld, res, s, &pentry);
    if (ret != 0) {
        goto done;
    }

    *_pentry = pentry;
    ret = 0;
done:
    free(search_base);
    free(filter);
    return ret;
}

int
ph_connect(struct pam_hbac_ctx *ctx)
{
    int ret;
    LDAP *ld;
    struct berval password = {0, NULL};

    /* FIXME - detect availability with configure? */
    ret = ldap_initialize(&ld, ctx->pc->uri);
    if (ret != LDAP_SUCCESS) {
#if 0
        D(("ldap_initialize failed [%d]: %s\n", ret, ldap_err2string(ret)));
#endif
        return EIO;
    }

    password.bv_len = strlen(ctx->pc->bind_pw);
    password.bv_val = discard_const(ctx->pc->bind_pw);

    ret = ldap_sasl_bind_s(ld, ctx->pc->bind_dn, LDAP_SASL_SIMPLE, &password,
                           NULL, NULL, NULL);
    if (ret != LDAP_SUCCESS) {
#if 0
        D(("ldap_simple_bind_s failed [%d]: %s\n", ret, ldap_err2string(ret)));
#endif
        return EACCES;
    }

    ctx->ld = ld;
    return 0;
}
void
ph_disconnect(struct pam_hbac_ctx *ctx)
{
    int ret;

    if (!ctx || !ctx->ld) return;

    ret = ldap_unbind_ext(ctx->ld, NULL, NULL);
    if (ret != LDAP_SUCCESS) {
#if 0
        D(("ldap_unbind_ext failed [%d]: %s\n", ret, ldap_err2string(ret)));
#endif
    }
}

