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

#include "pam_hbac_compat.h"
#include "pam_hbac_ldap.h"

static int
internal_search(pam_handle_t *pamh,
                LDAP *ld,
                int timeout,
                const char *search_base,
                const char * const attrs[],
                const char *filter,
                LDAPMessage **_msg)
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

    logger(pamh, LOG_DEBUG,
           "Searching LDAP using filter [%s] base [%s] timeout [%d]\n",
           filter, search_base, timeout);

    ret = ldap_search_ext_s(ld, search_base, LDAP_SCOPE_SUBTREE, filter,
                            discard_const(attrs), 0, NULL, NULL, &tv, 0, &msg);
    if (ret != LDAP_SUCCESS) {
        D(("ldap_search_ext_s failed: %s", ldap_err2string(ret)));
        ret = EIO;
        goto done;
    }

    ret = 0;
    *_msg = msg;
done:
    return ret;
}

static bool
entry_has_oc(pam_handle_t *pamh, LDAP *ld, LDAPMessage *entry, const char *oc)
{
    size_t i;
    struct berval **vals;
    bool ret;

    vals = ldap_get_values_len(ld, entry, PAM_HBAC_ATTR_OC);
    if (vals == NULL) {
        logger(pamh, LOG_ERR, "No objectclass? Corrupt entry\n");
        return false;
    }

    for (i = 0; vals[i] != NULL; i++) {
        if (strcasecmp(vals[i]->bv_val, oc) == 0) {
            break;
        }
    }

    if (vals[i] == NULL) {
        logger(pamh, LOG_NOTICE, "Could not find objectclass %s\n", oc);
        ret = false;
    } else {
        ret = true;
    }

    ldap_value_free_len(vals);
    return ret;
}

static int
want_attrname(const char *attr, struct ph_search_ctx *obj)
{
    for (size_t i = 0; i < obj->num_attrs; i++) {
        if (strcasecmp(obj->attrs[i], attr) == 0) {
            return i;
        }
    }

    return -1;
}

static int
parse_entry(pam_handle_t *pamh,
            LDAP *ld,
            LDAPMessage *entry,
            struct ph_search_ctx *obj,
            struct ph_entry *pentry)
{
    BerElement *ber = NULL;
    char *a;
    struct berval **vals;
    struct ph_attr *attr;
    int index;
    int ret;
    char *dn;
    size_t num_attrs;

    dn = ldap_get_dn(ld, entry);
    logger(pamh, LOG_DEBUG, "received DN: %s\n", dn);

    /* check objectclass first */
    if (entry_has_oc(pamh, ld, entry, obj->oc) == false) {
        return ENOENT;
    }

    /* Process the rest of the attributes */
    num_attrs = 0;
    for (a = ldap_first_attribute(ld, entry, &ber);
         a != NULL;
         a = ldap_next_attribute(ld, entry, ber)) {

        index = want_attrname(a, obj);
        if (index == -1) {
            ldap_memfree(a);
            continue;
        }

        logger(pamh, LOG_DEBUG, "Received attribute %s\n", a);
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
        num_attrs++;
    }

    logger(pamh, LOG_DEBUG, "Total attributes %d\n", num_attrs);

    /* FIXME - should we iterate here over unset attrs and set them
     * to an empty value?
     */

    if (ber != NULL) {
        ber_free(ber, 0);
    }

    return 0;
}

static int
parse_ldap_msg(pam_handle_t *pamh,
               LDAP *ld,
               LDAPMessage *msg,
               struct ph_search_ctx *s,
               size_t num_entries,
               struct ph_entry **entries)
{
    LDAPMessage *ent;
    int ent_type;
    int ret;
    size_t entry_idx = 0;

    if (msg == NULL) {
        /* Return empty array and let the caller iterate over it */
        return 0;
    }

    /* Iterate through the results. */
    for (ent = ldap_first_message(ld, msg);
         ent != NULL;
         ent = ldap_next_message(ld, ent)) {
        /* Determine what type of message was sent from the server. */
        ent_type = ldap_msgtype(ent);
        switch (ent_type) {
            /* FIXME - break into a function? */
            case LDAP_RES_SEARCH_ENTRY:
                if (entry_idx >= num_entries) {
                    /* Be defensive.. */
                    return E2BIG;
                }

                /* The result is an entry. */
                ret = parse_entry(pamh, ld, ent, s, entries[entry_idx]);
                if (ret != 0) {
                    /* This is safe b/c we don't support deny fules */
                    continue;
                }
                entry_idx++;
                break;
            case LDAP_RES_SEARCH_REFERENCE:
                logger(pamh, LOG_NOTICE, "No support for referrals..");
                break;
            case LDAP_RES_SEARCH_RESULT:
                /* The result is the final result sent by the server. */
                break;
            default:
                logger(pamh, LOG_NOTICE,
                       "Unexpected message type %d, ignoring\n", ent_type);
                break;
        }
    }

    return 0;
}

static int
parse_message(pam_handle_t *pamh,
              LDAP *ld,
              LDAPMessage *msg,
              struct ph_search_ctx *s,
              struct ph_entry ***_entries)
{
    struct ph_entry **entries = NULL;
    size_t num_entries;
    int ret;

    num_entries = ldap_count_entries(ld, msg);
    logger(pamh, LOG_DEBUG, "Found %d entries\n", num_entries);

    entries = ph_entry_array_alloc(s->num_attrs, num_entries);
    if (entries == NULL) {
        return ENOMEM;
    }

    ret = parse_ldap_msg(pamh, ld, msg, s, num_entries, entries);
    if (ret != 0) {
        ph_entry_array_free(entries);
        return ret;
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
ph_search(pam_handle_t *pamh,
          LDAP *ld,
          struct pam_hbac_config *conf,
          struct ph_search_ctx *s,
          const char *obj_filter,
          struct ph_entry ***_entry_list)
{
    LDAPMessage *msg = NULL;
    char *search_base = NULL;
    char *filter = NULL;
    int ret;
    struct ph_entry **entry_list;

    if (ld == NULL || conf == NULL || s == NULL) {
        logger(pamh, LOG_ERR, "Invalid parameters\n");
        return EINVAL;
    }

    ret = asprintf(&search_base, "%s,%s", s->sub_base, conf->search_base);
    if (ret < 0) {
        logger(pamh, LOG_CRIT, "Cannot create filter\n");
        ret = ENOMEM;
        goto done;
    }

    filter = compose_search_filter(s, obj_filter);
    if (filter == NULL) {
        logger(pamh, LOG_CRIT, "Cannot compose filter\n");
        ret = ENOMEM;
        goto done;
    }

    ret = internal_search(pamh, ld, conf->timeout, search_base, s->attrs,
                          filter, &msg);
    if (ret != 0) {
        logger(pamh, LOG_ERR,
               "Search returned [%d]: %s\n", ret, strerror(ret));
        goto done;
    }

    ret = parse_message(pamh, ld, msg, s, &entry_list);
    if (ret != 0) {
        logger(pamh, LOG_ERR,
               "Message parsing failed [%d]: %s\n", ret, strerror(ret));
        goto done;
    }

    *_entry_list = entry_list;
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

    if (ctx == NULL) {
        return EINVAL;
    }

    ret = ldap_initialize(&ld, ctx->pc->uri);
    if (ret != LDAP_SUCCESS) {
        logger(ctx->pamh, LOG_ERR,
               "ldap_initialize failed [%d]: %s\n",
               ret, ldap_err2string(ret));
        return EIO;
    }

    password.bv_len = strlen(ctx->pc->bind_pw);
    password.bv_val = discard_const(ctx->pc->bind_pw);

    ret = ldap_sasl_bind_s(ld, ctx->pc->bind_dn, LDAP_SASL_SIMPLE, &password,
                           NULL, NULL, NULL);
    if (ret != LDAP_SUCCESS) {
        logger(ctx->pamh, LOG_ERR,
               "ldap_simple_bind_s failed [%d]: %s\n",
               ret, ldap_err2string(ret));
        ldap_destroy(ld);
        return EACCES;
    }

    ctx->ld = ld;
    return 0;
}

void
ph_disconnect(struct pam_hbac_ctx *ctx)
{
    int ret;

    if (ctx == NULL || ctx->ld == NULL) {
        return;
    }

    ret = ldap_unbind_ext(ctx->ld, NULL, NULL);
    if (ret != LDAP_SUCCESS) {
        logger(ctx->pamh, LOG_ERR,
               "ldap_unbind_ext failed [%d]: %s\n",
               ret, ldap_err2string(ret));
    }
    ctx->ld = NULL;
}
