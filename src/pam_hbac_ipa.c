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

#define _GNU_SOURCE

#include <ldap.h>
#include <errno.h>
#include <stdio.h>
#include <sys/time.h>

#include <security/_pam_macros.h>

#include "pam_hbac.h"
#include "config.h"

enum ph_user_attrmap {
    PH_MAP_USER_OC,
    PH_MAP_USER_NAME,
    PH_MAP_USER_MEMBEROF,
    PH_MAP_USER_END
};
static const char *ph_user_attrs[] = { PAM_HBAC_ATTR_OC, "uid", "memberof", NULL };

enum ph_rule_attrmap {
    PH_MAP_RULE_OC,
    PH_MAP_RULE_NAME,
    PH_MAP_RULE_UNIQUE_ID,
    PH_MAP_RULE_ENABLED_FLAG,
    PH_MAP_RULE_ACCESS_RULE_TYPE,
    PH_MAP_RULE_MEMBER_USER,
    PH_MAP_RULE_USER_CAT,
    PH_MAP_RULE_MEMBER_SVC,
    PH_MAP_RULE_SVC_CAT,
    PH_MAP_RULE_SRC_HOST,
    PH_MAP_RULE_SRC_HOST_CAT,
    PH_MAP_RULE_EXTERNAL_HOST,
    PH_MAP_RULE_MEMBER_HOST,
    PH_MAP_RULE_HOST_CAT,
    PH_MAP_RULE_END
};
static const char *ph_rule_attrs[] = { PAM_HBAC_ATTR_OC, "cn", "ipaUniqueID",
                                       "ipaEnabledFlag", "accessRuleType",
                                       "memberUser", "userCategory",
                                       "memberService", "serviceCategory",
                                       "sourceHost", "sourceHostCategory",
                                       "externalHost", "memberHost",
                                       "hostCategory", NULL };

enum ph_host_attrmap {
    PH_MAP_HOST_OC,
    PH_MAP_HOST_NAME,
    PH_MAP_HOST_FQDN,
    PH_MAP_HOST_MEMBEROF,
    PH_MAP_HOST_END
};
static const char *ph_host_attrs[] = { PAM_HBAC_ATTR_OC, "cn", "fqdn",
                                       "memberOf", NULL };

static struct ph_search_ctx ph_search_objs[] = {
    { .sub_base = "cn=users,cn=accounts", .oc = "posixAccount",
      .attrs = ph_user_attrs, .num_attrs = PH_MAP_USER_END },

    { .sub_base = "cn=hbac", .oc = "ipaHbacRule",
      .attrs = ph_rule_attrs  },

    { .sub_base = "cn=computers,cn=accounts", .oc = "ipaHost",
      .attrs = ph_host_attrs, .num_attrs = PH_MAP_HOST_END },

    { .sub_base = NULL, .oc = NULL }
};

/* Utility functions */
static int
ph_search(LDAP *ld, struct pam_hbac_config *conf, struct ph_search_ctx *s,
          const char *obj_filter, LDAPMessage **res)
{
    int ret;
    char *base = NULL;
    char *filter = NULL;
    struct timeval tv;
    LDAPMessage *msg;

    ret = gettimeofday(&tv, NULL);
    if (ret < 0) {
        ret = errno;
        goto done;
    }
    tv.tv_sec += conf->timeout;

    ret = asprintf(&base, "%s,%s", s->sub_base, conf->search_base);
    if (ret < 0) {
        ret = ENOMEM;
        goto done;
    }

    ret = asprintf(&filter, "(objectclass=%s)", s->oc);
    if (ret < 0) {
        ret = ENOMEM;
        goto done;
    }

    if (obj_filter != NULL) {
        /* FIXME - check if the obj_filter is enclosed in () */
        ret = asprintf(&filter, "(&%s(%s))", filter, obj_filter);
        if (ret < 0) {
            ret = ENOMEM;
            goto done;
        }
    }

    /* FIXME - test timeout */
    D(("searching with filter: %s\n", filter));
    ret = ldap_search_ext_s(ld, base, LDAP_SCOPE_SUBTREE, filter,
                            discard_const(s->attrs),
                            0, NULL, NULL, &tv, 0, &msg);
    if (ret != LDAP_SUCCESS) {
        D(("ldap_search_ext_s failed: %s", ldap_err2string(ret)));
        ret = EIO;
        goto done;
    }

    ret = 0;
    *res = msg;
done:
    free(base);
    free(filter);
    return ret;
}

static int
parse_entry(LDAP *ld, LDAPMessage *entry, struct ph_search_ctx *obj,
            struct ph_entry **_pentry)
{
    BerElement *ber;
    char *a;
    struct berval **vals;
    struct ph_entry *pentry;
    struct ph_attr *attr;
    int index;
    int ret;

    /* check objectclass first */
    if (!ph_ldap_entry_has_oc(ld, entry, obj->oc)) {
        return ENOENT;
    }

    pentry = ph_entry_new(obj);
    if (!pentry) {
        return ENOMEM;
    }

    /* Process the rest of the attributes */
    for (a = ldap_first_attribute(ld, entry, &ber);
         a != NULL;
         a = ldap_next_attribute(ld, entry, ber)) {

        index = ph_want_attr(a, obj);
        if (index == -1) {
            ldap_memfree(a);
            continue;
        }

        vals = ldap_get_values_len(ld, entry, a);
        attr = ph_attr_new(a, vals);
        if (!attr) {
            ph_entry_free(pentry);
            ldap_value_free_len(vals);
            return ENOMEM;
        }
        /* attr owns vals and a now */

        ret = ph_entry_set_attr(pentry, attr, index);
        if (ret) {
            ph_attr_free(attr);
            ph_entry_free(pentry);
            return ret;
        }
    }

    if (ber != NULL) {
        ber_free(ber, 0);
    }

    *_pentry = pentry;
    return 0;
}

static int
ph_parse_message(LDAP *ld, LDAPMessage *msg, struct ph_search_ctx *s,
                 struct ph_entry **_entries)
{
    int num_entries;
    LDAPMessage *ent;
    int ent_type;
    int ret;
    struct ph_entry *pentry;
    struct ph_entry *first = NULL;

    num_entries = ldap_count_entries(ld, msg);
    D(("Found %d entries\n", num_entries));

    /* Iterate through the results. */
    for (ent = ldap_first_message(ld, msg);
         ent != NULL;
         ent = ldap_next_message(ld, ent)) {
        /* Determine what type of message was sent from the server. */
        ent_type = ldap_msgtype(ent);
        switch(ent_type) {
            case LDAP_RES_SEARCH_ENTRY:
                /* The result is an entry. */
                ret = parse_entry(ld, ent, s, &pentry);
                if (ret != 0) {
                    /* FIXME - free resources */
                    return ret;
                }
#if 0
                ph_entry_debug(pentry);
#endif
                ph_entry_add(&first, pentry);
                break;
            case LDAP_RES_SEARCH_REFERENCE:
                D(("No support for referrals.."));
                break;
            case LDAP_RES_SEARCH_RESULT:
                /* The result is the final result sent by the server. */
                break;
            default:
                D(("Unexpected message type %d, ignoring\n", ent_type));
                break;
        }
    }

    *_entries = first;
    return 0;
}

/* Search specific objects */
int
ph_search_user(LDAP *ld, struct pam_hbac_config *conf,
               const char *username, struct ph_member_obj **_user_obj)
{
    int ret;
    size_t num;
    LDAPMessage *msg;
    char *user_filter;
    struct ph_entry *user_entry;
    struct ph_member_obj *user_obj;
    struct berval **vals;

    if (!username) {
        return EINVAL;
    }

    ret = asprintf(&user_filter, "%s=%s", conf->map->user_key, username);
    if (ret < 0) {
        return ENOMEM;
    }

    ret = ph_search(ld, conf, &ph_search_objs[PH_OBJ_USER], user_filter, &msg);
    free(user_filter);
    if (ret != 0) {
        return ret;
    }

    ret = ph_parse_message(ld, msg, &ph_search_objs[PH_OBJ_USER], &user_entry);
    if (ret != 0) {
        ldap_msgfree(msg);
        return ret;
    }

    num = ph_num_entries(user_entry);
    if (num == 0) {
        D(("No such user %s\n", username));
        return ENOENT;
    } else if (num > 1) {
        D(("Got more than one user entry\n"));
        return EINVAL;
    }

    /* extract username */
    vals = ph_entry_get_attr_val(user_entry, PH_MAP_USER_NAME);
    if (!vals) {
        D(("User has no name\n"));
        ph_entry_free(user_entry);
        ldap_msgfree(msg);
        return EINVAL;
    }

    /* FIXME - do not call ldap functions directly */
    if (ldap_count_values_len(vals) != 1) {
        D(("Expected 1 user name, got %d\n", ldap_count_values_len(vals)));
        ph_entry_free(user_entry);
        ldap_msgfree(msg);
        return EINVAL;
    }

    user_obj = ph_member_obj_new(vals[0]->bv_val);
    if (!user_obj) {
        D(("User has no name\n"));
        ph_entry_free(user_entry);
        ldap_msgfree(msg);
        return ENOMEM;
    }

    ph_member_obj_debug(user_obj);

    /* FIXME - extract memberof */

    ldap_msgfree(msg);
    return 0;
}

int
ph_search_host(LDAP *ld, struct pam_hbac_config *conf,
               const char *hostname, struct ph_member_obj **_host_obj)
{
    LDAPMessage *msg;
    size_t num;
    int ret;
    char *host_filter;
    struct ph_entry *host_entry;
    struct ph_member_obj *host_obj;
    struct berval **vals;

    if (!hostname) return EINVAL;

    ret = asprintf(&host_filter, "%s=%s",
                   ph_host_attrs[PH_MAP_HOST_FQDN], hostname);
    if (ret < 0) {
        return ENOMEM;
    }

    /* FIXME - combine search and parse_message into one function to avoid
     * leaking LDAPMessage into this module completely */
    ret = ph_search(ld, conf, &ph_search_objs[PH_OBJ_HOST], host_filter, &msg);
    free(host_filter);
    if (ret != 0) {
        return ret;
    }

    ret = ph_parse_message(ld, msg, &ph_search_objs[PH_OBJ_HOST], &host_entry);
    if (ret != 0) {
        ldap_msgfree(msg);
        return ret;
    }

    num = ph_num_entries(host_entry);
    if (num == 0) {
        D(("No such host %s\n", hostname));
        return ENOENT;
    } else if (num > 1) {
        D(("Got more than one host entry\n"));
        return EINVAL;
    }

    /* extract hostname */
    vals = ph_entry_get_attr_val(host_entry, PH_MAP_HOST_FQDN);
    if (!vals) {
        D(("User has no name\n"));
        ph_entry_free(host_entry);
        ldap_msgfree(msg);
        return EINVAL;
    }

    /* FIXME - do not call ldap functions directly */
    if (ldap_count_values_len(vals) != 1) {
        D(("Expected 1 host name, got %d\n", ldap_count_values_len(vals)));
        ph_entry_free(host_entry);
        ldap_msgfree(msg);
        return EINVAL;
    }

    host_obj = ph_member_obj_new(vals[0]->bv_val);
    if (!host_obj) {
        D(("User has no name\n"));
        ph_entry_free(host_entry);
        ldap_msgfree(msg);
        return ENOMEM;
    }

    ph_member_obj_debug(host_obj);

    /* FIXME - extract memberof */

    ldap_msgfree(msg);
    return 0;
}


int
ph_search_rules(LDAP *ld, struct pam_hbac_config *conf, const char *hostname)
{
    LDAPMessage *msg;
    char *rule_filter;
    struct ph_entry *rule_entries;
    int ret;

    ret = asprintf(&rule_filter, "(%s=%s)(%s=%s)(|(%s=%s)(%s=%s)",
                   ph_rule_attrs[PH_MAP_RULE_ENABLED_FLAG], PAM_HBAC_TRUE_VALUE,
                   ph_rule_attrs[PH_MAP_RULE_ACCESS_RULE_TYPE], PAM_HBAC_ALLOW_VALUE,
                   ph_rule_attrs[PH_MAP_RULE_SRC_HOST_CAT], PAM_HBAC_ALL_VALUE,
                   ph_rule_attrs[PH_MAP_RULE_MEMBER_HOST], hostname);
    if (ret < 0) {
        return ENOMEM;
    }

    ret = ph_search(ld, conf, &ph_search_objs[PH_OBJ_RULE], rule_filter, &msg);
    free(rule_filter);
    if (ret != 0) {
        return ret;
    }

    ret = ph_parse_message(ld, msg, &ph_search_objs[PH_OBJ_RULE], &rule_entries);
    if (ret != 0) {
        ldap_msgfree(msg);
        return ret;
    }

    return 0;
}

