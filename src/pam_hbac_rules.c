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
#include "pam_hbac_ldap.h"      /* FIXME - should we merge this module and obj? */
#include "pam_hbac_obj_int.h"
#include "pam_hbac_dnparse.h"
#include "pam_hbac_entry.h"
#include "pam_hbac_compat.h"

#include "libhbac/ipa_hbac.h"
#include "config.h"

#define RULE_NAME_FALLBACK  "unknown rule name"

static void free_hbac_rule_element(struct hbac_rule_element *el)
{
    if (el == NULL) {
        return;
    }

    free_string_clist(el->names);
    free_string_clist(el->groups);
    free(el);
}

static void free_hbac_rule(struct hbac_rule *rule)
{
    if (rule == NULL) {
        return;
    }

    free_hbac_rule_element(rule->users);
    free_hbac_rule_element(rule->targethosts);
    free_hbac_rule_element(rule->services);
    free_hbac_rule_element(rule->srchosts);

    free_const(rule->name);
    free(rule);
}

void ph_free_hbac_rules(struct hbac_rule **rules)
{
    size_t i;

    if (rules == NULL) {
        return;
    }

    for (i = 0; rules[i]; i++) {
        free_hbac_rule(rules[i]);
    }
    free(rules);
}

static const char *ph_rule_attrs[] = { PAM_HBAC_ATTR_OC, "cn", "ipaUniqueID",
                                       "ipaEnabledFlag", "accessRuleType",
                                       "memberUser", "userCategory",
                                       "memberService", "serviceCategory",
                                       "memberHost", "hostCategory",
                                       "externalHost",  NULL };

static struct ph_search_ctx rule_search_obj = {
    .sub_base = "cn=hbac",
    .oc = "ipaHbacRule",
    .attrs = ph_rule_attrs,
    .num_attrs = PH_MAP_RULE_END,
};

static char *
create_rules_filter(pam_handle_t *pamh, struct ph_entry *host)
{
    char *prev;
    char *filter;
    int ret;
    size_t i;
    struct ph_attr *hostname;
    struct ph_attr *hostgroups;

    hostname = ph_entry_get_attr(host, PH_MAP_HOST_FQDN);
    if (hostname == NULL || hostname->nvals != 1) {
        logger(pamh, LOG_ERR, "No hostname or more than one hostname\n");
        return NULL;
    }

    ret = asprintf(&filter, "&(%s=%s)(%s=%s)(|(%s=%s)(%s=%s)",
                   ph_rule_attrs[PH_MAP_RULE_ENABLED_FLAG], PAM_HBAC_TRUE_VALUE,
                   ph_rule_attrs[PH_MAP_RULE_ACCESS_RULE_TYPE], PAM_HBAC_ALLOW_VALUE,
                   ph_rule_attrs[PH_MAP_RULE_HOST_CAT], PAM_HBAC_ALL_VALUE,
                   ph_rule_attrs[PH_MAP_RULE_MEMBER_HOST],
                   (const char *) hostname->vals[0]->bv_val);
    if (ret < 0) {
        return NULL;
    }

    hostgroups = ph_entry_get_attr(host, PH_MAP_HOST_MEMBEROF);
    if (hostgroups) {
        for (i = 0; i < hostgroups->nvals; i++) {
            prev = filter;

            ret = asprintf(&filter, "%s(%s=%s)",
                        prev,
                        ph_rule_attrs[PH_MAP_RULE_MEMBER_HOST],
                        (const char *) hostgroups->vals[i]->bv_val);
            free(prev);
            if (ret < 0) {
                free(filter);
                return NULL;
            }
        }
    }

    prev = filter;

    ret = asprintf(&filter, "%s)", prev);
    free(prev);
    if (ret < 0) {
        free(filter);
        return NULL;
    }

    return filter;
}

static struct ph_attr *
el_member_attr(struct ph_entry *rule_entry,
               enum member_el_type el_type)
{
    switch (el_type) {
    case DN_TYPE_USER:
        return ph_entry_get_attr(rule_entry,
                                     PH_MAP_RULE_MEMBER_USER);
    case DN_TYPE_HOST:
        return ph_entry_get_attr(rule_entry,
                                     PH_MAP_RULE_MEMBER_HOST);
    case DN_TYPE_SVC:
        return ph_entry_get_attr(rule_entry,
                                     PH_MAP_RULE_MEMBER_SVC);
    default:
        break;
    }

    return NULL;
}

static struct ph_attr *
el_category_attr(struct ph_entry *rule_entry,
                 enum member_el_type el_type)
{
    switch (el_type) {
    case DN_TYPE_USER:
        return ph_entry_get_attr(rule_entry,
                                 PH_MAP_RULE_USER_CAT);
    case DN_TYPE_HOST:
        return ph_entry_get_attr(rule_entry,
                                 PH_MAP_RULE_HOST_CAT);
    case DN_TYPE_SVC:
        return ph_entry_get_attr(rule_entry,
                                 PH_MAP_RULE_SVC_CAT);
    default:
        break;
    }

    return NULL;
}

static int
el_fill_category(pam_handle_t *pamh,
                 struct ph_entry *rule_entry,
                 enum member_el_type el_type,
                 struct hbac_rule_element *el)
{
    struct ph_attr *cat_attr;
    struct berval *bv;

    el->category = 0;

    cat_attr = el_category_attr(rule_entry, el_type);
    if (cat_attr == NULL || cat_attr->nvals == 0) {
        return ENOENT;
    } else if (cat_attr->nvals > 1) {
        logger(pamh, LOG_ERR, "More than one value for category, fail!\n");
        return EIO;
    }

    bv = cat_attr->vals[0];
    if (strncasecmp(bv->bv_val, PAM_HBAC_ALL_VALUE, bv->bv_len) != 0) {
        logger(pamh, LOG_ERR, "Invalid category value\n");
        return EINVAL;
    }

    logger(pamh, LOG_DEBUG,
           "Setting category ALL for %s\n",
           ph_member_el_type2str(el_type));
    el->category |= HBAC_CATEGORY_ALL;
    return 0;
}

static int
add_empty_rule_element(struct hbac_rule_element **_el)
{
    struct hbac_rule_element *el;

    el = calloc(1, sizeof(struct hbac_rule_element));
    if (el == NULL) {
        return ENOMEM;
    }

    el->names = calloc(1, sizeof(char *));
    el->groups = calloc(1, sizeof(char *));
    if (el->names == NULL || el->groups == NULL) {
        free_hbac_rule_element(el);
        return ENOMEM;
    }
    el->category |= HBAC_CATEGORY_ALL;

    *_el = el;
    return 0;
}

static int
attr_to_rule_element(pam_handle_t *pamh,
                     struct ph_entry *rule_entry,
                     enum member_el_type el_type,
                     struct hbac_rule_element **_el)
{
    struct ph_attr *a;
    struct hbac_rule_element *el;
    size_t i;
    size_t ni;
    size_t gi;
    int ret;
    const char *member_name;

    el = calloc(1, sizeof(struct hbac_rule_element));
    if (el == NULL) {
        return ENOMEM;
    }

    ret = el_fill_category(pamh, rule_entry, el_type, el);
    if (ret == 0) {
        /* Do we still need to check the elements? */
    } else if (ret != ENOENT) {
        free_hbac_rule_element(el);
        return ret;
    }

    a = el_member_attr(rule_entry, el_type);
    if (a == NULL) {
        /* FIXME - test an empty element? */
        logger(pamh, LOG_DEBUG, "No members\n");
        *_el = el;
        return 0;
    }

    el->names = calloc(a->nvals + 1, sizeof(char *));
    el->groups = calloc(a->nvals + 1, sizeof(char *));
    if (el->names == NULL || el->groups == NULL) {
        free_hbac_rule_element(el);
        return ENOMEM;
    }

    ni = gi = 0;
    for (i = 0; i < a->nvals; i++) {
        member_name = NULL;

        ret = ph_name_from_dn(a->vals[i]->bv_val, el_type, &member_name);
        if (ret == 0) {
            logger(pamh, LOG_DEBUG, "%s is a single member object\n", member_name);
            el->names[ni] = member_name;
            ni++;
            continue;
        }

        ret = ph_group_name_from_dn(a->vals[i]->bv_val, el_type, &member_name);
        if (ret == 0) {
            logger(pamh, LOG_DEBUG, "%s is a group member object\n", member_name);
            el->groups[gi] = member_name;
            gi++;
            continue;
        }

        logger(pamh, LOG_NOTICE,
               "Cannot determine type of member %s\n", a->vals[i]->bv_val);
    }

    *_el = el;
    return 0;
}

static int
fill_rule_enabled(pam_handle_t *pamh,
                  struct ph_entry *rule_entry,
                  struct hbac_rule *rule)
{
    struct ph_attr *enabled_attr;
    struct berval *bv;

    enabled_attr = ph_entry_get_attr(rule_entry, PH_MAP_RULE_ENABLED_FLAG);
    if (enabled_attr == NULL || enabled_attr->nvals < 1) {
        logger(pamh, LOG_NOTICE, "No value for enabled\n");
        return ENOENT;
    } else if (enabled_attr->nvals > 1) {
        logger(pamh, LOG_ERR, "More than one value for enabled, fail\n");
        return EIO;
    }

    bv = enabled_attr->vals[0];
    if (strncasecmp(bv->bv_val, PAM_HBAC_TRUE_VALUE, bv->bv_len) == 0) {
        rule->enabled = true;
        logger(pamh, LOG_DEBUG, "Rule %s is enabled\n", rule->name);
    } else if (strncasecmp(bv->bv_val, PAM_HBAC_FALSE_VALUE, bv->bv_len) == 0) {
        logger(pamh, LOG_ERR, "Unknown than one value for enabled, fail\n");
        rule->enabled = false;
    } else {
        return EINVAL;
    }

    return 0;
}

static int
fill_rule_name(pam_handle_t *pamh,
               struct ph_entry *rule_entry,
               struct hbac_rule *rule)
{
    struct ph_attr *name_attr;

    name_attr = ph_entry_get_attr(rule_entry, PH_MAP_RULE_NAME);
    if (name_attr == NULL || name_attr->nvals < 1) {
        logger(pamh, LOG_WARNING, "No value for name, using fallback\n");
        rule->name = strdup(RULE_NAME_FALLBACK);
        if (rule->name == NULL) {
            return ENOMEM;
        }
        return 0;
    }

    if (name_attr->nvals > 1) {
        logger(pamh, LOG_NOTICE,
               "More than one value for name, using the first one\n");
        /* Not fatal */
    }

    rule->name = strdup(name_attr->vals[0]->bv_val);
    if (rule->name == NULL) {
        return ENOMEM;
    }

    return 0;
}

static int
entry_to_hbac_rule(pam_handle_t *pamh,
                   struct ph_entry *rule_entry,
                   struct hbac_rule **_rule)
{
    struct hbac_rule *rule = NULL;
    int ret;

    rule = calloc(1, sizeof(struct hbac_rule));
    if (rule == NULL) {
        return ENOMEM;
    }

    ret = fill_rule_name(pamh, rule_entry, rule);
    if (ret != 0) {
        logger(pamh, LOG_ERR,
               "Cannot determine rule name [%d]: %s\n", ret, strerror(ret));
        free_hbac_rule(rule);
        return ret;
    }

    /* FIXME - This only makes sense to check if there is exactly one value
     * of enabled flag, should we do the same for accessRuleType? 
     */
    ret = fill_rule_enabled(pamh, rule_entry, rule);
    if (ret != 0) {
        logger(pamh, LOG_ERR,
               "Cannot fill the enabled flag [%d]: %s\n", ret, strerror(ret));
        free_hbac_rule(rule);
        return ret;
    }

    ret = attr_to_rule_element(pamh, rule_entry, DN_TYPE_USER, &rule->users);
    if (ret != 0) {
        logger(pamh, LOG_ERR,
               "Cannot add user data to rule [%d]: %s\n",
               ret, strerror(ret));
        free_hbac_rule(rule);
        return ret;
    }

    ret = attr_to_rule_element(pamh, rule_entry, DN_TYPE_SVC, &rule->services);
    if (ret != 0) {
        logger(pamh, LOG_ERR,
               "Cannot add service data to rule [%d]: %s\n",
               ret, strerror(ret));
        free_hbac_rule(rule);
        return ret;
    }

    ret = attr_to_rule_element(pamh, rule_entry, DN_TYPE_HOST, &rule->targethosts);
    if (ret != 0) {
        logger(pamh, LOG_ERR,
               "Cannot add target host data to rule [%d]: %s\n",
               ret, strerror(ret));
        free_hbac_rule(rule);
        return ret;
    }

    /* We don't support srchosts, but we need to provide an empty array,
     * otherwise libhbac would barf
     */
    ret = add_empty_rule_element(&rule->srchosts);
    if (ret != 0) {
        logger(pamh, LOG_ERR,
               "Cannot add source host data to rule [%d]: %s\n",
               ret, strerror(ret));
        free_hbac_rule(rule);
        return ret;
    }

    *_rule = rule;
    return 0;
}

int
ph_get_hbac_rules(struct pam_hbac_ctx *ctx,
                  struct ph_entry *targethost,
                  struct hbac_rule ***_rules)
{
    char *rule_filter;
    int ret;
    struct hbac_rule **rules;
    struct ph_entry **rule_entries;
    size_t num_rule_entries;
    size_t i;
    size_t num_rules;

    if (ctx == NULL || targethost == NULL || _rules == NULL) {
        logger(ctx->pamh, LOG_ERR, "Invalid input\n");
        return EINVAL;
    }

    rule_filter = create_rules_filter(ctx->pamh, targethost);
    if (rule_filter == NULL) {
        logger(ctx->pamh, LOG_CRIT, "Cannot create filter\n");
        return ENOMEM;
    }

    ret = ph_search(ctx->pamh, ctx->ld, ctx->pc, &rule_search_obj,
                    rule_filter, &rule_entries);
    free(rule_filter);
    if (ret != 0) {
        logger(ctx->pamh, LOG_ERR,
               "Search failed [%d]: %s\n", ret, strerror(ret));
        return ret;
    }

    num_rule_entries = ph_num_entries(rule_entries);
    rules = calloc(num_rule_entries + 1, sizeof(struct hbac_rule));
    if (rules == NULL) {
        ph_entry_array_free(rule_entries);
        logger(ctx->pamh, LOG_CRIT, "Cannot allocate entries\n");
        return ENOMEM;
    }

    num_rules = 0;
    for (i = 0; i < num_rule_entries; i++) {
        ret = entry_to_hbac_rule(ctx->pamh, rule_entries[i], &rules[num_rules]);
        if (ret != 0) {
            logger(ctx->pamh, LOG_WARNING,
                   "Skipping malformed rule %d/%d\n", i+1, num_rule_entries);
            continue;
        }
        num_rules++;
    }

    *_rules = rules;
    return 0;
}
