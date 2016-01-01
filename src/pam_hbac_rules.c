/*
    Copyright (C) 2015 Jakub Hrozek <jakub.hrozek@posteo.se>

    Module structure based on pam_sss by Sumit Bose <sbose@redhat.com>

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

/* Should this be utility function? */
static void free_string_list(const char **list)
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

static void free_hbac_rule_element(struct hbac_rule_element *el)
{
    if (el == NULL) {
        return;
    }

    free_string_list(el->names);
    free_string_list(el->groups);
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
}

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

static struct ph_search_ctx rule_search_obj = {
    .sub_base = "cn=hbac",
    .oc = "ipaHbacRule",
    .attrs = ph_rule_attrs
};

static char *
create_rules_filter(struct ph_entry *host)
{
    char *prev;
    char *filter;
    int ret;
    size_t i;
    struct ph_attr *hostname;
    struct ph_attr *hostgroups;

    hostname = ph_entry_get_attr_val(host, PH_MAP_HOST_FQDN);
    if (hostname == NULL || hostname->nvals != 1) {
        return NULL;
    }

    hostgroups = ph_entry_get_attr_val(host, PH_MAP_HOST_MEMBEROF);
    if (hostgroups == NULL) {
        return NULL;
    }

    ret = asprintf(&filter, "(%s=%s)(%s=%s)(|(%s=%s)(%s=%s)",
                   ph_rule_attrs[PH_MAP_RULE_ENABLED_FLAG], PAM_HBAC_TRUE_VALUE,
                   ph_rule_attrs[PH_MAP_RULE_ACCESS_RULE_TYPE], PAM_HBAC_ALLOW_VALUE,
                   ph_rule_attrs[PH_MAP_RULE_SRC_HOST_CAT], PAM_HBAC_ALL_VALUE,
                   ph_rule_attrs[PH_MAP_RULE_MEMBER_HOST],
                   (const char *) hostname->vals[0]->bv_val);
    if (ret < 0) {
        return NULL;
    }

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
    case REQ_EL_USER:
        return ph_entry_get_attr_val(rule_entry,
                                     PH_MAP_RULE_MEMBER_USER);
    case REQ_EL_HOST:
        return ph_entry_get_attr_val(rule_entry,
                                     PH_MAP_RULE_MEMBER_HOST);
    case REQ_EL_SVC:
        return ph_entry_get_attr_val(rule_entry,
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
    case REQ_EL_USER:
        return ph_entry_get_attr_val(rule_entry,
                                     PH_MAP_RULE_USER_CAT);
    case REQ_EL_HOST:
        return ph_entry_get_attr_val(rule_entry,
                                     PH_MAP_RULE_HOST_CAT);
    case REQ_EL_SVC:
        return ph_entry_get_attr_val(rule_entry,
                                     PH_MAP_RULE_SVC_CAT);
    default:
        break;
    }

    return NULL;
}

static int
el_fill_category(struct ph_entry *rule_entry,
                 enum member_el_type el_type,
                 struct hbac_rule_element *el)
{
    struct ph_attr *cat_attr;
    struct berval *bv;

    cat_attr = el_category_attr(rule_entry, el_type);
    if (cat_attr == NULL || cat_attr->nvals == 0) {
        return ENOENT;
    } else if (cat_attr->nvals > 1) {
        D(("More than one value for name, fail\n"));
        return EIO;
    }

    bv = cat_attr->vals[0];
    if (strncasecmp(bv->bv_val, "all", bv->bv_len) != 0) {
        return EINVAL;
    }

    el->category |= HBAC_CATEGORY_ALL;
    return 0;
}

static int
attr_to_rule_element(struct ph_entry *rule_entry,
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

    el = malloc(sizeof(struct hbac_rule_element));
    if (el == NULL) {
        return ENOMEM;
    }

    ret = el_fill_category(rule_entry, el_type, el);
    if (ret == 0) {
        /* Do we still need to check the elements? */
    } else if (ret != ENOENT) {
        free_hbac_rule_element(el);
        return ret;
    }

    a = el_member_attr(rule_entry, el_type);
    if (a == NULL) {
        /* FIXME - test an empty element? */
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

        ret = name_from_dn(a->vals[i]->bv_val, el_type, &member_name);
        if (ret == 0) {
            el->names[ni] = member_name;
            ni++;
            continue;
        }

        ret = group_name_from_dn(a->vals[i]->bv_val, el_type, &member_name);
        if (ret == 0) {
            el->groups[gi] = member_name;
            gi++;
            continue;
        }

        /* FIXME - log failure but continue */
    }

    *_el = el;
    return 0;
}

static int
fill_rule_enabled(struct ph_entry *rule_entry,
                  struct hbac_rule *rule)
{
    struct ph_attr *enabled_attr;
    struct berval *bv;

    enabled_attr = ph_entry_get_attr_val(rule_entry, PH_MAP_RULE_NAME);
    if (enabled_attr == NULL || enabled_attr->nvals < 1) {
        D(("No value for enabled\n"));
        return ENOENT;
    } else if (enabled_attr->nvals > 1) {
        D(("More than one value for enabled, fail\n"));
        return EIO;
    }

    bv = enabled_attr->vals[0];
    if (strncasecmp(bv->bv_val, "true", bv->bv_len) == 0) {
        rule->enabled = true;
    } else if (strncasecmp(bv->bv_val, "false", bv->bv_len) == 0) {
        rule->enabled = false;
    } else {
        return EINVAL;
    }

    return 0;
}

static int
fill_rule_name(struct ph_entry *rule_entry,
               struct hbac_rule *rule)
{
    struct ph_attr *name_attr;

    name_attr = ph_entry_get_attr_val(rule_entry, PH_MAP_RULE_NAME);
    if (name_attr == NULL || name_attr->nvals < 1) {
        D(("No value for name, using fallback\n"));
        rule->name = RULE_NAME_FALLBACK;
        return 0;
    }

    if (name_attr->nvals > 1) {
        D(("More than one value for name, using the first one\n"));
        /* Not fatal */
    }

    rule->name = strdup(name_attr->vals[0]->bv_val);
    if (rule->name == NULL) {
        return ENOMEM;
    }

    return 0;
}

static int
entry_to_hbac_rule(struct ph_entry *rule_entry,
                   struct hbac_rule **_rule)
{
    struct hbac_rule *rule = NULL;
    int ret;

    rule = calloc(1, sizeof(struct hbac_rule));
    if (rule == NULL) {
        return ENOMEM;
    }

    ret = fill_rule_name(rule_entry, rule);
    if (ret != 0) {
        free_hbac_rule(rule);
        return ret;
    }

    /* FIXME - This only makes sense to check if there is exactly one value
     * of enabled flag, should we do the same for accessRuleType? 
     */
    ret = fill_rule_enabled(rule_entry, rule);
    if (ret != 0) {
        free_hbac_rule(rule);
        return ret;
    }

    ret = attr_to_rule_element(rule_entry, REQ_EL_USER, &rule->users);
    if (ret != 0) {
        free_hbac_rule(rule);
        return ret;
    }

    ret = attr_to_rule_element(rule_entry, REQ_EL_SVC, &rule->services);
    if (ret != 0) {
        free_hbac_rule(rule);
        return ret;
    }

    ret = attr_to_rule_element(rule_entry, REQ_EL_HOST, &rule->targethosts);
    if (ret != 0) {
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
    struct ph_entry *rule_entries;
    struct ph_entry *rule;
    size_t num_rule_entries;
    size_t i;
    size_t num_rules;

    if (ctx == NULL || targethost == NULL || _rules == NULL) {
        return EINVAL;
    }

    rule_filter = create_rules_filter(targethost);
    if (rule_filter == NULL) {
        return ENOMEM;
    }

    ret = ph_search(ctx->ld, ctx->pc, &rule_search_obj, rule_filter, &rule_entries);
    free(rule_filter);
    if (ret != 0) {
        return ret;
    }

    num_rule_entries = ph_num_entries(rule_entries);
    rules = calloc(num_rule_entries + 1, sizeof(struct hbac_rule));
    if (rules == NULL) {
        ph_entry_array_free(rule_entries);
        return ENOMEM;
    }

    num_rules = 0;
    for (i = 0; i < num_rule_entries; i++) {
        rule = ph_entry_array_el(rule_entries, i);
        if (rule == NULL) {
            continue;
        }

        ret = entry_to_hbac_rule(rule, &rules[num_rules]);
        if (ret != 0) {
            continue;
        }
        num_rules++;
    }

    *_rules = rules;
    return 0;
}
