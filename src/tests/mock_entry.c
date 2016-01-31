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

static struct ph_attr *
mock_ph_attr_valist(const char *name, va_list vlist)
{
    const char *v = NULL;
    struct berval *bv;
    struct berval **vals = NULL;
    char *nc;

    while ((v = va_arg(vlist, const char *)) != NULL) {
        bv = ber_bvstrdup(v);
        if (bv == NULL) {
            ber_bvecfree(vals);
            return NULL;
        }
        ber_bvecadd(&vals, bv);
    }

    nc = ldap_strdup(name);
    if (nc == NULL) {
        ber_bvecfree(vals);
        return NULL;
    }

    return ph_attr_new(nc, vals);
}

struct ph_attr *
mock_ph_attr(const char *name, ...)
{
    va_list va;
    struct ph_attr *a;

    va_start(va, name);
    a = mock_ph_attr_valist(name, va);
    va_end(va);

    return a;
}

static struct ph_attr *
mock_ph_attr_str_array(const char *name, const char *attr_vals[])
{
    char *nc;
    struct berval *bv;
    size_t i;
    struct berval **vals = NULL;

    for (i = 0; attr_vals[i]; i++) {
        bv = ber_bvstrdup(attr_vals[i]);
        if (bv == NULL) {
            ber_bvecfree(vals);
            return NULL;
        }
        ber_bvecadd(&vals, bv);
    }

    nc = ldap_strdup(name);
    if (nc == NULL) {
        ber_bvecfree(vals);
        return NULL;
    }

    return ph_attr_new(nc, vals);
}

int
mock_ph_host(struct ph_entry *host,
             const char *fqdn,
             ...)
{
    va_list va;
    va_list ap_copy;
    size_t num_host_groups = 0;
    const char *v;

    if (host == NULL) {
        return EINVAL;
    }

    host->attrs[PH_MAP_HOST_OC] = mock_ph_attr("objectClass",
                                               "top", "ipaHost",
                                                NULL);
    if (host->attrs[PH_MAP_HOST_OC] == NULL) {
        return ENOMEM;
    }

    if (fqdn != NULL) {
        host->attrs[PH_MAP_HOST_FQDN] = mock_ph_attr("fqdn", fqdn, NULL);
        if (host->attrs[PH_MAP_HOST_FQDN] == NULL) {
            ph_attr_free(host->attrs[PH_MAP_HOST_OC]);
            return ENOMEM;
        }
    }

    va_start(ap_copy, fqdn);
    while ((v = va_arg(ap_copy, const char *)) != NULL) {
        num_host_groups++;
    }
    va_end(ap_copy);


    /* FIXME - if we decide all attribute lists will be empty if attribute is
     * not found, change this
     */
    if (num_host_groups > 0) {
        va_start(va, fqdn);
        host->attrs[PH_MAP_HOST_MEMBEROF] = mock_ph_attr_valist(fqdn, va);
        va_end(va);
        if (host->attrs[PH_MAP_HOST_MEMBEROF] == NULL) {
            ph_attr_free(host->attrs[PH_MAP_HOST_OC]);
            ph_attr_free(host->attrs[PH_MAP_HOST_FQDN]);
            return ENOMEM;
        }
    }

    return 0;
}

int
mock_ph_svc(struct ph_entry *svc,
            const char *svcname)
{
    if (svc == NULL) {
        return EINVAL;
    }

    svc->attrs[PH_MAP_SVC_OC] = mock_ph_attr("objectClass",
                                              "top",
                                              "ipaHbacService",
                                              NULL);
    if (svc->attrs[PH_MAP_SVC_OC] == NULL) {
        return ENOMEM;
    }

    if (svcname != NULL) {
        svc->attrs[PH_MAP_SVC_NAME] = mock_ph_attr("cn", svcname, NULL);
        if (svc->attrs[PH_MAP_SVC_NAME] == NULL) {
            ph_attr_free(svc->attrs[PH_MAP_SVC_OC]);
            return ENOMEM;
        }
    }

    return 0;
}

int
mock_ph_rule(struct ph_entry *rule,
             const char *cn,
             const char *uuid,
             const char *ipa_enabled_flag,
             const char *member_user[], const char *member_user_groups[],
             const char *user_category,
             const char *member_service[], const char *member_service_groups[],
             const char *service_category,
             const char *member_host[], const char *member_host_groups[],
             const char *host_category,
             const char *external_host)
{
    int ret;

    if (rule == NULL) {
        return EINVAL;
    }

    rule->attrs[PH_MAP_RULE_OC] = mock_ph_attr("ipaAssociation",
                                               "ipaHbacRule",
                                              NULL);
    if (rule->attrs[PH_MAP_RULE_OC] == NULL) {
        return ENOMEM;
    }

    rule->attrs[PH_MAP_RULE_NAME] = mock_ph_attr("cn", cn, NULL);
    if (rule->attrs[PH_MAP_RULE_NAME] == NULL) {
        ret = ENOMEM;
        goto fail;
    }

    rule->attrs[PH_MAP_RULE_UNIQUE_ID] = mock_ph_attr("ipaUniqueID",
                                                       uuid, NULL);
    if (rule->attrs[PH_MAP_RULE_UNIQUE_ID] == NULL) {
        ret = ENOMEM;
        goto fail;
    }

    rule->attrs[PH_MAP_RULE_ENABLED_FLAG] = mock_ph_attr("ipaEnabledFlag",
                                                          ipa_enabled_flag,
                                                          NULL);
    if (rule->attrs[PH_MAP_RULE_UNIQUE_ID] == NULL) {
        ret = ENOMEM;
        goto fail;
    }

    if (member_user != NULL) {
        rule->attrs[PH_MAP_RULE_MEMBER_USER] = mock_ph_attr_str_array(
                                                        "memberUser",
                                                        member_user);
        if (rule->attrs[PH_MAP_RULE_MEMBER_USER] == NULL) {
            ret = ENOMEM;
            goto fail;
        }
    }

    if (user_category != NULL) {
        rule->attrs[PH_MAP_RULE_USER_CAT] = mock_ph_attr("userCategory",
                                                          user_category,
                                                          NULL);
        if (rule->attrs[PH_MAP_RULE_USER_CAT] == NULL) {
            ret = ENOMEM;
            goto fail;
        }
    }

    if (member_service != NULL) {
        rule->attrs[PH_MAP_RULE_MEMBER_SVC] = mock_ph_attr_str_array(
                                                        "memberService",
                                                        member_service);
        if (rule->attrs[PH_MAP_RULE_MEMBER_SVC] == NULL) {
            ret = ENOMEM;
            goto fail;
        }
    }

    if (service_category != NULL) {
        rule->attrs[PH_MAP_RULE_SVC_CAT] = mock_ph_attr("serviceCategory",
                                                         service_category,
                                                         NULL);
        if (rule->attrs[PH_MAP_RULE_SVC_CAT] == NULL) {
            ret = ENOMEM;
            goto fail;
        }
    }

    if (member_host != NULL) {
        rule->attrs[PH_MAP_RULE_MEMBER_HOST] = mock_ph_attr_str_array(
                                                        "memberHost",
                                                        member_host);
        if (rule->attrs[PH_MAP_RULE_MEMBER_HOST] == NULL) {
            ret = ENOMEM;
            goto fail;
        }
    }

    if (host_category != NULL) {
        rule->attrs[PH_MAP_RULE_HOST_CAT] = mock_ph_attr("hostCategory",
                                                          host_category,
                                                          NULL);
        if (rule->attrs[PH_MAP_RULE_HOST_CAT] == NULL) {
            ret = ENOMEM;
            goto fail;
        }
    }

    /* FIXME - Handle externalHost */

    return 0;

fail:
    ph_attr_free(rule->attrs[PH_MAP_RULE_OC]);
    ph_attr_free(rule->attrs[PH_MAP_RULE_NAME]);
    ph_attr_free(rule->attrs[PH_MAP_RULE_MEMBER_USER]);
    ph_attr_free(rule->attrs[PH_MAP_RULE_USER_CAT]);
    ph_attr_free(rule->attrs[PH_MAP_RULE_SVC_CAT]);
    ph_attr_free(rule->attrs[PH_MAP_RULE_HOST_CAT]);
    return ret;
}
