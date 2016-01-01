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
#include <ctype.h>
#include <errno.h>

#include "pam_hbac.h"
#include "libhbac/ipa_hbac.h"
#include "config.h"

enum req_el_type {
    REQ_EL_USER,
    REQ_EL_HOST,
    REQ_EL_SVC,
};

static void
free_request_element(struct hbac_request_element *el)
{
    size_t i;

    if (el == NULL) {
        return;
    }

    if (el->groups != NULL) {
        for (i=0; el->groups[i]; i++) {
            free(discard_const(el->groups[i]));
        }
    }

    free(el);
}

static struct hbac_request_element *
new_request_element(struct ph_member_obj *obj)
{
    struct hbac_request_element *el;
    size_t nmem = 0;

    if (obj->memberofs) {
        for (; obj->memberofs[nmem]; nmem++);
    }

    el = malloc(sizeof(struct hbac_request_element));
    if (el == NULL) {
        return NULL;
    }

    /* Add sentinel. This also handles objects with no memberships */
    el->groups = calloc(nmem + 1, sizeof(const char *));
    if (el->groups == NULL) {
        free(el);
        return NULL;
    }

    return el;
}

static const char *rdn_get_val(char **exploded_rdn, const char *attr)
{
    size_t i;
    size_t j;
    int attr_len;

    attr_len = strlen(attr);

    if (exploded_rdn == NULL) {
        return NULL;
    }

    for (i = 0; exploded_rdn[i]; i++) {
        if (strncasecmp(exploded_rdn[i], attr, attr_len) != 0) {
            continue;
        }

        for (j = attr_len; isspace(exploded_rdn[i][j]); j++);

        if (exploded_rdn[i][j] != '=') {
            continue;
        }
        j++;

        while (isspace(exploded_rdn[i][j])) j++;

        if (exploded_rdn[i][j] == '\0') {
            continue;
        }

        return exploded_rdn[i] + j;
    }

    return NULL;
}

/* if val is NULL, only key is checked */
static bool
rdn_keyval_matches(const char *rdn, const char *key, const char *val)
{
    char **exploded_rdn;
    const char *rdn_val;
    bool ret = false;

    exploded_rdn = ldap_explode_rdn(rdn, 0);
    if (exploded_rdn == NULL) {
        return false;
    }

    rdn_val = rdn_get_val(exploded_rdn, key);
    if ((rdn_val != NULL) && ((val == NULL || strcmp(val, rdn_val) == 0))) {
            ret = true;
    }
    ldap_value_free(exploded_rdn);

    return ret;
}

static char *
rdn_check_and_getval(const char *rdn, const char *key)
{
    char **exploded_rdn;
    const char *rdn_val = NULL;
    char *ret;

    exploded_rdn = ldap_explode_rdn(rdn, 0);
    if (exploded_rdn == NULL) {
        return false;
    }

    rdn_val = rdn_get_val(exploded_rdn, key);
    if (rdn_val) {
        ret = strdup(rdn_val);
    } else {
        ret = NULL;
    }
    ldap_value_free(exploded_rdn);

    return ret;
}

static bool
container_matches(char * const *dn_parts, const char ***kvs)
{
    size_t idx;
    bool match;

    if (dn_parts == NULL || dn_parts[0] == NULL || kvs == NULL) {
        return false;
    }

    for (idx = 0; kvs[idx]; idx++) {
        /* +1 because we don't care about RDN */
        if (dn_parts[idx+1] == NULL) {
            /* Short DN.. */
            return false;
        }

        match = rdn_keyval_matches(dn_parts[idx+1], kvs[idx][0], kvs[idx][1]);
        if (match == false) {
            return false;
        }
    }

    /* There must be at least one more for basedn */
    /* FIXME - should we check explicitly?? */
    if (dn_parts[idx+1] == NULL) {
        return false;
    }
    return true;
}

static int
container_check_and_get_rdn(char * const *dn_parts,
                            const char ***container_kvs,
                            const char **_rdn_val)
{
    bool ok;

    ok = container_matches(dn_parts, container_kvs);
    if (!ok) {
        return EINVAL;
    }

    if (dn_parts[0] == NULL) {
        return ERANGE;
    }
    *_rdn_val = rdn_check_and_getval(dn_parts[0], "cn");
    if (*_rdn_val == NULL) {
        return EINVAL;
    }

    return 0;
}

static int
group_container_rdn(char * const *dn_parts,
                    const char **_rdn_val)
{
    const char *cn1[] = { "cn", "groups" };
    const char *cn2[] = { "cn", "accounts" };
    const char **group_container[] = {
        cn1, cn2, NULL
    };

    return container_check_and_get_rdn(dn_parts, group_container, _rdn_val);
}

static int
svc_container_rdn(char * const *dn_parts,
                  const char **_rdn_val)
{
    const char *cn1[] = { "cn", "hbacservicegroups" };
    const char *cn2[] = { "cn", "hbac" };
    const char **svc_container[] = {
        cn1, cn2, NULL
    };

    return container_check_and_get_rdn(dn_parts, svc_container, _rdn_val);
}

static int
host_container_rdn(char * const *dn_parts,
                   const char **_rdn_val)
{
    const char *cn1[] = { "cn", "hostgroups" };
    const char *cn2[] = { "cn", "accounts" };
    const char **host_container[] = {
        cn1, cn2, NULL
    };

    return container_check_and_get_rdn(dn_parts, host_container, _rdn_val);
}

static int
name_from_dn(const char *dn, enum req_el_type el_type, const char **_name)
{
    /* Extract NAME from cn=NAME,cn=groups,cn=accounts */
    char **dn_parts;
    int ret;

    dn_parts = ldap_explode_dn(dn, 0);
    if (dn_parts == NULL) {
        return EINVAL; /* FIXME - better error code */
    }

    switch (el_type) {
    case REQ_EL_USER:
        ret = group_container_rdn(dn_parts, _name);
        break;
    case REQ_EL_SVC:
        ret = svc_container_rdn(dn_parts, _name);
        break;
    case REQ_EL_HOST:
        ret = host_container_rdn(dn_parts, _name);
        break;
    default:
        ret = EINVAL;
        break;
    }

    ldap_value_free(dn_parts);
    return ret;
}

static struct hbac_request_element *
member_obj_to_eval_req_el(struct ph_member_obj *obj,
                          enum req_el_type el_type)
{
    struct hbac_request_element *el;
    size_t i, gi;
    int ret;

    el = new_request_element(obj);
    if (el == NULL) {
        return NULL;
    }

    /* No need to copy objname */
    el->name = obj->name;

    if (obj->memberofs == NULL) {
        return el;
    }

    /* Iterate over all memberof attribute values and copy out the
     * groupname */
    gi = 0;
    for (i=0; obj->memberofs[i]; i++) {
        ret = name_from_dn(obj->memberofs[i], el_type, &el->groups[gi]);
        switch (ret) {
            case 0:
                break;
            /* Unexpected DN, skip these.. */
            case ERANGE:
            case EINVAL:
                continue;
            default:
                /* ENOMEMs and such */
                free_request_element(el);
                return NULL;
        }

        gi++;
    }

    return el;
}

static struct hbac_request_element *
user_to_eval_req_el(struct ph_member_obj *user)
{
    return member_obj_to_eval_req_el(user, REQ_EL_USER);
}

static struct hbac_request_element *
svc_to_eval_req_el(struct ph_member_obj *svc)
{
    return member_obj_to_eval_req_el(svc, REQ_EL_SVC);
}

static struct hbac_request_element *
tgt_host_to_eval_req_el(struct ph_member_obj *svc)
{
    return member_obj_to_eval_req_el(svc, REQ_EL_HOST);
}

void
ph_free_eval_req(struct hbac_eval_req *req)
{
    if (req == NULL) {
        return;
    }

    free_request_element(req->user);
    free_request_element(req->service);
    free_request_element(req->targethost);
    free(req);
}

int
ph_create_hbac_eval_req(struct ph_member_obj *user,
                        struct ph_member_obj *tgthost,
                        struct ph_member_obj *service,
                        struct hbac_eval_req **_req)
{
    int ret;
    struct hbac_eval_req *req;

    if (user == NULL || tgthost == NULL || service == NULL
            || _req == NULL) {
        return EINVAL;
    }

    req = calloc(1, sizeof(struct hbac_eval_req));
    if (req == NULL) {
        return ENOMEM;
    }

    req->user = user_to_eval_req_el(user);
    if (req->user == NULL) {
        ret = ENOMEM;
        goto fail;
    }

    req->service = svc_to_eval_req_el(service);
    if (req->service == NULL) {
        ret = ENOMEM;
        goto fail;
    }

    req->targethost = tgt_host_to_eval_req_el(tgthost);
    if (req->targethost == NULL) {
        ret = ENOMEM;
        goto fail;
    }

    req->request_time = time(NULL);

    *_req = req;
    return 0;

fail:
    ph_free_eval_req(req);
    return ret;
}
