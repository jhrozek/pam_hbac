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

#include <string.h>
#include <ctype.h>
#include <stdbool.h>
#include <errno.h>
#include <ldap.h>

#include "pam_hbac_dnparse.h"

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
                            const char *rdn_key,
                            const char **_rdn_val)
{
    bool ok;

    ok = container_matches(dn_parts, container_kvs);
    if (!ok) {
        /* FIXME - This return code sucks */
        return EINVAL;
    }

    if (dn_parts[0] == NULL) {
        return ERANGE;
    }
    *_rdn_val = rdn_check_and_getval(dn_parts[0], rdn_key);
    if (*_rdn_val == NULL) {
        return EINVAL;
    }

    return 0;
}

static int
user_container_rdn(char * const *dn_parts,
                   const char **_rdn_val)
{
    const char *cn1[] = { "cn", "users" };
    const char *cn2[] = { "cn", "accounts" };
    const char **group_container[] = {
        cn1, cn2, NULL
    };

    return container_check_and_get_rdn(dn_parts, group_container,
                                       "uid", _rdn_val);
}

static int
usergroup_container_rdn(char * const *dn_parts,
                        const char **_rdn_val)
{
    const char *cn1[] = { "cn", "groups" };
    const char *cn2[] = { "cn", "accounts" };
    const char **group_container[] = {
        cn1, cn2, NULL
    };

    return container_check_and_get_rdn(dn_parts, group_container,
                                       "cn",_rdn_val);
}

static int
svc_container_rdn(char * const *dn_parts,
                  const char **_rdn_val)
{
    const char *cn1[] = { "cn", "hbacservices" };
    const char *cn2[] = { "cn", "hbac" };
    const char **svc_container[] = {
        cn1, cn2, NULL
    };

    return container_check_and_get_rdn(dn_parts, svc_container,
                                       "cn", _rdn_val);
}

static int
svcgroup_container_rdn(char * const *dn_parts,
                       const char **_rdn_val)
{
    const char *cn1[] = { "cn", "hbacservicegroups" };
    const char *cn2[] = { "cn", "hbac" };
    const char **svc_container[] = {
        cn1, cn2, NULL
    };

    return container_check_and_get_rdn(dn_parts, svc_container,
                                       "cn", _rdn_val);
}

static int
host_container_rdn(char * const *dn_parts,
                   const char **_rdn_val)
{
    const char *cn1[] = { "cn", "computers" };
    const char *cn2[] = { "cn", "accounts" };
    const char **host_container[] = {
        cn1, cn2, NULL
    };

    return container_check_and_get_rdn(dn_parts, host_container,
                                       "fqdn", _rdn_val);
}

static int
hostgroup_container_rdn(char * const *dn_parts,
                         const char **_rdn_val)
{
    const char *cn1[] = { "cn", "hostgroups" };
    const char *cn2[] = { "cn", "accounts" };
    const char **host_container[] = {
        cn1, cn2, NULL
    };

    return container_check_and_get_rdn(dn_parts, host_container,
                                       "cn", _rdn_val);
}

int
group_name_from_dn(const char *dn,
                   enum member_el_type el_type,
                   const char **_group_name)
{
    char **dn_parts;
    int ret;

    dn_parts = ldap_explode_dn(dn, 0);
    if (dn_parts == NULL) {
        return EINVAL; /* FIXME - better error code */
    }

    switch (el_type) {
    case DN_TYPE_USER:
        ret = usergroup_container_rdn(dn_parts, _group_name);
        break;
    case DN_TYPE_SVC:
        ret = svcgroup_container_rdn(dn_parts, _group_name);
        break;
    case DN_TYPE_HOST:
        ret = hostgroup_container_rdn(dn_parts, _group_name);
        break;
    default:
        ret = EINVAL;
        break;
    }

    ldap_value_free(dn_parts);
    return ret;
}

int
name_from_dn(const char *dn,
             enum member_el_type el_type,
             const char **_name)
{
    /* Extract NAME from cn=NAME,cn=groups,cn=accounts */
    char **dn_parts;
    int ret;

    dn_parts = ldap_explode_dn(dn, 0);
    if (dn_parts == NULL) {
        return EINVAL; /* FIXME - better error code */
    }

    switch (el_type) {
    case DN_TYPE_USER:
        ret = user_container_rdn(dn_parts, _name);
        break;
    case DN_TYPE_SVC:
        ret = svc_container_rdn(dn_parts, _name);
        break;
    case DN_TYPE_HOST:
        ret = host_container_rdn(dn_parts, _name);
        break;
    default:
        ret = EINVAL;
        break;
    }

    ldap_value_free(dn_parts);
    return ret;
}

