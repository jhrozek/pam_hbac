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

#include "pam_hbac_compat.h"
#include "pam_hbac_ldap.h"

#include <ctype.h>

#if !defined(HAVE_LDAP_STR2DN) || defined(COMPAT_LDAP_UNIT_TESTS)
static int rdn_keyval(const char *exploded_rdn_value,
                      char **_key, char **_val)
{
    size_t i;
    char *eq_sign;
    const char *rdn_start;
    const char *rdn_end;
    char *val_start;
    char *key = NULL;
    char *value = NULL;
    char *val_end = NULL;

    if (exploded_rdn_value == NULL) {
        return EINVAL;
    }

    /* Skip leading whitespace before the key */
    rdn_start = exploded_rdn_value;
    for (i = 0; isspace(rdn_start[i]); i++);

    rdn_start += i;
    if (*rdn_start == '\0') {
        return EINVAL;
    }

    eq_sign = strchr(rdn_start, '=');
    if (eq_sign == NULL) {
        return EINVAL;
    }

    /* Skip whitespace before the '=' sign and after the key */
    for (rdn_end = eq_sign;
         isspace(*rdn_end);
         rdn_end--);

    val_start = eq_sign+1;
    /* Skip leading whitespace before the value */
    for (i =0; isspace(val_start[i]); i++);

    /* Empty value? */
    val_start += i;
    if (*val_start == '\0') {
        return EINVAL;
    }

    /* Strip trailing val whitespace */
    for (val_end = val_start + strlen(val_start);
         isspace(*val_end);
         val_end--);

    key = strndup(rdn_start, rdn_end - rdn_start);
    value = strndup(val_start, val_end - val_start);
    if (key == NULL || value == NULL) {
        free(key);
        free(value);
        return ENOMEM;
    }

    *_key = key;
    *_val = value;
    return 0;
}

static LDAPAVA *rdn2ava(const char *rdn)
{
    char **exploded_rdn = NULL;
    LDAPAVA *ava;
    char *key = NULL;
    char *val = NULL;
    int ret;

    /* For single-valued RDNs, this is a noop, for multiple-valued, we just
     * hope for the best. Because we don't support deny rules, the user
     * might be not allowed access at worst
     */
    exploded_rdn = ldap_explode_rdn(rdn, 0);
    if (exploded_rdn == NULL) {
        return NULL;
    }

    ava = malloc(sizeof(LDAPAVA));
    if (ava == NULL) {
        ldap_value_free(exploded_rdn);
        return NULL;
    }

    /* Since the server is IPA, we can ignore anything but the simplest,
     * single-valued RDNs, we know IPA doesn't use those
     */
    ret = rdn_keyval(exploded_rdn[0], &key, &val);
    ldap_value_free(exploded_rdn);
    if (ret != 0 || key == NULL || val == NULL) {
        free(key);
        free(val);
        free(ava);
        return NULL;
    }

    ava->la_attr.bv_val = key;
    ava->la_value.bv_val = val;
    ava->la_attr.bv_len = strlen(key);
    ava->la_value.bv_len = strlen(val);

    return ava;
}

static int str2rdn(const char *str_rdn, LDAPRDN *_rdn)
{
    LDAPAVA **new_rdn;

    /* For single-valued RDNs, this is a noop, for multiple-valued, we just
     * hope for the best. Because we don't support deny rules, the user
     * might be not allowed access at worst
     */
    new_rdn = calloc(2, sizeof(LDAPAVA *));
    new_rdn[0] = rdn2ava(str_rdn);
    if (new_rdn[0] == NULL) {
        free(new_rdn);
        return ENOMEM;
    }

    *_rdn = new_rdn;
    return 0;
}
#endif

int ph_str2dn(const char *str, LDAPDN *dn)
{
#if defined(HAVE_LDAP_STR2DN) && !defined(COMPAT_LDAP_UNIT_TESTS)
    return ldap_str2dn(str, dn, LDAP_DN_FORMAT_LDAPV3);
#else
    char **str_rdn_list;
    size_t n_rdns;
    size_t i;
    LDAPDN new_dn;
    LDAPRDN rdn;
    int ret;

    if (str == NULL || dn == NULL) {
        return EINVAL;
    }

    str_rdn_list = ldap_explode_dn(str, 0);
    if (str_rdn_list == NULL) {
        return ENOMEM;
    }

    for (n_rdns = 0; str_rdn_list[n_rdns]; n_rdns++);

    new_dn = calloc(n_rdns + 1, sizeof(LDAPRDN));
    if (new_dn == NULL) {
        ldap_value_free(str_rdn_list);
        return ENOMEM;
    }

    for (i = 0; str_rdn_list[i]; i++) {
        ret = str2rdn(str_rdn_list[i], &rdn);
        if (ret != 0) {
            ldap_value_free(str_rdn_list);
            ph_ldap_dnfree(new_dn);
            return ret;
        }

        new_dn[i] = rdn;
    }

    ldap_value_free(str_rdn_list);
    *dn = new_dn;
    return LDAP_SUCCESS;
#endif
}

#if !defined(HAVE_LDAP_INITIALIZE) || defined(COMPAT_LDAP_UNIT_TESTS)
static ssize_t uri_proto_prefix_len(const char *uri)
{

    if (strncasecmp(uri, "ldap://", sizeof("ldap://")-1) == 0) {
        /* The server is IPA and we don't support anything else */
        return sizeof("ldap://")-1;
    }

#ifdef HAVE_LDAPSSL_CLIENT_INIT
    /* Older MozLDAP/SunLDAP libraries don't support StartTLS but only
     * SSL.
     */
    if (strncasecmp(uri, "ldaps://", sizeof("ldaps://")-1) == 0) {
        /* The server is IPA and we don't support anything else */
        return sizeof("ldaps://")-1;
    }
#endif

    return -1;
}
#endif

/* ldap_initialize version for systems that only have ldap_init.
 * More or less stolen from nss-pam-ldapd
 */
int ph_ldap_initialize(LDAP **ld, const char *uri, bool secure)
{
#if defined(HAVE_LDAP_INITIALIZE) && !defined(COMPAT_LDAP_UNIT_TESTS)
    return ldap_initialize(ld, uri);
#else
    char hostname[HOST_NAME_MAX+1];
    size_t hostlen;
    ssize_t uri_prefix;

    if (ld == NULL || uri == NULL) {
        return EINVAL;
    }

    uri_prefix = uri_proto_prefix_len(uri);
    if (uri_prefix == -1) {
        return LDAP_INVALID_SYNTAX;
    }

    strncpy(hostname, uri + uri_prefix, sizeof(hostname));
    hostname[HOST_NAME_MAX] = '\0';

    hostlen = strlen(hostname);
    if (hostlen == 0) {
        return LDAP_INVALID_SYNTAX;
    }

    *ld = ldap_init(hostname, secure ? LDAPS_PORT : LDAP_PORT);
    if (*ld == NULL) {
        return LDAP_OPERATIONS_ERROR;
    }

    return LDAP_SUCCESS;
#endif
}

#if !defined(HAVE_LDAP_DNFREE) || defined(COMPAT_LDAP_UNIT_TESTS)
static void free_ava(LDAPAVA *ava)
{
    if (ava == NULL) {
        return;
    }

    free(ava->la_attr.bv_val);
    free(ava->la_value.bv_val);
    free(ava);
}

static void free_rdn(LDAPRDN rdn)
{
    if (rdn == NULL) {
        return;
    }

    free_ava(rdn[0]);
    free(rdn);
}
#endif

void ph_ldap_dnfree(LDAPDN dn)
{
#if defined(HAVE_LDAP_DNFREE) && !defined(COMPAT_LDAP_UNIT_TESTS)
    ldap_dnfree(dn);
#else
    size_t i;

    if (dn == NULL) {
       return;
    }

    for (i = 0; dn[i] != NULL; i++) {
        free_rdn(dn[i]);
    }
    free(dn);

#endif
}
