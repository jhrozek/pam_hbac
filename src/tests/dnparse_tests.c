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
#include <setjmp.h>
#include <cmocka.h>
#include <stdarg.h>
#include <ldap.h>

#include "pam_hbac.h"
#include "pam_hbac_dnparse.h"

#define TEST_BASEDN "dc=ipa,dc=test"
#define TEST_BASEDN2 "dc=aaa,dc=bbb"
#define TEST_BASEDN3 "d=ipa,dc=test"
#define TEST_BASEDN4 "dc=ipaa,dc=test"
#define TEST_BASEDN5 "dc=ipa,dc=tesd"
#define TEST_BASEDN6 "cn=ipa,dc=test"
#define TEST_BASEDN_short "dc=ipa"
#define TEST_BASEDN_long "dc=ipa,dc=test,dc=xxx"

typedef int (*rdn_getter_fn)(const char *,
                             enum member_el_type,
                             const char *,
                             const char **);

static void ph_test_rdn_from_dn(rdn_getter_fn getter,
                                const char *basedn,
                                const char *dn_list[],
                                const char *rdn_list[])
{
    int ret;
    const char *rdn_val = NULL;
    size_t i;
    size_t ii;

    for (i = 0; i <= DN_TYPE_SVC; i++) {
        for (ii = 0; ii <= DN_TYPE_SVC; ii++) {
            rdn_val = NULL;

            ret = getter(dn_list[i], ii, basedn, &rdn_val);
            if (i == ii) {
                assert_int_equal(ret, 0);
                assert_non_null(rdn_val);
                assert_string_equal(rdn_val, rdn_list[i]);
                free_const(rdn_val);
                rdn_val = NULL;
            } else {
                assert_int_not_equal(ret, 0);
                assert_null(rdn_val);
            }
        }
    }
}

static const char *ok_entry_dn[] = {
    " uid = admin , cn = users ,cn=accounts,dc=ipa,dc=test",
    "fqdn=server.ipa.test,cn=computers,cn=accounts,dc=ipa,dc=test",
    "cn=login,cn=hbacservices,cn=hbac,dc=ipa,dc=test",
};

static const char *ok_entry_rdn[] = {
    "admin",
    "server.ipa.test",
    "login",
};

static void
test_ph_name_from_dn(void **state)
{
    (void) state; /* unused */

    ph_test_rdn_from_dn(ph_name_from_dn, TEST_BASEDN, ok_entry_dn,
                        ok_entry_rdn);
}

static const char *ok_group_dn[] = {
    "cn=admins,cn=groups,cn=accounts,dc=ipa,dc=test",
    "cn=servers,cn=hostgroups,cn=accounts,dc=ipa,dc=test",
    "cn=Sudo,cn=hbacservicegroups,cn=hbac,dc=ipa,dc=test",
};

static const char *ok_group_rdn[] = {
    "admins",
    "servers",
    "Sudo",
};

static void
test_ph_group_name_from_dn(void **state)
{
    (void) state; /* unused */
    ph_test_rdn_from_dn(ph_group_name_from_dn, TEST_BASEDN, ok_group_dn,
                        ok_group_rdn);
}

static void
test_rdn_key_mismatch(void **state)
{
    int ret;
    const char *rdn_val = NULL;

    (void) state; /* unused */

    /* test RDN key mismatch */
    ret = ph_name_from_dn("oops=admin,cn=users,cn=accounts,dc=ipa,dc=test",
                          DN_TYPE_USER, TEST_BASEDN, &rdn_val);
    assert_int_not_equal(ret, 0);

    ret = ph_group_name_from_dn("oops=admins,cn=groups,cn=accounts,dc=ipa,dc=test",
                                DN_TYPE_USER, TEST_BASEDN, &rdn_val);
    assert_int_not_equal(ret, 0);

    /* No basedn */
    ret = ph_name_from_dn("uid=admin,cn=users,cn=accounts",
                          DN_TYPE_USER, TEST_BASEDN, &rdn_val);
    assert_int_equal(ret, EINVAL);

    /* Not matching basedn */
    ret = ph_name_from_dn("uid=admin,cn=users,cn=accounts,"TEST_BASEDN2,
                          DN_TYPE_USER, TEST_BASEDN, &rdn_val);
    assert_int_equal(ret, EINVAL);

    /* Too few computers in basedn */
    ret = ph_name_from_dn("uid=admin,cn=users,cn=accounts,"TEST_BASEDN_short,
                          DN_TYPE_USER, TEST_BASEDN, &rdn_val);
    assert_int_equal(ret, EINVAL);

    /* Too many components in basedn */
    ret = ph_name_from_dn("uid=admin,cn=users,cn=accounts,"TEST_BASEDN_long,
                          DN_TYPE_USER, TEST_BASEDN, &rdn_val);
    assert_int_equal(ret, EINVAL);

    /* basedn mismatch too short */
    ret = ph_name_from_dn("uid=admin,cn=users,cn=accounts,"TEST_BASEDN3,
                          DN_TYPE_USER, TEST_BASEDN, &rdn_val);
    assert_int_equal(ret, EINVAL);

    /* basedn mismatch - too long */
    ret = ph_name_from_dn("uid=admin,cn=users,cn=accounts,"TEST_BASEDN4,
                          DN_TYPE_USER, TEST_BASEDN, &rdn_val);
    assert_int_equal(ret, EINVAL);

    /* basedn mismatch - typo */
    ret = ph_name_from_dn("uid=admin,cn=users,cn=accounts,"TEST_BASEDN5,
                          DN_TYPE_USER, TEST_BASEDN, &rdn_val);
    assert_int_equal(ret, EINVAL);

    /* basedn mismatch - typo in attribute */
    ret = ph_name_from_dn("uid=admin,cn=users,cn=accounts,"TEST_BASEDN6,
                          DN_TYPE_USER, TEST_BASEDN, &rdn_val);
    assert_int_equal(ret, EINVAL);

    /* basedn NULL */
    ret = ph_name_from_dn("uid=admin,cn=users,cn=accounts,"TEST_BASEDN,
                          DN_TYPE_USER, NULL, &rdn_val);
    assert_int_equal(ret, EINVAL);

    /* Missing required component */
    ret = ph_name_from_dn("uid=admin",
                          DN_TYPE_USER, TEST_BASEDN, &rdn_val);
    assert_int_not_equal(ret, 0);
}

int
main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_ph_name_from_dn),
        cmocka_unit_test(test_ph_group_name_from_dn),
        cmocka_unit_test(test_rdn_key_mismatch),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
