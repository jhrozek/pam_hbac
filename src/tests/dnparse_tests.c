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

typedef int (*rdn_getter_fn)(const char *,
                             enum member_el_type,
                             const char **);

static void ph_test_rdn_from_dn(rdn_getter_fn getter,
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

            ret = getter(dn_list[i], ii, &rdn_val);
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
    "uid=admin,cn=users,cn=accounts,dc=ipa,dc=test",
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

    ph_test_rdn_from_dn(ph_name_from_dn, ok_entry_dn, ok_entry_rdn);
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
    ph_test_rdn_from_dn(ph_group_name_from_dn, ok_group_dn, ok_group_rdn);
}

static void
test_rdn_key_mismatch(void **state)
{
    int ret;
    const char *rdn_val = NULL;

    (void) state; /* unused */

    /* test RDN key mismatch */
    ret = ph_name_from_dn("oops=admin,cn=users,cn=accounts,dc=ipa,dc=test",
                          DN_TYPE_USER, &rdn_val);
    assert_int_not_equal(ret, 0);

    ret = ph_group_name_from_dn("oops=admins,cn=groups,cn=accounts,dc=ipa,dc=test",
                                DN_TYPE_USER, &rdn_val);
    assert_int_not_equal(ret, 0);

    /* No basedn */
    ret = ph_name_from_dn("uid=admin,cn=users",
                          DN_TYPE_USER, &rdn_val);
    assert_int_not_equal(ret, 0);

    /* Missing required component */
    ret = ph_name_from_dn("uid=admin",
                          DN_TYPE_USER, &rdn_val);
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
