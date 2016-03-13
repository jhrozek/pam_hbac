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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <stdarg.h>
#include <ldap.h>

#include "pam_hbac.h"
#include "pam_hbac_entry.h"
#include "pam_hbac_obj.h"
#include "pam_hbac_obj_int.h"

#include "common_mock.h"

static void
test_ph_get_user_no_sup_groups(void **state)
{
    struct ph_user *u;
    size_t ngroups;

    (void) state; /* unused */

    u = ph_get_user(NULL, "no_sup_groups");
    assert_non_null(u);

    assert_non_null(u->name);
    assert_string_equal(u->name, "no_sup_groups");

    assert_non_null(u->group_names);
    ngroups = null_string_array_size(u->group_names);
    assert_int_equal(ngroups, 1);
    assert_string_equal(u->group_names[0], "no_sup_groups");
    assert_null(u->group_names[1]);

    ph_free_user(u);
}

static void
test_ph_get_user_sup_groups(void **state)
{
    struct ph_user *u;
    size_t ngroups;

    (void) state; /* unused */

    u = ph_get_user(NULL, "sup_groups");
    assert_non_null(u);

    assert_non_null(u->name);
    assert_string_equal(u->name, "sup_groups");

    assert_non_null(u->group_names);
    ngroups = null_string_array_size(u->group_names);
    assert_int_equal(ngroups, 3);

    assert_string_equal(u->group_names[0], "sup_groups");
    assert_string_equal(u->group_names[1], "gr1");
    assert_string_equal(u->group_names[2], "gr2");
    assert_null(u->group_names[3]);

    ph_free_user(u);
}

static void
test_ph_get_user_unknown(void **state)
{
    struct ph_user *u;

    (void) state; /* unused */

    u = ph_get_user(NULL, "nosuchuser");
    assert_null(u);
}

struct ph_search_ctx;

int
__wrap_ph_search(pam_handle_t *pamh,
                 LDAP *ld,
                 struct pam_hbac_config *conf,
                 struct ph_search_ctx *s,
                 const char *obj_filter,
                 struct ph_entry ***_entry_list)
{
    int ret;
    int rv;
    const char *key = NULL;
    struct ph_entry **entry_list = NULL;

    rv = ph_mock_type(int);
    key = ph_mock_ptr_type(const char *);
    if (rv != 0) {
        return rv;
    }

    assert_non_null(strstr(obj_filter, key));
    if (strcmp(key, "single.ipa.test") == 0) {
        entry_list = ph_entry_array_alloc(PH_MAP_HOST_END, 1);
        if (entry_list == NULL) {
            return ENOMEM;
        }

        ret = mock_ph_host(entry_list[0], key, NULL);
        assert_int_equal(ret, 0);
    } else if (strcmp(key, "multi.ipa.test") == 0) {
        entry_list = ph_entry_array_alloc(PH_MAP_HOST_END, 2);
        if (entry_list == NULL) {
            return ENOMEM;
        }

        ret = mock_ph_host(entry_list[0], key, NULL);
        assert_int_equal(ret, 0);
        ret = mock_ph_host(entry_list[1], "foo.ipa.test", NULL);
        assert_int_equal(ret, 0);
    } else if (strcmp(key, "nofqdn.ipa.test") == 0) {
        entry_list = ph_entry_array_alloc(PH_MAP_HOST_END, 1);
        if (entry_list == NULL) {
            return ENOMEM;
        }

        entry_list[0]->attrs[PH_MAP_HOST_OC] = mock_ph_attr("objectClass",
                                                            "top", "ipaHost",
                                                            NULL);
        if (entry_list[0]->attrs[PH_MAP_HOST_OC] == NULL) {
            return ENOMEM;
        }
    } else if (strcmp(key, "singlesvc") == 0) {
        entry_list = ph_entry_array_alloc(PH_MAP_SVC_END, 1);
        if (entry_list == NULL) {
            return ENOMEM;
        }

        ret = mock_ph_svc(entry_list[0], key);
        assert_int_equal(ret, 0);
    } else if (strcmp(key, "multisvc") == 0) {
        entry_list = ph_entry_array_alloc(PH_MAP_SVC_END, 2);
        if (entry_list == NULL) {
            return ENOMEM;
        }

        ret = mock_ph_svc(entry_list[0], key);
        assert_int_equal(ret, 0);
        ret = mock_ph_svc(entry_list[1], "foosvc");
        assert_int_equal(ret, 0);
    } else if (strcmp(key, "nocnsvc") == 0) {
        entry_list = ph_entry_array_alloc(PH_MAP_SVC_END, 1);
        if (entry_list == NULL) {
            return ENOMEM;
        }

        entry_list[0]->attrs[PH_MAP_SVC_OC] = mock_ph_attr("objectClass",
                                                           "top",
                                                           "ipaHbacService",
                                                           NULL);
        if (entry_list[0]->attrs[PH_MAP_SVC_OC] == NULL) {
            ph_entry_array_free(entry_list);
            return ENOMEM;
        }
    } else {
        return EINVAL;
    }

    *_entry_list = entry_list;
    return rv;
}

static void
mock_ph_search(int ret, const char *key)
{
    will_return(__wrap_ph_search, ret);
    will_return(__wrap_ph_search, key);
}

static void
test_ph_host(void **state)
{
    int ret;
    struct pam_hbac_ctx ph_ctx;
    const char *hostname = "single.ipa.test";
    struct ph_entry *host;

    memset(&ph_ctx, 0, sizeof(ph_ctx));

    mock_ph_search(0, hostname);
    ret = ph_get_host(&ph_ctx, hostname, &host);
    assert_int_equal(ret, 0);
    assert_non_null(host);

    ph_entry_free(host);
}

static void
test_ph_host_multiple(void **state)
{
    int ret;
    struct pam_hbac_ctx ph_ctx;
    const char *hostname = "multi.ipa.test";
    struct ph_entry *host = NULL;

    memset(&ph_ctx, 0, sizeof(ph_ctx));

    mock_ph_search(0, hostname);
    ret = ph_get_host(&ph_ctx, hostname, &host);
    assert_int_equal(ret, E2BIG);
    assert_null(host);
}

static void
test_ph_host_srch_fail(void **state)
{
    int ret;
    struct pam_hbac_ctx ph_ctx;
    const char *hostname = "single.ipa.test";
    struct ph_entry *host = NULL;

    memset(&ph_ctx, 0, sizeof(ph_ctx));

    mock_ph_search(EIO, hostname);
    ret = ph_get_host(&ph_ctx, hostname, &host);
    assert_int_equal(ret, EIO);
    assert_null(host);
}

static void
test_ph_host_no_fqdn(void **state)
{
    int ret;
    struct pam_hbac_ctx ph_ctx;
    const char *hostname = "nofqdn.ipa.test";
    struct ph_entry *host = NULL;

    memset(&ph_ctx, 0, sizeof(ph_ctx));

    mock_ph_search(0, hostname);
    ret = ph_get_host(&ph_ctx, hostname, &host);
    assert_int_equal(ret, EINVAL);
    assert_null(host);
}

static void
test_ph_svc(void **state)
{
    int ret;
    struct pam_hbac_ctx ph_ctx;
    const char *svcname = "singlesvc";
    struct ph_entry *svc;

    memset(&ph_ctx, 0, sizeof(ph_ctx));

    mock_ph_search(0, svcname);
    ret = ph_get_svc(&ph_ctx, svcname, &svc);
    assert_int_equal(ret, 0);
    assert_non_null(svc);

    ph_entry_free(svc);
}

static void
test_ph_svc_multiple(void **state)
{
    int ret;
    struct pam_hbac_ctx ph_ctx;
    const char *svcname = "multisvc";
    struct ph_entry *svc;

    memset(&ph_ctx, 0, sizeof(ph_ctx));

    mock_ph_search(0, svcname);
    ret = ph_get_svc(&ph_ctx, svcname, &svc);
    assert_int_equal(ret, E2BIG);
}

static void
test_ph_svc_srch_fail(void **state)
{
    int ret;
    struct pam_hbac_ctx ph_ctx;
    const char *svcname = "singlesvc";
    struct ph_entry *svc;

    memset(&ph_ctx, 0, sizeof(ph_ctx));

    mock_ph_search(EIO, svcname);
    ret = ph_get_svc(&ph_ctx, svcname, &svc);
    assert_int_equal(ret, EIO);
}


static void
test_ph_svc_no_cn(void **state)
{
    int ret;
    struct pam_hbac_ctx ph_ctx;
    const char *svcname = "nocnsvc";
    struct ph_entry *svc;

    memset(&ph_ctx, 0, sizeof(ph_ctx));

    mock_ph_search(0, svcname);
    ret = ph_get_svc(&ph_ctx, svcname, &svc);
    assert_int_equal(ret, EINVAL);
}

int
main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_ph_get_user_no_sup_groups),
        cmocka_unit_test(test_ph_get_user_sup_groups),
        cmocka_unit_test(test_ph_get_user_unknown),
        cmocka_unit_test(test_ph_host),
        cmocka_unit_test(test_ph_host_multiple),
        cmocka_unit_test(test_ph_host_srch_fail),
        cmocka_unit_test(test_ph_host_no_fqdn),
        cmocka_unit_test(test_ph_svc),
        cmocka_unit_test(test_ph_svc_multiple),
        cmocka_unit_test(test_ph_svc_srch_fail),
        cmocka_unit_test(test_ph_svc_no_cn),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
