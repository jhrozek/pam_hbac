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
#include "common_mock.h"

#define TEST_BASEDN "dc=ipa,dc=test"
#define GROUP_CONTAINER "cn=groups,cn=accounts"
#define HOST_CONTAINER "cn=hostgroups,cn=accounts"
#define SVC_CONTAINER "cn=hbacservicegroups,cn=hbac"

#define USER_GROUP1 "usr_gr1"
#define USER_GROUP2 "usr_gr2"

#define HOST_GROUP1 "host_gr1"
#define HOST_GROUP2 "host_gr2"

#define SVC_GROUP1  "svc_gr1"
#define SVC_GROUP2  "svc_gr2"

struct eval_req_test_ctx {
    struct ph_user *user;
    struct hbac_eval_req *req;

    struct ph_entry *targethost;
    struct ph_entry *service;
};

static void
assert_empty_groups(struct hbac_request_element *el)
{
    assert_non_null(el);
    assert_non_null(el->groups);
    assert_null(el->groups[0]);
}

static void
assert_string_list_matches(const char *list[],
                           const char *expected[])
{
    size_t exp_size;
    size_t list_size;
    size_t i;

    exp_size = null_cstring_array_size(expected);
    list_size = null_cstring_array_size(list);
    assert_int_equal(exp_size, list_size);

    for (i = 0; i < exp_size; i++) {
        assert_string_equal(list[i], expected[i]);
    }
}

static int
eval_req_test_setup(void **state)
{
    struct eval_req_test_ctx *test_ctx;

    test_ctx = calloc(1, sizeof(struct eval_req_test_ctx));
    if (test_ctx == NULL) {
        return 1;
    }

    test_ctx->targethost = ph_entry_alloc(PH_MAP_HOST_END);
    if (test_ctx->targethost == NULL) {
        return 1;
    }
    test_ctx->targethost->attrs[PH_MAP_HOST_OC] = \
                                                mock_ph_attr("objectClass",
                                                             "top", "ipaHost",
                                                             NULL);
    test_ctx->targethost->attrs[PH_MAP_HOST_FQDN] = \
                                             mock_ph_attr("fqdn",
                                                          "testhost",
                                                           NULL);
    if (test_ctx->targethost->attrs[PH_MAP_HOST_OC] == NULL ||
            test_ctx->targethost->attrs[PH_MAP_HOST_FQDN] == NULL) {
        return 1;
    }

    test_ctx->service = ph_entry_alloc(PH_MAP_SVC_END);
    if (test_ctx->service == NULL) {
        return 1;
    }
    test_ctx->service->attrs[PH_MAP_SVC_OC] = mock_ph_attr("objectClass",
                                                      "top", "ipaService",
                                                      NULL);
    test_ctx->service->attrs[PH_MAP_SVC_NAME] = mock_ph_attr("cn",
                                                        "testsvc",
                                                         NULL);
    if (test_ctx->service->attrs[PH_MAP_SVC_OC] == NULL ||
            test_ctx->service->attrs[PH_MAP_SVC_NAME] == NULL) {
        return 1;
    }

    *state = test_ctx;
    return 0;
}

static int
eval_req_test_teardown(void **state)
{
    struct eval_req_test_ctx *test_ctx = *state;

    if (test_ctx == NULL) {
        return 0;
    }

    ph_entry_free(test_ctx->targethost);
    ph_entry_free(test_ctx->service);

    free(test_ctx);
    return 0;
}

static void
test_create_eval_req_invalid(void **state)
{
    int ret;

    (void) state; /* unused */

    ret = ph_create_hbac_eval_req(NULL, NULL, NULL, NULL);
    assert_int_equal(ret, EINVAL);
}

static int
test_create_eval_req_nogroups_setup(void **state)
{
    struct eval_req_test_ctx *test_ctx = *state;

    test_ctx->user = mock_user_obj("testuser", NULL);
    if (test_ctx->user == NULL) {
        return 1;
    }

    return 0;
}

static int
test_create_eval_req_nogroups_teardown(void **state)
{
    struct eval_req_test_ctx *test_ctx = *state;

    ph_free_user(test_ctx->user);
    ph_free_hbac_eval_req(test_ctx->req);
    return 0;
}

static void test_create_eval_req_nogroups(void **state)
{
    int ret;
    struct eval_req_test_ctx *test_ctx = *state;

    ret = ph_create_hbac_eval_req(test_ctx->user,
                                  test_ctx->targethost,
                                  test_ctx->service,
                                  &test_ctx->req);
    assert_int_equal(ret, 0);

    assert_non_null(test_ctx->req);
    assert_string_equal(test_ctx->req->user->name, "testuser");
    assert_empty_groups(test_ctx->req->user);
    assert_string_equal(test_ctx->req->targethost->name, "testhost");
    assert_empty_groups(test_ctx->req->targethost);
    assert_string_equal(test_ctx->req->service->name, "testsvc");
    assert_empty_groups(test_ctx->req->service);
    assert_int_equal(test_ctx->req->request_time, time(NULL));
}

static int
test_create_eval_req_valid_groups_setup(void **state)
{
    struct eval_req_test_ctx *test_ctx = *state;

    test_ctx->user = mock_user_obj("testuser", USER_GROUP1, USER_GROUP2, NULL);
    if (test_ctx->user == NULL) {
        return 1;
    }

    test_ctx->targethost->attrs[PH_MAP_HOST_MEMBEROF] = \
               mock_ph_attr("memberof",
                            "cn="HOST_GROUP1","HOST_CONTAINER","TEST_BASEDN,
                            NULL);
    if (test_ctx->targethost->attrs[PH_MAP_HOST_MEMBEROF] == NULL) {
        return 1;
    }

    test_ctx->service->attrs[PH_MAP_SVC_MEMBEROF] = \
               mock_ph_attr("memberof",
                            "cn="SVC_GROUP1","SVC_CONTAINER","TEST_BASEDN,
                            "cn="SVC_GROUP2","SVC_CONTAINER","TEST_BASEDN,
                            NULL);
    if (test_ctx->service->attrs[PH_MAP_SVC_MEMBEROF] == NULL) {
        return 1;
    }

    return 0;
}

static int
test_create_eval_req_valid_groups_teardown(void **state)
{
    struct eval_req_test_ctx *test_ctx = *state;

    ph_attr_free(test_ctx->targethost->attrs[PH_MAP_HOST_MEMBEROF]);
    test_ctx->targethost->attrs[PH_MAP_HOST_MEMBEROF] = NULL;

    ph_attr_free(test_ctx->service->attrs[PH_MAP_SVC_MEMBEROF]);
    test_ctx->service->attrs[PH_MAP_SVC_MEMBEROF] = NULL;

    ph_free_hbac_eval_req(test_ctx->req);
    ph_free_user(test_ctx->user);
    return 0;
}

static void test_create_eval_req_valid_groups(void **state)
{
    int ret;
    struct eval_req_test_ctx *test_ctx = *state;
    const char *exp_usr_groups[] = {
        USER_GROUP1,
        USER_GROUP2,
        NULL
    };
    const char *exp_host_groups[] = {
        HOST_GROUP1,
        NULL
    };
    const char *exp_svc_groups[] = {
        SVC_GROUP1,
        SVC_GROUP2,
        NULL
    };

    ret = ph_create_hbac_eval_req(test_ctx->user,
                                  test_ctx->targethost,
                                  test_ctx->service,
                                  &test_ctx->req);
    assert_int_equal(ret, 0);

    assert_non_null(test_ctx->req);
    assert_string_equal(test_ctx->req->user->name, "testuser");
    assert_string_list_matches(test_ctx->req->user->groups, exp_usr_groups);
    assert_string_equal(test_ctx->req->targethost->name, "testhost");
    assert_string_list_matches(test_ctx->req->targethost->groups,
                               exp_host_groups);
    assert_string_equal(test_ctx->req->service->name, "testsvc");
    assert_string_list_matches(test_ctx->req->service->groups,
                               exp_svc_groups);
    assert_int_equal(test_ctx->req->request_time, time(NULL));
}

static int
test_create_eval_req_invalid_groups_setup(void **state)
{
    struct eval_req_test_ctx *test_ctx = *state;

    test_ctx->user = mock_user_obj("testuser", USER_GROUP1, USER_GROUP2, NULL);
    if (test_ctx->user == NULL) {
        return 1;
    }

    test_ctx->targethost->attrs[PH_MAP_HOST_MEMBEROF] = \
               mock_ph_attr("memberof",
                            /* Missing basedn */
                            "cn="HOST_GROUP2","HOST_CONTAINER,
                            NULL);
    if (test_ctx->targethost->attrs[PH_MAP_HOST_MEMBEROF] == NULL) {
        return 1;
    }

    test_ctx->service->attrs[PH_MAP_SVC_MEMBEROF] = \
               mock_ph_attr("memberof",
                            /* Bad RDN  */
                            "foo="SVC_GROUP1","SVC_CONTAINER","TEST_BASEDN,
                            /* Bad container */
                            "cn="SVC_GROUP1",cn=foo,"TEST_BASEDN,
                            "cn="SVC_GROUP2","SVC_CONTAINER","TEST_BASEDN,
                            /* Not a DN */
                            "kalle_anka",
                            NULL);
    if (test_ctx->service->attrs[PH_MAP_SVC_MEMBEROF] == NULL) {
        return 1;
    }

    return 0;
}

static int
test_create_eval_req_invalid_groups_teardown(void **state)
{
    struct eval_req_test_ctx *test_ctx = *state;

    ph_attr_free(test_ctx->targethost->attrs[PH_MAP_HOST_MEMBEROF]);
    test_ctx->targethost->attrs[PH_MAP_HOST_MEMBEROF] = NULL;

    ph_attr_free(test_ctx->service->attrs[PH_MAP_SVC_MEMBEROF]);
    test_ctx->service->attrs[PH_MAP_SVC_MEMBEROF] = NULL;

    ph_free_hbac_eval_req(test_ctx->req);
    ph_free_user(test_ctx->user);
    return 0;
}

static void test_create_eval_req_skip_invalid_groups(void **state)
{
    int ret;
    struct eval_req_test_ctx *test_ctx = *state;
    const char *exp_usr_groups[] = {
        USER_GROUP1,
        USER_GROUP2,
        NULL
    };
    const char *exp_svc_groups[] = {
        SVC_GROUP2,
        NULL
    };

    ret = ph_create_hbac_eval_req(test_ctx->user,
                                  test_ctx->targethost,
                                  test_ctx->service,
                                  &test_ctx->req);
    assert_int_equal(ret, 0);

    assert_string_equal(test_ctx->req->user->name, "testuser");
    assert_string_list_matches(test_ctx->req->user->groups, exp_usr_groups);
    assert_string_equal(test_ctx->req->targethost->name, "testhost");
    assert_empty_groups(test_ctx->req->targethost);
    assert_string_equal(test_ctx->req->service->name, "testsvc");
    assert_string_list_matches(test_ctx->req->service->groups,
                               exp_svc_groups);
    assert_int_equal(test_ctx->req->request_time, time(NULL));
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_create_eval_req_invalid),
        cmocka_unit_test_setup_teardown(test_create_eval_req_nogroups,
                                        test_create_eval_req_nogroups_setup,
                                        test_create_eval_req_nogroups_teardown),
        cmocka_unit_test_setup_teardown(test_create_eval_req_valid_groups,
                                        test_create_eval_req_valid_groups_setup,
                                        test_create_eval_req_valid_groups_teardown),
        cmocka_unit_test_setup_teardown(test_create_eval_req_skip_invalid_groups,
                                        test_create_eval_req_invalid_groups_setup,
                                        test_create_eval_req_invalid_groups_teardown),
    };

    return cmocka_run_group_tests(tests,
                                  eval_req_test_setup,
                                  eval_req_test_teardown);
}
