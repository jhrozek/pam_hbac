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

#include <errno.h>
#include "pam_hbac.h"

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
    struct ph_member_obj user;
    struct ph_member_obj tgthost;
    struct ph_member_obj service;
    struct hbac_eval_req *req;
};

static void add_to_member_obj(struct ph_member_obj *obj,
                              char *name,
                              char **group_dns)
{
    obj->name = name;
    obj->memberofs = group_dns;
}

static void assert_empty_groups(struct hbac_request_element *el)
{
    assert_non_null(el);
    assert_non_null(el->groups);
    assert_null(el->groups[0]);
}

static size_t string_list_size(const char *list[])
{
    size_t i;

    assert_non_null(list);

    for (i = 0; list[i]; i++);
    return i;
}

static void assert_string_list_matches(const char *list[],
                                       const char *expected[])
{
    size_t exp_size;
    size_t list_size;
    size_t i;

    exp_size = string_list_size(expected);
    list_size = string_list_size(list);
    assert_int_equal(exp_size, list_size);

    for (i = 0; i < exp_size; i++) {
        assert_string_equal(list[i], expected[i]);
    }
}

static int eval_req_test_setup(void **state)
{
    struct eval_req_test_ctx *test_ctx;
    static char *nogroups[] = { NULL };

    test_ctx = calloc(1, sizeof(struct eval_req_test_ctx));
    if (test_ctx == NULL) {
        return 1;
    }

    add_to_member_obj(&test_ctx->user, "testuser", nogroups);
    add_to_member_obj(&test_ctx->tgthost, "testhost", nogroups);
    add_to_member_obj(&test_ctx->service, "testsvc", nogroups);

    *state = test_ctx;
    return 0;
}

static int eval_req_test_teardown(void **state)
{
    struct eval_req_test_ctx *test_ctx = *state;

    if (test_ctx != NULL) {
        ph_free_eval_req(test_ctx->req);
        free(test_ctx);
    }
    return 0;
}

static void test_create_eval_req_invalid(void **state)
{
    int ret;

    (void) state; /* unused */

    ret = ph_create_hbac_eval_req(NULL, NULL, NULL, NULL);
    assert_int_equal(ret, EINVAL);
}

static void test_create_eval_req_nogroups(void **state)
{
    int ret;
    struct eval_req_test_ctx *test_ctx = *state;

    ret = ph_create_hbac_eval_req(&test_ctx->user,
                                  &test_ctx->tgthost,
                                  &test_ctx->service,
                                  &test_ctx->req);
    assert_int_equal(ret, 0);

    assert_string_equal(test_ctx->req->user->name, "testuser");
    assert_empty_groups(test_ctx->req->user);
    assert_string_equal(test_ctx->req->targethost->name, "testhost");
    assert_empty_groups(test_ctx->req->targethost);
    assert_string_equal(test_ctx->req->service->name, "testsvc");
    assert_empty_groups(test_ctx->req->service);
    assert_int_equal(test_ctx->req->request_time, time(NULL));
}

static void test_create_eval_req_valid_groups(void **state)
{
    int ret;
    struct eval_req_test_ctx *test_ctx = *state;

    char *user_group_dns[] = {
        "cn="USER_GROUP1","GROUP_CONTAINER","TEST_BASEDN,
        NULL
    };
    const char *user_groups[] = {
        USER_GROUP1,
        NULL
    };

    char *service_group_dns[] = {
        "cn="SVC_GROUP1","SVC_CONTAINER","TEST_BASEDN,
        NULL
    };
    const char *service_groups[] = {
        SVC_GROUP1,
        NULL
    };

    char *host_group_dns[] = {
        "cn="HOST_GROUP1","HOST_CONTAINER","TEST_BASEDN,
        NULL
    };
    const char *host_groups[] = {
        HOST_GROUP1,
        NULL
    };

    test_ctx->user.memberofs = user_group_dns;
    test_ctx->service.memberofs = service_group_dns;
    test_ctx->tgthost.memberofs = host_group_dns;

    ret = ph_create_hbac_eval_req(&test_ctx->user,
                                  &test_ctx->tgthost,
                                  &test_ctx->service,
                                  &test_ctx->req);
    assert_int_equal(ret, 0);

    assert_string_equal(test_ctx->req->user->name, "testuser");
    assert_string_list_matches(test_ctx->req->user->groups, user_groups);
    assert_string_equal(test_ctx->req->targethost->name, "testhost");
    assert_string_list_matches(test_ctx->req->targethost->groups, host_groups);
    assert_string_equal(test_ctx->req->service->name, "testsvc");
    assert_string_list_matches(test_ctx->req->service->groups, service_groups);
    assert_int_equal(test_ctx->req->request_time, time(NULL));
}

static void test_create_eval_req_skip_invalid_groups(void **state)
{
    int ret;
    struct eval_req_test_ctx *test_ctx = *state;

   char *user_group_dns[] = {
        /* Bad RDN */
        "uid="USER_GROUP1","GROUP_CONTAINER","TEST_BASEDN,
        "cn="USER_GROUP1","GROUP_CONTAINER","TEST_BASEDN,
        "cn="USER_GROUP2","GROUP_CONTAINER","TEST_BASEDN,
        NULL
    };
    const char *user_groups[] = {
        USER_GROUP1,
        USER_GROUP2,
        NULL
    };

    char *service_group_dns[] = {
        "cn="SVC_GROUP1","SVC_CONTAINER","TEST_BASEDN,
        /* Bad container */
        "cn="SVC_GROUP1",cn=foo,"TEST_BASEDN,
        "cn="SVC_GROUP2","SVC_CONTAINER","TEST_BASEDN,
        /* Not a DN */
        "kalle_anka",
        NULL
    };
    const char *service_groups[] = {
        SVC_GROUP1,
        SVC_GROUP2,
        NULL
    };

    char *host_group_dns[] = {
        /* Missing basedn */
        "cn="HOST_GROUP2","HOST_CONTAINER,
        NULL
    };

    test_ctx->user.memberofs = user_group_dns;
    test_ctx->service.memberofs = service_group_dns;
    test_ctx->tgthost.memberofs = host_group_dns;

    ret = ph_create_hbac_eval_req(&test_ctx->user,
                                  &test_ctx->tgthost,
                                  &test_ctx->service,
                                  &test_ctx->req);
    assert_int_equal(ret, 0);

    assert_string_equal(test_ctx->req->user->name, "testuser");
    assert_string_list_matches(test_ctx->req->user->groups, user_groups);
    assert_string_equal(test_ctx->req->targethost->name, "testhost");
    assert_empty_groups(test_ctx->req->targethost);
    assert_string_equal(test_ctx->req->service->name, "testsvc");
    assert_string_list_matches(test_ctx->req->service->groups, service_groups);
    assert_int_equal(test_ctx->req->request_time, time(NULL));
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_create_eval_req_invalid),
        cmocka_unit_test(test_create_eval_req_nogroups),
        cmocka_unit_test(test_create_eval_req_valid_groups),
        cmocka_unit_test(test_create_eval_req_skip_invalid_groups),
    };

    return cmocka_run_group_tests(tests,
                                  eval_req_test_setup,
                                  eval_req_test_teardown);
}
