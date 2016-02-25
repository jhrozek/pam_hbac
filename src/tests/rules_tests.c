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

#include "pam_hbac_obj.h"
#include "pam_hbac_ldap.h"

#include "common_mock.h"

int
__wrap_ph_search(pam_handle_t *pamh,
                 LDAP *ld,
                 struct pam_hbac_config *conf,
                 struct ph_search_ctx *s,
                 const char *obj_filter,
                 struct ph_entry ***_entry_list)
{
    int rv;
    struct ph_entry **entry_list;

#if 0
    check_expected(obj_filter);
#endif

    rv = ph_mock_type(int);
    entry_list = ph_mock_ptr_type(struct ph_entry **);
    if (rv != 0) {
        return rv;
    }

    if (entry_list) {
        *_entry_list = entry_list;
    }

    return 0;
}

static void
mock_ph_search(int ret, struct ph_entry **entries)
{
    will_return(__wrap_ph_search, ret);
    will_return(__wrap_ph_search, entries);
}

struct get_rules_ctx {
    struct pam_hbac_ctx ctx;
    struct pam_hbac_config pc;
    struct ph_entry *targethost;
    struct hbac_rule **rules;
};

static int
test_get_rules_setup(void **state)
{
    struct get_rules_ctx  *test_ctx;

    test_ctx = calloc(1, sizeof(struct get_rules_ctx));
    if (test_ctx == NULL) {
        return 1;
    }

    test_ctx->pc.search_base = "rules.test";

    test_ctx->ctx.pc = &test_ctx->pc;

    test_ctx->targethost = ph_entry_alloc(PH_MAP_HOST_END);
    if (test_ctx->targethost == NULL) {
        free(test_ctx);
        return 1;
    }

    *state = test_ctx;
    return 0;
}

static int
test_get_rules_teardown(void **state)
{
    struct get_rules_ctx  *test_ctx = *state;

    ph_entry_free(test_ctx->targethost);
    ph_free_hbac_rules(test_ctx->rules);
    free(test_ctx);
    return 0;
}

static void
assert_srchosts(struct hbac_rule_element *el)
{
    assert_non_null(el);

    assert_non_null(el->names);
    assert_null(el->names[0]);

    assert_non_null(el->groups);
    assert_null(el->groups[0]);

    assert_true(el->category & HBAC_CATEGORY_ALL);
}

static void
assert_hbac_rule(struct hbac_rule *rule,
                 const char *name,
                 const char *user_names[], const char *user_groups[],
                 uint32_t user_category,
                 const char *service_names[], const char *service_groups[],
                 uint32_t service_category,
                 const char *host_names[], const char *host_groups[],
                 uint32_t host_category)
{
    assert_non_null(rule);

    assert_non_null(rule->name);
    assert_string_equal(rule->name, name);

    assert_string_list_matches(rule->users->names, user_names);
    assert_true((rule->users->category ^ user_category) == 0);
    assert_true((rule->services->category ^ service_category) == 0);
    assert_true((rule->targethosts->category ^ host_category) == 0);
    assert_srchosts(rule->srchosts);
}

static void
test_get_rules_allow_all(void **state)
{
    int ret;
    struct get_rules_ctx *test_ctx = *state;
    struct ph_entry **ldap_rules = NULL;

    ret = mock_ph_host(test_ctx->targethost, "nogroups.ipa.test", NULL);
    assert_int_equal(ret, 0);

    ldap_rules = ph_entry_array_alloc(PH_MAP_RULE_END, 1);
    assert_non_null(ldap_rules);
    ret = mock_ph_rule(ldap_rules[0],
                       "allow_all",
                       "1-2-3-4-",
                       "true",
                       NULL, NULL, "all", /* users */
                       NULL, NULL, "all", /* services */
                       NULL, NULL, "all", /* hosts */
                       NULL);
    mock_ph_search(0, ldap_rules);

#if 0
    expect_string(__wrap_ph_search, order,
                  "(ipaEnabledFlag=TRUE)(accessRuleType=allow)(|(sourceHostCategory=all)"
                  "(memberHost=nogroups.ipa.test))");
#endif

    ret = ph_get_hbac_rules(&test_ctx->ctx,
                            test_ctx->targethost,
                            &test_ctx->rules);
    assert_int_equal(ret, 0);
    assert_non_null(test_ctx->rules);
    assert_hbac_rule(test_ctx->rules[0], "allow_all",
                     NULL, NULL, HBAC_CATEGORY_ALL,
                     NULL, NULL, HBAC_CATEGORY_ALL,
                     NULL, NULL, HBAC_CATEGORY_ALL);

    ph_entry_array_free(ldap_rules);
}

static void
test_get_rules_user_svc_host(void **state)
{
    int ret;
    struct get_rules_ctx *test_ctx = *state;
    struct ph_entry **ldap_rules = NULL;
    const char *member_users[] = {
        "uid=tuser,cn=users,cn=accounts,dc=ipa,dc=test",
        NULL,
    };
    const char *member_service[] = {
        "cn=sshd,cn=hbacservices,cn=hbac,dc=ipa,dc=test",
        NULL,
    };
    const char *member_host[] = {
        "fqdn=client.ipa.test,cn=computers,cn=accounts,dc=ipa,dc=test",
        NULL,
    };
    const char *exp_names[] = {
        "tuser",
        NULL,
    };
    const char *exp_services[] = {
        "sshd",
        NULL,
    };
    const char *exp_hosts[] = {
        "client.ipa.test",
        NULL,
    };

    ret = mock_ph_host(test_ctx->targethost, "client.ipa.test", NULL);
    assert_int_equal(ret, 0);

    ldap_rules = ph_entry_array_alloc(PH_MAP_RULE_END, 1);
    assert_non_null(ldap_rules);
    ret = mock_ph_rule(ldap_rules[0],
                       "tuser_sshd",
                       "1-2-3-4",
                       "true",
                       member_users, NULL, NULL,
                       member_service, NULL, NULL,
                       member_host, NULL, NULL,
                       NULL);
    mock_ph_search(0, ldap_rules);

#if 0
    expect_string(__wrap_ph_search, order,
                  "(ipaEnabledFlag=TRUE)(accessRuleType=allow)(|(sourceHostCategory=all)"
                  "(memberHost=nogroups.ipa.test))");
#endif

    ret = ph_get_hbac_rules(&test_ctx->ctx,
                            test_ctx->targethost,
                            &test_ctx->rules);
    assert_int_equal(ret, 0);
    assert_non_null(test_ctx->rules);
    assert_hbac_rule(test_ctx->rules[0],
                     "tuser_sshd",
                     exp_names, NULL, 0,
                     exp_services, NULL, 0,
                     exp_hosts, NULL, 0);

    ph_entry_array_free(ldap_rules);
}

static void
test_get_rules_groups(void **state)
{
    int ret;
    struct get_rules_ctx *test_ctx = *state;
    struct ph_entry **ldap_rules = NULL;
    const char *member_user_groups[] = {
        "cn=tgroup,cn=groups,cn=accounts,dc=ipa,dc=test",
        NULL,
    };
    const char *member_service_groups[] = {
        "cn=Sudo,cn=hbacservicegroups,cn=hbac,dc=ipa,dc=test",
        NULL,
    };
    const char *member_host_groups[] = {
        "cn=testhgr,cn=hostgroups,cn=accounts,dc=ipa,dc=test",
        NULL,
    };
    const char *exp_group_names[] = {
        "tgroup",
        NULL,
    };
    const char *exp_svc_groups[] = {
        "Sudo",
        NULL,
    };
    const char *exp_host_groups[] = {
        "testhgr",
        NULL,
    };

    ret = mock_ph_host(test_ctx->targethost, "client.ipa.test", NULL);
    assert_int_equal(ret, 0);
    /* FIXME - add hostgroups and check them in the filter */

    ldap_rules = ph_entry_array_alloc(PH_MAP_RULE_END, 1);
    assert_non_null(ldap_rules);
    ret = mock_ph_rule(ldap_rules[0],
                       "tgroup_sudo",
                       "1-2-3-4",
                       "true",
                       NULL, member_user_groups, NULL,
                       NULL, member_service_groups, NULL,
                       NULL, member_host_groups, NULL,
                       NULL);
    mock_ph_search(0, ldap_rules);

    ret = ph_get_hbac_rules(&test_ctx->ctx,
                            test_ctx->targethost,
                            &test_ctx->rules);
    assert_int_equal(ret, 0);
    assert_non_null(test_ctx->rules);
    assert_hbac_rule(test_ctx->rules[0],
                     "tgroup_sudo",
                     NULL, exp_group_names, 0,
                     NULL, exp_svc_groups, 0,
                     NULL, exp_host_groups, 0);

    ph_entry_array_free(ldap_rules);
}

int
main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_get_rules_allow_all,
                                        test_get_rules_setup,
                                        test_get_rules_teardown),
        cmocka_unit_test_setup_teardown(test_get_rules_user_svc_host,
                                        test_get_rules_setup,
                                        test_get_rules_teardown),
        cmocka_unit_test_setup_teardown(test_get_rules_groups,
                                        test_get_rules_setup,
                                        test_get_rules_teardown),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
