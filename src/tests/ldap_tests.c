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
#include "pam_hbac_ldap.h"

#include "common_mock.h"

#define BIND_PW     "Secret"
#define BIND_DN     "cn=admin,dc=ipa,dc=test"
#define LDAP_URI    "ldap://dc.ipa.test"

LDAPMessage *dummy_ent = (LDAPMessage *) 0xdeadbeef;

struct mock_ldap_attr {
    const char *name;
    const char **values;
};

struct mock_ldap_entry {
    const char *dn;
    struct mock_ldap_attr *attrs;
};

struct mock_ldap_msg_array {
    struct mock_ldap_entry **array;
    size_t index;
};

static int
mock_ldap_entry_iter(void)
{
    return ph_mock_type(int);
}

struct berval **
__wrap_ldap_get_values_len(LDAP *ld,
                           LDAPMessage *entry,
                           LDAP_CONST char *target)
{
    size_t count, i;
    struct berval **vals;
    const char **attrvals;
    struct mock_ldap_entry *mock_entry = (struct mock_ldap_entry *) entry;

    if (target == NULL) {
        return NULL;
    }

    if (mock_entry == NULL) {
        return NULL;
    }

    /* Should we return empty array here? */
    if (mock_entry->attrs == NULL) {
        return NULL;
    }

    attrvals = NULL;
    for (i = 0; mock_entry->attrs[i].name != NULL; i++) {
        if (strcmp(mock_entry->attrs[i].name, target) == 0) {
            attrvals = mock_entry->attrs[i].values;
            break;
        }
    }

    if (attrvals == NULL) {
        return NULL;
    }

    count = 0;
    for (i = 0; attrvals[i]; i++) {
        count++;
    }

    vals = calloc(count + 1, sizeof(struct berval *));
    assert_non_null(vals);

    for (i = 0; attrvals[i]; i++) {
        vals[i] = malloc(sizeof(struct berval));
        assert_non_null(vals[i]);

        vals[i]->bv_val = strdup(attrvals[i]);
        if (vals[i]->bv_val == NULL) {
            return NULL;
        }
        vals[i]->bv_len = strlen(attrvals[i]);
    }

    return vals;
}

void
__wrap_ldap_value_free_len(struct berval **vals)
{
    size_t i;

    if (vals == NULL) {
        return;
    }

    for (i = 0; vals[i]; i++) {
        if (vals[i] != NULL) {
            free(vals[i]->bv_val);
        }
        free(vals[i]);
    }

    free(vals);
}

char *
__wrap_ldap_first_attribute(LDAP *ld,
                            LDAPMessage *entry,
                            BerElement **berout)
{
    struct mock_ldap_entry *mock_entry = (struct mock_ldap_entry *) entry;

    if (mock_entry == NULL) return NULL;
    if (mock_entry->attrs == NULL) return NULL;

    will_return(mock_ldap_entry_iter, 1);

    if (berout) {
        *berout = NULL;
    }

    return discard_const(mock_entry->attrs[0].name);
}

char *
__wrap_ldap_next_attribute(LDAP *ld,
                           LDAPMessage *entry,
                           BerElement *ber)
{
    struct mock_ldap_entry *mock_entry = (struct mock_ldap_entry *) entry;

    int idx = mock_ldap_entry_iter();
    char *val;

    val = discard_const(mock_entry->attrs[idx].name);
    if (val != NULL) {
        will_return(mock_ldap_entry_iter, idx + 1);
    }
    return val;
}

void __wrap_ldap_memfree(void *p)
{
    return;
}

void
__wrap_ber_free(BerElement *ber, int freebuf)
{
    return;
}

LDAPMessage *
__wrap_ldap_first_message(LDAP *ld, LDAPMessage *chain)
{
    return ph_mock_ptr_type(LDAPMessage *);
}

LDAPMessage *
__wrap_ldap_next_message(LDAP *ld, LDAPMessage *chain)
{
    return ph_mock_ptr_type(LDAPMessage *);
}

int
__wrap_ldap_msgtype(LDAPMessage *lm)
{
    return ph_mock_type(int);
}

int
__wrap_ldap_count_entries(LDAP *ld, LDAPMessage *chain)
{
    return ph_mock_type(int);
}

int
__wrap_ldap_sasl_bind_s(LDAP *ld, const char *dn, const char *mechanism,
                        struct berval *cred, LDAPControl *sctrls[],
                        LDAPControl *cctrls[], struct berval **servercredp)
{
    if (strncmp(BIND_PW, cred->bv_val, cred->bv_len) != 0) {
        return -1;
    }

    return LDAP_SUCCESS;
}

int
__wrap_ldap_unbind_ext(LDAP *ld, LDAPControl *sctrls[],
                       LDAPControl *cctrls[])
{
    assert_non_null(ld);

    return 0;
}

int
__wrap_ldap_search_ext_s(LDAP *ld, const char *base, int scope,
                         const char *filter, char **attrs,
                         int attrsonly, LDAPControl **sctrls,
                         LDAPControl **cctrls, struct timeval *timeout,
                         int sizelimit, LDAPMessage **res)
{
    assert_non_null(ld);
    assert_non_null(base);
    assert_non_null(filter);
    assert_non_null(attrs);

    return ph_mock_type(int);
}

static void
set_dummy_config(struct pam_hbac_config *conf)
{
    memset(conf, 0, sizeof(struct pam_hbac_config));
    conf->bind_pw = BIND_PW;
    conf->bind_dn = BIND_DN;
    conf->uri     = LDAP_URI;
}

static void
assert_connect(struct pam_hbac_ctx *ctx)
{
    int ret;

    ret = ph_connect(ctx);
    assert_int_equal(ret, 0);
    assert_non_null(ctx->ld);
}

struct search_test_ctx {
    struct pam_hbac_ctx ctx;
    struct pam_hbac_config conf;
};

static int
test_search_setup(void **state)
{
    struct search_test_ctx *test_ctx;

    test_ctx = malloc(sizeof(struct search_test_ctx));
    if (test_ctx == NULL) {
        return 1;
    }

    set_dummy_config(&test_ctx->conf);
    memset(&test_ctx->ctx, 0, sizeof(struct pam_hbac_ctx));
    test_ctx->ctx.pc = &test_ctx->conf;

    assert_connect(&test_ctx->ctx);

    *state = test_ctx;
    return 0;
}

static int
test_search_teardown(void **state)
{
    struct search_test_ctx *test_ctx = *state;

    ph_disconnect(&test_ctx->ctx);
    assert_null(test_ctx->ctx.ld);

    free(test_ctx);
    return 0;
}

static void
will_return_entry_msg_array(struct mock_ldap_msg_array *msgs)
{
    size_t count;

    will_return(__wrap_ldap_search_ext_s, 0);

    for (count = 0; msgs->array[count]; count++) {
        if (count == 0) {
            /* We only care about a non-NULL pointer being returned */
            will_return(__wrap_ldap_first_message, msgs->array[count]);
        } else {
            will_return(__wrap_ldap_next_message, msgs->array[count]);
        }
        will_return(__wrap_ldap_msgtype, LDAP_RES_SEARCH_ENTRY);
    }
    will_return(__wrap_ldap_next_message, NULL);

    will_return(__wrap_ldap_count_entries, count);
}

static void
assert_entry_attr_vals(struct ph_entry *e,
                       int attr_index,
                       const char *vals[])
{
    struct ph_attr *a;

    a = ph_entry_get_attr(e, attr_index);
    assert_non_null(a);

    assert_int_equal(a->nvals, null_cstring_array_size(vals));

    for (size_t i = 0; i < a->nvals; i++) {
        assert_string_equal(a->vals[i]->bv_val, vals[i]);
    }
}

static const char *ph_host_attrs[] = { PAM_HBAC_ATTR_OC,
                                       "fqdn",
                                       "memberOf",
                                       NULL };

static struct ph_search_ctx test_search_obj = {
    .sub_base = "cn=computers,cn=accounts",
    .oc = "ipaHost",
    .attrs = ph_host_attrs,
    .num_attrs = PH_MAP_HOST_END,
};

static void
test_search_host_full(void **state)
{
    int ret;
    struct ph_entry **entry_list;
    struct search_test_ctx *test_ctx = *state;

    const char *oc_values[] = { "top",
                                "ipaHost",
                                NULL };
    const char *fqdn_values[] = { "client.ipa.test",
                                  NULL };
    const char *memberof_values[] = { "cn=servers,cn=hostgroups,cn=accounts,dc=ipa,dc=test",
                                      "cn=clients,cn=hostgroups,cn=accounts,dc=ipa,dc=test",
                                      NULL };
    const char *krb_last_pwd_change_values[] = { "20151207103045Z",
                                                 NULL };
    struct mock_ldap_attr test_ipa_host_attrs[] = {
        { .name = "objectClass", .values = oc_values },
        { .name = "fqdn", .values = fqdn_values },
        { .name = "memberOf", .values = memberof_values },
        { .name = "krbLastPwdChange", .values = krb_last_pwd_change_values },
        { NULL, NULL }
    };
    struct mock_ldap_entry test_ipa_host;
    struct mock_ldap_entry *ldap_result[] = { &test_ipa_host, NULL };
    struct mock_ldap_msg_array test_msg = {
        .array = ldap_result,
        .index = 0
    };

    test_ipa_host.dn = "fqdn=client.ipa.test,cn=computers,dc=ipa,dc=test";
    test_ipa_host.attrs = test_ipa_host_attrs;

    will_return_entry_msg_array(&test_msg);

    ret = ph_search(test_ctx->ctx.ld, test_ctx->ctx.pc, &test_search_obj,
                    "fqdn=client.ipa.test", &entry_list);
    assert_int_equal(ret, 0);
    assert_int_equal(ph_num_entries(entry_list), 1);

    assert_entry_attr_vals(entry_list[0], PH_MAP_HOST_OC, oc_values);
    assert_entry_attr_vals(entry_list[0], PH_MAP_HOST_FQDN, fqdn_values);
    assert_entry_attr_vals(entry_list[0], PH_MAP_HOST_MEMBEROF, memberof_values);

    ph_entry_array_free(entry_list);
}

static void
test_search_host_no_memberof(void **state)
{
    int ret;
    struct ph_entry **entry_list;
    struct search_test_ctx *test_ctx = *state;

    const char *oc_values[] = { "top",
                                "ipaHost",
                                NULL };
    const char *fqdn_values[] = { "client.ipa.test",
                                  NULL };
    const char *memberof_values[] = { NULL };
    const char *krb_last_pwd_change_values[] = { "20151207103045Z",
                                                 NULL };
    struct mock_ldap_attr test_ipa_host_attrs[] = {
        { .name = "objectClass", .values = oc_values },
        { .name = "fqdn", .values = fqdn_values },
        { .name = "memberOf", .values = memberof_values },
        { .name = "krbLastPwdChange", .values = krb_last_pwd_change_values },
        { NULL, NULL }
    };
    struct mock_ldap_entry test_ipa_host;
    struct mock_ldap_entry *ldap_result[] = { &test_ipa_host, NULL };
    struct mock_ldap_msg_array test_msg = {
        .array = ldap_result,
        .index = 0
    };

    test_ipa_host.dn = "fqdn=client.ipa.test,cn=computers,dc=ipa,dc=test";
    test_ipa_host.attrs = test_ipa_host_attrs;

    will_return_entry_msg_array(&test_msg);

    ret = ph_search(test_ctx->ctx.ld, test_ctx->ctx.pc, &test_search_obj,
                    "fqdn=client.ipa.test", &entry_list);
    assert_int_equal(ret, 0);
    assert_int_equal(ph_num_entries(entry_list), 1);

    assert_entry_attr_vals(entry_list[0], PH_MAP_HOST_OC, oc_values);
    assert_entry_attr_vals(entry_list[0], PH_MAP_HOST_FQDN, fqdn_values);
    assert_entry_attr_vals(entry_list[0], PH_MAP_HOST_MEMBEROF, memberof_values);

    ph_entry_array_free(entry_list);
}

static void
test_search_neg(void **state)
{
    int ret;
    struct ph_entry **entry_list = NULL;
    struct search_test_ctx *test_ctx = *state;

    ret = ph_search(NULL, test_ctx->ctx.pc, &test_search_obj,
                    "fqdn=client.ipa.test", &entry_list);
    assert_int_equal(ret, EINVAL);
    assert_null(entry_list);

    ret = ph_search(test_ctx->ctx.ld, NULL, &test_search_obj,
                    "fqdn=client.ipa.test", &entry_list);
    assert_int_equal(ret, EINVAL);
    assert_null(entry_list);

    ret = ph_search(test_ctx->ctx.ld, test_ctx->ctx.pc, NULL,
                    "fqdn=client.ipa.test", &entry_list);
    assert_int_equal(ret, EINVAL);
    assert_null(entry_list);
}

static void
test_search_host_no_oc(void **state)
{
    int ret;
    struct ph_entry **entry_list = NULL;
    struct search_test_ctx *test_ctx = *state;

    const char *oc_values[] = { NULL };
    const char *fqdn_values[] = { "client.ipa.test",
                                  NULL };
    const char *memberof_values[] = { "cn=servers,cn=hostgroups,cn=accounts,dc=ipa,dc=test",
                                      "cn=clients,cn=hostgroups,cn=accounts,dc=ipa,dc=test",
                                      NULL };
    const char *krb_last_pwd_change_values[] = { "20151207103045Z",
                                                 NULL };
    struct mock_ldap_attr test_ipa_host_attrs[] = {
        { .name = "objectClass", .values = oc_values },
        { .name = "fqdn", .values = fqdn_values },
        { .name = "memberOf", .values = memberof_values },
        { .name = "krbLastPwdChange", .values = krb_last_pwd_change_values },
        { NULL, NULL }
    };
    struct mock_ldap_entry test_ipa_host;
    struct mock_ldap_entry *ldap_result[] = { &test_ipa_host, NULL };
    struct mock_ldap_msg_array test_msg = {
        .array = ldap_result,
        .index = 0
    };

    test_ipa_host.dn = "fqdn=client.ipa.test,cn=computers,dc=ipa,dc=test";
    test_ipa_host.attrs = test_ipa_host_attrs;

    will_return_entry_msg_array(&test_msg);

    ret = ph_search(test_ctx->ctx.ld, test_ctx->ctx.pc, &test_search_obj,
                    "fqdn=client.ipa.test", &entry_list);
    assert_int_equal(ret, 0);
    assert_int_equal(ph_num_entries(entry_list), 1);

    /* On failure we return an empty entry and let the caller handle it..*/
    assert_non_null(entry_list[0]->attrs);
    assert_null(entry_list[0]->attrs[0]);
    ph_entry_array_free(entry_list);
}

static void
test_search_host_search_fail(void **state)
{
    int ret;
    struct ph_entry **entry_list = NULL;
    struct search_test_ctx *test_ctx = *state;

    will_return(__wrap_ldap_search_ext_s, EIO);

    ret = ph_search(test_ctx->ctx.ld, test_ctx->ctx.pc, &test_search_obj,
                    "fqdn=client.ipa.test", &entry_list);
    assert_int_not_equal(ret, 0);
    assert_null(entry_list);
}

static void
test_connect(void **state)
{
    int ret;
    struct pam_hbac_ctx ctx;
    struct pam_hbac_config pc;

    (void) state; /* unused */

    /* positive test */
    set_dummy_config(&pc);
    memset(&ctx, 0, sizeof(ctx));
    ctx.pc = &pc;

    assert_connect(&ctx);

    ph_disconnect(&ctx);
    assert_null(ctx.ld);

    /* negative tests */
    assert_int_equal(ph_connect(NULL), EINVAL);

    /* wrong password */
    pc.bind_pw = "blablabla";
    ret = ph_connect(&ctx);
    assert_int_equal(ret, EACCES);
    assert_null(ctx.ld);

    /* wrong uri */
    pc.bind_pw = BIND_PW;
    pc.uri     = "http://dc.ipa.test";
    ret = ph_connect(&ctx);
    assert_int_equal(ret, EIO);
    assert_null(ctx.ld);
}

int
main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_connect),
        cmocka_unit_test_setup_teardown(test_search_host_full,
                                        test_search_setup,
                                        test_search_teardown),
        cmocka_unit_test_setup_teardown(test_search_host_no_memberof,
                                        test_search_setup,
                                        test_search_teardown),
        cmocka_unit_test_setup_teardown(test_search_host_no_oc,
                                        test_search_setup,
                                        test_search_teardown),
        cmocka_unit_test_setup_teardown(test_search_host_search_fail,
                                        test_search_setup,
                                        test_search_teardown),
        cmocka_unit_test_setup_teardown(test_search_neg,
                                        test_search_setup,
                                        test_search_teardown),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
