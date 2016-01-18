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

#include "pam_hbac_entry.h"
#include "common_mock.h"

static void test_ph_attr(void **state)
{
    struct ph_attr *a;
    char *name;
    struct berval *bv;
    struct berval **vals = NULL;

    (void) state; /* unused */

    name = ldap_strdup("key");
    assert_non_null(name);

    bv = ber_bvstrdup("value1");
    assert_non_null(bv);
    ber_bvecadd(&vals, bv);

    bv = ber_bvstrdup("value2");
    assert_non_null(bv);
    ber_bvecadd(&vals, bv);

    a = ph_attr_new(name, vals);
    assert_non_null(a);
    assert_string_equal(a->name, name);
    assert_int_equal(a->nvals, 2);
    assert_string_equal(a->vals[0]->bv_val, "value1");
    assert_string_equal(a->vals[1]->bv_val, "value2");

    ph_attr_free(a);

    a = ph_attr_new(NULL, NULL);
    assert_null(a);

    a = ph_attr_new(name, NULL);
    assert_null(a);
}

static void test_ph_entry(void **state)
{
    const size_t num_attrs = 3;
    struct ph_entry *entry = NULL;
    struct ph_attr *a, *aa;
    int ret;

    (void) state; /* unused */

    entry = ph_entry_alloc(num_attrs);
    assert_non_null(entry);

    assert_null(ph_entry_get_attr(entry, 0));
    assert_null(ph_entry_get_attr(entry, 666));

    a = mock_ph_attr("name", "foo", "bar", NULL);
    ret = ph_entry_set_attr(entry, a, 3);
    assert_int_not_equal(ret, 0);   /* off by one */

    ret = ph_entry_set_attr(entry, a, 0);
    assert_int_equal(ret, 0);   /* off by one */

    aa = ph_entry_get_attr(entry, 0);
    assert_non_null(aa);
    assert_non_null(aa->name);
    assert_string_equal(aa->name, "name");
    assert_int_equal(aa->nvals, 2);
    assert_string_equal(aa->vals[0]->bv_val, "foo");
    assert_string_equal(aa->vals[1]->bv_val, "bar");

    ph_entry_free(entry);
}

static void test_ph_entry_array(void **state)
{
    const size_t num_entries = 2;
    const size_t num_attrs = 3;
    struct ph_entry **entry_list = NULL;
    struct ph_entry *e1;
    struct ph_entry *e2;
    struct ph_attr *a, *aa;
    int ret;

    (void) state; /* unused */

    entry_list = ph_entry_array_alloc(num_attrs, num_entries);
    assert_non_null(entry_list);
    assert_non_null(entry_list[0]);
    assert_non_null(entry_list[1]);
    assert_null(entry_list[2]);

    assert_int_equal(ph_num_entries(NULL), 0);
    assert_int_equal(ph_num_entries(entry_list), 2);

    assert_null(ph_entry_get_attr(NULL, 0));
    assert_null(ph_entry_get_attr(entry_list[0], 0));
    assert_null(ph_entry_get_attr(entry_list[0], 666));

    a = mock_ph_attr("name", "foo", "bar", NULL);
    ret = ph_entry_set_attr(entry_list[0], a, 3);
    assert_int_not_equal(ret, 0);   /* off by one */

    ret = ph_entry_set_attr(entry_list[0], a, 0);
    assert_int_equal(ret, 0);   /* off by one */

    aa = ph_entry_get_attr(entry_list[0], 0);
    assert_non_null(aa);
    assert_non_null(aa->name);
    assert_string_equal(aa->name, "name");
    assert_int_equal(aa->nvals, 2);
    assert_string_equal(aa->vals[0]->bv_val, "foo");
    assert_string_equal(aa->vals[1]->bv_val, "bar");

    ph_entry_array_free(entry_list);

    entry_list = ph_entry_array_alloc(num_attrs, num_entries);
    assert_non_null(entry_list);
    assert_non_null(entry_list[0]);
    e1 = entry_list[0];
    assert_non_null(entry_list[1]);
    e2 = entry_list[1];
    assert_null(entry_list[2]);

    ph_entry_array_shallow_free(entry_list);
    ph_entry_free(e1);
    ph_entry_free(e2);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_ph_attr),
        cmocka_unit_test(test_ph_entry),
        cmocka_unit_test(test_ph_entry_array),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
