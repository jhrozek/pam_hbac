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

static void
test_list_ops(void **state)
{
    char **list;

    list = calloc(2, sizeof(char *));
    assert_non_null(list);
    list[0] = strdup("foo");
    assert_non_null(list[0]);

    assert_int_equal(null_string_array_size(list), 1);
    free_string_list(list);

    free_string_list(NULL);
    assert_int_equal(null_string_array_size(NULL), 0);
}

static void
test_clist_ops(void **state)
{
    const char **list;

    list = calloc(2, sizeof(const char *));
    assert_non_null(list);
    list[0] = strdup("foo");
    assert_non_null(list[0]);

    assert_int_equal(null_cstring_array_size(list), 1);
    free_string_clist(list);

    free_string_clist(NULL);
    assert_int_equal(null_cstring_array_size(NULL), 0);
}

int
main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_list_ops),
        cmocka_unit_test(test_clist_ops),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
