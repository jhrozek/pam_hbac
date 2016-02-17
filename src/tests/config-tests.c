/*
    Copyright (C) 2012 Jakub Hrozek <jakub.hrozek@posteo.se>

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

#include "pam_hbac.h"
#include "tests/ph_tests.h"

static struct pam_hbac_config *
read_test_config(const char *filename)
{
    int ret = 0;
    struct pam_hbac_config *conf = NULL;

    ret = ph_read_config(NULL, filename, &conf);
    assert_int_equal(ret, 0);
    assert_non_null(conf);

    return conf;
}

static void
_print_config(struct pam_hbac_config *conf, const char *test)
{
    assert_non_null(conf);

    printf("In unit test [%s]\n", test);
    printf("uri -> [%s]\n", conf->uri);
    printf("base -> [%s]\n", conf->search_base);
}

#define print_config(conf) _print_config(conf, __FUNCTION__)

#define EXAMPLE_URI     "ldap://example.com"
#define EXAMPLE_BASE    "dc=example,dc=com"

#define check_example_result(c) do {                      \
    assert_string_equal(c->uri, EXAMPLE_URI);             \
    assert_string_equal(c->search_base, EXAMPLE_BASE);    \
} while(0);                                               \

/* ------------- the tests themselves ------------- */
void test_good_config(void **state)
{
    struct pam_hbac_config *conf;

    (void) state; /* unused */

    conf = read_test_config(TEST_CONF_DIR"/src/tests/good1.conf");
    print_config(conf);
    check_example_result(conf);
    ph_cleanup_config(conf);
}

void test_whitespace_around_equal_sign(void **state)
{
    struct pam_hbac_config *conf;

    (void) state; /* unused */

    conf = read_test_config(TEST_CONF_DIR"/src/tests/eqwsp.conf");
    print_config(conf);
    check_example_result(conf);
    ph_cleanup_config(conf);
}

void test_leading_whitespace(void **state)
{
    struct pam_hbac_config *conf;

    (void) state; /* unused */

    conf = read_test_config(TEST_CONF_DIR"/src/tests/lwsp.conf");
    print_config(conf);
    check_example_result(conf);
    ph_cleanup_config(conf);
}

void test_trailing_whitespace(void **state)
{
    struct pam_hbac_config *conf;

    (void) state; /* unused */

    conf = read_test_config(TEST_CONF_DIR"/src/tests/twsp.conf");
    print_config(conf);
    check_example_result(conf);
    ph_cleanup_config(conf);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_good_config),
        cmocka_unit_test(test_whitespace_around_equal_sign),
        cmocka_unit_test(test_leading_whitespace),
        cmocka_unit_test(test_trailing_whitespace),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
