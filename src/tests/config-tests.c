/*
    Copyright (C) 2012 Jakub Hrozek <jakub.hrozek@gmail.com>

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
#include <check.h>
#include <stdio.h>

#include "pam_hbac.h"
#include "tests/ph_tests.h"

static struct pam_hbac_config *
read_test_config(const char *filename)
{
    int ret = 0;
    struct pam_hbac_config *conf = NULL;

    ret = ph_read_config(filename, &conf);
    fail_if(conf == NULL, "Could not read the config file [%d]: %s\n",
            ret, strerror(ret));

    return conf;
}

static void
_print_config(struct pam_hbac_config *conf, const char *test)
{
    printf("In unit test [%s]\n", test);
    printf("uri -> [%s]\n", conf->uri);
    printf("base -> [%s]\n", conf->search_base);
}

#define print_config(conf) _print_config(conf, __FUNCTION__)

#define EXAMPLE_URI     "ldap://example.com"
#define EXAMPLE_BASE    "dc=example,dc=com"

#define CHECK_EXAMPLE_RESULT(c) do {                 \
    fail_if_strneq(c->uri, EXAMPLE_URI);             \
    fail_if_strneq(c->search_base, EXAMPLE_BASE);    \
} while(0);                                          \

/* ------------- the tests themselves ------------- */
START_TEST(test_good_config)
{
    struct pam_hbac_config *conf;

    conf = read_test_config("src/tests/good1.conf");
    quit_if(conf == NULL, "Could not read the config file\n");
    print_config(conf);
    CHECK_EXAMPLE_RESULT(conf);
    ph_cleanup_config(conf);
}
END_TEST

START_TEST(test_whitespace_around_equal_sign)
{
    struct pam_hbac_config *conf;

    conf = read_test_config("src/tests/eqwsp.conf");
    quit_if(conf == NULL, "Could not read the config file\n");
    print_config(conf);
    CHECK_EXAMPLE_RESULT(conf);
    ph_cleanup_config(conf);
}
END_TEST

START_TEST(test_leading_whitespace)
{
    struct pam_hbac_config *conf;

    conf = read_test_config("src/tests/lwsp.conf");
    quit_if(conf == NULL, "Could not read the config file\n");
    print_config(conf);
    CHECK_EXAMPLE_RESULT(conf);
    ph_cleanup_config(conf);
}
END_TEST

START_TEST(test_trailing_whitespace)
{
    struct pam_hbac_config *conf;

    conf = read_test_config("src/tests/twsp.conf");
    quit_if(conf == NULL, "Could not read the config file\n");
    print_config(conf);
    CHECK_EXAMPLE_RESULT(conf);
    ph_cleanup_config(conf);
}
END_TEST

Suite *config_suite(void)
{
    Suite *s;
    TCase *tc_config_suite;
    
    s = suite_create("config_suite");
    tc_config_suite = tcase_create("basic_config");

    tcase_add_test(tc_config_suite, test_good_config);
    tcase_add_test(tc_config_suite, test_whitespace_around_equal_sign);
    tcase_add_test(tc_config_suite, test_leading_whitespace);
    tcase_add_test(tc_config_suite, test_trailing_whitespace);
    suite_add_tcase(s, tc_config_suite);

    return s;
}

int main(void)
{
    int number_failed;

    Suite *s = config_suite();
    SRunner *sr = srunner_create(s);
    /* If CK_VERBOSITY is set, use that, otherwise it defaults to CK_NORMAL */
    srunner_run_all(sr, CK_ENV);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
