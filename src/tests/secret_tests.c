
/*
    Copyright (C) 2016 Pavel Reichl  <preichl@redhat.com>

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

#include "pam_hbac.c"

#define BIND_PW     "Secret"

static void
test_destroy_secret(void **state)
{
    struct pam_hbac_ctx ctx;
    struct pam_hbac_config *conf;

    (void) state; /* unused */

    conf = calloc(1, sizeof(struct pam_hbac_config));
    conf->bind_pw = strdup(BIND_PW);

    memset(&ctx, 0, sizeof(ctx));
    ctx.pc = conf;

    ph_destroy_secret(&ctx);

    assert_null(conf->bind_pw);
    free(conf);

    ph_destroy_secret(NULL);
}

int
main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_destroy_secret),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
