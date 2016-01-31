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
#include "common_mock.h"

void
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


