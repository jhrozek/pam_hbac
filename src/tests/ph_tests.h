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

#ifndef _PH_TESTS_H_
#define _PH_TESTS_H_

#define quit_if(expr, ...) do {         \
    fail_if(expr, ## __VA_ARGS__);      \
    if (expr) {                         \
        return;                         \
    }                                   \
} while(0)

#define fail_if_strneq(s1, s2, ...) do {                            \
    fail_if(strcmp(s1, s2) != 0, ## __VA_ARGS__);                   \
    if (strcmp(s1, s2) != 0) {                                      \
        fprintf(stderr, "String comparison failed\n");              \
        fprintf(stderr, #s1" is [%s], "#s2" is [%s]\n", s1, s2);    \
    }                                                               \
} while(0)                                                          \

#endif /* _PH_TESTS_H_ */
