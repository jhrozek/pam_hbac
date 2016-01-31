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

#ifndef __COMMON_MOCK_H__
#define __COMMON_MOCK_H__

#include "pam_hbac.h"
#include "pam_hbac_entry.h"
#include "pam_hbac_obj.h"
#include "pam_hbac_obj_int.h"

#define ph_mock_type(type) ((type) mock());
#define ph_mock_ptr_type(type) ((type) (uintptr_t) mock());

void
assert_string_list_matches(const char *list[],
                           const char *expected[]);

struct ph_attr *mock_ph_attr(const char *name, ...);
struct ph_user *mock_user_obj(const char *name, ...);
int mock_ph_host(struct ph_entry *host, const char *fqdn, ...);
int mock_ph_svc(struct ph_entry *host, const char *svcname);

int
mock_ph_rule(struct ph_entry *rule,
             const char *cn,
             const char *uuid,
             const char *ipa_enabled_flag,
             const char *member_user[], const char *member_user_groups[],
             const char *user_category,
             const char *member_service[], const char *member_service_groups[],
             const char *service_category,
             const char *member_host[], const char *member_host_groups[],
             const char *host_category,
             const char *external_host);

#endif /* __COMMON_MOCK_H__ */
