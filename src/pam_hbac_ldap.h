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

#ifndef __PAM_HBAC_LDAP_H__
#define __PAM_HBAC_LDAP_H__

#include <ldap.h>

#include "pam_hbac.h"
#include "pam_hbac_entry.h"

struct ph_search_ctx {
    const char *sub_base;
    const char **attrs;
    const char *oc;
    size_t num_attrs;
};

int ph_search(LDAP *ld,
              struct pam_hbac_config *conf,
              struct ph_search_ctx *s,
              const char *obj_filter,
              struct ph_entry ***_entry_list);

int ph_connect(struct pam_hbac_ctx *ctx);

void ph_disconnect(struct pam_hbac_ctx *ctx);

#endif /* __PAM_HBAC_LDAP_H__ */

