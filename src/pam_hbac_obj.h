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

#ifndef __PAM_HBAC_OBJ_H__
#define __PAM_HBAC_OBJ_H__

#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>

#include "pam_hbac.h"

struct ph_user;

struct ph_user *
ph_get_user(pam_handle_t *ph, const char *username);
void ph_free_user(struct ph_user *user);

struct ph_entry;

int ph_get_host(struct pam_hbac_ctx *ctx,
                const char *hostname,
                struct ph_entry **_host);

int ph_get_svc(struct pam_hbac_ctx *ctx,
               const char *svcname,
               struct ph_entry **_svc);

/* pam_hbac_eval_req.c */

int ph_create_hbac_eval_req(struct ph_user *user,
                            struct ph_entry *targethost,
                            struct ph_entry *service,
                            struct hbac_eval_req **_req);
void ph_free_hbac_eval_req(struct hbac_eval_req *req);

/* pam_hbac_rules.c */
int ph_get_hbac_rules(struct pam_hbac_ctx *ctx,
                      struct ph_entry *targethost,
                      struct hbac_rule ***_rules);
void ph_free_hbac_rules(struct hbac_rule **rules);

#endif /* __PAM_HBAC_OBJ_H__ */

