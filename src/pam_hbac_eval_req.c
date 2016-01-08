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

#define _GNU_SOURCE

#include <stdlib.h>
#include <ctype.h>
#include <errno.h>

#include "config.h"

#include "pam_hbac.h"
#include "pam_hbac_entry.h"
#include "pam_hbac_dnparse.h"
#include "pam_hbac_obj_int.h"

#include "libhbac/ipa_hbac.h"

static void
free_request_element(struct hbac_request_element *el,
                     bool free_group_ptrs)
{
    size_t i;

    if (el == NULL) {
        return;
    }

    if (el->groups != NULL && free_group_ptrs) {
        for (i=0; el->groups[i]; i++) {
            free_const(el->groups[i]);
        }
    }

    free(el->groups);
    free(el);
}

static struct hbac_request_element *
alloc_sized_request_element(size_t ngroups)
{
    struct hbac_request_element *el;

    el = malloc(sizeof(struct hbac_request_element));
    if (el == NULL) {
        return NULL;
    }

    /* Add sentinel. This also handles objects with no memberships */
    el->groups = calloc(ngroups + 1, sizeof(const char *));
    if (el->groups == NULL) {
        free(el);
        return NULL;
    }

    return el;
}

static struct hbac_request_element *
entry_to_eval_req_el(struct ph_attr *name,
                     struct ph_attr *memberof,
                     enum member_el_type el_type)
{
    struct hbac_request_element *el;
    size_t i, gi;
    size_t n_memberof = 0;
    int ret;

    /* Name can only have one value */
    if (name->nvals != 1) {
        return NULL;
    }

    if (memberof != NULL) {
        n_memberof = memberof->nvals;
    }

    el = alloc_sized_request_element(n_memberof);
    if (el == NULL) {
        return NULL;
    }
    el->name = (const char *) name->vals[0]->bv_val;

    /* Iterate over all memberof attribute values and copy out the
     * groupname */
    gi = 0;
    for (i=0; i < n_memberof; i++) {
        ret = group_name_from_dn((const char *) memberof->vals[i]->bv_val,
                                 el_type,
                                 &el->groups[gi]);
        switch (ret) {
            case 0:
                break;
            /* Unexpected DN, skip these.. */
            case ERANGE:
            case EINVAL:
                continue;
            default:
                /* ENOMEMs and such */
                free_request_element(el, true);
                return NULL;
        }

        gi++;
    }

    return el;
}

static struct hbac_request_element *
user_to_eval_req_el(struct ph_user *user)
{
    struct hbac_request_element *el;
    size_t ngroups;
    size_t i;

    ngroups = null_string_array_size(user->group_names);

    el = alloc_sized_request_element(ngroups);
    if (el == NULL) {
        return NULL;
    }

    /* No need to copy username */
    el->name = user->name;

    for (i=0; user->group_names[i]; i++) {
        el->groups[i] = user->group_names[i];
    }

    return el;
}

static struct hbac_request_element *
svc_to_eval_req_el(struct ph_entry *svc)
{
    struct ph_attr *svcname;
    struct ph_attr *svcgroups;

    svcname = ph_entry_get_attr(svc, PH_MAP_SVC_NAME);
    svcgroups = ph_entry_get_attr(svc, PH_MAP_SVC_MEMBEROF);

    return entry_to_eval_req_el(svcname, svcgroups, DN_TYPE_SVC);
}

static struct hbac_request_element *
tgt_host_to_eval_req_el(struct ph_entry *host)
{
    struct ph_attr *fqdn;
    struct ph_attr *hostgroups;

    fqdn = ph_entry_get_attr(host, PH_MAP_HOST_FQDN);
    hostgroups = ph_entry_get_attr(host, PH_MAP_HOST_MEMBEROF);

    return entry_to_eval_req_el(fqdn, hostgroups, DN_TYPE_HOST);
}

void
ph_free_hbac_eval_req(struct hbac_eval_req *req)
{
    if (req == NULL) {
        return;
    }

    free_request_element(req->user, false);
    free_request_element(req->service, true);
    free_request_element(req->targethost, true);
    free(req);
}

int
ph_create_hbac_eval_req(struct ph_user *user,
                        struct ph_entry *targethost,
                        struct ph_entry *service,
                        struct hbac_eval_req **_req)
{
    int ret;
    struct hbac_eval_req *req;

    if (user == NULL || targethost == NULL || service == NULL
            || _req == NULL) {
        return EINVAL;
    }

    req = calloc(1, sizeof(struct hbac_eval_req));
    if (req == NULL) {
        return ENOMEM;
    }

    req->user = user_to_eval_req_el(user);
    if (req->user == NULL) {
        ret = ENOMEM;
        goto fail;
    }

    req->service = svc_to_eval_req_el(service);
    if (req->service == NULL) {
        ret = ENOMEM;
        goto fail;
    }

    req->targethost = tgt_host_to_eval_req_el(targethost);
    if (req->targethost == NULL) {
        ret = ENOMEM;
        goto fail;
    }

    req->request_time = time(NULL);

    *_req = req;
    return 0;

fail:
    ph_free_hbac_eval_req(req);
    return ret;
}
