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
free_request_element(struct hbac_request_element *el)
{
    size_t i;

    if (el == NULL) {
        return;
    }

    if (el->groups != NULL) {
        for (i=0; el->groups[i]; i++) {
            free_const(el->groups[i]);
        }
    }

    free(el);
}

/* FIXME - split to utils? */
static size_t
null_string_array_size(char *arr[])
{
    size_t nelem;

    if (arr == NULL) {
        return 0;
    }

    for (nelem = 0; arr[nelem] != NULL; nelem++);

    return nelem;
}

static struct hbac_request_element *
new_sized_request_element(size_t ngroups)
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
    int ret;

    /* Name can only have one value */
    if (name->nvals != 1) {
        return NULL;
    }

    el = new_sized_request_element(memberof->nvals);
    if (el == NULL) {
        return NULL;
    }
    el->name = (const char *) name->vals[0]->bv_val;

    /* Iterate over all memberof attribute values and copy out the
     * groupname */
    gi = 0;
    for (i=0; i < memberof->nvals; i++) {
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
                free_request_element(el);
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

    el = new_sized_request_element(ngroups);
    if (el == NULL) {
        return NULL;
    }

    /* No need to copy objname */
    el->name = user->name;

    if (ngroups == 0) {
        return el;
    }

    /* Iterate over all memberof attribute values and copy out the
     * groupname */
    for (i=0; user->group_names[i]; i++) {
        el->groups[i] = user->group_names[i];
    }

    return el;
}

static struct hbac_request_element *
svc_to_eval_req_el(struct ph_entry *svc)
{
    struct ph_attr *svcname = NULL;
    struct ph_attr *hostgroups = NULL;

    return entry_to_eval_req_el(svcname, hostgroups, REQ_EL_SVC);
}

static struct hbac_request_element *
tgt_host_to_eval_req_el(struct ph_entry *host)
{
    struct ph_attr *fqdn;
    struct ph_attr *hostgroups;

    fqdn = ph_entry_get_attr(host, PH_MAP_HOST_FQDN);
    hostgroups = ph_entry_get_attr(host, PH_MAP_HOST_MEMBEROF);

    return entry_to_eval_req_el(fqdn, hostgroups, REQ_EL_HOST);
}

void
ph_free_eval_req(struct hbac_eval_req *req)
{
    if (req == NULL) {
        return;
    }

    free_request_element(req->user);
    free_request_element(req->service);
    free_request_element(req->targethost);
    free(req);
}

int ph_create_hbac_eval_req(struct ph_user *user,
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
    ph_free_eval_req(req);
    return ret;
}
