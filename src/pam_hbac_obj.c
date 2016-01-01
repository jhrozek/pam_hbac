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
#include <stdio.h>
#include <ctype.h>
#include <errno.h>
#include <sys/time.h>

#include "pam_hbac.h"
#include "pam_hbac_compat.h"
#include "pam_hbac_entry.h"
#include "pam_hbac_ldap.h"
#include "pam_hbac_obj.h"
#include "pam_hbac_obj_int.h"
#include "config.h"

struct ph_user *
ph_get_user(const char *username)
{
    return NULL;
}

void
ph_free_user(struct ph_user *user)
{
    if (user == NULL) {
        return;
    }
}

static const char *ph_host_attrs[] = { PAM_HBAC_ATTR_OC,
                                       "cn",
                                       "fqdn",
                                       "memberOf",
                                       NULL };

/* FIXME - do we need this complexity? */
static struct ph_search_ctx host_search_obj = {
    .sub_base = "cn=computers,cn=accounts",
    .oc = "ipaHost",
    .attrs = ph_host_attrs,
    .num_attrs = PH_MAP_HOST_END,
};

int ph_get_host(struct pam_hbac_ctx *ctx,
                const char *hostname,
                struct ph_entry **_host)
{
    size_t num;
    int ret;
    char *host_filter;
    struct ph_entry *host;
    struct ph_attr *fqdn;

    if (hostname == NULL) {
        return EINVAL;
    }

    /* FIXME - GNU extenstion!! */
    ret = asprintf(&host_filter, "%s=%s",
                   ph_host_attrs[PH_MAP_HOST_FQDN], hostname);
    if (ret < 0) {
        return ENOMEM;
    }

    ret = ph_search(ctx->ld, ctx->pc, &host_search_obj, host_filter, &host);
    free(host_filter);
    if (ret != 0) {
        return ret;
    }

    num = ph_num_entries(host);
    if (num == 0) {
        D(("No such host %s\n", hostname));
        ph_entry_array_free(host);
        return ENOENT;
    } else if (num > 1) {
        D(("Got more than one host entry\n"));
        ph_entry_array_free(host);
        return EINVAL;
    }

    /* check host validity */
    fqdn = ph_entry_get_attr_val(host, PH_MAP_HOST_FQDN);
    if (fqdn == NULL) {
        D(("Host %s has no FQDN attribute\n", hostname));
        ph_entry_array_free(host);
        return EINVAL;
    }

    if (fqdn->nvals != 1) {
        D(("Expected 1 host name, got %d\n", ldap_count_values_len(vals)));
        ph_entry_array_free(host);
        return EINVAL;
    }


    *_host = host;
    return 0;
}

void
ph_free_host(struct ph_entry *host)
{
    ph_entry_array_free(host);
}

int
ph_get_svc(struct pam_hbac_ctx *ctx,
           const char *svcname,
           struct ph_entry **_svc)
{
    return 0;
}

void
ph_free_svc(struct ph_entry *svc)
{
    ph_entry_array_free(svc);
}
