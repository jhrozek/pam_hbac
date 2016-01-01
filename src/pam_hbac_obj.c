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
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#include <unistd.h>
#include <uuid/uuid.h>

#include "pam_hbac.h"
#include "pam_hbac_compat.h"
#include "pam_hbac_entry.h"
#include "pam_hbac_ldap.h"
#include "pam_hbac_obj.h"
#include "pam_hbac_obj_int.h"
#include "config.h"

static char *
getgroupname(gid_t gid)
{
    int bufsize;
    struct group grp;
    struct group *result = NULL;

    bufsize = sysconf(_SC_GETGR_R_SIZE_MAX);
    if (bufsize == -1) {
        return NULL;
    }

    int ret;
    char buffer[bufsize];

    ret = getgrgid_r(gid, &grp, buffer, bufsize, &result);
    if (ret != 0 || result == NULL) {
        return NULL;
    }

    return strdup(grp.gr_name);
}

struct ph_user *
get_user_names(struct passwd *pwd,
               int *gidlist,
               size_t maxgroups)
{
    struct ph_user *user;
    size_t i;

    user = malloc(sizeof(struct ph_user));
    if (user == NULL) {
        return NULL;
    }

    user->name = strdup(pwd->pw_name);
    if (user->name == NULL) {
        free(user);
        return NULL;
    }

    user->group_names = calloc(maxgroups + 1, sizeof(char *));
    if (user->group_names == NULL) {
        ph_free_user(user);
        return NULL;
    }

    for (i = 0; i < maxgroups; i++) {
        user->group_names[i] = getgroupname(gidlist[i]);
        if (user->group_names[i] == NULL) {
            ph_free_user(user);
            return NULL;
        }
    }

    return user;
}

struct ph_user *
ph_get_user(const char *username)
{
    int bufsize;
    int maxgroups;

    bufsize = sysconf(_SC_GETPW_R_SIZE_MAX);
    if (bufsize == -1) {
        return NULL;
    }

    maxgroups = sysconf(_SC_NGROUPS_MAX);
    if (maxgroups == -1) {
        return NULL;
    }

    int ret;
    char buffer[bufsize];
    int gidlist[maxgroups];
    struct passwd pwd;
    struct passwd *result = NULL;

    ret = getpwnam_r(username, &pwd, buffer, bufsize, &result);
    if (ret != 0 || result == NULL) {
        return NULL;
    }

    ret = getgrouplist(pwd.pw_name, pwd.pw_gid, gidlist, &maxgroups);
    if (ret != 0) {
        return NULL;
    }

    return get_user_names(&pwd, gidlist, maxgroups);
}

void
ph_free_user(struct ph_user *user)
{
    if (user == NULL) {
        return;
    }

    free_string_list(user->group_names);
    free(user->name);
    free(user);
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
