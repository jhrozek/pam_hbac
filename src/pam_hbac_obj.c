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
    int ret;
    char *buffer;
    int bufsize;
    struct group grp;
    struct group *result = NULL;
    char *name;

    bufsize = sysconf(_SC_GETGR_R_SIZE_MAX);
    if (bufsize == -1) {
        bufsize = FALLBACK_GETGR_R_SIZE_MAX;
    }

    buffer = malloc(bufsize);
    if (buffer == NULL) {
        return NULL;
    }

    ret = getgrgid_r(gid, &grp, buffer, bufsize, &result);
    if (ret != 0 || result == NULL) {
        free(buffer);
        return NULL;
    }

    name = strdup(grp.gr_name);
    free(buffer);
    return name;
}

struct ph_user *
get_user_names(struct passwd *pwd,
               gid_t *gidlist,
               size_t ngroups)
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

    user->group_names = calloc(ngroups + 1, sizeof(char *));
    if (user->group_names == NULL) {
        ph_free_user(user);
        return NULL;
    }

    for (i = 0; i < ngroups; i++) {
        user->group_names[i] = getgroupname(gidlist[i]);
        if (user->group_names[i] == NULL) {
            ph_free_user(user);
            return NULL;
        }
    }

    return user;
}

struct ph_user *
get_user_int(const char *username, const size_t bufsize, const int maxgroups)
{
    char buffer[bufsize];
    gid_t gidlist[maxgroups];
    int ret;
    struct passwd pwd;
    struct passwd *result = NULL;
    int ngroups;

    ret = getpwnam_r(username, &pwd, buffer, bufsize, &result);
    if (ret != 0 || result == NULL) {
        return NULL;
    }

    ngroups = maxgroups;    /* don't modify input parameter */
    ret = getgrouplist(pwd.pw_name, pwd.pw_gid, gidlist, &ngroups);
    if (ret == -1) {
        /* FIXME - resize on platforms where we allocate fewer groups? */
        return NULL;
    }

    return get_user_names(&pwd, gidlist, ngroups);
}

struct ph_user *
ph_get_user(pam_handle_t *ph, const char *username)
{
    int bufsize;
    int maxgroups;
    struct ph_user *pu;

    bufsize = sysconf(_SC_GETPW_R_SIZE_MAX);
    if (bufsize == -1) {
        logger(ph, LOG_NOTICE,
               "Cannot get the value of _SC_GETPW_R_SIZE_MAX, "
               "using fallback\n");
        bufsize = FALLBACK_GETPW_R_SIZE_MAX;
    }

    maxgroups = sysconf(_SC_NGROUPS_MAX);
    if (maxgroups == -1) {
        logger(ph, LOG_NOTICE,
               "Cannot get the value of _SC_NGROUPS_MAX, "
               "using fallback\n");
        maxgroups = FALLBACK_NGROUPS_MAX;
        return NULL;
    }

    pu = get_user_int(username, bufsize, maxgroups);
    if (pu == NULL) {
        logger(ph, LOG_NOTICE, "Cannot find user %s\n", username);
        return NULL;
    }

    return pu;
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

int
ph_get_host(struct pam_hbac_ctx *ctx,
            const char *hostname,
            struct ph_entry **_host)
{
    size_t num;
    int ret;
    char *host_filter;
    struct ph_entry **hosts;
    struct ph_attr *fqdn;
    static const char *ph_host_attrs[] = { PAM_HBAC_ATTR_OC,
                                           "fqdn",
                                           "memberOf",
                                           NULL };

    static struct ph_search_ctx host_search_obj = {
        .sub_base = "cn=computers,cn=accounts",
        .oc = "ipaHost",
        .attrs = ph_host_attrs,
        .num_attrs = PH_MAP_HOST_END,
    };

    if (ctx == NULL || hostname == NULL) {
        return EINVAL;
    }

    ret = asprintf(&host_filter, "%s=%s",
                   ph_host_attrs[PH_MAP_HOST_FQDN], hostname);
    if (ret < 0) {
        return ENOMEM;
    }
    logger(ctx->pamh, LOG_DEBUG,
           "Searching for host %s using filter [%s]\n",
           hostname, host_filter);

    ret = ph_search(ctx->pamh, ctx->ld, ctx->pc,
                    &host_search_obj, host_filter, &hosts);
    free(host_filter);
    if (ret != 0) {
        return ret;
    }

    num = ph_num_entries(hosts);
    if (num == 0) {
        logger(ctx->pamh, LOG_WARNING, "No such host %s\n", hostname);
        ph_entry_array_free(hosts);
        return ENOENT;
    } else if (num > 1) {
        logger(ctx->pamh, LOG_ERR, "Got more than one host entry\n");
        ph_entry_array_free(hosts);
        return E2BIG;
    }

    /* check host validity */
    fqdn = ph_entry_get_attr(hosts[0], PH_MAP_HOST_FQDN);
    if (fqdn == NULL) {
        logger(ctx->pamh, LOG_ERR,
               "Host %s has no FQDN attribute\n", hostname);
        ph_entry_array_free(hosts);
        return EINVAL;
    }

    if (fqdn->nvals != 1) {
        logger(ctx->pamh, LOG_ERR,
               "Expected 1 host name, got %d\n", fqdn->nvals);
        ph_entry_array_free(hosts);
        return EINVAL;
    }

    logger(ctx->pamh, LOG_DEBUG,
           "Found host entry %s\n", fqdn->vals[0]->bv_val);
    *_host = hosts[0];
    ph_entry_array_shallow_free(hosts);
    return 0;
}

/* FIXME - shouldn't we just merge get_svc and get_hosts? */
int
ph_get_svc(struct pam_hbac_ctx *ctx,
           const char *svcname,
           struct ph_entry **_svc)
{
    size_t num;
    int ret;
    char *svc_filter;
    struct ph_entry **services;
    struct ph_attr *svc_cn;
    static const char *ph_svc_attrs[] = { PAM_HBAC_ATTR_OC,
                                          "cn",
                                          "memberOf",
                                          NULL };

    static struct ph_search_ctx svc_search_obj = {
        /* FIXME - this is copied in parsing DN as well, should we use
        * common definition?
        */
        .sub_base = "cn=hbacservices,cn=hbac",
        .oc = "ipaHbacService",
        .attrs = ph_svc_attrs,
        .num_attrs = PH_MAP_HOST_END,
    };

    if (ctx == NULL || svcname == NULL) {
        return EINVAL;
    }

    /* FIXME - GNU extenstion!! */
    ret = asprintf(&svc_filter, "%s=%s",
                   ph_svc_attrs[PH_MAP_SVC_NAME], svcname);
    if (ret < 0) {
        return ENOMEM;
    }
    logger(ctx->pamh, LOG_DEBUG,
           "Searching for service %s using filter [%s]\n",
           svcname, svc_filter);

    ret = ph_search(ctx->pamh, ctx->ld, ctx->pc,
                    &svc_search_obj, svc_filter, &services);
    free(svc_filter);
    if (ret != 0) {
        return ret;
    }

    num = ph_num_entries(services);
    if (num == 0) {
        logger(ctx->pamh, LOG_WARNING, "No such service %s\n", svcname);
        ph_entry_array_free(services);
        return ENOENT;
    } else if (num > 1) {
        logger(ctx->pamh, LOG_ERR, "Got more than one service entry\n");
        ph_entry_array_free(services);
        return E2BIG;
    }

    /* check service validity */
    svc_cn = ph_entry_get_attr(services[0], PH_MAP_SVC_NAME);
    if (svc_cn == NULL) {
        logger(ctx->pamh, LOG_WARNING,
               "Service %s has no name attribute\n", svcname);
        ph_entry_array_free(services);
        return EINVAL;
    }

    if (svc_cn->nvals != 1) {
        logger(ctx->pamh, LOG_ERR,
               "Expected 1 service name, got %d\n", svc_cn->nvals);
        ph_entry_array_free(services);
        return EINVAL;
    }

    logger(ctx->pamh, LOG_DEBUG,
           "Found service entry %s\n", svc_cn->vals[0]->bv_val);
    *_svc = services[0];
    ph_entry_array_shallow_free(services);
    return 0;
}
