/*
    Copyright (C) 2012 Jakub Hrozek <jakub.hrozek@gmail.com>

    Based on pam_sss by Sumit Bose <sbose@redhat.com>

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


#include <syslog.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include <security/_pam_macros.h>
#include <security/pam_ext.h>
#include <security/pam_modules.h>

#include <ldap.h>

#include "pam_hbac.h"
#include "config.h"

#define CHECK_AND_RETURN_PI_STRING(s) ((s != NULL && *s != '\0')? s : "(not available)")

#define PAM_DEBUG_ARG       0x0001

enum pam_hbac_actions {
    PAM_HBAC_ACCOUNT,
    PAM_HBAC_SENTINEL   /* SENTINEL */
};

struct pam_items {
    const char *pam_service;
    const char *pam_user;
    const char *pam_tty;
    const char *pam_ruser;
    const char *pam_rhost;

    size_t pam_service_size;
    size_t pam_user_size;
    size_t pam_tty_size;
    size_t pam_ruser_size;
    size_t pam_rhost_size;
};

static const char *
action2str(enum pam_hbac_actions action)
{
    switch(action) {
        case PAM_HBAC_ACCOUNT:
            return "Account";
        case PAM_HBAC_SENTINEL:
            return "Sentinel - this should never happen!";
    }

    return "unknown";
}

static int
parse_args(const pam_handle_t *pamh, int argc, const char **argv)
{
    int ctrl = 0;

    /* step through arguments */
    for (; argc-- > 0; ++argv) {
        /* generic options */
        if (0 == strcmp(*argv, "debug")) {
            ctrl |= PAM_DEBUG_ARG;
            D(("pam_debug found"));
        } else {
            pam_syslog(pamh, LOG_ERR, "unknown option: %s", *argv);
            D(("unknown option %s\n", *argv));
        }
    }

    return ctrl;
}


static int
pam_hbac_get_items(pam_handle_t *pamh, struct pam_items *pi)
{
    int ret;

    ret = pam_get_item(pamh, PAM_SERVICE, (const void **) &(pi->pam_service));
    if (ret != PAM_SUCCESS) return ret;
    if (pi->pam_service == NULL) pi->pam_service="";
    pi->pam_service_size = strlen(pi->pam_service) + 1;

    ret = pam_get_item(pamh, PAM_USER, (const void **) &(pi->pam_user));
    if (ret != PAM_SUCCESS) return ret;
    if (pi->pam_user == NULL) {
        D(("No user found, aborting."));
        return PAM_BAD_ITEM;
    }
    /*
    if (strcmp(pi->pam_user, "root") == 0) {
        D(("pam_hbac will not handle root."));
        return PAM_USER_UNKNOWN;
    }
    */
    pi->pam_user_size = strlen(pi->pam_user) + 1;

    ret = pam_get_item(pamh, PAM_TTY, (const void **) &(pi->pam_tty));
    if (ret != PAM_SUCCESS) return ret;
    if (pi->pam_tty == NULL) pi->pam_tty="";
    pi->pam_tty_size = strlen(pi->pam_tty) + 1;

    ret = pam_get_item(pamh, PAM_RUSER, (const void **) &(pi->pam_ruser));
    if (ret != PAM_SUCCESS) return ret;
    if (pi->pam_ruser == NULL) pi->pam_ruser="";
    pi->pam_ruser_size = strlen(pi->pam_ruser) + 1;

    ret = pam_get_item(pamh, PAM_RHOST, (const void **) &(pi->pam_rhost));
    if (ret != PAM_SUCCESS) return ret;
    if (pi->pam_rhost == NULL) pi->pam_rhost="";
    pi->pam_rhost_size = strlen(pi->pam_rhost) + 1;

    return PAM_SUCCESS;
}

static void
print_pam_items(struct pam_items *pi, int args)
{
    if (!(args & PAM_DEBUG_ARG)) return;
    if (pi == NULL) return;

    D(("Service: %s", CHECK_AND_RETURN_PI_STRING(pi->pam_service)));
    D(("User: %s", CHECK_AND_RETURN_PI_STRING(pi->pam_user)));
    D(("Tty: %s", CHECK_AND_RETURN_PI_STRING(pi->pam_tty)));
    D(("Ruser: %s", CHECK_AND_RETURN_PI_STRING(pi->pam_ruser)));
    D(("Rhost: %s", CHECK_AND_RETURN_PI_STRING(pi->pam_rhost)));
}

static struct pam_hbac_ctx *
ph_init(void)
{
    return calloc(1, sizeof(struct pam_hbac_ctx));
}

static LDAP *
ph_connect(struct pam_hbac_config *pc)
{
    int ret;
    LDAP *ld;

    /* FIXME - detect with configure? */
    ret = ldap_initialize(&ld, pc->uri);
    if (ret != LDAP_SUCCESS) {
        D(("ldap_initialize failed [%d]: %s\n", ret, ldap_err2string(ret)));
        return NULL;
    }

    return ld;
}

static void
ph_cleanup(struct pam_hbac_ctx *ctx)
{
    ph_cleanup_config(ctx->pc);
}

static int
pam_hbac(enum pam_hbac_actions action, pam_handle_t *pamh,
         int pam_flags, int argc, const char **argv)
{
    int ret;
    int args;
    struct pam_items pi;
    struct pam_hbac_ctx *ctx;

    /* Check supported actions */
    switch (action) {
        case PAM_HBAC_ACCOUNT:
            break;
        default:
            return PAM_SYSTEM_ERR;
    }

    D(("Hello pam_hbac: %s", action2str(action)));

    args = parse_args(pamh, argc, argv);

    ret = pam_hbac_get_items(pamh, &pi);
    if (ret != PAM_SUCCESS) {
        D(("pam_hbac_get_items returned error: %s", pam_strerror(pamh,ret)));
        goto fail;
    }
    D(("pam_hbac_get_items: OK"));

    ctx = ph_init();
    if (!ctx) {
        D(("ph_init failed\n"));
        goto fail;
    }

    ret = ph_read_dfl_config(&ctx->pc);
    if (ret != 0) {
        D(("ph_read_dfl_config returned error: %s", pam_strerror(pamh,ret)));
        goto fail;
    }
    D(("ph_read_dfl_config: OK"));

    ctx->ld = ph_connect(ctx->pc);
    if (ctx->ld == NULL) {
        D(("ph_read_dfl_config returned error: %s", pam_strerror(pamh,ret)));
        goto fail;
    }

    print_pam_items(&pi, args);
    ret = PAM_SUCCESS;

fail:
    ph_cleanup(ctx);
    return PAM_SYSTEM_ERR;
}

/* --- public account management functions --- */

PAM_EXTERN int
pam_sm_acct_mgmt(pam_handle_t *pamh, int flags,
                 int argc, const char **argv)
{
    return pam_hbac(PAM_HBAC_ACCOUNT, pamh, flags, argc, argv);
}

/* static module data */
#ifdef PAM_STATIC

struct pam_module _pam_hbac_modstruct = {
    "pam_hbac",
    NULL,
    NULL,
    pam_sm_acct_mgmt,
    NULL,
    NULL,
    NULL
};

#endif
