/*
    Copyright (C) 2015 Jakub Hrozek <jakub.hrozek@posteo.se>

    Module structure based on pam_sss by Sumit Bose <sbose@redhat.com>

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
#include <stdint.h>
#include <sys/types.h>
#include <sys/time.h>

#include <security/pam_modules.h>

#include <ldap.h>

#include "pam_hbac.h"
#include "pam_hbac_compat.h"
#include "pam_hbac_obj.h"
#include "pam_hbac_ldap.h"
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

static int
parse_args(int argc, const char **argv)
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

    if (strcmp(pi->pam_user, "root") == 0) {
        D(("pam_hbac will not handle root."));
        return PAM_USER_UNKNOWN;
    }
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
    errno_t ret;
    struct pam_hbac_ctx *ctx;

    ctx = (struct pam_hbac_ctx *) calloc(1, sizeof(struct pam_hbac_ctx));
    if (ctx == NULL) {
        return NULL;
    }

    ret = ph_read_dfl_config(&ctx->pc);
    if (ret != 0) {
        D(("ph_read_dfl_config returned error: %s", strerror(ret)));
        free(ctx);
        return NULL;
    }
    D(("ph_read_dfl_config: OK"));

    return ctx;
}

static void
ph_cleanup(struct pam_hbac_ctx *ctx)
{
    ph_cleanup_config(ctx->pc);
    free(ctx);
}

/* FIXME - return more sensible return codes */
static int
pam_hbac(enum pam_hbac_actions action, pam_handle_t *pamh,
         int pam_flags, int argc, const char **argv)
{
    int ret;
    int pam_ret = PAM_SYSTEM_ERR;
    int args;
    struct pam_items pi;
    struct pam_hbac_ctx *ctx = NULL;

    struct ph_user *user = NULL;
    struct ph_entry *service = NULL;
    struct ph_entry *targethost = NULL;

    struct hbac_eval_req *eval_req = NULL;
    struct hbac_rule **rules = NULL;
    enum hbac_eval_result hbac_eval_result;
    struct hbac_info *info;

    (void) pam_flags; /* unused */

    /* Check supported actions */
    switch (action) {
        case PAM_HBAC_ACCOUNT:
            break;
        default:
            return PAM_SYSTEM_ERR;
    }

    D(("Hello pam_hbac: %s", action2str(action)));

    args = parse_args(argc, argv);

    ret = pam_hbac_get_items(pamh, &pi);
    if (ret != PAM_SUCCESS) {
        D(("pam_hbac_get_items returned error: %s", strerror(ret)));
        pam_ret = PAM_SYSTEM_ERR;
        goto done;
    }
    D(("pam_hbac_get_items: OK"));

    ctx = ph_init();
    if (!ctx) {
        D(("ph_init failed\n"));
        pam_ret = PAM_SYSTEM_ERR;
        goto done;
    }
    D(("ph_init: OK"));

    ret = ph_connect(ctx);
    if (ret != 0) {
        D(("ph_connect returned error: %s", strerror(ret)));
        pam_ret = PAM_AUTHINFO_UNAVAIL;
        goto done;
    }
    D(("ph_connect: OK"));

    print_pam_items(&pi, args);

    /* Run info on the user from NSS, otherwise we can't support AD users since
     * they are not in IPA LDAP.
     */
    user = ph_get_user(pi.pam_user);
    if (user == NULL) {
        pam_ret = PAM_USER_UNKNOWN;
        goto done;
    }

    /* Search hosts for fqdn = hostname. FIXME - Make the hostname configurable in the
     * future.
     */
    ret = ph_get_host(ctx, pi.pam_rhost, &targethost);
    if (ret != 0) {
        pam_ret = PAM_ABORT;
        goto done;
    }

    /* Search for the service */
    ret = ph_get_svc(ctx, pi.pam_service, &service);
    if (ret != 0) {
        pam_ret = PAM_ABORT;
        goto done;
    }

    /* Download all enabled rules that apply to this host or any of its hostgroups.
     * Iterate over the rules. For each rule:
     *  - Allocate hbac_rule
     *  - check its memberUser attributes. Parse either a username or a groupname
     *    from the DN. Put it into hbac_rule_element
     *  - check its memberService attribtue. Parse either a svcname or a svcgroupname
     *    from the DN. Put into hbac_rule_element
     *
     * Get data for eval request by matching the PAM service name with a downloaded
     * service. Not matching it is not an error, it can still match /all/.
     */

    ret = ph_create_hbac_eval_req(user, targethost, service, &eval_req);
    if (ret != 0) {
        D(("ph_create_eval_req returned error: %s", strerror(ret)));
        pam_ret = PAM_SYSTEM_ERR;
        goto done;
    }

    ret = ph_get_hbac_rules(ctx, targethost, &rules);
    if (ret != 0) {
        D(("ph_get_hbac_rules returned error: %s", strerror(ret)));
        pam_ret = PAM_SYSTEM_ERR;
        goto done;
    }

    hbac_eval_result = hbac_evaluate(rules, eval_req, &info);
    switch (hbac_eval_result) {
    case HBAC_EVAL_ALLOW:
        pam_ret = PAM_SUCCESS;
        break;
    case HBAC_EVAL_DENY:
        pam_ret = PAM_AUTH_ERR;
        break;
    case HBAC_EVAL_OOM:
        pam_ret = PAM_BUF_ERR;
        break;
    case HBAC_EVAL_ERROR:
    default:
        pam_ret = PAM_SYSTEM_ERR;
        break;
    }

done:
    ph_free_hbac_rules(rules);
    ph_free_hbac_eval_req(eval_req);
    ph_free_user(user);
    ph_free_svc(service);
    ph_free_host(targethost);
    ph_disconnect(ctx);
    ph_cleanup(ctx);
    return pam_ret;
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
