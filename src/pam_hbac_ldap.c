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

#define _GNU_SOURCE

#include <stdio.h>
#include <sys/time.h>

#include "pam_hbac_compat.h"
#include "pam_hbac_ldap.h"

static int
internal_search(pam_handle_t *pamh,
                LDAP *ld,
                int timeout,
                const char *search_base,
                const char * const attrs[],
                const char *filter,
                LDAPMessage **_msg)
{
    int ret;
    LDAPMessage *msg;

    logger(pamh, LOG_DEBUG,
           "Searching LDAP using filter [%s] base [%s] timeout [%d]\n",
           filter, search_base, timeout);

    /* Explicitly don't specify timeout. The admin can set TIMELIMIT in
     * ldap.conf instead */
    ret = ldap_search_ext_s(ld, search_base, LDAP_SCOPE_SUBTREE, filter,
                            discard_const(attrs),
                            0, NULL, NULL, NULL, 0, &msg);
    if (ret == LDAP_NO_SUCH_OBJECT) {
        logger(pamh, LOG_NOTICE, "No such object\n");
        msg = NULL;
    } else if (ret != LDAP_SUCCESS) {
        logger(pamh, LOG_ERR,
               "ldap_search_ext_s failed [%d]: %s\n",
               ret, ldap_err2string(ret));
        ret = EIO;
        goto done;
    }

    ret = 0;
    *_msg = msg;
done:
    return ret;
}

static bool
entry_has_oc(pam_handle_t *pamh, LDAP *ld, LDAPMessage *entry, const char *oc)
{
    size_t i;
    struct berval **vals;
    bool ret;

    vals = ldap_get_values_len(ld, entry, PAM_HBAC_ATTR_OC);
    if (vals == NULL) {
        logger(pamh, LOG_ERR, "No objectclass? Corrupt entry\n");
        return false;
    }

    for (i = 0; vals[i] != NULL; i++) {
        if (strcasecmp(vals[i]->bv_val, oc) == 0) {
            break;
        }
    }

    if (vals[i] == NULL) {
        logger(pamh, LOG_NOTICE, "Could not find objectclass %s\n", oc);
        ret = false;
    } else {
        ret = true;
    }

    ldap_value_free_len(vals);
    return ret;
}

static int
want_attrname(const char *attr, struct ph_search_ctx *obj)
{
    size_t i;

    for (i = 0; i < obj->num_attrs; i++) {
        if (strcasecmp(obj->attrs[i], attr) == 0) {
            return i;
        }
    }

    return -1;
}

static int
parse_entry(pam_handle_t *pamh,
            LDAP *ld,
            LDAPMessage *entry,
            struct ph_search_ctx *obj,
            struct ph_entry *pentry)
{
    BerElement *ber = NULL;
    char *a;
    struct berval **vals;
    struct ph_attr *attr;
    int idx;
    int ret;
    char *dn;
    size_t num_attrs;

    dn = ldap_get_dn(ld, entry);
    logger(pamh, LOG_DEBUG, "received DN: %s\n", dn);

    /* check objectclass first */
    if (entry_has_oc(pamh, ld, entry, obj->oc) == false) {
        return ENOENT;
    }

    /* Process the rest of the attributes */
    num_attrs = 0;
    for (a = ldap_first_attribute(ld, entry, &ber);
         a != NULL;
         a = ldap_next_attribute(ld, entry, ber)) {

        idx = want_attrname(a, obj);
        if (idx == -1) {
            ldap_memfree(a);
            continue;
        }

        logger(pamh, LOG_DEBUG, "Received attribute %s\n", a);
        vals = ldap_get_values_len(ld, entry, a);
        attr = ph_attr_new(a, vals);
        if (attr == NULL) {
            ldap_memfree(a);
            ldap_value_free_len(vals);
            return ENOMEM;
        }
        /* attr owns vals and a now */

        ret = ph_entry_set_attr(pentry, attr, idx);
        if (ret) {
            ph_attr_free(attr);
            return ret;
        }
        num_attrs++;
    }

    logger(pamh, LOG_DEBUG, "Total attributes %d\n", num_attrs);

    /* FIXME - should we iterate here over unset attrs and set them
     * to an empty value?
     */

    if (ber != NULL) {
        ber_free(ber, 0);
    }

    return 0;
}

static int
parse_ldap_msg(pam_handle_t *pamh,
               LDAP *ld,
               LDAPMessage *msg,
               struct ph_search_ctx *s,
               size_t num_entries,
               struct ph_entry **entries)
{
    LDAPMessage *ent;
    int ent_type;
    int ret;
    size_t entry_idx = 0;

    if (msg == NULL) {
        /* Return empty array and let the caller iterate over it */
        return 0;
    }

    /* Iterate through the results. */
    for (ent = ldap_first_message(ld, msg);
         ent != NULL;
         ent = ldap_next_message(ld, ent)) {
        /* Determine what type of message was sent from the server. */
        ent_type = ldap_msgtype(ent);
        switch (ent_type) {
            /* FIXME - break into a function? */
            case LDAP_RES_SEARCH_ENTRY:
                if (entry_idx >= num_entries) {
                    /* Be defensive.. */
                    return E2BIG;
                }

                /* The result is an entry. */
                ret = parse_entry(pamh, ld, ent, s, entries[entry_idx]);
                if (ret != 0) {
                    /* This is safe b/c we don't support deny fules */
                    continue;
                }
                entry_idx++;
                break;
            case LDAP_RES_SEARCH_REFERENCE:
                logger(pamh, LOG_NOTICE, "No support for referrals..");
                break;
            case LDAP_RES_SEARCH_RESULT:
                /* The result is the final result sent by the server. */
                break;
            default:
                logger(pamh, LOG_NOTICE,
                       "Unexpected message type %d, ignoring\n", ent_type);
                break;
        }
    }

    return 0;
}

static int
parse_message(pam_handle_t *pamh,
              LDAP *ld,
              LDAPMessage *msg,
              struct ph_search_ctx *s,
              struct ph_entry ***_entries)
{
    struct ph_entry **entries = NULL;
    size_t num_entries;
    int ret;

    num_entries = ldap_count_entries(ld, msg);
    logger(pamh, LOG_DEBUG, "Found %d entries\n", num_entries);

    entries = ph_entry_array_alloc(s->num_attrs, num_entries);
    if (entries == NULL) {
        return ENOMEM;
    }

    ret = parse_ldap_msg(pamh, ld, msg, s, num_entries, entries);
    if (ret != 0) {
        ph_entry_array_free(entries);
        return ret;
    }

    *_entries = entries;
    return 0;
}

static char *
compose_search_filter(struct ph_search_ctx *s,
                      const char *obj_filter)
{
    int ret;
    char *oc_filter = NULL;
    char *filter = NULL;

    ret = asprintf(&oc_filter, "(objectclass=%s)", s->oc);
    if (ret < 0) {
        return NULL;
    }

    if (obj_filter != NULL) {
        ret = asprintf(&filter, "(&%s(%s))", oc_filter, obj_filter);
        free(oc_filter);
        if (ret < 0) {
            return NULL;
        }
    } else {
        filter = oc_filter;
    }

    return filter;
}

int
ph_search(pam_handle_t *pamh,
          LDAP *ld,
          struct pam_hbac_config *conf,
          struct ph_search_ctx *s,
          const char *obj_filter,
          struct ph_entry ***_entry_list)
{
    LDAPMessage *msg = NULL;
    char *search_base = NULL;
    char *filter = NULL;
    int ret;
    struct ph_entry **entry_list;

    if (ld == NULL || conf == NULL || s == NULL) {
        logger(pamh, LOG_ERR, "Invalid parameters\n");
        return EINVAL;
    }

    ret = asprintf(&search_base, "%s,%s", s->sub_base, conf->search_base);
    if (ret < 0) {
        logger(pamh, LOG_CRIT, "Cannot create filter\n");
        ret = ENOMEM;
        goto done;
    }

    filter = compose_search_filter(s, obj_filter);
    if (filter == NULL) {
        logger(pamh, LOG_CRIT, "Cannot compose filter\n");
        ret = ENOMEM;
        goto done;
    }

    ret = internal_search(pamh, ld, conf->timeout, search_base, s->attrs,
                          filter, &msg);
    if (ret != 0) {
        logger(pamh, LOG_ERR,
               "Search returned [%d]: %s\n", ret, strerror(ret));
        goto done;
    }

    ret = parse_message(pamh, ld, msg, s, &entry_list);
    if (ret != 0) {
        logger(pamh, LOG_ERR,
               "Message parsing failed [%d]: %s\n", ret, strerror(ret));
        goto done;
    }

    *_entry_list = entry_list;
    ret = 0;
done:
    free(search_base);
    free(filter);
    return ret;
}

#ifdef HAVE_LDAP_START_TLS
static int
start_tls(pam_handle_t *ph, LDAP *ldap, const char *ca_cert, bool secure)
{
    int lret;
    int msgid;
    int optret;
    char *errmsg = NULL;
    char *diag_msg = NULL;
    int ldaperr;
    LDAPMessage *result = NULL;

    if (secure == false) {
        return LDAP_SUCCESS;
    }

    if (ca_cert != NULL) {
        lret = ldap_set_option(NULL, LDAP_OPT_X_TLS_CACERTFILE, ca_cert);
        if (lret != LDAP_SUCCESS) {
            logger(ph, LOG_ERR, "Cannot set ca cert: %d\n");
            return lret;
        }

        logger(ph, LOG_DEBUG, "CA cert set to: %s\n", ca_cert);
    }

    lret = ldap_start_tls(ldap, NULL, NULL, &msgid);
    if (lret != LDAP_SUCCESS) {
        optret = ldap_get_option(ldap, PH_DIAGNOSTIC_MESSAGE, (void*)&errmsg);
        if (optret != LDAP_SUCCESS) {
            logger(ph, LOG_ERR,
                   "Cannot start TLS [%d]: %s\n",
                   lret, ldap_err2string(lret));
        } else {
            logger(ph, LOG_ERR,
                   "Cannot start TLS [%d]: %s diagnostic message: %s\n",
                   lret, ldap_err2string(lret), errmsg);
            ldap_memfree(errmsg);
        }
        goto done;
    }

    lret = ldap_result(ldap, msgid, 1, NULL, &result);
    if (lret != LDAP_RES_EXTENDED) {
        logger(ph, LOG_ERR,
              "Unexpected ldap_result, expected [%lu] got [%d].\n",
               LDAP_RES_EXTENDED, lret);
        lret = LDAP_PARAM_ERROR;
        goto done;
    }

    lret = ldap_parse_result(ldap, result, &ldaperr, NULL,
                             &errmsg, NULL, NULL, 0);
    if (lret != LDAP_SUCCESS) {
        logger(ph, LOG_ERR,
              "ldap_parse_result failed (%d) [%d][%s]\n", msgid, lret,
              ldap_err2string(lret));
        goto done;
    }

    logger(ph, LOG_DEBUG,
           "START TLS result: %s(%d), %s\n",
           ldap_err2string(ldaperr), ldaperr, errmsg);

    if (ldap_tls_inplace(ldap)) {
        logger(ph, LOG_DEBUG, "SSL/TLS handler already in place.\n");
        lret = LDAP_SUCCESS;
        goto done;
    }

    lret = ldap_install_tls(ldap);
    if (lret != LDAP_SUCCESS) {
        optret = ldap_get_option(ldap, PH_DIAGNOSTIC_MESSAGE, (void*)&diag_msg);
        if (optret == LDAP_SUCCESS) {
            logger(ph, LOG_ERR,
                   "ldap_install_tls failed: [%s] [%s]\n",
                   ldap_err2string(lret), diag_msg);
        } else {
            logger(ph, LOG_ERR, "ldap_install_tls failed: [%s]\n",
                   ldap_err2string(lret));
        }

        goto done;
    }

    lret = LDAP_SUCCESS;
done:
    if (result) {
        ldap_msgfree(result);
    }

    if (errmsg) {
        ldap_memfree(errmsg);
    }

    if (diag_msg) {
        ldap_memfree(diag_msg);
    }
    return lret;
}
#endif

static int secure_preinit(pam_handle_t *ph,
                          const char *ssl_path,
                          bool secure)
{
#ifdef HAVE_LDAPSSL_CLIENT_INIT
    int ret;

    if (secure == false) {
        return LDAP_SUCCESS;
    }

    /* http://www-archive.mozilla.org/directory/csdk-docs/ssl.htm says:
     * """
     *      Note that you need to initialize your client before initializing
     *      the LDAP session. The process of initializing the client opens the
     *      certificate database.
     * """
     */
    ret = ldapssl_client_init(ssl_path, NULL);
    if (ret != LDAP_SUCCESS) {
        logger(ph, LOG_ERR, "ldapssl_client_init failed: [%s]\n",
               ldap_err2string(ret));
    }

    return ret;
#else
    return LDAP_SUCCESS;
#endif
}

#ifdef HAVE_LDAPSSL_CLIENT_INIT
/* Taken from http://www-archive.mozilla.org/directory/csdk-docs/ssl.htm */
static int start_ssl(pam_handle_t *ph,
                     LDAP *ldap,
                     const char *ca_cert,
                     bool secure)
{
    int ret;

    if (secure == false) {
        return LDAP_SUCCESS;
    }

    /* Load SSL routines */
    ret = ldapssl_install_routines(ldap);
    if (ret != LDAP_SUCCESS) {
        logger(ph, LOG_ERR, "ldapssl_install_routines failed: [%s]\n",
               ldap_err2string(ret));
        return ret;
    }

    /* Set up option in LDAP struct for using SSL */
    ret = ldap_set_option(ldap, LDAP_OPT_SSL, LDAP_OPT_ON);
    if (ret != LDAP_SUCCESS) {
        logger(ph, LOG_ERR, "setting up SSL option failed: [%s]\n",
               ldap_err2string(ret));
        return ret;
    }

    return LDAP_SUCCESS;
}
#endif

static int secure_connection(pam_handle_t *ph,
                             LDAP *ldap,
                             const char *ca_cert,
                             bool secure)
{
#if defined(DISABLE_SSL)
    return LDAP_NOT_SUPPORTED;
#elif defined(HAVE_LDAP_START_TLS)
    return start_tls(ph, ldap, ca_cert, secure);
#elif defined(HAVE_LDAPSSL_CLIENT_INIT)
    return start_ssl(ph, ldap, ca_cert, secure);
#else
    return LDAP_NOT_SUPPORTED;
#endif
}

int
ph_connect(struct pam_hbac_ctx *ctx)
{
    int ret;
    LDAP *ld;
    struct berval password = {0, NULL};
    int ldap_vers = LDAP_VERSION3;

    if (ctx == NULL) {
        return EINVAL;
    }

    /* Some LDAP implementations require parts of the SSL/TLS setup are done
     * prior to initializing the LDAP handle
     */
    ret = secure_preinit(ctx->pamh, ctx->pc->ca_cert, ctx->pc->secure);
    if (ret != LDAP_SUCCESS) {
        logger(ctx->pamh, LOG_ERR,
               "SSL/TLS pre-initialization failed [%d]: %s\n",
               ret, ldap_err2string(ret));
        return EIO;
    }

    ret = ph_ldap_initialize(&ld, ctx->pc->uri, ctx->pc->secure);
    if (ret != LDAP_SUCCESS) {
        logger(ctx->pamh, LOG_ERR,
               "ldap_initialize failed [%d]: %s\n",
               ret, ldap_err2string(ret));
        return EIO;
    }

    ret = ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &ldap_vers);
    if (ret != LDAP_SUCCESS) {
        logger(ctx->pamh, LOG_ERR,
               "ldap_set_option failed [%d]: %s\n",
               ret, ldap_err2string(ret));
        ldap_unbind_ext(ld, NULL, NULL);
        return EIO;
    }

    ret = secure_connection(ctx->pamh, ld, ctx->pc->ca_cert, ctx->pc->secure);
    if (ret == LDAP_NOT_SUPPORTED) {
        logger(ctx->pamh,
               LOG_NOTICE,
               "This platform does not support TLS!\n");
        /* Not fatal, continue */
    } else if (ret != LDAP_SUCCESS) {
        logger(ctx->pamh, LOG_ERR,
               "start_tls failed [%d]: %s\n",
               ret, ldap_err2string(ret));
        ldap_unbind_ext(ld, NULL, NULL);
        return EIO;
    }

    password.bv_len = strlen(ctx->pc->bind_pw);
    password.bv_val = discard_const(ctx->pc->bind_pw);

    ret = ldap_sasl_bind_s(ld, ctx->pc->bind_dn, LDAP_SASL_SIMPLE, &password,
                           NULL, NULL, NULL);
    if (ret != LDAP_SUCCESS) {
        logger(ctx->pamh, LOG_ERR,
               "ldap_simple_bind_s failed [%d]: %s\n",
               ret, ldap_err2string(ret));
        ldap_unbind_ext(ld, NULL, NULL);
        return EACCES;
    }

    ctx->ld = ld;
    return 0;
}

void
ph_disconnect(struct pam_hbac_ctx *ctx)
{
    int ret;

    if (ctx == NULL || ctx->ld == NULL) {
        return;
    }

    ret = ldap_unbind_ext(ctx->ld, NULL, NULL);
    if (ret != LDAP_SUCCESS) {
        logger(ctx->pamh, LOG_ERR,
               "ldap_unbind_ext failed [%d]: %s\n",
               ret, ldap_err2string(ret));
    }
    ctx->ld = NULL;
}
