/*
    Copyright (C) 2012 Jakub Hrozek <jakub.hrozek@posteo.se>

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

#ifndef __PAM_HBAC_H__
#define __PAM_HBAC_H__

#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdarg.h>
#include <errno.h>
#include <syslog.h>

#include <ldap.h>
#include <security/pam_modules.h>

#include "libhbac/ipa_hbac.h"

/* various utilities */
/* taken from sources of SSSD - http://fedorahosted.org/sssd */
#ifndef discard_const
#define discard_const(ptr) ((void *)((uintptr_t)(ptr)))
#endif

#define free_const(ptr) free(discard_const(ptr))

/* config file */
#ifndef PAM_HBAC_CONFIG_FILE_NAME
#define PAM_HBAC_CONFIG_FILE_NAME      "pam_hbac.conf"
#endif  /* PAM_HBAC_CONFIG_FILE_NAME */

#define PAM_HBAC_CONFIG                PAM_HBAC_CONF_DIR"/"PAM_HBAC_CONFIG_FILE_NAME

/* config defaults */
#define PAM_HBAC_DEFAULT_TIMEOUT        5

/* default attributes */
#define PAM_HBAC_ATTR_OC                "objectClass"
#define PAM_HBAC_TRUE_VALUE             "TRUE"
#define PAM_HBAC_FALSE_VALUE            "FALSE"
#define PAM_HBAC_ALLOW_VALUE            "allow"
#define PAM_HBAC_ALL_VALUE              "all"

/* config keys  */
#define PAM_HBAC_CONFIG_URI             "URI"
#define PAM_HBAC_CONFIG_SEARCH_BASE     "BASE"
#define PAM_HBAC_CONFIG_HOST_NAME       "HOST_NAME"
#define PAM_HBAC_CONFIG_BIND_DN         "BIND_DN"
#define PAM_HBAC_CONFIG_BIND_PW         "BIND_PW"
#define PAM_HBAC_CONFIG_CA_CERT         "CA_CERT"

struct pam_hbac_ctx {
    pam_handle_t *pamh;
    struct pam_hbac_config *pc;
    LDAP *ld;
};

/* pam_hbac_config.c */
struct pam_hbac_config {
    const char *uri;
    const char *search_base;
    const char *bind_dn;
    const char *bind_pw;
    const char *ca_cert;
    char *hostname;
    int timeout;
};

int
ph_read_config(pam_handle_t *pamh,
               const char *config_file,
               struct pam_hbac_config **_conf);
#define ph_read_dfl_config(pamh, conf) ph_read_config(pamh, PAM_HBAC_CONFIG, conf)
void ph_cleanup_config(struct pam_hbac_config *conf);
void ph_dump_config(pam_handle_t *pamh, struct pam_hbac_config *conf);

/* pam_hbac_util.c */
void free_string_clist(const char **list);
void free_string_list(char **list);
size_t null_string_array_size(char *arr[]);
size_t null_cstring_array_size(const char *arr[]);
void logger(pam_handle_t *pamh, int level, const char *fmt, ...);
void va_logger(pam_handle_t *pamh, int level, const char *fmt, va_list ap);
void set_debug_mode(bool v);

#endif /* __PAM_HBAC_H__ */
