/*
    Copyright (C) 2012 Jakub Hrozek <jakub.hrozek@gmail.com>

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

#include <ldap.h>

/* various utilities */
/* taken from sources of SSSD - http://fedorahosted.org/sssd */
#ifndef discard_const
#define discard_const(ptr) ((void *)((uintptr_t)(ptr)))
#endif

#ifndef NULL
#define NULL 0
#endif

#define CHECK_PTR_L(ptr, l) do { \
    if(ptr == NULL) {            \
        goto l;                  \
    }                            \
} while(0);

#define free_const(ptr) free(discard_const(ptr))

#define CHECK_PTR(ptr) CHECK_PTR_L(ptr, fail)

/* config file */
#ifndef PAM_HBAC_CONFIG_FILE_NAME
#define PAM_HBAC_CONFIG_FILE_NAME      "pam_hbac.conf"
#endif  /* PAM_HBAC_CONFIG_FILE_NAME */

#define PAM_HBAC_CONFIG                PAM_HBAC_CONF_DIR"/"PAM_HBAC_CONFIG_FILE_NAME

/* attribute maps */
#define IPA_HOST                        "ipaHost"

/* search bases */
#define HOST_BASE_PREFIX                "cn=accounts"

/* config defaults */
#define PAM_HBAC_DEFAULT_URI            "ldap://localhost:389"
#define PAM_HBAC_DEFAULT_SEARCH_BASE    "dc=localhost,dc=com"
#define PAM_HBAC_DEFAULT_TIMEOUT        5

#if 0
"[(&(objectClass=ipaHost)(fqdn=vm-087.idm.lab.bos.redhat.com))][cn=accounts,dc=idm,dc=lab,dc=bos,dc=redhat,dc=com]"
#endif

/* default attributes */
#define PAM_HBAC_ATTR_OC                "objectClass"
#define PAM_HBAC_TRUE_VALUE             "TRUE"
#define PAM_HBAC_ALLOW_VALUE            "allow"
#define PAM_HBAC_ALL_VALUE              "all"

#define PAM_HBAC_ATTR_USER              "uid"
#define PAM_HBAC_ATTR_MEMBEROF          "memberOf"

/* config keys  */
#define PAM_HBAC_CONFIG_URI             "URI"
#define PAM_HBAC_CONFIG_SEARCH_BASE     "BASE"
#define PAM_HBAC_CONFIG_HOST_NAME       "HOST_NAME"
#define PAM_HBAC_CONFIG_BIND_DN         "BIND_DN"
#define PAM_HBAC_CONFIG_BIND_PW         "BIND_PW"

enum pam_hbac_objects {
    PH_OBJ_USER,
    PH_OBJ_RULE,
    /* Sentinel */
    PH_OBJ_NUM_OBJECTS
};

struct ph_search_ctx {
    const char *sub_base;
    const char **attrs;
    const char *oc;
    size_t num_attrs;
};

struct pam_hbac_ctx {
    struct pam_hbac_config *pc;
    struct ph_search_ctx objs[PH_OBJ_NUM_OBJECTS];

    LDAP *ld;

    struct ph_member_obj *user_obj;
};

/* pam_hbac_search.c */
struct ph_attr;
struct ph_attr *ph_attr_new(char *name, struct berval **vals);
void ph_attr_debug(struct ph_attr *a);
void ph_attr_free(struct ph_attr *a);

struct ph_entry;
struct ph_entry *ph_entry_new(struct ph_search_ctx *obj);
void ph_entry_add(struct ph_entry **head, struct ph_entry *e);
size_t ph_num_entries(struct ph_entry *head);
void ph_entry_debug(struct ph_entry *e);
int ph_entry_set_attr(struct ph_entry *e, struct ph_attr *a, int index);
struct berval **ph_entry_get_attr_val(struct ph_entry *e, int attr);
void ph_entry_free(struct ph_entry *e);

struct ph_member_obj *ph_member_obj_new(char *name);
void ph_member_obj_debug(struct ph_member_obj *o);
void ph_member_obj_free(struct ph_member_obj *o);

bool ph_ldap_entry_has_oc(LDAP *ld, LDAPMessage *entry, const char *oc);
int ph_want_attr(const char *attr, struct ph_search_ctx *obj);

/* pam_hbac_ipa.c */
int ph_search_user(LDAP *ld, struct pam_hbac_config *conf,
                   const char *username, struct ph_member_obj **_user_obj);
int ph_search_rules(LDAP *ld, struct pam_hbac_config *conf, const char *hostname);

/* pam_hbac_config.c */
struct pam_hbac_attrmap {
    char *user_key;
};

struct pam_hbac_config {
    struct pam_hbac_attrmap *map;

    const char *uri;
    const char *search_base;
    const char *bind_dn;
    const char *bind_pw;
    char *hostname;
    int timeout;
};

int ph_read_config(const char *config_file, struct pam_hbac_config **_conf);
#define ph_read_dfl_config(conf) ph_read_config(PAM_HBAC_CONFIG, conf)
void ph_cleanup_config(struct pam_hbac_config *conf);

#endif /* __PAM_HBAC_H__ */
