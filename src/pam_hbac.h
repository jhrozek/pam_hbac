#ifndef __PAM_HBAC_H__
#define __PAM_HBAC_H__

#include <stdint.h>
#include <stdlib.h>

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

#if 0
"[(&(objectClass=ipaHost)(fqdn=vm-087.idm.lab.bos.redhat.com))][cn=accounts,dc=idm,dc=lab,dc=bos,dc=redhat,dc=com]"
#endif 

/* config keys  */
#define PAM_HBAC_CONFIG_URI             "URI"
#define PAM_HBAC_CONFIG_SEARCH_BASE     "BASE"
#define PAM_HBAC_CONFIG_BIND_DN         "BIND_DN"
#define PAM_HBAC_CONFIG_BIND_PW         "BIND_PW"

struct pam_hbac_ctx {
    struct pam_hbac_config *pc;
    LDAP *ld;
};

/* pam_hbac_config.h */
struct pam_hbac_config {
    const char *uri;
    const char *search_base;
    const char *bind_dn;
    const char *bind_pw;
};

int ph_read_config(const char *config_file, struct pam_hbac_config **_conf);
#define ph_read_dfl_config(conf) ph_read_config(PAM_HBAC_CONFIG, conf)
void ph_cleanup_config(struct pam_hbac_config *conf);

#endif /* __PAM_HBAC_H__ */
