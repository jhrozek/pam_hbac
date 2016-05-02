/*
    Authors:
        Sumit Bose <sbose@redhat.com>
        Jakub Hrozek <jhrozek@redhat.com>

    Copyright (C) 2009 Red Hat

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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <unistd.h>
#include <string.h>

#include "pam_hbac_compat.h"

#define PAM_TEST_DFL_SVC    "pam_hbac_test"
#define PAM_TEST_DFL_USER   "dummy"

#ifdef HAVE_SECURITY_PAM_MISC_H
# include <security/pam_misc.h>
#elif defined(HAVE_SECURITY_OPENPAM_H)
# include <security/openpam.h>
#endif

#ifdef HAVE_SECURITY_PAM_MISC_H
static struct pam_conv conv = {
    misc_conv,
    NULL
};
#elif defined(HAVE_SECURITY_OPENPAM_H)
static struct pam_conv conv = {
    openpam_ttyconv,
    NULL
};
#else
static int dummy_pam_conv(int num_msg,
                          const struct pam_message **msgm,
                          struct pam_response **response,
                          void *appdata_ptr)
{
    return PAM_SUCCESS;
}

static struct pam_conv conv = {
    dummy_pam_conv,
    NULL
};
#endif

int main(int argc, char *argv[])
{
    pam_handle_t *pamh;
    char *user;
    char *svc;
    int ret;

    if (argc == 1) {
        fprintf(stderr, "missing user and service name, using default\n");
        user = strdup(PAM_TEST_DFL_USER);
        svc = strdup(PAM_TEST_DFL_SVC);
    } else if (argc == 2) {
        fprintf(stdout, "using first argument as user and default service name\n");
        user = strdup(argv[1]);
        svc = strdup(PAM_TEST_DFL_SVC);
    } else {
        user = strdup(argv[1]);
        svc = strdup(argv[2]);
    }

    fprintf(stdout, "service: %s\nuser: %s\n", svc, user);

    ret = pam_start(svc, user, &conv, &pamh);
    if (ret != PAM_SUCCESS) {
        fprintf(stderr, "pam_start failed: %s\n", pam_strerror(pamh, ret));
        return 1;
    }

    fprintf(stdout, "testing pam_acct_mgmt\n");
    ret = pam_acct_mgmt(pamh, 0);
    fprintf(stderr, "pam_acct_mgmt: %s\n", pam_strerror(pamh, ret));

    pam_end(pamh, ret);
    return 0;
}
