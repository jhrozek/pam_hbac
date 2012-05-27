/*
    Copyright (C) 2012 Jakub Hrozek <jakub.hrozek@gmail.com>

    Based on pam_test_client used in the SSSD project, written
    by Sumit Bose <sbose@redhat.com>

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

#include <security/pam_appl.h>
#include <security/pam_misc.h>

static struct pam_conv conv = {
    misc_conv,
    NULL
};

int main(int argc, char *argv[]) {

    pam_handle_t *pamh;
    char *user = NULL;
    int ret;

    if (argc == 1) {
        fprintf(stderr, "usage: pam_test_client [user]\n");
        exit(1);
    } else if (argc == 2) {
        user = strdup(argv[1]);
    }

    ret = pam_start("hbac_test", user, &conv, &pamh);
    if (ret != PAM_SUCCESS) {
        free(user);
        fprintf(stderr, "pam_start failed: %s\n", pam_strerror(pamh, ret));
        return 1;
    }

    ret = pam_acct_mgmt(pamh, 0);
    fprintf(stderr, "pam_acct_mgmt: %s\n", pam_strerror(pamh, ret));

    pam_end(pamh, ret);
    free(user);
    return 0;
}
