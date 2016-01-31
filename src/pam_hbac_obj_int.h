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

#ifndef __PAM_HBAC_OBJ_INT_H__
#define __PAM_HBAC_OBJ_INT_H__

#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>

struct ph_user {
    char *name;
    /* We mostly have a separate ph_user structure because unlike other
     * objects, users are searched with NSS interface which returns group
     * names directly, not DNs
     */
    char **group_names;
};

enum ph_host_attrmap {
    PH_MAP_HOST_OC,
    PH_MAP_HOST_FQDN,
    PH_MAP_HOST_MEMBEROF,
    PH_MAP_HOST_END     /* FIXME - rename to PH_PAM_NUM_ATTRS?? */
};

enum ph_svc_attrmap {
    PH_MAP_SVC_OC,
    PH_MAP_SVC_NAME,
    PH_MAP_SVC_MEMBEROF,
    PH_MAP_SVC_END
};

enum ph_rule_attrmap {
    PH_MAP_RULE_OC,
    PH_MAP_RULE_NAME,
    PH_MAP_RULE_UNIQUE_ID,
    PH_MAP_RULE_ENABLED_FLAG,
    PH_MAP_RULE_ACCESS_RULE_TYPE,
    PH_MAP_RULE_MEMBER_USER,
    PH_MAP_RULE_USER_CAT,
    PH_MAP_RULE_MEMBER_SVC,
    PH_MAP_RULE_SVC_CAT,
    PH_MAP_RULE_SRC_HOST,
    PH_MAP_RULE_SRC_HOST_CAT,
    PH_MAP_RULE_EXTERNAL_HOST,
    PH_MAP_RULE_MEMBER_HOST,
    PH_MAP_RULE_HOST_CAT,
    PH_MAP_RULE_END
};

#endif /* __PAM_HBAC_OBJ_INT_H__ */
