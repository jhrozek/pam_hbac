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

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <syslog.h>
#include <stdlib.h>
#include <ctype.h>
#include <limits.h>

#include <security/_pam_macros.h>

#include "pam_hbac.h"
#include "config.h"

#define MAX_LINE    1024
#define SEPARATOR   '='

#define SET_DEFAULT_STRING(k, def) do {              \
    if (k == NULL) {                                 \
        k = strdup(def);                             \
        CHECK_PTR(k);                                \
    }                                                \
} while(0);                                          \

void
ph_cleanup_attrmap(struct pam_hbac_attrmap *map)
{
    if (!map) return;

    free(map->user_key);

    free(map);
}

void
ph_cleanup_config(struct pam_hbac_config *conf)
{
    if (!conf) return;

    ph_cleanup_attrmap(conf->map);

    free_const(conf->uri);
    free_const(conf->search_base);
    free(conf->hostname);

    free(conf);
}

static struct pam_hbac_attrmap *
default_attrmap(struct pam_hbac_attrmap *map)
{
    SET_DEFAULT_STRING(map->user_key, PAM_HBAC_ATTR_USER);

    return map;

fail:
    ph_cleanup_attrmap(map);
    return NULL;
}

static struct pam_hbac_config *
default_config(struct pam_hbac_config *conf)
{
    int ret;

    SET_DEFAULT_STRING(conf->uri, PAM_HBAC_DEFAULT_URI);
    SET_DEFAULT_STRING(conf->search_base, PAM_HBAC_DEFAULT_SEARCH_BASE);

    if (conf->hostname) {
        conf->hostname = malloc(HOST_NAME_MAX);
        if (!conf->hostname) goto fail;

        ret = gethostname(conf->hostname, HOST_NAME_MAX);
        if (ret == -1) {
            ret = errno;
            goto fail;
        }
        conf->hostname[HOST_NAME_MAX-1] = '\0';
    }

    if (conf->timeout == 0) {
        conf->timeout = PAM_HBAC_DEFAULT_TIMEOUT;
    }

    return conf;

fail:
    ph_cleanup_config(conf);
    return NULL;
}

static char *
strip(char *s)
{
    char *start, *end;

    start = s;
    end = s + strlen(s) - 1;

    /* Trim leading whitespace */
    while(*start && isspace(*start)) ++start;
    /* Trim trailing whitespace */
    while(end > start && isspace(*end)) *end-- = '\0';

    return start;
}

static int
get_key_value(const char *line,
              const char **_key,
              const char **_value)
{
    char *sep;
    const char *key;
    char *value;
    char *l;

    sep = strchr(line, SEPARATOR);
    if (!sep) {
        D(("Malformed line; no separator\n"));
        return EINVAL;
    }

    l = strdup(line);
    l[sep-line] = '\0';
    key = strdup(strip(l));
    value = strdup(strip(sep+1));
    free(l);
    if (!key || !value) {
        return ENOMEM;
    }

    *_key = key;
    *_value = value;
    return 0;
}

static int
read_config_line(const char *line, struct pam_hbac_config *conf)
{
    const char *key = NULL;
    const char *value = NULL;
    const char *l;
    int ret;

    l = line;

    /* Skip leading whitespace */
    while(isspace(*l)) {
        ++l;
    }

    /* Skip comments */
    if (*l == '#') {
        ret = EAGAIN;
        goto done;
    }

    ret = get_key_value(l, &key, &value);
    if (ret) {
        goto done;
    }

    if (strcasecmp(key, PAM_HBAC_CONFIG_URI) == 0) {
        conf->uri = value;
        D(("URI: %s", conf->uri));
    } else if (strcasecmp(key, PAM_HBAC_CONFIG_BIND_DN) == 0) {
        conf->bind_dn = value;
        D(("bind dn: %s", conf->bind_dn));
    } else if (strcasecmp(key, PAM_HBAC_CONFIG_BIND_PW) == 0) {
        conf->bind_pw = value;
#if 0
        D(("bind pw: %s", conf->bind_pw));
#endif
    } else if (strcasecmp(key, PAM_HBAC_CONFIG_SEARCH_BASE) == 0) {
        conf->search_base = value;
        D(("search base: %s", conf->search_base));
    } else if (strcasecmp(key, PAM_HBAC_CONFIG_HOST_NAME) == 0) {
        conf->hostname = discard_const(value);
        D(("host name: %s", conf->hostname));
    } else {
        /* Skip unknown key/values */
        free_const(value);
    }

    free_const(key);
    return 0;

done:
    D(("cannot read config [%d]: %s\n", ret, strerror(ret)));
    free_const(key);
    free_const(value);
    return ret;
}

int
ph_create_attrmap(struct pam_hbac_attrmap **_map)
{
    struct pam_hbac_attrmap *map;

    map = calloc(1, sizeof(struct pam_hbac_attrmap));
    if (!map) return ENOMEM;

    /* Only defaults for now */
    map = default_attrmap(map);
    if (!map) return ENOMEM;

    *_map = map;
    return 0;
}

int
ph_read_config(const char *config_file, struct pam_hbac_config **_conf)
{
    FILE *fp;
    int ret;
    char line[MAX_LINE];
    struct pam_hbac_config *conf;

    D(("config file: %s", config_file));

    errno = 0;
    fp = fopen(config_file, "r");
    if (!fp) {
        /* According to PAM Documentation, such an error in a config file
         * SHOULD be logged at LOG_ALERT level
         */
        ret = errno;
        syslog(LOG_ALERT, "pam_hbac: cannot open config file %s [%d]: %s\n",
                           config_file, ret, strerror(ret));
        return ret;
    }

    conf = calloc(1, sizeof(struct pam_hbac_config));
    CHECK_PTR_L(conf, done);

    ret = ph_create_attrmap(&conf->map);
    if (ret) goto done;

    while (fgets(line, sizeof(line), fp) != NULL) {
        /* Try to parse a line */
        ret = read_config_line(line, conf);
        if (ret == EAGAIN) {
            continue;
        } else if (ret != 0) {
            goto done;
        }
    }

    /* Set all values that were not set explicitly */
    if ((conf = default_config(conf)) == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = 0;
    *_conf = conf;
done:
    if (ret) {
        ph_cleanup_config(conf);
    }
    fclose(fp);
    return ret;
}
