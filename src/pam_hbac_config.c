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

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <limits.h>
#include <unistd.h>

#include "pam_hbac.h"
#include "config.h"

#define MAX_LINE    1024
#define SEPARATOR   '='

void
ph_cleanup_config(struct pam_hbac_config *conf)
{
    if (conf == NULL) {
        return;
    }

    free_const(conf->uri);
    free_const(conf->search_base);
    free_const(conf->bind_dn);
    free_const(conf->bind_pw);
    free_const(conf->ca_cert);
    free(conf->hostname);

    free(conf);
}

int check_mandatory_opt(pam_handle_t *pamh, const char *name, const char *value)
{
    if (value == NULL) {
        logger(pamh, LOG_ERR,
               "Missing mandatory option: %s in config file.\n", name);
        return 1;
    }
    return 0;
}

static int
check_config(pam_handle_t *pamh, struct pam_hbac_config *conf)
{
    int error = 0;

    /* Mandatory options. */
    error |= check_mandatory_opt(pamh, PAM_HBAC_CONFIG_URI, conf->uri);
    error |= check_mandatory_opt(pamh, PAM_HBAC_CONFIG_SEARCH_BASE, conf->search_base);
    error |= check_mandatory_opt(pamh, PAM_HBAC_CONFIG_BIND_DN, conf->bind_dn);
    error |= check_mandatory_opt(pamh, PAM_HBAC_CONFIG_BIND_PW, conf->bind_pw);

    if (error != 0) {
        return EINVAL;
    }

    return 0;
}

static int
default_hostname(char **_hostname)
{
    char *hostname = NULL;
    int ret;

    hostname = malloc(HOST_NAME_MAX);
    if (hostname == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = gethostname(hostname, HOST_NAME_MAX);
    if (ret == -1) {
        ret = errno;
        if (ret == 0) {
            /* Prevent resource leak in case gethostname() failed but errno
             * was set to 0. Probably not very useful, but silences Coverity
             */
            ret = EIO;
        }
        goto done;
    }

    /* Make sure that returned string is terminated. */
    hostname[HOST_NAME_MAX-1] = '\0';

    *_hostname = hostname;
    ret = 0;

done:
    if (ret != 0) {
        free(hostname);
    }
    return ret;
}

static int
default_config(pam_handle_t *pamh, struct pam_hbac_config *conf)
{
    int ret;

    ret = default_hostname(&conf->hostname);
    if (ret != 0) {
        logger(pamh, LOG_ERR, "Failed to set default hostname [%d]: %s\n",
                ret, strerror(ret));
        return ret;
    }

    conf->timeout = PAM_HBAC_DEFAULT_TIMEOUT;
    conf->secure = true;
    return 0;
}

static char *
strip(char *s)
{
    char *start, *end;

    start = s;
    end = s + strlen(s) - 1;

    /* Trim leading whitespace */
    while (*start && isspace(*start)) ++start;
    /* Trim trailing whitespace */
    while (end > start && isspace(*end)) *end-- = '\0';

    return start;
}

static int
get_key_value(pam_handle_t *pamh,
              const char *line,
              const char **_key,
              const char **_value)
{
    char *sep;
    char *key;
    char *value;
    char *l;

    sep = strchr(line, SEPARATOR);
    if (sep == NULL) {
        logger(pamh, LOG_ERR, "Malformed line; no separator\n");
        return EINVAL;
    }

    l = strdup(line);
    l[sep-line] = '\0';
    key = strdup(strip(l));
    value = strdup(strip(sep+1));
    /* Some of the lines could contain secret data. */
    _pam_overwrite(l);
    free(l);
    if (key == NULL || value == NULL) {
        free(key);
        free(value);
        return ENOMEM;
    }

    *_key = key;
    *_value = value;
    return 0;
}

static bool get_bool(const char *value, bool dfl)
{
    if (value == NULL) {
        return dfl;
    }

    if (strcasecmp(value, PAM_HBAC_TRUE_VALUE) == 0) {
        return true;
    } else if (strcasecmp(value, PAM_HBAC_FALSE_VALUE) == 0) {
        return false;
    }

    return dfl;
}

static int
read_config_line(pam_handle_t *pamh,
                 const char *line,
                 struct pam_hbac_config *conf)
{
    const char *key = NULL;
    const char *value = NULL;
    const char *l;
    int ret;
    bool skip_line = false;

    l = line;

    /* Skip leading whitespace */
    while(isspace(*l)) {
        ++l;
    }

    /* Skip comments and empty lines */
    if (*l == '#' || *l == '\0') {
        skip_line = true;
        ret = EAGAIN;
        goto fail;
    }

    ret = get_key_value(pamh, l, &key, &value);
    if (ret) {
        logger(pamh, LOG_ERR,
               "Cannot split \"%s\" into a key-value pair [%d]: %s\n",
               l, ret, strerror(ret));
        goto fail;
    }

    if (strcasecmp(key, PAM_HBAC_CONFIG_URI) == 0) {
        conf->uri = value;
        logger(pamh, LOG_DEBUG, "URI: %s", conf->uri);
    } else if (strcasecmp(key, PAM_HBAC_CONFIG_BIND_DN) == 0) {
        conf->bind_dn = value;
        logger(pamh, LOG_DEBUG, "bind dn: %s", conf->bind_dn);
    } else if (strcasecmp(key, PAM_HBAC_CONFIG_BIND_PW) == 0) {
        conf->bind_pw = value;
    } else if (strcasecmp(key, PAM_HBAC_CONFIG_SEARCH_BASE) == 0) {
        conf->search_base = value;
        logger(pamh, LOG_DEBUG, "search base: %s", conf->search_base);
    } else if (strcasecmp(key, PAM_HBAC_CONFIG_HOST_NAME) == 0) {
        conf->hostname = discard_const(value);
        logger(pamh, LOG_DEBUG, "host name: %s", conf->hostname);
    } else if (strcasecmp(key, PAM_HBAC_CONFIG_SSL_PATH) == 0) {
        conf->ca_cert = discard_const(value);
        logger(pamh, LOG_DEBUG, "ca cert: %s", conf->ca_cert);
    } else if (strcasecmp(key, PAM_HBAC_CONFIG_SECURE) == 0) {
        conf->secure = get_bool(value, conf->secure);
        logger(pamh, LOG_DEBUG,
               "use TLS/SSL: %s", conf->secure ? "yes" : "no");
        free_const(value);
    } else {
        /* Skip unknown key/values */
        free_const(value);
    }

    free_const(key);
    return 0;

fail:
    if (skip_line) {
        logger(pamh, LOG_DEBUG, "Empty line in config file\n");
    } else {
        logger(pamh, LOG_CRIT,
               "cannot read config [%d]: %s\n", ret, strerror(ret));
    }
    free_const(key);
    free_const(value);
    return ret;
}

int
ph_read_config(pam_handle_t *pamh,
               const char *config_file,
               struct pam_hbac_config **_conf)
{
    FILE *fp;
    int ret;
    char line[MAX_LINE];
    struct pam_hbac_config *conf;

    logger(pamh, LOG_DEBUG, "config file: %s", config_file);

    errno = 0;
    fp = fopen(config_file, "r");
    if (fp == NULL) {
        /* According to PAM Documentation, such an error in a config file
         * SHOULD be logged at LOG_ALERT level
         */
        ret = errno;
        logger(pamh, LOG_ALERT,
               "pam_hbac: cannot open config file %s [%d]: %s\n",
               config_file, ret, strerror(ret));
        return ret;
    }

    conf = calloc(1, sizeof(struct pam_hbac_config));
    if (conf == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = default_config(pamh, conf);
    if (ret != 0) {
        goto done;
    }

    while (fgets(line, sizeof(line), fp) != NULL) {
        /* Try to parse a line */
        ret = read_config_line(pamh, line, conf);
        if (ret == EAGAIN) {
            continue;
        } else if (ret != 0) {
            logger(pamh, LOG_ERR,
                   "couldn't read from the config file [%d]: %s",
                   ret, strerror(ret));
            goto done;
        }
    }

    ret = check_config(pamh, conf);
    if (ret != 0) {
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

static void
log_string_opt(pam_handle_t *pamh, const char *name, const char *value)
{
    /* Better to be secure about passing NULL. */
    logger(pamh, LOG_DEBUG, "%s: %s\n", name, value ? value : "not set");
}

void
ph_dump_config(pam_handle_t *pamh, struct pam_hbac_config *conf)
{
    if (conf == NULL) {
        logger(pamh, LOG_NOTICE, "NULL config pointer\n");
        return;
    }

    log_string_opt(pamh, "URI", conf->uri);
    log_string_opt(pamh, "search base", conf->search_base);
    log_string_opt(pamh, "bind DN", conf->bind_dn);
    /* Don't dump password */
    log_string_opt(pamh, "client hostname", conf->hostname);
    log_string_opt(pamh, "cert", conf->ca_cert);
    logger(pamh, LOG_DEBUG, "timeout %d\n", conf->timeout);
}
