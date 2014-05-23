/** @file */
/*
 * ratools: Router Advertisement Tools
 *
 * Copyright 2013-2014 Dan Luedtke <mail@danrl.de>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


#include "opt_rdnss.h"

#include "library.h"
#include "log.h"
#include "module.h"

#include <stdlib.h>
#include <netinet/icmp6.h>


/* --- helper function ------------------------------------------------------ */


/**
 * @brief Get a server from a server list by address
 *
 * @param[in] list              start of server list
 * @param[in] addr              address to check
 *
 * @return Returns pointer to server if found, NULL otherwise
 */
static struct rat_opt_rdnss_srv *
rat_opt_rdnss_get_srv (struct rat_opt_rdnss_srv *list,
                       struct in6_addr *addr)
{
    struct rat_opt_rdnss_srv *srv;

    if (!list)
        goto exit_err;

    for (srv = list; srv; srv = srv->srv_next) {
        if (memcmp(&srv->srv_addr, addr, sizeof(srv->srv_addr)) != 0)
            continue;
        return srv;
    }

exit_err:
    return NULL;
}


/* --- functions called by ratools/rad to maintain module ------------------- */


/**
 * @brief Create new option
 *
 * @param mf                    module helper functions
 * @param mi                    module instance information
 *
 * @return Returns RAT_ERROR on error, RAT_OK otherwise
 */
static int rat_opt_rdnss_create (struct rat_mod_functions *mf,
                                 struct rat_mod_instance *mi)
{
    struct rat_opt_rdnss_private *rds;
    RAT_DEBUG_TRACE();
    RAT_DISCARD_UNUSED(mf);

    /* allocate memory for module private data */
    rds = calloc(1, sizeof(*rds));
    if (!rds) {
        rat_log_err("Module RDNSS: Out of memory!");
        goto exit_err;
    }

    /* set default values */
    rds->rds_enabled      = 0;
    rds->rds_lifetime     = RAT_OPT_RDNSS_LIFE_DEF(mi->mi_maxadvint);
    rds->rds_srv          = NULL;

    /* write back changes */
    RAT_MOD_PRIVATE(mi) = rds;

    return RAT_OK;

exit_err:
    return RAT_ERROR;
}


/**
 * @brief Destroy option
 *
 * @param mf                    module helper functions
 * @param mi                    module instance information
 *
 * @return Returns RAT_ERROR on error, RAT_OK otherwise
 */
static int rat_opt_rdnss_destroy (struct rat_mod_functions *mf,
                                  struct rat_mod_instance *mi)
{
    struct rat_opt_rdnss_private *rds = RAT_MOD_PRIVATE(mi);
    uint8_t *raw = RAT_MOD_RAWDATA(mi);
    struct rat_opt_rdnss_srv *srv, *tmp;
    RAT_DEBUG_TRACE();
    RAT_DISCARD_UNUSED(mf);

    tmp = srv = rds->rds_srv;
    while (srv) {
        srv = srv->srv_next;
        if (tmp)
            free(tmp);
    }
    if (rds)
        free(rds);
    rds = NULL;

    if (raw)
        free(raw);
    raw = NULL;

    /* write back changes */
    RAT_MOD_PRIVATE(mi) = rds;
    RAT_MOD_RAWDATA(mi) = raw;
    RAT_MOD_RAWLEN(mi) = 0;

    return RAT_OK;
}


/**
 * @brief Compile option
 *
 * @param mi                    module instance information
 *
 * @return Returns RAT_ERROR on error, RAT_OK otherwise
 */
static int rat_opt_rdnss_compile (struct rat_mod_instance *mi)
{
    struct rat_opt_rdnss_private *rds = RAT_MOD_PRIVATE(mi);
    struct nd_opt_rdnss *raw = RAT_MOD_RAWDATA(mi);
    struct rat_opt_rdnss_srv *srv;
    uint16_t rawlen;
    uint8_t *rawptr;
    RAT_DEBUG_TRACE();

    if (!rds->rds_enabled)
        goto exit_ok;

    rawlen = sizeof(*raw);
    for (srv = rds->rds_srv; srv; srv = srv->srv_next)
        rawlen += sizeof(srv->srv_addr);
    rawlen = ALIGN(rawlen, 8);

    /* allocate memory for raw data */
    if (!raw)
        raw = calloc(1, rawlen);
    if (!raw) {
        rat_log_err("Module RDNSS: Out of memory!");
        goto exit_err;
    }

    /* set option data */
    raw->nd_opt_rdnss_type = ND_OPT_RDNSS;
    raw->nd_opt_rdnss_len = rawlen / 8;
    raw->nd_opt_rdnss_reserved = 0;
    raw->nd_opt_rdnss_lifetime = htonl(rds->rds_lifetime);

    /* copy server addresses */
    rawptr = ((uint8_t *) raw) + sizeof(*raw);
    for (srv = rds->rds_srv; srv; srv = srv->srv_next) {
        memcpy(rawptr, &srv->srv_addr, sizeof(srv->srv_addr));
        rawptr += sizeof(srv->srv_addr);
    }

    /* write back changes */
    RAT_MOD_RAWDATA(mi) = raw;
    RAT_MOD_RAWLEN(mi) = rawlen;

exit_ok:
    return RAT_OK;

exit_err:
    return RAT_ERROR;
}


/**
 * @brief Show option
 *
 * @param mf                    module helper functions
 * @param mi                    module instance information
 *
 * @return Returns RAT_ERROR on error, RAT_OK otherwise
 */
static int rat_opt_rdnss_show (struct rat_mod_functions *mf,
                               struct rat_mod_instance *mi)
{
    struct rat_opt_rdnss_private *rds = RAT_MOD_PRIVATE(mi);
    struct rat_opt_rdnss_srv *srv;
    char buffer[RAT_6ADDR_STRSIZ];
    RAT_DEBUG_TRACE();

    mf->mf_title(mi->mi_in, "Recursive DNS Server Option `%s':", mi->mi_myname);

    mf->mf_param(mi->mi_in, "State");
    mf->mf_value("%s", rds->rds_enabled ? "Enabled" : "Disabled");
    mf->mf_info(NULL);

    mf->mf_param(mi->mi_in, "Lifeime");
    mf->mf_value("%" PRIu32, rds->rds_lifetime);
    if (rds->rds_lifetime == RAT_OPT_RDNSS_LIFE_INF)
        mf->mf_info("Infinity");
    else if (rds->rds_lifetime == RAT_OPT_RDNSS_LIFE_NOT)
        mf->mf_info("RDNSS not valid");
    else
        mf->mf_info("%ud %uh %um %us",
                  RAT_LIB_S_D_TO_D(rds->rds_lifetime),
                  RAT_LIB_S_D_TO_H(rds->rds_lifetime),
                  RAT_LIB_S_D_TO_M(rds->rds_lifetime),
                  RAT_LIB_S_D_TO_S(rds->rds_lifetime));
    if (rds->rds_lifetime < RAT_OPT_RDNSS_LIFE_MIN(mi->mi_maxadvint))
        mf->mf_comment(mi->mi_in, "Warning: Lifetime too short!");
    if (rds->rds_lifetime != RAT_OPT_RDNSS_LIFE_INF &&
        rds->rds_lifetime > RAT_OPT_RDNSS_LIFE_MAX(mi->mi_maxadvint))
        mf->mf_comment(mi->mi_in, "Warning: Lifetime too long!");

    for (srv = rds->rds_srv; srv; srv = srv->srv_next) {
        mf->mf_param(mi->mi_in, "Server");
        rat_lib_6addr_to_str(buffer, sizeof(buffer), &srv->srv_addr);
        mf->mf_value("%s", buffer);
        mf->mf_info(NULL);
        if (rat_lib_6addr_is_documentation(&srv->srv_addr))
            mf->mf_comment(mi->mi_in + 1, "Warning: Documentation prefix!");
        if (rat_lib_6addr_is_multicast(&srv->srv_addr))
            mf->mf_comment(mi->mi_in + 1, "Warning: Multicast prefix!");
        if (rat_lib_6addr_is_linklocal(&srv->srv_addr))
            mf->mf_comment(mi->mi_in + 1, "Warning: Link-local prefix!");
        if (rat_lib_6addr_is_unspecified(&srv->srv_addr))
            mf->mf_comment(mi->mi_in + 1, "Warning: Unspecified prefix!");
    }
    if (!rds->rds_srv) {
        mf->mf_param(mi->mi_in, "Warning");
        mf->mf_value("Empty server list!");
        mf->mf_info(NULL);
    }

    return RAT_OK;
}


/**
 * @brief Dump configuration of option
 *
 * @param mf                    module helper functions
 * @param mi                    module instance information
 *
 * @return Returns RAT_ERROR on error, RAT_OK otherwise
 */
static int rat_opt_rdnss_dump (struct rat_mod_functions *mf,
                             struct rat_mod_instance *mi)
{
    struct rat_opt_rdnss_private *rds = RAT_MOD_PRIVATE(mi);
    struct rat_opt_rdnss_srv *srv;
    char buffer[RAT_6ADDR_STRSIZ];
    RAT_DEBUG_TRACE();

    mf->mf_message("# Recursive DNS Server Option `%s':", mi->mi_myname);
    mf->mf_message("%s create", mi->mi_myname);

    if (rds->rds_lifetime != RAT_OPT_RDNSS_LIFE_DEF(mi->mi_maxadvint)) {
        if (rds->rds_lifetime == RAT_OPT_RDNSS_LIFE_INF) {
            mf->mf_message("%s set lifetime infinity", mi->mi_myname);
        } else if (rds->rds_lifetime == RAT_OPT_RDNSS_LIFE_NOT) {
            mf->mf_message("%s set lifetime not-valid",
                           mi->mi_myname);
        } else {
            mf->mf_message("%s set lifetime %ud%uh%um%us", mi->mi_myname,
                           RAT_LIB_S_D_TO_D(rds->rds_lifetime),
                           RAT_LIB_S_D_TO_H(rds->rds_lifetime),
                           RAT_LIB_S_D_TO_M(rds->rds_lifetime),
                           RAT_LIB_S_D_TO_S(rds->rds_lifetime));
        }
    }

    for (srv = rds->rds_srv; srv; srv = srv->srv_next) {
        rat_lib_6addr_to_str(buffer, sizeof(buffer), &srv->srv_addr);
        mf->mf_message("%s add server %s", mi->mi_myname, buffer);
    }

    if (rds->rds_enabled)
        mf->mf_message("%s enable", mi->mi_myname);

    return RAT_OK;
}


/**
 * @brief Enable option
 *
 * @param mf                    module helper functions
 * @param mi                    module instance information
 *
 * @return Returns RAT_ERROR on error, RAT_OK otherwise
 */
static int rat_opt_rdnss_enable (struct rat_mod_functions *mf,
                               struct rat_mod_instance *mi)
{
    struct rat_opt_rdnss_private *rds = RAT_MOD_PRIVATE(mi);
    RAT_DEBUG_TRACE();
    RAT_DISCARD_UNUSED(mf);

    rds->rds_enabled = 1;

    return RAT_OK;
}


/**
 * @brief Disable option
 *
 * @param mf                    module helper functions
 * @param mi                    module instance information
 *
 * @return Returns RAT_ERROR on error, RAT_OK otherwise
 */
static int rat_opt_rdnss_disable (struct rat_mod_functions *mf,
                                struct rat_mod_instance *mi)
{
    struct rat_opt_rdnss_private *rds = RAT_MOD_PRIVATE(mi);
    struct nd_opt_prefix_info *raw = RAT_MOD_RAWDATA(mi);
    RAT_DEBUG_TRACE();
    RAT_DISCARD_UNUSED(mf);

    rds->rds_enabled = 0;

    if (raw) {
        free(raw);
        raw = NULL;
    }

    /* write back changes */
    RAT_MOD_RAWDATA(mi) = raw;
    RAT_MOD_RAWLEN(mi) = 0;

    return RAT_OK;
}


/* --- functions called by ratools/rad to manage module private data -------- */


/**
 * @brief Set lifetime
 *
 * @param mf                    module helper functions
 * @param mi                    module instance information
 * @param data                  data provided by the parameter's parser function
 * @param len                   maximum length of provided data
 *
 * @return Returns RAT_ERROR on error, RAT_OK otherwise
 */
static int rat_opt_rdnss_set_lifetime (struct rat_mod_functions *mf,
                                       struct rat_mod_instance *mi,
                                       uint8_t *data, uint16_t len)
{
    struct rat_opt_rdnss_private *rds = RAT_MOD_PRIVATE(mi);
    uint32_t lifetime;
    RAT_DEBUG_TRACE();

    if (len < sizeof(lifetime))
        goto exit_err;

    lifetime = *((uint32_t *) data);

    if (lifetime < RAT_OPT_RDNSS_LIFE_MIN(mi->mi_maxadvint)) {
        mf->mf_message("Warning: Invalid lifetime `%" PRIu32 "'!\n" \
                       "Must not be less than maximum interval (%" PRIu32 ").",
                       lifetime, mi->mi_maxadvint);
    }
    if (lifetime > RAT_OPT_RDNSS_LIFE_MAX(mi->mi_maxadvint)) {
        mf->mf_message("Warning: Invalid lifetime `%" PRIu32 "'!\n" \
                       "Must not be more than two times maximum interval " \
                       "(%" PRIu32 ").",
                       lifetime, RAT_OPT_RDNSS_LIFE_MAX(mi->mi_maxadvint));
    }
    rds->rds_lifetime = lifetime;

    return RAT_OK;

exit_err:
    return RAT_ERROR;
}


/**
 * @brief Add server
 *
 * @param mf                    module helper functions
 * @param mi                    module instance information
 * @param data                  data provided by the parameter's parser function
 * @param len                   maximum length of provided data
 *
 * @return Returns RAT_ERROR on error, RAT_OK otherwise
 */
static int rat_opt_rdnss_add_server (struct rat_mod_functions *mf,
                                     struct rat_mod_instance *mi,
                                     uint8_t *data, uint16_t len)
{
    struct rat_opt_rdnss_private *rds = RAT_MOD_PRIVATE(mi);
    struct in6_addr *addr = (struct in6_addr *) data;
    struct rat_opt_rdnss_srv *new, *srv;
    RAT_DEBUG_TRACE();
    RAT_DISCARD_UNUSED(mf);

    if (len < sizeof(*addr))
        goto exit_err;

    if (!rat_lib_6addr_ok(addr)) {
        mf->mf_error("Invalid address!");
        goto exit_err;
    }

    new = rat_opt_rdnss_get_srv(rds->rds_srv, addr);
    if (new) {
        mf->mf_error("Server already exists!");
        goto exit_err;
    }

    new = calloc(1, sizeof(*new));
    if (!new) {
        rat_log_err("Module RDNSS: Out of memory!");
        goto exit_err;
    }
    new->srv_next = NULL;
    memcpy(&new->srv_addr, addr, sizeof(new->srv_addr));

    /* add server to list */
    if (rds->rds_srv) {
        for (srv = rds->rds_srv; srv->srv_next; srv = srv->srv_next);
        srv->srv_next = new;
    } else {
        rds->rds_srv = new;
    }
    return RAT_OK;

exit_err:
    return RAT_ERROR;
}


/**
 * @brief Delete server
 *
 * @param mf                    module helper functions
 * @param mi                    module instance information
 * @param data                  data provided by the parameter's parser function
 * @param len                   maximum length of provided data
 *
 * @return Returns RAT_ERROR on error, RAT_OK otherwise
 */
static int rat_opt_rdnss_del_server (struct rat_mod_functions *mf,
                                     struct rat_mod_instance *mi,
                                     uint8_t *data, uint16_t len)
{
    struct rat_opt_rdnss_private *rds = RAT_MOD_PRIVATE(mi);
    struct in6_addr *addr = (struct in6_addr *) data;
    struct rat_opt_rdnss_srv *srv, *del;
    RAT_DEBUG_TRACE();
    RAT_DISCARD_UNUSED(mf);

    if (len < sizeof(*addr))
        goto exit_err;

    del = rat_opt_rdnss_get_srv(rds->rds_srv, addr);
    if (!del) {
        mf->mf_error("Server not found!");
        goto exit_err;
    }

    /* remove from list */
    if (rds->rds_srv == del) {
        rds->rds_srv = del->srv_next;
    } else if (rds->rds_srv) {
        for (srv = rds->rds_srv; srv->srv_next; srv = srv->srv_next) {
            if (srv->srv_next == del) {
                srv->srv_next = del->srv_next;
                break;
            }
        }
    }
    free(del);

    return RAT_OK;

exit_err:
    return RAT_ERROR;
}

/* --- functions called by ratools/ractl to parse CLI input ----------------- */


/**
 * @brief Set address
 *
 * @param argv                  argument value provided by CLI
 * @param data                  pointer to data part of control message
 * @param len                   maximum available space in control message
 *
 * @return Returns RAT_ERROR on error, RAT_OK otherwise
 */
static int rat_opt_rdnss_set_val_addr (const char *argv,
                                       uint8_t *data, uint16_t len)
{
    struct in6_addr *addr = (struct in6_addr *) data;
    RAT_DEBUG_TRACE();

    if (len < sizeof(*addr))
        goto exit_err;

    return rat_lib_6addr_from_str(addr, argv);

exit_err:
    return RAT_ERROR;
}


/* --- module configuration ------------------------------------------------- */


/**
 * @brief Value parser
 */
static struct rat_mod_valreg rat_opt_rdnss_reg_sad_val_server[] = {
    {
        /*
         * catching a *valid* ipv6 prefix via regex is near to impossible. this
         * is a rough sanity check and the function will test the values for
         * general compliance
         */
        .mvr_regex              = "^[0-9a-f:.]{2," STR(RAT_6ADDR_STRSIZ) "}$",
        .mvr_help               = "2001:db8::53",
        .mvr_parse              = rat_opt_rdnss_set_val_addr,
    }
};


/**
 * @brief Value parser
 */
static struct rat_mod_valreg rat_opt_rdnss_reg_set_val_lifetime[] = {
    {
        .mvr_regex              = "[0-9]{1,10}$",
        .mvr_help               = "300",
        .mvr_parse              = rat_mod_generic_set_val_uint32,
    },
    {
        .mvr_regex              = "^[0-9]{1,2}d" \
                                  "[0-9]{1,2}h" \
                                  "[0-9]{1,2}m" \
                                  "[0-9]{1,2}s$",
        .mvr_help               = "0d0h5m0s",
        .mvr_parse              = rat_mod_generic_set_val_dhminsec32,
    },
    {
        .mvr_regex              = "^no?$|" \
                                  "^not-?$|" \
                                  "^not-va?$|" \
                                  "^not-vali?$|" \
                                  "^not-valid$",
        .mvr_help               = "not-valid",
        .mvr_parse              = rat_mod_generic_set_val_zero32,
    },
    {
        .mvr_regex              = "^in?$|" \
                                  "^infi?$|" \
                                  "^infini?$|" \
                                  "^infinity?$",
        .mvr_help               = "infinity",
        .mvr_parse              = rat_mod_generic_set_val_max32,
    }
};


/**
 * @brief Parameter parser
 */
static struct rat_mod_sadreg rat_opt_rdnss_reg_set[] = {
    {
        .msr_regex              = "^li?$|" \
                                  "^life?$|" \
                                  "^lifeti?$|" \
                                  "^lifetime$",
        .msr_help               = "lifetime",
        .msr_func               = rat_opt_rdnss_set_lifetime,
        .msr_val                = rat_opt_rdnss_reg_set_val_lifetime,
        .msr_vallen             = sizeof(rat_opt_rdnss_reg_set_val_lifetime) / \
                                  sizeof(rat_opt_rdnss_reg_set_val_lifetime[0])
    }
};


/**
 * @brief Parameter parser
 */
static struct rat_mod_sadreg rat_opt_rdnss_reg_add[] = {
    {
        .msr_regex              = "^se?$|" \
                                  "^serv?$|" \
                                  "^server?$",
        .msr_help               = "server",
        .msr_func               = rat_opt_rdnss_add_server,
        .msr_val                = rat_opt_rdnss_reg_sad_val_server,
        .msr_vallen             = sizeof(rat_opt_rdnss_reg_sad_val_server) / \
                                  sizeof(rat_opt_rdnss_reg_sad_val_server[0])
    }
};


/**
 * @brief Parameter parser
 */
static struct rat_mod_sadreg rat_opt_rdnss_reg_del[] = {
    {
        .msr_regex              = "^se?$|" \
                                  "^serv?$|" \
                                  "^server?$",
        .msr_help               = "server",
        .msr_func               = rat_opt_rdnss_del_server,
        .msr_val                = rat_opt_rdnss_reg_sad_val_server,
        .msr_vallen             = sizeof(rat_opt_rdnss_reg_sad_val_server) / \
                                  sizeof(rat_opt_rdnss_reg_sad_val_server[0])
    }
};


/**
 * @brief Module configuration
 */
static struct rat_mod_modreg rat_opt_rdnss_reg = {
    .mmr_regex                  = "^rdnss$",
    .mmr_name                   = "rdnss",
    .mmr_multiple               = 1,
    .mmr_create                 = rat_opt_rdnss_create,
    .mmr_destroy                = rat_opt_rdnss_destroy,
    .mmr_enable                 = rat_opt_rdnss_enable,
    .mmr_disable                = rat_opt_rdnss_disable,
    .mmr_show                   = rat_opt_rdnss_show,
    .mmr_dump                   = rat_opt_rdnss_dump,
    .mmr_kill                   = NULL,
    .mmr_set                    = rat_opt_rdnss_reg_set,
    .mmr_setlen                 = sizeof(rat_opt_rdnss_reg_set) / \
                                  sizeof(rat_opt_rdnss_reg_set[0]),
    .mmr_add                    = rat_opt_rdnss_reg_add,
    .mmr_addlen                 = sizeof(rat_opt_rdnss_reg_add) / \
                                  sizeof(rat_opt_rdnss_reg_add[0]),
    .mmr_del                    = rat_opt_rdnss_reg_del,
    .mmr_dellen                 = sizeof(rat_opt_rdnss_reg_del) / \
                                  sizeof(rat_opt_rdnss_reg_del[0]),
    .mmr_compile                = rat_opt_rdnss_compile
};


/* --- registry function ---------------------------------------------------- */


/**
 * @brief Register this module
 *
 * This function has to be called once by the inclucing program, e.g.
 * ratools/ractl or ratools/rad.
 *
 * @return Returns RAT_ERROR on error, RAT_OK otherwise.
 */
extern int rat_opt_rdnss_init (void)
{
    RAT_DEBUG_TRACE();

    return rat_mod_register(&rat_opt_rdnss_reg);
}
