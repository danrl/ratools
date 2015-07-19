/** @file */
/*
 * ratools: Router Advertisement Tools
 *
 * Copyright 2013-2015 Dan Luedtke <mail@danrl.de>
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


#include "opt_cpuri.h"

#include "library.h"
#include "log.h"
#include "module.h"

#include <stdlib.h>
#include <string.h>
#include <netinet/icmp6.h>


/* --- functions called by ratools/rad to maintain module ------------------- */


/**
 * @brief Create new option
 *
 * @param mf                    module helper functions
 * @param mi                    module instance information
 *
 * @return Returns RAT_ERROR on error, RAT_OK otherwise
 */
static int rat_opt_cpuri_create (struct rat_mod_functions *mf,
                                 struct rat_mod_instance *mi)
{
    struct rat_opt_cpuri_private *cp;
    RAT_DEBUG_TRACE();
    RAT_DISCARD_UNUSED(mf);

    /* allocate memory for module private data */
    cp = calloc(1, sizeof(*cp));
    if (!cp) {
        rat_log_err("Module CPURI: Out of memory!");
        goto exit_err;
    }

    /* set default values */
    cp->cp_enabled = 0;

    /* write back changes */
    RAT_MOD_PRIVATE(mi) = cp;

    return RAT_OK;

exit_err:
    return RAT_ERROR;
}


/**
 * @brief Compile option
 *
 * @param mi                    module instance information
 *
 * @return Returns RAT_ERROR on error, RAT_OK otherwise
 */
static int rat_opt_cpuri_compile (struct rat_mod_instance *mi)
{
    struct rat_opt_cpuri_private *cp = RAT_MOD_PRIVATE(mi);
    uint8_t *raw = RAT_MOD_RAWDATA(mi);
    uint16_t rawlen;
    RAT_DEBUG_TRACE();

    if (!cp->cp_enabled)
        goto exit_ok;

    rawlen = ALIGN(2 + MIN(strlen(cp->cp_uri), RAT_OPT_CPURI_URI_STRLEN), 8);

    /* allocate memory for raw data */
    if (!raw)
        raw = calloc(1, rawlen);
    if (!raw) {
        rat_log_err("Module CPURI: Out of memory!");
        goto exit_err;
    }

    raw[0] = RAT_OPT_CPURI_TYPE;
    raw[1] = rawlen / 8;

    memcpy(((uint8_t *) raw) + 2, &cp->cp_uri,
           MIN(strlen(cp->cp_uri), RAT_OPT_CPURI_URI_STRLEN));

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
static int rat_opt_cpuri_show (struct rat_mod_functions *mf,
                               struct rat_mod_instance *mi)
{
    struct rat_opt_cpuri_private *cp = RAT_MOD_PRIVATE(mi);
    RAT_DEBUG_TRACE();

    mf->mf_title(mi->mi_in, "Captive Portal URI Option `%s':", mi->mi_myname);

    mf->mf_param(mi->mi_in, "State");
    mf->mf_value("%s", cp->cp_enabled ? "Enabled" : "Disabled");
    mf->mf_info(NULL);

    mf->mf_param(mi->mi_in, "URI");
    mf->mf_value("%s", cp->cp_uri);
    mf->mf_info(NULL);

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
static int rat_opt_cpuri_dump (struct rat_mod_functions *mf,
                             struct rat_mod_instance *mi)
{
    struct rat_opt_cpuri_private *cp = RAT_MOD_PRIVATE(mi);
    RAT_DEBUG_TRACE();

    mf->mf_message("# Captive Portal Option `%s':", mi->mi_myname);
    mf->mf_message("%s create", mi->mi_myname);

    if (strlen(cp->cp_uri)) {
        mf->mf_message("%s set payload \"%s\"", mi->mi_myname, cp->cp_uri);
    }

    if (cp->cp_enabled)
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
static int rat_opt_cpuri_enable (struct rat_mod_functions *mf,
                                 struct rat_mod_instance *mi)
{
    struct rat_opt_cpuri_private *cp = RAT_MOD_PRIVATE(mi);
    RAT_DEBUG_TRACE();
    RAT_DISCARD_UNUSED(mf);

    cp->cp_enabled = 1;

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
static int rat_opt_cpuri_disable (struct rat_mod_functions *mf,
                                  struct rat_mod_instance *mi)
{
    struct rat_opt_cpuri_private *cp = RAT_MOD_PRIVATE(mi);
    void *raw = RAT_MOD_RAWDATA(mi);
    RAT_DEBUG_TRACE();
    RAT_DISCARD_UNUSED(mf);

    cp->cp_enabled = 0;

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
 * @brief Set value URI
 *
 * @param mf                    module helper functions
 * @param mi                    module instance information
 * @param data                  data provided by the parameter's parser function
 * @param len                   maximum length of provided data
 *
 * @return Returns RAT_ERROR on error, RAT_OK otherwise
 */
static int rat_opt_cpuri_set_uri (struct rat_mod_functions *mf,
                                  struct rat_mod_instance *mi,
                                  uint8_t *data, uint16_t len)
{
    struct rat_opt_cpuri_private *cp = RAT_MOD_PRIVATE(mi);
    const char *uri = (const char *) data;
    RAT_DEBUG_TRACE();
    RAT_DISCARD_UNUSED(len);

    if (strlen(uri) > RAT_OPT_CPURI_URI_STRLEN) {
        mf->mf_error("URI too long!");
        goto exit_err;
    }

    memset(&cp->cp_uri, 0x0, sizeof(cp->cp_uri));
    strncpy(cp->cp_uri, uri, RAT_OPT_CPURI_URI_STRLEN);

    return RAT_OK;

exit_err:
    return RAT_ERROR;
}


/* --- functions called by ratools/ractl to parse CLI input ----------------- */


/**
 * @brief Parse value URI
 *
 * @param argv                  argument value provided by CLI
 * @param data                  pointer to data part of control message
 * @param len                   maximum available space in control message
 *
 * @return Returns RAT_ERROR on error, RAT_OK otherwise
 */
static int rat_opt_cpuri_set_val_uri (const char *argv,
                                      uint8_t *data, uint16_t len)
{
    RAT_DEBUG_TRACE();

    if (strlen(argv) > len || strlen(argv) > RAT_OPT_CPURI_URI_STRLEN)
        goto exit_err;

    memcpy(data, argv, MIN(strlen(argv), len));

    return RAT_OK;

exit_err:
    return RAT_ERROR;
}


/* --- module configuration ------------------------------------------------- */


/**
 * @brief Value parser
 */
static struct rat_mod_valreg rat_opt_cpuri_reg_set_val_uri[] = {
    {
/*
        .mvr_regex              = "^[:graph:]{1," \
                                  STR(RAT_OPT_CPURI_URI_MAXLEN) "}$",
*/
        .mvr_regex              = "^.+$",
        .mvr_help               = "http://example.com/portal.html",
        .mvr_parse              = rat_opt_cpuri_set_val_uri
    }
};


/**
 * @brief Parameter parser
 */
static struct rat_mod_sadreg rat_opt_cpuri_reg_set[] = {
    {
        .msr_regex              = "^ur?$|" \
                                  "^uri$",
        .msr_help               = "uri",
        .msr_func               = rat_opt_cpuri_set_uri,
        .msr_val                = rat_opt_cpuri_reg_set_val_uri,
        .msr_vallen             = sizeof(rat_opt_cpuri_reg_set_val_uri) / \
                                  sizeof(rat_opt_cpuri_reg_set_val_uri[0])
    }
};


/**
 * @brief Module configuration
 */
static struct rat_mod_modreg rat_opt_cpuri_reg = {
    .mmr_regex                  = "^cpuri$",
    .mmr_name                   = "cpuri",
    .mmr_multiple               = 1,
    .mmr_create                 = rat_opt_cpuri_create,
    .mmr_destroy                = rat_mod_generic_destroy,
    .mmr_enable                 = rat_opt_cpuri_enable,
    .mmr_disable                = rat_opt_cpuri_disable,
    .mmr_show                   = rat_opt_cpuri_show,
    .mmr_dump                   = rat_opt_cpuri_dump,
    .mmr_kill                   = NULL,
    .mmr_set                    = rat_opt_cpuri_reg_set,
    .mmr_setlen                 = sizeof(rat_opt_cpuri_reg_set) / \
                                  sizeof(rat_opt_cpuri_reg_set[0]),
    .mmr_add                    = NULL,
    .mmr_addlen                 = 0,
    .mmr_del                    = NULL,
    .mmr_dellen                 = 0,
    .mmr_compile                = rat_opt_cpuri_compile
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
extern int rat_opt_cpuri_init (void)
{
    RAT_DEBUG_TRACE();

    return rat_mod_register(&rat_opt_cpuri_reg);
}
