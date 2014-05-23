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

#include "opt_sll.h"

#include "library.h"
#include "log.h"
#include "module.h"

#include <stdlib.h>
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
static int rat_opt_sll_create (struct rat_mod_functions *mf,
                               struct rat_mod_instance *mi)
{
    struct rat_opt_sll_private *sll;
    RAT_DEBUG_TRACE();
    RAT_DISCARD_UNUSED(mf);

    /* allocate memory for module private data */
    sll = calloc(1, sizeof(*sll));
    if (!sll) {
        rat_log_err("Module SLL: Out of memory!");
        goto exit_err;
    }

    /* set default values */
    sll->sll_enabled    = 0;
    sll->sll_autodetect = RAT_OPT_SLL_AUTO_DEF;
    memcpy(&sll->sll_hwaddr, &mi->mi_hwaddr, sizeof(sll->sll_hwaddr));

    /* write back changes */
    RAT_MOD_PRIVATE(mi) = sll;

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
static int rat_opt_sll_compile (struct rat_mod_instance *mi)
{
    struct rat_opt_sll_private *sll = RAT_MOD_PRIVATE(mi);
    struct nd_opt_hdr *raw = RAT_MOD_RAWDATA(mi);
    uint16_t rawlen;
    RAT_DEBUG_TRACE();

    if (!sll->sll_enabled)
        goto exit_ok;

    if (sll->sll_autodetect)
        rawlen = ALIGN(sizeof(*raw) + sll->sll_hwaddr.hwa_len, 8);
    else
        rawlen = ALIGN(sizeof(*raw) + mi->mi_hwaddr.hwa_len, 8);

    /* allocate memory for raw data */
    if (!raw || RAT_MOD_RAWLEN(mi) != rawlen)
        raw = calloc(1, rawlen);
    if (!raw) {
        rat_log_err("Module SLL: Out of memory!");
        goto exit_err;
    }

    raw->nd_opt_type = ND_OPT_SOURCE_LINKADDR;
    raw->nd_opt_len = rawlen / 8;
    if (sll->sll_autodetect)
        memcpy((uint8_t *) raw + sizeof(*raw), &mi->mi_hwaddr.hwa_addr,
               mi->mi_hwaddr.hwa_len);
    else
        memcpy((uint8_t *) raw + sizeof(*raw), &sll->sll_hwaddr.hwa_addr,
               sll->sll_hwaddr.hwa_len);


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
static int rat_opt_sll_show (struct rat_mod_functions *mf,
                             struct rat_mod_instance *mi)
{
    struct rat_opt_sll_private *sll = RAT_MOD_PRIVATE(mi);
    char buffer[RAT_HWADDR_STRSIZ];
    RAT_DEBUG_TRACE();

    mf->mf_title(mi->mi_in, "Source Link-layer Address Option `%s':",
                 mi->mi_myname);

    mf->mf_param(mi->mi_in, "State");
    mf->mf_value("%s", sll->sll_enabled ? "Enabled" : "Disabled");
    mf->mf_info(NULL);

    mf->mf_param(mi->mi_in, "Auto-detection");
    mf->mf_value("%s", sll->sll_autodetect ? "On" : "Off");
    mf->mf_info(NULL);

    mf->mf_param(mi->mi_in, "Hardware Address");
    if (sll->sll_autodetect) {
        rat_lib_hwaddr_to_str(buffer, sizeof(buffer), &mi->mi_hwaddr);
        mf->mf_value("%s", buffer);
        mf->mf_info(NULL);
    } else {
        rat_lib_hwaddr_to_str(buffer, sizeof(buffer), &sll->sll_hwaddr);
        mf->mf_value("%s", buffer);
        mf->mf_info(NULL);
        if (RAT_OPT_SLL_UNCOMMON(&sll->sll_hwaddr))
            mf->mf_comment(mi->mi_in,
                           "Advertising an uncommon hardware address!");
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
static int rat_opt_sll_dump (struct rat_mod_functions *mf,
                             struct rat_mod_instance *mi)
{
    struct rat_opt_sll_private *sll = RAT_MOD_PRIVATE(mi);
    char buffer[RAT_HWADDR_STRSIZ];
    RAT_DEBUG_TRACE();

    mf->mf_message("# Source Link-layer Address Option `%s'", mi->mi_myname);
    mf->mf_message("%s create", mi->mi_myname);

    if (sll->sll_autodetect != RAT_OPT_SLL_AUTO_DEF) {
        mf->mf_message("%s set auto-detect %s",
                       mi->mi_myname, sll->sll_autodetect ? "on" : "off");
        rat_lib_hwaddr_to_str(buffer, sizeof(buffer), &sll->sll_hwaddr);
        mf->mf_message("%s set link-layer-address %s", mi->mi_myname, buffer);
    }

    if (sll->sll_enabled)
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
static int rat_opt_sll_enable (struct rat_mod_functions *mf,
                               struct rat_mod_instance *mi)
{
    struct rat_opt_sll_private *sll = RAT_MOD_PRIVATE(mi);
    RAT_DEBUG_TRACE();
    RAT_DISCARD_UNUSED(mf);

    sll->sll_enabled = 1;

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
static int rat_opt_sll_disable (struct rat_mod_functions *mf,
                                struct rat_mod_instance *mi)
{
    struct rat_opt_sll_private *sll = RAT_MOD_PRIVATE(mi);
    struct nd_opt_sll *raw = RAT_MOD_RAWDATA(mi);
    RAT_DEBUG_TRACE();
    RAT_DISCARD_UNUSED(mf);

    sll->sll_enabled = 0;

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
 * @brief Set hardware address
 *
 * @param mf                    module helper functions
 * @param mi                    module instance information
 * @param data                  data provided by the parameter's parser function
 * @param len                   maximum length of provided data
 *
 * @return Returns RAT_ERROR on error, RAT_OK otherwise
 */
static int rat_opt_sll_set_hwaddr (struct rat_mod_functions *mf,
                                   struct rat_mod_instance *mi,
                                   uint8_t *data, uint16_t len)
{
    struct rat_opt_sll_private *sll = RAT_MOD_PRIVATE(mi);
    struct rat_hwaddr *hwa = (struct rat_hwaddr *) data;
    RAT_DEBUG_TRACE();
    RAT_DISCARD_UNUSED(mf);

    if (len < sizeof(*hwa))
        goto exit_err;

    if (!rat_lib_hwaddr_ok(hwa)) {
        mf->mf_error("Malformed hardware address!");
        goto exit_err;
    }
    memcpy(&sll->sll_hwaddr, hwa, sizeof(sll->sll_hwaddr));

    return RAT_OK;

exit_err:
    return RAT_ERROR;
}


/**
 * @brief Set auto-detection
 *
 * @param mf                    module helper functions
 * @param mi                    module instance information
 * @param data                  data provided by the parameter's parser function
 * @param len                   maximum length of provided data
 *
 * @return Returns RAT_ERROR on error, RAT_OK otherwise
 */
static int rat_opt_sll_set_autodetect (struct rat_mod_functions *mf,
                                       struct rat_mod_instance *mi,
                                       uint8_t *data, uint16_t len)
{
    struct rat_opt_sll_private *sll = RAT_MOD_PRIVATE(mi);
    RAT_DEBUG_TRACE();
    RAT_DISCARD_UNUSED(mf);

    if (len < sizeof(sll->sll_autodetect))
        goto exit_err;

    sll->sll_autodetect = *((int *) data);

    return RAT_OK;

exit_err:
    return RAT_ERROR;
}


/* --- functions called by ratools/ractl to parse CLI input ----------------- */


/**
 * @brief Set hardware address
 *
 * @param argv                  argument value provided by CLI
 * @param data                  pointer to data part of control message
 * @param len                   maximum available space in control message
 *
 * @return Returns RAT_ERROR on error, RAT_OK otherwise
 */
static int rat_opt_sll_set_val_hwaddr (const char *argv,
                                       uint8_t *data, uint16_t len)
{
    struct rat_hwaddr *hwa = (struct rat_hwaddr *) data;
    RAT_DEBUG_TRACE();

    if (len < sizeof(*hwa))
        goto exit_err;

    return rat_lib_hwaddr_from_str(hwa, argv);

exit_err:
    return RAT_ERROR;
}


/* --- module configuration ------------------------------------------------- */


/**
 * @brief Value parser
 */
static struct rat_mod_valreg rat_opt_sll_reg_set_val_hwaddr[] = {
    {
        .mvr_regex              = "^([0-9a-f]{2}[-:]){5,7}[0-9a-f]{2}$",
        .mvr_help               = "00:13:37:00:ba:be",
        .mvr_parse              = rat_opt_sll_set_val_hwaddr,
    }
};


/**
 * @brief Parameter parser
 */
static struct rat_mod_sadreg rat_opt_sll_reg_set[] = {
    {
        .msr_regex              = "^au?$|" \
                                  "^auto?$|" \
                                  "^auto-d?$|" \
                                  "^auto-det?$|" \
                                  "^auto-detec?$|" \
                                  "^auto-detect$",
        .msr_help               = "auto-detect",
        .msr_func               = rat_opt_sll_set_autodetect,
        .msr_val                = rat_mod_generic_set_val_flag,
        .msr_vallen             = RAT_MOD_GENERIC_SET_VAL_FLAG_LEN,
    },
    {
        .msr_regex              = "^li?$|" \
                                  "^link?$|" \
                                  "^link-l?$|" \
                                  "^link-lay?$|" \
                                  "^link-layer?$|" \
                                  "^link-layer-a?$|" \
                                  "^link-layer-add?$|" \
                                  "^link-layer-addre?$|" \
                                  "^link-layer-address?$",
        .msr_help               = "link-layer-address",
        .msr_func               = rat_opt_sll_set_hwaddr,
        .msr_val                = rat_opt_sll_reg_set_val_hwaddr,
        .msr_vallen             = sizeof(rat_opt_sll_reg_set_val_hwaddr) / \
                                  sizeof(rat_opt_sll_reg_set_val_hwaddr[0])
    }
};


/**
 * @brief Module configuration
 */
static struct rat_mod_modreg rat_opt_sll_reg = {
    .mmr_regex                  = "^sll$",
    .mmr_name                   = "sll",
    .mmr_multiple               = 0,
    .mmr_create                 = rat_opt_sll_create,
    .mmr_destroy                = rat_mod_generic_destroy,
    .mmr_enable                 = rat_opt_sll_enable,
    .mmr_disable                = rat_opt_sll_disable,
    .mmr_show                   = rat_opt_sll_show,
    .mmr_dump                   = rat_opt_sll_dump,
    .mmr_kill                   = NULL,
    .mmr_set                    = rat_opt_sll_reg_set,
    .mmr_setlen                 = sizeof(rat_opt_sll_reg_set) / \
                                  sizeof(rat_opt_sll_reg_set[0]),
    .mmr_add                    = NULL,
    .mmr_addlen                 = 0,
    .mmr_del                    = NULL,
    .mmr_dellen                 = 0,
    .mmr_compile                = rat_opt_sll_compile
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
extern int rat_opt_sll_init (void)
{
    RAT_DEBUG_TRACE();

    return rat_mod_register(&rat_opt_sll_reg);
}
