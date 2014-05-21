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


#include "opt_mtu.h"

#include "log.h"
#include "module.h"

#include <stdlib.h>
#include <stdio.h>
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
static int rat_opt_mtu_create (struct rat_mod_functions *mf,
                               struct rat_mod_instance *mi)
{
    struct rat_opt_mtu_private *mtu;
    RAT_DEBUG_TRACE();
    RAT_DISCARD_UNUSED(mf);

    /* allocate memory for module private data */
    mtu = calloc(1, sizeof(*mtu));
    if (!mtu) {
        rat_log_err("Module MTU: Out of memory!");
        goto exit_err;
    }

    /* set default values */
    mtu->mtu_enabled    = 0;
    mtu->mtu_autodetect = RAT_OPT_MTU_AUTO_DEF;
    mtu->mtu_linkmtu    = RAT_OPT_MTU_DEF;

    /* write back changes */
    RAT_MOD_PRIVATE(mi) = mtu;

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
static int rat_opt_mtu_compile (struct rat_mod_instance *mi)
{
    struct rat_opt_mtu_private *mtu = RAT_MOD_PRIVATE(mi);
    struct nd_opt_mtu *raw = RAT_MOD_RAWDATA(mi);
    RAT_DEBUG_TRACE();

    if (!mtu->mtu_enabled)
        goto exit_ok;

    /* allocate memory for raw data */
    if (!raw)
        raw = calloc(1, sizeof(*raw));
    if (!raw) {
        rat_log_err("Module MTU: Out of memory!");
        goto exit_err;
    }

    raw->nd_opt_mtu_type = ND_OPT_MTU;
    raw->nd_opt_mtu_len = 1;
    raw->nd_opt_mtu_reserved = 0;
    if (mtu->mtu_autodetect)
        raw->nd_opt_mtu_mtu = htonl(mi->mi_linkmtu);
    else
        raw->nd_opt_mtu_mtu = htonl(mtu->mtu_linkmtu);

    /* write back changes */
    RAT_MOD_RAWDATA(mi) = raw;
    RAT_MOD_RAWLEN(mi) = sizeof(*raw);

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
static int rat_opt_mtu_show (struct rat_mod_functions *mf,
                             struct rat_mod_instance *mi)
{
    struct rat_opt_mtu_private *mtu = RAT_MOD_PRIVATE(mi);
    RAT_DEBUG_TRACE();

    mf->mf_title(1, "Link-MTU Option `%s':", mi->mi_myname);

    mf->mf_param(1, "State");
    mf->mf_value("%s", mtu->mtu_enabled ? "Enabled" : "Disabled");
    mf->mf_info(NULL);

    mf->mf_param(1, "Auto-detection");
    mf->mf_value("%s", mtu->mtu_autodetect ? "On" : "Off");
    mf->mf_info(NULL);

    mf->mf_param(1, "Link-MTU");
    if (mtu->mtu_autodetect) {
        mf->mf_value("%" PRIu32, mi->mi_linkmtu);
        mf->mf_info(NULL);
    } else {
        mf->mf_value("%" PRIu32, mtu->mtu_linkmtu);
        mf->mf_info(NULL);
        if (RAT_OPT_MTU_UNCOMMON(mtu->mtu_linkmtu))
            mf->mf_comment(1, "Advertising an uncommon link MTU!");
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
static int rat_opt_mtu_dump (struct rat_mod_functions *mf,
                             struct rat_mod_instance *mi)
{
    struct rat_opt_mtu_private *mtu = RAT_MOD_PRIVATE(mi);
    RAT_DEBUG_TRACE();

    mf->mf_message("# Link MTU Option `%s'", mi->mi_myname);
    mf->mf_message("%s create", mi->mi_myname);

    if (mtu->mtu_autodetect != RAT_OPT_MTU_AUTO_DEF) {
        mf->mf_message("%s set auto-detect %s",
                       mi->mi_myname, mtu->mtu_autodetect ? "on" : "off");
    } else {
        if (mtu->mtu_linkmtu != RAT_OPT_MTU_DEF)
            mf->mf_message("%s set link-mtu %" PRIu16,
                           mi->mi_myname, mtu->mtu_linkmtu);
    }

    if (mtu->mtu_enabled)
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
static int rat_opt_mtu_enable (struct rat_mod_functions *mf,
                               struct rat_mod_instance *mi)
{
    struct rat_opt_mtu_private *mtu = RAT_MOD_PRIVATE(mi);
    RAT_DEBUG_TRACE();
    RAT_DISCARD_UNUSED(mf);

    mtu->mtu_enabled = 1;

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
static int rat_opt_mtu_disable (struct rat_mod_functions *mf,
                                struct rat_mod_instance *mi)
{
    struct rat_opt_mtu_private *mtu = RAT_MOD_PRIVATE(mi);
    struct nd_opt_mtu *raw = RAT_MOD_RAWDATA(mi);
    RAT_DEBUG_TRACE();
    RAT_DISCARD_UNUSED(mf);

    mtu->mtu_enabled = 0;

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
 * @brief Set link-mtu
 *
 * @param mf                    module helper functions
 * @param mi                    module instance information
 * @param data                  data provided by the parameter's parser function
 * @param len                   maximum length of provided data
 *
 * @return Returns RAT_ERROR on error, RAT_OK otherwise
 */
static int rat_opt_mtu_set_linkmtu (struct rat_mod_functions *mf,
                                    struct rat_mod_instance *mi,
                                    uint8_t *data, uint16_t len)
{
    struct rat_opt_mtu_private *mtu = RAT_MOD_PRIVATE(mi);
    uint32_t linkmtu;
    RAT_DEBUG_TRACE();
    RAT_DISCARD_UNUSED(mf);

    if (len < sizeof(linkmtu))
        goto exit_err;

    linkmtu = *((uint32_t *) data);


    mtu->mtu_linkmtu = linkmtu;

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
static int rat_opt_mtu_set_autodetect (struct rat_mod_functions *mf,
                                       struct rat_mod_instance *mi,
                                       uint8_t *data, uint16_t len)
{
    struct rat_opt_mtu_private *mtu = RAT_MOD_PRIVATE(mi);
    RAT_DEBUG_TRACE();
    RAT_DISCARD_UNUSED(mf);

    if (len < sizeof(mtu->mtu_autodetect))
        goto exit_err;

    mtu->mtu_autodetect = *((int *) data);

    return RAT_OK;

exit_err:
    return RAT_ERROR;
}


/* --- functions called by ratools/ractl to parse CLI input ----------------- */



/* --- module configuration ------------------------------------------------- */


/**
 * @brief Value parser
 */
static struct rat_mod_valreg rat_opt_mtu_reg_set_linkmtu[] = {
    {
        .mvr_regex              = "[0-9]{1,10}$",
        .mvr_help               = "1500",
        .mvr_parse              = rat_mod_generic_set_val_uint32,
    },
    {
        .mvr_regex              = "^un?$|" \
                                  "^unsp?$|" \
                                  "^unspec?$|" \
                                  "^unspecif?$|" \
                                  "^unspecifie?$|" \
                                  "^unspecified$",
        .mvr_help               = "unspecified",
        .mvr_parse              = rat_mod_generic_set_val_zero32,
    }
};


/**
 * @brief Parameter parser
 */
static struct rat_mod_sadreg rat_opt_mtu_reg_set[] = {
    {
        .msr_regex              = "^au?$|" \
                                  "^auto?$|" \
                                  "^auto-d?$|" \
                                  "^auto-det?$|" \
                                  "^auto-detec?$|" \
                                  "^auto-detect$",
        .msr_help               = "auto-detect",
        .msr_func               = rat_opt_mtu_set_autodetect,
        .msr_val                = rat_mod_generic_set_val_flag,
        .msr_vallen             = RAT_MOD_GENERIC_SET_VAL_FLAG_LEN,
    },
    {
        .msr_regex              = "^li?$|" \
                                  "^link?$|" \
                                  "^link-m?$|" \
                                  "^link-mtu?$",
        .msr_help               = "link-mtu",
        .msr_func               = rat_opt_mtu_set_linkmtu,
        .msr_val                = rat_opt_mtu_reg_set_linkmtu,
        .msr_vallen             = sizeof(rat_opt_mtu_reg_set_linkmtu) / \
                                  sizeof(rat_opt_mtu_reg_set_linkmtu[0])
    }
};


/**
 * @brief Module configuration
 */
static struct rat_mod_modreg rat_opt_mtu_reg = {
    .mmr_regex                  = "^mtu$",
    .mmr_name                   = "mtu",
    .mmr_multiple               = 0,
    .mmr_create                 = rat_opt_mtu_create,
    .mmr_destroy                = rat_mod_generic_destroy,
    .mmr_enable                 = rat_opt_mtu_enable,
    .mmr_disable                = rat_opt_mtu_disable,
    .mmr_show                   = rat_opt_mtu_show,
    .mmr_dump                   = rat_opt_mtu_dump,
    .mmr_kill                   = NULL,
    .mmr_set                    = rat_opt_mtu_reg_set,
    .mmr_setlen                 = sizeof(rat_opt_mtu_reg_set) / \
                                  sizeof(rat_opt_mtu_reg_set[0]),
    .mmr_add                    = NULL,
    .mmr_addlen                 = 0,
    .mmr_del                    = NULL,
    .mmr_dellen                 = 0,
    .mmr_compile                = rat_opt_mtu_compile
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
extern int rat_opt_mtu_init (void)
{
    RAT_DEBUG_TRACE();

    return rat_mod_register(&rat_opt_mtu_reg);
}
