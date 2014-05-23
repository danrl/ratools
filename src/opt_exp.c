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


#include "opt_exp.h"

#include "library.h"
#include "log.h"
#include "module.h"

#include <stdlib.h>
#include <string.h>
#include <netinet/icmp6.h>


/**
 * @brief Convert payload to asciiz string
 *
 * @param buf                   string buffer
 * @param buflen                string buffer length
 * @param exp                   experimental option private data
 *
 * @return Returns RAT_ERROR on error, RAT_OK otherwise
 */
static int rat_opt_exp_payload_to_str (char *buf, size_t buflen,
                                       struct rat_opt_exp_private *exp)
{
    uint16_t i, len;

    if (!buf || !buflen)
        goto exit_err;

    memset(buf, 0x0, buflen);
    len = MIN(exp->exp_len, (buflen - 1) / 2);
    for (i = 0; i < len; i++)
        snprintf(&buf[2 * i], 3, "%02x", exp->exp_payload[i]);

    return RAT_OK;

exit_err:
    return RAT_ERROR;
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
static int rat_opt_exp_create (struct rat_mod_functions *mf,
                               struct rat_mod_instance *mi)
{
    struct rat_opt_exp_private *exp;
    RAT_DEBUG_TRACE();
    RAT_DISCARD_UNUSED(mf);

    /* allocate memory for module private data */
    exp = calloc(1, sizeof(*exp));
    if (!exp) {
        rat_log_err("Module PI: Out of memory!");
        goto exit_err;
    }

    /* set default values */
    exp->exp_enabled     = 0;
    exp->exp_type        = RAT_OPT_EXP_TYPE_DEF;
    exp->exp_len         = RAT_OPT_EXP_LEN_DEF;

    /* write back changes */
    RAT_MOD_PRIVATE(mi) = exp;

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
static int rat_opt_exp_compile (struct rat_mod_instance *mi)
{
    struct rat_opt_exp_private *exp = RAT_MOD_PRIVATE(mi);
    uint8_t *raw = RAT_MOD_RAWDATA(mi);
    uint16_t rawlen;
    RAT_DEBUG_TRACE();

    if (!exp->exp_enabled)
        goto exit_ok;

    rawlen = ALIGN(2 + MIN(exp->exp_len, RAT_OPT_EXP_PAYLOAD_MAXLEN), 8);

    /* allocate memory for raw data */
    if (!raw)
        raw = calloc(1, rawlen);
    if (!raw) {
        rat_log_err("Module EXP: Out of memory!");
        goto exit_err;
    }

    raw[0] = exp->exp_type;
    raw[1] = rawlen / 8;

    memcpy(((uint8_t *) raw) + 2, &exp->exp_payload,
           MIN(sizeof(exp->exp_payload), exp->exp_len));

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
static int rat_opt_exp_show (struct rat_mod_functions *mf,
                             struct rat_mod_instance *mi)
{
    struct rat_opt_exp_private *exp = RAT_MOD_PRIVATE(mi);
    char buffer[MAX(
                    RAT_OPT_EXP_PAYLOAD_STRSIZ,
                    RAT_BYTES_STRSIZ
                )];
    RAT_DEBUG_TRACE();

    mf->mf_title(mi->mi_in, "Experimental Option `%s':", mi->mi_myname);

    mf->mf_param(mi->mi_in, "State");
    mf->mf_value("%s", exp->exp_enabled ? "Enabled" : "Disabled");
    mf->mf_info(NULL);

    mf->mf_param(mi->mi_in, "Type");
    mf->mf_value("%" PRIu8, exp->exp_type);
    mf->mf_info(NULL);

    mf->mf_param(mi->mi_in, "Payload Length");
    mf->mf_value("%" PRIu8, exp->exp_len);
    rat_lib_bytes_to_str(buffer, sizeof(buffer), exp->exp_len);
    mf->mf_info(buffer);

    mf->mf_param(mi->mi_in, "Payload");
    rat_opt_exp_payload_to_str(buffer, sizeof(buffer), exp);
    mf->mf_value("%s", buffer);
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
static int rat_opt_exp_dump (struct rat_mod_functions *mf,
                             struct rat_mod_instance *mi)
{
    struct rat_opt_exp_private *exp = RAT_MOD_PRIVATE(mi);
    char buffer[RAT_OPT_EXP_PAYLOAD_STRSIZ];
    RAT_DEBUG_TRACE();

    mf->mf_message("# Experimental Option `%s':", mi->mi_myname);
    mf->mf_message("%s create", mi->mi_myname);

    if (exp->exp_type != RAT_OPT_EXP_TYPE_DEF)
        mf->mf_message("%s set type %" PRIu8, mi->mi_myname, exp->exp_type);

    if (exp->exp_len) {
        rat_opt_exp_payload_to_str(buffer, sizeof(buffer), exp);
        mf->mf_message("%s set payload %s", mi->mi_myname, buffer);
    }

    if (exp->exp_enabled)
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
static int rat_opt_exp_enable (struct rat_mod_functions *mf,
                               struct rat_mod_instance *mi)
{
    struct rat_opt_exp_private *exp = RAT_MOD_PRIVATE(mi);
    RAT_DEBUG_TRACE();
    RAT_DISCARD_UNUSED(mf);

    exp->exp_enabled = 1;

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
static int rat_opt_exp_disable (struct rat_mod_functions *mf,
                                struct rat_mod_instance *mi)
{
    struct rat_opt_exp_private *exp = RAT_MOD_PRIVATE(mi);
    struct nd_opt_prefix_info *raw = RAT_MOD_RAWDATA(mi);
    RAT_DEBUG_TRACE();
    RAT_DISCARD_UNUSED(mf);

    exp->exp_enabled = 0;

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
 * @brief Set type
 *
 * @param mf                    module helper functions
 * @param mi                    module instance information
 * @param data                  data provided by the parameter's parser function
 * @param len                   maximum length of provided data
 *
 * @return Returns RAT_ERROR on error, RAT_OK otherwise
 */
static int rat_opt_exp_set_type (struct rat_mod_functions *mf,
                                 struct rat_mod_instance *mi,
                                 uint8_t *data, uint16_t len)
{
    struct rat_opt_exp_private *exp = RAT_MOD_PRIVATE(mi);
    RAT_DEBUG_TRACE();
    RAT_DISCARD_UNUSED(mf);

    if (len < sizeof(uint8_t))
        goto exit_err;

    /* no further checks required */
    exp->exp_type = *((uint8_t *) data);

    return RAT_OK;

exit_err:
    return RAT_ERROR;
}


#include <stdio.h>

/**
 * @brief Set payload
 *
 * @param mf                    module helper functions
 * @param mi                    module instance information
 * @param data                  data provided by the parameter's parser function
 * @param len                   maximum length of provided data
 *
 * @return Returns RAT_ERROR on error, RAT_OK otherwise
 */
static int rat_opt_exp_set_payload (struct rat_mod_functions *mf,
                                    struct rat_mod_instance *mi,
                                    uint8_t *data, uint16_t len)
{
    struct rat_opt_exp_private *exp = RAT_MOD_PRIVATE(mi);
    struct rat_opt_exp_transfer *et = (struct rat_opt_exp_transfer *) data;
    RAT_DEBUG_TRACE();

    if (len < sizeof(*et))
        goto exit_err;

    if (et->et_len > RAT_OPT_EXP_PAYLOAD_MAXLEN) {
        mf->mf_error("Payload too large!");
        goto exit_err;
    }

    exp->exp_len = MIN(et->et_len, RAT_OPT_EXP_PAYLOAD_MAXLEN);
    memcpy(&exp->exp_payload, &et->et_payload, exp->exp_len);

    return RAT_OK;

exit_err:
    return RAT_ERROR;
}


/* --- functions called by ratools/ractl to parse CLI input ----------------- */


/**
 * @brief Parse payload
 *
 * @param argv                  argument value provided by CLI
 * @param data                  pointer to data part of control message
 * @param len                   maximum available space in control message
 *
 * @return Returns RAT_ERROR on error, RAT_OK otherwise
 */
static int rat_opt_exp_set_val_payload (const char *argv,
                                        uint8_t *data, uint16_t len)
{
    struct rat_opt_exp_transfer *et = (struct rat_opt_exp_transfer *) data;
    uint16_t i;
    unsigned int tmp;
    RAT_DEBUG_TRACE();

    if (len < sizeof(*et) || strlen(argv) >= RAT_OPT_EXP_PAYLOAD_STRSIZ)
        goto exit_err;

    et->et_len = MIN(strlen(argv) / 2, sizeof(et->et_payload));
    for (i = 0; i < et->et_len; i++) {
        sscanf(&argv[i * 2], "%02x", &tmp);
        et->et_payload[i] = (uint8_t) tmp;
    }

    return RAT_OK;

exit_err:
    return RAT_ERROR;
}


/* --- module configuration ------------------------------------------------- */


/**
 * @brief Value parser
 */
static struct rat_mod_valreg rat_opt_exp_reg_set_val_type[] = {
    {
        .mvr_regex              = "[0-9]{1,3}$",
        .mvr_help               = "253",
        .mvr_parse              = rat_mod_generic_set_val_uint8,
    }
};


/**
 * @brief Value parser
 */
static struct rat_mod_valreg rat_opt_exp_reg_set_val_payload[] = {
    {
        .mvr_regex              = "^([0-9a-f]{2}){1,"               \
                                  STR(RAT_OPT_EXP_PAYLOAD_MAXLEN)   \
                                  "}$",
        .mvr_help               = "babe1337",
        .mvr_parse              = rat_opt_exp_set_val_payload,
    }
};


/**
 * @brief Parameter parser
 */
static struct rat_mod_sadreg rat_opt_exp_reg_set[] = {
    {
        .msr_regex              = "^ty?$|" \
                                  "^type?$",
        .msr_help               = "type",
        .msr_func               = rat_opt_exp_set_type,
        .msr_val                = rat_opt_exp_reg_set_val_type,
        .msr_vallen             = sizeof(rat_opt_exp_reg_set_val_type) / \
                                  sizeof(rat_opt_exp_reg_set_val_type[0])
    },
    {
        .msr_regex              = "^pa?$|" \
                                  "^payl?$|" \
                                  "^payloa?$|" \
                                  "^payload$",
        .msr_help               = "payload",
        .msr_func               = rat_opt_exp_set_payload,
        .msr_val                = rat_opt_exp_reg_set_val_payload,
        .msr_vallen             = sizeof(rat_opt_exp_reg_set_val_payload) / \
                                  sizeof(rat_opt_exp_reg_set_val_payload[0])
    }
};


/**
 * @brief Module configuration
 */
static struct rat_mod_modreg rat_opt_exp_reg = {
    .mmr_regex                  = "^exp$",
    .mmr_name                   = "exp",
    .mmr_multiple               = 1,
    .mmr_create                 = rat_opt_exp_create,
    .mmr_destroy                = rat_mod_generic_destroy,
    .mmr_enable                 = rat_opt_exp_enable,
    .mmr_disable                = rat_opt_exp_disable,
    .mmr_show                   = rat_opt_exp_show,
    .mmr_dump                   = rat_opt_exp_dump,
    .mmr_kill                   = NULL,
    .mmr_set                    = rat_opt_exp_reg_set,
    .mmr_setlen                 = sizeof(rat_opt_exp_reg_set) / \
                                  sizeof(rat_opt_exp_reg_set[0]),
    .mmr_add                    = NULL,
    .mmr_addlen                 = 0,
    .mmr_del                    = NULL,
    .mmr_dellen                 = 0,
    .mmr_compile                = rat_opt_exp_compile
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
extern int rat_opt_exp_init (void)
{
    RAT_DEBUG_TRACE();

    return rat_mod_register(&rat_opt_exp_reg);
}
