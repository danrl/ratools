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


#include "opt_pi.h"

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
static int rat_opt_pi_create (struct rat_mod_functions *mf,
                              struct rat_mod_instance *mi)
{
    struct rat_opt_pi_private *pi;
    RAT_DEBUG_TRACE();
    RAT_DISCARD_UNUSED(mf);

    /* allocate memory for module private data */
    pi = calloc(1, sizeof(*pi));
    if (!pi) {
        rat_log_err("Module PI: Out of memory!");
        goto exit_err;
    }

    /* set default values */
    pi->pi_enabled      = 0;
    pi->pi_onlink       = RAT_OPT_PI_ONLINK_DEF;
    pi->pi_auto         = RAT_OPT_PI_AUTO_DEF;
    pi->pi_rtraddr      = RAT_OPT_PI_RTRADDR_DEF;
    pi->pi_valid        = RAT_OPT_PI_VALID_DEF;
    pi->pi_preferred    = RAT_OPT_PI_PREF_DEF;

    /* write back changes */
    RAT_MOD_PRIVATE(mi) = pi;

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
static int rat_opt_pi_compile (struct rat_mod_instance *mi)
{
    struct rat_opt_pi_private *pi = RAT_MOD_PRIVATE(mi);
    struct nd_opt_prefix_info *raw = RAT_MOD_RAWDATA(mi);
    RAT_DEBUG_TRACE();

    if (!pi->pi_enabled)
        goto exit_ok;

    /* allocate memory for raw data */
    if (!raw)
        raw = calloc(1, sizeof(*raw));
    if (!raw) {
        rat_log_err("Module PI: Out of memory!");
        goto exit_err;
    }

    raw->nd_opt_pi_type = ND_OPT_PREFIX_INFORMATION;
    raw->nd_opt_pi_len = 4;
    raw->nd_opt_pi_flags_reserved = 0;
    if (pi->pi_onlink)
        raw->nd_opt_pi_flags_reserved |= ND_OPT_PI_FLAG_ONLINK;
    if (pi->pi_auto)
        raw->nd_opt_pi_flags_reserved |= ND_OPT_PI_FLAG_AUTO;
    if (pi->pi_rtraddr)
        raw->nd_opt_pi_flags_reserved |= ND_OPT_PI_FLAG_RADDR;
    raw->nd_opt_pi_valid_time = htonl(pi->pi_valid);
    raw->nd_opt_pi_preferred_time = htonl(pi->pi_preferred);
    raw->nd_opt_pi_reserved2 = 0;
    memcpy(&raw->nd_opt_pi_prefix, &pi->pi_prefix.pfx_addr,
           sizeof(raw->nd_opt_pi_prefix));
    raw->nd_opt_pi_prefix_len = pi->pi_prefix.pfx_len;

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
static int rat_opt_pi_show (struct rat_mod_functions *mf,
                             struct rat_mod_instance *mi)
{
    struct rat_opt_pi_private *pi = RAT_MOD_PRIVATE(mi);
    char buffer[RAT_PREFIX_STRSIZ];
    RAT_DEBUG_TRACE();

    mf->mf_title(1, "Prefix Information Option `%s':", mi->mi_myname);

    mf->mf_param(1, "State");
    mf->mf_value("%s", pi->pi_enabled ? "Enabled" : "Disabled");
    mf->mf_info(NULL);

    mf->mf_param(1, "On-link Flag");
    mf->mf_value("%s", pi->pi_onlink ? "1" : "0");
    mf->mf_info("%s%s", pi->pi_onlink ? "" : "No ", "On-link Prefix");

    mf->mf_param(1, "Autonomous Flag");
    mf->mf_value("%s", pi->pi_auto ? "1" : "0");
    mf->mf_info("%s%s", pi->pi_auto ? "" : "No ",
                "Autonomous Address Configuration");

    mf->mf_param(1, "Router Address Flag");
    mf->mf_value("%s", pi->pi_rtraddr ? "1" : "0");
    mf->mf_info("%s%s", pi->pi_rtraddr ? "" : "No ",
                "Mobile IPv6 Router Address");

    mf->mf_param(1, "Valid Time");
    mf->mf_value("%" PRIu32, pi->pi_valid);
    if (pi->pi_valid == RAT_OPT_PI_VALID_INF)
        mf->mf_info("Infinity");
    else if (pi->pi_valid == RAT_OPT_PI_VALID_NOT)
        mf->mf_info("Prefix not valid");
    else
        mf->mf_info("%ud %uh %um %us",
                  RAT_MOD_S_D_TO_D(pi->pi_valid),
                  RAT_MOD_S_D_TO_H(pi->pi_valid),
                  RAT_MOD_S_D_TO_M(pi->pi_valid),
                  RAT_MOD_S_D_TO_S(pi->pi_valid));

    mf->mf_param(1, "Preferred Time");
    mf->mf_value("%" PRIu32, pi->pi_preferred);
    if (pi->pi_preferred == RAT_OPT_PI_PREF_INF)
        mf->mf_info("Infinity");
    else if (pi->pi_preferred == RAT_OPT_PI_PREF_NOT)
        mf->mf_info("Prefix not preferred");
    else
        mf->mf_info("%ud %uh %um %us",
                  RAT_MOD_S_D_TO_D(pi->pi_preferred),
                  RAT_MOD_S_D_TO_H(pi->pi_preferred),
                  RAT_MOD_S_D_TO_M(pi->pi_preferred),
                  RAT_MOD_S_D_TO_S(pi->pi_preferred));

    mf->mf_param(1, "Prefix");
    rat_lib_prefix_to_str(buffer, sizeof(buffer), &pi->pi_prefix);
    mf->mf_value("%s", buffer);
    mf->mf_info(NULL);
    if (rat_lib_6addr_is_documentation(&pi->pi_prefix.pfx_addr))
        mf->mf_comment(1, "Warning: Documentation prefix!");
    if (rat_lib_6addr_is_multicast(&pi->pi_prefix.pfx_addr))
        mf->mf_comment(1, "Warning: Multicast prefix!");
    if (rat_lib_6addr_is_linklocal(&pi->pi_prefix.pfx_addr))
        mf->mf_comment(1, "Warning: Link-local prefix!");
    if (rat_lib_6addr_is_unspecified(&pi->pi_prefix.pfx_addr))
        mf->mf_comment(1, "Warning: Unspecified prefix!");
    if (RAT_OPT_PI_PLEN_INVALID(&pi->pi_prefix))
        mf->mf_comment(1, "Warning: Invalid prefix length!");
    else if (!RAT_OPT_PI_PLEN_SLAAC(&pi->pi_prefix))
        mf->mf_comment(1, "Warning: Prefix length not SLAAC-compatible!");

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
static int rat_opt_pi_dump (struct rat_mod_functions *mf,
                             struct rat_mod_instance *mi)
{
    struct rat_opt_pi_private *pi = RAT_MOD_PRIVATE(mi);
    char buffer[RAT_PREFIX_STRSIZ];
    RAT_DEBUG_TRACE();

    mf->mf_message("# Prefix Information Option `%s':", mi->mi_myname);
    mf->mf_message("%s create", mi->mi_myname);

    if (pi->pi_onlink != RAT_OPT_PI_ONLINK_DEF)
        mf->mf_message("%s set on-link-flag %s", mi->mi_myname,
                       pi->pi_onlink ? "on" : "off");

    if (pi->pi_auto != RAT_OPT_PI_AUTO_DEF)
        mf->mf_message("%s set autonomous-flag %s", mi->mi_myname,
                       pi->pi_auto ? "on" : "off");

    if (pi->pi_rtraddr != RAT_OPT_PI_RTRADDR_DEF)
        mf->mf_message("%s set router-address-flag %s", mi->mi_myname,
                       pi->pi_rtraddr ? "on" : "off");

    if (pi->pi_valid != RAT_OPT_PI_VALID_DEF) {
        if (pi->pi_valid == RAT_OPT_PI_VALID_INF) {
            mf->mf_message("%s set valid-time infinity", mi->mi_myname);
        } else if (pi->pi_valid == RAT_OPT_PI_VALID_NOT) {
            mf->mf_message("%s set valid-time not-valid",
                           mi->mi_myname);
        } else {
            mf->mf_message("%s set valid-time %ud%uh%um%us", mi->mi_myname,
                           RAT_MOD_S_D_TO_D(pi->pi_valid),
                           RAT_MOD_S_D_TO_H(pi->pi_valid),
                           RAT_MOD_S_D_TO_M(pi->pi_valid),
                           RAT_MOD_S_D_TO_S(pi->pi_valid));
        }
    }

    if (pi->pi_preferred != RAT_OPT_PI_PREF_DEF) {
        if (pi->pi_preferred == RAT_OPT_PI_PREF_INF) {
            mf->mf_message("%s set preferred-time infinity", mi->mi_myname);
        } else if (pi->pi_preferred == RAT_OPT_PI_PREF_NOT) {
            mf->mf_message("%s set preferred-time not-preferred",
                           mi->mi_myname);
        } else {
            mf->mf_message("%s set preferred-time %ud%uh%um%us", mi->mi_myname,
                           RAT_MOD_S_D_TO_D(pi->pi_preferred),
                           RAT_MOD_S_D_TO_H(pi->pi_preferred),
                           RAT_MOD_S_D_TO_M(pi->pi_preferred),
                           RAT_MOD_S_D_TO_S(pi->pi_preferred));
        }
    }

    rat_lib_prefix_to_str(buffer, sizeof(buffer), &pi->pi_prefix);
    mf->mf_message("%s set prefix %s", mi->mi_myname, buffer);

    if (pi->pi_enabled)
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
static int rat_opt_pi_enable (struct rat_mod_functions *mf,
                               struct rat_mod_instance *mi)
{
    struct rat_opt_pi_private *pi = RAT_MOD_PRIVATE(mi);
    RAT_DEBUG_TRACE();
    RAT_DISCARD_UNUSED(mf);

    pi->pi_enabled = 1;

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
static int rat_opt_pi_disable (struct rat_mod_functions *mf,
                                struct rat_mod_instance *mi)
{
    struct rat_opt_pi_private *pi = RAT_MOD_PRIVATE(mi);
    struct nd_opt_prefix_info *raw = RAT_MOD_RAWDATA(mi);
    RAT_DEBUG_TRACE();
    RAT_DISCARD_UNUSED(mf);

    pi->pi_enabled = 0;

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
 * @brief Set prefix
 *
 * @param mf                    module helper functions
 * @param mi                    module instance information
 * @param data                  data provided by the parameter's parser function
 * @param len                   maximum length of provided data
 *
 * @return Returns RAT_ERROR on error, RAT_OK otherwise
 */
static int rat_opt_pi_set_prefix (struct rat_mod_functions *mf,
                                  struct rat_mod_instance *mi,
                                  uint8_t *data, uint16_t len)
{
    struct rat_opt_pi_private *pi = RAT_MOD_PRIVATE(mi);
    struct rat_prefix *pfx = (struct rat_prefix *) data;
    RAT_DEBUG_TRACE();
    RAT_DISCARD_UNUSED(mf);

    if (len < sizeof(*pfx))
        goto exit_err;

    if (!rat_lib_prefix_ok(pfx)) {
        mf->mf_error("Invalid prefix!");
        goto exit_err;
    }
    memcpy(&pi->pi_prefix, pfx, sizeof(pi->pi_prefix));

    return RAT_OK;

exit_err:
    return RAT_ERROR;
}


/**
 * @brief Set a flag
 *
 * Not to be used without wrapper function!
 *
 * @param flag                  pointer to flag address
 * @param data                  data provided by the parameter's parser function
 * @param len                   maximum length of provided data
 *
 * @return Returns RAT_ERROR on error, RAT_OK otherwise
 */
static int __rat_opt_pi_set_flag (int *flag, uint8_t *data, uint16_t len)
{
    RAT_DEBUG_TRACE();

    if (len < sizeof(int))
        return RAT_ERROR;

    *flag = *((int *) data) ? 1 : 0;

    return RAT_OK;
}


/**
 * @brief Set on-link flag
 *
 * @param mf                    module helper functions
 * @param mi                    module instance information
 * @param data                  data provided by the parameter's parser function
 * @param len                   maximum length of provided data
 *
 * @return Returns RAT_ERROR on error, RAT_OK otherwise
 */
static int rat_opt_pi_set_onlink (struct rat_mod_functions *mf,
                                  struct rat_mod_instance *mi,
                                  uint8_t *data, uint16_t len)
{
    struct rat_opt_pi_private *pi = RAT_MOD_PRIVATE(mi);
    RAT_DEBUG_TRACE();
    RAT_DISCARD_UNUSED(mf);

    return __rat_opt_pi_set_flag(&pi->pi_onlink, data, len);
}


/**
 * @brief Set autonomous flag
 *
 * @param mf                    module helper functions
 * @param mi                    module instance information
 * @param data                  data provided by the parameter's parser function
 * @param len                   maximum length of provided data
 *
 * @return Returns RAT_ERROR on error, RAT_OK otherwise
 */
static int rat_opt_pi_set_auto (struct rat_mod_functions *mf,
                                struct rat_mod_instance *mi,
                                uint8_t *data, uint16_t len)
{
    struct rat_opt_pi_private *pi = RAT_MOD_PRIVATE(mi);
    RAT_DEBUG_TRACE();
    RAT_DISCARD_UNUSED(mf);

    return __rat_opt_pi_set_flag(&pi->pi_auto, data, len);
}


/**
 * @brief Set router address flag
 *
 * @param mf                    module helper functions
 * @param mi                    module instance information
 * @param data                  data provided by the parameter's parser function
 * @param len                   maximum length of provided data
 *
 * @return Returns RAT_ERROR on error, RAT_OK otherwise
 */
static int rat_opt_pi_set_rtraddr (struct rat_mod_functions *mf,
                                   struct rat_mod_instance *mi,
                                   uint8_t *data, uint16_t len)
{
    struct rat_opt_pi_private *pi = RAT_MOD_PRIVATE(mi);
    RAT_DEBUG_TRACE();
    RAT_DISCARD_UNUSED(mf);

    return __rat_opt_pi_set_flag(&pi->pi_rtraddr, data, len);
}


/**
 * @brief Set valid time
 *
 * @param mf                    module helper functions
 * @param mi                    module instance information
 * @param data                  data provided by the parameter's parser function
 * @param len                   maximum length of provided data
 *
 * @return Returns RAT_ERROR on error, RAT_OK otherwise
 */
static int rat_opt_pi_set_valid (struct rat_mod_functions *mf,
                                 struct rat_mod_instance *mi,
                                 uint8_t *data, uint16_t len)
{
    struct rat_opt_pi_private *pi = RAT_MOD_PRIVATE(mi);
    uint32_t valid;
    RAT_DEBUG_TRACE();

    if (len < sizeof(valid))
        goto exit_err;

    valid = *((uint32_t *) data);

    if (valid < pi->pi_preferred) {
        mf->mf_error("Invalid value `%" PRIu32 "'! " \
                     "Must not be less than preferred time (%" PRIu32 ").",
                     valid, pi->pi_preferred);
        goto exit_err;
    }
    pi->pi_valid = valid;

    return RAT_OK;

exit_err:
    return RAT_ERROR;
}


/**
 * @brief Set preferred time
 *
 * @param mf                    module helper functions
 * @param mi                    module instance information
 * @param data                  data provided by the parameter's parser function
 * @param len                   maximum length of provided data
 *
 * @return Returns RAT_ERROR on error, RAT_OK otherwise
 */
static int rat_opt_pi_set_preferred (struct rat_mod_functions *mf,
                                     struct rat_mod_instance *mi,
                                     uint8_t *data, uint16_t len)
{
    struct rat_opt_pi_private *pi = RAT_MOD_PRIVATE(mi);
    uint32_t preferred;
    RAT_DEBUG_TRACE();

    if (len < sizeof(preferred))
        goto exit_err;

    preferred = *((uint32_t *) data);

    if (preferred > pi->pi_valid) {
        mf->mf_error("Invalid value `%" PRIu32 "'! " \
                     "Must not exceed valid time (%" PRIu32 ").",
                     preferred, pi->pi_valid);
        goto exit_err;
    }
    pi->pi_preferred = preferred;

    return RAT_OK;

exit_err:
    return RAT_ERROR;
}


/* --- functions called by ratools/ractl to parse CLI input ----------------- */


/**
 * @brief Set prefix
 *
 * @param argv                  argument value provided by CLI
 * @param data                  pointer to data part of control message
 * @param len                   maximum available space in control message
 *
 * @return Returns RAT_ERROR on error, RAT_OK otherwise
 */
static int rat_opt_pi_set_val_prefix (const char *argv,
                                      uint8_t *data, uint16_t len)
{
    struct rat_prefix *pfx = (struct rat_prefix *) data;
    RAT_DEBUG_TRACE();

    if (len < sizeof(*pfx))
        goto exit_err;

    return rat_lib_prefix_from_str(pfx, argv);

exit_err:
    return RAT_ERROR;
}


/* --- module configuration ------------------------------------------------- */


/**
 * @brief Value parser
 */
static struct rat_mod_valreg rat_opt_pi_reg_set_val_valid[] = {
    {
        .mvr_regex              = "[0-9]{1,10}$",
        .mvr_help               = "2592000",
        .mvr_parse              = rat_mod_generic_set_val_uint32,
    },
    {
        .mvr_regex              = "^[0-9]{1,2}d" \
                                  "[0-9]{1,2}h" \
                                  "[0-9]{1,2}m" \
                                  "[0-9]{1,2}s$",
        .mvr_help               = "30d0h0m0s",
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
 * @brief Value parser
 */
static struct rat_mod_valreg rat_opt_pi_reg_set_val_preferred[] = {
    {
        .mvr_regex              = "[0-9]{1,10}$",
        .mvr_help               = "604800",
        .mvr_parse              = rat_mod_generic_set_val_uint32,
    },
    {
        .mvr_regex              = "^[0-9]{1,2}d" \
                                  "[0-9]{1,2}h" \
                                  "[0-9]{1,2}m" \
                                  "[0-9]{1,2}s$",
        .mvr_help               = "7d0h0m0s",
        .mvr_parse              = rat_mod_generic_set_val_dhminsec32,
    },
    {
        .mvr_regex              = "^no?$|" \
                                  "^not-?$|" \
                                  "^not-pr?$|" \
                                  "^not-pref?$|" \
                                  "^not-prefer?$|" \
                                  "^not-preferre?$|" \
                                  "^not-preferred$",
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
 * @brief Value parser
 */
static struct rat_mod_valreg rat_opt_pi_reg_set_val_prefix[] = {
    {
        /*
         * catching a *valid* ipv6 prefix via regex is near to impossible. this
         * is a rough sanity check and the function will test the values for
         * general compliance
         */
        .mvr_regex              = "^[0-9a-f:.]{2," STR(RAT_6ADDR_STRSIZ) "}" \
                                  "/[0-9]{1,3}$",
        .mvr_help               = "2001:db8::/64",
        .mvr_parse              = rat_opt_pi_set_val_prefix,
    }
};


/**
 * @brief Parameter parser
 */
static struct rat_mod_sadreg rat_opt_pi_reg_set[] = {
    {
        .msr_regex              = "^on?$|" \
                                  "^on-l?$|" \
                                  "^on-lin?$|" \
                                  "^on-link-?$|" \
                                  "^on-link-fl?$|" \
                                  "^on-link-flag?$",
        .msr_help               = "on-link-flag",
        .msr_func               = rat_opt_pi_set_onlink,
        .msr_val                = rat_mod_generic_set_val_flag,
        .msr_vallen             = RAT_MOD_GENERIC_SET_VAL_FLAG_LEN,
    },
    {
        .msr_regex              = "^au?$|" \
                                  "^auto?$|" \
                                  "^autono?$|" \
                                  "^autonomo?$|" \
                                  "^autonomous?$|" \
                                  "^autonomous-f?$|" \
                                  "^autonomous-fla?$|" \
                                  "^autonomous-flag$",
        .msr_help               = "autonomous-flag",
        .msr_func               = rat_opt_pi_set_auto,
        .msr_val                = rat_mod_generic_set_val_flag,
        .msr_vallen             = RAT_MOD_GENERIC_SET_VAL_FLAG_LEN,
    },
    {
        .msr_regex              = "^ro?$|" \
                                  "^rout?$|" \
                                  "^router?$|" \
                                  "^router-a?$|" \
                                  "^router-add?$|" \
                                  "^router-addre?$|" \
                                  "^router-address?$|" \
                                  "^router-address-f?$|" \
                                  "^router-address-fla?$|" \
                                  "^router-address-flag$",
        .msr_help               = "router-address-flag",
        .msr_func               = rat_opt_pi_set_rtraddr,
        .msr_val                = rat_mod_generic_set_val_flag,
        .msr_vallen             = RAT_MOD_GENERIC_SET_VAL_FLAG_LEN,
    },
    {
        .msr_regex              = "^va?$|" \
                                  "^vali?$|" \
                                  "^valid-?$|" \
                                  "^valid-ti?$|" \
                                  "^valid-time?$",
        .msr_help               = "valid-time",
        .msr_func               = rat_opt_pi_set_valid,
        .msr_val                = rat_opt_pi_reg_set_val_valid,
        .msr_vallen             = sizeof(rat_opt_pi_reg_set_val_valid) / \
                                  sizeof(rat_opt_pi_reg_set_val_valid[0])
    },
    {
        .msr_regex              = "^prefer?$|" \
                                  "^preferre?$|" \
                                  "^preferred-?$|" \
                                  "^preferred-ti?$|" \
                                  "^preferred-time?$",
        .msr_help               = "preferred-time",
        .msr_func               = rat_opt_pi_set_preferred,
        .msr_val                = rat_opt_pi_reg_set_val_preferred,
        .msr_vallen             = sizeof(rat_opt_pi_reg_set_val_preferred) / \
                                  sizeof(rat_opt_pi_reg_set_val_preferred[0])
    },
    {
        .msr_regex              = "^prefix?$",
        .msr_help               = "prefix",
        .msr_func               = rat_opt_pi_set_prefix,
        .msr_val                = rat_opt_pi_reg_set_val_prefix,
        .msr_vallen             = sizeof(rat_opt_pi_reg_set_val_prefix) / \
                                  sizeof(rat_opt_pi_reg_set_val_prefix[0])
    }
};


/**
 * @brief Module configuration
 */
static struct rat_mod_modreg rat_opt_pi_reg = {
    .mmr_regex                  = "^pi$",
    .mmr_name                   = "pi",
    .mmr_multiple               = 1,
    .mmr_create                 = rat_opt_pi_create,
    .mmr_destroy                = rat_mod_generic_destroy,
    .mmr_enable                 = rat_opt_pi_enable,
    .mmr_disable                = rat_opt_pi_disable,
    .mmr_show                   = rat_opt_pi_show,
    .mmr_dump                   = rat_opt_pi_dump,
    .mmr_kill                   = NULL,
    .mmr_set                    = rat_opt_pi_reg_set,
    .mmr_setlen                 = sizeof(rat_opt_pi_reg_set) / \
                                  sizeof(rat_opt_pi_reg_set[0]),
    .mmr_add                    = NULL,
    .mmr_addlen                 = 0,
    .mmr_del                    = NULL,
    .mmr_dellen                 = 0,
    .mmr_compile                = rat_opt_pi_compile
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
extern int rat_opt_pi_init (void)
{
    RAT_DEBUG_TRACE();

    return rat_mod_register(&rat_opt_pi_reg);
}
