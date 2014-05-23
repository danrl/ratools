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


#include "ra.h"

#include "library.h"
#include "log.h"
#include "module.h"

#include <stdlib.h>
#include <stdio.h>
#include <netinet/icmp6.h>


/* --- functions called by ratools/rad to maintain module ------------------- */


/**
 * @brief Create new RA
 *
 * @param mf                    module helper functions
 * @param mi                    module instance information
 *
 * @return Returns RAT_ERROR on error, RAT_OK otherwise
 */
static int rat_ra_create (struct rat_mod_functions *mf,
                          struct rat_mod_instance *mi)
{
    struct rat_ra_private *ra;
    RAT_DEBUG_TRACE();
    RAT_DISCARD_UNUSED(mf);

    /* allocate memory for module private data */
    ra = calloc(1, sizeof(*ra));
    if (!ra) {
        rat_log_err("Module RA: Out of memory!");
        goto exit_err;
    }

    /* set default values */
    ra->ra_curhl        = RAT_RA_CURHL_DEF;
    ra->ra_managed      = RAT_RA_MANAGED_DEF;
    ra->ra_other        = RAT_RA_OTHER_DEF;
    ra->ra_homeagent    = RAT_RA_HOMEAGENT_DEF;
    ra->ra_preference   = RAT_RA_PREFERENCE_DEF;
    ra->ra_proxy        = RAT_RA_PROXY_DEF;
    ra->ra_lifetime     = RAT_RA_LIFETIME_DEF;
    ra->ra_reachable    = RAT_RA_REACHABLE_DEF;
    ra->ra_retrans      = RAT_RA_RETRANS_DEF;

    /* write back changes */
    RAT_MOD_PRIVATE(mi) = ra;

    return RAT_OK;

exit_err:
    return RAT_ERROR;
}


/**
 * @brief Compile RA
 *
 * @param mi                    module instance information
 *
 * @return Returns RAT_ERROR on error, RAT_OK otherwise
 */
static int rat_ra_compile (struct rat_mod_instance *mi)
{
    struct rat_ra_private *ra = RAT_MOD_PRIVATE(mi);
    struct nd_router_advert *nra = RAT_MOD_RAWDATA(mi);
    RAT_DEBUG_TRACE();

    /* allocate memory for raw data */
    if (!nra)
        nra = calloc(1, sizeof(*nra));
    if (!nra) {
        rat_log_err("Module RA: Out of memory!");
        goto exit_err;
    }

    nra->nd_ra_type = ND_ROUTER_ADVERT;
    nra->nd_ra_curhoplimit = ra->ra_curhl;
    if (ra->ra_managed)
        nra->nd_ra_flags_reserved |= ND_RA_FLAG_MANAGED;
    if (ra->ra_other)
        nra->nd_ra_flags_reserved |= ND_RA_FLAG_OTHER;
    if (ra->ra_homeagent)
        nra->nd_ra_flags_reserved |= ND_RA_FLAG_HOME_AGENT;
    switch (ra->ra_preference) {
        case RAT_RA_PREF_LOW:
            nra->nd_ra_flags_reserved |= ND_RA_RTPREF_LOW;
            break;
        case RAT_RA_PREF_MEDIUM:
            nra->nd_ra_flags_reserved |= ND_RA_RTPREF_MEDIUM;
            break;
        case RAT_RA_PREF_HIGH:
            nra->nd_ra_flags_reserved |= ND_RA_RTPREF_HIGH;
            break;
        case RAT_RA_PREF_RESERVED:
            nra->nd_ra_flags_reserved |= ND_RA_RTPREF_RESERVED;
            break;
        default:
            rat_log_err("Module RA: Could not compile RA header! " \
                        "Invalid router preference.");
            goto exit_err;
            break;
    }
    if (ra->ra_proxy)
        nra->nd_ra_flags_reserved |= ND_RA_FLAG_PROXY;

    nra->nd_ra_router_lifetime = htons(ra->ra_lifetime);
    nra->nd_ra_reachable = htonl(ra->ra_reachable);
    nra->nd_ra_retransmit = htonl(ra->ra_retrans);

    /*
     * In such cases the router SHOULD transmit one or more (but not more
     * than MAX_FINAL_RTR_ADVERTISEMENTS) final multicast Router
     * Advertisements on the interface with a Router Lifetime field of zero.
     *
     * (RFC 2461 Sec. 6.2.5. Ceasing To Be An Advertising Interface)
     */
    if (mi->mi_fadingout) {
        nra->nd_ra_router_lifetime = 0;
        /*
         * If the Router Lifetime is zero, the preference value MUST be set
         * to (00) by the sender and MUST be ignored by the receiver.
         *
         * (RFC 4191 sec. 2.2.)
         */
        ra->ra_preference = RAT_RA_PREF_MEDIUM;
    }

    /* write back changes */
    RAT_MOD_RAWDATA(mi) = nra;
    RAT_MOD_RAWLEN(mi) = sizeof(*nra);

    return RAT_OK;

exit_err:
    return RAT_ERROR;
}


/**
 * @brief Show RA
 *
 * @param mf                    module helper functions
 * @param mi                    module instance information
 *
 * @return Returns RAT_ERROR on error, RAT_OK otherwise
 */
static int rat_ra_show (struct rat_mod_functions *mf,
                        struct rat_mod_instance *mi)
{
    struct rat_ra_private *ra = RAT_MOD_PRIVATE(mi);
    RAT_DEBUG_TRACE();

    mf->mf_param(mi->mi_in, "Current Hop Limit");
    mf->mf_value("%" PRIu8, ra->ra_curhl);
    if (ra->ra_curhl == RAT_RA_CURHL_UNSPEC)
        mf->mf_info("Unspecified");
    else
        mf->mf_info(NULL);

    mf->mf_param(mi->mi_in, "Managed Flag");
    mf->mf_value("%s", ra->ra_managed ? "1" : "0");
    mf->mf_info("%s%s", ra->ra_managed ? "" : "No ",
                 "Managed Address Configuration");

    mf->mf_param(mi->mi_in, "Other Managed Flag");
    mf->mf_value("%s", ra->ra_other ? "1" : "0");
    mf->mf_info("%s%s", ra->ra_other ? "" : "No ",
                 "Other Managed Configuration");

    mf->mf_param(mi->mi_in, "Home Agent Flag");
    mf->mf_value("%s", ra->ra_homeagent ? "1" : "0");
    mf->mf_info("%s%s", ra->ra_homeagent ? "" : "No ",
                 "Mobile IPv6 Home Agent");

    mf->mf_param(mi->mi_in, "Router Preference");
    switch (ra->ra_preference) {
        case RAT_RA_PREF_LOW:
            mf->mf_value("11");
            mf->mf_info("Low");
            break;
        case RAT_RA_PREF_MEDIUM:
            mf->mf_value("00");
            mf->mf_info("Medium");
            break;
        case RAT_RA_PREF_HIGH:
            mf->mf_value("01");
            mf->mf_info("High");
            break;
        default:
            mf->mf_value("10");
            mf->mf_info("Reserved");
            mf->mf_comment(mi->mi_in, "Router advertises a reserved value!");
            break;
    }

    mf->mf_param(mi->mi_in, "NDP Proxy Flag");
    mf->mf_value("%s", ra->ra_proxy ? "1" : "0");
    mf->mf_info("%s%s", ra->ra_proxy ? "" : "No ", "NDP Proxy");


    mf->mf_param(mi->mi_in, "Lifetime");
    mf->mf_value("%" PRIu16, ra->ra_lifetime);
    if (ra->ra_lifetime)
        mf->mf_info("%uh %um %us",
                  RAT_LIB_S_H_TO_H(ra->ra_lifetime),
                  RAT_LIB_S_H_TO_M(ra->ra_lifetime),
                  RAT_LIB_S_H_TO_S(ra->ra_lifetime));
    else
        mf->mf_info("No Default Router");
    if (ra->ra_lifetime > RAT_RA_LIFETIME_MAX)
        mf->mf_comment(mi->mi_in, "Illegal Router Lifetime!");

    mf->mf_param(mi->mi_in, "Reachable Time");
    mf->mf_value("%" PRIu32, ra->ra_reachable);
    mf->mf_info("%uh %um %us %ums",
              RAT_LIB_MS_H_TO_H(ra->ra_reachable),
              RAT_LIB_MS_H_TO_M(ra->ra_reachable),
              RAT_LIB_MS_H_TO_S(ra->ra_reachable),
              RAT_LIB_MS_H_TO_MS(ra->ra_reachable));

    mf->mf_param(mi->mi_in, "Retransmission Timer");
    mf->mf_value("%" PRIu32, ra->ra_retrans);
    mf->mf_info("%uh %um %us %ums",
              RAT_LIB_MS_H_TO_H(ra->ra_retrans),
              RAT_LIB_MS_H_TO_M(ra->ra_retrans),
              RAT_LIB_MS_H_TO_S(ra->ra_retrans),
              RAT_LIB_MS_H_TO_MS(ra->ra_retrans));

    return RAT_OK;
}


/**
 * @brief Dump configuration of RA
 *
 * @param mf                    module helper functions
 * @param mi                    module instance information
 *
 * @return Returns RAT_ERROR on error, RAT_OK otherwise
 */
static int rat_ra_dump (struct rat_mod_functions *mf,
                        struct rat_mod_instance *mi)
{
    struct rat_ra_private *ra = RAT_MOD_PRIVATE(mi);
    RAT_DEBUG_TRACE();

    if (ra->ra_curhl != RAT_RA_CURHL_DEF)
        mf->mf_message("%s set current-hop-limit %" PRIu8, mi->mi_myname,
                       ra->ra_curhl);
    if (ra->ra_managed != RAT_RA_MANAGED_DEF)
        mf->mf_message("ra@%s set managed-flag %s", mi->mi_myname,
                       ra->ra_managed ? "on" : "off");
    if (ra->ra_other != RAT_RA_OTHER_DEF)
        mf->mf_message("ra@%s set other-managed-flag %s", mi->mi_myname,
                       ra->ra_other ? "on" : "off");
    if (ra->ra_homeagent != RAT_RA_HOMEAGENT_DEF)
        mf->mf_message("ra@%s set homeagent-flag %s", mi->mi_myname,
                       ra->ra_homeagent ? "on" : "off");
    if (ra->ra_preference != RAT_RA_PREFERENCE_DEF) {
        switch (ra->ra_preference) {
            case RAT_RA_PREF_LOW:
                mf->mf_message("%s set preference low", mi->mi_myname);
                break;
            case RAT_RA_PREF_MEDIUM:
                mf->mf_message("%s set preference medium", mi->mi_myname);
                break;
            case RAT_RA_PREF_HIGH:
                mf->mf_message("%s set preference high", mi->mi_myname);
                break;
            default:
                mf->mf_message("%s set preference reserved", mi->mi_myname);
                break;
        }
    }
    if (ra->ra_proxy != RAT_RA_PROXY_DEF)
        mf->mf_message("%s set ndp-proxy-flag %s", mi->mi_myname,
                       ra->ra_proxy ? "on" : "off");
    if (ra->ra_lifetime != RAT_RA_LIFETIME_DEF)
        mf->mf_message("%s set lifetime %uh%um%us", mi->mi_myname,
                       RAT_LIB_S_H_TO_H(ra->ra_lifetime),
                       RAT_LIB_S_H_TO_M(ra->ra_lifetime),
                       RAT_LIB_S_H_TO_S(ra->ra_lifetime));
    if (ra->ra_reachable != RAT_RA_REACHABLE_DEF)
        mf->mf_message("%s set reachable-time %uh%um%us%ums", mi->mi_myname,
                       RAT_LIB_MS_H_TO_H(ra->ra_reachable),
                       RAT_LIB_MS_H_TO_M(ra->ra_reachable),
                       RAT_LIB_MS_H_TO_S(ra->ra_reachable),
                       RAT_LIB_MS_H_TO_MS(ra->ra_reachable));
    if (ra->ra_retrans != RAT_RA_RETRANS_DEF)
        mf->mf_message("%s set retransmission-timer %uh%um%us%ums",
                       mi->mi_myname,
                       RAT_LIB_MS_H_TO_H(ra->ra_retrans),
                       RAT_LIB_MS_H_TO_M(ra->ra_retrans),
                       RAT_LIB_MS_H_TO_S(ra->ra_retrans),
                       RAT_LIB_MS_H_TO_MS(ra->ra_retrans));

    return RAT_OK;
}


/* --- functions called by ratools/rad to manage module private data -------- */


/**
 * @brief Set current hop limit of RA
 *
 * @param mf                    module helper functions
 * @param mi                    module instance information
 * @param data                  data provided by the parameter's parser function
 * @param len                   maximum length of provided data
 *
 * @return Returns RAT_ERROR on error, RAT_OK otherwise
 */
static int rat_ra_set_curhl (struct rat_mod_functions *mf,
                             struct rat_mod_instance *mi,
                             uint8_t *data, uint16_t len)
{
    struct rat_ra_private *ra = RAT_MOD_PRIVATE(mi);
    RAT_DEBUG_TRACE();
    RAT_DISCARD_UNUSED(mf);

    if (len < sizeof(uint8_t))
        goto exit_err;

    /* no further checks required */
    ra->ra_curhl = *((uint8_t *) data);

    return RAT_OK;

exit_err:
    return RAT_ERROR;
}


/**
 * @brief Set a flag of RA
 *
 * Not to be used without wrapper function!
 *
 * @param flag                  pointer to flag address
 * @param data                  data provided by the parameter's parser function
 * @param len                   maximum length of provided data
 *
 * @return Returns RAT_ERROR on error, RAT_OK otherwise
 */
static int __rat_ra_set_flag (int *flag, uint8_t *data, uint16_t len)
{
    RAT_DEBUG_TRACE();

    if (len < sizeof(int))
        return RAT_ERROR;

    *flag = *((int *) data) ? 1 : 0;

    return RAT_OK;
}


/**
 * @brief Set managed configuration flag of RA
 *
 * @param mf                    module helper functions
 * @param mi                    module instance information
 * @param data                  data provided by the parameter's parser function
 * @param len                   maximum length of provided data
 *
 * @return Returns RAT_ERROR on error, RAT_OK otherwise
 */
static int rat_ra_set_managed (struct rat_mod_functions *mf,
                               struct rat_mod_instance *mi,
                               uint8_t *data, uint16_t len)
{
    struct rat_ra_private *ra = RAT_MOD_PRIVATE(mi);
    RAT_DEBUG_TRACE();
    RAT_DISCARD_UNUSED(mf);

    return __rat_ra_set_flag(&ra->ra_managed, data, len);
}


/**
 * @brief Set other managed configuration flag of RA
 *
 * @param mf                    module helper functions
 * @param mi                    module instance information
 * @param data                  data provided by the parameter's parser function
 * @param len                   maximum length of provided data
 *
 * @return Returns RAT_ERROR on error, RAT_OK otherwise
 */
static int rat_ra_set_other (struct rat_mod_functions *mf,
                             struct rat_mod_instance *mi,
                             uint8_t *data, uint16_t len)
{
    struct rat_ra_private *ra = RAT_MOD_PRIVATE(mi);
    RAT_DEBUG_TRACE();
    RAT_DISCARD_UNUSED(mf);

    return __rat_ra_set_flag(&ra->ra_other, data, len);
}


/**
 * @brief Set home agent flag of RA
 *
 * @param mf                    module helper functions
 * @param mi                    module instance information
 * @param data                  data provided by the parameter's parser function
 * @param len                   maximum length of provided data
 *
 * @return Returns RAT_ERROR on error, RAT_OK otherwise
 */
static int rat_ra_set_homeagent (struct rat_mod_functions *mf,
                                 struct rat_mod_instance *mi,
                                 uint8_t *data, uint16_t len)
{
    struct rat_ra_private *ra = RAT_MOD_PRIVATE(mi);
    RAT_DEBUG_TRACE();
    RAT_DISCARD_UNUSED(mf);

    return __rat_ra_set_flag(&ra->ra_homeagent, data, len);
}


/**
 * @brief Set NDP proxy flag of RA
 *
 * @param mf                    module helper functions
 * @param mi                    module instance information
 * @param data                  data provided by the parameter's parser function
 * @param len                   maximum length of provided data
 *
 * @return Returns RAT_ERROR on error, RAT_OK otherwise
 */
static int rat_ra_set_proxy (struct rat_mod_functions *mf,
                             struct rat_mod_instance *mi,
                             uint8_t *data, uint16_t len)
{
    struct rat_ra_private *ra = RAT_MOD_PRIVATE(mi);
    RAT_DEBUG_TRACE();
    RAT_DISCARD_UNUSED(mf);

    return __rat_ra_set_flag(&ra->ra_proxy, data, len);
}


/**
 * @brief Set router preference of RA
 *
 * @param mf                    module helper functions
 * @param mi                    module instance information
 * @param data                  data provided by the parameter's parser function
 * @param len                   maximum length of provided data
 *
 * @return Returns RAT_ERROR on error, RAT_OK otherwise
 */
static int rat_ra_set_preference (struct rat_mod_functions *mf,
                                  struct rat_mod_instance *mi,
                                  uint8_t *data, uint16_t len)
{
    struct rat_ra_private *ra = RAT_MOD_PRIVATE(mi);
    enum rat_ra_preference preference;
    RAT_DEBUG_TRACE();

    RAT_DISCARD_UNUSED(mf);

    if (len < sizeof(preference))
        goto exit_err;

    preference = *((enum rat_ra_preference *) data);

    /*
     * If the Router Lifetime is zero, the preference value MUST be set to
     * (00) by the sender and MUST be ignored by the receiver.
     * (RFC 4191 Sec. 2.2.  Changes to Router Advertisement Message Format)
     */
    if (ra->ra_lifetime == RAT_RA_LIFETIME_NODEF &&
        preference != RAT_RA_PREF_MEDIUM) {
        mf->mf_error("Zero lifetime requires medium router preference.");
        goto exit_err;
    }

    switch (preference) {
        case RAT_RA_PREF_LOW:
        case RAT_RA_PREF_MEDIUM:
        case RAT_RA_PREF_HIGH:
            ra->ra_preference = *((enum rat_ra_preference *) data);
            break;
       default:
            ra->ra_preference = RAT_RA_PREF_RESERVED;
            break;
    }

    return RAT_OK;

exit_err:
    return RAT_ERROR;
}


/**
 * @brief Set router lifetime of RA
 *
 * @param mf                    module helper functions
 * @param mi                    module instance information
 * @param data                  data provided by the parameter's parser function
 * @param len                   maximum length of provided data
 *
 * @return Returns RAT_ERROR on error, RAT_OK otherwise
 */
static int rat_ra_set_lifetime (struct rat_mod_functions *mf,
                                struct rat_mod_instance *mi,
                                uint8_t *data, uint16_t len)
{
    struct rat_ra_private *ra = RAT_MOD_PRIVATE(mi);
    uint16_t lifetime;
    RAT_DEBUG_TRACE();

    if (len < sizeof(lifetime))
        goto exit_err;

    lifetime = *((uint16_t *) data);

    if (lifetime > RAT_RA_LIFETIME_MAX) {
        mf->mf_error("Invalid lifetime `%" PRIu16 "'! " \
                     "Must not be greater than %" PRIu16 ".",
                     lifetime, RAT_RA_LIFETIME_MAX);
        goto exit_err;
    }
    /*
     * MUST be either zero or between MaxRtrAdvInterval and 9000 seconds.
     * (RFC 4861 sec. 6.2.1.)
     */
    if ((lifetime != RAT_RA_LIFETIME_NODEF) &&
        (lifetime < mi->mi_maxadvint)) {
        mf->mf_message("Warning: Invalid lifetime `%" PRIu16 "'! " \
                       "Must not be less than maximum interval (%" PRIu16 ").",
                       lifetime, mi->mi_maxadvint);
    }
    /*
     * If the Router Lifetime is zero, the preference value MUST be set
     * to (00) by the sender and MUST be ignored by the receiver.
     *
     * (RFC 4191 sec. 2.2.)
     */
    if (lifetime == RAT_RA_LIFETIME_NODEF &&
        ra->ra_preference != RAT_RA_PREF_MEDIUM) {
        mf->mf_message("Warning: Invalid lifetime `%" PRIu16 "'! " \
                       "Zero lifetime requires medium router preference.",
                       lifetime);
    }

    ra->ra_lifetime = lifetime;

    return RAT_OK;

exit_err:
    return RAT_ERROR;
}


/**
 * @brief Set reachable time of RA
 *
 * @param mf                    module helper functions
 * @param mi                    module instance information
 * @param data                  data provided by the parameter's parser function
 * @param len                   maximum length of provided data
 *
 * @return Returns RAT_ERROR on error, RAT_OK otherwise
 */
static int rat_ra_set_reachable (struct rat_mod_functions *mf,
                                 struct rat_mod_instance *mi,
                                 uint8_t *data, uint16_t len)
{
    struct rat_ra_private *ra = RAT_MOD_PRIVATE(mi);
    uint32_t reachable;
    RAT_DEBUG_TRACE();

    if (len < sizeof(reachable))
        goto exit_err;

    reachable = *((uint32_t *) data);

    if (reachable > RAT_RA_REACHABLE_MAX) {
        mf->mf_error("Invalid reachable time `%" PRIu32 "'! " \
                     "Must not be greater than %" PRIu32 ".",
                     reachable, RAT_RA_REACHABLE_MAX);
        goto exit_err;
    }
    ra->ra_reachable = reachable;

    return RAT_OK;

exit_err:
    return RAT_ERROR;
}


/**
 * @brief Set retransmission timer of RA
 *
 * @param mf                    module helper functions
 * @param mi                    module instance information
 * @param data                  data provided by the parameter's parser function
 * @param len                   maximum length of provided data
 *
 * @return Returns RAT_ERROR on error, RAT_OK otherwise
 */
static int rat_ra_set_retrans (struct rat_mod_functions *mf,
                               struct rat_mod_instance *mi,
                               uint8_t *data, uint16_t len)
{
    struct rat_ra_private *ra = RAT_MOD_PRIVATE(mi);
    uint32_t retrans;
    RAT_DEBUG_TRACE();

    if (len < sizeof(retrans))
        goto exit_err;

    retrans = *((uint32_t *) data);

    if (retrans > RAT_RA_RETRANS_MAX) {
        mf->mf_error("Invalid retransmission timer `%" PRIu32 "'! " \
                     "Must not be greater than %" PRIu32 ".",
                     retrans, RAT_RA_RETRANS_MAX);
        goto exit_err;
    }
    ra->ra_retrans = retrans;

    return RAT_OK;

exit_err:
    return RAT_ERROR;
}


/* --- functions called by ratools/ractl to parse CLI input ----------------- */


/**
 * @brief Parse preference of RA
 *
 * Not to be used without wrapper function!
 *
 * @param pref                  parsed preference
 * @param data                  pointer to data part of control message
 * @param len                   maximum available space in control message
 *
 * @return Returns RAT_ERROR on error, RAT_OK otherwise
 */
static int __rat_ra_cli_set_val_pref (enum rat_ra_preference pref,
                                      uint8_t *data, uint16_t len)
{
    if (!data || len < sizeof(enum rat_ra_preference))
        return RAT_ERROR;

    *((enum rat_ra_preference *) data) = pref;

    return RAT_OK;
}


/**
 * @brief Parse preference of RA (low)
 *
 * @param argv                  argument value provided by CLI
 * @param data                  pointer to data part of control message
 * @param len                   maximum available space in control message
 *
 * @return Returns RAT_ERROR on error, RAT_OK otherwise
 */
static int rat_ra_cli_set_val_preference_low (const char *argv,
                                              uint8_t *data, uint16_t len)
{
    RAT_DISCARD_UNUSED(argv);

    return __rat_ra_cli_set_val_pref(RAT_RA_PREF_LOW, data, len);
}


/**
 * @brief Parse preference of RA (medium)
 *
 * @param argv                  argument value provided by CLI
 * @param data                  pointer to data part of control message
 * @param len                   maximum available space in control message
 *
 * @return Returns RAT_ERROR on error, RAT_OK otherwise
 */
static int rat_ra_cli_set_val_preference_medium (const char *argv,
                                                 uint8_t *data, uint16_t len)
{
    RAT_DISCARD_UNUSED(argv);

    return __rat_ra_cli_set_val_pref(RAT_RA_PREF_MEDIUM, data, len);
}


/**
 * @brief Parse preference of RA (high)
 *
 * @param argv                  argument value provided by CLI
 * @param data                  pointer to data part of control message
 * @param len                   maximum available space in control message
 *
 * @return Returns RAT_ERROR on error, RAT_OK otherwise
 */
static int rat_ra_cli_set_val_preference_high (const char *argv,
                                              uint8_t *data, uint16_t len)
{
    RAT_DISCARD_UNUSED(argv);

    return __rat_ra_cli_set_val_pref(RAT_RA_PREF_HIGH, data, len);
}


/**
 * @brief Parse preference of RA (reserved)
 *
 * @param argv                  argument value provided by CLI
 * @param data                  pointer to data part of control message
 * @param len                   maximum available space in control message
 *
 * @return Returns RAT_ERROR on error, RAT_OK otherwise
 */
static int rat_ra_cli_set_val_preference_reserved (const char *argv,
                                                   uint8_t *data, uint16_t len)
{
    RAT_DISCARD_UNUSED(argv);

    return __rat_ra_cli_set_val_pref(RAT_RA_PREF_RESERVED, data, len);
}


/* --- module configuration ------------------------------------------------- */


/**
 * @brief Maximum advertising interval value parser
 */
static struct rat_mod_valreg rat_ra_reg_set_maxint[] = {
    {
        .mvr_regex              = "[0-9]{1,5}$",
        .mvr_help               = "600",
        .mvr_parse              = rat_mod_generic_set_val_uint16,
    },
    {
        .mvr_regex              = "^[0-9]{1,2}h[0-9]{1,2}m[0-9]{1,2}s$",
        .mvr_help               = "0h10m0s",
        .mvr_parse              = rat_mod_generic_set_val_hminsec16,
    }
};


/**
 * @brief Minimum advertising interval value parser
 */
static struct rat_mod_valreg rat_ra_reg_set_minint[] = {
    {
        .mvr_regex              = "[0-9]{1,5}$",
        .mvr_help               = "3",
        .mvr_parse              = rat_mod_generic_set_val_uint16,
    },
    {
        .mvr_regex              = "^[0-9]{1,2}h[0-9]{1,2}m[0-9]{1,2}s$",
        .mvr_help               = "0h0m3s",
        .mvr_parse              = rat_mod_generic_set_val_hminsec16,
    }
};


/**
 * @brief Current hop limit value parser
 */
static struct rat_mod_valreg rat_ra_reg_set_curhl[] = {
    {
        .mvr_regex              = "[0-9]{1,3}$",
        .mvr_help               = "64",
        .mvr_parse              = rat_mod_generic_set_val_uint8,
    },
    {
        .mvr_regex              = "^un?$|" \
                                  "^unsp?$|" \
                                  "^unspec?$|" \
                                  "^unspecif?$|" \
                                  "^unspecifie?$|" \
                                  "^unspecified$",
        .mvr_help               = "unspecified",
        .mvr_parse              = rat_mod_generic_set_val_zero8,
    }
};


/**
 * @brief Router preference value parser
 */
static struct rat_mod_valreg rat_ra_reg_set_preference[] = {
    {
        .mvr_regex              = "^lo?$|" \
                                  "^low$",
        .mvr_help               = "low",
        .mvr_parse              = rat_ra_cli_set_val_preference_low,
    },
    {
        .mvr_regex              = "^me?$|" \
                                  "^medi?$|" \
                                  "^medium?$",
        .mvr_help               = "medium",
        .mvr_parse              = rat_ra_cli_set_val_preference_medium,
    },
    {
        .mvr_regex              = "^hi?$|" \
                                  "^high?$",
        .mvr_help               = "high",
        .mvr_parse              = rat_ra_cli_set_val_preference_high,
    },
    {
        .mvr_regex              = "^re?$|" \
                                  "^rese?$|" \
                                  "^reserv?$|" \
                                  "^reserved?$",
        .mvr_help               = "reserved",
        .mvr_parse              = rat_ra_cli_set_val_preference_reserved,
    },
};


/**
 * @brief Router lifetime value parser
 */
static struct rat_mod_valreg rat_ra_reg_set_lifetime[] = {
    {
        .mvr_regex              = "[0-9]{1,5}$",
        .mvr_help               = "1800",
        .mvr_parse              = rat_mod_generic_set_val_uint16,
    },
    {
        .mvr_regex              = "^[0-9]{1,2}h[0-9]{1,2}m[0-9]{1,2}s$",
        .mvr_help               = "0h30m0s",
        .mvr_parse              = rat_mod_generic_set_val_hminsec16,
    },
    {
        .mvr_regex              = "^no?$|" \
                                  "^no-d?$|" \
                                  "^no-def?$|" \
                                  "^no-defau?$|" \
                                  "^no-default?$",
        .mvr_help               = "no-default",
        .mvr_parse              = rat_mod_generic_set_val_zero16,
    }
};


/**
 * @brief Reachable time and restransmission timer value parser
 */
static struct rat_mod_valreg rat_ra_reg_set_mstimer[] = {
    {
        .mvr_regex              = "[0-9]{1,10}$",
        .mvr_help               = "0",
        .mvr_parse              = rat_mod_generic_set_val_uint32,
    },
    {
        .mvr_regex              = "^[0-9]{1,3}h" \
                                  "[0-9]{1,2}m" \
                                  "[0-9]{1,2}s" \
                                  "[0-9]{1,3}ms$",
        .mvr_help               = "0h0m0s0ms",
        .mvr_parse              = rat_mod_generic_set_val_hminsecms32,
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
static struct rat_mod_sadreg rat_ra_reg_set[] = {
    {
        .msr_regex              = "^maxi?$|" \
                                  "^maximu?$|" \
                                  "^maximum-?$|" \
                                  "^maximum-in?$|" \
                                  "^maximum-inte?$|" \
                                  "^maximum-interv?$|" \
                                  "^maximum-interval?$",
        .msr_help               = "maximum-interval",
        .msr_func               = rat_mod_generic_set_dummy,
        .msr_val                = rat_ra_reg_set_maxint,
        .msr_vallen             = sizeof(rat_ra_reg_set_maxint) / \
                                  sizeof(rat_ra_reg_set_maxint[0]),
    },
    {
        .msr_regex              = "^mini?$|" \
                                  "^minimu?$|" \
                                  "^minimum-?$|" \
                                  "^minimum-in?$|" \
                                  "^minimum-inte?$|" \
                                  "^minimum-interv?$|" \
                                  "^minimum-interval?$",
        .msr_help               = "minimum-interval",
        .msr_func               = rat_mod_generic_set_dummy,
        .msr_val                = rat_ra_reg_set_minint,
        .msr_vallen             = sizeof(rat_ra_reg_set_minint) / \
                                  sizeof(rat_ra_reg_set_minint[0]),
    },
    {
        .msr_regex              = "^cu?$|" \
                                  "^curr?$|" \
                                  "^curre?$|" \
                                  "^current?$|" \
                                  "^current-h?$|" \
                                  "^current-hop?$|" \
                                  "^current-hop-l?$|" \
                                  "^current-hop-lim?$|" \
                                  "^current-hop-limit?$",
        .msr_help               = "current-hop-limit",
        .msr_func               = rat_ra_set_curhl,
        .msr_val                = rat_ra_reg_set_curhl,
        .msr_vallen             = sizeof(rat_ra_reg_set_curhl) / \
                                  sizeof(rat_ra_reg_set_curhl[0]),
    },
    {
        .msr_regex              = "^mana?$|" \
                                  "^manage?$|" \
                                  "^managed-?$|" \
                                  "^managed-fl?$|" \
                                  "^managed-flag?$",
        .msr_help               = "managed-flag",
        .msr_func               = rat_ra_set_managed,
        .msr_val                = rat_mod_generic_set_val_flag,
        .msr_vallen             = RAT_MOD_GENERIC_SET_VAL_FLAG_LEN,
    },
    {
        .msr_regex              = "^ot?$|" \
                                  "^othe?$|" \
                                  "^other-?$|" \
                                  "^other-ma?$|" \
                                  "^other-mana?$|" \
                                  "^other-manage?$|" \
                                  "^other-managed-?$|" \
                                  "^other-managed-fl?$|" \
                                  "^other-managed-flag?$",
        .msr_help               = "other-managed-flag",
        .msr_func               = rat_ra_set_other,
        .msr_val                = rat_mod_generic_set_val_flag,
        .msr_vallen             = RAT_MOD_GENERIC_SET_VAL_FLAG_LEN,
    },
    {
        .msr_regex              = "^ho?$|" \
                                  "^home?$|" \
                                  "^home-a?$|" \
                                  "^home-age?$|" \
                                  "^home-agent?$|" \
                                  "^home-agent-f?$|" \
                                  "^home-agent-fla?|$" \
                                  "^home-agent-flag$",
        .msr_help               = "home-agent-flag",
        .msr_func               = rat_ra_set_homeagent,
        .msr_val                = rat_mod_generic_set_val_flag,
        .msr_vallen             = RAT_MOD_GENERIC_SET_VAL_FLAG_LEN,
    },
    {
        .msr_regex              = "^pr?$|" \
                                  "^pref?$|" \
                                  "^prefer?$|" \
                                  "^preferen?$|" \
                                  "^preference?$",
        .msr_help               = "preference",
        .msr_func               = rat_ra_set_preference,
        .msr_val                = rat_ra_reg_set_preference,
        .msr_vallen             = sizeof(rat_ra_reg_set_preference) / \
                                  sizeof(rat_ra_reg_set_preference[0]),
    },
    {
        .msr_regex              = "^nd?$|" \
                                  "^ndp-?$|" \
                                  "^ndp-pr?$|" \
                                  "^ndp-prox?$|" \
                                  "^ndp-proxy-?$|" \
                                  "^ndp-proxy-fl?$|" \
                                  "^ndp-proxy-flag?$",
        .msr_help               = "ndp-proxy-flag",
        .msr_func               = rat_ra_set_proxy,
        .msr_val                = rat_mod_generic_set_val_flag,
        .msr_vallen             = RAT_MOD_GENERIC_SET_VAL_FLAG_LEN,
    },
    {
        .msr_regex              = "^li?$|" \
                                  "^life?$|" \
                                  "^lifeti?$|" \
                                  "^lifetime?$",
        .msr_help               = "lifetime",
        .msr_func               = rat_ra_set_lifetime,
        .msr_val                = rat_ra_reg_set_lifetime,
        .msr_vallen             = sizeof(rat_ra_reg_set_lifetime) / \
                                  sizeof(rat_ra_reg_set_lifetime[0]),
    },
    {
        .msr_regex              = "^reac?$|" \
                                  "^reacha?$|" \
                                  "^reachabl?$|" \
                                  "^reachable-?$|" \
                                  "^reachable-ti?$|" \
                                  "^reachable-time?$",
        .msr_help               = "reachable-time",
        .msr_func               = rat_ra_set_reachable,
        .msr_val                = rat_ra_reg_set_mstimer,
        .msr_vallen             = sizeof(rat_ra_reg_set_mstimer) / \
                                  sizeof(rat_ra_reg_set_mstimer[0]),
    },
    {
        .msr_regex              = "^retr?$|" \
                                  "^retran?$|" \
                                  "^retransm?$|" \
                                  "^retransmis?$|" \
                                  "^retransmissi?$|" \
                                  "^retransmission?|$" \
                                  "^retransmission-t?|$" \
                                  "^retransmission-tim?|$" \
                                  "^retransmission-timer?$",
        .msr_help               = "retransmission-timer",
        .msr_func               = rat_ra_set_retrans,
        .msr_val                = rat_ra_reg_set_mstimer,
        .msr_vallen             = sizeof(rat_ra_reg_set_mstimer) / \
                                  sizeof(rat_ra_reg_set_mstimer[0])
    }
};


/**
 * @brief Module configuration
 */
static struct rat_mod_modreg rat_ra_reg = {
    .mmr_regex                  = RAT_RAMODREGEX,
    .mmr_name                   = RAT_RAMODNAME,
    .mmr_multiple               = 0,
    .mmr_create                 = rat_ra_create,
    .mmr_destroy                = rat_mod_generic_destroy,
    .mmr_enable                 = rat_mod_generic_dummy,
    .mmr_disable                = rat_mod_generic_dummy,
    .mmr_show                   = rat_ra_show,
    .mmr_dump                   = rat_ra_dump,
    .mmr_kill                   = rat_mod_generic_dummy,
    .mmr_set                    = rat_ra_reg_set,
    .mmr_setlen                 = sizeof(rat_ra_reg_set) / \
                                  sizeof(rat_ra_reg_set[0]),
    .mmr_add                    = NULL,
    .mmr_addlen                 = 0,
    .mmr_del                    = NULL,
    .mmr_dellen                 = 0,
    .mmr_compile                = rat_ra_compile
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
extern int rat_ra_init (void)
{
    RAT_DEBUG_TRACE();

    return rat_mod_register(&rat_ra_reg);
}
