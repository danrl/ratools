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


#ifndef __RATOOLS_OPT_PI_H
#define __RATOOLS_OPT_PI_H

#include "ratools.h"

#include "library.h"


/**
 * @brief On-link flag
 *
 * Default: TRUE
 * (RFC 4861 sec. 6.2.1.)
 */
#define RAT_OPT_PI_ONLINK_DEF   1


/**
 * @brief Autonomous address configuration flag
 *
 * Default: TRUE
 * (RFC 4861 sec. 6.2.1.)
 */
#define RAT_OPT_PI_AUTO_DEF     1


/**
 * @brief Mobile IPv6 router address flag
 *
 * Default is somewhat unclear. So we require the user to enable this flag
 * by hand if needed. It was introduced in RFC 6275 Mobility Support in IPv6
 * and is not needed on non-mobility links. There we set the dafault to false.
 */
#define RAT_OPT_PI_RTRADDR_DEF  0


/**
 * @brief Valid time
 *
 * Default: 2592000 seconds (30 days), fixed (i.e., stays the same in
 * consecutive advertisements).
 * (RFC 4861 sec. 6.2.1.)
 */
#define RAT_OPT_PI_VALID_DEF    (30 * 24 * 60 * 60)


/**
 * @brief Valid time special values
 *
 * A value of all one bits (0xffffffff) represents infinity.
 * (RFC 4861 sec. 4.6.2.)
 */
/** @{ */
#define RAT_OPT_PI_VALID_INF    0xffffffff
#define RAT_OPT_PI_VALID_NOT    0
/** @} */

/**
 * @brief Preferred time
 *
 * Default: 604800 seconds (7 days), fixed (i.e., stays the same in consecutive
 * advertisements).  This value MUST NOT be larger than AdvValidLifetime.
 * (RFC 4861 sec. 6.2.1.)
 */
#define RAT_OPT_PI_PREF_DEF     (7 * 24 * 60 * 60)


/**
 * @brief Preferred time special values
 *
 * A value of all one bits (0xffffffff) represents infinity.
 * (RFC 4861 sec. 4.6.2.)
 */
/** @{ */
#define RAT_OPT_PI_PREF_INF     0xffffffff
#define RAT_OPT_PI_PREF_NOT     0
/** @} */


/** Detect SLAAC-compatible prefix lengths. */
#define RAT_OPT_PI_PLEN_SLAAC(x)                                            \
    ((                                                                      \
        (((struct rat_prefix *) (x))->pfx_len) == 64                        \
    ))


/** Detect invalid prefix lengths. */
#define RAT_OPT_PI_PLEN_INVALID(x)                                          \
    ((                                                                      \
        (((struct rat_prefix *) (x))->pfx_len) > 128                        \
    ))

/**
 * @brief Prefix information option private data
 */
struct rat_opt_pi_private {
    /** Whether or not the option is enabled */
    int                         pi_enabled;
    /** On-link flag */
    int                         pi_onlink;
    /** Autonomous address configuration flag */
    int                         pi_auto;
    /** Mobile ipv6 router address flag */
    int                         pi_rtraddr;
    /** Valid lifetime */
    uint32_t                    pi_valid;
    /** Prefered lifetime */
    uint32_t                    pi_preferred;
    /** Hardware address */
    struct rat_prefix           pi_prefix;
};


/* --- registry function ---------------------------------------------------- */


extern int rat_opt_pi_init (void);


#endif /* __RATOOLS_OPT_PI_H */
