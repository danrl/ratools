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


#ifndef __RATOOLS_RA_H
#define __RATOOLS_RA_H

#include "ratools.h"


/**
 * @brief Router preference
 */
enum rat_ra_preference {
    /** Router has low preference */
    RAT_RA_PREF_LOW,
    /** Router has medium preference */
    RAT_RA_PREF_MEDIUM,
    /** Router has high preference */
    RAT_RA_PREF_HIGH,
    /** Reserved value */
    RAT_RA_PREF_RESERVED
};


/**
 * @brief Router Advertisement private data
 */
struct rat_ra_private {
    /** Current hop limit */
    uint8_t                     ra_curhl;
    /** Managed flag */
    int                         ra_managed;
    /** Other managed flag */
    int                         ra_other;
    /** Home agent flag */
    int                         ra_homeagent;
    /** Router preference */
    enum rat_ra_preference      ra_preference;
    /** NDP proxy flag */
    int                         ra_proxy;
    /** Router lifetime */
    uint16_t                    ra_lifetime;
    /** Reachable timer */
    uint32_t                    ra_reachable;
    /** Retransmission timer */
    uint32_t                    ra_retrans;
};


/**
 * @brief Current Hop Limit
 *
 * IPv4 default TTL: 64 (Not updated for IPv6 HL at the time of writing)
 * (http://www.iana.org/assignments/ip-parameters/ip-parameters.xhtml)
 *
 * A value of zero means unspecified (by this router).
 * (RFC 4861 sec. 4.2.)
 */
/** @{ */
#define RAT_RA_CURHL_DEF        64
#define RAT_RA_CURHL_UNSPEC     0
/** @} */


/**
 * @brief Managed Configuration Flag
 *
 * Default: FALSE
 * (RFC 4861 sec. 6.2.1.)
 */
#define RAT_RA_MANAGED_DEF      0


/**
 * @brief Other Configuration Flag
 *
 * Default: FALSE
 * (RFC 4861 sec. 6.2.1.)
 */
#define RAT_RA_OTHER_DEF        0


/**
 * @brief Home Agent
 *
 * The Home Agent (H) bit is set in a Router Advertisement to
 * indicate that the router sending this Router Advertisement is also
 * functioning as a Mobile IPv6 home agent on this link.
 * (RFC 3775 sec. 7.1.)
 *
 * Default: FALSE
 */
#define RAT_RA_HOMEAGENT_DEF    0


/**
 * @brief NDP Proxy
 *
 * A new "Proxy" bit is defined in the existing Router Advertisement
 * flags field as follows:
 *
 *  +-+-+-+-+-+-+-+-+
 *  |M|O|H|Prf|P|Rsv|
 *  +-+-+-+-+-+-+-+-+
 * (RFC 4389 sec. 4.1.3.3.)
 *
 * Default: FALSE
 */
#define RAT_RA_PROXY_DEF        0


/**
 * @brief Router Preference
 *
 * RFC 4191 does not explicitly state a default value. Medium seems reasonable
 * and provides best compatibility.
 */
#define RAT_RA_PREFERENCE_DEF   RAT_RA_PREF_MEDIUM


/**
 * @brief Router Lifetime
 *
 * The field can contain values up to 65535 and receivers
 * should handle any value, while the sending rules in
 * Section 6 limit the lifetime to 9000 seconds.  A
 * Lifetime of 0 indicates that the router is not a
 * default router and SHOULD NOT appear on the default
 * router list.
 * (RFC 4861 sec. 4.2.)
 *
 * MUST be either zero or between MaxRtrAdvInterval and 9000 seconds.
 * (RFC 4861 sec. 6.2.1.)
 *
 * Default: 3 * MaxRtrAdvInterval
 * (RFC 4861 sec. 6.2.1.)
 *
 * This document updates Section 6.2.1. of [RFC4861] to update the
 * following router configuration variables.  MaxRtrAdvInterval MUST be
 * no greater than 21845.  AdvDefaultLifetime MUST be between
 * MaxRtrAdvInterval and 65535.
 * (DRAFT draft-krishnan-6man-maxra-01 sec. 3)
 */
/** @{ */
#define RAT_RA_LIFETIME_NODEF   0
#define RAT_RA_LIFETIME_DEF     1800
#define RAT_RA_LIFETIME_MAX     9000
#define RAT_RA_LIFETIME_DRAFT   65335
/** @} */


/**
 * @brief Reachable Time
 *
 * Default: 0
 * (RFC 4861 sec. 6.2.1.)
 */
/** @{ */
#define RAT_RA_REACHABLE_UNSPEC 0
#define RAT_RA_REACHABLE_DEF    RAT_RA_REACHABLE_UNSPEC
/** @} */

/**
 * @brief Reachable Time maximum
 *
 * MUST be no greater than 3,600,000 milliseconds (1 hour).
 * (RFC 4861 sec. 6.2.1.)
 */
#define RAT_RA_REACHABLE_MAX    (60 * 60 * 1000)


/**
 * @brief Retransmission Timer
 *
 * Default: 0
 * (RFC 4861 sec. 6.2.1.)
 */
/** @{ */
#define RAT_RA_RETRANS_UNSPEC   0
#define RAT_RA_RETRANS_DEF      RAT_RA_RETRANS_UNSPEC
#define RAT_RA_RETRANS_MAX      UINT32_MAX
/** @} */


/* --- registry function ---------------------------------------------------- */


extern int rat_ra_init (void);


#endif /* __RATOOLS_RA_H */
