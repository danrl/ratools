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


#ifndef __RATOOLS_OPT_RDNSS_H
#define __RATOOLS_OPT_RDNSS_H

#include "ratools.h"

#include "library.h"


/**
 * @brief Infinite lifetime
 *
 * A value of all one bits (0xffffffff) represents infinity.
 * (RFC 5006 sec. 5.1.)
 */
#define RAT_OPT_RDNSS_LIFE_INF  UINT32_MAX


/**
 * @brief Zero lifetime
 *
 *      A value of zero means that the RDNSS address MUST no longer be used.
 *      (RFC 5006 sec. 5.1.)
 */
#define RAT_OPT_RDNSS_LIFE_NOT  0


/**
 * @brief Default lifetime
 * In order to provide fixed hosts
 * with stable DNS service and allow mobile hosts to
 * prefer local RDNSSes to remote RDNSSes, the value of
 * Lifetime should be at least as long as the Maximum RA
 * Interval (MaxRtrAdvInterval) in RFC 4861, and be at
 * most as long as two times MaxRtrAdvInterval; Lifetime
 * SHOULD be bounded as follows:  MaxRtrAdvInterval <=
 * Lifetime <= 2*MaxRtrAdvInterval.
 */
/** @{ */
#define RAT_OPT_RDNSS_LIFE_MIN(x) \
    (x)
#define RAT_OPT_RDNSS_LIFE_MAX(x) \
    (2 * (x))
#define RAT_OPT_RDNSS_LIFE_DEF(x) \
    ((x) + ((x) / 2))
/** @} */


/**
 * @brief RDNSS server
 *
 * RDNSS option supports multiple servers. They are managed in a linked list.
 * This struct defines such a list item.
 */
struct rat_opt_rdnss_srv {
    /** Next server in list */
    struct rat_opt_rdnss_srv    *srv_next;
    /** Server address */
    struct in6_addr             srv_addr;
};


/**
 * @brief Prefix information option private data
 */
struct rat_opt_rdnss_private {
    /** Whether or not the option is enabled */
    int                         rds_enabled;
    /** Lifetime */
    uint32_t                    rds_lifetime;
    /** List of servers */
    struct rat_opt_rdnss_srv    *rds_srv;
};


/* --- registry function ---------------------------------------------------- */


extern int rat_opt_rdnss_init (void);


#endif /* __RATOOLS_OPT_RDNSS_H */
