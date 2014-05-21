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


#ifndef __RATOOLS_OPT_MTU_H
#define __RATOOLS_OPT_MTU_H

#include "ratools.h"


/**
 * @brief Defaults and limits
 *
 * Default: 0
 * (RFC 4861 sec. 6.2.1.)
 */
/** @{ */
#define RAT_OPT_MTU_AUTO_DEF    1
#define RAT_OPT_MTU_UNSPEC      0
#define RAT_OPT_MTU_DEF         RAT_OPT_MTU_UNSPEC
#define RAT_OPT_MTU_MIN         RAT_ICMP6_MAXPACKETLEN
#define RAT_OPT_MTU_MAX         UINT32_MAX
/** @} */


/** Ethernet Jumbo Frames (1501-9216) are so special that we ignore them :) */
#define RAT_OPT_MTU_UNCOMMON(x)                                             \
    (!(                                                                     \
        (x) == 1280 ||          /* IPv6 Minimal MTU */                      \
        (x) == 1492 ||          /* LLC and SNAP or PPPoE on Ethernet */     \
        (x) == 1500 ||          /* Ethernet */                              \
        (x) == 4352 ||          /* FDDI */                                  \
        (x) == 4464 ||          /* Token Ring IEEE 802.5 */                 \
        (x) == 7981             /* IEEE 802.11 */                           \
    ))


/**
 * @brief Link MTU option private data
 */
struct rat_opt_mtu_private {
    /** Whether or not the option is enabled */
    int                         mtu_enabled;
    /** Auto detection enabled */
    int                         mtu_autodetect;
    /** MTU value */
    uint32_t                    mtu_linkmtu;
};


/* --- registry function ---------------------------------------------------- */


extern int rat_opt_mtu_init (void);


#endif /* __RATOOLS_OPT_MTU_H */
