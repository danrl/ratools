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


#ifndef __RATOOLS_OPT_SLL_H
#define __RATOOLS_OPT_SLL_H

#include "ratools.h"

#include "library.h"


/**
 * @brief Defaults and Limits
 */
#define RAT_OPT_SLL_AUTO_DEF    1


/** Ethernet Jumbo Frames (1501-9216) are so special that we ignore them :) */
#define RAT_OPT_SLL_UNCOMMON(x)                                             \
    (!(                                                                     \
        /* 48 bit MAC address */                                            \
        (((struct rat_hwaddr *) (x))->hwa_len) == 6 ||                      \
        /* 64 bit hardware address */                                       \
        (((struct rat_hwaddr *) (x))->hwa_len) == 8                         \
    ))


/**
 * @brief Link MTU option private data
 */
struct rat_opt_sll_private {
    /** Whether or not the option is enabled */
    int                         sll_enabled;
    /** Auto detection enabled */
    int                         sll_autodetect;
    /** Hardware address */
    struct rat_hwaddr           sll_hwaddr;
};


/* --- registry function ---------------------------------------------------- */


extern int rat_opt_sll_init (void);


#endif /* __RATOOLS_OPT_SLL_H */
