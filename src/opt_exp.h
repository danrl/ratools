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


#ifndef __RATOOLS_OPT_EXP_H
#define __RATOOLS_OPT_EXP_H

#include "ratools.h"

#include "library.h"


/**
 * @brief Default type for new experimental options
 *
 * This document assigns two IPv6 Neighbor Discovery Option Types, 253 and 254.
 * (RFC 4727 Sec. 5.1.3.  IPv6 Neighbor Discovery Option Type)
 */
#define RAT_OPT_EXP_TYPE_DEF    253

/** Default length for new experimental options */
#define RAT_OPT_EXP_LEN_DEF     0

/** Maximum length of experimental payload data */
#define RAT_OPT_EXP_PAYLOAD_MAXLEN \
    256

/** Buffer length for asciiz representation of payload */
#define RAT_OPT_EXP_PAYLOAD_STRSIZ \
    ((2 * RAT_OPT_EXP_PAYLOAD_MAXLEN) + 1)


/**
 * @brief Experimental option private data
 */
struct rat_opt_exp_private {
    /** Whether or not the option is enabled */
    int                         exp_enabled;
    /** ICMPv6 option type */
    uint8_t                     exp_type;
    /** Length of payload */
    uint16_t                    exp_len;
    /** Mobile ipv6 router address flag */
    uint8_t                     exp_payload[RAT_OPT_EXP_PAYLOAD_MAXLEN];
};


/**
 * @brief Experimental option transfer data structure
 *
 * Used to transfer data vom CLI to daemon in a well formed way.
 */
struct rat_opt_exp_transfer {
    /** Length of payload data */
    uint16_t                    et_len;
    /** Payload data */
    uint8_t                     et_payload[RAT_OPT_EXP_PAYLOAD_MAXLEN];
};


/* --- registry function ---------------------------------------------------- */


extern int rat_opt_exp_init (void);


#endif /* __RATOOLS_OPT_EXP_H */
