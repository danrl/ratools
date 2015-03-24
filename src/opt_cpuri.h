/** @file */
/*
 * ratools: Router Advertisement Tools
 *
 * Copyright 2013-2015 Dan Luedtke <mail@danrl.de>
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


#ifndef __RATOOLS_OPT_CPURI_H
#define __RATOOLS_OPT_CPURI_H

#include "ratools.h"

#include "library.h"


/**
 * @brief Default type for new experimental options
 *
 * This document assigns two IPv6 Neighbor Discovery Option Types, 253 and 254.
 * (RFC 4727 Sec. 5.1.3.  IPv6 Neighbor Discovery Option Type)
 */
#define RAT_OPT_CPURI_TYPE      253


/** Maximum length of captive portal URI */
#define RAT_OPT_CPURI_URI_STRLEN \
    253


/**
 * @brief Captive Portl URI option private data
 */
struct rat_opt_cpuri_private {
    /** Whether or not the option is enabled */
    int                         cp_enabled;
    /** URI */
    char                        cp_uri[RAT_OPT_CPURI_URI_STRLEN  + 1];
};


/* --- registry function ---------------------------------------------------- */


extern int rat_opt_cpuri_init (void);


#endif /* __RATOOLS_OPT_CPURI_H */
