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


#ifndef __RATOOLS_RACTL_H
#define __RATOOLS_RACTL_H

#include "ratools.h"


/** Regex of module name */
#define RAT_RACTL_REGEX_NAME    "[a-z]{2," STR(RAT_MODNAMELEN) "}"

/** Regex of module index number */
#define RAT_RACTL_REGEX_INDEX   "[0-9]{1," STR(RAT_INDEXSTRLEN) "}"

/** Regex of interface name */
#define RAT_RACTL_REGEX_IFNAME  "[a-zA-Z0-9.:-]{1," STR(RAT_IFNAMELEN) "}"

/** Regex of module object */
#define RAT_RACTL_REGEX_OBJECT  "^"                             \
                                "(" RAT_RACTL_REGEX_NAME ")"    \
                                "(" RAT_RACTL_REGEX_INDEX ")?"  \
                                "@"                             \
                                "(" RAT_RACTL_REGEX_IFNAME ")$"


/** Regexes of special commands and values */
/** @{ */
#define RAT_RACTL_REGEX_VERSION "^ve?$|" \
                                "^vers?$|" \
                                "^versio?$|" \
                                "^version$"

#define RAT_RACTL_REGEX_SHOW    "^sh?$|" \
                                "^show?$"

#define RAT_RACTL_REGEX_DUMP    "^du?$|" \
                                "^dump?$"

#define RAT_RACTL_REGEX_LOG     "^lo?$|" \
                                "^log$"

#define RAT_RACTL_REGEX_ERROR   "^er?$|" \
                                "^erro?$|" \
                                "^error$"

#define RAT_RACTL_REGEX_WARNING "^wa?$|" \
                                "^warn?$|" \
                                "^warnin?$|" \
                                "^warning$"

#define RAT_RACTL_REGEX_INFO    "^in?$|" \
                                "^info?$"
/** @} */

/** Maximum number of configuration tokens (argvs) */
#define RAT_RACTL_MAXTOKENS     8


#endif /* __RATOOLS_RACTL_H */
