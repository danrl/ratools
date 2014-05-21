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


#ifndef __RATOOLS_PROC_H
#define __RATOOLS_PROC_H


#include "ratools.h"

#include "database.h"


/**
 * @brief IPv6 forwarding variable path
 *
 * Path to forwarding variable in the Kernel's proc filesystem. In IPv6 you can
 * not control forwarding per device, so this path looks for the global value.
 */
#define RAT_PRC_IP6FORWARDPATH  "/proc/sys/net/ipv6/conf/all/forwarding"


/** forwarding state constants */
/** @{ */
#define RAT_PRC_FWD_DISABLED    0
#define RAT_PRC_FWD_ENABLED     1
#define RAT_PRC_FWD_ENABLEDRS   2
/** @} */


extern int rat_prc_forwarding (struct rat_db *);


#endif /* __RATOOLS_PROC_H */
