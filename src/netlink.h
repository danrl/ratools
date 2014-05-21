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


#ifndef __RATOOLS_NETLINK_H
#define __RATOOLS_NETLINK_H

#include "ratools.h"

#include "database.h"

#include <linux/rtnetlink.h>


/** buffer for receiving netlink and rtnetlink messages */
#define RAT_NL_REPLYBUFSIZE     4096


/** netlink request */
struct rat_nl_rtreq {
    /** netlink message header */
    struct nlmsghdr             req_nlmsg;
    /** actual rtnetlink message */
    struct rtgenmsg             req_rtgen;
};


extern int rat_nl_init_db (struct rat_db *);
extern void *rat_nl_listener (void *);


#endif /* __RATOOLS_NETLINK_H */
