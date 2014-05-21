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


#include "multicast.h"

#include "library.h"

#include <string.h>
#include <inttypes.h>           /* PRIu32 and friends */


/**
 * @brief Set socket multicast group membership options
 *
 * @param sd                    socket descriptor to use
 * @param action                group membership action (e.g. add, drop)
 * @param ifindex               interface index
 *
 * @return Returns RAT_ERROR on error, RAT_OK otherwise
 */
static int __rat_mc_membership (int sd, int action, uint32_t ifindex)
{
    struct ipv6_mreq mreq;

    if (sd < 1)
        goto exit_err;

    memset(&mreq, 0x0, sizeof(mreq));
    rat_lib_6addr_set_allrouters(&mreq.ipv6mr_multiaddr);
    mreq.ipv6mr_interface = ifindex;

    if (setsockopt(sd, IPPROTO_IPV6, action, &mreq, sizeof(mreq)) == 0)
        return RAT_OK;

exit_err:
    return RAT_ERROR;
}


/**
 * @brief Join the all routers multicast group
 *
 * @param sd                    socket descriptor to use
 * @param ifindex               interface index
 *
 * @return Returns RAT_ERROR on error, RAT_OK otherwise
 */
int rat_mc_join (int sd, uint32_t ifindex)
{
    return __rat_mc_membership(sd, IPV6_ADD_MEMBERSHIP, ifindex);
}


/**
 * @brief Leave the all routers multicast group
 *
 * @param sd                    socket descriptor to use
 * @param ifindex               interface index
 *
 * @return Returns RAT_ERROR on error, RAT_OK otherwise
 */
int rat_mc_leave (int sd, uint32_t ifindex)
{
    return __rat_mc_membership(sd, IPV6_DROP_MEMBERSHIP, ifindex);
}
