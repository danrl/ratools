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


#ifndef __RATOOLS_RAD_H
#define __RATOOLS_RAD_H

#include "ratools.h"

#include "string.h"             /* RAT_STR_HWADDRBYTELEN */

#include <unistd.h>
#include <time.h>
#include <pthread.h>
#include <arpa/inet.h>          /* useconds_t */

#include <linux/rtnetlink.h>


/* --- database ------------------------------------------------------------- */


/**
 * Database metadata of ICMPv6 option
 */
struct rat_db_opt {
    /** Next option in linked list */
    struct rat_db_opt           *opt_next;
    /** Module ID */
    uint16_t                    opt_mid;
    /** Option Index */
    uint16_t                    opt_oid;
    /** Option private data, allocated and managed by module */
    void                        *opt_private;
    /** Option ICMPv6 raw data */
    uint8_t                     *opt_rawdata;
    /** Length of ICMPv6 raw data */
    uint16_t                    opt_rawlen;
};


/**
 * RA multicast state
 *
 * Note: This state machine's states are only effective for complete RAs. Other
 * options, e.g. prefixes and RDNSS lists may maintain individual states.
 */
enum rat_db_state {
    /*
     * MAX_INITIAL_RTR_ADVERTISEMENTS 3 transmissions
     * (RFC 4861 sec. 10.)
     */
    /** Interface is advertising (1/3) */
    RAT_DB_STATE_FADEIN1,
    /** Interface is advertising (2/3) */
    RAT_DB_STATE_FADEIN2,
    /** Interface is advertising (3/3) */
    RAT_DB_STATE_FADEIN3,
    /*
     * AdvSendAdvertisements = TRUE
     * (RFC 4861 sec. 6.2.1.)
     */
    /** Interface is periodically advertising */
    RAT_DB_STATE_ENABLED,
    /*
     * MAX_FINAL_RTR_ADVERTISEMENTS 3 transmissions
     * (RFC 4861 sec. 10.)
     */
    /** Interface is deadvertising (1/3) */
    RAT_DB_STATE_FADEOUT1,
    /** Interface is deadvertising (2/3) */
    RAT_DB_STATE_FADEOUT2,
    /** Interface is deadvertising (3/3) */
    RAT_DB_STATE_FADEOUT3,
    /*
     * AdvSendAdvertisements = FALSE
     * (RFC 4861 sec. 6.2.1.)
     */
    /** Advertising is disabled */
    RAT_DB_STATE_DISABLED,
    /** Interface is destroyed */
    RAT_DB_STATE_DESTROYED
};


/**
 * Maximum Advertising Interval
 *
 * MUST be no less than 4 seconds and no greater than 1800 seconds.
 * Default: 600 seconds
 * (RFC 4861 sec. 6.2.1.)
 *
 * This document updates Section 6.2.1. of [RFC4861] to update the
 * following router configuration variables.  MaxRtrAdvInterval MUST be
 * no greater than 21845.  AdvDefaultLifetime MUST be between
 * MaxRtrAdvInterval and 65535.
 * (DRAFT draft-krishnan-6man-maxra-01 sec. 3)
 */
#define RAT_DB_MAXADVINT_DEF    600
/** Minimum allowed value of maximum advertising interval */
#define RAT_DB_MAXADVINT_MIN    4
/** Maximum allowed value of maximum advertising interval */
#define RAT_DB_MAXADVINT_MAX    1800
#define RAT_DB_MAXADVINT_DRAFT  21845


/**
 * MAX_INITIAL_RTR_ADVERT_INTERVAL 16 seconds
 * (RFC 4861 sec. 10.)
 */
#define RAT_DB_MAXADVINT_INIT   16


/**
 * Minimum Advertising Interval
 *
 * Default: 0.33 * MaxRtrAdvInterval
 * (RFC 4861 sec. 6.2.1.)
 */
#define RAT_DB_MINADVINT_DEF    198


/**
 * MIN_DELAY_BETWEEN_RAS 3 seconds
 * (RFC 4861 sec. 10.)
 */
#define RAT_DB_MINADVINT_MIN    3


/**
 * Maximum allowed value for minimum advertising interval
 * 0.75 * RAT_DB_MAXINT_MAX
 */
#define RAT_DB_MINADVINT_MAX    1350


/**
 * Database entry
 */
struct rat_db {
    /** @{ */
    /** Next database entry */
    struct rat_db               *db_next;
    /** Interface index */
    uint32_t                    db_ifindex;
    /** @} */
    /** @{ */
    /** State of the RA */
    enum rat_db_state           db_state;
    /** Maximum advertising interval */
    uint16_t                    db_maxadvint;
    /** Minium advertising interval */
    uint16_t                    db_minadvint;
    /** RA module private data */
    void                        *db_ra_private;
    /** RA module ICMPv6 raw data */
    uint8_t                     *db_ra_rawdata;
    /** RA module ICMPv6 raw data length */
    uint16_t                    db_ra_rawlen;
    /** Options (linked list start) */
    struct rat_db_opt           *db_opt;
    /** Configuration version. Gets increased with every configuration change */
    uint32_t                    db_version;
    /** Compiled version. Must match db_version prior to sending RA */
    uint32_t                    db_compiled;
    /** Delay of next multicast packet */
    useconds_t                  db_delay;
    /** Interface up/down state */
    int                         db_ifup;
    /** Interface asciiz name */
    char                        db_ifname[RAT_IFNAMESIZ];
    /** Interface maximum transmission unit */
    uint32_t                    db_mtu;
    /** Interface hardware address */
    struct rat_hwaddr           db_hwaddr;
    /** Interface link-local address */
    struct in6_addr             db_lladdr;
    /** Timestamp of database entry creation */
    time_t                      db_created;
    /** Timestamp of database entry update */
    time_t                      db_updated;
    /** RA worker thread */
    pthread_t                   db_worker_thread;
    /** RA worker thread attribute */
    pthread_attr_t              db_worker_attr;
    /** RA worker thread signaling condition */
    pthread_cond_t              db_worker_cond;
    /** RA worker thread signaling mutex */
    pthread_mutex_t             db_worker_mutex;
    /** RA worker thread next timed wake up */
    struct timespec             db_worker_next;
    /** Byte counter for outgoing packets */
    uint64_t                    db_stat_bytes;
    /** Counter for RAs sent */
    uint64_t                    db_stat_total;
    /** Counter for solicited RAs sent */
    uint64_t                    db_stat_solicited;
    /** Counter for multicast RAs sent */
    uint64_t                    db_stat_multicast;
    /** @} */
};


/* --- netlink -------------------------------------------------------------- */


/** netlink reply message buffer size */
#define RAT_NL_REPLYBUFSIZE     4096


/** netlink request */
struct rat_nl_rtreq {
    /** netlink message header */
    struct nlmsghdr             req_nlmsg;
    /** actual netlink message */
    union {
        /** link-layer information */
        struct ifinfomsg        req_un_ifi;
        /** network-layer information */
        struct ifaddrmsg        req_un_ifa;
    } req_un;
    /** link-layer information */
#   define req_ifi              req_un.req_un_ifi
    /** network-layer information */
#   define req_ifa              req_un.req_un_ifa
};


#endif /* __RATOOLS_RAD_H */
