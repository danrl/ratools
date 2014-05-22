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


#ifndef __RATOOLS_H
#define __RATOOLS_H


#include <stdint.h>
#include <stdio.h>              /* fprintf() in RAT_DEBUG_*() functions */
#include <netinet/in.h>         /* struct in6_addr */


/* --- glibc patches not yet accepted by upstream --------------------------- */


/*
 * Still waiting for it to happen...
 * https://sourceware.org/ml/libc-alpha/2014-02/msg00383.html
 * https://sourceware.org/ml/libc-alpha/2014-03/msg00006.html
 */


/** Flags and bitmasks missing in glic */
/** @{ */
#define ND_RA_FLAG_HA           ND_RA_FLAG_HOME_AGENT /* name differs on BSD */
#define ND_RA_FLAG_PROXY        0x04
#define ND_RA_RTPREF_LOW        0x18
#define ND_RA_RTPREF_MEDIUM     0x00
#define ND_RA_RTPREF_HIGH       0x08
#define ND_RA_RTPREF_RESERVED   0x10
#define ND_OPT_PI_FLAG_RADDR    0x20
#define ND_OPT_RDNSS            25
/** @} */


/**
 * glibc-style icmp6 raw data format for recursive dns servers option */
struct nd_opt_rdnss {
    /** option type */
    uint8_t                     nd_opt_rdnss_type;
    /** option length */
    uint8_t                     nd_opt_rdnss_len;
    /** reserved */
    uint16_t                    nd_opt_rdnss_reserved;
    /** option lifetime */
    uint32_t                    nd_opt_rdnss_lifetime;
    /* followed by recursive DNS servers */
};


/* --- avoid non-posix ------------------------------------------------------ */


/**
 * We do not define _GNU_SOURCE to avoid opening that can of worms... However,
 * we use a structure to communicate with the Kernel that usually requires
 * _GNU_SOURCE :( Thus we have to define it here.
 */
struct in6_pktinfo {
    /** IPv6 address of packet */
    struct in6_addr             ipi_addr;
    /** Interface index of packet */
    unsigned int                ipi_ifindex;
};


/* --- helper macros -------------------------------------------------------- */


/**
 * @brief Macros for limiting values
 *
 * Caution: These are not type-safe!
 */
/** @{ */
#define MIN(x,y)                (((x) < (y)) ? (x) : (y))
#define MAX(x,y)                (((x) > (y)) ? (x) : (y))
/** @} */


/**
 * @brief Aligning space x to chunk size y
 */
#define ALIGN(x,y)              ((((x) / (y)) + (((x) % (y) ? (y) : 0))) * (y))


/** @brief A meta-macro to convert numbers to strings. i heard u like... */
/** @{ */
#define STR_INDIRECTION(x)      #x
#define STR(x)                  STR_INDIRECTION(x)
/** @} */


/** @brief Discard unsused parameters macro */
#define RAT_DISCARD_UNUSED(x)   ((void) (x))


/* --- ratools defaults ----------------------------------------------------- */


/** static version information */
/** @{ */
#define RAT_VERSION             "0.3.5"
#define RAT_DATE                "May 2014"
/** @} */

/**
 * @brief Default socket address
 *
 * For communication between ratools/ractl and ratools/rad. Can be overwritten
 * by environment variable RAT_SOCKET_ADDRESS.
 */
#define RAT_SOCKADDR            "/var/lib/ratools/rad.sock"

/** RA core module name */
#define RAT_RAMODNAME           "ra"

/** RA core module regex */
#define RAT_RAMODREGEX          "^ra$"

/**
 * @brief Maximum module name length
 *
 * This one is safe to increase.
 */
#define RAT_MODNAMELEN          8


/**
 * @brief Maximum length of index string
 *
 * An index is a number to identify a instance of a module. E.g. in
 * `pi3[AT]eth0' the `3' is the index number of the third instance of module
 * `pi' at interface `eth0'. It has a length of `1' (not including the
 * terminating \0). The maximum index number is currently limited because the
 * highest value a string of `4' characters can describe is `9999'.
 *
 * We have to check for uint16_t overflow if we ever want to increase this
 * already insane high value.
 */
#define RAT_INDEXSTRLEN         4


/**
 * @brief Interface name string length
 *
 * There is IFNAMSIZ but this does not work with macro string indirection.
 * Reason is, the number of characters a valid interface name can have is
 * (IFNAMSIZ - 1) wich, as indirected string, turns out to be something like
 * "16 - 1" and not "15". The former cannot be used in a regular expresion as
 * quantifier whilst the latter could be. Thus we define our own constant, which
 * also is a bit larger than current IFNAMSIZ definitions. Just to be sure :)
 */
#define RAT_IFNAMELEN           23


/* --- hardware addresses --------------------------------------------------- */


/**
 * @brief Hardware address length
 *
 * Hardware addresses (read: link-layer addresses) larger than 8
 * octets are rather hard to find. However, net/if_dl.h on *BSD
 * reserves 12 chars for it. To avoid overflowing the buffer some day
 * we too reserve 12 octets for the hardware address. Linux header
 * file packet/netpacket.h reserves only 8 octets.
 */
#define RAT_HWADDR_SIZ          12


/**
 * @brief Asciiz representation of hardware addresses
 *
 * Example:
 *
 *      0x001122334455 -> "00:11:22:33:44:55\0"
 */
#define RAT_HWADDR_STRSIZ       (RAT_HWADDR_SIZ * 3)


/** Hardware address */
struct rat_hwaddr {
    /** Hardware address bytes */
    uint8_t                     hwa_addr[RAT_HWADDR_SIZ];
    /** Hardware address length */
    uint8_t                     hwa_len;
};


/* --- ipv6 addresses ------------------------------------------------------- */


/**
 * @brief Asciiz representation of ipv6 addresses
 *
 * Examples:
 *
 *      2001:db8::42\0
 *      2001:db8::193.160.39.34\0
 */
#define RAT_6ADDR_STRSIZ        48


/* --- prefixes ------------------------------------------------------------- */


/**
 * @brief Asciiz representation of ipv6 prefix
 *
 * Example:
 *
 *      2001:db8::42/64\0
 */
#define RAT_PREFIX_STRSIZ       (RAT_6ADDR_STRSIZ + 4)


/** IPv6 prefix */
struct rat_prefix {
    /** Address or prefix part */
    struct in6_addr             pfx_addr;
    /** Prefix length */
    uint8_t                     pfx_len;
};


/* --- return codes --------------------------------------------------------- */


/** Everything went better then expected! */
#define RAT_OK                  0

/** Problem? */
#define RAT_ERROR               -1


/* --- time ----------------------------------------------------------------- */


/** ISO time asciiz string buffer length */
#define RAT_TIME_STRSIZ         20


/* --- counters ------------------------------------------------------------- */


/**
 * @brief Asciiz representation of byte counters
 *
 * Example:
 *
 *      134217728 -> "128.00 MiB\0"
 *
 */
#define RAT_BYTES_STRSIZ        16


/* --- debug ---------------------------------------------------------------- */


/**
 * @brief Debug logging
 *
 * Logs additional information, e.g. locking counter.
 *
 * Compile with RAT_DEBUG defined to enable.
 * E.g. -DRAT_DEBUG for gcc.
 */
/** @{ */
#ifdef RAT_DEBUG
#   define RAT_DEBUG_MESSAGE(...)                                           \
        do {                                                                \
            fprintf(stderr, "Debug: %s: %d: %s: ",                          \
                    __FILE__, __LINE__, __func__);                          \
            fprintf(stderr, __VA_ARGS__);                                   \
            fprintf(stderr, "\n");                                          \
        } while (0)
#else
#   define RAT_DEBUG_MESSAGE(...)                                           \
        do { } while (0)
#endif /* RAT_DEBUG */


/**
 * @brief Debug tracing
 *
 *  Traces functions as they are being called.
 *
 * Compile with RAT_DEBUG_TRACING defined to enable.
 * E.g. -DRAT_DEBUG_TRACING for gcc.
 */
/** @{ */
#ifdef RAT_DEBUG_TRACING
#   define RAT_DEBUG_TRACE()                                                \
        do {                                                                \
            fprintf(stderr, "Trace: %s: %d: %s\n",                          \
                    __FILE__, __LINE__, __func__);                          \
        } while (0)
#else
#   define RAT_DEBUG_TRACE()    do { } while (0)
#endif /* RAT_DEBUG_TRACING */
/** @} */


/* --- NDP protocol constands ----------------------------------------------- */


/**
 * @brief IPv6 minimum MTU
 *
 *      IPv6 requires that every link in the internet have an MTU of 1280
 *      octets or greater.
 *      (RFC 2460 Sec. 5. Packet Size Issues)
 *
 */
#define RAT_IP6_MINIMUMMTU      1280

/**
 * @brief Maximum NPD message packet length
 *
 * TODO: find source for this value!
 */
#define RAT_NDP_MAXPACKETLEN    RAT_IP6_MINIMUMMTU

/**
 * @brief NDP Hop Limit
 *
 *      Hop Limit: 255
 *      (RFC 2461 sec. 4.2.  Router Advertisement Message Format)
 *
 */
#define RAT_NDP_HOPLIMIT        255

/**
 * @brief RA delay time
 *
 *      MAX_RA_DELAY_TIME                 .5 seconds
 *      (RFC 4861 sec. 10.)
 */
#define RAT_NDP_MSECDELAY_MAX   500



/* --- control messages ----------------------------------------------------- */


/**
 * @page ratools_control Control Messages
 *
 * ratools daemons are controlled by a control client using control messages and
 * control sockets. A control client (usually a CLI, e.g. ratools/ractl) sends
 * control messages (requests) via a socket (usually AF_UNIX) to a daemon. The
 * daemon sends one or more replies to the control client. A reply usually
 * contains a asciiz message to be printed by the client. The last reply message
 * a daemon sends before closing the client's control socket contains a hint for
 * a suggested exit code.
 *
 *      +-----------+
 *      | request   |
 *      +-----------+    from the CLI
 *      | -type     | +---------------->
 *      | -mid      |    to the daemon
 *      | -...      |
 *      | -data     |
 *      +-----------+
 *                          +-----------+
 *                          | reply     |-+
 *         from the daemon  +-----------+ |-+
 *       <----------------+ | -type     |-+ |
 *            to the CLI    | -msg      | |-+
 *                          +-----------+ | |
 *                            +-----------+ |
 *                              +-----------+
 *
 */


/**
 * Maximum additional data in a request message
 */
#define RAT_CTL_REQ_DATA_LEN    512

/**
 * Maximum asciiz message length in a reply message
 */
#define RAT_CTL_REPLY_MSG_LEN   123


/**
 * @brief Request control message types
 *
 * There are different types of request control messages. This enum
 * contains one element for each global (read: multi-module) control request.
 * Furthermore, there is one type to indicate that a specific module should be
 * called. The latter one is the normale use case.
 */
enum rat_ctl_request_type {
    /** Show all RAs */
    RAT_CTL_REQUEST_TYPE_SHOWALL,
    /** Dump all RA */
    RAT_CTL_REQUEST_TYPE_DUMPALL,
    /** Set log level of daemon to `error' */
    RAT_CTL_REQUEST_TYPE_SETLOGERROR,
    /** Set log level of daemon to `warning' */
    RAT_CTL_REQUEST_TYPE_SETLOGWARNING,
    /** Set log level of daemon to `info' */
    RAT_CTL_REQUEST_TYPE_SETLOGINFO,
    /** Just run the requested module */
    RAT_CTL_REQUEST_TYPE_MODULE
};


/**
 * @brief  Request control message
 *
 * Sent from a control client to a daemon.
 */
struct rat_ctl_request {
    /** Rype of request */
    enum rat_ctl_request_type   crq_type;
    /** ID of requested module*/
    uint16_t                    crq_mid;
    /** object index */
    uint16_t                    crq_oid;
    /** ID of requested action */
    uint16_t                    crq_aid;
    /** ID of requested parameter */
    uint16_t                    crq_pid;
    /** ID of requested value */
    uint16_t                    crq_vid;
    /** Index of interface */
    uint32_t                    crq_ifindex;
    /** Additional data, e.g. values for a parameter */
    uint8_t                     crq_data[RAT_CTL_REQ_DATA_LEN];
};


/**
 * @brief Types of reply messages
 */
enum rat_ctl_reply_type {
    /** Close client socket, exit with return code EXIT_SUCCESS */
    RAT_CTL_REPLY_TYPE_EXIT_OK,
    /** Close client socket, exit with return code EXIT_FAILURE */
    RAT_CTL_REPLY_TYPE_EXIT_ERROR,
    /** Print message to stdout as it is */
    RAT_CTL_REPLY_TYPE_PRINT,
    /** Print message to stdout. May apply further formatting, e.g. add EOL */
    RAT_CTL_REPLY_TYPE_MSG,
    /** Print message to stderr. May apply further formatting, e.g. add EOL */
    RAT_CTL_REPLY_TYPE_ERRMSG
};


/**
 * @brief Daemon reply message
 */
struct rat_ctl_reply {
    /** Type of reply message */
    enum rat_ctl_reply_type     cry_type;
    /** Actual reply message */
    char                        cry_msg[RAT_CTL_REPLY_MSG_LEN + 1];
};



#endif /* __RATOOLS_H */
