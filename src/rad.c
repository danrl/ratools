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


#include "rad.h"

#include "library.h"
#include "log.h"
#include "database.h"
#include "module.h"
#include "netlink.h"
#include "multicast.h"
#include "proc.h"
#include "packetset.h"
#include "ra.h"
#include "opt_mtu.h"
#include "opt_sll.h"
#include "opt_pi.h"
#include "opt_rdnss.h"
#include "opt_exp.h"

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <inttypes.h>           /* PRIu8 and friends */
#include <stdarg.h>             /* va_start(), va_end() */
#include <unistd.h>             /* close */
#include <signal.h>             /* exit clean on SIGINT/SIGTERM */
#include <sys/un.h>             /* struct sockaddr_un */
#include <netinet/icmp6.h>
#include <sys/stat.h>           /* mkdir() */
#include <getopt.h>
#include <libgen.h>             /* dirname() */


/* --- globals -------------------------------------------------------------- */


/** RS listening and RA sending socket */
static int rat_rad_rsra_sd = 0;

/** Module ID of RA core module */
static uint16_t rat_rad_ra_mid;

/** Control socket for daemon */
static int rat_rad_ctlsrv_sd = 0;

/** Control socket for accepted client */
static int rat_rad_ctlcli_sd = 0;


/* --- control message functions -------------------------------------------- */


/**
 * @page rad_control Fancy Output
 *
 * Modules, as well as the core, use a set of functions to produce fancy output
 * for the CLI. See the following figure to get an idea:
 *
 *     mf_param()
 *      |           mf_value()
 *      |            |
 *      V            V
 *     Foo:         9001   (over) <-- mf_info()
 *     Bar:         42
 *       Warning: 42 is a reserved value! <-- mf_comment()
 *
 *
 * The parameter named `Foo' was printed using the following code:
 *
 * ~~~~~~~~~~~~~~~{.c}
 * mf->mf_param(0, "Foo");
 * mf->mf_value("%u", 9001);
 * mf->mf_param("over");
 * ~~~~~~~~~~~~~~~
 *
 * Whereas the parameter `Bar' was printed using the following code:
 *
 * ~~~~~~~~~~~~~~~{.c}
 * mf->mf_param(0, "Bar");
 * mf->mf_value("%u", 42);
 * mf->mf_param(NULL);
 * mf->mf_comment(0, "Warning: %u is a reserved value!", 42);
 * ~~~~~~~~~~~~~~~
 *
 * The use of mf_comment() is optional. The indendation level
 * (here: `0') must be the same as in mf_param(), because comments
 * always get one extra level of indentation automatically.
 *
 * Note: These function are usually populated to modules as function pointers
 * using `struct rat_mod_functions'.
 */


/**
 * @brief Send a reply message
 *
 * For internal use only, should not be called from outside this file. It also
 * requires all fields of the reply struct to be set before calling.
 *
 * @param cry                   reply
 *
 * @return Returns RAT_ERROR on error, RAT_OK otherwise
 */
static int __rat_rad_ctl_send_reply (struct rat_ctl_reply *cry)
{
    RAT_DEBUG_TRACE();

    if (send(rat_rad_ctlcli_sd, cry, sizeof(*cry), 0) == sizeof(*cry))
        return RAT_OK;

    return RAT_ERROR;
}


/**
 * @brief Send a reply message
 *
 * Turns a formatted string into a reply informational message and sends it
 * to the current control client.
 *
 * @param fmt                   format string
 * @param ...                   variable number of arguments
 *
 * @return Returns RAT_ERROR on error, RAT_OK otherwise
 *
 * @see rat_ctl_print_error()
 */
static int rat_rad_ctl_print_message (const char *fmt, ...)
{
    struct rat_ctl_reply cry;
    va_list arglist;
    RAT_DEBUG_TRACE();

    memset(&cry, 0x0, sizeof(cry));
    cry.cry_type = RAT_CTL_REPLY_TYPE_MSG;
    va_start(arglist, fmt);
    vsnprintf(cry.cry_msg, RAT_CTL_REPLY_MSG_LEN, fmt, arglist);
    va_end(arglist);

    return __rat_rad_ctl_send_reply(&cry);
}


/**
 * @brief Send a reply error message
 *
 * Turns a formatted string into a reply error message and sends it to the
 * current control client.
 *
 * @param fmt                   format string
 * @param ...                   variable number of arguments
 *
 * @return Returns RAT_ERROR on error, RAT_OK otherwise
 *
 * @see rat_ctl_print_message()
 */
static int rat_rad_ctl_print_error (const char *fmt, ...)
{
    struct rat_ctl_reply cry;
    va_list arglist;
    RAT_DEBUG_TRACE();

    memset(&cry, 0x0, sizeof(cry));
    cry.cry_type = RAT_CTL_REPLY_TYPE_ERRMSG;
    va_start(arglist, fmt);
    vsnprintf(cry.cry_msg, RAT_CTL_REPLY_MSG_LEN, fmt, arglist);
    va_end(arglist);

    return __rat_rad_ctl_send_reply(&cry);
}


/**
 * @brief Send a option title reply message
 *
 * Turns a formatted string into a reply message and sends it to the current
 * control client for printing. The message contains an option title.
 *
 * @param in                    indentation level
 * @param fmt                   format string
 * @param ...                   variable number of arguments
 *
 * @return Returns RAT_ERROR on error, RAT_OK otherwise
 *
 * @see rat_rad_ctl_print_value()
 * @see rat_rad_ctl_print_info()
 * @see rat_rad_ctl_print_comment()
 */
static int rat_rad_ctl_print_title (uint8_t in, const char *fmt, ...)
{
    char tmp[RAT_CTL_REPLY_MSG_LEN + 1];
    struct rat_ctl_reply cry;
    va_list arglist;
    RAT_DEBUG_TRACE();

    memset(&cry, 0x0, sizeof(cry));
    cry.cry_type = RAT_CTL_REPLY_TYPE_PRINT;
    va_start(arglist, fmt);
    vsnprintf(tmp, RAT_CTL_REPLY_MSG_LEN, fmt, arglist);
    va_end(arglist);

    in *= 2;
    if (in)
        snprintf(cry.cry_msg, RAT_CTL_REPLY_MSG_LEN, "%*s%s\n", in, " ", tmp);
    else
        snprintf(cry.cry_msg, RAT_CTL_REPLY_MSG_LEN, "%s\n", tmp);

    return __rat_rad_ctl_send_reply(&cry);
}


/**
 * @brief Send a paramater name reply message
 *
 * Turns a formatted string into a reply message and sends it to the current
 * control client for printing. The message contains a parameter name.
 *
 * @param indent                indentation level
 * @param fmt                   format string
 * @param ...                   variable number of arguments
 *
 * @return Returns RAT_ERROR on error, RAT_OK otherwise
 *
 * @see rat_rad_ctl_print_value()
 * @see rat_rad_ctl_print_info()
 * @see rat_rad_ctl_print_comment()
 */
static int rat_rad_ctl_print_param (uint8_t indent, const char *fmt, ...)
{
    char tmp[RAT_CTL_REPLY_MSG_LEN + 1];
    struct rat_ctl_reply cry;
    va_list arglist;
    RAT_DEBUG_TRACE();

    memset(&cry, 0x0, sizeof(cry));
    cry.cry_type = RAT_CTL_REPLY_TYPE_PRINT;
    va_start(arglist, fmt);
    vsnprintf(tmp, RAT_CTL_REPLY_MSG_LEN, fmt, arglist);
    va_end(arglist);

    strncat(tmp, ":", RAT_CTL_REPLY_MSG_LEN - strlen(tmp));
    indent = (indent + 1) * 2;
    snprintf(cry.cry_msg, RAT_CTL_REPLY_MSG_LEN, "%*s%*s", indent, " ",
             indent - 26, tmp);

    return __rat_rad_ctl_send_reply(&cry);
}


/**
 * @brief Send a paramater value reply message
 *
 * Turns a formatted string into a reply message and sends it to the current
 * control client for printing. The message contains parameter's value.
 *
 * @param fmt                   format string
 * @param ...                   variable number of arguments
 *
 * @return Returns RAT_ERROR on error, RAT_OK otherwise
 *
 * @see rat_rad_ctl_print_name()
 * @see rat_rad_ctl_print_info()
 * @see rat_rad_ctl_print_comment()
 */
static int rat_rad_ctl_print_value (const char *fmt, ...)
{
    char tmp[RAT_CTL_REPLY_MSG_LEN + 1];
    struct rat_ctl_reply cry;
    va_list arglist;
    RAT_DEBUG_TRACE();

    memset(&cry, 0x0, sizeof(cry));
    cry.cry_type = RAT_CTL_REPLY_TYPE_PRINT;
    va_start(arglist, fmt);
    vsnprintf(tmp, RAT_CTL_REPLY_MSG_LEN, fmt, arglist);
    va_end(arglist);

    snprintf(cry.cry_msg, RAT_CTL_REPLY_MSG_LEN, "%*s", -16, tmp);

    return __rat_rad_ctl_send_reply(&cry);
}


/**
 * @brief Send a paramater info reply message
 *
 * Turns a formatted string into a reply message and sends it to the current
 * control client for printing. The message contains a parameter's additional
 * information.
 *
 * @param fmt                   format string
 * @param ...                   variable number of arguments
 *
 * @return Returns RAT_ERROR on error, RAT_OK otherwise
 *
 * @see rat_rad_ctl_print_name()
 * @see rat_rad_ctl_print_value()
 * @see rat_rad_ctl_print_comment()
 */
static int rat_rad_ctl_print_info (const char *fmt, ...)
{
    char tmp[RAT_CTL_REPLY_MSG_LEN + 1];
    struct rat_ctl_reply cry;
    va_list arglist;
    RAT_DEBUG_TRACE();

    memset(&cry, 0x0, sizeof(cry));
    cry.cry_type = RAT_CTL_REPLY_TYPE_PRINT;
    if (fmt) {
		va_start(arglist, fmt);
		vsnprintf(tmp, RAT_CTL_REPLY_MSG_LEN, fmt, arglist);
		va_end(arglist);
        snprintf(cry.cry_msg, RAT_CTL_REPLY_MSG_LEN, "(%s)\n", tmp);
	}
	else {
		snprintf(cry.cry_msg, RAT_CTL_REPLY_MSG_LEN, "\n");
	}

    return __rat_rad_ctl_send_reply(&cry);
}


/**
 * @brief Send a paramater comment reply message
 *
 * Turns a formatted string into a reply message and sends it to the current
 * control client for printing. The message contains a parameter's optional
 * comment.
 *
 * @param indent                indentation level
 * @param fmt                   format string
 * @param ...                   variable number of arguments
 *
 * @return Returns RAT_ERROR on error, RAT_OK otherwise
 *
 * @see rat_rad_ctl_print_name()
 * @see rat_rad_ctl_print_value()
 * @see rat_rad_ctl_print_info()
 */
static int rat_rad_ctl_print_comment (uint8_t indent, const char *fmt, ...)
{
    char tmp[RAT_CTL_REPLY_MSG_LEN + 1];
    struct rat_ctl_reply cry;
    va_list arglist;
    RAT_DEBUG_TRACE();

    memset(&cry, 0x0, sizeof(cry));
    cry.cry_type = RAT_CTL_REPLY_TYPE_PRINT;
    va_start(arglist, fmt);
    vsnprintf(tmp, RAT_CTL_REPLY_MSG_LEN, fmt, arglist);
    va_end(arglist);

    indent = (indent + 2) * 2;
    snprintf(cry.cry_msg, RAT_CTL_REPLY_MSG_LEN, "%*s%s\n", indent, " ", tmp);

    return __rat_rad_ctl_send_reply(&cry);
}


/**
 * @brief Send exit code RAT_OK
 *
 * Sends a reply message to the client telling it to close the control socket
 * and exit with return code 'EXIT_SUCCESS'.
 *
 * @return Returns RAT_ERROR on error, RAT_OK otherwise
 *
 * @see rat_rad_ctl_send_exit_error()
 */
static int rat_rad_ctl_send_exit_ok (void)
{
    struct rat_ctl_reply cry;
    RAT_DEBUG_TRACE();

    cry.cry_type = RAT_CTL_REPLY_TYPE_EXIT_OK;

    return __rat_rad_ctl_send_reply(&cry);
}


/**
 * @brief Send exit code RAT_ERROR
 *
 * Sends a reply message to the client telling it to close the control socket
 * and exit with return code 'EXIT_FAILURE'.
 *
 * @return Returns RAT_ERROR on error, RAT_OK otherwise
 *
 * @see rat_rad_ctl_send_exit_ok()
 */
static int rat_rad_ctl_send_exit_error (void)
{
    struct rat_ctl_reply cry;
    RAT_DEBUG_TRACE();

    cry.cry_type = RAT_CTL_REPLY_TYPE_EXIT_ERROR;

    return __rat_rad_ctl_send_reply(&cry);
}


/** Module helper functions */
static struct rat_mod_functions rat_rad_mf = {
    .mf_message                 = rat_rad_ctl_print_message,
    .mf_error                   = rat_rad_ctl_print_error,
    .mf_title                   = rat_rad_ctl_print_title,
    .mf_param                   = rat_rad_ctl_print_param,
    .mf_value                   = rat_rad_ctl_print_value,
    .mf_info                    = rat_rad_ctl_print_info,
    .mf_comment                 = rat_rad_ctl_print_comment
};


/* --- little helper functions ---------------------------------------------- */


/**
 * @brief Find ancillary data of specific type
 *
 * @param msg                   message header
 * @param type                  type of data to find
 *
 * @return Returns pointer to requested data or NULL if not found.
 */
static inline void *rat_rad_find_cmsgdata (struct msghdr *msg, int type)
{
    struct cmsghdr *cmsg = NULL;
    RAT_DEBUG_TRACE();

    for (cmsg = CMSG_FIRSTHDR(msg); cmsg; cmsg = CMSG_NXTHDR(msg, cmsg))
        if ((cmsg->cmsg_level == IPPROTO_IPV6) && (cmsg->cmsg_type == type))
            return CMSG_DATA(cmsg);

    return NULL;
}


/**
 * @brief Dummy thread that instantly dies
 *
 * This little friend might seem a little odd, but it does a good and important
 * job. Every pthread_t for a joinable thread needs to be used at least once.
 * Otherwise pthread_join() will fail on it leading to ugly segfaults. If this
 * dummy thread wasn't around, the daemon could segfault when receiving SIGINT
 * after a RA was created that was never enabled.
 *
 * @param ptr                   thread argument
 *
 * @return Returns nothing
 */
static void *rat_rad_thread_dummy (void *ptr)
{
    RAT_DISCARD_UNUSED(ptr);
    pthread_exit(NULL);
}


/* --- instance information preparation functions --------------------------- */


/**
 * @brief Add additional data to instance information
 *
 * We are leaking some additional data to the module instances to help modules
 * making decissions about reasonable behavior and values.
 *
 * @param db                    database entry
 * @param mi                    instance data buffer
 */
static void rat_rad_fill_mi_additional (struct rat_db *db,
                                        struct rat_mod_instance *mi)
{
    if (!db || !mi)
        goto exit;

    /* additional information */
    mi->mi_maxadvint = db->db_maxadvint;
    switch (db->db_state) {
        case RAT_DB_STATE_FADEOUT1:
        case RAT_DB_STATE_FADEOUT2:
        case RAT_DB_STATE_FADEOUT3:
            mi->mi_fadingout = 1;
            break;
        default:
            mi->mi_fadingout = 0;
            break;
    }
    mi->mi_linkmtu = db->db_mtu;
    memcpy(&mi->mi_hwaddr, &db->db_hwaddr, sizeof(mi->mi_hwaddr));

exit:
    return;
}


/**
 * @brief Prepare instance information for RA a module instance
 *
 * @param db                    database entry
 * @param mi                    instance data buffer
 *
 * @return Returns RAT_ERROR on error, RAT_OK otherwise
 */
static int rat_rad_fill_mi_ra (struct rat_db *db, struct rat_mod_instance *mi)
{
    RAT_DEBUG_TRACE();

    if (!db || !mi)
        return RAT_ERROR;

    memset(mi, 0x0, sizeof(*mi));
    mi->mi_ifindex = RAT_DB_IFINDEX(db);
    mi->mi_index = 0;
    mi->mi_in = 0;

    /* human readable name of instance*/
    snprintf(mi->mi_myname, sizeof(mi->mi_myname), RAT_RAMODNAME "@%s",
             db->db_ifname);

    /* private data */
    mi->mi_private = &db->db_ra_private;
    mi->mi_rawdata = &db->db_ra_rawdata;
    mi->mi_rawlen = &db->db_ra_rawlen;

    rat_rad_fill_mi_additional(db, mi);

    return RAT_OK;
}


/**
 * @brief Prepare instance information based on option reference
 *
 * @param db                    database entry
 * @param opt                   option
 * @param mi                    instance data buffer
 *
 * @return Returns RAT_ERROR on error, RAT_OK otherwise
 */
static int rat_rad_fill_mi_opt (struct rat_db *db, struct rat_db_opt *opt,
                                struct rat_mod_instance *mi)
{
    char *modname;
    RAT_DEBUG_TRACE();

    if (!db || !opt || !mi)
        goto exit_err;

    modname = rat_mod_get_name(opt->opt_mid);
    if (!modname)
        goto exit_err;

    /* craft instance information */
    memset(mi, 0x0, sizeof(*mi));
    mi->mi_ifindex = RAT_DB_IFINDEX(db);
    mi->mi_in = 1;

    /* index and human readable name of instance */
    if (rat_mod_requires_oid(opt->opt_mid)) {
        mi->mi_index = opt->opt_oid;
        snprintf(mi->mi_myname, sizeof(mi->mi_myname), "%s%" PRIu16 "@%s",
                 modname, opt->opt_oid, db->db_ifname);
    } else {
        mi->mi_index = 0;
        snprintf(mi->mi_myname, sizeof(mi->mi_myname), "%s@%s", modname,
                 db->db_ifname);
    }

    /* private data */
    mi->mi_private = &opt->opt_private;
    mi->mi_rawdata = &opt->opt_rawdata;
    mi->mi_rawlen = &opt->opt_rawlen;

    rat_rad_fill_mi_additional(db, mi);

    return RAT_OK;

exit_err:
    return RAT_ERROR;
}


/* --- compilation and packet set preparation ------------------------------- */


/**
 * @brief Compile RA and all options
 *
 * @param db                    database entry
 *
 * @return Returns RAT_ERROR on error, RAT_OK otherwise
 */
static int rat_rad_compile (struct rat_db *db)
{
    struct rat_mod_instance mi;
    struct rat_db_opt *opt;
    RAT_DEBUG_TRACE();

    /* skip compilation if possible to save cycle, time and energy */
    if (db->db_compiled == db->db_version)
        goto exit_ok;

    /* compile RA */
    if (rat_rad_fill_mi_ra(db, &mi) != RAT_OK) {
        rat_log_err("Could not prepare instance information for RA on " \
                    "interface `%" PRIu32 "'!", RAT_DB_IFINDEX(db));
        goto exit_err;
    }
    if (rat_mod_rad_call_compile(&mi, rat_rad_ra_mid) != RAT_OK) {
        rat_log_err("Could not compile `%s'!", mi.mi_myname);
        goto exit_err;
    }

    /* compile options */
    for (opt = db->db_opt; opt; opt = opt->opt_next) {
        if (rat_rad_fill_mi_opt(db, opt, &mi) != RAT_OK) {
            rat_log_err("Could not prepare instance information for module " \
                        "`%" PRIu16 "' instance `%" PRIu16 "' on " \
                        "interface `%" PRIu32 "'!",
                        opt->opt_mid, opt->opt_oid, RAT_DB_IFINDEX(db));
            continue;
        }
        if (rat_mod_rad_call_compile(&mi, opt->opt_mid) != RAT_OK) {
            rat_log_err("Could not compile `%s'!", mi.mi_myname);
            continue;
        }
    }

    db->db_compiled = db->db_version;

exit_ok:
    return RAT_OK;

exit_err:
    return RAT_ERROR;
}


/**
 * @brief Create packet set of RA
 *
 * @param db                    database entry
 *
 * @return Returns RAT_ERROR on error, RAT_OK otherwise
 */
static struct rat_ps *rat_rad_packetset (struct rat_db *db)
{
    struct rat_ps *ps = NULL;
    struct rat_db_opt *opt;
    RAT_DEBUG_TRACE();

    if (!db)
        goto exit_err;

    /* initialize packet set */
    ps = rat_ps_create();
    if (!ps)
        goto exit_err;

    /* set defaults */
    rat_ps_set_sd(ps, rat_rad_rsra_sd);
    rat_ps_set_ifindex(ps, db->db_ifindex);
    rat_ps_set_saddr(ps, &db->db_lladdr);
    rat_ps_set_delay(ps, 0);

    /* set RA header */
    rat_ps_set_header(ps, db->db_ra_rawdata, db->db_ra_rawlen);

    /* add options */
    for (opt = db->db_opt; opt; opt = opt->opt_next) {
        if (!opt->opt_rawdata || !opt->opt_rawlen)
            continue;
        if (rat_ps_add_data(ps, opt->opt_rawdata, opt->opt_rawlen) != RAT_OK)
            goto exit_err;
    }

    return ps;

exit_err:
    if (ps)
        ps = rat_ps_destroy(ps);
    return NULL;
}


/* --- worker threads for listening to RS and receiving RA ------------------ */


/**
 * @brief RS listener thread
 *
 * Thread argument has to be set to NULL!
 *
 * @param ptr                   thread argument
 */
static void *rat_rad_listener (void *ptr)
{
    int err, val;
    /* satisfying pselect() */
    sigset_t emptyset, blockset;
    fd_set rfds;
    /* socket and ipv6 addresses */
    struct icmp6_filter filter;
    struct sockaddr_in6 srcaddr;
    ssize_t slen;
    /* ancillary data */
    struct msghdr msghdr;
    struct iovec iov;
    int *hl;
    int unspecified;
    struct in6_pktinfo *ipi;
    uint8_t cmsgbuf[CMSG_SPACE(sizeof(int)) + CMSG_SPACE(sizeof(*ipi))];
    char srcname[INET6_ADDRSTRLEN];
    char dstname[INET6_ADDRSTRLEN];
    /* payload buffer */
    uint8_t buf[RAT_NDP_MAXPACKETLEN];
    struct nd_router_solicit *ndrs;
    /* others */
    struct rat_db *db = NULL;
    useconds_t delay;
    struct rat_ps *ps;
    uint64_t bytes;
    RAT_DEBUG_TRACE();

    rat_log_nfo("Listener: Thread started.");

    if (ptr)
        goto exit;

    /* block SIGINT on normal operation */
    sigemptyset(&blockset);
    sigaddset(&blockset, SIGINT);
    pthread_sigmask(SIG_BLOCK, &blockset, NULL);

    /* register signal for times we are waiting for pselect() */
    signal(SIGINT, rat_lib_signal_dummy_handler);

    /* empty set for times we are waiting for pselect() */
    sigemptyset(&emptyset);

    /* check socket */
    if (rat_rad_rsra_sd < 0) {
        rat_log_err("Listener: Could not use socket: %s", strerror(errno));
        goto exit;
    }

    /*
     * filtering of ICMPv6 messages using the advanced sockets
     * sockets API for IPv6 https://tools.ietf.org/html/rfc2292#section-3.2
     */
    ICMP6_FILTER_SETBLOCKALL(&filter);
    ICMP6_FILTER_SETPASS(ND_ROUTER_SOLICIT, &filter);
    err = setsockopt(rat_rad_rsra_sd, IPPROTO_ICMPV6, ICMP6_FILTER, &filter,
                     sizeof(filter));
    if (err < 0)
        rat_log_wrn("Listener: Could not set ICMPv6 socket filter: %s",
                    strerror(errno));
    /* receive hop limit for sanity check */
    val = 1;
    err = setsockopt(rat_rad_rsra_sd, IPPROTO_IPV6, IPV6_RECVHOPLIMIT, &val,
                     sizeof(val));
    if (err < 0) {
        rat_log_err("Listener: Could not request hop limit: %s",
                    strerror(errno));
        goto exit;
    }

    /* receive packet info */
    val = 1;
    err = setsockopt(rat_rad_rsra_sd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &val,
                     sizeof(val));
    if (err < 0) {
        rat_log_err("Listener: Could not request packet info: %s",
                    strerror(errno));
        goto exit;
    }

    /* prepare message buffer */
    iov.iov_base = buf;
    iov.iov_len = RAT_NDP_MAXPACKETLEN;
    msghdr.msg_name = &srcaddr;
    msghdr.msg_namelen = sizeof(srcaddr);
    msghdr.msg_iov = &iov;
    msghdr.msg_iovlen = 1;
    msghdr.msg_control = &cmsgbuf;
    msghdr.msg_controllen = sizeof(cmsgbuf);

    /* pselect() file descriptor set */
    FD_ZERO(&rfds);
    FD_SET(rat_rad_rsra_sd, &rfds);

    for (;;) {
        if (db)
            db = rat_db_release(db);                               /* RELEASE */

        /* wait for data or thread signal */
        if (pselect(rat_rad_rsra_sd + 1, &rfds,
                    NULL, NULL, NULL, &emptyset) == -1 &&
            errno == EINTR)
            goto exit;

        /* receive data */
        slen = recvmsg(rat_rad_rsra_sd, &msghdr, 0);
        if (slen < 0)
            goto exit;

        /* check type */
        ndrs = (struct nd_router_solicit *) buf;
        if (ndrs->nd_rs_type != ND_ROUTER_SOLICIT)
            continue;

        /* extract and prepare ancillary data */
        hl = (int *) rat_rad_find_cmsgdata(&msghdr, IPV6_HOPLIMIT);
        ipi = (struct in6_pktinfo *) rat_rad_find_cmsgdata(&msghdr,
                                                           IPV6_PKTINFO);
        if (!hl || !ipi ||
            !inet_ntop(AF_INET6, (void *) &srcaddr.sin6_addr, srcname,
                       sizeof(srcname)) ||
            !inet_ntop(AF_INET6, (void *) &ipi->ipi_addr, dstname,
                       sizeof(dstname)))
            continue;

        /* check hop limit */
        if (*hl != RAT_NDP_HOPLIMIT) {
            rat_log_wrn("Listener: Interface %u: Received RS " \
                        "with invalid hop limit `%d' from `%s'",
                        ipi->ipi_ifindex, *hl, srcname);
            continue;
        }

        /* check source address */
        unspecified = rat_lib_6addr_is_unspecified(&srcaddr.sin6_addr);
        if (!rat_lib_6addr_is_linklocal(&srcaddr.sin6_addr) && !unspecified) {
            rat_log_wrn("Listener: Interface %u: Received RS from invalid " \
                        "source address `%s'", ipi->ipi_ifindex, srcname);
            continue;
        }

        /* check destination address */
        if (!rat_lib_6addr_is_allrouters(&ipi->ipi_addr)) {
            rat_log_wrn("Listener: Interface %u: Received RS with invalid " \
                        "destination address `%s' from `%s'",
                        ipi->ipi_ifindex, dstname, srcname);
            continue;
        }

        /* log RS */
        rat_log_nfo("Listener: Interface %u: Received RS from `%s' " \
                    "(%zu bytes)", ipi->ipi_ifindex, srcname, slen);

        db = rat_db_grab(ipi->ipi_ifindex);                           /* GRAB */
        if (!db)
            continue;

        /* check for valid state, other functions may have changed it */
        if (db->db_state == RAT_DB_STATE_DISABLED ||
            db->db_state == RAT_DB_STATE_DESTROYED) {
            continue;
        }


        /* send RA and update stats */
        /*
         * In all cases, Router Advertisements sent in response to a Router
         * Solicitation MUST be delayed by a random time between 0 and
         * MAX_RA_DELAY_TIME seconds. (If a single advertisement is sent in
         * response to multiple solicitations, the delay is relative to the
         * first solicitation.)
         *
         * (RFC 4861 sec. 6.2.6)
         */
         delay = (rand() % RAT_NDP_MSECDELAY_MAX) * 1000;
        /*
         * A router MAY choose to unicast the response directly to the
         * soliciting host's address (if the solicitation's source address is
         * not the unspecified address), but the usual case is to multicast the
         * response to the all-nodes group.
         *
         * (RFC 4861 sec. 6.2.6.)
         */
        /*
         * [RFC4861] in section 6.2.6 already allows to do so via a MAY verb (if
         * the solicitation's source address is not the unspecified address).
         * This is further weakened by the subsequent qualifier being "but the
         * usual case is to multicast the response to the all-nodes group."  As
         * a result of this, a lot of implementations do multicast the solicited
         * RAs, significantly impacting the devices.
         *
         * To help address this, all router implementations SHOULD have a way to
         * send solicited RAs unicast in the environments which wish to do so.
         *
         * (draft-yourtchenko-colitti-nd-reduce-multicast-00 sec. 4.2)
         */
        if (unspecified) {
            db->db_delay = delay;
            pthread_cond_signal(&db->db_worker_cond);
        } else {
            /* send RA */
            if (rat_rad_compile(db) != RAT_OK) {
                rat_log_err("Listener: Interface %" PRIu32 ": " \
                            "Could not compile RA", db->db_ifindex);
                continue;
            }
            ps = rat_rad_packetset(db);
            if (!ps) {
                rat_log_err("Listener: Interface %" PRIu32 ": " \
                            "Could not create packet set", db->db_ifindex);
                continue;
            }
            rat_ps_set_daddr(ps, &srcaddr.sin6_addr);
            rat_ps_set_delay(ps, delay);
            bytes = rat_ps_get_size(ps);

            if (rat_ps_send(ps) != RAT_OK) {
                rat_log_err("Listener: Interface %" PRIu32 ": " \
                            "Could not send packet set", db->db_ifindex);
                continue;
            }

            /* update statistics */
            db->db_stat_total++;
            db->db_stat_solicited++;
            db->db_stat_bytes += bytes;
        }
    }

exit:
    FD_ZERO(&rfds);
    rat_log_nfo("Listener: Thread stopped.");
    pthread_exit(NULL);
}


/**
 * @brief RA worker thread
 *
 * @param ptr                   thread argument
 *
 * @return Detached thread. Does not return a value.
 */
static void *rat_rad_worker (void *ptr)
{
    uint16_t ifindex = *((uint32_t *) ptr);
    struct rat_db *db = NULL;
    int iv;
    struct rat_ps *ps;
    struct in6_addr allnodes;
    uint64_t bytes;
    RAT_DEBUG_TRACE();

    rat_lib_6addr_set_allnodes(&allnodes);
    rat_log_nfo("Worker: Interface %" PRIu32 ": Thread started.", ifindex);

    db = rat_db_grab(ifindex);
    if (!db) {
        rat_log_err("Worker: Interface %" PRIu32 ": Could not grab interface!",
                    ifindex);
        goto exit;
    }

    /* join all routers multicast group for solicited RAs */
    if (rat_mc_join(rat_rad_rsra_sd, ifindex) == RAT_OK)
        rat_log_nfo("Worker: Interface %" PRIu32 ": Joined " \
                    "all routers multicast group.", ifindex);
    else
        rat_log_wrn("Worker: Interface %" PRIu32 ": Could not join " \
                    "all routers multicast group.", ifindex);

    for (;;) {
        /*
         * Unsolicited Router Advertisements are not strictly periodic: the
         * interval between subsequent transmissions is randomized to reduce the
         * probability of synchronization with the advertisements from other
         * routers on the same link [SYNC].  Each advertising interface has its
         * own timer.  Whenever a multicast advertisement is sent from an
         * interface, the timer is reset to a uniformly distributed random value
         * between the interface's configured MinRtrAdvInterval and
         * MaxRtrAdvInterval; expiration of the timer causes the next
         * advertisement to be sent and a new random value to be chosen.
         * (RFC 4861 sec. 10.)
         */
        iv = db->db_minadvint;
        iv += rand() % (1 + db->db_maxadvint - db->db_minadvint);

        /*
         * For the first few advertisements (up to
         * MAX_INITIAL_RTR_ADVERTISEMENTS) sent from an interface when it
         * becomes an advertising interface, if the randomly chosen interval is
         * greater than MAX_INITIAL_RTR_ADVERT_INTERVAL, the timer SHOULD be set
         * to MAX_INITIAL_RTR_ADVERT_INTERVAL instead.  Using a smaller interval
         * for the initial advertisements increases the likelihood of a router
         * being discovered quickly when it first becomes available, in the
         * presence of possible packet loss.
         * (RFC 4861 sec. 10.)
         */
        switch (db->db_state) {
            case RAT_DB_STATE_FADEIN1:
            case RAT_DB_STATE_FADEOUT1:
                iv = 0;
                break;
            case RAT_DB_STATE_FADEIN2:
            case RAT_DB_STATE_FADEIN3:
                iv = MIN(iv, RAT_DB_MAXADVINT_INIT);
                break;
            case RAT_DB_STATE_FADEOUT2:
            case RAT_DB_STATE_FADEOUT3:
                iv = RAT_DB_MINADVINT_MIN;
                break;
            default:
                break;
        }

        if (iv) {
            db->db_worker_next.tv_sec = time(NULL) + iv;
            rat_log_nfo("Worker: Interface %" PRIu32 ": Sleeping %d seconds.",
                        ifindex, iv);
            rat_db_release(db);                                    /* RELEASE */

            /*
             * going to sleep
             * --------------
             * basically this is `write after release' what we are doing here :(
             * TODO: describe why this is ok here and how this does not void the
             * locking
             */
            pthread_cond_timedwait(&db->db_worker_cond, &db->db_worker_mutex,
                                   &db->db_worker_next);

            /*   ____                 _         _       _     _   _
             *  / ___| ___   ___   __| |  _ __ (_) __ _| |__ | |_| |
             * | |  _ / _ \ / _ \ / _` | | '_ \| |/ _` | '_ \| __| |
             * | |_| | (_) | (_) | (_| | | | | | | (_| | | | | |_|_|
             *  \____|\___/ \___/ \__,_| |_| |_|_|\__, |_| |_|\__(_)
             *                                    |___/sweet prince!
             */
            db = rat_db_grab(ifindex);                                /* GRAB */
            if (!db) {
                rat_log_err("Worker: Interface %" PRIu32 ": " \
                            "Could not grab interface!", ifindex);
                goto exit;
            }
        }

        /* check for valid state, other functions may have changed it */
        if (db->db_state == RAT_DB_STATE_DISABLED ||
            db->db_state == RAT_DB_STATE_DESTROYED)
            goto exit_release;

        /* check for interface state */
        if (!db->db_ifup) {
            rat_log_err("Worker: Interface %" PRIu32 ":" \
                        "Interface went down!", ifindex);
            goto exit_release;
        }

        /* send RA */
        if (rat_rad_compile(db) != RAT_OK) {
            rat_log_err("Worker: Interface %" PRIu32 ":" \
                        "Could not compile RA!", ifindex);
            goto exit_release;
        }
        ps = rat_rad_packetset(db);
        if (!ps) {
            rat_log_err("Worker: Interface %" PRIu32 ":" \
                        "Could not create packet set!", ifindex);
            goto exit_release;
        }
        rat_ps_set_daddr(ps, &allnodes);
        rat_ps_set_delay(ps, db->db_delay);
        db->db_delay = 0; /* reset delay */
        bytes = rat_ps_get_size(ps);

        rat_log_nfo("Worker: Interface %" PRIu32 ": Sending RA.", ifindex);

        if (rat_ps_send(ps) != RAT_OK) {
            rat_log_err("Worker: Interface %" PRIu32 ":" \
                        "Could not send packet set!", ifindex);
            goto exit_release;
        }

        /* update statistics */
        db->db_stat_total++;
        db->db_stat_multicast++;
        db->db_stat_bytes += bytes;

        /* update state */
        switch (db->db_state) {
        case RAT_DB_STATE_FADEIN1:
            db->db_state = RAT_DB_STATE_FADEIN2;
            rat_db_updated(db);
            break;
        case RAT_DB_STATE_FADEIN2:
            db->db_state = RAT_DB_STATE_FADEIN3;
            rat_db_updated(db);
            break;
        case RAT_DB_STATE_FADEIN3:
            db->db_state = RAT_DB_STATE_ENABLED;
            rat_db_updated(db);
            break;
        case RAT_DB_STATE_FADEOUT1:
            db->db_state = RAT_DB_STATE_FADEOUT2;
            rat_db_updated(db);
            break;
        case RAT_DB_STATE_FADEOUT2:
            db->db_state = RAT_DB_STATE_FADEOUT3;
            rat_db_updated(db);
            break;
        case RAT_DB_STATE_FADEOUT3:
            db->db_state = RAT_DB_STATE_DISABLED;
            goto exit_release;
            break;
        default:
            break;
        }
    }

exit_release:
    if (db) {
        db->db_state = RAT_DB_STATE_DISABLED;
        db->db_worker_next.tv_sec = 0;
        rat_db_updated(db);
        db = rat_db_release(db);
    }
    /* leave all routers multicast group for solicited RAs */
    if (rat_mc_leave(rat_rad_rsra_sd, ifindex) == RAT_OK)
        rat_log_nfo("Worker: Interface %" PRIu32 ": Left " \
                    "all routers multicast group ", ifindex);
    else
        rat_log_wrn("Worker: Interface %" PRIu32 ": Could not leave " \
                    "all routers multicast group ", ifindex);
exit:
    rat_log_nfo("Worker: Interface %" PRIu32 ": Thread stopped.", ifindex);
    pthread_exit(NULL);
}


/* --- managing RAs --------------------------------------------------------- */


/**
 * @brief Destroy RA
 *
 * @param db                    database entry
 *
 * @return Returns RAT_ERROR on error, RAT_OK otherwise
 */
static int rat_rad_ra_destroy (struct rat_db *db)
{
    uint32_t ifindex;
    struct rat_db_opt *opt;
    struct rat_mod_instance mi;
    RAT_DEBUG_TRACE();

    if (db->db_state != RAT_DB_STATE_DISABLED) {
        rat_rad_mf.mf_error("RA is still active. Disable first!");
        goto exit_err;
    }
    db->db_state = RAT_DB_STATE_DESTROYED;

    /* kill all the options */
    while (db->db_opt) {
        opt = db->db_opt;
        rat_rad_fill_mi_opt(db, opt, &mi);
        rat_mod_rad_call_aid(&rat_rad_mf, &mi, opt->opt_mid,
                             RAT_MOD_AID_KILL);
        rat_mod_rad_call_aid(&rat_rad_mf, &mi, opt->opt_mid,
                             RAT_MOD_AID_DESTROY);
        rat_db_del_opt(db, opt->opt_mid, opt->opt_oid);
    }

    ifindex = RAT_DB_IFINDEX(db);
    db = rat_db_release(db);
    rat_db_destroy(ifindex);

    return RAT_OK;

exit_err:
    return RAT_ERROR;
}


/**
 * @brief Create RA
 *
 * Creates the framework's part of RA and calls the RA module's create-function
 * afterwards.
 *
 * @param ifindex               interface index
 *
 * @return Returns RAT_ERROR on error, RAT_OK otherwise
 */
static int rat_rad_ra_create (uint32_t ifindex)
{
    struct rat_db *db;
    struct rat_mod_instance mi;
    RAT_DEBUG_TRACE();

    if (rat_db_create(ifindex) != RAT_OK) {
        rat_rad_mf.mf_error("Could not create database entry for " \
                            "Router Advertisement!");
        goto exit_err;
    }

    db = rat_db_grab(ifindex);
    if (!db) {
        rat_rad_mf.mf_error("Could not get database entry for " \
                            "Router Advertisement!");
        goto exit_err;
    }

    db->db_state = RAT_DB_STATE_DISABLED;
    db->db_maxadvint = RAT_DB_MAXADVINT_DEF;
    db->db_minadvint = RAT_DB_MINADVINT_DEF;
    db->db_created = time(NULL);
    db->db_updated = time(NULL);
    db->db_version = 1;

    /* thread */
    pthread_attr_init(&db->db_worker_attr);
    pthread_attr_setdetachstate(&db->db_worker_attr, PTHREAD_CREATE_JOINABLE);
    if (pthread_create(&db->db_worker_thread, &db->db_worker_attr,
                       rat_rad_thread_dummy, NULL)) {
        rat_rad_mf.mf_error("Could not initialize worker thread.");
        goto exit_err_destroy;
    }
    pthread_join(db->db_worker_thread, NULL);


    /* interface */
    if (rat_nl_init_db(db) != RAT_OK) {
        rat_rad_mf.mf_error("Could not initialize! Interface down?");
        goto exit_err_destroy;
    }
    if (rat_prc_forwarding(db) != RAT_OK) {
        rat_rad_mf.mf_error("Could not read procfs!");
        goto exit_err_destroy;
    }

    /* module */
    if (rat_rad_fill_mi_ra(db, &mi) != RAT_OK) {
        rat_rad_mf.mf_error("Could not prepare instance information for RA " \
                            " on interface `%" PRIu32 "'!", ifindex);
        goto exit_err_destroy;
    }
    if (rat_mod_rad_call_aid(&rat_rad_mf, &mi, rat_rad_ra_mid,
                             RAT_MOD_AID_CREATE) != RAT_OK) {
        rat_rad_mf.mf_error("Could not initialize Router Advertisement!");
        goto exit_err_destroy;
    }

    db = rat_db_release(db);

    return RAT_OK;

exit_err_destroy:
    if (db) {
        pthread_attr_destroy(&db->db_worker_attr);
        db = rat_db_release(db);
    }
    rat_db_destroy(ifindex);
exit_err:
    return RAT_ERROR;
}


/**
 * @brief Show RA
 *
 * Shows the framework's part of RA and calls the RA module's show-function
 * afterwards.
 *
 * @param db                    database entry
 *
 * @return Returns RAT_ERROR on error, RAT_OK otherwise
 */
static int rat_rad_ra_show (struct rat_db *db)
{
    int ret;
    char buffer[MAX(
                    MAX(
                        RAT_BYTES_STRSIZ,
                        RAT_TIME_STRSIZ
                    ),
                    MAX(
                        RAT_HWADDR_STRSIZ,
                        RAT_6ADDR_STRSIZ
                    )
                )];
    struct rat_mod_instance mi;
    struct rat_db_opt *opt;
    RAT_DEBUG_TRACE();

    rat_rad_fill_mi_ra(db, &mi);

    rat_rad_mf.mf_title(0, "Router Advertisement `%s':", mi.mi_myname);

    rat_rad_mf.mf_param(0, "State");
    switch (db->db_state) {
        case RAT_DB_STATE_FADEIN1:
            rat_rad_mf.mf_value("Fading in");
            rat_rad_mf.mf_info("1%%");
            break;
        case RAT_DB_STATE_FADEIN2:
            rat_rad_mf.mf_value("Fading in");
            rat_rad_mf.mf_info("34%%");
            break;
        case RAT_DB_STATE_FADEIN3:
            rat_rad_mf.mf_value("Fading in");
            rat_rad_mf.mf_info("67%%");
            break;
        case RAT_DB_STATE_ENABLED:
            rat_rad_mf.mf_value("Enabled");
            rat_rad_mf.mf_info(NULL);
            break;
        case RAT_DB_STATE_FADEOUT1:
            rat_rad_mf.mf_value("Fading out");
            rat_rad_mf.mf_info("1%%");
            break;
        case RAT_DB_STATE_FADEOUT2:
            rat_rad_mf.mf_value("Fading out");
            rat_rad_mf.mf_info("34%%");
            break;
        case RAT_DB_STATE_FADEOUT3:
            rat_rad_mf.mf_value("Fading out");
            rat_rad_mf.mf_info("67%%");
            break;
        case RAT_DB_STATE_DISABLED:
            rat_rad_mf.mf_value("Disabled");
            rat_rad_mf.mf_info(NULL);
            break;
        default:
            rat_rad_mf.mf_value("Unknown");
            rat_rad_mf.mf_info(NULL);
            rat_rad_mf.mf_comment(0, "Warning: This should never happen!");
    }

    rat_rad_mf.mf_param(0, "Created");
    rat_lib_time_to_str(buffer, sizeof(buffer), &db->db_created);
    rat_rad_mf.mf_value(buffer);
    rat_rad_mf.mf_info(NULL);

    rat_rad_mf.mf_param(0, "Updated");
    rat_lib_time_to_str(buffer, sizeof(buffer), &db->db_updated);
    rat_rad_mf.mf_value(buffer);
    rat_rad_mf.mf_info(NULL);

    rat_rad_mf.mf_param(0, "Version");
    rat_rad_mf.mf_value("%" PRIu32 "/%" PRIu32, db->db_compiled,
                        db->db_version);
    if (db->db_version != db->db_compiled)
        rat_rad_mf.mf_info("Compilation scheduled");
    else
        rat_rad_mf.mf_info(NULL);

    rat_rad_mf.mf_param(0, "Interface ID");
    rat_rad_mf.mf_value("%" PRIu32, db->db_ifindex);
    rat_rad_mf.mf_info("%s", db->db_ifname);

    rat_rad_mf.mf_param(0, "Interface State");
    rat_rad_mf.mf_value("%d", db->db_ifup);
    rat_rad_mf.mf_info("%s", db->db_ifup ? "Up" : "Down");
    if (!db->db_ifup)
        rat_rad_mf.mf_comment(0, "Warning: " \
                                 "This prevents ratools/rad from sending!");

    rat_rad_mf.mf_param(0, "Interface MTU");
    rat_rad_mf.mf_value("%" PRIu32, db->db_mtu);
    rat_rad_mf.mf_info(NULL);
    if (db->db_mtu < RAT_IP6_MINIMUMMTU)
        rat_rad_mf.mf_comment(0, "Warning: MTU must be at least `%u'!",
                              RAT_IP6_MINIMUMMTU);

    rat_rad_mf.mf_param(0, "Hardware Address");
    rat_lib_hwaddr_to_str(buffer, sizeof(buffer), &db->db_hwaddr);
    rat_rad_mf.mf_value("%s", buffer);
    rat_rad_mf.mf_info(NULL);

    rat_rad_mf.mf_param(0, "Link-local Address");
    rat_lib_6addr_to_str(buffer, sizeof(buffer), &db->db_lladdr);
    rat_rad_mf.mf_value("%s", buffer);
    rat_rad_mf.mf_info(NULL);

    rat_rad_mf.mf_param(0, "Forwarding");
    rat_rad_mf.mf_value("%d", db->db_forwarding);
    switch (db->db_forwarding) {
        case RAT_PRC_FWD_DISABLED:
            rat_rad_mf.mf_info("Disabled");
            rat_rad_mf.mf_comment(0, "Warning: " \
                                  "This system will not forward packets!");
            break;
        case RAT_PRC_FWD_ENABLED:
            rat_rad_mf.mf_info("Enabled");
            break;
        case RAT_PRC_FWD_ENABLEDRS:
            rat_rad_mf.mf_info("Enabled");
            rat_rad_mf.mf_comment(0, "Warning: " \
                                  "Interface is also listening to RA!");
            break;
        default:
            rat_rad_mf.mf_info("Unknown");
            rat_rad_mf.mf_comment(0, "Warning: Assuming forwarding enabled!");
            break;
    }

    rat_rad_mf.mf_param(0, "Maximum Interval");
    rat_rad_mf.mf_value("%" PRIu16, db->db_maxadvint);
    rat_rad_mf.mf_info("%ud %uh %um %us",
                       RAT_LIB_S_D_TO_D(db->db_maxadvint),
                       RAT_LIB_S_D_TO_H(db->db_maxadvint),
                       RAT_LIB_S_D_TO_M(db->db_maxadvint),
                       RAT_LIB_S_D_TO_S(db->db_maxadvint));

    rat_rad_mf.mf_param(0, "Minimum Interval");
    rat_rad_mf.mf_value("%" PRIu16, db->db_minadvint);
    rat_rad_mf.mf_info("%ud %uh %um %us",
                       RAT_LIB_S_D_TO_D(db->db_minadvint),
                       RAT_LIB_S_D_TO_H(db->db_minadvint),
                       RAT_LIB_S_D_TO_M(db->db_minadvint),
                       RAT_LIB_S_D_TO_S(db->db_minadvint));

    /* statistics */
    rat_rad_mf.mf_param(0, "Solicited/Unsolicited");
    rat_rad_mf.mf_value("%" PRIu64 "/%" PRIu64,
                        db->db_stat_total - db->db_stat_solicited,
                        db->db_stat_solicited);
    rat_rad_mf.mf_info(NULL);

    rat_rad_mf.mf_param(0, "Unicast/Multicast");
    rat_rad_mf.mf_value("%" PRIu64 "/%" PRIu64,
                        db->db_stat_total - db->db_stat_multicast,
                        db->db_stat_multicast);
    rat_rad_mf.mf_info(NULL);

    rat_rad_mf.mf_param(0, "Total RAs");
    rat_rad_mf.mf_value("%" PRIu64, db->db_stat_total);
    rat_lib_bytes_to_str(buffer, sizeof(buffer), db->db_stat_bytes);
    rat_rad_mf.mf_info(buffer);

    if (db->db_worker_next.tv_sec) {
        rat_rad_mf.mf_param(0, "Next RA scheduled");
        rat_lib_time_to_str(buffer, sizeof(buffer), &db->db_worker_next.tv_sec);
        rat_rad_mf.mf_value(buffer);
        rat_rad_mf.mf_info(NULL);
    }

    /* call module's show function */
    ret = rat_mod_rad_call_aid(&rat_rad_mf, &mi, rat_rad_ra_mid,
                               RAT_MOD_AID_SHOW);

    /* show options */
    for (opt = db->db_opt; opt; opt = opt->opt_next) {
        rat_rad_fill_mi_opt(db, opt, &mi);
        rat_mod_rad_call_aid(&rat_rad_mf, &mi, opt->opt_mid, RAT_MOD_AID_SHOW);
    }

    return ret;
}


/**
 * @brief Shows all RA in database
 *
 * @return Returns RAT_ERROR on error, RAT_OK otherwise
 */
static int rat_rad_ra_showall (void)
{
    struct rat_db *db;
    RAT_DEBUG_TRACE();

    db = rat_db_grab_first();
    if (!db) {
        rat_rad_mf.mf_error("No Router Advertisement configured!");
        goto exit_err;
    }
    while (db) {
        rat_rad_ra_show(db);
        db = rat_db_grab_next(db);
    }

    return RAT_OK;

exit_err:
    return RAT_ERROR;
}


/**
 * @brief Dump RA
 *
 * Dumps the framework's part of RA and calls the RA module's dump-function
 * afterwards.
 *
 * @param db                    database entry
 *
 * @return Returns RAT_ERROR on error, RAT_OK otherwise
 */
static int rat_rad_ra_dump (struct rat_db *db)
{
    int ret;
    struct rat_mod_instance mi, rami;
    struct rat_db_opt *opt;
    RAT_DEBUG_TRACE();

    if (db->db_state == RAT_DB_STATE_DESTROYED) {
        ret = RAT_OK;
        goto exit_ret;
    }

    rat_rad_fill_mi_ra(db, &rami);
    rat_rad_mf.mf_message("### Router Advertisement `%s'", rami.mi_myname);
    rat_rad_mf.mf_message("%s create", rami.mi_myname);

    if (db->db_maxadvint != RAT_DB_MAXADVINT_DEF)
        rat_rad_mf.mf_message("%s set maximum-interval %uh%um%us",
                              rami.mi_myname,
                              RAT_LIB_S_H_TO_H(db->db_maxadvint),
                              RAT_LIB_S_H_TO_M(db->db_maxadvint),
                              RAT_LIB_S_H_TO_S(db->db_maxadvint));

    if (db->db_minadvint != RAT_DB_MINADVINT_DEF)
        rat_rad_mf.mf_message("%s set minimum-interval %uh%um%us",
                              rami.mi_myname,
                              RAT_LIB_S_H_TO_H(db->db_minadvint),
                              RAT_LIB_S_H_TO_M(db->db_minadvint),
                              RAT_LIB_S_H_TO_S(db->db_minadvint));

    ret = rat_mod_rad_call_aid(&rat_rad_mf, &rami, rat_rad_ra_mid,
                               RAT_MOD_AID_DUMP);

    /* dump options */
    for (opt = db->db_opt; opt; opt = opt->opt_next) {
        rat_rad_fill_mi_opt(db, opt, &mi);
        rat_mod_rad_call_aid(&rat_rad_mf, &mi, opt->opt_mid, RAT_MOD_AID_DUMP);
    }

    switch (db->db_state) {
        case RAT_DB_STATE_FADEIN1:
        case RAT_DB_STATE_FADEIN2:
        case RAT_DB_STATE_FADEIN3:
        case RAT_DB_STATE_ENABLED:
            rat_rad_mf.mf_message("%s enable", rami.mi_myname);
            break;
        default:
            break;
    }

exit_ret:
    return ret;
}


/**
 * @brief Dumps all RA in database
 *
 * @return Returns RAT_ERROR on error, RAT_OK otherwise
 */
static int rat_rad_ra_dumpall (void)
{
    struct rat_db *db;
    RAT_DEBUG_TRACE();

    db = rat_db_grab_first();
    if (!db) {
        rat_rad_mf.mf_error("No Router Advertisement configured!");
        goto exit_err;
    }
    while (db) {
        rat_rad_ra_dump(db);
        db = rat_db_grab_next(db);
    }

    return RAT_OK;

exit_err:
    return RAT_ERROR;
}


/**
 * @brief Enable RA
 *
 * @param db                    database entry
 *
 * @return Returns RAT_ERROR on error, RAT_OK otherwise
 */
static int rat_rad_ra_enable (struct rat_db *db)
{
    RAT_DEBUG_TRACE();

    /* check state */
    switch (db->db_state) {
        case RAT_DB_STATE_DISABLED:
            break;
        case RAT_DB_STATE_FADEIN1:
        case RAT_DB_STATE_FADEIN2:
        case RAT_DB_STATE_FADEIN3:
        case RAT_DB_STATE_ENABLED:
            rat_rad_mf.mf_error("RA already enabled!");
            goto exit_err;
            break;
        case RAT_DB_STATE_FADEOUT1:
        case RAT_DB_STATE_FADEOUT2:
        case RAT_DB_STATE_FADEOUT3:
            rat_rad_mf.mf_error("RA currently de-advertising! Kill first.");
            goto exit_err;
            break;
        case RAT_DB_STATE_DESTROYED:
            rat_rad_mf.mf_error("RA currently being destroyed! Be patient.");
            goto exit_err;
            break;
        default:
            rat_rad_mf.mf_error("Could not enable RA!");
            goto exit_err;
            break;
    }

    /* interface up/down state */
    if (!db->db_ifup) {
        rat_rad_mf.mf_error("Interface down!");
        goto exit_err;
    }

    db->db_state = RAT_DB_STATE_FADEIN1;

    /* create worker thread for unsolicited RAs */
    if (pthread_create(&db->db_worker_thread, &db->db_worker_attr,
                       rat_rad_worker, (void *) &RAT_DB_IFINDEX(db)))
        goto exit_err;

    rat_db_updated(db);

    return RAT_OK;

exit_err:
    return RAT_ERROR;
}


/**
 * @brief Disable RA
 *
 * @param db                    database entry
 *
 * @return Returns RAT_ERROR on error, RAT_OK otherwise
 */
static int rat_rad_ra_disable (struct rat_db *db)
{
    RAT_DEBUG_TRACE();

    db->db_state = RAT_DB_STATE_FADEOUT1;
    rat_db_updated(db);
    pthread_cond_signal(&db->db_worker_cond);

    return RAT_OK;
}

/**
 * @brief Kill RA
 *
 * Force-disables RA. This is how to disable a RA even if it is still in the
 * de-advertising phase.
 *
 * @param db                    database entry
 *
 * @return Returns RAT_ERROR on error, RAT_OK otherwise
 */
static int rat_rad_ra_kill (struct rat_db *db)
{
    RAT_DEBUG_TRACE();

    db->db_state = RAT_DB_STATE_DISABLED;
    rat_db_updated(db);

    pthread_cond_signal(&db->db_worker_cond);

    return RAT_OK;
}


/**
 * @brief Get minimum value for maxadvint of interface
 *
 * @param db                    database entry
 *
 * @return Returns minimum value valid for db_maxadvint
 */
static uint16_t rat_rad_ra_maxadvint_min (struct rat_db *db)
{
    uint16_t x;
    RAT_DEBUG_TRACE();

    x = (uint16_t) (((double) db->db_minadvint) * 1.33);
    x = MAX(x, RAT_DB_MAXADVINT_MIN);

    return x;
}


/**
 * @brief Get maximum value for minadvint of interface
 *
 * @param db                    database entry
 *
 * @return Returns minimum value valid for db_minadvint
 */
static uint16_t rat_rad_ra_minadvint_max (struct rat_db *db)
{
    uint16_t x;
    RAT_DEBUG_TRACE();

    /*
     * MUST be (...) no greater than .75 * MaxRtrAdvInterval.
     * (RFC 4861 sec. 6.2.1.)
     */
    x = (uint16_t) (((double) db->db_maxadvint) * 0.75);
    x = MIN(x, RAT_DB_MAXADVINT_MAX);

    return x;
}


/**
 * @brief Set maximum advertising interval of RA
 *
 * @param db                    database entry
 * @param data                  data provided by the parameter's parser function
 * @param len                   maximum length of provided data
 *
 * @return Returns RAT_ERROR on error, RAT_OK otherwise
 */
static int rat_rad_ra_set_maxadvint (struct rat_db *db, uint8_t *data,
                                     uint16_t len)
{
    uint16_t advint;
    RAT_DEBUG_TRACE();

    if (len < sizeof(uint16_t))
        goto exit_err;

    advint = *((uint16_t *) data);

    /* upper boundary check */
    if (advint > RAT_DB_MAXADVINT_MAX) {
        rat_rad_mf.mf_error("Invalid Maximum Interval `%" PRIu16 "'!", advint);
        rat_rad_mf.mf_message("Must not be greater than %" PRIu16 ".",
                              RAT_DB_MAXADVINT_MAX);
        goto exit_err;
    }

    /* lower boundary check (must not come too close to minimum interval */
    if (advint < rat_rad_ra_maxadvint_min(db)) {
        rat_rad_mf.mf_message("Warning: Invalid maximum interval " \
                              "`%" PRIu16 "'!", advint);
        rat_rad_mf.mf_message("Must not be less than 1.3 times " \
                              "Minimum Interval (%" PRIu16 ").",
                              rat_rad_ra_maxadvint_min(db));
    }

    /*
     * if interval was lowered, we signal the worker to give it a chance to
     * catch up
     */
    if (advint < db->db_maxadvint)
        pthread_cond_signal(&db->db_worker_cond);

    db->db_maxadvint = advint;
    rat_db_updated(db);

    return RAT_OK;

exit_err:
    return RAT_ERROR;
}


/**
 * @brief Set minimum advertising interval of RA
 *
 * @param db                    database entry
 * @param data                  data provided by the parameter's parser function
 * @param len                   maximum length of provided data
 *
 * @return Returns RAT_ERROR on error, RAT_OK otherwise
 */
static int rat_rad_ra_set_minadvint (struct rat_db *db, uint8_t *data,
                                     uint16_t len)
{
    uint16_t advint;
    RAT_DEBUG_TRACE();

    if (len < sizeof(uint16_t))
        goto exit_err;

    advint = *((uint16_t *) data);

    /* lower boundary check */
    if (advint < RAT_DB_MINADVINT_MIN) {
        rat_rad_mf.mf_error("Invalid Minimum Interval `%" PRIu16 "'!", advint);
        rat_rad_mf.mf_message("Must not be less than %" PRIu16 ".",
                              RAT_DB_MINADVINT_MIN);
        goto exit_err;
    }
    /* upper boundary check (must not come too close to maximum interval */
    if (advint > rat_rad_ra_minadvint_max(db)) {
        rat_rad_mf.mf_message("Warning: Invalid minimum interval " \
                              "`%" PRIu16 "'!", advint);
        rat_rad_mf.mf_message("Must not be greater than 0.75 times " \
                              "Maximum Interval (%" PRIu16 ").",
                              rat_rad_ra_minadvint_max(db));
    }

    /*
     * if interval was lowered, we signal the worker to give it a chance to
     * catch up
     */
    if (advint < db->db_maxadvint)
        pthread_cond_signal(&db->db_worker_cond);

    db->db_minadvint = advint;
    rat_db_updated(db);

    return RAT_OK;

exit_err:
    return RAT_ERROR;
}


/* --- module management and execution -------------------------------------- */


/**
 * @brief Execute a module function as requested by control message
 *
 * @param crq                   control message (request)
 *
 * @return Returns RAT_ERROR on error, RAT_OK otherwise
 */
static int rat_rad_exec_module (struct rat_ctl_request *crq)
{
    struct rat_db *db;
    struct rat_mod_instance mi;
    struct rat_db_opt *opt;
    RAT_DEBUG_TRACE();

    db = rat_db_grab(crq->crq_ifindex);

    /*
     * we have not found the interface and we shall create it
     */
    if (!db && rat_mod_icpt_aid(crq->crq_mid, "ra",
                                crq->crq_aid, "create") == RAT_OK) {
        RAT_DEBUG_MESSAGE("Intercepting `ra@dev create'");
        if (rat_rad_ra_create(crq->crq_ifindex) == RAT_OK) {
            /*
             * intentionally skipping release
             * there is no db at this moment to release
             */
            db = NULL;
            goto exit_ok;
        }
    }
    /*
     * we could not find the interface. too bad :(
     */
    else if (!db) {
        rat_rad_mf.mf_error("Interface not found in database!");
    }

    /*
     * we have the requested interface in the database although it's creation
     * was requested.
     */
    else if (rat_mod_icpt_aid(crq->crq_mid, "ra",
                              crq->crq_aid, "create") == RAT_OK) {
        RAT_DEBUG_MESSAGE("Intercepting `ra@dev create'");
        rat_rad_mf.mf_error("Router Advertisement already exists!");
    }

    /*
     * ra@dev enable
     * -------------
     * We maintain state outside the module. RA state is also the interface's
     * state and this is managed by the framework not by the module.
     */
    else if (rat_mod_icpt_aid(crq->crq_mid, "ra",
                              crq->crq_aid, "enable") == RAT_OK) {
        RAT_DEBUG_MESSAGE("Intercepting `ra@dev enable'");
        if (rat_rad_ra_enable(db) == RAT_OK) {
            goto exit_ok_release;
        }
    }

    /*
     * ra@dev disable
     * --------------
     * We maintain state outside the module. RA state is also the interface's
     * state and this is managed by the framework not by the module.
     */
    else if (rat_mod_icpt_aid(crq->crq_mid, "ra",
                              crq->crq_aid, "disable") == RAT_OK) {
        RAT_DEBUG_MESSAGE("Intercepting `ra@dev disable'");
        if (rat_rad_ra_disable(db) == RAT_OK)
            goto exit_ok_release;
    }
    /*
     * ra@dev kill
     * -----------
     * We maintain state outside the module. RA state is also the interface's
     * state and this is managed by the framework not by the module.
     */
    else if (rat_mod_icpt_aid(crq->crq_mid, "ra",
                              crq->crq_aid, "kill") == RAT_OK) {
        RAT_DEBUG_MESSAGE("Intercepting `ra@dev kill'");
        if (rat_rad_ra_kill(db) == RAT_OK)
            goto exit_ok_release;
    }

    /*
     * ra@dev show
     * -----------
     * Since we maintain the interface-specific values of RA ourselfs, we also
     * have to give them back on action `show'.
     */
    else if (rat_mod_icpt_aid(crq->crq_mid, "ra",
                              crq->crq_aid, "show") == RAT_OK) {
        RAT_DEBUG_MESSAGE("Intercepting `ra@dev show'");
        if (rat_rad_ra_show(db) == RAT_OK)
            goto exit_ok_release;
    }

    /*
     * ra@dev dump
     * -----------
     * Since we maintain the interface-specific values of RA ourselfs, we also
     * have to give them back on action `dump'.
     */
    else if (rat_mod_icpt_aid(crq->crq_mid, "ra",
                              crq->crq_aid, "dump") == RAT_OK) {
        RAT_DEBUG_MESSAGE("Intercepting `ra@dev dump'");
        if (rat_rad_ra_dump(db) == RAT_OK)
            goto exit_ok_release;
    }

    /*
     * ra@dev destroy
     * --------------
     * Destroying a RA means removing the interface from the database.
     */
    else if (rat_mod_icpt_aid(crq->crq_mid, "ra",
                              crq->crq_aid, "destroy") == RAT_OK) {
        RAT_DEBUG_MESSAGE("Intercepting `ra@dev destroy'");
        if (rat_rad_ra_destroy(db) == RAT_OK) {
            /*
             * intentionally skipping release
             * there is no db anymore
             */
            db = NULL;
            goto exit_ok;
        }
    }

    /*
     * ra@dev set maximum-interval
     * ---------------------------
     * We maintain the interval ourselfs, because this is interface specific
     * data.
     */
    else if (rat_mod_icpt_pid(crq->crq_mid, "ra",
                              crq->crq_aid, "set",
                              crq->crq_pid, "maximum-interval") == RAT_OK) {
        RAT_DEBUG_MESSAGE("Intercepting `ra@dev set maximum-interval'");
        if (rat_rad_ra_set_maxadvint(db, crq->crq_data,
                                     RAT_CTL_REQ_DATA_LEN) == RAT_OK)
            goto exit_ok_release;
    }

    /*
     * ra@dev set minimum-interval
     * ---------------------------
     * We maintain the interval ourselfs, because this is interface specific
     * data.
     */
    else if (rat_mod_icpt_pid(crq->crq_mid, "ra",
                              crq->crq_aid, "set",
                              crq->crq_pid, "minimum-interval") == RAT_OK) {
        RAT_DEBUG_MESSAGE("Intercepting `ra@dev set minimum-interval'");
        if (rat_rad_ra_set_minadvint(db, crq->crq_data,
                                     RAT_CTL_REQ_DATA_LEN) == RAT_OK)
            goto exit_ok_release;
    }

    /*
     * ra@dev set
     * ----------
     * All other parameters on RAs.
     */
    else if (rat_mod_icpt_aid(crq->crq_mid, "ra",
                              crq->crq_aid, "set") == RAT_OK) {
        RAT_DEBUG_MESSAGE("Intercepting `ra@dev set'");
        rat_rad_fill_mi_ra(db, &mi);
        if (rat_mod_rad_call_pid(&rat_rad_mf, &mi,
                                 crq->crq_mid, crq->crq_aid,
                                 crq->crq_pid, crq->crq_data,
                                 sizeof(crq->crq_data)) == RAT_OK) {
            rat_db_updated(db);
            goto exit_ok_release;
        }
    }

    /* execute module */
    else {
        switch (crq->crq_aid) {
            case RAT_MOD_AID_CREATE:
                opt = rat_db_get_opt(db, crq->crq_mid, crq->crq_oid);
                if (opt) {
                    rat_rad_mf.mf_error("Option already exists!");
                    goto exit_err_release;
                }
                opt = rat_db_add_opt(db, crq->crq_mid, crq->crq_oid);
                if (!opt) {
                    rat_rad_mf.mf_error("Could not create option!");
                    goto exit_err_release;
                }
                rat_rad_fill_mi_opt(db, opt, &mi);
                if (rat_mod_rad_call_aid(&rat_rad_mf, &mi, crq->crq_mid,
                                         crq->crq_aid) == RAT_OK) {
                    rat_db_updated(db);
                    goto exit_ok_release;
                }
                rat_db_del_opt(db, crq->crq_mid, crq->crq_oid);
                break;
            case RAT_MOD_AID_DESTROY:
                opt = rat_db_get_opt(db, crq->crq_mid, crq->crq_oid);
                if (!opt) {
                    rat_rad_mf.mf_error("Option does not exist!");
                    goto exit_err_release;
                }
                rat_rad_fill_mi_opt(db, opt, &mi);
                if (rat_mod_rad_call_aid(&rat_rad_mf, &mi, crq->crq_mid,
                                         crq->crq_aid) == RAT_OK) {
                    rat_db_del_opt(db, crq->crq_mid, crq->crq_oid);
                    rat_db_updated(db);
                    goto exit_ok_release;
                }
                break;
            case RAT_MOD_AID_ENABLE:
            case RAT_MOD_AID_DISABLE:
            case RAT_MOD_AID_KILL:
            case RAT_MOD_AID_SHOW:
            case RAT_MOD_AID_DUMP:
                opt = rat_db_get_opt(db, crq->crq_mid, crq->crq_oid);
                if (!opt) {
                    rat_rad_mf.mf_error("Unknown option!");
                    goto exit_err_release;
                }
                rat_rad_fill_mi_opt(db, opt, &mi);
                RAT_MOD_MI_IN(&mi, 0);
                if (rat_mod_rad_call_aid(&rat_rad_mf, &mi, crq->crq_mid,
                                         crq->crq_aid) == RAT_OK) {
                    rat_db_updated(db);
                    goto exit_ok_release;
                }
                break;
            case RAT_MOD_AID_SET:
            case RAT_MOD_AID_ADD:
            case RAT_MOD_AID_DEL:
                opt = rat_db_get_opt(db, crq->crq_mid, crq->crq_oid);
                if (!opt) {
                    rat_rad_mf.mf_error("Unknown option!");
                    goto exit_err_release;
                }
                rat_rad_fill_mi_opt(db, opt, &mi);
                if (rat_mod_rad_call_pid(&rat_rad_mf, &mi,
                                         crq->crq_mid, crq->crq_aid,
                                         crq->crq_pid, crq->crq_data,
                                         sizeof(crq->crq_data)) == RAT_OK) {
                    rat_db_updated(db);
                    goto exit_ok_release;
                }
                break;
            default:
                rat_rad_mf.mf_error("Unknown action!");
                break;
        }
    }

exit_err_release:
    if (db)
        db = rat_db_release(db);

    return RAT_ERROR;

exit_ok_release:
    if (db)
        db = rat_db_release(db);
exit_ok:
    return RAT_OK;
}


/* --- cleanup functions ---------------------------------------------------- */


/**
 * @brief Disable all RAs
 *
 * Used when shutting down the daemon.
 */
static void rat_rad_ra_disable_all (void)
{
    struct rat_db *db;
    RAT_DEBUG_TRACE();

    db = rat_db_grab_first();
    while (db) {
        switch (db->db_state) {
            case RAT_DB_STATE_FADEIN1:
            case RAT_DB_STATE_FADEIN2:
            case RAT_DB_STATE_FADEIN3:
            case RAT_DB_STATE_ENABLED:
                db->db_state = RAT_DB_STATE_FADEOUT1;
                rat_db_updated(db);
                pthread_cond_signal(&db->db_worker_cond);
                break;
            default:
                break;
        }
        db = rat_db_grab_next(db);
    }

    return;
}


/**
 * @brief Join all worker threads
 *
 * Used when shutting down the daemon.
 */
static void rat_rad_ra_join_workers (void)
{
    struct rat_db *db;
    pthread_t* tptr;
    RAT_DEBUG_TRACE();

    db = rat_db_grab_first();
    while (db) {
        tptr = &db->db_worker_thread;
        db = rat_db_grab_next(db);
        pthread_join(*tptr, NULL);
    }

    return;
}


/* --- main ----------------------------------------------------------------- */


/**
 * @brief ratools/rad main function
 *
 * @param argc                  number of arguments given
 * @param argv                  array of argument values
 *
 * @return Returns RAT_ERROR on error, RAT_OK otherwise
 */
int main (int argc, char *argv[])
{
    /* threads */
    pthread_attr_t attr;
    pthread_t rs_thread;
    pthread_t nl_thread;
    /* signals */
    sigset_t emptyset, blockset;
    /* control socket */
    char *sockaddr;
    struct sockaddr_un srvsa;
    struct sockaddr_un clisa;
    socklen_t slen;
    fd_set rfds;
    /* control request handling */
    struct rat_ctl_request crq;
    int ret;
    RAT_DEBUG_TRACE();

    /* version information */
    fprintf(stdout, "ratools/rad " RAT_VERSION " (" RAT_DATE ")\n");
    fprintf(stdout, "Written by Dan Luedtke <mail@danrl.de>\n");


    /* --- set defaults and get options ------------------------------------- */


    sockaddr = strdup(RAT_SOCKADDR);
    while (1) {
        int c, cidx;
        static struct option copts[] = {
            {"socket",       required_argument, 0, 's'},
            {"loglevel",     required_argument, 0, 'l'},
            {0, 0, 0, 0}
        };
        c = getopt_long(argc, argv, "s:l:", copts, &cidx);

        if (c == -1)
            break;
        switch (c) {
            case 's':
                sockaddr = optarg;
                break;
            case 'l':
                if (strcmp(optarg, "info") == 0) {
                    rat_log_set_level(RAT_LOG_INFO);
                } else if (strcmp(optarg, "warning") == 0) {
                    rat_log_set_level(RAT_LOG_WARNING);
                } else if (strcmp(optarg, "error") == 0) {
                    rat_log_set_level(RAT_LOG_ERROR);
                } else {
                    rat_log_err("Unknown log level `%s'!", optarg);
                    goto exit_err;
                }
                break;
            case '?':
                goto exit_err;
                break;
            default:
                break;
        }
    }
    argc = argc - optind + 1;
    argv += optind - 1;


    /* --- various initializations ------------------------------------------ */


    /* block SIGINT on normal operation */
    sigemptyset(&blockset);
    sigaddset(&blockset, SIGINT);
    sigprocmask(SIG_BLOCK, &blockset, NULL);

    /* register signal for times we are waiting for pselect() */
    signal(SIGINT, rat_lib_signal_dummy_handler);

    /* empty set for times we are waiting for pselect() */
    sigemptyset(&emptyset);

    /* initialize thread attribute */
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);

    /* initialze random generator */
    rat_lib_random_init();

    /* initialize unix domain socket address */
    memset(&srvsa, 0x0, sizeof(srvsa));
    srvsa.sun_family = AF_UNIX;
    strncpy(srvsa.sun_path, sockaddr, sizeof(srvsa.sun_path) - 1);

    /* register modules */
    rat_ra_init();
    rat_opt_mtu_init();
    rat_opt_sll_init();
    rat_opt_pi_init();
    rat_opt_rdnss_init();
    rat_opt_exp_init();

    /* find RA core module id in registry */
    if (rat_mod_parse_module(RAT_RAMODNAME, &rat_rad_ra_mid) != RAT_OK) {
        rat_log_err("Could not find core module `" RAT_RAMODNAME "'!");
        goto exit_err;
    }


    /* --- netlink thread for receiving interface configuration changes ----- */


    /* start netlink listener thread */
    if (pthread_create(&nl_thread, &attr, rat_nl_listener, NULL)) {
        rat_log_err("Could not start netlink listener thread: %s!",
                    strerror(errno));
        goto exit_err;
    }


    /* --- socket for receiving RS and sending RA --------------------------- */


    /* open raw socket for receiving RS and sending RA */
    rat_rad_rsra_sd = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
    if (rat_rad_rsra_sd < 0) {
        rat_log_err("Could not open raw socket: %s.", strerror(errno));
        goto exit_err;
    }

    /* start Router Solicitation listener thread */
    if (pthread_create(&rs_thread, &attr, rat_rad_listener, NULL)) {
        rat_log_err("Could not start RS listener thread: %s!", strerror(errno));
        goto exit_err_rsra_sd;
    }


    /* --- socket for ratools/rad configuration ----------------------------- */


    /* open control socket */
    if (mkdir(dirname(sockaddr), S_IRWXU | S_IRWXG | S_IRWXO) &&
        errno != EEXIST) {
        rat_log_err("Could not create socket path `%s': %s!",
                    sockaddr, strerror(errno));
        goto exit_err_rsra_sd;
    }
    if ((rat_rad_ctlsrv_sd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
        rat_log_err("Could not open socket `%s': %s!",
                    srvsa.sun_path, strerror(errno));
        goto exit_err_rsra_sd;
    }

    /* bind socket */
    slen = sizeof(srvsa.sun_family) + strlen(srvsa.sun_path);
    if (bind(rat_rad_ctlsrv_sd, (struct sockaddr *) &srvsa, slen) < 0) {
        rat_log_err("Could not bind to socket `%s': %s!",
                    srvsa.sun_path, strerror(errno));
        goto exit_err_ctlsrv_sd;
    }


    /* listen on socket */
    if (listen(rat_rad_ctlsrv_sd, 5) < 0) {
        rat_log_err("Could not listen on socket `%s': %s!",
                    srvsa.sun_path, strerror(errno));
        goto exit_err_ctlsrv_sd;
    }

    /* pselect() file descriptor set */
    FD_ZERO(&rfds);
    FD_SET(rat_rad_ctlsrv_sd, &rfds);

    for (;;) {
        /* wait for data or thread signal */
        if (pselect(rat_rad_ctlsrv_sd + 1, &rfds, NULL, NULL, NULL,
                    &emptyset) == -1 && errno == EINTR)
            break;

        slen = sizeof(clisa);
        rat_rad_ctlcli_sd = accept(rat_rad_ctlsrv_sd,
                                   (struct sockaddr *) &clisa, &slen);
        if (rat_rad_ctlcli_sd < 0)
            continue;

        memset(&crq, 0x0, sizeof(crq));
        slen = recv(rat_rad_ctlcli_sd, &crq, sizeof(crq), 0);
        if (slen != sizeof(crq)) {
            rat_log_err("Received malformed control request!");
            close(rat_rad_ctlcli_sd);
            continue;
        }

        RAT_DEBUG_MESSAGE("Received control message: " \
                          "type=`%d', " \
                          "mid=`%" PRIu16 "', " \
                          "oid=`%" PRIu16 "', " \
                          "aid=`%" PRIu16 "', " \
                          "pid=`%" PRIu16 "', " \
                          "vid=`%" PRIu16 "', " \
                          "ifindex=`%" PRIu32 "', " \
                          "data=`%p'",
                          crq.crq_type, crq.crq_mid, crq.crq_oid,
                          crq.crq_aid, crq.crq_pid, crq.crq_vid,
                          crq.crq_ifindex, crq.crq_data);

        switch (crq.crq_type) {
            case RAT_CTL_REQUEST_TYPE_SHOWALL:
                ret = rat_rad_ra_showall();
                break;
            case RAT_CTL_REQUEST_TYPE_DUMPALL:
                ret = rat_rad_ra_dumpall();
                break;
            case RAT_CTL_REQUEST_TYPE_SETLOGERROR:
                ret = rat_log_set_level(RAT_LOG_ERROR);
                break;
            case RAT_CTL_REQUEST_TYPE_SETLOGWARNING:
                ret = rat_log_set_level(RAT_LOG_WARNING);
                break;
            case RAT_CTL_REQUEST_TYPE_SETLOGINFO:
                ret = rat_log_set_level(RAT_LOG_INFO);
                break;
            case RAT_CTL_REQUEST_TYPE_MODULE:
                ret = rat_rad_exec_module(&crq);
                break;
            default:
                rat_rad_mf.mf_error("Unknown control message type!");
                ret = RAT_ERROR;
                break;
        }

        if (ret == RAT_OK)
            rat_rad_ctl_send_exit_ok();
        else
            rat_rad_ctl_send_exit_error();

        close(rat_rad_ctlcli_sd);
    }


    /* --- clean up --------------------------------------------------------- */


    rat_log_wrn("Shutting down in a few seconds! Be patient...");

    /* close control socket */
    close(rat_rad_ctlsrv_sd);
    if (unlink(srvsa.sun_path))
        rat_log_err("Could not unlink `%s': %s!", srvsa.sun_path,
                    strerror(errno));

    /* tell helper threads to shut down */
    pthread_kill(nl_thread, SIGINT);
    pthread_kill(rs_thread, SIGINT);

    /* disable all RAs and shutdown worker threads */
    pthread_join(nl_thread, NULL);
    pthread_join(rs_thread, NULL);
    rat_rad_ra_disable_all();
    rat_rad_ra_join_workers();

    /* close RS listening and RA sending socket */
    close(rat_rad_rsra_sd);

    fprintf(stdout, "Life tasted so good!\n");
    return EXIT_SUCCESS;

exit_err_ctlsrv_sd:
    close(rat_rad_ctlsrv_sd);
    if (unlink(srvsa.sun_path))
        rat_log_err("Could not unlink `%s': %s!", srvsa.sun_path,
                    strerror(errno));
exit_err_rsra_sd:
    close(rat_rad_rsra_sd);
exit_err:
    return EXIT_FAILURE;
}
