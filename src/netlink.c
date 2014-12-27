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


#include "netlink.h"

#include "library.h"
#include "log.h"

#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <net/if.h>
#include <inttypes.h>           /* PRIu8 and friends */
#include <errno.h>
#include <signal.h>


/* --- functions ------------------------------------------------------------ */


/**
 * @brief Parse rtnetlink attributes of RTM_*LINK message
 *
 * Updates database if a value has changed.
 *
 * @param ifindex               interface index
 * @param nh                    netlink message header
 */
static void __rat_nl_parse_link_rtattr (uint32_t ifindex, struct nlmsghdr *nh)
{
    struct ifinfomsg *ifi = (struct ifinfomsg *) NLMSG_DATA(nh);
    unsigned int rtlen, mtu;
    enum rat_db_ifstate ifstate;
    char ifname[RAT_IFNAMELEN + 1];
    struct rtattr *rtattr;
    struct rat_hwaddr hwanl, hwadb;
    char hwaddrstr[RAT_HWADDR_STRSIZ];
    RAT_DEBUG_TRACE();

    /* interface up/down state */
    if ((ifi->ifi_flags & IFF_UP) && (ifi->ifi_flags & IFF_RUNNING))
        ifstate = RAT_DB_IFSTATE_UP;
    else
        ifstate = RAT_DB_IFSTATE_DOWN;
    if (rat_db_get_ifstate(ifindex) != ifstate) {
        rat_db_set_ifstate(ifindex, ifstate);
        rat_log_nfo("Netlink: Interface %" PRIu32 ": New state `%s'.", ifindex,
                    ifstate == RAT_DB_IFSTATE_UP ? "up" : "down");
        /* signal worker if interface went down */
        if (ifstate == RAT_DB_IFSTATE_DOWN)
            rat_db_signal_worker(ifindex);
    }

    rtlen = nh->nlmsg_len - NLMSG_LENGTH(sizeof(*ifi));
    for (rtattr = IFLA_RTA(ifi); RTA_OK(rtattr, rtlen);
         rtattr = RTA_NEXT(rtattr, rtlen)) {
        switch (rtattr->rta_type) {

            case IFLA_IFNAME:
                /* interface name */
                rat_db_get_ifname(ifindex, ifname, sizeof(ifname));
                if (strncmp(ifname, RTA_DATA(rtattr), sizeof(ifname)) == 0)
                    break;
                rat_db_set_ifname(ifindex, RTA_DATA(rtattr));
                rat_log_nfo("Netlink: Interface %" PRIu32 ": New name `%s'.",
                            ifindex, RTA_DATA(rtattr));
                break;

            case IFLA_MTU:
                /* MTU */
                mtu =  (uint32_t) (*((unsigned int *) RTA_DATA(rtattr)));
                if (rat_db_get_mtu(ifindex) == mtu)
                    break;
                rat_db_set_mtu(ifindex, mtu);
                rat_db_set_state_refadein(ifindex);
                rat_db_signal_worker(ifindex);
                rat_log_nfo("Netlink: Interface %" PRIu32 ": New MTU `%u'.",
                            ifindex, mtu);
                break;

            case IFLA_ADDRESS:
                /* hardware address */
                /* hardware address proviled by netlink */
                memset(&hwanl, 0x0, sizeof(hwanl));
                hwanl.hwa_len = (uint8_t) MIN(RTA_PAYLOAD(rtattr),
                                              sizeof(hwanl.hwa_addr));
                memcpy(hwanl.hwa_addr, RTA_DATA(rtattr), hwanl.hwa_len);
                /* hardware address from database */
                rat_db_get_hwaddr(ifindex, &hwadb);
                /* compare */
                if (memcmp(&hwadb, &hwanl, sizeof(struct rat_hwaddr)) == 0)
                    break;
                rat_db_set_hwaddr(ifindex, &hwanl);
                rat_db_set_state_refadein(ifindex);
                rat_db_signal_worker(ifindex);
                rat_lib_hwaddr_to_str(hwaddrstr, sizeof(hwaddrstr), &hwanl);
                rat_log_nfo("Netlink: Interface %" PRIu32 ": " \
                            "New hardware address `%s'.",
                            ifindex, hwaddrstr);
                break;

            default:
                RAT_DEBUG_MESSAGE("Unhandled IFLA %d", rtattr->rta_type);
                break;
            }
    }

    return;
}


/**
 * @brief Parse rtnetlink RTM_*LINK message
 *
 * Updates database if a value has changed.
 *
 * @param nh                    netlink message header
 */
static void __rat_nl_parse_link (struct nlmsghdr *nh)
{
    struct ifinfomsg *ifi = (struct ifinfomsg *) NLMSG_DATA(nh);
    uint32_t ifindex;
    RAT_DEBUG_TRACE();

    if (ifi->ifi_index < 1) {
        rat_log_err("Netlink: Ignoring out of bound interface index!");
        goto exit;
    }
    ifindex = ifi->ifi_index;

    if (!rat_db_exists(ifindex)) {
        rat_log_nfo("Netlink: Interface %" PRIu32 ": Ignored.", ifindex);
        goto exit;
    }


    __rat_nl_parse_link_rtattr(ifindex, nh);

exit:
    return;
}


/**
 * @brief Parse rtnetlink attributes of RTM_*ADDR message
 *
 * Updates database entry if a value has changed.
 *
 * @param db                    database entry
 * @param nh                    netlink message header
 */
static void __rat_nl_parse_addr_rtattr (uint32_t ifindex, struct nlmsghdr *nh)
{
    struct ifaddrmsg *ifa = (struct ifaddrmsg *) NLMSG_DATA(nh);
    unsigned int rtlen;
    struct rtattr *rtattr;
    struct in6_addr lladdr;
    char addrstr[RAT_6ADDR_STRSIZ];
    RAT_DEBUG_TRACE();

    rtlen = IFA_PAYLOAD(nh);
    for (rtattr = IFA_RTA(ifa); RTA_OK(rtattr, rtlen);
         rtattr = RTA_NEXT(rtattr, rtlen)) {
        switch (rtattr->rta_type) {
            /*
             * if_addr.h:
             * IFA_ADDRESS is prefix address, rather than local interface
             * address. It makes no difference for normally configured
             * broadcast interfaces, but for point-to-point IFA_ADDRESS is
             * DESTINATION address, local address is supplied in IFA_LOCAL
             * attribute.
             */
            case IFA_ADDRESS:
            case IFA_LOCAL:
                if (!rat_lib_6addr_is_linklocal(RTA_DATA(rtattr)))
                    break;
                rat_db_get_lladdr(ifindex, &lladdr);
                if (memcmp(&lladdr, RTA_DATA(rtattr), sizeof(lladdr)) == 0)
                    break;
                rat_db_set_lladdr(ifindex, RTA_DATA(rtattr));
                rat_db_set_state_refadein(ifindex);
                rat_db_signal_worker(ifindex);
                rat_lib_6addr_to_str(addrstr, sizeof(addrstr),
                                     RTA_DATA(rtattr));
                rat_log_nfo("Netlink: Interface %" PRIu32 ": " \
                            "New link-local address `%s'.",
                            ifindex, addrstr);
                break;

            default:
                RAT_DEBUG_MESSAGE("Unhandled IFA %d", rtattr->rta_type);
                break;
            }
    }

    return;
}


/**
 * @brief Parse rtnetlink RTM_*ADDR message
 *
 * Updates database entry if a value has changed.
 *
 * @param nh                    netlink message header
 */
static void __rat_nl_parse_addr (struct nlmsghdr *nh)
{
    struct ifaddrmsg *ifa = (struct ifaddrmsg *) NLMSG_DATA(nh);
    uint32_t ifindex;
    RAT_DEBUG_TRACE();

    if (ifa->ifa_index < 1) {
        rat_log_err("Netlink: Ignoring out of bound interface index!");
        goto exit;
    }
    ifindex = ifa->ifa_index;

    if (!rat_db_exists(ifindex)) {
        rat_log_nfo("Netlink: Interface %" PRIu32 ": Ignored.", ifindex);
        goto exit;
    }

    if (nh->nlmsg_type == RTM_DELADDR)
        rat_nl_init_db(ifindex);
    else
        __rat_nl_parse_addr_rtattr(ifindex, nh);

exit:
    return;
}


/**
 * @brief Initialiy fetch interface data
 *
 * The purpose of this function is to fetch interface state, MTU value, hardware
 * address and link-local address of an interface. A netlink listener thread
 * will update the initial information over time.
 *
 * @param ifindex               interface index
 *
 * @return Returns RAT_ERROR on error, RAT_OK otherwise
 */
int rat_nl_init_db (uint32_t ifindex)
{
    RAT_DEBUG_TRACE();

    int sd;
    unsigned int len;
    uint32_t seq = 0;
    struct sockaddr_nl la, ka;
    struct rat_nl_rtreq req;
    struct msghdr msg;
    struct iovec iov;
    struct ifinfomsg *ifi;
    struct ifaddrmsg *ifa;
    struct nlmsghdr *nh;
    char replybuf[RAT_NL_REPLYBUFSIZE];
    RAT_DEBUG_TRACE();


    /* local address */
    memset(&la, 0x0, sizeof(la));
    la.nl_family = AF_NETLINK;
    la.nl_pid = getpid();
    la.nl_groups = 0;

    /* kernel address */
    memset(&ka, 0x0, sizeof(ka));
    ka.nl_family = AF_NETLINK;
    ka.nl_pid = 0;

    /* open netlink socket */
    sd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (sd < 0) {
        rat_log_err("Netlink socket: %s", strerror(errno));
        goto exit_err;
    }

    /* bind netlink socket */
    if (bind(sd, (struct sockaddr *) &la, sizeof(la))) {
        rat_log_err("Netlink bind: %s", strerror(errno));
        goto exit_err_sd;
    }

    /* ---------------------------------------------------------------------- */

    /* LINK LAYER: craft request */
    memset(&req, 0x0, sizeof(req));
    req.req_nlmsg.nlmsg_len = NLMSG_LENGTH(sizeof(req.req_un));
    req.req_nlmsg.nlmsg_type = RTM_GETLINK;
    req.req_nlmsg.nlmsg_flags = NLM_F_REQUEST;
    req.req_nlmsg.nlmsg_seq = ++seq;
    req.req_nlmsg.nlmsg_pid = la.nl_pid;
    req.req_ifi.ifi_family = AF_INET6;
    req.req_ifi.ifi_index = (int) ifindex;

    /* LINK LAYER: iovec */
    memset(&iov, 0x0, sizeof(iov));
    iov.iov_base = &req;
    iov.iov_len = req.req_nlmsg.nlmsg_len;

    /* LINK LAYER: msghdr */
    memset(&msg, 0x0, sizeof(msg));
    msg.msg_name = &ka; /* socket name */
    msg.msg_namelen = sizeof(ka);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1; /* number of iovec blocks */

    /* LINK LAYER: send netlink message */
    sendmsg(sd, (struct msghdr *) &msg, 0);

    /* LINK LAYER: re-using old iov and msg for receiving */
    memset(&iov, 0x0, sizeof(iov));
    memset(&msg, 0x0, sizeof(msg));
    iov.iov_base = replybuf;
    iov.iov_len = sizeof(replybuf);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_name = &ka;
    msg.msg_namelen = sizeof(ka);

    /* receive reply messages */
    do {
        len = recvmsg(sd, &msg, 0);
        for (nh = (struct nlmsghdr *) replybuf; NLMSG_OK(nh, len);
             nh = NLMSG_NEXT(nh, len)) {

            /* time to bail out */
            if (nh->nlmsg_type == NLMSG_DONE ||
                nh->nlmsg_type == NLMSG_NOOP ||
                nh->nlmsg_type == NLMSG_ERROR ||
                nh->nlmsg_type != RTM_NEWLINK)
                continue;

            /* skip interfaces not matching the requested ifindex */
            ifi = (struct ifinfomsg *) NLMSG_DATA(nh);
            if (ifi->ifi_index < 1 ||
                ((uint32_t) ifi->ifi_index) != ifindex)
                continue;

            __rat_nl_parse_link_rtattr(ifindex, nh);

        }
    } while (len);

    /* ---------------------------------------------------------------------- */

    /*
     * We close and re-open the socket here because the second message's
     * replies will otherwise always match NLMSG_DONE. The reason is unclear
     * and the workaround not cool.
     *
     * TODO: Dig deeper into netlink and find
     * out why this happens and how we can manage to process multiple
     * requests.
     */
    close(sd);

    /* re-open netlink socket */
    sd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (sd < 0) {
        rat_log_err("Netlink socket: %s", strerror(errno));
        goto exit_err;
    }

    /* re-bind netlink socket */
    if (bind(sd, (struct sockaddr *) &la, sizeof(la))) {
        rat_log_err("Netlink bind: %s", strerror(errno));
        goto exit_err_sd;
    }

    /* ---------------------------------------------------------------------- */

    /* NETWORK LAYER: craft request */
    memset(&req, 0x0, sizeof(req));
    req.req_nlmsg.nlmsg_len = NLMSG_LENGTH(sizeof(req.req_un));
    req.req_nlmsg.nlmsg_type = RTM_GETADDR;
    req.req_nlmsg.nlmsg_seq = ++seq;
    req.req_nlmsg.nlmsg_pid = la.nl_pid;
    req.req_nlmsg.nlmsg_flags = NLM_F_REQUEST;
    req.req_ifa.ifa_family = AF_INET6;
    req.req_ifa.ifa_index = ifindex;

    /* NETWORK LAYER: iovec */
    memset(&iov, 0x0, sizeof(iov));
    iov.iov_base = &req;
    iov.iov_len = req.req_nlmsg.nlmsg_len;

    /* NETWORK LAYER: msghdr */
    memset(&msg, 0x0, sizeof(msg));
    msg.msg_name = &ka; /* socket name */
    msg.msg_namelen = sizeof(ka);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1; /* number of iovec blocks */

    /* NETWORK LAYER: send netlink message */
    sendmsg(sd, (struct msghdr *) &msg, 0);

    /* NETWORK LAYER: re-using old iov and msg for receiving */
    memset(&iov, 0x0, sizeof(iov));
    memset(&msg, 0x0, sizeof(msg));
    iov.iov_base = replybuf;
    iov.iov_len = RAT_NL_REPLYBUFSIZE;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_name = &ka;
    msg.msg_namelen = sizeof(ka);

    /* receive reply messages */
    do {
        len = recvmsg(sd, &msg, 0);
        for (nh = (struct nlmsghdr *) replybuf; NLMSG_OK(nh, len);
             nh = NLMSG_NEXT(nh, len)) {

            /* time to bail out */
            if (nh->nlmsg_type == NLMSG_DONE ||
                nh->nlmsg_type == NLMSG_NOOP ||
                nh->nlmsg_type == NLMSG_ERROR ||
                nh->nlmsg_type != RTM_NEWADDR)
                continue;

            /* skip interfaces not matching the requested ifindex */
            ifa = (struct ifaddrmsg *) NLMSG_DATA(nh);
            if (ifa->ifa_index < 1 ||
                ((uint32_t) ifa->ifa_index) != ifindex)
                continue;

            __rat_nl_parse_addr_rtattr(ifindex, nh);

        }
    } while (len);

    close(sd);

    return RAT_OK;

exit_err_sd:
    close(sd);
exit_err:
    return RAT_ERROR;
}


/**
 * @brief Netlink listener thread
 *
 * Thread listening for interface configuration changes from Kerner via netlink
 * socket.
 *
 * Thread argument has to be set to NULL!
 *
 * @param ptr                   thread argument
 */
void *rat_nl_listener (void *ptr)
{
    int sd;
    unsigned int len;
    struct sockaddr_nl la, ka;
    struct msghdr msg;
    struct iovec iov;
    struct nlmsghdr *nh;
    sigset_t emptyset, blockset;
    fd_set rfds;
    char replybuf[RAT_NL_REPLYBUFSIZE];
    RAT_DEBUG_TRACE();

    rat_log_nfo("Netlink: Thread started.");

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

    /* local address */
    memset(&la, 0x0, sizeof(la));
    la.nl_family = AF_NETLINK;
    la.nl_pid = pthread_self();
    la.nl_groups = RTMGRP_LINK | RTMGRP_IPV6_IFADDR | RTMGRP_IPV6_IFINFO;

    /* kernel address */
    memset(&ka, 0x0, sizeof(ka));
    ka.nl_family = AF_NETLINK;
    ka.nl_pid = 0;

    /* open netlink socket */
    sd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (sd < 0) {
        rat_log_err("Netlink: socket: %s", strerror(errno));
        goto exit;
    }

    /* bind netlink socket */
    if (bind(sd, (struct sockaddr *) &la, sizeof(la))) {
        rat_log_err("Netlink: bind: %s", strerror(errno));
        goto exit_sd;
    }

    /* ---------------------------------------------------------------------- */

    /* scatter/gather array for reply buffer */
    memset(&iov, 0x0, sizeof(iov));
    iov.iov_base = replybuf;
    iov.iov_len = sizeof(replybuf);

    /* craft message header */
    memset(&msg, 0x0, sizeof(msg));
    msg.msg_name = &ka; /* socket name */
    msg.msg_namelen = sizeof(ka);
    msg.msg_iov = &iov;
    msg.msg_iovlen = sizeof(iov) / sizeof(struct iovec[1]);

    /* pselect() file descriptor set */
    FD_ZERO(&rfds);
    FD_SET(sd, &rfds);

    /* receive answer messages */
    for(;;) {
        /* wait for data or thread signal */
        if (pselect(sd + 1, &rfds, NULL, NULL, NULL, &emptyset) == -1 &&
            errno == EINTR)
            goto exit_sd;

        /* receive message */
        len = recvmsg(sd, &msg, 0);
        for (nh = (struct nlmsghdr *) replybuf; NLMSG_OK(nh, len);
             nh = NLMSG_NEXT(nh, len)) {

            /* time to bail out */
            if (nh->nlmsg_type == NLMSG_DONE ||
                nh->nlmsg_type == NLMSG_NOOP ||
                nh->nlmsg_type == NLMSG_ERROR)
                continue;

            switch (nh->nlmsg_type) {
                case RTM_NEWLINK:
                case RTM_DELLINK:
                    __rat_nl_parse_link(nh);
                    break;
                case RTM_NEWADDR:
                case RTM_DELADDR:
                    __rat_nl_parse_addr(nh);
                    break;
                default:
                    RAT_DEBUG_MESSAGE("Unhandled RTM %d", nh->nlmsg_type);
                    break;
            }
        }
    }

exit_sd:
    close(sd);
exit:
    FD_ZERO(&rfds);
    rat_log_nfo("Netlink: Thread stopped.");
    pthread_exit(NULL);
}


