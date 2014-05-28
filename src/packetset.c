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


#include "packetset.h"

#include "log.h"

#include <stdlib.h>             /* calloc() */
#include <pthread.h>
#include <sys/socket.h>
#include <string.h>             /* memcpy() */
#include <inttypes.h>           /* PRIu32 and friends */


/* --- craft packet set ----------------------------------------------------- */


/**
 * @brief Create a new packet set
 *
 * @return Returns a pointer to new packet set, NULL on error
 */
struct rat_ps *rat_ps_create (void)
{
    RAT_DEBUG_TRACE();

    return (struct rat_ps *) calloc(1, sizeof(struct rat_ps));
}


/**
 * @brief Destroy and free an entire packet set
 *
 * @param ps                    packet set
 *
 * @return Returns NULL
 */
struct rat_ps *rat_ps_destroy (struct rat_ps *ps)
{
    struct rat_ps_pkt *tmp;
    struct rat_ps_pkt *pkt;
    RAT_DEBUG_TRACE();

    if (!ps)
        goto exit;

    if (ps->ps_hdrdata)
        free(ps->ps_hdrdata);

    if (ps->ps_pkt) {
        pkt = ps->ps_pkt;
        for (tmp = pkt->pkt_next; tmp; tmp = tmp->pkt_next) {
            free(pkt);
            pkt = tmp;
        }
        free(pkt);
    }
    free(ps);

exit:
    return NULL;
}


/**
 * @brief Set packet set socket
 *
 * @param ps                    packet set
 * @param sd                    socket descriptor
 */
void rat_ps_set_sd (struct rat_ps *ps, int sd)
{
    RAT_DEBUG_TRACE();

    if (ps)
        ps->ps_sd = sd;

    return;
}


/**
 * @brief Set packet set interface index
 *
 * @param ps                    packet set
 * @param ifindex               interface index
 */
void rat_ps_set_ifindex (struct rat_ps *ps, uint32_t ifindex)
{
    RAT_DEBUG_TRACE();

    if (ps)
        ps->ps_ifindex = ifindex;

    return;
}


/**
 * @brief Set packet set source address
 *
 * @param ps                    packet set
 * @param saddr                 source address
 */
void rat_ps_set_saddr (struct rat_ps *ps, struct in6_addr *saddr)
{
    RAT_DEBUG_TRACE();

    if (ps)
        memcpy(&ps->ps_saddr, saddr, sizeof(ps->ps_saddr));

    return;
}


/**
 * @brief Set packet set destination address
 *
 * @param ps                    packet set
 * @param daddr                 destination address
 */
void rat_ps_set_daddr (struct rat_ps *ps, struct in6_addr *daddr)
{
    RAT_DEBUG_TRACE();

    if (ps)
        memcpy(&ps->ps_daddr, daddr, sizeof(ps->ps_daddr));

    return;
}


/**
 * @brief Set packet set delay
 *
 * @param ps                    packet set
 * @param delay                 delay in useconds
 */
void rat_ps_set_delay (struct rat_ps *ps, useconds_t delay)
{
    RAT_DEBUG_TRACE();

    if (ps)
        ps->ps_delay = delay;

    return;
}


/**
 * @brief Set packet set header data
 *
 * @param ps                    packet set
 * @param hdr                   pointer to header raw data
 * @param len                   length of header data
 */
int rat_ps_set_header (struct rat_ps *ps, void *hdr, uint16_t len)
{
    RAT_DEBUG_TRACE();

    if (!ps || !hdr || !len || len > RAT_PS_PKTSPACE)
        goto exit_err;

    /* free old header if exists */
    if (ps->ps_hdrdata)
        free(ps->ps_hdrdata);

    /* malloc new header */
    ps->ps_hdrdata = malloc(len);
    if (!ps->ps_hdrdata)
        goto exit_err;

    /* copy header data and set length */
    memcpy(ps->ps_hdrdata, hdr, len);
    ps->ps_hdrlen = len;

    return RAT_OK;

exit_err:
    return RAT_ERROR;
}


/**
 * @brief Enlarge a packet set by one more packet
 *
 * @param ps                    packet set
 *
 * @return Returns pointer to new packet in ps, NULL on error
 */
static struct rat_ps_pkt *rat_ps_enlarge (struct rat_ps *ps)
{
    struct rat_ps_pkt *cur;
    struct rat_ps_pkt *new;
    RAT_DEBUG_TRACE();

    if (!ps)
        goto exit_err;

    /* allocate new element */
    new = calloc(1, sizeof(*new));
    if (!new)
        goto exit_err;

    /* add back reference */
    new->pkt_ps = ps;

    /* find end of list */
    if (!ps->ps_pkt) {
        ps->ps_pkt = new;
    } else {
        for (cur = ps->ps_pkt; cur->pkt_next; cur = cur->pkt_next);
        cur->pkt_next = new;
    }

    return new;

exit_err:
    return NULL;
}


/**
 * @brief Find free space in a packet set
 *
 * @param ps                    packet set
 * @param len                   number of bytes of free space to find
 *
 * @return Returns a packet having enough space left, NULL if not found
 */
static struct rat_ps_pkt *rat_ps_findspace (struct rat_ps *ps, uint16_t len)
{
    struct rat_ps_pkt *pkt;
    RAT_DEBUG_TRACE();

    if (!ps || !len || len > (RAT_PS_PKTSPACE - ps->ps_hdrlen))
        goto exit_err;

    for (pkt = ps->ps_pkt; pkt; pkt = pkt->pkt_next)
        if ((RAT_PS_PKTSPACE - ps->ps_hdrlen - pkt->pkt_len) > len)
            return pkt;

exit_err:
    return NULL;
}


/**
 * @brief Copy raw data to a packet
 *
 * @param pkt                   packet
 * @param data                  pointer to data
 * @param len                   number of bytes to copy
 *
 * @return Returns RAT_ERROR on error, RAT_OK otherwise
 */
static int rat_ps_pkt_copy_data (struct rat_ps_pkt *pkt, uint8_t *data,
                                 uint16_t len)
{
    RAT_DEBUG_TRACE();

    if (!pkt || !pkt->pkt_ps || !data || !len ||
        len > (RAT_PS_PKTSPACE - pkt->pkt_ps->ps_hdrlen - pkt->pkt_len))
        goto exit_err;

    memcpy(pkt->pkt_data + pkt->pkt_len, data, len);
    pkt->pkt_len += len;

    return RAT_OK;

exit_err:
    return RAT_ERROR;
}


/**
 * @brief Add raw data to a packet set
 *
 * @param ps                    packet set
 * @param data                  pointer to data
 * @param len                   number of bytes to copy
 *
 * @return Returns RAT_ERROR on error, RAT_OK otherwise
 */
int rat_ps_add_data (struct rat_ps *ps, uint8_t *data, uint16_t len)
{
    struct rat_ps_pkt *pkt;
    RAT_DEBUG_TRACE();

    if (!ps || !data || !len || len > (RAT_PS_PKTSPACE - ps->ps_hdrlen))
        goto exit_err;

    pkt = rat_ps_findspace(ps, len);
    if (!pkt) {
        pkt = rat_ps_enlarge(ps);
        if (!pkt)
            goto exit_err;
    }
    return rat_ps_pkt_copy_data(pkt, data, len);

exit_err:
    return RAT_ERROR;
}


/* --- send packet set ------------------------------------------------------ */


/**
 * @brief Send a packet set (threadable)
 *
 * For internal use only. Should always be called/threaded via rat_ps_send()!
 *
 * @param ptr                   pointer to packet set
 *
 * @return Returns NULL
 */
static void *__rat_ps_send (void *ptr)
{
    struct rat_ps *ps = (struct rat_ps *) ptr;
    /* socket and ancillary data */
    struct sockaddr_in6 dst;
    struct msghdr msghdr;
    struct iovec iov[2];
    struct in6_pktinfo *ipi;
    struct cmsghdr *cmsghdr;
    uint8_t cmsgbuf[CMSG_SPACE(sizeof(int)) + CMSG_SPACE(sizeof(*ipi))];
    struct rat_ps_pkt *pkt;
    RAT_DEBUG_TRACE();

    /* prepare buffers */
    memset(&dst, 0x0, sizeof(dst));
    memset(&msghdr, 0x0, sizeof(msghdr));
    memset(&cmsgbuf, 0x0, sizeof(cmsgbuf));
    memset(&iov, 0x0, sizeof(iov));

    /* destination address */
    dst.sin6_family = AF_INET6;
    dst.sin6_port = htons(IPPROTO_ICMPV6);
    /* TODO: make use of sin6_scope_id ? */
    memcpy(&dst.sin6_addr, &ps->ps_daddr, sizeof(dst.sin6_addr));

    /* message header */
    msghdr.msg_name = (void *) &dst;
    msghdr.msg_namelen = sizeof(dst);
    msghdr.msg_iov = (struct iovec *) &iov;
    msghdr.msg_iovlen = sizeof(iov) / sizeof(struct iovec);
    msghdr.msg_control = &cmsgbuf;
    msghdr.msg_controllen = sizeof(cmsgbuf);

    /* control message: hop limit */
    cmsghdr = CMSG_FIRSTHDR(&msghdr);
    cmsghdr->cmsg_level = IPPROTO_IPV6;
    cmsghdr->cmsg_type = IPV6_HOPLIMIT;
    cmsghdr->cmsg_len = CMSG_LEN(sizeof(int));
    *CMSG_DATA(cmsghdr) = RAT_PS_HOPLIMIT;
    /* control message: packet info */
    cmsghdr = CMSG_NXTHDR(&msghdr, cmsghdr);
    cmsghdr->cmsg_level = IPPROTO_IPV6;
    cmsghdr->cmsg_type = IPV6_PKTINFO;
    cmsghdr->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));
    ipi = (struct in6_pktinfo *) CMSG_DATA(cmsghdr);
    memcpy(&ipi->ipi_addr, &ps->ps_saddr, sizeof(ipi->ipi_addr));
    ipi->ipi_ifindex = ps->ps_ifindex;

    /* RA header */
    iov[0].iov_base = ps->ps_hdrdata;
    iov[0].iov_len = ps->ps_hdrlen;

    if (ps->ps_delay) {
        /*  __________________________
         * < Good night schoene Maid! >
         *  --------------------------
         *         \   ^__^
         *          \  (oo)\_______
         *             (__)\       )\/\
         *                 ||----w |
         *                 ||     ||
         */
        usleep(ps->ps_delay);
    }

    /* case 1: no pacekts, just packet header */
    if (!ps->ps_pkt) {
        msghdr.msg_iovlen = 1;
        if (sendmsg(ps->ps_sd, &msghdr, 0) < 0)
            rat_log_err("Delay: Interface %" PRIu32 ": Could not send packet",
                        ps->ps_ifindex);
    }
    /* case 2: packets containing payload */
    for (pkt = ps->ps_pkt; pkt; pkt = pkt->pkt_next) {
        iov[1].iov_base = pkt->pkt_data;
        iov[1].iov_len = pkt->pkt_len;
        if (sendmsg(ps->ps_sd, &msghdr, 0) < 0)
            rat_log_err("Delay: Interface %" PRIu32 ": Could not send packet",
                        ps->ps_ifindex);
    }

    rat_ps_destroy(ps);
    return NULL;
}


/**
 * @brief Send a packet set
 *
 * Non-delayed packets will be send by simply calling __rat_ps_send(), delayed
 * packets will be send by creating a new thread for __rat_ps_send().
 *
 * @param ps                    packet set
 *
 * @return Returns RAT_ERROR on error, RAT_OK otherwise
 */
int rat_ps_send (struct rat_ps *ps)
{
    pthread_t pthread;
    pthread_attr_t attr;
    RAT_DEBUG_TRACE();

    if (!ps)
        goto exit_err;

    if (ps->ps_delay) {
        /* create worker thread for delayed sending of packet set */
        pthread_attr_init(&attr);
        pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
        if (pthread_create(&pthread, &attr, __rat_ps_send, (void *) ps))
            goto exit_err;
        pthread_detach(pthread);
        pthread_attr_destroy(&attr);
    } else {
        /* send non-delayed packet set directly */
        __rat_ps_send((void *) ps);
    }

    return RAT_OK;

exit_err:
    return RAT_ERROR;
}


/* --- statistics ----------------------------------------------------------- */


/**
 * @brief Get number of bytes of packet set's payload
 *
 * @param ps                    packet set
 *
 * @return Returns the payload size in bytes
 */
uint64_t rat_ps_get_size (struct rat_ps *ps)
{
    uint64_t bytes;
    struct rat_ps_pkt *pkt;
    RAT_DEBUG_TRACE();

    if (!ps)
        return 0;

    bytes = ps->ps_hdrlen;
    for (pkt = ps->ps_pkt; pkt; pkt = pkt->pkt_next)
        bytes += pkt->pkt_len;

    return bytes;
}
