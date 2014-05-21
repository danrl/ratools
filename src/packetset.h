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


#ifndef __RATOOLS_PACKETSET_H
#define __RATOOLS_PACKETSET_H


#include "ratools.h"

#include <unistd.h>             /* useconds_t */


/** maximum payload size of a packet in a packet set */
#define RAT_PS_PKTSPACE         RAT_NDP_MAXPACKETLEN

/** Hop limit for outgoing packets */
#define RAT_PS_HOPLIMIT         RAT_NDP_HOPLIMIT


/**
 * @brief Packet set
 *
 * Packet sets are multiple packets of raw data (read: ICMPv6 options) that are
 * sent out at the same time. They share a common header (read: RA header) that
 * preceeds every single one of the packets of the packet set. Packet sets can
 * easily be delayed since they do not share any data with other parts of the
 * software. Added data is always copied to the packet set and not referenced.
 */
struct rat_ps {
    /** raw socket to use for sending */
    int                         ps_sd;
    /** interface to send the packet set from */
    uint32_t                    ps_ifindex;
    /** Source address of packet(s) */
    struct in6_addr             ps_saddr;
    /** Destination address of packet(s) */
    struct in6_addr             ps_daddr;
    /** Delay in microseconds */
    useconds_t                  ps_delay;
    /** Common header for all packets */
    void                        *ps_hdrdata;
    /** Length of common header */
    uint16_t                    ps_hdrlen;
    /** List of raw packet data */
    struct rat_ps_pkt           *ps_pkt;
};


/**
 * @brief Packet (part of a packet set)
 */
struct rat_ps_pkt {
    /** Pointer to packet set packet is part of */
    struct rat_ps               *pkt_ps;
    /** Pointer to next packet */
    struct rat_ps_pkt           *pkt_next;
    /** Length of data occupying the packet */
    uint16_t                    pkt_len;
    /** Actual packet raw data */
    uint8_t                     pkt_data[RAT_PS_PKTSPACE];
};


extern struct rat_ps *rat_ps_create (void);
extern struct rat_ps *rat_ps_destroy (struct rat_ps *);

extern void rat_ps_set_sd (struct rat_ps *, int);
extern void rat_ps_set_ifindex (struct rat_ps *, uint32_t);
extern void rat_ps_set_saddr (struct rat_ps *, struct in6_addr *);
extern void rat_ps_set_daddr (struct rat_ps *, struct in6_addr *);
extern void rat_ps_set_delay (struct rat_ps *, useconds_t);
extern int rat_ps_set_header (struct rat_ps *, void *, uint16_t);

extern int rat_ps_add_data (struct rat_ps *, uint8_t *, uint16_t);

extern uint64_t rat_ps_get_size (struct rat_ps *);

extern int rat_ps_send (struct rat_ps *);


#endif /* __RATOOLS_PACKETSET_H */
