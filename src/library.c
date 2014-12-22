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


#include "library.h"

#include <arpa/inet.h>          /* inet_ntop() */
#include <string.h>             /* memset */
#include <sys/time.h>
#include <time.h>
#include <stdlib.h>             /* srand() */
#include <regex.h>
#include <inttypes.h>           /* PRIu8 and friends */


/* --- hardware addresses --------------------------------------------------- */


/**
 * @brief Check hardware address for consistency
 *
 * @param hwa                   hardware address
 *
 * @return Returns true if hardware address is consistent, false otherwise
 */
int rat_lib_hwaddr_ok (struct rat_hwaddr *hwa)
{
    return (hwa->hwa_len && hwa->hwa_len <= sizeof(hwa->hwa_addr));
}


/**
 * @brief Convert hardware address to human readable string
 *
 *      0x112233445566 -> "11:22:33:44:55:66"
 *
 * @param buf                   string buffer
 * @param buflen                buffer size
 * @param hwa                   hardware address
 *
 * @return Returns RAT_ERROR on error, RAT_OK otherwise
 */
int rat_lib_hwaddr_to_str (char *buf, size_t buflen, struct rat_hwaddr *hwa)
{
    uint8_t len;

    if (!buf || !buflen || !hwa)
        goto exit_err;

    *buf = 0x0;
    /* check if buffer is large enough to hold hardware address string */
    if (buflen < (hwa->hwa_len * 3))
        return 0;

    for (len = 0; len < hwa->hwa_len; len++) {
        snprintf(buf, 3, "%02x", hwa->hwa_addr[len]);
        buf += 2;
        *buf++ = ':';
    }
    *--buf = 0x0;

    return RAT_OK;

exit_err:
    return RAT_ERROR;
}


/**
 * @brief Parse hardware address string
 *
 * Please note: The human readable string must not contain characters other
 * then 0-9, a-f, `:' and `-'.
 * "11:22:33:44:55:66" -> 0x112233445566
 *
 * @param[out] hwa              hardware address
 * @param[in] str               string
 *
 * @return Returns RAT_ERROR on error, RAT_OK otherwise
 */
int rat_lib_hwaddr_from_str (struct rat_hwaddr *hwa, const char *str)
{
    size_t slen;
    unsigned int tmp = 0;
    char c = 0x0;

    slen = (strlen(str) + 1) / 3;
    hwa->hwa_len = 0;

    /* convert every 2 hex chars into one hardware address byte each */
    while (hwa->hwa_len < sizeof(hwa->hwa_addr) && hwa->hwa_len < slen) {
        sscanf(str, "%02x%c", &tmp, &c);
        if (c != ':' && c != '-')
            break;
        hwa->hwa_addr[hwa->hwa_len] = (uint8_t) tmp;
        str += 3;
        hwa->hwa_len++;
    }

    return (hwa->hwa_len ? RAT_OK : RAT_ERROR);
}


/* --- ipv6 addresses ------------------------------------------------------- */


/** All nodes multicast address */
static const struct in6_addr rat_lib_6addr_allnodes =  { { {
    0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
} } };


/** All routers multicast address */
static const struct in6_addr rat_lib_6addr_allrouters =  { { {
    0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02
} } };


/** Unspecified address */
static const struct in6_addr rat_lib_6addr_unspecified =  { { {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
} } };


/** Link-local prefix, we use the first 64 bits only */
static const struct in6_addr rat_lib_6addr_linklocal =  { { {
    0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
} } };


/** Documentation prefix, we use the first 32 bits only */
static const struct in6_addr rat_lib_6addr_documentation =  { { {
    0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
} } };


/**
 * @brief Test for all nodes multicast address
 *
 * @param addr:                 address to test
 *
 * @return True on success, false otherwise.
 */
int rat_lib_6addr_is_allnodes (struct in6_addr *addr)
{
    return !(memcmp(&rat_lib_6addr_allnodes, addr, sizeof(*addr)));
}


/**
 * @brief Set addr to all nodes multicast address
 *
 * @param addr:                 address to set
 *
 * @return Pointer to addr on success, NULL otherwise.
 */
void *rat_lib_6addr_set_allnodes (struct in6_addr *addr)
{
    return memcpy(addr, &rat_lib_6addr_allnodes, sizeof(*addr));
}


/**
 * @brief Test for all routers multicast address
 *
 * @param addr:                 address to test
 *
 * @return True on success, false otherwise.
 */
int rat_lib_6addr_is_allrouters (struct in6_addr *addr)
{
    return !(memcmp(&rat_lib_6addr_allrouters, addr, sizeof(*addr)));
}


/**
 * @brief Set addr to all routers multicast address
 *
 * @param addr:                 address to set
 *
 * @return Pointer to addr on success, NULL otherwise.
 */
void *rat_lib_6addr_set_allrouters (struct in6_addr *addr)
{
    return memcpy(addr, &rat_lib_6addr_allrouters, sizeof(*addr));
}


/**
 * @brief Test for unspecified address
 *
 * @param addr:                 address to test
 *
 * @return True on success, false otherwise.
 */
int rat_lib_6addr_is_unspecified (struct in6_addr *addr)
{
    return !(memcmp(&rat_lib_6addr_unspecified, addr, sizeof(*addr)));
}


/**
 * @page lib_6addr1 Link-local Address Validation
 *
 * There are already macros out there for this but they are often not strict
 * enough! Even KAME validated link-local addresses by just comparing the first
 * two octets which is not enough.
 *
 *     RFC 4291 IP Version 6 Addressing Architecture
 *       2.5.6.  Link-Local IPv6 Unicast Addresses
 *
 *          Link-Local addresses are for use on a single link.  Link-Local
 *          addresses have the following format:
 *
 *          |   10     |
 *          |  bits    |         54 bits         |          64 bits           |
 *          +----------+-------------------------+----------------------------+
 *          |1111111010|           0             |       interface ID         |
 *          +----------+-------------------------+----------------------------+
 *
 * RFC 4291 requires that link-local addresses are within fe80::/64 even if the
 * link-local prefix is fe80::/10.
 */


/**
 * @brief Test for link-local address
 *
 * @param addr:                 address to test
 *
 * @return True on success, false otherwise.
 */
int rat_lib_6addr_is_linklocal (struct in6_addr *addr)
{
    return !(memcmp(&rat_lib_6addr_linklocal, addr, 8));
}


/**
 * @brief Test for documentation prefix
 *
 * @param addr:                 address to test
 *
 * @return True on success, false otherwise.
 */
int rat_lib_6addr_is_documentation (struct in6_addr *addr)
{
    return !(memcmp(&rat_lib_6addr_documentation, addr, 16));
}


/**
 * @brief Test for multicast address
 *
 * @param addr:                 address to test
 *
 * @return True on success, false otherwise.
 */
int rat_lib_6addr_is_multicast (struct in6_addr *addr)
{
    return (addr->s6_addr[0] == 0xff);
}


/**
 * @brief Convert ipv6 address to human readable string
 *
 * @param buf                   string buffer
 * @param buflen                buffer size
 * @param addr                  ipv6 address
 *
 * @return Returns RAT_ERROR on error, RAT_OK otherwise
 */
int rat_lib_6addr_to_str (char *buf, size_t buflen, struct in6_addr *addr)
{
    if (!buf || !buflen || !addr)
        goto exit_err;

    if (inet_ntop(AF_INET6, (void *) addr, buf, buflen))
        return RAT_OK;

exit_err:
    return RAT_ERROR;
}


/**
 * @brief Parse ipv6 address string
 *
 * @param[out] addr             address
 * @param[in] str               string
 *
 * @return Returns RAT_ERROR on error, RAT_OK otherwise
 */
int rat_lib_6addr_from_str (struct in6_addr *addr, const char *str)
{
    if (!addr || !str)
        goto exit_err;

    if (inet_pton(AF_INET6, str, addr) != 0)
        return RAT_OK;

exit_err:
    return RAT_ERROR;
}


/**
 * @brief Check ipv6 address string
 *
 * @param addr                  address
 *
 * @return Returns RAT_ERROR on error, RAT_OK otherwise
 */
int rat_lib_6addr_ok (struct in6_addr *addr)
{
    char buf[INET6_ADDRSTRLEN];
    if (!addr)
        goto exit_err;

    if (inet_pton(AF_INET6, buf, addr) == 0)
        return 1;

exit_err:
    return 0;
}


/* --- prefixes ------------------------------------------------------------- */


/**
 * @brief Check ipv6 prefix for consistency
 *
 * @param pfx                   hardware address
 *
 * @return Returns true if prefix is consistent, false otherwise
 */
int rat_lib_prefix_ok (struct rat_prefix *pfx)
{
    return (pfx->pfx_len <= 128);
}


/**
 * @brief Convert prefix to human readable string
 *
 * @param buf                   string buffer
 * @param buflen                buffer size
 * @param pfx                   prefix
 *
 * @return Returns RAT_ERROR on error, RAT_OK otherwise
 */
int rat_lib_prefix_to_str (char *buf, size_t buflen, struct rat_prefix *pfx)
{
    char tmp[5];

    if (!buf || !buflen || !pfx ||
        rat_lib_6addr_to_str(buf, buflen, &pfx->pfx_addr) != RAT_OK)
        goto exit_err;

    snprintf(tmp, sizeof(tmp), "/%" PRIu8, pfx->pfx_len);
    strncat(buf, tmp, buflen - strlen(buf) - 1);
    return RAT_OK;

exit_err:
    return RAT_ERROR;
}


/**
 * @brief Parse prefix address
 *
 * @param[out] pfx              prefix
 * @param[in] str               string
 *
 * @return Returns RAT_ERROR on error, RAT_OK otherwise
 */
int rat_lib_prefix_from_str (struct rat_prefix *pfx, const char *str)
{
    char buf[RAT_PREFIX_STRSIZ];
    char *plen;
    unsigned int u;

    if (!pfx || !str)
        goto exit_err;

    strncpy(buf, str, sizeof(buf) - 1);
    plen = buf - 1;
    while (*++plen && *plen != '/');
    if (*plen)
        *plen++ = 0x0;

    if (rat_lib_6addr_from_str(&pfx->pfx_addr, buf) != RAT_OK)
        goto exit_err;

    sscanf(plen, "%u", &u);
    pfx->pfx_len = (uint8_t) u;

    if (!rat_lib_prefix_ok(pfx))
        goto exit_err;

    return RAT_OK;

exit_err:
    return RAT_ERROR;
}


/* --- signal --------------------------------------------------------------- */


/**
 * @brief Dummy signal handler that does nothing
 *
 * @param sig                   signal (ignored)
 */
void rat_lib_signal_dummy_handler (int sig)
{
    RAT_DISCARD_UNUSED(sig);

    return;
}


/* --- bytes ---------------------------------------------------------------- */


/**
 * @brief Convert a byte counter to a human readable asciiz string
 *
 * @param buf                   destination buffer
 * @param buflen                siye of destination buffer
 * @param bytes                 byte counter
 *
 * @return Returns RAT_ERROR on error, RAT_OK otherwise
 */
int rat_lib_bytes_to_str (char *buf, size_t buflen, uint64_t bytes)
{
    unsigned int i = 0;
    double dbytes;
    const char const *sfx[] = {
        "Bytes", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB", "ZiB", "YiB"
    };

    if (!buf || !buflen)
        goto exit_err;

    dbytes = bytes;
    while ((dbytes / 1024.0) >= 1024.0) {
        dbytes /= 1024.0;
        i++;
        if (i > 2 && (i - 2) >= sizeof(sfx) / sizeof(sfx[0]))
            break;
    }
    if (i)
        snprintf(buf, buflen, "%0.2f %s", dbytes, sfx[i]);
    else
        snprintf(buf, buflen, "%.0f %s", dbytes, sfx[i]);

    return RAT_OK;

exit_err:
    return RAT_ERROR;
}


/* --- time ----------------------------------------------------------------- */


/**
 * @brief Time to ISO time string
 *
 * We replace ISO `T' with a whitespace to increase human readability
 *
 * @param buf                   string buffer
 * @param buflen                string buffer size
 * @param t                     time
 *
 * @return Returns RAT_ERROR on error, RAT_OK otherwise
 */
int rat_lib_time_to_str (char * const buf, const size_t buflen, time_t *t)
{
    if (strftime(buf, buflen, "%Y-%m-%d %H:%M:%S", localtime(t)))
        return RAT_OK;

    return RAT_ERROR;
}


/* --- random --------------------------------------------------------------- */


/**
 * @brief Initialize random number generator
 */
void rat_lib_random_init (void)
{
    struct timeval tv;

    /* TODO: This one needs a more unique seed! */

    /*
     * if a pseudo-random number generator is used in
     * calculating a random delay component, the generator
     * should be initialized with a unique seed prior to being
     * used.  Note that it is not sufficient to use the
     * interface identifier alone as the seed, since interface
     * identifiers will not always be unique.  To reduce the
     * probability that duplicate interface identifiers cause
     * the same seed to be used, the seed should be calculated
     * from a variety of input sources (e.g., machine
     * components) that are likely to be different even on
     * identical "boxes".  For example, the seed could be
     * formed by combining the CPU's serial number with an
     * interface identifier.
     *
     * (RFC 4861 sec. 2.1)
     */
    gettimeofday(&tv, NULL);
    srand(tv.tv_usec * tv.tv_sec);

    return;
}


/* --- regex ---------------------------------------------------------------- */



/**
 * @brief Match a string against a regex pattern
 *
 * @param regex                 regex pattern
 * @param str                   string to match
 *
 * This function is shamefully inefficient. Previous versions of it cached
 * precompiled regex patterns and maintained a list of commonly used patterns.
 * Eventually the patterns where scattered over multiple files and required more
 * than a handful of macros to abstract them. For the sake of beautiful code we
 * waste some precious cpu cycles here. Warming up the planet a bit... /o\ Sry!
 */
int rat_lib_regex_match (const char *regex, const char *str)
{
    regex_t rgx;

    if (regcomp(&rgx, regex, REG_EXTENDED | REG_ICASE) != 0)
        goto exit_err;

    if (regexec(&rgx, str, 0, NULL, 0) == 0) {
        regfree(&rgx);
        return RAT_OK;
    }
    regfree(&rgx);

exit_err:
    return RAT_ERROR;
}


