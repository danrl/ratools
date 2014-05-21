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


#ifndef __RATOOLS_LIBRARY_H
#define __RATOOLS_LIBRARY_H

#include "ratools.h"

#include <netinet/in.h>         /* struct in6_addr */


/* --- hardware addresses --------------------------------------------------- */


extern int rat_lib_hwaddr_ok (struct rat_hwaddr *);
extern int rat_lib_hwaddr_to_str (char *, size_t, struct rat_hwaddr *);
extern int rat_lib_hwaddr_from_str (struct rat_hwaddr *, const char *);

/* --- ipv6 addresses ------------------------------------------------------- */


extern int rat_lib_6addr_is_allnodes (struct in6_addr *);
extern void *rat_lib_6addr_set_allnodes (struct in6_addr *);
extern int rat_lib_6addr_is_allrouters (struct in6_addr *);
extern void *rat_lib_6addr_set_allrouters (struct in6_addr *);
extern int rat_lib_6addr_is_unspecified (struct in6_addr *);
extern int rat_lib_6addr_is_linklocal (struct in6_addr *);
extern int rat_lib_6addr_is_documentation (struct in6_addr *);
extern int rat_lib_6addr_is_multicast (struct in6_addr *);
extern int rat_lib_6addr_to_str (char *, size_t, struct in6_addr *);
extern int rat_lib_6addr_from_str (struct in6_addr *, const char *);
extern int rat_lib_6addr_ok (struct in6_addr *);

/* --- prefixes ------------------------------------------------------------- */


extern int rat_lib_prefix_ok (struct rat_prefix *);
extern int rat_lib_prefix_to_str (char *, size_t, struct rat_prefix *);
extern int rat_lib_prefix_from_str (struct rat_prefix *, const char *);


/* --- signal --------------------------------------------------------------- */


extern void rat_lib_signal_dummy_handler (int);


/* --- bytes ---------------------------------------------------------------- */


extern int rat_lib_bytes_to_str (char *, size_t, uint64_t);


/* --- time ----------------------------------------------------------------- */


extern int rat_lib_time_to_str (char * const, const size_t, time_t *);


/* --- random --------------------------------------------------------------- */


extern void rat_lib_random_init (void);


/* --- regex ---------------------------------------------------------------- */


extern int rat_lib_regex_match (const char *, const char *);


#endif /* __RATOOLS_LIBRARY_H */
