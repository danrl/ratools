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


#ifndef __RATOOLS_MODULE_H
#define __RATOOLS_MODULE_H


#include "ratools.h"

#include <stdint.h>


/* --- actions  ------------------------------------------------------------- */


/** Action IDs */
/** @{ */
#define RAT_MOD_AID_CREATE      0
#define RAT_MOD_AID_DESTROY     1
#define RAT_MOD_AID_ENABLE      2
#define RAT_MOD_AID_DISABLE     3
#define RAT_MOD_AID_KILL        4
#define RAT_MOD_AID_SHOW        5
#define RAT_MOD_AID_DUMP        6
#define RAT_MOD_AID_SET         7
#define RAT_MOD_AID_ADD         8
#define RAT_MOD_AID_DEL         9
/** @} */


/** Regular expressions to parse actions */
/** @{ */
#define RAT_MOD_ACT_RGX_CREATE  "^cr?$|" \
                                "^crea?$|" \
                                "^create?$"
#define RAT_MOD_ACT_RGX_DESTROY "^des?$|" \
                                "^destr?$|" \
                                "^destroy?$"
#define RAT_MOD_ACT_RGX_ENABLE  "^en?$|" \
                                "^enab?$|" \
                                "^enable?$"
#define RAT_MOD_ACT_RGX_DISABLE "^dis?$|" \
                                "^disab?$|" \
                                "^disable?$"
#define RAT_MOD_ACT_RGX_KILL    "^ki?$|" \
                                "^kill?$"
#define RAT_MOD_ACT_RGX_SHOW    "^sho?$|" \
                                "^show$"
#define RAT_MOD_ACT_RGX_DUMP    "^dum?$|" \
                                "^dump$"
#define RAT_MOD_ACT_RGX_SET     "^set?$"
#define RAT_MOD_ACT_RGX_ADD     "^ad?$|" \
                                "^add$"
#define RAT_MOD_ACT_RGX_DEL     "^del?$"
/** @} */


/* --- module registry data structures -------------------------------------- */


/**
 * @brief Module instance data
 *
 * There are some information we have to leak out to modules to make sure they
 * an test their values for RFC compliance and to produce meaningful error
 * messages.
 */
struct rat_mod_instance {
    /** @{ */
    /** Interface index */
    uint32_t                    mi_ifindex;
    /** Option index of instance */
    uint32_t                    mi_index;
    /** Instance name. [module][index]@[ifname]\0 */
    char                        mi_myname[RAT_MODNAMELEN +
                                          RAT_INDEXSTRLEN + 1 +
                                          RAT_IFNAMELEN + 1];
    /** Output indentation hint */
    uint8_t                     mi_in;
    /** Pointer to instance private data */
    void                        *mi_private;
    /** Pointer to instance raw icmp6 raw data */
    void                        *mi_rawdata;
    /** Pointer to instance raw icmp6 raw data length */
    uint16_t                    *mi_rawlen;
    /** @} */
    /** @{ */
    /** Maximum advertising interval of interface */
    uint16_t                    mi_maxadvint;
    /** Indicate that RA is currently fading out */
    uint16_t                    mi_fadingout;
    /** Interface MTU */
    uint32_t                    mi_linkmtu;
    /** Interface hardware address */
    struct rat_hwaddr           mi_hwaddr;
    /** @} */
};


/** Set output indentation hint */
#define RAT_MOD_MI_IN(mi, in)   (((struct rat_mod_instance *) mi)->mi_in = in)

/** Macro to access the private data directly */
#define RAT_MOD_PRIVATE(mi)                                                 \
    (*((void **) ((struct rat_mod_instance *) mi)->mi_private))

/** Macro to access raw data directly (for mmr_compile) */
#define RAT_MOD_RAWDATA(mi)                                                 \
    (*((void **) ((struct rat_mod_instance *) mi)->mi_rawdata))

/** Macro to access raw data length directly */
#define RAT_MOD_RAWLEN(mi)                                                  \
    (*((uint16_t *) ((struct rat_mod_instance *) mi)->mi_rawlen))


/**
 * @brief Module helper function
 *
 * A set of functions for modules to use for fancy output, informational and
 * error messages.
 */
struct rat_mod_functions {
    /** @{ */
    /** Send formatted message to client */
    int                         (*mf_message)        (const char *, ...);
    /** Send formatted error message to client */
    int                         (*mf_error)          (const char *, ...);
    /** @} */
    /** @{ */
    /** Send option title to client */
    int                         (*mf_title)          (uint8_t, const char *,
                                                     ...);
    /** Send parameter name to client */
    int                         (*mf_param)          (uint8_t, const char *,
                                                     ...);
    /** Send parameter value to client */
    int                         (*mf_value)          (const char *, ...);
    /** Send parameter info to client */
    int                         (*mf_info)           (const char *, ...);
    /** Send parameter comment to client */
    int                         (*mf_comment)        (uint8_t, const char *,
                                                     ...);
    /** @} */
};


/**
 * @brief Value registration information
 *
 * Used to register a value and a parser target function.
 */
struct rat_mod_valreg {
    /** Regular expression matching the expected value */
    char                        *mvr_regex;
    /** Asciiz string of expected value for printing help */
    char                        *mvr_help;
    /** Parser function for the values matching mvr_regex */
    int                         (*mvr_parse)        (const char *, uint8_t *,
                                                     uint16_t);
};


/**
 * @brief set/add/del parameter registration information
 *
 * Used to register parameters for the extendable actions `set', `add' and
 * `del'.
 */
struct rat_mod_sadreg {
    /** Regular expression of parameter */
    char                        *msr_regex;
    /** Asciiz string of parameter */
    char                        *msr_help;
    /** Function to process parsed value on the daemon side */
    int                         (*msr_func)         (struct rat_mod_functions *,
                                                     struct rat_mod_instance *,
                                                     uint8_t *, uint16_t);
    /** Value registration information */
    struct rat_mod_valreg       *msr_val;
    /** Length of value registration information */
    uint16_t                    msr_vallen;
};


/**
 * @brief Module registration information
 *
 * Used to register a module.
 */
struct rat_mod_modreg {
    /** @{ */
    /** Next registration information in registry. Managed my the framework. */
    struct rat_mod_modreg       *mmr_next;
    /** Module id. Managed my the framework. */
    uint16_t                    mmr_mid;
    /** @} */
    /** @{ */
    /** Regular expression to match module name */
    char                        *mmr_regex;
    /** Module name */
    char                        *mmr_name;
    /** Whether or not the module allowes multiple instances */
    int                         mmr_multiple;
    /** Daemon function for action `create' */
    int                         (*mmr_create)       (struct rat_mod_functions *,
                                                     struct rat_mod_instance *);
    /** Daemon function for action `destroy' */
    int                         (*mmr_destroy)      (struct rat_mod_functions *,
                                                     struct rat_mod_instance *);
    /** Daemon function for action `enable' */
    int                         (*mmr_enable)       (struct rat_mod_functions *,
                                                     struct rat_mod_instance *);
    /** Daemon function for action `disable' */
    int                         (*mmr_disable)      (struct rat_mod_functions *,
                                                     struct rat_mod_instance *);
    /** Daemon function for action `kill' */
    int                         (*mmr_kill)         (struct rat_mod_functions *,
                                                     struct rat_mod_instance *);
    /** Daemon function for action `show' */
    int                         (*mmr_show)         (struct rat_mod_functions *,
                                                     struct rat_mod_instance *);
    /** Daemon function for action `dump' */
    int                         (*mmr_dump)         (struct rat_mod_functions *,
                                                     struct rat_mod_instance *);
    /** Parameter registration information for action `set' */
    struct rat_mod_sadreg       *mmr_set;
    /** Length of parameter registration information for action `set' */
    uint16_t                    mmr_setlen;
    /** Parameter registration information for action `add' */
    struct rat_mod_sadreg       *mmr_add;
    /** Length of parameter registration information for action `add' */
    uint16_t                    mmr_addlen;
    /** Parameter registration information for action `del' */
    struct rat_mod_sadreg       *mmr_del;
    /** Length of parameter registration information for action `del' */
    uint16_t                    mmr_dellen;
    /** Compile function */
    int                         (*mmr_compile)      (struct rat_mod_instance *);
    /** Whether or not the instance is enabled and provind ICMPv6 raw data */
    int                         (*mmr_is_enabled)   (struct rat_mod_functions *,
                                                     struct rat_mod_instance *);
    /** @} */
};


/* --- generics ------------------------------------------------------------- */


extern int rat_mod_generic_dummy (struct rat_mod_functions *,
                                  struct rat_mod_instance *);
extern int rat_mod_generic_destroy (struct rat_mod_functions *,
                                    struct rat_mod_instance *);
extern int rat_mod_generic_set_dummy (struct rat_mod_functions *,
                                      struct rat_mod_instance *,
                                      uint8_t *, uint16_t);

extern int rat_mod_generic_set_val_uint8 (const char *, uint8_t *, uint16_t);
extern int rat_mod_generic_set_val_uint16 (const char *, uint8_t *, uint16_t);
extern int rat_mod_generic_set_val_uint32 (const char *, uint8_t *, uint16_t);
extern int rat_mod_generic_set_val_zero8 (const char *, uint8_t *, uint16_t);
extern int rat_mod_generic_set_val_max8 (const char *, uint8_t *, uint16_t);
extern int rat_mod_generic_set_val_zero16 (const char *, uint8_t *, uint16_t);
extern int rat_mod_generic_set_val_max16 (const char *, uint8_t *, uint16_t);
extern int rat_mod_generic_set_val_zero32 (const char *, uint8_t *, uint16_t);
extern int rat_mod_generic_set_val_max32 (const char *, uint8_t *, uint16_t);
extern int rat_mod_generic_set_val_minsec16 (const char *, uint8_t *, uint16_t);
extern int rat_mod_generic_set_val_hminsec16 (const char *, uint8_t *,
                                              uint16_t);
extern int rat_mod_generic_set_val_hminsecms32 (const char *, uint8_t *,
                                                uint16_t);
extern int rat_mod_generic_set_val_dhminsec32 (const char *, uint8_t *,
                                               uint16_t );
extern struct rat_mod_valreg rat_mod_generic_set_val_flag[];


/** length of rat_mod_generic_set_flag[] */
#define RAT_MOD_GENERIC_SET_VAL_FLAG_LEN    2


/* --- module registry functions -------------------------------------------- */


extern int rat_mod_register (struct rat_mod_modreg *);
extern int rat_mod_requires_oid (uint16_t);
extern int rat_mod_requires_pid (uint16_t, uint16_t);
extern int rat_mod_requires_vid (uint16_t, uint16_t, uint16_t);
extern struct rat_mod_modreg *rat_mod_leak_registry (void);

extern char *rat_mod_get_name (uint16_t);

extern int rat_mod_parse_module (const char *, uint16_t *);
extern int rat_mod_parse_action (uint16_t, const char *, uint16_t *);
extern int rat_mod_parse_parameter (uint16_t, uint16_t, const char *,
                                    uint16_t *);
extern int rat_mod_parse_value (uint16_t, uint16_t, uint16_t, const char *,
                                uint16_t *);


/* --- CLI help ------------------------------------------------------------- */


extern int rat_mod_help_modules (void);
extern int rat_mod_help_actions (uint16_t);
extern int rat_mod_help_parameters (uint16_t, uint16_t);
extern int rat_mod_help_values (uint16_t, uint16_t, uint16_t);


/* --- function caller ------------------------------------------------------ */


extern int rat_mod_cli_call_vid (uint16_t, uint16_t, uint16_t, uint16_t,
                                 const char *, uint8_t *, uint16_t);
extern int rat_mod_rad_call_aid (struct rat_mod_functions *,
                                 struct rat_mod_instance *, uint16_t, uint16_t);
extern int rat_mod_rad_call_pid (struct rat_mod_functions *,
                                 struct rat_mod_instance *, uint16_t, uint16_t,
                                 uint16_t, uint8_t *, uint16_t);
extern int rat_mod_rad_call_compile (struct rat_mod_instance *, uint16_t);


/* --- API interception ----------------------------------------------------- */


extern int rat_mod_icpt_pid (uint16_t, const char *, uint16_t, const char *,
                             uint16_t, const char *);
extern int rat_mod_icpt_aid (uint16_t, const char *, uint16_t, const char *);
extern int rat_mod_icpt_mid (uint16_t, const char *);


#endif /* __RATOOLS_MODULE_H */
