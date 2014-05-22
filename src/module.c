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


#include "module.h"

#include "library.h"

#include <stdlib.h>
#include <stdio.h>
#include <inttypes.h>
#include <string.h>


/* --- generic parser functions --------------------------------------------- */


/**
 * @brief Dummy target for action command interception or debug use
 *
 * @param mf                    module helper functions
 * @param mi                    module instance data
 *
 * There are only rare cases where you want to use this function. Nevertheless,
 * it is essential to the core framework. This is not useless code, it just
 * happens to come in perfect disguise!
 *
 * @return Always returns RAT_OK
 */
int rat_mod_generic_dummy (struct rat_mod_functions *mf,
                           struct rat_mod_instance *mi)
{
    RAT_DEBUG_TRACE();

    RAT_DISCARD_UNUSED(mf);
    RAT_DISCARD_UNUSED(mi);

    return RAT_OK;
}


/**
 * @brief Generic target for action `destroy'
 *
 * Free's the instances private data using free(). For modules that use simple
 * allocation for their private data.
 *
 * @param mf                    module helper functions
 * @param mi                    module instance data
 *
 * @return Always returns RAT_OK
 */
int rat_mod_generic_destroy (struct rat_mod_functions *mf,
                             struct rat_mod_instance *mi)
{
    void *ptr;
    RAT_DEBUG_TRACE();

    RAT_DISCARD_UNUSED(mf);

    /* free private data */
    ptr = RAT_MOD_PRIVATE(mi);
    if (ptr)
        free(ptr);
    RAT_MOD_PRIVATE(mi) = NULL;

    /* free raw data */
    ptr = RAT_MOD_RAWDATA(mi);
    if (ptr)
        free(ptr);
    RAT_MOD_RAWDATA(mi) = NULL;
    RAT_MOD_RAWLEN(mi) = 0;

    return RAT_OK;
}


/**
 * @brief Dummy target for set/add/del command interception or debug use
 *
 * There are only rare cases where you want to use this function. Nevertheless,
 * it is essential to the core framework. This is not useless code, it just
 * happens to come in perfect disguise!
 *
 * @param mf                    module helper functions
 * @param mi                    module instance data
 * @param argdata               argument data
 * @param arglen                argument data length
 *
 * @return Always returns RAT_OK
 */
int rat_mod_generic_set_dummy (struct rat_mod_functions *mf,
                               struct rat_mod_instance *mi,
                               uint8_t *argdata, uint16_t arglen)
{
    RAT_DEBUG_TRACE();

    RAT_DISCARD_UNUSED(mf);
    RAT_DISCARD_UNUSED(mi);
    RAT_DISCARD_UNUSED(argdata);
    RAT_DISCARD_UNUSED(arglen);

    return RAT_OK;
}


/**
 * @brief Generic target for setting an 8 bit unsigned int value
 *
 * @param argv                  argument value
 * @param data                  data buffer in request
 * @param len                   data buffer length
 *
 * @return Returns RAT_ERROR on error, RAT_OK otherwise
 */
int rat_mod_generic_set_val_uint8 (const char *argv, uint8_t *data,
                                   uint16_t len)
{
    uint64_t v;
    RAT_DEBUG_TRACE();

    if (!argv || !data || len < sizeof(uint8_t))
        return RAT_ERROR;

    v = strtoull(argv, NULL, 10);
    if (v > UINT8_MAX) {
        fprintf(stderr, "Warning: Value `%" PRIu64 "' out of range! " \
                "Limited to `%" PRIu8 "'!\n", v, UINT8_MAX);
        v = UINT8_MAX;
    }
    *((uint8_t *) data) = (uint8_t) v;

    return RAT_OK;
}


/**
 * @brief Generic target for setting a 16 bit unsigned int value
 *
 * @param argv                  argument value
 * @param data                  data buffer in request
 * @param len                   data buffer length
 *
 * @return Returns RAT_ERROR on error, RAT_OK otherwise
 */
int rat_mod_generic_set_val_uint16 (const char *argv, uint8_t *data,
                                    uint16_t len)
{
    uint64_t v;
    RAT_DEBUG_TRACE();

    if (!argv || !data || len < sizeof(uint16_t))
        return RAT_ERROR;

    v = strtoull(argv, NULL, 10);
    if (v > UINT16_MAX) {
        fprintf(stderr, "Warning: Value `%" PRIu64 "' out of range! " \
                "Limited to `%" PRIu16 "'!\n", v, UINT16_MAX);
        v = UINT16_MAX;
    }
    *((uint16_t *) data) = (uint16_t) v;

    return RAT_OK;
}


/**
 * @brief Generic target for setting a 32 bit unsigned int value
 *
 * @param argv                  argument value
 * @param data                  data buffer in request
 * @param len                   data buffer length
 *
 * @return Returns RAT_ERROR on error, RAT_OK otherwise
 */
int rat_mod_generic_set_val_uint32 (const char *argv, uint8_t *data,
                                    uint16_t len)
{
    uint64_t v;
    RAT_DEBUG_TRACE();

    if (!argv || !data || len < sizeof(uint32_t))
        return RAT_ERROR;

    v = strtoull(argv, NULL, 10);
    if (v > UINT32_MAX) {
        fprintf(stderr, "Warning: Value `%" PRIu64 "' out of range! " \
                "Limited to `%" PRIu32 "'!\n", v, UINT32_MAX);
        v = UINT32_MAX;
    }
    *((uint32_t *) data) = (uint32_t) v;

    return RAT_OK;
}


/**
 * @brief Generic target for setting an 8 bit unsigned int value to zero
 *
 * @param argv                  argument value
 * @param data                  data buffer in request
 * @param len                   data buffer length
 *
 * @return Returns RAT_ERROR on error, RAT_OK otherwise
 */
int rat_mod_generic_set_val_zero8 (const char *argv, uint8_t *data,
                                   uint16_t len)
{
    RAT_DEBUG_TRACE();

    if (!argv || !data || len < sizeof(uint8_t))
        return RAT_ERROR;

    *((uint8_t *) data) = 0;

    return RAT_OK;
}


/**
 * @brief Generic target for setting an 8 bit unsigned int value to maximum
 *
 * @param argv                  argument value
 * @param data                  data buffer in request
 * @param len                   data buffer length
 *
 * @return Returns RAT_ERROR on error, RAT_OK otherwise
 */
int rat_mod_generic_set_val_max8 (const char *argv, uint8_t *data,
                                   uint16_t len)
{
    RAT_DEBUG_TRACE();

    if (!argv || !data || len < sizeof(uint8_t))
        return RAT_ERROR;

    *((uint8_t *) data) = UINT8_MAX;

    return RAT_OK;
}


/**
 * @brief Generic target for setting a 16 bit unsigned int value to zero
 *
 * @param argv                  argument value
 * @param data                  data buffer in request
 * @param len                   data buffer length
 *
 * @return Returns RAT_ERROR on error, RAT_OK otherwise
 */
int rat_mod_generic_set_val_zero16 (const char *argv, uint8_t *data,
                                    uint16_t len)
{
    RAT_DEBUG_TRACE();

    if (!argv || !data || len < sizeof(uint16_t))
        return RAT_ERROR;

    *((uint16_t *) data) = 0;

    return RAT_OK;
}


/**
 * @brief Generic target for setting a 16 bit unsigned int value to maximum
 *
 * @param argv                  argument value
 * @param data                  data buffer in request
 * @param len                   data buffer length
 *
 * @return Returns RAT_ERROR on error, RAT_OK otherwise
 */
int rat_mod_generic_set_val_max16 (const char *argv, uint8_t *data,
                                   uint16_t len)
{
    RAT_DEBUG_TRACE();

    if (!argv || !data || len < sizeof(uint16_t))
        return RAT_ERROR;

    *((uint16_t *) data) = UINT16_MAX;

    return RAT_OK;
}


/**
 * @brief Generic target for setting a 32 bit unsigned int value to zero
 *
 * @param argv                  argument value
 * @param data                  data buffer in request
 * @param len                   data buffer length
 *
 * @return Returns RAT_ERROR on error, RAT_OK otherwise
 */
int rat_mod_generic_set_val_zero32 (const char *argv, uint8_t *data,
                                    uint16_t len)
{
    RAT_DEBUG_TRACE();

    if (!argv || !data || len < sizeof(uint32_t))
        return RAT_ERROR;

    *((uint32_t *) data) = 0;

    return RAT_OK;
}


/**
 * @brief Generic target for setting a 32 bit unsigned int value to maximum
 *
 * @param argv                  argument value
 * @param data                  data buffer in request
 * @param len                   data buffer length
 *
 * @return Returns RAT_ERROR on error, RAT_OK otherwise
 */
int rat_mod_generic_set_val_max32 (const char *argv, uint8_t *data,
                                   uint16_t len)
{
    RAT_DEBUG_TRACE();

    if (!argv || !data || len < sizeof(uint32_t))
        return RAT_ERROR;

    *((uint32_t *) data) = UINT32_MAX;

    return RAT_OK;
}


/**
 * @brief Generic target for setting a time value (minutes and seconds)
 *
 * @param argv                  argument value
 * @param data                  data buffer in request
 * @param len                   data buffer length
 *
 * @return Returns RAT_ERROR on error, RAT_OK otherwise
 */
int rat_mod_generic_set_val_minsec16 (const char *argv, uint8_t *data,
                                      uint16_t len)
{
    uint64_t m = 0;
    uint64_t s = 0;
    uint64_t v;
    RAT_DEBUG_TRACE();

    if (!argv || !data || len < sizeof(uint16_t))
        return RAT_ERROR;

    sscanf(argv, "%" PRIu64 "m%" PRIu64 "s", &m, &s);
    v = (m * 60) + s;
    if (v > UINT16_MAX) {
        fprintf(stderr, "Warning: Value `%" PRIu64 "' out of range! " \
                "Limited to `%" PRIu16 "'!\n", v, UINT16_MAX);
        v = UINT16_MAX;
    }
    *((uint16_t *) data) = (uint16_t) v;

    return RAT_OK;
}

/**
 * @brief Generic target for setting a time value (hours, minutes and seconds)
 *
 * @param argv                  argument value
 * @param data                  data buffer in request
 * @param len                   data buffer length
 *
 * @return Returns RAT_ERROR on error, RAT_OK otherwise
 */
int rat_mod_generic_set_val_hminsec16 (const char *argv, uint8_t *data,
                                       uint16_t len)
{
    uint64_t h = 0;
    uint64_t m = 0;
    uint64_t s = 0;
    uint64_t v;
    RAT_DEBUG_TRACE();

    if (!argv || !data || len < sizeof(uint16_t))
        return RAT_ERROR;

    sscanf(argv, "%" PRIu64 "h%" PRIu64 "m%" PRIu64 "s", &h, &m, &s);
    v = (h * 60 * 60) + (m * 60) + s;
    if (v > UINT16_MAX) {
        fprintf(stderr, "Warning: Value `%" PRIu64 "' out of range! " \
                "Limited to `%" PRIu16 "'!\n", v, UINT16_MAX);
        v = UINT16_MAX;
    }
    *((uint16_t *) data) = (uint16_t) v;

    return RAT_OK;
}


/**
 * @brief Generic target for setting a time (hours, minutes, seconds and ms)
 *
 * @param argv                  argument value
 * @param data                  data buffer in request
 * @param len                   data buffer length
 *
 * @return Returns RAT_ERROR on error, RAT_OK otherwise
 */
int rat_mod_generic_set_val_hminsecms32 (const char *argv, uint8_t *data,
                                         uint16_t len)
{
    uint64_t h = 0;
    uint64_t m = 0;
    uint64_t s = 0;
    uint64_t ms = 0;
    uint64_t v;
    RAT_DEBUG_TRACE();

    if (!argv || !data || len < sizeof(uint32_t))
        return RAT_ERROR;

    sscanf(argv, "%" PRIu64 "h%" PRIu64 "m%" PRIu64 "s%" PRIu64 "ms",
           &h, &m, &s, &ms);
    v = (h * 60 * 60 * 1000) + (m * 60 * 1000) + (s * 1000) + ms;
    if (v > UINT32_MAX) {
        fprintf(stderr, "Warning: Value `%" PRIu64 "' out of range! " \
                "Limited to `%" PRIu32 "'!\n", v, UINT32_MAX);
        v = UINT32_MAX;
    }
    *((uint32_t *) data) = (uint32_t) v;

    return RAT_OK;
}


/**
 * @brief Generic target for setting a time (days, hours, minutes and seconds)
 *
 * @param argv                  argument value
 * @param data                  data buffer in request
 * @param len                   data buffer length
 *
 * @return Returns RAT_ERROR on error, RAT_OK otherwise
 */
int rat_mod_generic_set_val_dhminsec32 (const char *argv, uint8_t *data,
                                        uint16_t len)
{
    uint64_t d = 0;
    uint64_t h = 0;
    uint64_t m = 0;
    uint64_t s = 0;
    uint64_t v;
    RAT_DEBUG_TRACE();

    if (!argv || !data || len < sizeof(uint32_t))
        return RAT_ERROR;

    sscanf(argv, "%" PRIu64 "d%" PRIu64 "h%" PRIu64 "m%" PRIu64 "s",
           &d, &h, &m, &s);
    v = (d * 24 * 60 * 60) + (h * 60 * 60) + (m * 60) + s;
    if (v > UINT32_MAX) {
        fprintf(stderr, "Warning: Value `%" PRIu64 "' out of range! " \
                "Limited to `%" PRIu32 "'!\n", v, UINT32_MAX);
        v = UINT32_MAX;
    }
    *((uint32_t *) data) = (uint32_t) v;

    return RAT_OK;
}


/**
 * @brief Generic target for setting a flag to `on'
 *
 * @param argv                  argument value
 * @param data                  data buffer in request
 * @param len                   data buffer length
 *
 * @return Returns RAT_ERROR on error, RAT_OK otherwise
 */
static int rat_mod_generic_set_val_flag_on (const char *argv, uint8_t *data,
                                            uint16_t len)
{
    RAT_DEBUG_TRACE();

    if (!argv || !data || len < sizeof(int))
        return RAT_ERROR;

    *((int *) data) = 1;

    return RAT_OK;
}


/**
 * @brief Generic target for setting a flag to `off'
 *
 * @param argv                  argument value
 * @param data                  data buffer in request
 * @param len                   data buffer length
 *
 * @return Returns RAT_ERROR on error, RAT_OK otherwise
 */
static int rat_mod_generic_set_val_flag_off (const char *argv, uint8_t *data,
                                             uint16_t len)
{
    RAT_DEBUG_TRACE();

    if (!argv || !data || len < sizeof(int))
        return RAT_ERROR;

    *((int *) data) = 0;

    return RAT_OK;
}


/**
 * @brief Generic target array for setting a flag
 */
struct rat_mod_valreg rat_mod_generic_set_val_flag[] = {
    {
        .mvr_regex              = "^on$",
        .mvr_help               = "on",
        .mvr_parse              = rat_mod_generic_set_val_flag_on,
    },
    {
        .mvr_regex              = "^off?$",
        .mvr_help               = "off",
        .mvr_parse              = rat_mod_generic_set_val_flag_off,
    }
};


/* --- module registry functions -------------------------------------------- */


/** Module registry (linked list) */
struct rat_mod_modreg *rat_mod_registry = NULL;


/**
 * @brief Get module registration information by module id
 *
 * @param mid                   module id
 *
 * @return Returns module registration information, NULL on error
 */
static struct rat_mod_modreg *rat_mod_get_mmr (uint16_t mid)
{
    struct rat_mod_modreg *mmr;
    RAT_DEBUG_TRACE();

    for (mmr = rat_mod_registry; mmr; mmr = mmr->mmr_next)
        if (mmr->mmr_mid == mid)
            return mmr;

    return NULL;
}


/**
 * @brief Get set/add/del parameter registration information and length
 *
 * @param mid                   module id
 * @param aid                   action id
 * @param[out] msr              pointer to storage for parameter information
 * @param[out] len              pointer to storage for length
 *
 * @return Returns parameter registration information, NULL on error
 */
static int rat_mod_get_msr (uint16_t mid, uint16_t aid,
                            struct rat_mod_sadreg **msr, uint16_t *len)
{
    struct rat_mod_modreg *mmr;
    RAT_DEBUG_TRACE();

    mmr = rat_mod_get_mmr(mid);
    if (!mmr)
        goto exit_err;

    switch (aid) {
        case RAT_MOD_AID_SET:
            if (!mmr->mmr_set || !mmr->mmr_setlen)
                goto exit_err;
            if (msr)
                *msr = mmr->mmr_set;
            if (len)
                *len = mmr->mmr_setlen;
            break;
        case RAT_MOD_AID_ADD:
            if (!mmr->mmr_add || !mmr->mmr_addlen)
                goto exit_err;
            if (msr)
                *msr = mmr->mmr_add;
            if (len)
                *len = mmr->mmr_addlen;
            break;
        case RAT_MOD_AID_DEL:
            if (!mmr->mmr_del || !mmr->mmr_dellen)
                goto exit_err;
            if (msr)
                *msr = mmr->mmr_del;
            if (len)
                *len = mmr->mmr_dellen;
            break;
        default:
            goto exit_err;
            break;
    }

    return RAT_OK;

exit_err:
    return RAT_ERROR;
}


/**
 * @brief Get value registration information and length
 *
 * @param mid                   module id
 * @param aid                   action id
 * @param pid                   parameter id
 * @param[out] mvr              pointer to storage for parameter information
 * @param[out] len              pointer to storage for length
 *
 * @return Returns value registration information, NULL on error
 */
static int rat_mod_get_mvr (uint16_t mid, uint16_t aid, uint16_t pid,
                            struct rat_mod_valreg **mvr, uint16_t *len)
{
    struct rat_mod_sadreg *msr;
    uint16_t j;
    uint16_t i;
    RAT_DEBUG_TRACE();

    if (rat_mod_get_msr(mid, aid, &msr, &j) != RAT_OK)
        goto exit_err;

    for (i = 0; i < j; i++) {
        if (i == pid) {
            if (!msr->msr_val || !msr->msr_vallen)
                goto exit_err;
            if (mvr)
                *mvr = msr->msr_val;
            if (len)
                *len = msr->msr_vallen;
            break;
        }
        msr++;
    }

    return RAT_OK;

exit_err:
    return RAT_ERROR;
}


/**
 * @brief Get module name
 *
 * @param mid                   module id
 *
 * @return Returns name, NULL on error
 */
char *rat_mod_get_name (uint16_t mid)
{
    struct rat_mod_modreg *mmr;
    RAT_DEBUG_TRACE();

    mmr = rat_mod_get_mmr(mid);
    if (mmr)
        return mmr->mmr_name;

    return NULL;
}


/**
 * @brief Test for option index requirement
 *
 * @param mid                   module id
 *
 * @return Returns 1 if module requires option indexes, 0 otherwise
 */
int rat_mod_requires_oid (uint16_t mid)
{
    struct rat_mod_modreg *mmr;
    RAT_DEBUG_TRACE();

    mmr = rat_mod_get_mmr(mid);
    if (mmr && mmr->mmr_multiple)
        return 1;

    return 0;
}


/**
 * @brief Test for parameter id requirement
 *
 * @param mid                   module id
 * @param aid                   action id
 *
 * @return Returns 1 if module's action requires parameter id, 0 otherwise
 */
int rat_mod_requires_pid (uint16_t mid, uint16_t aid)
{
    RAT_DEBUG_TRACE();

    if (rat_mod_get_msr(mid, aid, NULL, NULL) == RAT_OK)
        return 1;

    return 0;
}


/**
 * @brief Test for value id requirement
 *
 * @param mid                   module id
 * @param aid                   action id
 * @param pid                   parameter id
 *
 * @return Returns 1 if module's parameter requires value id, 0 otherwise
 */
int rat_mod_requires_vid (uint16_t mid, uint16_t aid, uint16_t pid)
{
    RAT_DEBUG_TRACE();

    if (rat_mod_get_mvr(mid, aid, pid, NULL, NULL) == RAT_OK)
        return 1;

    return 0;
}


/**
 * @brief Count number of valid actions of a module
 *
 * @param mmr                   module registration information
 *
 * @return Returns the number of valid actions the module provides
 */
static uint16_t rat_mod_count_actions (struct rat_mod_modreg *mmr)
{
    uint16_t len = 0;
    RAT_DEBUG_TRACE();

    if (!mmr)
        goto exit;

    if (mmr->mmr_create)    len++;
    if (mmr->mmr_destroy)   len++;
    if (mmr->mmr_enable)    len++;
    if (mmr->mmr_disable)   len++;
    if (mmr->mmr_kill)      len++;
    if (mmr->mmr_show)      len++;
    if (mmr->mmr_dump)      len++;
    if (mmr->mmr_set)       len++;
    if (mmr->mmr_add)       len++;
    if (mmr->mmr_del)       len++;

exit:
    return len;
}


/**
 * @brief Register a module
 *
 * @param mmr                   module registration information
 *
 * @return Returns RAT_ERROR on error, RAT_OK otherwise
 */
int rat_mod_register (struct rat_mod_modreg *mmr)
{
    struct rat_mod_modreg *tmp;
    uint16_t i = 1;
    RAT_DEBUG_TRACE();

    if (!mmr)
        goto exit_err;

    /* reset next pointer */
    mmr->mmr_next = NULL;

    /* add new module to global modal registry */
    if (!rat_mod_registry) {
        mmr->mmr_mid = 0;
        rat_mod_registry = mmr;
    } else {
        for (tmp = rat_mod_registry; tmp->mmr_next; tmp = tmp->mmr_next)
            i++;
        mmr->mmr_mid = i;
        tmp->mmr_next = mmr;
    }

    return RAT_OK;

exit_err:
    return RAT_ERROR;
}


/**
 * @brief Leak module registry
 *
 * This is a special purpose function and must never be called by a module!
 *
 * @return Returns pointer to first module in registry
 */
extern struct rat_mod_modreg *rat_mod_leak_registry (void)
{
    return rat_mod_registry;
}


/* --- cli help functions --------------------------------------------------- */


/**
 * @brief Print module names
 *
 * @return Returns RAT_ERROR on error, RAT_OK otherwise
 */
int rat_mod_help_modules (void)
{
    struct rat_mod_modreg *mmr;
    uint_fast16_t i = 0;
    uint_fast16_t j = 0;
    RAT_DEBUG_TRACE();

    if (!rat_mod_registry)
        goto exit_err;

    /* get total number of registered modules */
    for (mmr = rat_mod_registry; mmr; mmr = mmr->mmr_next)
        j++;

    /* print help */
    fprintf(stderr, "Try ");
    for (mmr = rat_mod_registry; mmr; mmr = mmr->mmr_next) {
        if (i && i == (j - 1))
            fprintf(stderr, " or ");
        else if (i > 0)
            fprintf(stderr, ", ");
        fprintf(stderr, "`%s%s@eth0'", mmr->mmr_name,
                mmr->mmr_multiple ? "0" : "");
        i++;
    }
    fprintf(stderr, ".\n");

exit_err:
    return RAT_ERROR;
}


/**
 * @brief Print module names (for bash completion)
 */
void rat_mod_list_modules (void)
{
    struct rat_mod_modreg *mmr;

    for (mmr = rat_mod_registry; mmr; mmr = mmr->mmr_next)
        printf(" %s%s@ ", mmr->mmr_name, mmr->mmr_multiple ? "0" : "");

    return;
}


/**
 * @brief Print module actions
 *
 * For internal use only!
 *
 * @param help                  help string to print
 * @param i                     iterator
 * @param j                     iteration maximum
 */
static inline void __rat_mod_help_action (const char *help, uint16_t *i,
                                          uint16_t *j)
{
    RAT_DEBUG_TRACE();

    if (*i && *i == (*j - 1))
        fprintf(stderr, " or ");
    else if (*i)
        fprintf(stderr, ", ");
    fprintf(stderr, "`%s'", help);
    ++*i;
}


/**
 * @brief Print module actions
 *
 * @param mid                   module id
 *
 * @return Returns RAT_ERROR on error, RAT_OK otherwise
 */
int rat_mod_help_actions (uint16_t mid)
{
    struct rat_mod_modreg *mmr;
    uint16_t i = 0;
    uint16_t j;
    RAT_DEBUG_TRACE();

    mmr = rat_mod_get_mmr(mid);
    if (!mmr)
        return RAT_ERROR;

    j = rat_mod_count_actions(mmr);

    fprintf(stderr, "Try ");
    if (mmr->mmr_create)
        __rat_mod_help_action("create",  &i, &j);
    if (mmr->mmr_destroy)
        __rat_mod_help_action("destroy", &i, &j);
    if (mmr->mmr_enable)
        __rat_mod_help_action("enable",  &i, &j);
    if (mmr->mmr_disable)
        __rat_mod_help_action("disable", &i, &j);
    if (mmr->mmr_kill)
        __rat_mod_help_action("kill",    &i, &j);
    if (mmr->mmr_show)
        __rat_mod_help_action("show",    &i, &j);
    if (mmr->mmr_dump)
        __rat_mod_help_action("dump",    &i, &j);
    if (mmr->mmr_set)
        __rat_mod_help_action("set",     &i, &j);
    if (mmr->mmr_add)
        __rat_mod_help_action("add",     &i, &j);
    if (mmr->mmr_del)
        __rat_mod_help_action("del",     &i, &j);
    fprintf(stderr, ".\n");

    return RAT_OK;
}


/**
 * @brief Print module parameters
 *
 * @param mid                   module id
 * @param aid                   action id
 *
 * @return Returns RAT_ERROR on error, RAT_OK otherwise
 */
int rat_mod_help_parameters (uint16_t mid, uint16_t aid)
{
    struct rat_mod_sadreg *msr;
    uint16_t j;
    uint16_t i;
    RAT_DEBUG_TRACE();

    if (rat_mod_get_msr(mid, aid, &msr, &j) != RAT_OK)
        return RAT_ERROR;

    fprintf(stderr, "Try ");
    for (i = 0; i < j; i++) {
        if (i && i == (j - 1))
            fprintf(stderr, " or ");
        else if (i)
            fprintf(stderr, ", ");
        fprintf(stderr, "`%s'", msr->msr_help);
        msr++;
    }
    fprintf(stderr, ".\n");

    return RAT_OK;
}


/**
 * @brief Print module values
 *
 * @param mid                   module id
 * @param aid                   action id
 * @param pid                   parameters id
 *
 * @return Returns RAT_ERROR on error, RAT_OK otherwise
 */
int rat_mod_help_values (uint16_t mid, uint16_t aid, uint16_t pid)
{
    struct rat_mod_valreg *mvr;
    uint16_t j;
    uint16_t i;
    RAT_DEBUG_TRACE();

    if (rat_mod_get_mvr(mid, aid, pid, &mvr, &j) != RAT_OK)
        return RAT_ERROR;

    fprintf(stderr, "Try ");
    for (i = 0; i < j; i++) {
        if (i && i == (j - 1))
            fprintf(stderr, " or ");
        else if (i)
            fprintf(stderr, ", ");
        fprintf(stderr, "`%s'", mvr->mvr_help);
        mvr++;
    }
    fprintf(stderr, ".\n");

    return RAT_OK;
}


/* --- parse and call functions --------------------------------------------- */


/**
 * @brief Parse module name
 *
 * @param str                   string to test module name regexes against
 * @param[out] mid              module id
 *
 * @return Returns RAT_ERROR on error, RAT_OK otherwise
 */
int rat_mod_parse_module (const char *str, uint16_t *mid)
{
    struct rat_mod_modreg *mmr;
    RAT_DEBUG_TRACE();

    if (!str || !mid)
        goto exit_err;

    for (mmr = rat_mod_registry; mmr; mmr = mmr->mmr_next) {
        if (rat_lib_regex_match(mmr->mmr_regex, str) == RAT_OK) {
            *mid = mmr->mmr_mid;
            return RAT_OK;
        }
    }

exit_err:
    return RAT_ERROR;
}


/**
 * @brief Parse module action
 *
 * @param mid                   module id
 * @param str                   string to test module action regexes against
 * @param[out] aid              action id
 *
 * @return Returns RAT_ERROR on error, RAT_OK otherwise
 */
int rat_mod_parse_action (uint16_t mid, const char *str, uint16_t *aid)
{
    struct rat_mod_modreg *mmr;
    RAT_DEBUG_TRACE();

    mmr = rat_mod_get_mmr(mid);
    if (!str || !aid || !mmr)
        goto exit_err;

    if (mmr->mmr_create &&
        rat_lib_regex_match(RAT_MOD_ACT_RGX_CREATE, str) == RAT_OK) {
        *aid = RAT_MOD_AID_CREATE;
    } else if (mmr->mmr_destroy &&
        rat_lib_regex_match(RAT_MOD_ACT_RGX_DESTROY, str) == RAT_OK) {
        *aid = RAT_MOD_AID_DESTROY;
    } else if (mmr->mmr_enable &&
        rat_lib_regex_match(RAT_MOD_ACT_RGX_ENABLE, str) == RAT_OK) {
        *aid = RAT_MOD_AID_ENABLE;
    } else if (mmr->mmr_disable &&
        rat_lib_regex_match(RAT_MOD_ACT_RGX_DISABLE, str) == RAT_OK) {
        *aid = RAT_MOD_AID_DISABLE;
    } else if (mmr->mmr_kill &&
        rat_lib_regex_match(RAT_MOD_ACT_RGX_KILL, str) == RAT_OK) {
        *aid = RAT_MOD_AID_KILL;
    } else if (mmr->mmr_show &&
        rat_lib_regex_match(RAT_MOD_ACT_RGX_SHOW, str) == RAT_OK) {
        *aid = RAT_MOD_AID_SHOW;
    } else if (mmr->mmr_dump &&
        rat_lib_regex_match(RAT_MOD_ACT_RGX_DUMP, str) == RAT_OK) {
        *aid = RAT_MOD_AID_DUMP;
    } else if (mmr->mmr_set &&
        rat_lib_regex_match(RAT_MOD_ACT_RGX_SET, str) == RAT_OK) {
        *aid = RAT_MOD_AID_SET;
    } else if (mmr->mmr_add &&
        rat_lib_regex_match(RAT_MOD_ACT_RGX_ADD, str) == RAT_OK) {
        *aid = RAT_MOD_AID_ADD;
    } else if (mmr->mmr_del &&
        rat_lib_regex_match(RAT_MOD_ACT_RGX_DEL, str) == RAT_OK) {
        *aid = RAT_MOD_AID_DEL;
    } else {
        goto exit_err;
    }

    return RAT_OK;

exit_err:
    return RAT_ERROR;
}


/**
 * @brief Parse module parameter
 *
 * @param mid                   module id
 * @param aid                   action id
 * @param str                   string to test module parameter regexes against
 * @param[out] pid              parameter id
 *
 * @return Returns RAT_ERROR on error, RAT_OK otherwise
 */
int rat_mod_parse_parameter (uint16_t mid, uint16_t aid, const char *str,
                             uint16_t *pid)
{
    struct rat_mod_sadreg *msr;
    uint16_t j;
    uint16_t i;
    RAT_DEBUG_TRACE();

    if (rat_mod_get_msr(mid, aid, &msr, &j) != RAT_OK)
        goto exit_err;

    for (i = 0; i < j; i++) {
        if (rat_lib_regex_match(msr->msr_regex, str) == RAT_OK) {
            *pid = i;
            return RAT_OK;
        }
        msr++;
    }

exit_err:
    return RAT_ERROR;
}


/**
 * @brief Parse module value
 *
 * @param mid                   module id
 * @param aid                   action id
 * @param pid                   parameter id
 * @param str                   string to test module value regexes against
 * @param[out] vid              value id
 *
 * @return Returns RAT_ERROR on error, RAT_OK otherwise
 */
int rat_mod_parse_value (uint16_t mid, uint16_t aid, uint16_t pid,
                         const char *str, uint16_t *vid)
{
    struct rat_mod_valreg *mvr;
    uint16_t j;
    uint16_t i;
    RAT_DEBUG_TRACE();

    if (rat_mod_get_mvr(mid, aid, pid, &mvr, &j) != RAT_OK)
        goto exit_err;

    for (i = 0; i < j; i++) {
        if (rat_lib_regex_match(mvr->mvr_regex, str) == RAT_OK) {
            *vid = i;
            return RAT_OK;
        }
        mvr++;
    }

exit_err:
    return RAT_ERROR;
}


/* --- function calls ------------------------------------------------------- */


/**
 * @brief Call a value parsing target
 *
 * @param mid                   module id
 * @param aid                   action id
 * @param pid                   parameter id
 * @param vid                   value id
 * @param argv                  CLI value argument
 * @param[out] data             request message data
 * @param len                   request message data length
 *
 * @return Returns RAT_ERROR on error, RAT_OK otherwise
 */
int rat_mod_cli_call_vid (uint16_t mid, uint16_t aid, uint16_t pid,
                          uint16_t vid, const char *argv, uint8_t *data,
                          uint16_t len)
{
    struct rat_mod_valreg *mvr;
    uint16_t j;
    uint16_t i;
    RAT_DEBUG_TRACE();

    if (rat_mod_get_mvr(mid, aid, pid, &mvr, &j) != RAT_OK)
        goto exit_err;

    for (i = 0; i < j; i++) {
        if (i == vid)
            return mvr->mvr_parse(argv, data, len);
        mvr++;
    }

exit_err:
    return RAT_ERROR;
}


/**
 * @brief Call a module action function
 *
 * @param mf                    helper functions
 * @param mi                    instance information
 * @param mid                   module id
 * @param aid                   action id
 *
 * @return Returns RAT_ERROR on error, RAT_OK otherwise
 */
int rat_mod_rad_call_aid (struct rat_mod_functions *mf,
                          struct rat_mod_instance *mi,
                          uint16_t mid, uint16_t aid)
{
    struct rat_mod_modreg *mmr;
    RAT_DEBUG_TRACE();

    mmr = rat_mod_get_mmr(mid);
    if (!mmr)
        goto exit_err;

    switch (aid) {
        case RAT_MOD_AID_CREATE:
            if (mmr->mmr_create)
                return mmr->mmr_create(mf, mi);
            break;
        case RAT_MOD_AID_DESTROY:
            if (mmr->mmr_destroy)
                return mmr->mmr_destroy(mf, mi);
            break;
        case RAT_MOD_AID_ENABLE:
            if (mmr->mmr_enable)
                return mmr->mmr_enable(mf, mi);
            break;
        case RAT_MOD_AID_DISABLE:
            if (mmr->mmr_disable)
                return mmr->mmr_disable(mf, mi);
            break;
        case RAT_MOD_AID_KILL:
            if (mmr->mmr_kill)
                return mmr->mmr_kill(mf, mi);
            break;
        case RAT_MOD_AID_SHOW:
            if (mmr->mmr_show)
                return mmr->mmr_show(mf, mi);
            break;
        case RAT_MOD_AID_DUMP:
            if (mmr->mmr_dump)
                return mmr->mmr_dump(mf, mi);
            break;
        default:
            break;
    }

exit_err:
    return RAT_ERROR;
}


/**
 * @brief Call a module parameter function
 *
 * @param mf                    helper functions
 * @param mi                    instance information
 * @param mid                   module id
 * @param aid                   action id
 * @param pid                   parameter id
 * @param pvdata                data as parsed by the values parser function
 * @param pvlen                 maximum length of parsed data
 *
 * @return Returns RAT_ERROR on error, RAT_OK otherwise
 */
int rat_mod_rad_call_pid (struct rat_mod_functions *mf,
                          struct rat_mod_instance *mi,
                          uint16_t mid, uint16_t aid, uint16_t pid,
                          uint8_t *pvdata, uint16_t pvlen)
{
    struct rat_mod_sadreg *msr;
    uint16_t i;
    uint16_t j;
    RAT_DEBUG_TRACE();

    if (rat_mod_get_msr(mid, aid, &msr, &j) != RAT_OK)
        goto exit_err;

    for (i = 0; i < j; i++) {
        if (i == pid) {
            if (!msr->msr_func)
                goto exit_err;
            return msr->msr_func(mf, mi, pvdata, pvlen);
        }
        msr++;
    }

exit_err:
    return RAT_ERROR;
}


/**
 * @brief Call a modules registered compile() function
 *
 * @param mi                    instance information
 * @param mid                   module id
 *
 * @return Returns RAT_ERROR on error, RAT_OK otherwise
 */
int rat_mod_rad_call_compile (struct rat_mod_instance *mi, uint16_t mid)
{
    struct rat_mod_modreg *mmr;
    RAT_DEBUG_TRACE();

    mmr = rat_mod_get_mmr(mid);
    if (!mmr)
        goto exit_err;

    if (mmr->mmr_compile)
        return mmr->mmr_compile(mi);

exit_err:
    return RAT_ERROR;
}


/* --- module interception -------------------------------------------------- */


/**
 * @brief Intercept a parameter function
 *
 * @param mid                   module id
 * @param mstr                  module name to intercept
 * @param aid                   action id
 * @param astr                  action name to intercept
 * @param pid                   parameter id
 * @param pstr                  parameter name to intercept
 *
 * @return Returns RAT_ERROR on error, RAT_OK otherwise
 */
int rat_mod_icpt_pid (uint16_t mid, const char *mstr,
                      uint16_t aid, const char *astr,
                      uint16_t pid, const char *pstr)
{
    uint16_t icptmid;
    uint16_t icptaid;
    uint16_t icptpid;
    RAT_DEBUG_TRACE();

    if (rat_mod_parse_module(mstr, &icptmid) == RAT_OK &&
        rat_mod_parse_action(icptmid, astr, &icptaid) == RAT_OK &&
        rat_mod_parse_parameter(icptmid, icptaid, pstr, &icptpid) == RAT_OK &&
        mid == icptmid &&
        aid == icptaid &&
        pid == icptpid)
            return RAT_OK;

    return RAT_ERROR;
}


/**
 * @brief Intercept an action function
 *
 * @param mid                   module id
 * @param mstr                  module name to intercept
 * @param aid                   action id
 * @param astr                  action name to intercept
 *
 * @return Returns RAT_ERROR on error, RAT_OK otherwise
 */
int rat_mod_icpt_aid (uint16_t mid, const char *mstr,
                      uint16_t aid, const char *astr)
{
    uint16_t icptmid;
    uint16_t icptaid;
    RAT_DEBUG_TRACE();

    if (rat_mod_parse_module(mstr, &icptmid) == RAT_OK &&
        rat_mod_parse_action(icptmid, astr, &icptaid) == RAT_OK &&
        mid == icptmid &&
        aid == icptaid)
            return RAT_OK;

    return RAT_ERROR;
}


/**
 * @brief Intercept a module
 *
 * @param mid                   module id
 * @param mstr                  module name to intercept
 *
 * @return Returns RAT_ERROR on error, RAT_OK otherwise
 */
int rat_mod_icpt_mid (uint16_t mid, const char *mstr)
{
    uint16_t icptmid;
    RAT_DEBUG_TRACE();

    if (rat_mod_parse_module(mstr, &icptmid) == RAT_OK &&
        mid == icptmid)
            return RAT_OK;

    return RAT_ERROR;
}
