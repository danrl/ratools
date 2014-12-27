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


#include "database.h"

#include "log.h"

#include <stdlib.h>             /* calloc() */
#include <stddef.h>             /* offsetof() */
#include <inttypes.h>           /* PRIu8 and friends */
#include <stdio.h>              /* PRIu8 and friends */
#include <pthread.h>
#include <net/if.h>             /* if_indextoname() */


/* --- globals -------------------------------------------------------------- */


/** database as linked lists */
static struct rat_db *rat_db_list = NULL;

/** global database read/write lock */
static pthread_rwlock_t rat_db_lock = PTHREAD_RWLOCK_INITIALIZER;


#ifdef RAT_DEBUG
/** Global lock count for debugging purposes. */
static int rat_db_debug_lockcount = 0;
#endif /* RAT_DEBUG */


/** Centralized locking and unlocking */
/** @{ */
#define RAT_DB_READLOCK()                                                   \
    do {                                                                    \
        RAT_DEBUG_MESSAGE("Readlock: before=%d", rat_db_debug_lockcount);   \
        pthread_rwlock_rdlock(&rat_db_lock);                                \
        RAT_DEBUG_MESSAGE("Readlock: after=%d", ++rat_db_debug_lockcount);  \
    } while (0)
#define RAT_DB_WRITELOCK()                                                  \
    do {                                                                    \
        RAT_DEBUG_MESSAGE("Writelock: before=%d", rat_db_debug_lockcount);  \
        pthread_rwlock_wrlock(&rat_db_lock);                                \
        RAT_DEBUG_MESSAGE("Writelock: after=%d", ++rat_db_debug_lockcount); \
    } while (0)
#define RAT_DB_UNLOCK()                                                     \
    do {                                                                    \
        RAT_DEBUG_MESSAGE("Unlock: before=%d", rat_db_debug_lockcount);     \
        pthread_rwlock_rdlock(&rat_db_lock);                                \
        RAT_DEBUG_MESSAGE("Unlock: after=%d", --rat_db_debug_lockcount);    \
    } while (0)
/** @} */


#define RAT_DB_UPDATE(db)                                                   \
    do {                                                                    \
        db->db_version++;                                                   \
        db->db_updated = time(NULL);                                        \
    } while (0)


/* --- functions ------------------------------------------------------------ */




/**
 * @brief Find database element by index number without
 *
 * @param ifindex               interface index number
 *
 *         /'\
 *        /   \      Caution!
 *       /  |  \     --------
 *      /   o   \    Caller must hold AT LEAST a READ LOCK on rat_db_lock!
 *     '_________'
 *
 * @return Returns database entry, NULL on error
 */
static struct rat_db *rat_db_find (uint32_t ifindex)
{
    struct rat_db *db;
    RAT_DEBUG_TRACE();

    for (db = rat_db_list; db; db = db->db_next)
        if (db->db_ifindex == ifindex)
            return db;

    return NULL;
}


/**
 * Create a database entry for an interface
 * @param ifindex               interface index number
 *
 * @return Returns RAT_ERROR on error, RAT_OK otherwise
 */
int rat_db_create (uint32_t ifindex)
{
    struct rat_db *db, *cur;
    RAT_DEBUG_TRACE();

    if (!ifindex)
        goto exit_err;

    RAT_DB_WRITELOCK();                                            /* LOCK DB */
    /* check for duplicate index */
    if (rat_db_find(ifindex))
        goto exit_err_unlock;

    /* allocate space */
    db = calloc(1, sizeof(*db));
    if (!db)
        goto exit_err_unlock;

    /* init db item */
    db->db_ifindex = ifindex;
    db->db_ifstate = RAT_DB_IFSTATE_DOWN;
    db->db_state = RAT_DB_STATE_DISABLED;
    db->db_compiled = 0;
    db->db_version = 1;

    /* add item to database */
    if (!rat_db_list) {
        /* list is empty */
        rat_db_list = db;
    } else {
        /* list is not empty, append */
        for (cur = rat_db_list; cur->db_next; cur = cur->db_next);
        cur->db_next = db;
    }

    RAT_DB_UNLOCK();                                             /* UNLOCK DB */
    return RAT_OK;


exit_err_unlock:
    RAT_DB_UNLOCK();                                             /* UNLOCK DB */
exit_err:
    return RAT_ERROR;
}


/**
 * Destroy a database entry for an interface
 * @param ifindex               interface index number
 *
 * @return Returns RAT_ERROR on error, RAT_OK otherwise
 */
int rat_db_destroy (uint32_t ifindex)
{
    struct rat_db *db, *pre, *cur;
    RAT_DEBUG_TRACE();

    RAT_DB_WRITELOCK();                                            /* LOCK DB */

    /* container of */
    db = rat_db_find(ifindex);
    if (!db)
        goto exit_err_unlock;

    /* remove interface from database */
    if (rat_db_list == db) {
        /* interface is first element in list */
        rat_db_list = db->db_next;
    } else {
        /* interface is not the first element in list */
        pre = rat_db_list;
        for (cur = pre->db_next; cur; cur = cur->db_next) {
            if (cur == db) {
                pre->db_next = cur->db_next;
                break;
            }
            pre = cur;
        }
    }

    RAT_DB_UNLOCK();                                             /* UNLOCK DB */

    /* free space */
    free(db);

    return RAT_OK;

exit_err_unlock:
    RAT_DB_UNLOCK();                                             /* UNLOCK DB */
    return RAT_ERROR;
}


/**
 * @page database1 Grab and Release
 *
 * All interfaces that have configured RAs are stored in a database. Alongside
 * with an interface are stored RA private data, all module private data for the
 * specific interface and various information fetched and regularly updated by
 * netlink. There are a lot of threads that like to read from or write to these
 * entries during operation. To avoid race conditions, dead locks and other bad
 * things, threads can grab an database entry (read: an interfaces
 * configuration) exclusively. The thread then has teh right do read from or
 * write to the database entry. It must release the database entry as soon as
 * possible to allow other (waiting) threads to also access the data.
 *
 * This is why we have `rat_db_grab()' and `rat_db_release()'.
 */



/**
 * @brief Reset running database entry to fade-in state
 *
 * Call this function if fundamental interface configuration changes have
 * applied that require hosts in the network to catch up with them. E.g.
 * mtu changes of the interface.
 *
 * @param db                    database entry
 */
int rat_db_set_state_refadein (uint32_t ifindex)
{
    struct rat_db *db;
    RAT_DEBUG_TRACE();

    RAT_DB_WRITELOCK();                                            /* LOCK DB */
    db = rat_db_find(ifindex);
    if (!db)
        goto exit_err_unlock;
    switch (db->db_state) {
        case RAT_DB_STATE_FADEIN2:
        case RAT_DB_STATE_FADEIN3:
        case RAT_DB_STATE_ENABLED:
            db->db_state = RAT_DB_STATE_FADEIN1;
            break;
        default:
            break;
    }
    RAT_DB_UPDATE(db);
    RAT_DB_UNLOCK();                                             /* UNLOCK DB */

    return RAT_OK;

exit_err_unlock:
    RAT_DB_UNLOCK();                                             /* UNLOCK DB */
    return RAT_ERROR;
}


/**
 * Print debug information for given option
 * @param opt                   option
 */
void rat_db_debug_opt (struct rat_db_opt *opt)
{
    RAT_DEBUG_TRACE();

    if (!opt)
        return;

    RAT_DEBUG_MESSAGE("next=%p\n", (void *) opt->opt_next);
    RAT_DEBUG_MESSAGE("mid=%" PRIu16 "\n", opt->opt_mid);
    RAT_DEBUG_MESSAGE("oid=%" PRIu16 "\n", opt->opt_oid);
    RAT_DEBUG_MESSAGE("private=%p\n", (void *) opt->opt_private);
    RAT_DEBUG_MESSAGE("rawdata=%p\n", (void *) opt->opt_rawdata);
    RAT_DEBUG_MESSAGE("rawlen=%" PRIu16 "\n", opt->opt_rawlen);

    return;
}


/**
 * Get an option from a database entry
 * @param db                    database entry
 * @param mid                   module id of requested option
 * @param oid                   option index of requested option
 *
 * @return Returns option, NULL on error
 */
struct rat_db_opt *rat_db_get_opt (struct rat_db *db, uint16_t mid,
                                   uint16_t oid)
{
    struct rat_db_opt *opt;
    RAT_DEBUG_TRACE();

    if (!db)
        goto exit_err;

    for (opt = db->db_opt; opt; opt = opt->opt_next)
        if (opt->opt_mid == mid && opt->opt_oid == oid)
            return opt;

exit_err:
    return NULL;
}


/**
 * Add an option to a database entry
 * @param db                    database entry
 * @param mid                   module id of requested option
 * @param oid                   option index of requested option
 *
 * @return Returns new option, NULL on error
 */
struct rat_db_opt *rat_db_add_opt (struct rat_db *db, uint16_t mid,
                                   uint16_t oid)
{
    struct rat_db_opt *opt, *cur;
    RAT_DEBUG_TRACE();

    if (!db)
        goto exit_err;

    /* check for existence */
    opt = rat_db_get_opt(db, mid, oid);
    if (opt)
        goto exit_err;

    opt = calloc(1, sizeof(*opt));
    if (!opt)
        goto exit_err;

    /* initialze option data */
    opt->opt_next = NULL;
    opt->opt_mid = mid;
    opt->opt_oid = oid;
    opt->opt_private = NULL;
    opt->opt_rawdata = NULL;
    opt->opt_rawlen = 0;

    if (db->db_opt) {
        for (cur = db->db_opt; cur->opt_next; cur = cur->opt_next);
        cur->opt_next = opt;
    } else {
        db->db_opt = opt;
    }

    return opt;

exit_err:
    return NULL;
}


/**
 * Delete an option from a database entry
 * @param db                    database entry
 * @param mid                   module id of requested option
 * @param oid                   option index of requested option
 *
 * @return Returns RAT_ERROR on error, RAT_OK otherwise
 */
int rat_db_del_opt (struct rat_db *db, uint16_t mid, uint16_t oid)
{
    struct rat_db_opt *opt, *cur;
    RAT_DEBUG_TRACE();

    if (!db)
        goto exit_err;

    /* get option */
    opt = rat_db_get_opt(db, mid, oid);
    if (!opt)
        goto exit_err;

    /* remove from list */
    if (db->db_opt == opt) {
        db->db_opt = opt->opt_next;
    } else {
        for (cur = db->db_opt; cur; cur = cur->opt_next) {
            if (cur->opt_next == opt) {
                cur->opt_next = opt->opt_next;
                break;
            }
        }
    }

    /* free option */
    if (opt->opt_private)
        free(opt->opt_private);
    if (opt->opt_rawdata)
        free(opt->opt_rawdata);
    free(opt);

    return RAT_OK;

exit_err:
    return RAT_ERROR;
}





















enum rat_db_ifstate rat_db_get_ifstate (uint32_t ifindex)
{
    struct rat_db *db;
    enum rat_db_ifstate ifstate = RAT_DB_IFSTATE_DOWN;

    RAT_DB_READLOCK();                                             /* LOCK DB */
    db = rat_db_find(ifindex);
    if (db)
        ifstate = db->db_ifstate;
    RAT_DB_UNLOCK();                                             /* UNLOCK DB */

    return ifstate;
}


int rat_db_set_ifstate (uint32_t ifindex, enum rat_db_ifstate ifstate)
{
    struct rat_db *db;

    RAT_DB_WRITELOCK();                                            /* LOCK DB */
    db = rat_db_find(ifindex);
    if (!db)
        goto exit_err_unlock;
    db->db_ifstate = ifstate;
    RAT_DB_UPDATE(db);
    RAT_DB_UNLOCK();                                             /* UNLOCK DB */

    return RAT_OK;

exit_err_unlock:
    RAT_DB_UNLOCK();                                             /* UNLOCK DB */
    return RAT_ERROR;
}




int rat_db_get_ifname (uint32_t ifindex, char *ifname, size_t len)
{
    struct rat_db *db;

    RAT_DB_READLOCK();                                             /* LOCK DB */
    db = rat_db_find(ifindex);
    if (!db)
        goto exit_err_unlock;

    memset(ifname, 0x0, len);
    strncpy(ifname, db->db_ifname, len - 1);
    RAT_DB_UNLOCK();                                             /* UNLOCK DB */

    return RAT_OK;

exit_err_unlock:
    RAT_DB_UNLOCK();                                             /* UNLOCK DB */
    return RAT_ERROR;
}


int rat_db_set_ifname (uint32_t ifindex, char *ifname)
{
    struct rat_db *db;

    RAT_DB_WRITELOCK();                                            /* LOCK DB */
    db = rat_db_find(ifindex);
    if (!db)
        goto exit_err_unlock;
    memset(db->db_ifname, 0x0, sizeof(db->db_ifname));
    strncpy(db->db_ifname, ifname, sizeof(db->db_ifname) - 1);
    RAT_DB_UPDATE(db);
    RAT_DB_UNLOCK();                                             /* UNLOCK DB */

    return RAT_OK;

exit_err_unlock:
    RAT_DB_UNLOCK();                                             /* UNLOCK DB */
    return RAT_ERROR;
}







uint32_t rat_db_get_mtu (uint32_t ifindex)
{
    struct rat_db *db;
    uint32_t mtu = 0;

    RAT_DB_READLOCK();                                             /* LOCK DB */
    db = rat_db_find(ifindex);
    if (db)
        mtu = db->db_mtu;
    RAT_DB_UNLOCK();                                             /* UNLOCK DB */

    return mtu;
}

int rat_db_set_mtu (uint32_t ifindex, uint32_t mtu)
{
    struct rat_db *db;

    RAT_DB_WRITELOCK();                                            /* LOCK DB */
    db = rat_db_find(ifindex);
    if (!db)
        goto exit_err_unlock;
    db->db_mtu = mtu;
    RAT_DB_UPDATE(db);
    RAT_DB_UNLOCK();                                             /* UNLOCK DB */

    return RAT_OK;

exit_err_unlock:
    RAT_DB_UNLOCK();                                             /* UNLOCK DB */
    return RAT_ERROR;
}







int rat_db_get_hwaddr (uint32_t ifindex, struct rat_hwaddr *hwa)
{
    struct rat_db *db;

    RAT_DB_READLOCK();                                             /* LOCK DB */
    db = rat_db_find(ifindex);
    if (!db)
        goto exit_err_unlock;
    memcpy(hwa, &db->db_hwaddr, sizeof(struct rat_hwaddr));
    RAT_DB_UNLOCK();                                             /* UNLOCK DB */

    return RAT_OK;

exit_err_unlock:
    RAT_DB_UNLOCK();                                             /* UNLOCK DB */
    return RAT_ERROR;
}


int rat_db_set_hwaddr (uint32_t ifindex, struct rat_hwaddr *hwa)
{
    struct rat_db *db;

    RAT_DB_WRITELOCK();                                            /* LOCK DB */
    db = rat_db_find(ifindex);
    if (!db)
        goto exit_err_unlock;
    memcpy(&db->db_hwaddr, hwa, sizeof(db->db_hwaddr));
    RAT_DB_UPDATE(db);
    RAT_DB_UNLOCK();                                             /* UNLOCK DB */

    return RAT_OK;

exit_err_unlock:
    RAT_DB_UNLOCK();                                             /* UNLOCK DB */
    return RAT_ERROR;
}


int rat_db_get_lladdr (uint32_t ifindex, struct in6_addr *lladdr)
{
    struct rat_db *db;

    RAT_DB_READLOCK();                                             /* LOCK DB */
    db = rat_db_find(ifindex);
    if (!db)
        goto exit_err_unlock;
    memcpy(lladdr, &db->db_lladdr, sizeof(struct in6_addr));
    RAT_DB_UNLOCK();                                             /* UNLOCK DB */

    return RAT_OK;

exit_err_unlock:
    RAT_DB_UNLOCK();                                             /* UNLOCK DB */
    return RAT_ERROR;
}


int rat_db_set_lladdr (uint32_t ifindex, struct in6_addr *lladdr)
{
    struct rat_db *db;

    RAT_DB_WRITELOCK();                                            /* LOCK DB */
    db = rat_db_find(ifindex);
    if (!db)
        goto exit_err_unlock;
    memcpy(&db->db_lladdr, lladdr, sizeof(db->db_lladdr));
    RAT_DB_UPDATE(db);
    RAT_DB_UNLOCK();                                             /* UNLOCK DB */

    return RAT_OK;

exit_err_unlock:
    RAT_DB_UNLOCK();                                             /* UNLOCK DB */
    return RAT_ERROR;
}



enum rat_db_state rat_db_get_state (uint32_t ifindex)
{
    struct rat_db *db;
    enum rat_db_state state = RAT_DB_STATE_DESTROYED;

    RAT_DB_READLOCK();                                             /* LOCK DB */
    db = rat_db_find(ifindex);
    if (db)
        state = db->db_state;
    RAT_DB_UNLOCK();                                             /* UNLOCK DB */

    return state;
}


int rat_db_set_state (uint32_t ifindex, enum rat_db_state state)
{
    struct rat_db *db;

    RAT_DB_WRITELOCK();                                            /* LOCK DB */
    db = rat_db_find(ifindex);
    if (!db)
        goto exit_err_unlock;
    db->db_state = state;
    RAT_DB_UPDATE(db);
    RAT_DB_UNLOCK();                                             /* UNLOCK DB */

    return RAT_OK;

exit_err_unlock:
    RAT_DB_UNLOCK();                                             /* UNLOCK DB */
    return RAT_ERROR;
}



useconds_t rat_db_get_delay (uint32_t ifindex)
{
    struct rat_db *db;
    useconds_t delay = 0;

    RAT_DB_READLOCK();                                             /* LOCK DB */
    db = rat_db_find(ifindex);
    if (db)
        delay = db->db_delay;
    RAT_DB_UNLOCK();                                             /* UNLOCK DB */

    return delay;
}

int rat_db_set_delay (uint32_t ifindex, useconds_t delay)
{
    struct rat_db *db;

    RAT_DB_WRITELOCK();                                            /* LOCK DB */
    db = rat_db_find(ifindex);
    if (!db)
        goto exit_err_unlock;
    db->db_delay = delay;
    RAT_DB_UPDATE(db);
    RAT_DB_UNLOCK();                                             /* UNLOCK DB */

    return RAT_OK;

exit_err_unlock:
    RAT_DB_UNLOCK();                                             /* UNLOCK DB */
    return RAT_ERROR;
}


void rat_db_get_ra_private (uint32_t ifindex, void *private)
{
    struct rat_db *db;

    private = NULL;

    RAT_DB_READLOCK();                                             /* LOCK DB */
    db = rat_db_find(ifindex);
    if (db)
        private = db->db_ra_private;
    RAT_DB_UNLOCK();                                             /* UNLOCK DB */

    return;
}


void rat_db_get_ra_rawdata (uint32_t ifindex, void *rawdata, uint16_t *rawlen)
{
    struct rat_db *db;

    rawdata = NULL;
    *rawlen = 0;

    RAT_DB_READLOCK();                                             /* LOCK DB */
    db = rat_db_find(ifindex);
    if (db) {
        rawdata = db->db_ra_rawdata;
        rawlen = &db->db_ra_rawlen;
    }
    RAT_DB_UNLOCK();                                             /* UNLOCK DB */

    return;
}

static uint32_t __rat_db_get_advint (uint32_t ifindex, int max)
{
    struct rat_db *db;
    uint32_t advint = 0;

    RAT_DB_READLOCK();                                             /* LOCK DB */
    db = rat_db_find(ifindex);
    if (db) {
        if (max)
            advint = db->db_maxadvint;
        else
            advint = db->db_minadvint;
    }
    RAT_DB_UNLOCK();                                             /* UNLOCK DB */

    return advint;
}

uint32_t rat_db_get_maxadvint (uint32_t ifindex)
{
    return __rat_db_get_advint(ifindex, 1);
}

uint32_t rat_db_get_minadvint (uint32_t ifindex)
{
    return __rat_db_get_advint(ifindex, 0);
}

static int __rat_db_set_advint (uint32_t ifindex, uint32_t advint, int max)
{
    struct rat_db *db;

    RAT_DB_WRITELOCK();                                            /* LOCK DB */
    db = rat_db_find(ifindex);
    if (!db)
        goto exit_err_unlock;
    if (max)
        db->db_maxadvint = advint;
    else
        db->db_minadvint = advint;
    RAT_DB_UPDATE(db);
    RAT_DB_UNLOCK();                                             /* UNLOCK DB */

    return RAT_OK;

exit_err_unlock:
    RAT_DB_UNLOCK();                                             /* UNLOCK DB */
    return RAT_ERROR;
}

int rat_db_set_maxadvint (uint32_t ifindex, uint32_t advint)
{
    return __rat_db_set_advint(ifindex, advint, 1);
}

int rat_db_set_minadvint (uint32_t ifindex, uint32_t advint)
{
    return __rat_db_set_advint(ifindex, advint, 0);
}




int rat_db_signal_worker (uint32_t ifindex)
{
    struct rat_db *db;

    RAT_DB_WRITELOCK();                                            /* LOCK DB */
    db = rat_db_find(ifindex);
    if (!db)
        goto exit_err_unlock;
    pthread_cond_signal(&db->db_worker_cond);
    RAT_DB_UNLOCK();                                             /* UNLOCK DB */

    return RAT_OK;

exit_err_unlock:
    RAT_DB_UNLOCK();                                             /* UNLOCK DB */
    return RAT_ERROR;
}


int rat_db_exists (uint32_t ifindex)
{
    int ret = 0;

    RAT_DB_READLOCK();                                             /* LOCK DB */
    if (rat_db_find(ifindex))
        ret = 1;
    RAT_DB_UNLOCK();                                             /* UNLOCK DB */

    return ret;
}

int rat_db_is_compiled (uint32_t ifindex)
{
    int ret = 0;
    struct rat_db *db;

    RAT_DB_READLOCK();
    db = rat_db_find(ifindex);
    if (db && db->db_compiled == db->db_version)
        ret = 1;
    RAT_DB_UNLOCK();

    return ret;
}

int rat_db_set_compiled (uint32_t ifindex, uint32_t version)
{
    struct rat_db *db;

    RAT_DB_WRITELOCK();                                            /* LOCK DB */
    db = rat_db_find(ifindex);
    if (!db)
        goto exit_err_unlock;
    db->db_compiled = db->db_version;
    RAT_DB_UNLOCK();                                             /* UNLOCK DB */

    return RAT_OK;

exit_err_unlock:
    RAT_DB_UNLOCK();                                             /* UNLOCK DB */
    return RAT_ERROR;
}

