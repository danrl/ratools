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


/** database as array of linked lists */
static struct rat_db *rat_db_fxstab[RAT_DB_FXSTS] \
    __attribute__((aligned(RAT_DB_FXSTALIGN))) = { NULL };

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
        pthread_rwlock_rdlock(&rat_db_lock);                                \
        RAT_DEBUG_MESSAGE("Writelock: after=%d", ++rat_db_debug_lockcount); \
    } while (0)
#define RAT_DB_UNLOCK()                                                     \
    do {                                                                    \
        RAT_DEBUG_MESSAGE("Unlock: before=%d", rat_db_debug_lockcount);     \
        pthread_rwlock_rdlock(&rat_db_lock);                                \
        RAT_DEBUG_MESSAGE("Unlock: after=%d", --rat_db_debug_lockcount);    \
    } while (0)
/** @} */


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

    for (db = rat_db_fxstab[ifindex % RAT_DB_FXSTS]; db; db = db->db_next)
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
    if (pthread_mutex_init(&db->db_mutex, NULL))
        goto exit_err_unlock_free;

    /* add item to database */
    if (!rat_db_fxstab[ifindex % RAT_DB_FXSTS]) {
        /* list is empty */
        rat_db_fxstab[ifindex % RAT_DB_FXSTS] = db;
    } else {
        /* list is not empty, append */
        for (cur = rat_db_fxstab[ifindex % RAT_DB_FXSTS]; cur->db_next;
             cur = cur->db_next);
        cur->db_next = db;
    }

    RAT_DB_UNLOCK();                                             /* UNLOCK DB */
    return RAT_OK;

exit_err_unlock_free:
    free(db);
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
    if (rat_db_fxstab[ifindex % RAT_DB_FXSTS] == db) {
        /* interface is first element in list */
        rat_db_fxstab[ifindex % RAT_DB_FXSTS] = db->db_next;
    } else {
        /* interface is not the first element in list */
        pre = rat_db_fxstab[ifindex % RAT_DB_FXSTS];
        for (cur = pre->db_next; cur; cur = cur->db_next) {
            if (cur == db) {
                pre->db_next = cur->db_next;
                break;
            }
            pre = cur;
        }
    }

    RAT_DB_UNLOCK();                                             /* UNLOCK DB */

    /* destroy interface elements */
    pthread_mutex_destroy(&db->db_mutex);

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
 * Create a database entry for an interface
 * @param ifindex               interface index number
 *
 * @return Returns database entry, NULL on error
 */
struct rat_db *rat_db_grab (uint32_t ifindex)
{
    struct rat_db *db = NULL;
    RAT_DEBUG_TRACE();

    if (!ifindex)
        goto exit_err;

    RAT_DB_READLOCK();                                             /* LOCK DB */

    db = rat_db_find(ifindex);
    if (!db)
        goto exit_err_unlock;

    if (pthread_mutex_lock(&db->db_mutex) != 0)
        goto exit_err_unlock;

    /*        _
     *    _  / |   Caution!
     *  _| |_| |   --------
     * |_   _| |   Number of database readers increases here!
     *   |_| |_|
     */
    return db;

exit_err_unlock:
    RAT_DB_UNLOCK();                                             /* UNLOCK DB */
exit_err:
    return NULL;
}


/**
 * Grabs first database entry
 *
 * This is useful if we want to iterate through the whole database. E.g. on
 * special commands like `show all' or `dump all'.
 *
 * @return Returns database entry, NULL on error
 */
struct rat_db *rat_db_grab_first (void)
{
    struct rat_db *db = NULL;
    unsigned int i;
    RAT_DEBUG_TRACE();

    RAT_DB_READLOCK();                                             /* LOCK DB */

    /* first entry in database requested */
    for (i = 0; i < RAT_DB_FXSTS; i++) {
        if (rat_db_fxstab[i]) {
            db = rat_db_fxstab[i];
            break;
        }
    }
    if (!db)
        goto exit_err_unlock;

    if (pthread_mutex_lock(&db->db_mutex) != 0)
        goto exit_err_unlock;

    /*        _
     *    _  / |   Caution!
     *  _| |_| |   --------
     * |_   _| |   Number of database readers increases here!
     *   |_| |_|
     */
    return db;

exit_err_unlock:
    RAT_DB_UNLOCK();                                             /* UNLOCK DB */
    return NULL;
}


/**
 * Grasb next interface in database and releases the current one
 * @param db                    database entry
 *
 * This function automatically releases the last used database entry if end of
 * list was reached.
 *
 * @return Returns database entry, NULL on error
 */
struct rat_db *rat_db_grab_next (struct rat_db *db)
{
    struct rat_db *next = NULL;
    unsigned int i;
    RAT_DEBUG_TRACE();

    if (!db)
        goto exit;

    if (db->db_next) {
        next = rat_db_grab(db->db_next->db_ifindex);
    } else {
        for (i = (db->db_ifindex % RAT_DB_FXSTS) + 1; i < RAT_DB_FXSTS; i++) {
            if (rat_db_fxstab[i]) {
                next = rat_db_fxstab[i];
                break;
            }
        }
    }
    db = rat_db_release(db);

exit:
    return next;
}


/**
 * @brief Increase database entry version number
 *
 * @param db                    database entry
 */
void rat_db_updated (struct rat_db *db)
{
    RAT_DEBUG_TRACE();

    if (db) {
        db->db_version++;
        db->db_updated = time(NULL);
    }

    return;
}


/**
 * @brief Reset running database entry to fade-in state
 *
 * Call this function if fundamental interface configuration changes have
 * applied that require hosts in the network to catch up with them. E.g.
 * link-local address changes of the router.
 *
 * @param db                    database entry
 */
void rat_db_refadein (struct rat_db *db)
{
    RAT_DEBUG_TRACE();

    if (!db)
        goto exit;

    switch (db->db_state) {
        case RAT_DB_STATE_FADEIN2:
        case RAT_DB_STATE_FADEIN3:
        case RAT_DB_STATE_ENABLED:
            db->db_state = RAT_DB_STATE_FADEIN1;
            pthread_cond_signal(&db->db_worker_cond);
            break;
        default:
            break;
    }

exit:
    return;
}

/**
 * Release a database entry
 * @param db                    database entry
 *
 * @return Returns NULL
 */
struct rat_db *rat_db_release (struct rat_db *db)
{
    RAT_DEBUG_TRACE();

    if (!db)
        goto exit;

    if (pthread_mutex_unlock(&db->db_mutex) != 0) {
        rat_log_err("Failed to unlock a mutex on interface `%" PRIu16 "'!",
                    db->db_ifindex);
        goto exit;
    }

    /*        _
     *       / |   Caution!
     *  _____| |   --------
     * |_____| |   Number of database readers decreases here!
     *       |_|
     */
    RAT_DB_UNLOCK();                                             /* UNLOCK DB */

exit:
    return NULL;
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
