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


#include "log.h"

#include <pthread.h>
#include <stdarg.h>             /* va_start() and friends */


/* --- globals  ------------------------------------------------------------- */


/** Current log level */
static enum rat_log_level rat_log_global_level = RAT_LOG_WARNING;


/** @brief Mutex for logging function
 *
 * Due to threading we would otherwise mess up the log file.
 */
pthread_mutex_t rat_log_mutex = PTHREAD_MUTEX_INITIALIZER;


/* --- functions  ----------------------------------------------------------- */


/**
 * @brief Drop a log message line
 * @param level                 log verbosity level
 * @param fmt                   format string
 * @param vl                    list of variadic arguments
 */
static void __rat_log (enum rat_log_level level, const char *fmt, va_list vl)
{
    RAT_DEBUG_TRACE();

    if (level > rat_log_global_level)
        return;

    pthread_mutex_lock(&rat_log_mutex);

    /* level */
    switch (level) {
    case RAT_LOG_NULL:
        fprintf(stderr, "Log: ");
        break;
    case RAT_LOG_INFO:
        fprintf(stderr, "Info: ");
        break;
    case RAT_LOG_WARNING:
        fprintf(stderr, "Warning: ");
        break;
    case RAT_LOG_ERROR:
        fprintf(stderr, "Error: ");
        break;
    default:
        break;
    }

    /* message */
    vfprintf(stderr, fmt, vl);
    fprintf(stderr, "\n");

    pthread_mutex_unlock(&rat_log_mutex);

    return;
}


/**
 * @brief Log an undefined message
 *
 * @param fmt                   format string
 * @param ...                   variadic arguments
 */
static void rat_log_null (const char *fmt, ...)
{
    va_list vl;
    RAT_DEBUG_TRACE();

    va_start(vl, fmt);
    __rat_log(RAT_LOG_NULL, fmt, vl);
    va_end(vl);

    return;
}


/**
 * @brief Log an error message
 *
 * @param fmt                   format string
 * @param ...                   variadic arguments
 */
void rat_log_err (const char *fmt, ...)
{
    va_list vl;
    RAT_DEBUG_TRACE();

    va_start(vl, fmt);
    __rat_log(RAT_LOG_ERROR, fmt, vl);
    va_end(vl);

    return;
}


/**
 * @brief Log a warning message
 *
 * @param fmt                   format string
 * @param ...                   variadic arguments
 */
void rat_log_wrn (const char *fmt, ...)
{
    va_list vl;
    RAT_DEBUG_TRACE();

    va_start(vl, fmt);
    __rat_log(RAT_LOG_WARNING, fmt, vl);
    va_end(vl);

    return;
}


/**
 * @brief Log an informational message
 *
 * @param fmt                   format string
 * @param ...                   variadic arguments
 */
void rat_log_nfo (const char *fmt, ...)
{
    va_list vl;
    RAT_DEBUG_TRACE();

    va_start(vl, fmt);
    __rat_log(RAT_LOG_INFO, fmt, vl);
    va_end(vl);

    return;
}


/**
 * @brief Set verbosity level for logging
 *
 * @param level                 log verbosity level
 *
 * @return Returns RAT_ERROR on error, RAT_OK otherwise
 */
int rat_log_set_level (enum rat_log_level level)
{
    RAT_DEBUG_TRACE();

    switch (level) {
        case RAT_LOG_ERROR:
            rat_log_global_level = level;
            rat_log_null("Level set to `error'.");
            break;
        case RAT_LOG_WARNING:
            rat_log_global_level = level;
            rat_log_null("Level set to `warning'.");
            break;
        case RAT_LOG_INFO:
            rat_log_global_level = level;
            rat_log_null("Level set to `info'.");
            break;
        default:
            return RAT_ERROR;
            break;
    }

    return RAT_OK;
}
