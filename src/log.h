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


#ifndef __RATOOLS_LOG_H
#define __RATOOLS_LOG_H

#include "ratools.h"


/**
 * @brief log verbosity level
 */
enum rat_log_level {
    /** Undefined log level. For internal use only! */
    RAT_LOG_NULL                = 0,
    /** Log error conditions */
    RAT_LOG_ERROR               = 3,
    /** Log warning conditions */
    RAT_LOG_WARNING             = 5,
    /** Log informational messages */
    RAT_LOG_INFO                = 7
};


extern int rat_log_set_level (enum rat_log_level);
extern void rat_log_err (const char *, ...);
extern void rat_log_wrn (const char *, ...);
extern void rat_log_nfo (const char *, ...);


#endif /* __RATOOLS_LOG_H */
