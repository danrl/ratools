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


#include "proc.h"

#include "log.h"

#include <stdio.h>
#include <string.h>
#include <errno.h>


/**
 * @brief Stores the forwarding state of an interface in the database
 *
 * @param db                    database entry
 *
 * @return Returns RAT_ERROR on error, RAT_OK otherwise
 */
int rat_prc_forwarding (struct rat_db *db)
{
    int f;
    FILE *fp;

    fp = fopen(RAT_PRC_IP6FORWARDPATH, "r");
    if (!fp) {
        rat_log_err("Could not open file `%s': %s", RAT_PRC_IP6FORWARDPATH,
                    strerror(errno));
        goto exit_err;
    }

    if (fscanf(fp, "%d", &f) != 1) {
        rat_log_err("Could read from file `%s': %s", RAT_PRC_IP6FORWARDPATH,
                    strerror(errno));
        goto exit_err;
    }
    fclose(fp);

    switch (f) {
        case RAT_PRC_FWD_DISABLED:
        case RAT_PRC_FWD_ENABLED:
        case RAT_PRC_FWD_ENABLEDRS:
            break;
        default:
            rat_log_wrn("Unknown value `%d' in file `%s'!", f,
                        RAT_PRC_IP6FORWARDPATH);
            rat_log_wrn("Assuming forwarding enabled.");
            break;
    }
    db->db_forwarding = f;

    return RAT_OK;

exit_err:
    return RAT_ERROR;
}
