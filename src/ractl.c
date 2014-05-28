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


#include "ractl.h"

#include "library.h"
#include "module.h"
#include "ra.h"
#include "opt_mtu.h"
#include "opt_sll.h"
#include "opt_pi.h"
#include "opt_rdnss.h"
#include "opt_exp.h"

#include <stdio.h>
#include <stdlib.h>
#include <regex.h>
#include <net/if.h>             /* if_nametoindex() */
#include <errno.h>
#include <unistd.h>             /* read() */
#include <sys/un.h>             /* struct sockaddr_un */
#include <getopt.h>
#include <string.h>


/* --- global --------------------------------------------------------------- */


/** Socket address for communication with ratools/rad */
static char *rat_ractl_sockaddr = NULL;


/* --- helper functions ----------------------------------------------------- */


/**
 * @brief Function wrapper
 *
 * @param regex                 regex pattern
 * @param str                   string to match
 *
 * @see rat_lib_regex_match()
 */
static inline int rat_ractl_rm (const char *regex, const char *str)
{
    return rat_lib_regex_match(regex, str);
}

/**
 * @brief Get interface index by name
 *
 * @param ifname                interface name
 * @param[out] ifindex          interface index
 *
 * @return Returns RAT_ERROR on error, RAT_OK otherwise
 */
static int rat_ractl_ifnametoindex (const char *ifname, uint32_t *ifindex)
{
    unsigned int tmpifx;

    tmpifx = if_nametoindex(ifname);
    if (tmpifx == 0) {
        fprintf(stderr, "Error: Interface `%s': %s\n", ifname, strerror(errno));
        goto exit_err;
    }
    if (tmpifx > UINT32_MAX) {
        fprintf(stderr, "Error: Interface `%s': Index out of range!\n", ifname);
        goto exit_err;
    }
    *ifindex = (uint32_t) tmpifx;

    return RAT_OK;

exit_err:
    return RAT_ERROR;
}


/**
 * @brief Normalize a configuration line
 *
 * Strips leading, consecutive and trailing white spaces.
 *
 * @param line                  configuration line
 *
 * @return Returns RAT_ERROR on error, RAT_OK otherwise
 */
static int rat_ractl_normalize (char *line)
{
    char *s, *p;
    int ws = 0;
    RAT_DEBUG_TRACE();

    if (*line == '#')
            return RAT_ERROR;

    s = p = line;
    while (*s && *s != '\n') {
        if (*s == '\t')
            *s = ' ';
        if (*s == ' ' && ws) {
            s++;
            continue;
        }
        ws = (*s == ' ');
        *p++ = *s++;
    }
    *p = 0x0;

    return RAT_OK;
}


/**
 * @brief Tokenize a configuration line
 *
 * Converts a normalized configuration line into an array of strings.
 *
 * @param line                  configuration line
 * @param tok                   array of strings
 * @param toklen                number of array elements
 *
 * @return Returns the number of found tokens
 */
static unsigned int rat_ractl_tokenize (char *line, char *tok[], size_t toklen)
{
    char *s = line;
    unsigned int i;
    RAT_DEBUG_TRACE();

    if (!*line)
        return 0;

    for (i = 0; i < toklen; i++)
        tok[i] = NULL;
    i = 0;

    tok[i++] = s;
    while (*++s && i < toklen) {
        if (*s == ' ') {
            *s = 0x0;
            if (*++s)
                tok[i++] = s;
        }
    }

    return i;
}


/* --- parser --------------------------------------------------------------- */


/**
 * @brief Parse and send a configuration line
 *
 * Configuration line is parsed and converted into a request control message.
 * Request is sent to the daemon and replies are parsed and printed.
 *
 * @param argc                  number of arguments
 * @param argv                  argument values
 *
 * @return Returns RAT_ERROR on error, RAT_OK otherwise
 */
static int rat_ractl_parse_send (int argc, char *argv[])
{
    regex_t rgx;
    regmatch_t rm[4];
    char rbuf[MAX(RAT_MODNAMELEN, RAT_INDEXSTRLEN) + 1];
    struct rat_ctl_request crq;
    struct sockaddr_un sa;
    int sd;
    struct rat_ctl_reply cry;
    RAT_DEBUG_TRACE();

    memset(&crq, 0x0, sizeof(crq));

    /*
     * name:    object/action   action      parameter       value
     * argv:    [0]             [1]         [2]             [3]
     * argc:    1               2           3               4
     * ----------------------------------------------------------
     * example: ra@eth0         create
     * example: ra@eth0         set         lifetime        30m
     * example: dump
     */

    /* special action: version information */
    if (rat_ractl_rm(RAT_RACTL_REGEX_VERSION, argv[0]) == RAT_OK) {
        fprintf(stdout, "ratools/ractl " RAT_VERSION " (" RAT_DATE ")\n");
        fprintf(stdout, "Written by Dan Luedtke <mail@danrl.de>\n");
        return EXIT_SUCCESS;
    }

    /* special action: show all */
    if (rat_ractl_rm(RAT_RACTL_REGEX_SHOW, argv[0]) == RAT_OK) {
        crq.crq_type = RAT_CTL_REQUEST_TYPE_SHOWALL;
        if (argc > 2)
            fprintf(stderr, "Ignoring trailing garbage after `%s'!\n", argv[0]);
        goto send_request;
    }

    /* special action: dump all */
    if (rat_ractl_rm(RAT_RACTL_REGEX_DUMP, argv[0]) == RAT_OK) {
        crq.crq_type = RAT_CTL_REQUEST_TYPE_DUMPALL;
        if (argc > 2)
            fprintf(stderr, "Ignoring trailing garbage after `%s'!\n", argv[0]);
        goto send_request;
    }

    /* special action: log (setting log level of daemon) */
    if (rat_ractl_rm(RAT_RACTL_REGEX_LOG, argv[0]) == RAT_OK) {
        if (argc < 2) {
            fprintf(stderr, "Error: Missing log level!\n");
            fprintf(stderr, "Try `error', `warning' or `info'.\n");
            goto exit_err;
        }
        if (rat_ractl_rm(RAT_RACTL_REGEX_ERROR, argv[1]) == RAT_OK) {
            crq.crq_type = RAT_CTL_REQUEST_TYPE_SETLOGERROR;
        } else if (rat_ractl_rm(RAT_RACTL_REGEX_WARNING, argv[1]) == RAT_OK) {
            crq.crq_type = RAT_CTL_REQUEST_TYPE_SETLOGWARNING;
        } else if (rat_ractl_rm(RAT_RACTL_REGEX_INFO, argv[1]) == RAT_OK) {
            crq.crq_type = RAT_CTL_REQUEST_TYPE_SETLOGINFO;
        } else {
            fprintf(stderr, "Error: Invalid log level `%s'!\n", argv[1]);
            fprintf(stderr, "Try `error', `warning' or `info'.\n");
            goto exit_err;
        }
        if (argc > 3)
            fprintf(stderr, "Ignoring trailing garbage after `%s'!\n", argv[0]);
        goto send_request;
    }


    /* --- parse object, e.g. ra@eth0 --------------------------------------- */


    crq.crq_type = RAT_CTL_REQUEST_TYPE_MODULE;

    /* compile and match object regex */
    if (regcomp(&rgx, RAT_RACTL_REGEX_OBJECT, REG_EXTENDED | REG_ICASE)) {
        fprintf(stderr, "Error: Could not compile regular expression `%s'!\n",
                RAT_RACTL_REGEX_OBJECT);
        goto exit_err;
    }
    if (regexec(&rgx, argv[0], sizeof(rm) / sizeof(rm[0]), rm, 0)) {
        regfree(&rgx);
        fprintf(stderr, "Error: Invalid object `%s'!\n", argv[0]);
        rat_mod_help_modules();
        goto exit_err;
    }
    regfree(&rgx);

    /* module id */
    memset(rbuf, 0x0, sizeof(rbuf));
    memcpy(rbuf, argv[0] + rm[1].rm_so, rm[1].rm_eo - rm[1].rm_so);
    if (rat_mod_parse_module(rbuf, &crq.crq_mid) != RAT_OK) {
        fprintf(stderr, "Error: Invalid object `%s'!\n", argv[0]);
        rat_mod_help_modules();
        goto exit_err;
    }

    /* option index */
    memset(rbuf, 0x0, sizeof(rbuf));
    memcpy(rbuf, argv[0] + rm[2].rm_so, rm[2].rm_eo - rm[2].rm_so);
    if (rat_mod_requires_oid(crq.crq_mid)) {
        if (strlen(rbuf) < 1) {
            fprintf(stderr, "Error: Missing object numer!\n");
            rat_mod_help_modules();
            goto exit_err;
        }
        crq.crq_oid = (uint16_t) strtoull(argv[0] + rm[2].rm_so, NULL, 10);
    } else if (strlen(rbuf)) {
        fprintf(stderr, "Error: Invalid object `%s'!\n", argv[0]);
        rat_mod_help_modules();
        goto exit_err;
    }

    /* interface name */
    if (rat_ractl_ifnametoindex(argv[0] + rm[3].rm_so,
                                &crq.crq_ifindex) != RAT_OK) {
        goto exit_err;
    }


    /* --- parse action ----------------------------------------------------- */


    if (argc < 2) {
        fprintf(stderr, "Error: Missing action!\n");
        rat_mod_help_actions(crq.crq_mid);
        goto exit_err;
    }

    if (rat_mod_parse_action(crq.crq_mid, argv[1], &crq.crq_aid)
        != RAT_OK) {
        fprintf(stderr, "Error: Invalid action `%s'!\n", argv[1]);
        rat_mod_help_actions(crq.crq_mid);
        goto exit_err;
    }


    /* --- parse parameter -------------------------------------------------- */


    if (!rat_mod_requires_pid(crq.crq_mid, crq.crq_aid)) {
        if (argc > 3)
        fprintf(stderr, "Ignoring trailing garbage after `%s'!\n", argv[1]);
        goto send_request;
    }

    if (argc < 3) {
        fprintf(stderr, "Error: Missing parameter!\n");
        rat_mod_help_parameters(crq.crq_mid, crq.crq_aid);
        goto exit_err;
    }

    if (rat_mod_parse_parameter(crq.crq_mid, crq.crq_aid, argv[2], &crq.crq_pid)
        != RAT_OK) {
        fprintf(stderr, "Error: Invalid parameter `%s'!\n", argv[2]);
        rat_mod_help_parameters(crq.crq_mid, crq.crq_aid);
        goto exit_err;
    }


    /* --- parse value ------------------------------------------------------ */


    if (!rat_mod_requires_vid(crq.crq_mid, crq.crq_aid, crq.crq_pid)) {
        if (argc > 4)
        fprintf(stderr, "Ignoring trailing garbage after `%s'!\n", argv[2]);
        goto send_request;
    }

    if (argc < 4) {
        fprintf(stderr, "Error: Missing value!\n");
        rat_mod_help_values(crq.crq_mid, crq.crq_aid, crq.crq_pid);
        goto exit_err;
    }

    if (rat_mod_parse_value(crq.crq_mid, crq.crq_aid, crq.crq_pid, argv[3],
                            &crq.crq_vid) != RAT_OK) {
        fprintf(stderr, "Error: Invalid value `%s'!\n", argv[3]);
        rat_mod_help_values(crq.crq_mid, crq.crq_aid, crq.crq_pid);
        goto exit_err;
    }

    if (argc > 5)
        fprintf(stderr, "Ignoring trailing garbage after `%s'!\n", argv[3]);

    if (rat_mod_cli_call_vid(crq.crq_mid, crq.crq_aid, crq.crq_pid,
                             crq.crq_vid, argv[3], crq.crq_data,
                             RAT_CTL_REQ_DATA_LEN) != RAT_OK)
        goto exit_err;


    /* --- send request ----------------------------------------------------- */
send_request:


    /* initialize unix domain socket address */
    memset(&sa, 0x0, sizeof(sa));
    sa.sun_family = AF_UNIX;
    strncpy(sa.sun_path, rat_ractl_sockaddr, sizeof(sa.sun_path) - 1);

    /* open unix domain socket */
    if ((sd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
        fprintf(stderr, "Error: Could not open socket `%s': %s!\n", sa.sun_path,
                strerror(errno));
        goto exit_err;
    }

    /* connect to unix domain socket */
    if (connect(sd, (struct sockaddr *) &sa, sizeof(sa)) < 0) {
        fprintf(stderr, "Error: Could not connect to socket `%s': %s!\n",
                sa.sun_path, strerror(errno));
        goto exit_err_sd;
    }

    /* send request */
    if (send(sd, &crq, sizeof(crq), 0) != sizeof(crq))
        goto exit_err_sd;

    /* receive reply message(s) */
    while (recv(sd, &cry, sizeof(cry), MSG_WAITALL) == sizeof(cry)) {
        switch(cry.cry_type) {
            case RAT_CTL_REPLY_TYPE_EXIT_OK:
                RAT_DEBUG_MESSAGE("Success!");
                goto exit_ok_sd;
                break;
            case RAT_CTL_REPLY_TYPE_EXIT_ERROR:
                RAT_DEBUG_MESSAGE("Error!");
                goto exit_err_sd;
                break;
            case RAT_CTL_REPLY_TYPE_PRINT:
                fprintf(stdout, "%s", cry.cry_msg);
                break;
            case RAT_CTL_REPLY_TYPE_MSG:
                fprintf(stdout, "%s\n", cry.cry_msg);
                break;
            case RAT_CTL_REPLY_TYPE_ERRMSG:
                fprintf(stderr, "Error: %s\n", cry.cry_msg);
                break;
            default:
                break;
        }
    }

exit_ok_sd:
    close(sd);
    return RAT_OK;

exit_err_sd:
    close(sd);
exit_err:
    return RAT_ERROR;
}


/* --- main ----------------------------------------------------------------- */


/**
 * @brief ratools/ractl main function
 *
 * @param argc                  number of command line arguments
 * @param argv                  array of command line arguments
 *
 * @return Returns EXIT_SUCCESS on success, EXIT_FAILURE otherwise
 */
int main (int argc, char *argv[])
{
    char buffer[256];
    char *stdinv[RAT_RACTL_MAXTOKENS];
    unsigned int stdinc;
    int ret = EXIT_SUCCESS;

    /* set defaults and get options */
    rat_ractl_sockaddr = strdup(RAT_SOCKADDR);
    while (1) {
        int c, cidx;
        static struct option copts[] = {
            {"socket",       required_argument, 0, 's'},
            {0, 0, 0, 0}
        };
        c = getopt_long(argc, argv, "s:", copts, &cidx);

        if (c == -1)
            break;
        switch (c) {
            case 's':
                rat_ractl_sockaddr = optarg;
                break;
            case '?':
                ret = EXIT_FAILURE;
                goto exit;
                break;
            default:
                break;
        }
    }
    argc = argc - optind + 1;
    argv += optind - 1;

    /* initialize modules */
    rat_ra_init();
    rat_opt_mtu_init();
    rat_opt_sll_init();
    rat_opt_pi_init();
    rat_opt_rdnss_init();
    rat_opt_exp_init();

    if (isatty(fileno(stdin))) {
        /* tty */
        if (argc < 2) {
            fprintf(stderr, "Error: Missing action or object!\n");
            fprintf(stderr, "Try `version', `loglevel', `show' or `dump'.\n");
            rat_mod_help_modules();
            ret = EXIT_FAILURE;
        } else {
            if (rat_ractl_parse_send(--argc, ++argv) != RAT_OK)
                ret = EXIT_FAILURE;
        }
    } else {
        /* stdin */
        while (fgets(buffer, sizeof(buffer), stdin)) {

            if (rat_ractl_normalize(buffer) != RAT_OK)
                continue;

            stdinc = rat_ractl_tokenize(buffer, stdinv, RAT_RACTL_MAXTOKENS);
            if (!stdinc)
                continue;

            if (rat_ractl_parse_send(stdinc, stdinv) != RAT_OK)
                ret = EXIT_FAILURE;
        }
    }

exit:
    return ret;
}
