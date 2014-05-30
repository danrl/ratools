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

#include "module.h"
#include "ra.h"
#include "opt_mtu.h"
#include "opt_sll.h"
#include "opt_pi.h"
#include "opt_rdnss.h"
#include "opt_exp.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>             /* va_start() and friends */


/** printf() short-hand */
static int (*pf) (const char *, ...) = printf;


/**
 * @brief Printf with newline wrapper
 *
 * @param fmt                   format string
 * @param ...                   variadic arguments
 */
static void pn (const char *fmt, ...)
{
    va_list vl;

    va_start(vl, fmt);
    vprintf(fmt, vl);
    va_end(vl);
    puts("");

    return;
}


/**
 * @brief Print actions
 *
 * @param mmr                   module configuration
 */
static void pf_actions (struct rat_mod_modreg *mmr)
{
    if (!mmr)
        goto exit;

    if (mmr->mmr_create)
        printf(" create ");
    if (mmr->mmr_destroy)
        printf(" destroy ");
    if (mmr->mmr_enable)
        printf(" enable ");
    if (mmr->mmr_disable)
        printf(" disable ");
    if (mmr->mmr_kill)
        printf(" kill ");
    if (mmr->mmr_show)
        printf(" show ");
    if (mmr->mmr_dump)
        printf(" dump ");
    if (mmr->mmr_set)
        printf(" set ");
    if (mmr->mmr_add)
        printf(" add ");
    if (mmr->mmr_del)
        printf(" del ");

exit:
    return;
}


/**
 * @brief Match on parameters and their values
 *
 * @param sad                   string of triggered action (e.g. "set")
 * @param msr                   set/add/del registration
 * @param len                   length of registration
 */
static void pn_sad (const char *sad, struct rat_mod_sadreg *msr, uint16_t len)
{
    struct rat_mod_sadreg *curmsr;
    struct rat_mod_valreg *curmvr;
    uint16_t i, j;

    if (!msr || !len)
        goto exit;

    pn("    \"%s\")", sad);
    pn("     if [[ ${COMP_CWORD} -eq 3 ]]");
    pn("     then");
    pf("      COMPREPLY=( $(compgen -W \"");
    curmsr = msr;
    for (i = 0; i < len; i++) {
        printf(" %s ", curmsr->msr_help);
        curmsr++;
    }
    pn("\" -- ${CUR}) )");
    pn("      return 0");
    pn("     fi");
    pn("     case \"${COMP_WORDS[3]}\" in");
    curmsr = msr;
    for (i = 0; i < len; i++) {
        pn("      \"%s\")", curmsr->msr_help);
        pn("       if [[ ${COMP_CWORD} -eq 4 ]]");
        pn("       then");
        pf("        COMPREPLY=( $(compgen -W \"");
        curmvr = curmsr->msr_val;
        for (j = 0; j < curmsr->msr_vallen; j++) {
            printf(" %s ", curmvr->mvr_help);
            curmvr++;
        }
        pn("\" -- ${CUR}) )");
        pn("        return 0");
        pn("       fi");
        pn("       ;;");
        curmsr++;
    }
    pn("     esac");
    pn("     ;;");

exit:
    return;
}


/**
 * @brief ratools/racmpl-ractl main function
 *
 * @param argc                  number of command line arguments
 * @param argv                  array of command line arguments
 *
 * @return Returns EXIT_SUCCESS on success, EXIT_FAILURE otherwise
 */
int main (int argc, char *argv[])
{
    struct rat_mod_modreg *rgy, *mmr;
    RAT_DISCARD_UNUSED(argc);
    RAT_DISCARD_UNUSED(argv);

    /* load modules */
    rat_ra_init();
    rat_opt_mtu_init();
    rat_opt_sll_init();
    rat_opt_pi_init();
    rat_opt_rdnss_init();
    rat_opt_exp_init();

    /* get access to the registry */
    rgy = rat_mod_leak_registry();

    pn("# bash completion function for ratools/ractl");
    pn("_racomplete_ractl() {");
    pn(" local CUR=${COMP_WORDS[COMP_CWORD]}");
    pn(" if [[ ${COMP_CWORD} -eq 1 ]]");
    pn(" then");
    pn("  COMPREPLY=( $(compgen -W \"version log dump show\" -- ${CUR}) )");

    for (mmr = rgy; mmr; mmr = mmr->mmr_next)
        pn("  COMPREPLY+=( $(compgen -W \"%s%s@eth0\" -- ${CUR}) )",
          mmr->mmr_name, mmr->mmr_multiple ? "0" : "");

    pn("  return 0");
    pn(" fi");
    pn(" case \"${COMP_WORDS[1]}\" in");


    /* --- special case: log ------------------------------------------------ */


    pn("  \"log\")");
    pn("   if [[ ${COMP_CWORD} -eq 2 ]]");
    pn("   then");
    pn("    COMPREPLY=( $(compgen -W \" info  warning  error \" -- ${CUR}) )");
    pn("    return 0");
    pn("   fi");
    pn("   ;;");


    /* --- modules ---------------------------------------------------------- */


    for (mmr = rgy; mmr; mmr = mmr->mmr_next) {
        pn("  %s%s@*)", mmr->mmr_name, mmr->mmr_multiple ? "*" : "");
        pn("   if [[ ${COMP_CWORD} -eq 2 ]]");
        pn("   then");
        pf("    COMPREPLY=( $(compgen -W \"");
        pf_actions(mmr);
        pn("\" -- ${CUR}) )");
        pn("    return 0");
        pn("   fi");
        pn("   case \"${COMP_WORDS[2]}\" in");
        pn_sad("set", mmr->mmr_set, mmr->mmr_setlen);
        pn_sad("add", mmr->mmr_add, mmr->mmr_addlen);
        pn_sad("del", mmr->mmr_del, mmr->mmr_dellen);
        pn("   esac");
        pn("   ;;");
    }

    pn(" esac");
    pn(" return 1");
    pn("}");
    pn("complete -F _racomplete_ractl ractl");

    return EXIT_SUCCESS;
}
