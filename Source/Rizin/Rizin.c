/**
 * @file : CmdHandlers.c
 * @date : 13th June 2024
 * @author : Siddharth Mishra (admin@brightprogrammer.in)
 * @copyright: Copyright (c) 2024 RevEngAI. All Rights Reserved.
 *
 * @brief Main plugin entry point.
 * */

/* rizin */
#include <rz_analysis.h>
#include <rz_asm.h>
#include <rz_cmd.h>
#include <rz_core.h>
#include <rz_lib.h>
#include <rz_th.h>
#include <rz_types.h>

/* revengai */
#include <Reai/Log.h>
#include <Reai/Api.h>
#include <Reai/Config.h>
#include <Reai/Types.h>
#include <Reai/Log.h>

/* libc */
#include <rz_util/rz_sys.h>
#include <stdarg.h>

/* local includes */
#include <Rizin/CmdGen/Output/CmdDescs.h>
#include <Plugin.h>
#include "../PluginVersion.h"

typedef int (*RzAnalysisFunctionRenameCallback) (
    RzAnalysis         *analysis,
    void               *core,
    RzAnalysisFunction *fcn,
    const char         *newname
);

Str *getMsg() {
    static Str  s;
    static bool is_inited = false;
    if (!is_inited) {
        s         = StrInit();
        is_inited = true;
    }
    return &s;
}

void rzClearMsg() {
    StrClear (getMsg());
}

void rzDisplayMsg (LogLevel level, Str *msg) {
    if (!msg) {
        LOG_ERROR ("Invalid arguments");
        return;
    }

    rzAppendMsg (level, msg);
    rz_cons_println (getMsg()->data);
    StrClear (getMsg());
}

void rzAppendMsg (LogLevel level, Str *msg) {
    if (!msg) {
        LOG_ERROR ("Invalid arguments");
        return;
    }

    StrAppendf (
        getMsg(),
        "%s: %s\n",
        level == LOG_LEVEL_INFO ? "INFO" : (level == LOG_LEVEL_ERROR ? "ERROR" : "FATAL"),
        msg->data
    );
}

// NOTE: Hook function for function rename
// This is called back from Rizin event system whenever a function is renamed.
static int reai_on_fcn_rename (RzAnalysis *analysis, RzCore *core, RzAnalysisFunction *fcn, const char *newname) {
    if (!analysis || !core || !fcn || !fcn->name || !newname) {
        LOG_ERROR ("Invalid arguments in function rename callback");
        return 1;
    }

    LOG_INFO ("Function rename detected: new name '%s' at 0x%llx", fcn->name, fcn->addr);

    // Only sync if we have a valid binary ID (analysis is applied)
    // Use GetBinaryIdFromCore to check both local storage and RzCore config.
    // In Cutter, fetching binary id from local plugin storage won't work,
    // and the IdFromCore will end up fetching from RzCore config only.
    // Check if we can work with the current analysis
    if (!rzCanWorkWithAnalysis (GetBinaryIdFromCore (core), false)) {
        LOG_INFO ("RevEngAI analysis not ready, skipping function rename sync");
        return 1;
    }

    // Look up the RevEngAI function ID for this Rizin function
    FunctionId fn_id = rzLookupFunctionId (core, fcn);
    if (!fn_id) {
        LOG_ERROR ("Failed to find RevEngAI function ID for function '%s' at 0x%llx", fcn->name, fcn->addr);
        return 1;
    }

    // Create new name string for the API call
    Str new_name = StrInitFromZstr (fcn->name);

    // Call RevEngAI API to rename the function
    int result = 0;
    if (RenameFunction (GetConnection(), fn_id, new_name)) {
        LOG_INFO ("Successfully synced function rename with RevEngAI: '%s' (ID: %llu)", fcn->name, fn_id);
        result = 0;
    } else {
        LOG_ERROR ("Failed to sync function rename with RevEngAI for function '%s' (ID: %llu)", fcn->name, fn_id);
        result = 1;
    }

    StrDeinit (&new_name);
    return result;
}

void *syncTypes (RzCore *core) {
    if (!core) {
        LOG_FATAL ("Invalid core provided. Cannot start background sync thread.");
    }
    return core;
}

RZ_IPI bool rz_plugin_init (RzCore *core) {
    if (!core) {
        DISPLAY_ERROR ("Invalid rizin core provided. Cannot initialize plugin.");
        return false;
    }

    LogInit (true);

    // Register our config variables
    if (core->config) {
        rz_config_set_i (core->config, "reai.binary_id", 0);
        rz_config_desc (core->config, "reai.binary_id", "Current RevEngAI binary ID for cross-context access");
        LOG_INFO ("Registered RevEngAI config variable: reai.binary_id");
    }

    // Install our hook
    if (core->analysis) {
        core->analysis->cb.on_fcn_rename = (RzAnalysisFunctionRenameCallback)reai_on_fcn_rename;
        LOG_INFO ("RevEngAI function rename hook installed");
    } else {
        LOG_ERROR ("Failed to install function rename hook: analysis not available");
    }

    rzshell_cmddescs_init (core);

    // TODO: Initialize variables from current analysis

    return true;
}

RZ_IPI bool rz_plugin_fini (RzCore *core) {
    if (!core) {
        DISPLAY_ERROR ("Invalid rizin core provided. Failed to free plugin resources.");
        return false;
    }

    RzCmd     *rcmd          = core->rcmd;
    RzCmdDesc *reai_cmd_desc = rz_cmd_get_desc (rcmd, "RE");
    return rz_cmd_desc_remove (rcmd, reai_cmd_desc);
}

/* plugin data */
RzCorePlugin core_plugin_reai = {
    .name    = "reai_rizin",
    .author  = "Siddharth Mishra",
    .desc    = "RevEng.AI Rizin Analysis Plugin",
    .license = "Copyright (c) 2024 RevEngAI. All Rights Reserved.",
    .version = REAI_PLUGIN_VERSION,
    .init    = (RzCorePluginCallback)rz_plugin_init,
    .fini    = (RzCorePluginCallback)rz_plugin_fini,
    // .analysis = (RzCorePluginCallback)reai_plugin_analysis,
};

#ifdef _MSC_VER
#    define RZ_EXPORT __declspec (dllexport)
#else
#    define RZ_EXPORT
#endif

#ifndef CORELIB
RZ_EXPORT RzLibStruct rizin_plugin = {
    .type    = RZ_LIB_TYPE_CORE,
    .data    = &core_plugin_reai,
    .version = RZ_VERSION,
};
#endif
