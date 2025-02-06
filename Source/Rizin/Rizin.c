/**
 * @file : CmdHandlers.c
 * @date : 13th June 2024
 * @author : Siddharth Mishra (admin@brightprogrammer.in)
 * @copyright: Copyright (c) 2024 RevEngAI. All Rights Reserved.
 *
 * @brief Main plugin entry point.
 * */

/* rizin */
#include <Reai/Api/Reai.h>
#include <rz_analysis.h>
#include <rz_asm.h>
#include <rz_cmd.h>
#include <rz_core.h>
#include <rz_lib.h>
#include <rz_th.h>
#include <rz_types.h>

/* revengai */
#include <Reai/AnalysisInfo.h>
#include <Reai/Log.h>
#include <Reai/Api/Api.h>
#include <Reai/Common.h>
#include <Reai/Config.h>
#include <Reai/Types.h>

/* libc */
#include <rz_util/rz_sys.h>
#include <stdarg.h>

/* local includes */
#include <Rizin/CmdGen/Output/CmdDescs.h>
#include <Plugin.h>

CStrVec* dmsgs[REAI_LOG_LEVEL_MAX];

/**
 * Display a message of given level in rizin shell.
 *
 * @param level
 * @param msg
 * */
void reai_plugin_display_msg (ReaiLogLevel level, CString msg) {
    if (!msg) {
        REAI_LOG_ERROR (ERR_INVALID_ARGUMENTS);
        return;
    }

    reai_plugin_append_msg (level, msg);

    /* append logs from each category */
    for (int x = 0; x < REAI_LOG_LEVEL_MAX; x++) {
        CStrVec* v = dmsgs[x];
        for (size_t l = 0; l < v->count; l++) {
            CString m = v->items[l];
            reai_log_printf (level, "rizin.display", m);
            rz_cons_println (m);
            FREE (v->items[l]);
        }
        v->count = 0;
    }
}

/**
 * Apend a message to a vector to be displayed all at once later on.
 *
 * @param level
 * @param msg
 * */
void reai_plugin_append_msg (ReaiLogLevel level, CString msg) {
    if (!msg) {
        REAI_LOG_ERROR (ERR_INVALID_ARGUMENTS);
        return;
    }

    reai_cstr_vec_append (dmsgs[level], &msg);
}

/**
 * @brief Called by rizin when loading reai_plugin()-> This is the plugin entrypoint where we
 * register all the commands and corresponding handlers.
 *
 * To know about how commands work for this plugin, refer to `CmdGen/README.md`.
 * */
RZ_IPI Bool rz_plugin_init (RzCore* core) {
    if (!core) {
        DISPLAY_ERROR ("Invalid rizin core provided. Cannot initialize plugin.");
        return false;
    }

    for (int x = 0; x < REAI_LOG_LEVEL_MAX; x++) {
        dmsgs[x] = reai_cstr_vec_create();
    }

    rzshell_cmddescs_init (core);
    if (!reai_plugin_init (core)) {
        DISPLAY_ERROR ("Failed to initialize plugin.");
    }

    return true;
}

/**
 * @b Will be called by rizin before unloading the reai_plugin()->
 * */
RZ_IPI Bool rz_plugin_fini (RzCore* core) {
    if (!core) {
        DISPLAY_ERROR ("Invalid rizin core provided. Failed to free plugin resources.");
        return false;
    }

    reai_plugin_deinit();

    for (int x = 0; x < REAI_LOG_LEVEL_MAX; x++) {
        reai_cstr_vec_destroy (dmsgs[x]);
        dmsgs[x] = NULL;
    }


    /* Remove command group from rzshell. The name of this comamnd group must match
     * with the one specified in Root.yaml */
    RzCmd*     rcmd          = core->rcmd;
    RzCmdDesc* reai_cmd_desc = rz_cmd_get_desc (rcmd, "RE");
    return rz_cmd_desc_remove (rcmd, reai_cmd_desc);
}

/* plugin data */
RzCorePlugin core_plugin_reai = {
    .name    = "reai_rizin",
    .author  = "Siddharth Mishra",
    .desc    = "RevEng.AI Rizin Analysis Plugin",
    .license = "Copyright (c) 2024 RevEngAI. All Rights Reserved.",
    .version = "0.0",
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
