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
#include <Reai/Db.h>
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

/**
 * Display a message of given level in rizin shell.
 *
 * If message is below error level then it's sent to log file,
 * otherwise it's displayed on screen as well as in log file.
 *
 * @param level
 * @param msg
 * */
void reai_plugin_display_msg (ReaiLogLevel level, CString msg) {
    RETURN_IF (!msg, ERR_INVALID_ARGUMENTS);

    if (level < REAI_LOG_LEVEL_ERROR) {
        reai_log_printf (reai_logger(), level, "", msg);
    } else {
        rz_cons_printf ("%s\n", msg);
        reai_log_printf (reai_logger(), level, "", msg);
    }
}

/**
 * @brief Called by rizin when loading reai_plugin()-> This is the plugin entrypoint where we
 * register all the commands and corresponding handlers.
 *
 * To know about how commands work for this plugin, refer to `CmdGen/README.md`.
 * */
RZ_IPI Bool rz_plugin_init (RzCore* core) {
    RETURN_VALUE_IF (!core, False, ERR_INVALID_ARGUMENTS);

    rzshell_cmddescs_init (core);
    return reai_plugin_init (core);
}

/**
 * @b Will be called by rizin before unloading the reai_plugin()->
 * */
RZ_IPI Bool rz_plugin_fini (RzCore* core) {
    RETURN_VALUE_IF (!core, False, ERR_INVALID_ARGUMENTS);
    reai_plugin_deinit (core);

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
