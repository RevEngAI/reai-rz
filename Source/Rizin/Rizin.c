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

Str* getMsg() {
    static Str s = StrInit();
    return &s;
}

void rzDisplayMsg (LogLevel level, Str* msg) {
    if (!msg) {
        LOG_ERROR ("Invalid arguments");
        return;
    }

    rzAppendMsg (level, msg);
    rz_cons_println (getMsg()->data);
}

void rzAppendMsg (LogLevel level, Str* msg) {
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

RZ_IPI bool rz_plugin_init (RzCore* core) {
    if (!core) {
        DISPLAY_ERROR ("Invalid rizin core provided. Cannot initialize plugin.");
        return false;
    }

    LogInit (true);

    rzshell_cmddescs_init (core);
    return true;
}

RZ_IPI bool rz_plugin_fini (RzCore* core) {
    if (!core) {
        DISPLAY_ERROR ("Invalid rizin core provided. Failed to free plugin resources.");
        return false;
    }

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
    .version = "v2+ai_decomp:may21",
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
