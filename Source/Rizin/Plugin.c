/**
 * @file : CmdHandlers.c
 * @date : 13th June 2024
 * @author : Siddharth Mishra (admin@brightprogrammer.in)
 * @copyright: Copyright (c) 2024 Siddharth Mishra. All Rights Reserved.
 *
 * @brief Main plugin entry point.
 * */

#include <rz_analysis.h>
#include <rz_asm.h>
#include <rz_core.h>
#include <rz_lib.h>
#include <rz_types.h>

/* revengai */
#include <Reai/Api/Api.h>
#include <Reai/Common.h>
#include <Reai/Types.h>

/* local includes */
#include "CmdGen/Output/CmdDescs.h"

/* global state required by reai command handlers and other methods */
Reai* _reai = Null;
ReaiResponse* _reai_response = Null;

RZ_IPI Bool reai_plugin_analysis(RzCore* core)
{
    rz_return_val_if_fail(core, False);
    return True;
}

/**
 * @brief Called by rizin when loading plugin. This is the plugin entrypoint where we
 * register all the commands and corresponding handlers.
 *
 * To know about how commands work for this plugin, refer to `CmdGen/README.md`.
 * */
RZ_IPI Bool reai_plugin_init(RzCore* core)
{
    rz_return_val_if_fail(core, False);

    /* initialize Reai objects. */
    _reai = reai_create(HARDCODED_HOST, HARDCODED_API_KEY);
    _reai_response = reai_response_init(NEW(ReaiResponse));

    rz_return_val_if_fail(_reai && _reai_response, RZ_CMD_STATUS_ERROR);

    /* initialize command descriptors */
    rzshell_cmddescs_init(core);

    return True;
}

RZ_IPI Bool reai_plugin_fini(RzCore* core)
{
    rz_return_val_if_fail(core, False);

    if (_reai) {
        reai_destroy(_reai);
    }

    if (_reai_response) {
        reai_response_deinit(_reai_response);
        FREE(_reai_response);
    }

    /* remove command group from rzshell */
    RzCmd* rcmd = core->rcmd;
    RzCmdDesc* reai_cmd_desc = rz_cmd_get_desc(rcmd, "reai");
    return rz_cmd_desc_remove(rcmd, reai_cmd_desc);
}

RzCorePlugin core_plugin_reai = {
    .name = "reai_rizin",
    .author = "Siddharth Mishra",
    .desc = "Reai Rizin Analysis Plugin",
    .license = "Copyright (c) 2024 Siddharth Mishra. All Rights Reserved.",
    .version = "0.0",
    .init = (RzCorePluginCallback)reai_plugin_init,
    .fini = (RzCorePluginCallback)reai_plugin_fini,
    .analysis = (RzCorePluginCallback)reai_plugin_analysis,
};

#ifdef _MSC_VER
#define RZ_EXPORT __declspec(dllexport)
#else
#define RZ_EXPORT
#endif

#ifndef CORELIB
RZ_EXPORT RzLibStruct rizin_plugin = {
    .type = RZ_LIB_TYPE_CORE,
    .data = &core_plugin_reai,
    .version = RZ_VERSION,
};
#endif
