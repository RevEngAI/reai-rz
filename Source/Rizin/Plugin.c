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
#include <rz_core.h>
#include <rz_lib.h>
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
#include <stdarg.h>

/* local includes */
#include "CmdGen/Output/CmdDescs.h"
#include "Plugin.h"

/**
 * Get Reai Plugin object.
 * */
ReaiPlugin* reai_plugin() {
    static ReaiPlugin* plugin = Null;

    if (!plugin) {
        RETURN_VALUE_IF (!(plugin = NEW (ReaiPlugin)), Null, ERR_OUT_OF_MEMORY);
    }

    return plugin;
}

/**
 * @b Get function boundaries from given binary file.
 *
 * @NOTE: returned vector is owned by the caller and hence is
 * responsible for destroying the vector after use.
 *
 * @param binfile
 *
 * @return @c ReaiFnInfoVec reference on success.
 * @return @c Null otherwise.
 *  */
ReaiFnInfoVec* reai_plugin_get_fn_boundaries (RzBinFile* binfile) {
    RETURN_VALUE_IF (!binfile, Null, ERR_INVALID_ARGUMENTS);

    /* prepare symbols info  */
    RzPVector*     psymbols      = binfile->o->symbols;
    ReaiFnInfoVec* fn_boundaries = reai_fn_info_vec_create();

    /* add all symbols corresponding to functions */
    void** psym = Null;
    rz_pvector_foreach (psymbols, psym) {
        RzBinSymbol* symbol = *(RzBinSymbol**)psym;

        /* if symbol is of function type */
        if (!strcmp (symbol->type, "FUNC") && symbol->name) {
            ReaiFnInfo fn_info = {
                .name  = symbol->name,
                .vaddr = symbol->vaddr,
                .size  = symbol->size
            };

            if (!reai_fn_info_vec_append (fn_boundaries, &fn_info)) {
                reai_fn_info_vec_destroy (fn_boundaries);
                return Null;
            }

            LOG_TRACE (
                "FUNCTION .name = %16s, .vaddr = 0x%08llx, .size = 0x%08llx",
                fn_info.name,
                fn_info.vaddr,
                fn_info.size
            );
        }
    }

    return fn_boundaries;
}

/**
 * @brief Called by rizin when loading reai_plugin()-> This is the plugin entrypoint where we
 * register all the commands and corresponding handlers.
 *
 * To know about how commands work for this plugin, refer to `CmdGen/README.md`.
 * */
RZ_IPI Bool reai_plugin_init (RzCore* core) {
    RETURN_VALUE_IF (!core, False, ERR_INVALID_ARGUMENTS);

    /* load default config */
    reai_config() = reai_config_load (Null);
    RETURN_VALUE_IF (!reai_config(), False, "Failed to load RevEng.AI toolkit config file.");

    /* create logger */
    reai_logger() = reai_log_create (Null);
    RETURN_VALUE_IF (!reai_logger(), False, "Failed to create Reai logger.");

    /* initialize reai object. */
    reai() = reai_create (reai_config()->host, reai_config()->apikey);
    RETURN_VALUE_IF (!reai(), False, "Failed to create Reai object.");

    /* create response object */
    reai_response() = reai_response_init ((reai_response() = NEW (ReaiResponse)));
    RETURN_VALUE_IF (!reai_response(), False, "Failed to create/init ReaiResponse object.");

    /* create database and set it to reai database */
    Size db_path_strlen = snprintf (Null, 0, "%s/reai.db", reai_config()->db_dir_path) + 1;
    Char db_path[db_path_strlen];
    snprintf (db_path, db_path_strlen, "%s/reai.db", reai_config()->db_dir_path);

    reai_db() = reai_db_create (db_path);
    RETURN_VALUE_IF (!reai_db(), False, "Failed to create Reai DB object.");
    reai_set_db (reai(), reai_db());

    /* initialize command descriptors */
    rzshell_cmddescs_init (core);

    return True;
}

/**
 * @b Will be called by rizin before unloading the reai_plugin()->
 * */
RZ_IPI Bool reai_plugin_fini (RzCore* core) {
    RETURN_VALUE_IF (!core, False, ERR_INVALID_ARGUMENTS);

    if (reai_response()) {
        reai_response_deinit (reai_response());
        FREE (reai_response());
    }

    if (reai()) {
        reai_destroy (reai());
    }

    if (reai_config()) {
        reai_config_destroy (reai_config());
    }

    if (reai_logger()) {
        reai_log_destroy (reai_logger());
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
    .desc    = "Reai Rizin Analysis Plugin",
    .license = "Copyright (c) 2024 RevEngAI. All Rights Reserved.",
    .version = "0.0",
    .init    = (RzCorePluginCallback)reai_plugin_init,
    .fini    = (RzCorePluginCallback)reai_plugin_fini,
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
