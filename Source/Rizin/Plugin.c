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
#include <rz_util/rz_sys.h>
#include <stdarg.h>

/* local includes */
#include "CmdGen/Output/CmdDescs.h"
#include "Plugin.h"

#define BACKGROUND_WORKER_UPDATE_INTERVAL 2

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
 * @param core
 *
 * @return @c ReaiFnInfoVec reference on success.
 * @return @c Null otherwise.
 *  */
ReaiFnInfoVec* reai_plugin_get_fn_boundaries (RzCore* core) {
    RETURN_VALUE_IF (!core, Null, ERR_INVALID_ARGUMENTS);

    /* prepare symbols info  */
    RzList*        fns           = core->analysis->fcns;
    ReaiFnInfoVec* fn_boundaries = reai_fn_info_vec_create();

    /* add all symbols corresponding to functions */
    RzListIter*         fn_iter = Null;
    RzAnalysisFunction* fn      = Null;
    rz_list_foreach (fns, fn_iter, fn) {
        ReaiFnInfo fn_info = {
            .name  = fn->name,
            .vaddr = fn->addr,
            .size  = rz_analysis_function_linear_size (fn)
        };

        if (!reai_fn_info_vec_append (fn_boundaries, &fn_info)) {
            reai_fn_info_vec_destroy (fn_boundaries);
            return Null;
        }
    }

    return fn_boundaries;
}

/**
 * @b Background worker thread that updates the DB and other required things
 * in the background periodically.
 * */
PRIVATE void reai_db_background_worker (ReaiPlugin* plugin) {
    RETURN_IF (!plugin, ERR_INVALID_ARGUMENTS);

    Reai* reai = reai_create (plugin->reai_config->host, plugin->reai_config->apikey);
    RETURN_IF (!reai, "Background worker failed to make connection with RevEng.AI servers.");

    reai_set_db (reai, plugin->reai_db);
    reai_set_logger (reai, plugin->reai_logger);

    while (True) {
        if (plugin) {
            reai_update_all_analyses_status_in_db (reai);
        }

        rz_sys_sleep (BACKGROUND_WORKER_UPDATE_INTERVAL);
    }
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

    /* initialize reai object. */
    reai() = reai_create (reai_config()->host, reai_config()->apikey);
    RETURN_VALUE_IF (!reai(), False, "Failed to create Reai object.");

    /* create log directory if not present before creating new log files */
    rz_sys_mkdirp (reai_config()->log_dir_path);

    /* create logger */
    reai_logger() = reai_log_create (Null);
    RETURN_VALUE_IF (
        !reai_logger() || !reai_set_logger (reai(), reai_logger()),
        False,
        "Failed to create and set Reai logger."
    );

    /* create response object */
    reai_response() = reai_response_init ((reai_response() = NEW (ReaiResponse)));
    RETURN_VALUE_IF (!reai_response(), False, "Failed to create/init ReaiResponse object.");

    /* create the database directory if not present before creating/opening database */
    rz_sys_mkdirp (reai_config()->db_dir_path);

    /* create database and set it to reai database */
    Size db_path_strlen = snprintf (Null, 0, "%s/reai.db", reai_config()->db_dir_path) + 1;
    Char db_path[db_path_strlen];
    snprintf (db_path, db_path_strlen, "%s/reai.db", reai_config()->db_dir_path);

    reai_db() = reai_db_create (db_path);
    RETURN_VALUE_IF (
        !reai_db() || !reai_set_db (reai(), reai_db()),
        False,
        "Failed to create and set Reai DB object."
    );

    reai_plugin()->background_worker =
        rz_th_new ((RzThreadFunction)reai_db_background_worker, reai_plugin());
    RETURN_VALUE_IF (
        !reai_plugin()->background_worker,
        False,
        "Failed to start RevEng.AI background worker."
    );

    /* initialize command descriptors */
    rzshell_cmddescs_init (core);

    return True;
}

/**
 * @b Will be called by rizin before unloading the reai_plugin()->
 * */
RZ_IPI Bool reai_plugin_fini (RzCore* core) {
    RETURN_VALUE_IF (!core, False, ERR_INVALID_ARGUMENTS);

    if (reai_plugin()->background_worker) {
        rz_th_free (reai_plugin()->background_worker);
        reai_plugin()->background_worker = Null;
    }

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
