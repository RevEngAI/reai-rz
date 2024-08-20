/**
 * @file : CmdHandlers.c
 * @date : 13th June 2024
 * @author : Siddharth Mishra (admin@brightprogrammer.in)
 * @copyright: Copyright (c) 2024 RevEngAI. All Rights Reserved.
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
#include <Reai/Api/Api.h>
#include <Reai/Common.h>
#include <Reai/Config.h>
#include <Reai/Db.h>
#include <Reai/Log.h>
#include <Reai/Types.h>

/* libc */
#include <rz_util/rz_sys.h>
#include <stdarg.h>

/* plugin includes */
#include <Plugin.h>

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

    Size update_interval = 4;

    Reai* reai = reai_create (
        plugin->reai_config->host,
        plugin->reai_config->apikey,
        plugin->reai_config->model
    );
    RETURN_IF (!reai, "Background worker failed to make connection with RevEng.AI servers.");

    /* we're allowed to use same db as long as the concurrency method is sequential */
    reai_set_db (reai, plugin->reai_db);
    reai_set_logger (reai, plugin->reai_logger);

    /* this is a HACK to signal the thread to stop */
    while (plugin->reai) {
        if (plugin) {
            reai_update_all_analyses_status_in_db (reai);
        }

        rz_sys_sleep (update_interval);
    }

    reai_destroy (reai);
}

/**
 * @brief Called by rizin when loading reai_plugin()-> This is the plugin entrypoint where we
 * register all the commands and corresponding handlers.
 *
 * To know about how commands work for this plugin, refer to `CmdGen/README.md`.
 * */
Bool reai_plugin_init (RzCore* core) {
    RETURN_VALUE_IF (!core, False, ERR_INVALID_ARGUMENTS);

    /* load default config */
    reai_config() = reai_config_load (Null);
    if (!reai_config()) {
        reai_plugin_display_msg (
            REAI_LOG_LEVEL_FATAL,
            "Failed to load RevEng.AI toolkit config file. If does not exist then please use "
            "\"REi\" command & restart.\n"
        );

        return True;
    }

    /* initialize reai object. */
    reai() = reai_create (reai_config()->host, reai_config()->apikey, reai_config()->model);
    RETURN_VALUE_IF (!reai(), False, "Failed to create Reai object.");

    /* create log directory if not present before creating new log files */
    rz_sys_mkdirp (reai_config()->log_dir_path);

    /* create logger */
    reai_logger() = reai_log_create ((CString)Null);
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

    return True;
}

/**
 * @b Must be called before unloading the plugin.
 *
 * @param core
 *
 * @return True on successful plugin init.
 * @return False otherwise.
* */
Bool reai_plugin_deinit (RzCore* core) {
    RETURN_VALUE_IF (!core, False, ERR_INVALID_ARGUMENTS);

    /* this must be destroyed first and set to Null to signal the background worker
     * thread to stop working */
    if (reai()) {
        reai_destroy (reai());
        reai_plugin()->reai = Null;
    }

    if (reai_plugin()->background_worker) {
        rz_th_wait (reai_plugin()->background_worker);
        rz_th_free (reai_plugin()->background_worker);
        reai_plugin()->background_worker = Null;
    }

    if (reai_db()) {
        reai_db_destroy (reai_db());
        reai_plugin()->reai_db = Null;
    }

    if (reai_logger()) {
        reai_log_destroy (reai_logger());
        reai_plugin()->reai_logger = Null;
    }

    if (reai_response()) {
        reai_response_deinit (reai_response());
        FREE (reai_response());
    }

    if (reai_config()) {
        reai_config_destroy (reai_config());
    }

    return True;
}
