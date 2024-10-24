/**
 * @file : CmdHandlers.c
 * @date : 13th June 2024
 * @author : Siddharth Mishra (admin@brightprogrammer.in)
 * @copyright: Copyright (c) 2024 RevEngAI. All Rights Reserved.
 * */

/* rizin */
#include "Reai/Api/Response.h"
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
#include <signal.h>

/* plugin includes */
#include <Plugin.h>
#include <Table.h>

PRIVATE void handle_signal (Int32 signal_code) {
    UNUSED (signal_code);

    LOG_TRACE ("Entered signal handler. This is backup code and I'll try to get you a save exit.");
    LOG_TRACE ("Received signal code : %d", signal_code);

    reai_plugin_deinit (NULL);
    exit (1);
}

PRIVATE void set_signal_handlers() {
    static Bool signals_set = false;
    if (signals_set) {
        return;
    }

    signal (SIGSEGV, handle_signal);
    signal (SIGILL, handle_signal);
    signal (SIGABRT, handle_signal);

    signals_set = true;
}

/**
 * @b Get name of function with given origin function id having max
 *    confidence.
 *
 * If multiple functions have same confidence level then the one that appears
 * first in the array will be returned.
 *
 * Returned pointer is not to be freed because it is owned by given @c fn_matches
 * vector. Destroying the vector will automatically free the returned string.
 *
 * @param fn_matches Array that contains all functions with their confidence levels.
 * @param origin_fn_id Function ID to search for.
 * @param confidence Pointer to @c Float64 value specifying min confidence level.
 *        If not @c NULL then value of max confidence of returned function name will
 *        be stored in this pointer.
 *        If @c NULL then just the function with max confidence will be selected.
 *
 * @return @c Name of function if present and has a confidence level greater than or equal to
 *            given confidence.
 * @return @c NULL otherwise.
 * */
PRIVATE CString get_function_name_with_max_confidence (
    ReaiAnnFnMatchVec *fn_matches,
    ReaiFunctionId     origin_fn_id,
    Float64           *required_confidence
) {
    if (!fn_matches) {
        DISPLAY_ERROR ("Function matches are invalid. Cannot proceed.");
        return NULL;
    }

    if (!origin_fn_id) {
        DISPLAY_ERROR ("Origin function ID is invalid. Cannot proceed.");
        return NULL;
    }

    Float64 max_confidence = 0;
    CString fn_name        = NULL;
    REAI_VEC_FOREACH (fn_matches, fn_match, {
        /* if function name starts with FUN_ then no need to rename */
        if (!strncmp (fn_match->nn_function_name, "FUN_", 4)) {
            continue;
        }

        /* otherwise find function with max confidence */
        if ((fn_match->confidence > max_confidence) &&
            (fn_match->origin_function_id == origin_fn_id)) {
            fn_name        = fn_match->nn_function_name;
            max_confidence = fn_match->confidence;
        }
    });

    if (required_confidence) {
        fn_name              = max_confidence >= *required_confidence ? fn_name : NULL;
        *required_confidence = max_confidence;
    }

    return fn_name;
}

/**
 * @b Get function infos for given binary id.
 *
 * The returned vector must be destroyed after use.
 *
 * @param bin_id
 *
 * @return @c ReaiFnInfoVec on success.
 * @return @c NULL otherwise.
 * */
PRIVATE ReaiFnInfoVec *get_fn_infos (ReaiBinaryId bin_id) {
    if (!bin_id) {
        DISPLAY_ERROR (
            "Invalid binary ID provied. Cannot fetch function info list from RevEng.AI servers."
        );
        return NULL;
    }

    /* get function names for all functions in the binary (this is why we need analysis) */
    ReaiFnInfoVec *fn_infos = reai_get_basic_function_info (reai(), reai_response(), bin_id);
    if (!fn_infos) {
        DISPLAY_ERROR ("Failed to get binary function names.");
        return NULL;
    }

    if (!fn_infos->count) {
        DISPLAY_ERROR ("Current binary does not have any function.");
        return NULL;
    }

    /* try cloning */
    fn_infos = reai_fn_info_vec_clone_create (fn_infos);
    if (!fn_infos) {
        DISPLAY_ERROR ("FnInfos vector clone failed");
        return NULL;
    }

    return fn_infos;
}

/**
 * @b Get function matches for given binary id.
 *
 * The returned vector must be destroyed after use.
 *
 * @param bin_id
 * @param max_results
 * @param max_dist
 * @param collections
 *
 * @return @c ReaiAnnFnMatchVec on success.
 * @return @c NULL otherwise.
 * */
PRIVATE ReaiAnnFnMatchVec *get_fn_matches (
    ReaiBinaryId bin_id,
    Uint32       max_results,
    Float64      max_dist,
    CStrVec     *collections
) {
    if (!bin_id) {
        DISPLAY_ERROR ("Invalid binary ID provided. Cannot get function matches.");
        return NULL;
    }

    ReaiAnnFnMatchVec *fn_matches = reai_batch_binary_symbol_ann (
        reai(),
        reai_response(),
        bin_id,
        max_results,
        max_dist,
        collections
    );

    if (!fn_matches) {
        DISPLAY_ERROR ("Failed to get ANN binary symbol similarity result");
        return NULL;
    }

    if (!fn_matches->count) {
        DISPLAY_ERROR ("No similar functions found.");
        return NULL;
    }

    /* try clone */
    fn_matches = reai_ann_fn_match_vec_clone_create (fn_matches);
    if (!fn_matches) {
        DISPLAY_ERROR ("ANN Fn Match vector clone failed.");
        return NULL;
    }

    return fn_matches;
}
/**
 * Get Reai Plugin object.
 * */
ReaiPlugin *reai_plugin() {
    static ReaiPlugin *plugin = NULL;

    if (plugin) {
        return plugin;
    }

    if (!(plugin = NEW (ReaiPlugin))) {
        DISPLAY_ERROR (ERR_OUT_OF_MEMORY);
        return NULL;
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
 * @return @c NULL otherwise.
 *  */
ReaiFnInfoVec *reai_plugin_get_function_boundaries (RzCore *core) {
    if (!core) {
        DISPLAY_ERROR ("Invalid rizin core provided. Cannot get function boundaries.");
        return NULL;
    }


    /* prepare symbols info  */
    RzList        *fns           = rz_analysis_function_list (core->analysis);
    ReaiFnInfoVec *fn_boundaries = reai_fn_info_vec_create();

    /* add all symbols corresponding to functions */
    RzListIter         *fn_iter = NULL;
    RzAnalysisFunction *fn      = NULL;
    rz_list_foreach (fns, fn_iter, fn) {
        ReaiFnInfo fn_info = {
            .name  = fn->name,
            .vaddr = fn->addr,
            .size  = rz_analysis_function_linear_size (fn)
        };

        if (!reai_fn_info_vec_append (fn_boundaries, &fn_info)) {
            DISPLAY_ERROR ("Failed to append function info in function boundaries list.");
            reai_fn_info_vec_destroy (fn_boundaries);
            return NULL;
        }
    }

    return fn_boundaries;
}

/**
 * @b Background worker thread that updates the DB and other required things
 * in the background periodically.
 * */
PRIVATE void reai_db_background_worker (ReaiPlugin *plugin) {
    if (!plugin) {
        DISPLAY_ERROR ("Invalid plugin instance provided. Cannot start background worker.");
        return;
    }

    Size update_interval = 4;

    Reai *reai = reai_create (
        plugin->reai_config->host,
        plugin->reai_config->apikey,
        plugin->reai_config->model
    );

    if (!reai) {
        DISPLAY_ERROR ("Background worker failed to make connection with RevEng.AI servers.");
        return;
    }

    /* we're allowed to use same db as long as the concurrency method is
   * sequential */
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
 * @brief Called by rizin when loading reai_plugin()-> This is the plugin
 * entrypoint where we register all the commands and corresponding handlers.
 *
 * To know about how commands work for this plugin, refer to `CmdGen/README.md`.
 * */
Bool reai_plugin_init (RzCore *core) {
    set_signal_handlers();

    if (!core) {
        DISPLAY_ERROR ("Invalid rizin core provided. Cannot initialize plugin.");
        return false;
    }

    /* load default config */
    reai_config() = reai_config_load (NULL);
    if (!reai_config()) {
        DISPLAY_ERROR (
            "Failed to load RevEng.AI toolkit config file. Please make sure the config exists or "
            "create a config using the plugin."
        );
        return false;
    }

    /* initialize reai object. */
    reai() = reai_create (reai_config()->host, reai_config()->apikey, reai_config()->model);
    if (!reai()) {
        DISPLAY_ERROR ("Failed to create Reai object.");
        return false;
    }

    /* create log directory if not present before creating new log files */
    rz_sys_mkdirp (reai_config()->log_dir_path);

    /* get current time */
    Char current_time[64] = {0};
    strftime (
        current_time,
        sizeof (current_time),
        "y%Y_m%m_d%d_h%H_m%M_s%S",
        localtime (&((time_t) {time (NULL)}))
    );

    /* create log file name */
    FMT (log_file_path, "%s/reai_%s.log", reai_config()->log_dir_path, current_time);

    /**
     * Note : This is not the best approach here, because the log will miss out any error that happened
     * before or during log creation. It is only after the logger is created, the logger will start capturing
     * all all traces and debugs.
     *
     * Since this works for now, let's just use it this way. Besides, if anything goes wrong before this,
     * it's possible that user will see a debug message on screen. We're sacrificing a very small segment
     * of log for this simplicity.
     * */

    /* create logger */
    reai_logger() = reai_log_create (log_file_path);
    if (!reai_logger() || !reai_set_logger (reai(), reai_logger())) {
        FREE(log_file_path);
        DISPLAY_ERROR ("Failed to create and set Reai logger.");
        return false;
    }

    FREE(log_file_path);

    /* create response object */
    reai_response() = reai_response_init ((reai_response() = NEW (ReaiResponse)));
    if (!reai_response()) {
        DISPLAY_ERROR ("Failed to create/init ReaiResponse object.");
        return false;
    }

    /* create the database directory if not present before creating/opening
   * database */
    rz_sys_mkdirp (reai_config()->db_dir_path);

    /* create database file name */
    FMT (db_path, "%s/reai.db", reai_config()->db_dir_path);

    /* create database and set it to reai database */
    reai_db() = reai_db_create (db_path);
    if (!reai_db() || !reai_set_db (reai(), reai_db())) {
        FREE(db_path);
        DISPLAY_ERROR ("Failed to create and set Reai DB object.");
        return false;
    }

    FREE(db_path);

    reai_plugin()->background_worker =
        rz_th_new ((RzThreadFunction)reai_db_background_worker, reai_plugin());

    if (!reai_plugin()->background_worker) {
        DISPLAY_ERROR ("Failed to start RevEng.AI background worker.");
        return false;
    }

    return true;
}

/**
 * @b Must be called before unloading the plugin.
 *
 * @param core
 *
 * @return true on successful plugin init.
 * @return false otherwise.
 * */
Bool reai_plugin_deinit (RzCore *core) {
    if (!core) {
        DISPLAY_WARN ("Invalid core provided. Some of the resources might not get freed.");
    }

    /* this must be destroyed first and set to NULL to signal the background
   * worker thread to stop working */
    if (reai()) {
        reai_destroy (reai());
        reai_plugin()->reai = NULL;
    }

    if (core && reai_plugin()->background_worker) {
        rz_th_wait (reai_plugin()->background_worker);
        rz_th_free (reai_plugin()->background_worker);
        reai_plugin()->background_worker = NULL;
    }

    if (reai_db()) {
        reai_db_destroy (reai_db());
        reai_plugin()->reai_db = NULL;
    }

    if (reai_logger()) {
        reai_log_destroy (reai_logger());
        reai_plugin()->reai_logger = NULL;
    }

    if (reai_response()) {
        reai_response_deinit (reai_response());
        FREE (reai_response());
    }

    if (reai_config()) {
        reai_config_destroy (reai_config());
    }

    return true;
}

/**
 * @b Check whether or not the default config exists.
 *
 * @return @c true on success.
 * @return @c NULL otherwise.
 * */
Bool reai_plugin_check_config_exists() {
    /* CString reai_config_file_path = reai_config_get_default_path(); */

    /* /\* if file already exists then we don't make changes *\/ */
    /* FILE* reai_config_file = fopen (reai_config_file_path, "r"); */
    /* if (reai_config_file) { */
    /*     fclose (reai_config_file); */
    /*     return true; */
    /* } */

    return !!reai_config();
}

/**
 * @b Get default database path.
 *
 * @return Database directory path on success.
 * @return NULL otherwise
 * */
CString reai_plugin_get_default_database_dir_path() {
    static Bool    is_created = false;
    static CString path       = NULL;

    if (is_created) {
        return path;
    }

    FMT (buf, "%s/%s", reai_config_get_default_dir_path(), ".reai-rz");
    static Char static_buf[512] = {0};
    memcpy (static_buf, buf, strlen(buf));

    is_created = true;
    return (path = static_buf);
}

/**
 * @b Get default database path.
 *
 * @return Database directory path on success.
 * @return NULL otherwise
 * */
CString reai_plugin_get_default_log_dir_path() {
    static Bool    is_created = false;
    static CString path       = NULL;

    if (is_created) {
        return path;
    }

    FMT (buf, "%s/%s", reai_config_get_default_dir_path(), ".reai-rz/log");
    static Char static_buf[512] = {0};
    memcpy (static_buf, buf, strlen (buf));

    is_created = true;
    return (path = static_buf);
}

/**
 * @b Save given config to a file.
 *
 * @param host
 * @param api_key
 * @param model
 * @param db_dir_path
 * @param log_dir_path
 * */
Bool reai_plugin_save_config (
    CString host,
    CString api_key,
    CString model,
    CString db_dir_path,
    CString log_dir_path
) {
    if (!host) {
        LOG_DEBUG ("%s %d", __FUNCTION__, __LINE__);
        DISPLAY_ERROR ("Provided host is invalid. Cannot save config.");
        return false;
    }

    if (!api_key) {
        LOG_DEBUG ("%s %d", __FUNCTION__, __LINE__);
        DISPLAY_ERROR ("Provided API key is invalid. Cannot save config.");
        return false;
    }

    if (!model) {
        LOG_DEBUG ("%s %d", __FUNCTION__, __LINE__);
        DISPLAY_ERROR ("Provided model is invalid. Cannot save config.");
        return false;
    }

    if (!db_dir_path) {
        LOG_DEBUG ("%s %d", __FUNCTION__, __LINE__);
        DISPLAY_ERROR ("Provided database directory path is invalid. Cannot save config.");
        return false;
    }

    if (!log_dir_path) {
        LOG_DEBUG ("%s %d", __FUNCTION__, __LINE__);
        DISPLAY_ERROR ("Provided log directory path is invalid. Cannot save config.");
        return false;
    }

    CString reai_config_file_path = reai_config_get_default_path();
    if (!reai_config_file_path) {
        LOG_DEBUG ("%s %d", __FUNCTION__, __LINE__);
        DISPLAY_ERROR ("Failed to get config file default path.");
        return false;
    }

    FILE *reai_config_file = fopen (reai_config_file_path, "w");
    if (!reai_config_file) {
        LOG_DEBUG ("%s %d", __FUNCTION__, __LINE__);
        DISPLAY_ERROR ("Failed to open config file. %s", strerror (errno));
        return false;
    }

    fprintf (reai_config_file, "host         = \"%s\"\n", host);
    fprintf (reai_config_file, "apikey       = \"%s\"\n", api_key);
    fprintf (reai_config_file, "model        = \"%s\"\n", model);
    fprintf (reai_config_file, "db_dir_path  = \"%s\"\n", db_dir_path);
    fprintf (reai_config_file, "log_dir_path = \"%s\"\n", log_dir_path);

    fclose (reai_config_file);

    return true;
}

/**
 * @b If a binary file is opened, then upload the binary file.
 *
 * @param core To get the currently opened binary file in rizin.
 *
 * @return true on successful upload.
 * @return false otherwise.
 * */
Bool reai_plugin_upload_opened_binary_file (RzCore *core) {
    if (!core) {
        DISPLAY_ERROR ("Invalid rizin core provided. Cannot perform upload.");
        return false;
    }

    /* get file path */
    CString binfile_path = reai_plugin_get_opened_binary_file_path (core);
    if (!binfile_path) {
        DISPLAY_ERROR ("No binary file opened in rizin. Cannot perform upload.");
        return false;
    }

    /* check if file is already uploaded or otherwise upload */
    CString sha256 = reai_db_get_latest_hash_for_file_path (reai_db(), binfile_path);
    if (!sha256) {
        sha256 = reai_upload_file (reai(), reai_response(), binfile_path);
        if (!sha256) {
            DISPLAY_ERROR ("Failed to upload binary file.");
            FREE (binfile_path);
            return false;
        }
    } else {
        LOG_INFO ("File already uploaded (and recorded in db) with hash = \"%s\"", sha256);
    }

    FREE (binfile_path);
    return true;
}

/**
 * @b Create a new analysis for currently opened binary file.
 *
 * This method first checks whether upload already exists for a given file path.
 * If upload does exist then the existing upload is used.
 * TODO: this needs to be refactored. Check trello "General Refactoring".
 *
 * @param core To get currently opened binary file in rizin/cutter.
 *
 * @return true on success.
 * @return false otherwise.
 * */
Bool reai_plugin_create_analysis_for_opened_binary_file (RzCore *core) {
    if (!core) {
        DISPLAY_ERROR ("Invalid rizin core provided. Cannot create analysis.");
        return false;
    }

    RzBinFile *binfile = reai_plugin_get_opened_binary_file (core);
    if (!binfile) {
        DISPLAY_ERROR ("No binary file opened. Cannot create analysis");
        return false;
    }

    CString binfile_path = reai_plugin_get_opened_binary_file_path (core);
    if (!binfile_path) {
        DISPLAY_ERROR ("Failed to get binary file full path. Cannot create analysis");
        return false;
    }

    /* check if file is already uploaded or otherwise upload */
    CString sha256 = reai_db_get_latest_hash_for_file_path (reai_db(), binfile_path);
    if (!sha256) {
        LOG_INFO ("Binary not already uploaded. Uploading...");

        /* try uploading file */
        sha256 = reai_upload_file (reai(), reai_response(), binfile_path);

        /* check whether upload worked */
        if (!sha256) {
            DISPLAY_ERROR ("Failed to upload file");
            FREE (binfile_path);
            return false;
        }

        /* make clone because making any new request will free the memory */
        if (!(sha256 = strdup (sha256))) {
            DISPLAY_ERROR ("Memory allocation failure.");
            FREE (binfile_path);
            return false;
        }

        LOG_INFO ("Binary uploaded successfully.");
    } else {
        LOG_INFO ("Using previously uploaded file with latest hash = \"%s\"", sha256);
    }

    /* warn the use if no analysis exists */
    /* NOTE: this might not be the best way to check whether an analysis exists or
   * not. */
    if (!reai_plugin_get_rizin_analysis_function_count (core)) {
        DISPLAY_ERROR (
            "It seems that rizin analysis hasn't been performed yet. "
            "Please create rizin analysis "
            "first."
        );
        FREE (sha256);
        FREE (binfile_path);
        return false;
    }

    /* get function boundaries to create analysis */
    ReaiFnInfoVec *fn_boundaries = reai_plugin_get_function_boundaries (core);
    if (!fn_boundaries) {
        DISPLAY_ERROR (
            "Failed to get function boundary information from rizin "
            "analysis. Cannot create "
            "RevEng.AI analysis."
        );
        FREE (sha256);
        FREE (binfile_path);
        return false;
    }

    /* ZENDBG_CHECK (reai_plugin_get_ai_model_for_opened_binary_file (core)); */
    /* ZENDBG_CHECK (reai_plugin_get_opened_binary_file_baseaddr (core)); */

    /* create analysis */
    ReaiBinaryId bin_id = reai_create_analysis (
        reai(),
        reai_response(),
        reai_plugin_get_ai_model_for_opened_binary_file (core),
        reai_plugin_get_opened_binary_file_baseaddr (core),
        fn_boundaries,
        true,
        sha256,
        rz_file_basename (binfile_path),
        NULL,
        binfile->size
    );

    if (!bin_id) {
        DISPLAY_ERROR ("Failed to create RevEng.AI analysis.");
        FREE (sha256);
        FREE (binfile_path);
        reai_fn_info_vec_destroy (fn_boundaries);
        return false;
    }

    /* destroy after use */
    FREE (sha256);
    FREE (binfile_path);
    reai_fn_info_vec_destroy (fn_boundaries);

    return true;
}

/**
 * @b Get binary id (analysis id) for opened binary file.
 *
 * @param core To get currently opened binary file in rizin/cutter.
 *
 * @return Non zero @c ReaiBinaryId on success.
 * @return 0 otherwise.
 * */
ReaiBinaryId reai_plugin_get_binary_id_for_opened_binary_file (RzCore *core) {
    if (!core) {
        DISPLAY_ERROR (
            "Invalid rizin core provided. Cannot get a binary id without "
            "a binary file."
        );
        return 0;
    }

    /* get opened binary file path */
    CString opened_binfile_path = reai_plugin_get_opened_binary_file_path (core);
    if (!opened_binfile_path) {
        DISPLAY_ERROR ("No binary file opeend.");
        return 0;
    }

    /* get binary id for opened binary file path by searching in local database */
    ReaiBinaryId binary_id = reai_db_get_latest_analysis_for_file (reai_db(), opened_binfile_path);
    FREE (opened_binfile_path);
    if (!binary_id) {
        DISPLAY_ERROR ("No analysis exists for currently opened binary in database.");
        return 0;
    }

    LOG_TRACE (
        "Using binary id of latest analysis for loaded binary present in "
        "database : %llu.",
        binary_id
    );

    return binary_id;
}

/**
 * @b Get analysis status for given binary id (analyis id).
 *
 * @param core
 *
 * @return @c ReaiAnalysisStatus other than @c REAI_ANALYSIS_STATUS_INVALID on
 * success.
 * @return @c REAI_ANALYSIS_STATUS_INVALID otherwise.
 * */
ReaiAnalysisStatus reai_plugin_get_analysis_status_for_binary_id (ReaiBinaryId binary_id) {
    if (!binary_id) {
        DISPLAY_ERROR ("Invalid binary id provided. Cannot fetch analysis status.");
        return REAI_ANALYSIS_STATUS_INVALID;
    }

    ReaiAnalysisStatus analysis_status = REAI_ANALYSIS_STATUS_INVALID;

    /* if analyses already exists in db */
    if (reai_db_check_analysis_exists (reai_db(), binary_id)) {
        LOG_TRACE ("Analysis already exists in database. Fetching status from database.");

        analysis_status = reai_db_get_analysis_status (reai_db(), binary_id);
        if (!analysis_status) {
            DISPLAY_ERROR (
                "Analysis records exist in local database but ailed to get "
                "analysis status from "
                "database."
            );
            return REAI_ANALYSIS_STATUS_INVALID;
        }
    } else {
        LOG_TRACE (
            "Analysis does not exist in database. Fetching status from "
            "RevEng.AI servers."
        );

        analysis_status = reai_get_analysis_status (reai(), reai_response(), binary_id);
        if (!analysis_status) {
            DISPLAY_ERROR ("Failed to get analysis status from RevEng.AI servers.");
            return REAI_ANALYSIS_STATUS_INVALID;
        }
    }

    LOG_TRACE ("Fetched analysis status \"%s\".", reai_analysis_status_to_cstr (analysis_status));
    return analysis_status;
}

/**
 * @b Automatically rename all funcitons with matching names.
 *
 * @param core To get currently opened binary file.
 * @param max_distance RevEng.AI function matching parameter.
 * @param max_results per function RevEng.AI function matching parameter.
 * @param max_distance RevEng.AI function matching parameter.
 * */
Bool reai_plugin_auto_analyze_opened_binary_file (
    RzCore *core,
    Float64 max_distance,
    Size    max_results_per_function,
    Float64 min_confidence
) {
    if (!core) {
        DISPLAY_ERROR ("Invalid rizin core provided. Cannot perform auto-analysis.");
        return false;
    }

    // get opened binary file and print error if no binary is loaded
    RzBinFile *binfile = reai_plugin_get_opened_binary_file (core);
    if (!binfile) {
        DISPLAY_ERROR ("No binary file opened. Cannot perform auto-analysis.");
        return false;
    }

    CString binfile_path = reai_plugin_get_opened_binary_file_path (core);
    if (!binfile_path) {
        DISPLAY_ERROR (
            "Failed to get opened binary file's full path. Cannot "
            "perform auto-analysis."
        );
        return false;
    }

    /* try to get latest analysis for loaded binary (if exists) */
    ReaiBinaryId bin_id = reai_db_get_latest_analysis_for_file (reai_db(), binfile_path);
    if (!bin_id) {
        DISPLAY_ERROR (
            "No RevEng.AI analysis exists for opened file. Please create "
            "an analysis first."
        );
        FREE (binfile_path);
        return false;
    }

    /* an analysis must already exist in order to make auto-analysis work */
    ReaiAnalysisStatus analysis_status = reai_db_get_analysis_status (reai_db(), bin_id);
    if (analysis_status != REAI_ANALYSIS_STATUS_COMPLETE) {
        DISPLAY_WARN (
            "Analysis not complete yet. Please wait for some time and "
            "then try again!"
        );
        FREE (binfile_path);
        return false;
    }

    /* names of current functions */
    ReaiFnInfoVec *fn_infos = get_fn_infos (bin_id);
    if (!fn_infos) {
        DISPLAY_ERROR ("Failed to get funciton info for opened binary.");
        FREE (binfile_path);
        return false;
    }

    /* function matches */
    ReaiAnnFnMatchVec *fn_matches =
        get_fn_matches (bin_id, max_results_per_function, max_distance, NULL);
    if (!fn_matches) {
        DISPLAY_ERROR ("Failed to get function matches for opened binary.");
        reai_fn_info_vec_destroy (fn_infos);
        FREE (binfile_path);
        return false;
    }

    /* new vector where new names of functions will be stored */
    ReaiFnInfoVec *new_name_mapping = reai_fn_info_vec_create();
    if (!new_name_mapping) {
        DISPLAY_ERROR ("Failed to create a new-name-mapping object.");
        reai_ann_fn_match_vec_destroy (fn_matches);
        reai_fn_info_vec_destroy (fn_infos);
        FREE (binfile_path);
        return false;
    }

    /* prepare table and print info */
    ReaiPluginTable *table = reai_plugin_table_create();
    if (!table) {
        DISPLAY_ERROR ("Failed to create table to display new name mapping.");
        reai_fn_info_vec_destroy (new_name_mapping);
        reai_ann_fn_match_vec_destroy (fn_matches);
        reai_fn_info_vec_destroy (fn_infos);
        FREE (binfile_path);
        return false;
    }
    reai_plugin_table_set_columnsf (
        table,
        "ssfsn",
        "old_name",
        "new_name",
        "confidence",
        "success",
        "address"
    );

    /* display information about what renames will be performed */ /* add rename information to new name mapping */
    /* rename the functions in rizin */
    REAI_VEC_FOREACH (fn_infos, fn, {
        Float64 confidence = min_confidence;
        CString new_name   = NULL;
        CString old_name   = fn->name;
        Uint64  fn_addr    = fn->vaddr + reai_plugin_get_opened_binary_file_baseaddr (core);

        /* if we get a match with required confidence level then we add to rename */
        if ((new_name = get_function_name_with_max_confidence (fn_matches, fn->id, &confidence))) {
            /* If functions already are same then no need to rename */
            if (!strcmp (new_name, old_name)) {
                if (!reai_plugin_table_add_rowf (
                        table,
                        "ssfsx",
                        old_name,
                        new_name,
                        (Float64)1.0,
                        "ok",
                        fn_addr
                    )) {
                    goto ROW_INSERT_FAILED;
                }
                continue;
            }

            /* if append fails then destroy everything and return error */
            Bool append = !!reai_fn_info_vec_append (
                new_name_mapping,
                &((ReaiFnInfo) {.name = new_name, .id = fn->id})
            );
            if (!append) {
                DISPLAY_ERROR ("Failed to append new name map.");
                goto ROW_INSERT_FAILED;
            }

            /* get function */
            RzAnalysisFunction *rz_fn = rz_analysis_get_function_at (core->analysis, fn->vaddr);
            if (rz_fn) {
                /* check if fucntion size matches */
                if (rz_analysis_function_linear_size (rz_fn) != fn->size) {
                    LOG_INFO (
                        "Function sizes don't match (\"%s\" - \"%s\")",
                        rz_fn->name,
                        fn->name
                    );
                }

                /* rename function */
                if (!rz_analysis_function_rename (rz_fn, new_name)) { // Try renaming in Rizin
                    if (!reai_plugin_table_add_rowf (
                            table,
                            "ssfsx",
                            old_name,
                            new_name,
                            confidence,
                            "rizin rename error",
                            fn_addr
                        )) {
                        goto ROW_INSERT_FAILED;
                    }
                } else { // If rename failed
                    if (!reai_plugin_table_add_rowf (
                            table,
                            "ssfsx",
                            old_name,
                            new_name,
                            confidence,
                            "true",
                            fn_addr
                        )) {
                        goto ROW_INSERT_FAILED;
                    }
                }
            } else { // If no Rizin funciton exists at given address
                if (!reai_plugin_table_add_rowf (
                        table,
                        "ssfsx",
                        old_name,
                        new_name,
                        (Float64)0.0,
                        "function not found",
                        fn_addr
                    )) {
                    goto ROW_INSERT_FAILED;
                }
            }
        } else { // If not able to find a function with given confidence
            if (!reai_plugin_table_add_rowf (
                    table,
                    "ssfsx",
                    old_name,
                    "n/a",
                    (Float64)0.0,
                    "match not found",
                    fn_addr
                )) {
                goto ROW_INSERT_FAILED;
            }
        }
    });

    reai_plugin_table_show (table);

    /* perform a batch rename */
    if (new_name_mapping->count) {
        Bool res = reai_batch_renames_functions (reai(), reai_response(), new_name_mapping);
        if (!res) {
            DISPLAY_ERROR ("Failed to rename all functions in binary");
        }
    } else {
        eprintf ("No function will be renamed.\n");
    }

    reai_plugin_table_destroy (table);
    reai_fn_info_vec_destroy (new_name_mapping);
    reai_ann_fn_match_vec_destroy (fn_matches);
    reai_fn_info_vec_destroy (fn_infos);
    FREE (binfile_path);

    return true;

ROW_INSERT_FAILED:
    DISPLAY_ERROR (
        "Failed to insert row into table. Failed to complete auto analysis due "
        "to internal error."
    );
    reai_plugin_table_destroy (table);
    reai_fn_info_vec_destroy (new_name_mapping);
    reai_ann_fn_match_vec_destroy (fn_matches);
    reai_fn_info_vec_destroy (fn_infos);
    FREE (binfile_path);

    return false;
}

/**
 * @b Search for function with given name and get the corresponding function id.
 *
 * @param core
 * @param fn_name
 *
 * @return Non-zero function ID corresponding to given function name on success, and if found.
 * @return zero otherwise.
 * */
ReaiFunctionId
    reai_plugin_get_function_id_for_rizin_function (RzCore *core, RzAnalysisFunction *rz_fn) {
    if (!core) {
        DISPLAY_ERROR (
            "Invalid rizin core provided. Cannot fetch function ID for given function name."
        );
        return 0;
    }

    if (!rz_fn || !rz_fn->name) {
        DISPLAY_ERROR ("Invalid Rizin function provided. Cannot get a function ID.");
        return 0;
    }

    ReaiBinaryId bin_id = reai_plugin_get_binary_id_for_opened_binary_file (core);
    if (!bin_id) {
        DISPLAY_ERROR ("Failed to get binary ID for opened binary file");
        return 0;
    }

    ReaiFnInfoVec *fn_infos = NULL;
    /* avoid making multiple calls subsequent calls to same endpoint if possible */
    if (reai_response()->type == REAI_RESPONSE_TYPE_BASIC_FUNCTION_INFO) {
        LOG_TRACE ("Using previously fetched response of basic function info.");

        fn_infos = reai_response()->basic_function_info.fn_infos;
    } else {
        LOG_TRACE ("Fetching basic function info again");

        fn_infos = reai_get_basic_function_info (reai(), reai_response(), bin_id);
        if (!fn_infos) {
            DISPLAY_ERROR (
                "Failed to get function info list for opened binary file from RevEng.AI servers."
            );
            return 0;
        }
    }

    REAI_VEC_FOREACH (fn_infos, fn_info, {
        if (rz_analysis_function_min_addr (rz_fn) <= fn_info->vaddr &&
            fn_info->vaddr <= rz_analysis_function_max_addr (rz_fn)) {
            LOG_TRACE (
                "Found function ID for rizin function \"%s\" (\"%s\"): [%llu]",
                rz_fn->name,
                fn_info->name,
                fn_info->id
            );
            return fn_info->id;
        }
    });

    LOG_TRACE ("Function ID not found for function \"%s\"", rz_fn->name);

    return 0;
}

/**
 * @b Get referfence to @c RzBinFile for currently opened binary file.
 *
 * @param core
 *
 * @return @c RzBinFile if a binary file is opened (on success).
 * @return @c NULL otherwise.
 * */
RzBinFile *reai_plugin_get_opened_binary_file (RzCore *core) {
    if (!core) {
        DISPLAY_ERROR ("Invalid rizin core provided. Cannot get opened binary file.");
        return NULL;
    }

    if (!core->bin) {
        DISPLAY_ERROR (
            "Seems like no binary file is opened yet. Binary container object is invalid. Cannot "
            "get opened binary file."
        );
        return NULL;
    }

    if (!core->bin->binfiles) {
        DISPLAY_ERROR (
            "Seems like no binary file is opened yet. Binary file list is invalid. Cannot "
            "get opened binary file."
        );
        return NULL;
    }

    if (!core->bin->binfiles->length) {
        DISPLAY_ERROR ("Seems like no binary file is opened yet. Cannot get opened binary file.");
        return NULL;
    }

    RzListIter *head = rz_list_head (core->bin->binfiles);
    if (!head) {
        DISPLAY_ERROR (
            "Cannot get object reference to currently opened binary file. Internal Rizin error."
        );
        return NULL;
    }

    return rz_list_iter_get_data (head);
}

/**
 * @b Get operating AI model to use with currently opened binary file.
 *
 * @param core
 *
 * @return @c REAI_MODEL_UNKNOWN on failure.
 * */
ReaiModel reai_plugin_get_ai_model_for_opened_binary_file (RzCore *core) {
    if (!core) {
        DISPLAY_ERROR ("Invalid rizin core provided. Cannot guess AI model.");
        return REAI_MODEL_UNKNOWN;
    }

    RzBinFile *binfile = reai_plugin_get_opened_binary_file (core);

    if (binfile && binfile->o && binfile->o->info && binfile->o->info->os) {
        CString os = binfile->o->info->os;
        if (!strcmp (os, "linux")) {
            return REAI_MODEL_X86_LINUX;
        } else if (!strncmp (os, "Windows", 7)) {
            return REAI_MODEL_X86_WINDOWS;
        } else if (!strcmp (os, "iOS") || !strcmp (os, "darwin")) {
            return REAI_MODEL_X86_MACOS;
        } else if (!strcmp (os, "android")) {
            return REAI_MODEL_X86_ANDROID;
        } else {
            return REAI_MODEL_UNKNOWN;
        }
    }

    return REAI_MODEL_UNKNOWN;
}

/**
 * @b Get path of currently opened binary file.
 *
 * The returned string is owned by caller and must be passed to FREE.
 *
 * @param core
 *
 * @return @c CString if a binary file is opened.
 * @return @c NULL otherwise.
 * */
CString reai_plugin_get_opened_binary_file_path (RzCore *core) {
    RzBinFile *binfile = reai_plugin_get_opened_binary_file (core);
    return binfile ? rz_path_realpath (binfile->file) : NULL;
}

/**
 * @b Get base address of currently opened binary file.
 *
 * @param core
 *
 * @return @c Base address if a binary file is opened.
 * @return @c 0 otherwise.
 * */
Uint64 reai_plugin_get_opened_binary_file_baseaddr (RzCore *core) {
    RzBinFile *binfile = reai_plugin_get_opened_binary_file (core);
    return binfile ? binfile->o->opts.baseaddr : 0;
}

/**
 * @b Get number of functions detected by rizin's own analysis.
 *
 * @param core To get analysis information.
 *
 * @return number of functions on success.
 * @return 0 otherwise.
 * */
Uint64 reai_plugin_get_rizin_analysis_function_count (RzCore *core) {
    if (!core) {
        DISPLAY_ERROR ("Invalid Rizin core provided. Cannot get analysis function count.");
        return 0;
    }

    if (!core->analysis) {
        DISPLAY_ERROR (
            "Seems like Rizin analysis is not performed yet. The analysis object is invalid. "
            "Cannot get "
            "analysis function count."
        );
        return 0;
    }

    RzList *fns = rz_analysis_function_list (core->analysis);
    if (!fns) {
        DISPLAY_ERROR (
            "Seems like Rizin analysis is not performed yet. Function list is invalid. Cannot get "
            "function with given name."
        );
        return 0;
    }

    return fns->length;
}

/**
 * @b Get reference to `RzAnalysisFunction` with given name.
 *
 * @param core Rizin core.
 * @param name Name of function to get reference of.
 *
 * @return `RzAnalyisFunction` on success.
 * @return NULL otherwise.
 * */
RzAnalysisFunction *reai_plugin_get_rizin_analysis_function_with_name (RzCore *core, CString name) {
    if (!core) {
        DISPLAY_ERROR ("Invalid Rizin core provided. Cannot get function with given name.");
        return NULL;
    }

    if (!name) {
        DISPLAY_ERROR ("Invalid function name provided. Cannot get function with given name.");
        return NULL;
    }

    if (!core->analysis) {
        DISPLAY_ERROR (
            "Seems like Rizin analysis is not performed yet. Analysis object is invalid. Cannot "
            "get function with given name."
        );
        return NULL;
    }

    RzList *fns = rz_analysis_function_list (core->analysis);
    if (!fns) {
        DISPLAY_ERROR (
            "Seems like Rizin analysis is not performed yet. Function list is invalid. Cannot get "
            "function with given name."
        );
        return NULL;
    }

    RzListIter         *fn_iter = NULL;
    RzAnalysisFunction *fn      = NULL;
    rz_list_foreach (fns, fn_iter, fn) {
        if (!fn->name) {
            LOG_ERROR (
                "Function at address 0x%016llx of size 0x%016llx has name=NULL.",
                fn->addr,
                rz_analysis_function_linear_size (fn)
            );
            continue;
        }

        if (!strcmp (fn->name, name)) {
            LOG_TRACE (
                "Found function with name \"%s\" at address 0x%016llx and has size 0x%016llx",
                name,
                fn->addr,
                rz_analysis_function_linear_size (fn)
            );
            return fn;
        }
    }

    LOG_TRACE ("Failed to find function with name \"%s\"", name);

    return NULL;
}
