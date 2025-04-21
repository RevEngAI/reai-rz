/**
 * @file : CmdHandlers.c
 * @date : 13th June 2024
 * @author : Siddharth Mishra (admin@brightprogrammer.in)
 * @copyright: Copyright (c) 2024 RevEngAI. All Rights Reserved.
 * */

/* rizin */
#include <Reai/Api/Request.h>
#include <rz_analysis.h>
#include <rz_asm.h>
#include <rz_cmd.h>
#include <rz_core.h>
#include <rz_lib.h>
#include <rz_th.h>
#include <rz_types.h>
#include <rz_util/rz_annotated_code.h>

/* revengai */
#include <Reai/AnalysisInfo.h>
#include <Reai/Api/Api.h>
#include <Reai/Common.h>
#include <Reai/Config.h>
#include <Reai/Log.h>
#include <Reai/Types.h>

/* libc */
#include <rz_util/rz_str.h>
#include <rz_util/rz_sys.h>

/* plugin includes */
#include <Plugin.h>
#include <Table.h>
#include <stdlib.h>

/**
 * NOTE: This is a background worker. Must not be used directly.
 * */
void *get_ai_models_in_bg (void *user) {
    ReaiPlugin *plugin = user;

    while (plugin->locked)
        ;

    plugin->locked = true;
    REAI_LOG_TRACE ("Plugin lock acquired");

    if (!plugin->ai_models) {
        plugin->ai_models = reai_cstr_vec_clone_create (
            reai_get_available_models (plugin->reai, plugin->reai_response)
        );

        if (plugin->ai_models) {
            REAI_LOG_TRACE ("Got the AI models");
        } else {
            REAI_LOG_ERROR (
                "Failed to get AI models. This might cause some features to fail working."
            );
        }
    }

    plugin->locked = false;
    REAI_LOG_TRACE ("Plugin lock released");

    return NULL;
}

void *perform_auth_check_in_bg (void *user) {
    ReaiPlugin *plugin = user;

    while (plugin->locked)
        ;

    plugin->locked = true;
    REAI_LOG_TRACE ("Plugin lock acquired");

    if (reai_auth_check (
            plugin->reai,
            plugin->reai_response,
            plugin->reai_config->host,
            plugin->reai_config->apikey
        )) {
        REAI_LOG_TRACE ("Auth check success");
    } else {
        REAI_LOG_ERROR (
            "RevEngAI auth check failed. You won't be able to use any of the plugin features!"
        );
    }

    plugin->locked = false;
    REAI_LOG_TRACE ("Plugin lock released");

    return NULL;
}

// TODO: remove this in next rizin release
const char *rizin_analysis_function_force_rename (RzAnalysisFunction *fcn, CString name) {
    rz_return_val_if_fail (fcn && name, NULL);

    // first attempt to rename normally, if that fails we try force rename
    if (rz_analysis_function_rename (fcn, name)) {
        return fcn->name;
    }

    // {name}_{addr} is guaranteed to be unique
    const char *new_name = rz_str_newf ("%s_%" PFMT64x, name, fcn->addr);
    bool        ok       = rz_analysis_function_rename (fcn, new_name);
    RZ_FREE (new_name);
    return ok ? fcn->name : NULL;
}

/**
 * @b Get name of function with given origin function id having similarity.
 *
 * If multiple functions have same similarity level then the one that appears
 * first in the array will be returned.
 *
 * Returned pointer MUST NOT freed because it is owned by given @c fn_matches
 * vector. Destroying the vector will automatically free the returned string.
 *
 * @param fn_matches Array that contains all functions with their similarity levels.
 * @param origin_fn_id Function ID to search for.
 * @param required_similarity Pointer to @c Float64 value specifying min similarity level.
 *        If not @c NULL then value of max similarity of returned function name will
 *        be stored in this pointer.
 *        This is a required argument.
 *
 * @return @c Pointer to an item from the provided vector on success. 
 * @return @c NULL otherwise.
 * */
PRIVATE ReaiAnnFnMatch *get_function_match_with_similarity (
    ReaiAnnFnMatchVec *fn_matches,
    ReaiFunctionId     origin_fn_id,
    Float64           *required_similarity
) {
    if (!required_similarity) {
        APPEND_ERROR ("A minimum similarity level is required");
        return NULL;
    }

    if (!fn_matches) {
        APPEND_ERROR ("Function matches are invalid. Cannot proceed.");
        return NULL;
    }

    if (!origin_fn_id) {
        APPEND_ERROR ("Origin function ID is invalid. Cannot proceed.");
        return NULL;
    }

    Float64         max_similarity = 0;    // The maximum available similarity among suggestions
    ReaiAnnFnMatch *fn_match       = NULL; // Function name with max similarity out of all
    REAI_VEC_FOREACH (fn_matches, match, {
        /* otherwise find function with max similarity */
        if ((match->confidence > max_similarity) && (match->origin_function_id == origin_fn_id)) {
            fn_match       = match;
            max_similarity = match->confidence; // is similarity but named confidence in API
        }
    });

    // return match with max similarity if we've crossed the required similarity
    // level, otherwise a suitable match failed
    return max_similarity >= *required_similarity ?
               (*required_similarity = max_similarity, fn_match) :
               NULL;
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
        APPEND_ERROR (
            "Invalid binary ID provied. Cannot fetch function info list from RevEng.AI servers."
        );
        return NULL;
    }

    /* get function names for all functions in the binary (this is why we need analysis) */
    ReaiFnInfoVec *fn_infos = reai_get_basic_function_info (reai(), reai_response(), bin_id);
    if (!fn_infos) {
        APPEND_ERROR ("Failed to get binary function names.");
        return NULL;
    }

    if (!fn_infos->count) {
        APPEND_ERROR ("Current binary does not have any function.");
        return NULL;
    }

    /* try cloning */
    fn_infos = reai_fn_info_vec_clone_create (fn_infos);
    if (!fn_infos) {
        APPEND_ERROR ("FnInfos vector clone failed");
        return NULL;
    }

    return fn_infos;
}

/**
 * @b Get function matches for given binary id.
 *
 * The returned vector must be destroyed after use.
 *
 * @param bin_id Binary id to get ANN function similarity results for.
 * @param max_results Maximum number of results per function.
 * @param min_similarity Minimum required similarity level for a good match.   
 * @param collections Collections to search into. Emtpy means all collections.
 * @param debug_filter Restrict search suggestions to debug symbols only.
 *
 * @return @c ReaiAnnFnMatchVec on success.
 * @return @c NULL otherwise.
 * */
PRIVATE ReaiAnnFnMatchVec *get_fn_matches (
    ReaiBinaryId bin_id,
    Uint32       max_results,
    Float64      min_similarity,
    CStrVec     *collections,
    Bool         debug_filter
) {
    if (!bin_id) {
        APPEND_ERROR ("Invalid binary ID provided. Cannot get function matches.");
        return NULL;
    }

    ReaiAnnFnMatchVec *fn_matches = reai_batch_binary_symbol_ann (
        reai(),
        reai_response(),
        bin_id,
        max_results,
        1 - min_similarity,
        collections,
        debug_filter
    );

    if (!fn_matches) {
        APPEND_ERROR ("Failed to get ANN binary symbol similarity result");
        return NULL;
    }

    if (!fn_matches->count) {
        APPEND_ERROR ("No similar functions found.");
        return NULL;
    }

    /* try clone */
    fn_matches = reai_ann_fn_match_vec_clone_create (fn_matches);
    if (!fn_matches) {
        APPEND_ERROR ("ANN Fn Match vector clone failed.");
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
        while (plugin->locked)
            ;
        return plugin;
    }

    if (!(plugin = NEW (ReaiPlugin))) {
        APPEND_ERROR (ERR_OUT_OF_MEMORY);
        return NULL;
    }

    return plugin;
}

/**
 * @b Get function boundaries from given binary file.
 *
 *@NOTE: returned vector is owned by the caller and hence is
 * responsible for destroying the vector after use.
 *
 * @param core
 *
 * @return @c ReaiFnInfoVec reference on success.
 * @return @c NULL otherwise.
 *  */
ReaiFnInfoVec *reai_plugin_get_function_boundaries (RzCore *core) {
    if (!core) {
        APPEND_ERROR ("Invalid rizin core provided. Cannot get function boundaries.");
        return NULL;
    }


    /* prepare symbols info  */
    RzList        *fns           = rz_analysis_function_list (core->analysis);
    ReaiFnInfoVec *fn_boundaries = reai_fn_info_vec_create();

    /** NOTE: We're sending addresses here in form of `base + offset`
     * but what we receive from reveng.ai is in `offset` only form */

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
            APPEND_ERROR ("Failed to append function info in function boundaries list.");
            reai_fn_info_vec_destroy (fn_boundaries);
            return NULL;
        }
    }

    return fn_boundaries;
}

/**
 * @brief Called by rizin when loading reai_plugin()-> This is the plugin
 * entrypoint where we register all the commands and corresponding handlers.
 *
 * To know about how commands work for this plugin, refer to `CmdGen/README.md`.
 * */
Bool reai_plugin_init (RzCore *core) {
    reai_plugin_deinit();

    if (!core) {
        APPEND_ERROR ("Invalid rizin core provided.");
        return false;
    }

    /* load default config */
    reai_plugin()->reai_config = reai_config_load (NULL);
    if (!reai_config()) {
        APPEND_ERROR (
            "Failed to load RevEng.AI toolkit config file. Please make sure the config exists or "
            "create a config using the plugin."
        );
        return false;
    }

    /* initialize reai object. */
    if (!reai()) {
        reai_plugin()->reai = reai_create (reai_config()->host, reai_config()->apikey);
        if (!reai()) {
            APPEND_ERROR ("Failed to create Reai object.");
            return false;
        }
    }

    /* create response object */
    if (!reai_response()) {
        reai_plugin()->reai_response = NEW (ReaiResponse);
        if (!reai_response_init (reai_response())) {
            APPEND_ERROR ("Failed to create/init ReaiResponse object.");
            FREE (reai_response());
            return false;
        }
    }

    /* create bg workers */
    reai_plugin()->bg_workers = reai_bg_workers_vec_create();
    if (!reai_bg_workers()) {
        APPEND_ERROR ("Failed to initialize background workers vec.");
        return false;
    }

    if (!reai_plugin_add_bg_work (perform_auth_check_in_bg, reai_plugin())) {
        REAI_LOG_ERROR ("Failed to add perform-auth-check bg worker.");
    }

    if (!reai_plugin_add_bg_work (get_ai_models_in_bg, reai_plugin())) {
        REAI_LOG_ERROR ("Failed to add get-ai-models bg worker.");
    }

    // get binary id
    reai_binary_id() = rz_config_get_i (core->config, "reai.id");

    // if file is not loaded from a project, or the project does not have a binary id
    // then binary id will be 0
    if (!reai_binary_id()) {
        // unlock and create a variable so that in future we can update it
        rz_config_lock (core->config, false);
        rz_config_set_i (core->config, "reai.id", 0);
        rz_config_lock (core->config, true);
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
Bool reai_plugin_deinit() {
    /* this must be destroyed first and set to NULL to signal the background
    * worker thread to stop working */
    if (reai()) {
        reai_destroy (reai());
        reai_plugin()->reai = NULL;
    }

    if (reai_response()) {
        reai_response_deinit (reai_response());
        FREE (reai_response());
    }

    if (reai_config()) {
        reai_config_destroy (reai_config());
    }

    if (reai_ai_models()) {
        reai_cstr_vec_destroy (reai_ai_models());
        reai_plugin()->ai_models = NULL;
    }

    if (reai_bg_workers()) {
        // wait for and destroy all threads first
        REAI_VEC_FOREACH (reai_bg_workers(), th, {
            rz_th_wait (*th);
            rz_th_free (*th);
        });

        reai_bg_workers_vec_destroy (reai_bg_workers());
        reai_plugin()->bg_workers = NULL;
    }

    memset (reai_plugin(), 0, sizeof (ReaiPlugin));

    return true;
}

Bool reai_plugin_add_bg_work (RzThreadFunction fn, void *user_data) {
    if (!fn) {
        APPEND_ERROR ("Invalid function provided. Cannot start background work");
        return false;
    }

    const Size MAX_WORKERS = 16;
    if (reai_bg_workers()->count >= MAX_WORKERS) {
        // destroy oldest thread
        RzThread *th = reai_bg_workers()->items[0];
        rz_th_wait (th);
        rz_th_free (th);

        // remove oldest thread
        reai_bg_workers_vec_remove (reai_bg_workers(), 0);
    }

    // create new thread
    RzThread *th = rz_th_new (fn, user_data);
    if (!th) {
        APPEND_ERROR ("Failed to create a new background worker thread. Task won't be executed.");
        return false;
    }

    // insert at end
    if (!reai_bg_workers_vec_append (reai_bg_workers(), &th)) {
        APPEND_WARN (
            "Failed to add background worker thread to collection of threads. This might cause "
            "memory leaks because thread object won't be destroyed."
        );
        return false;
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
    return !!reai_config();
}

/**
 * @b Save given config to a file.
 *
 * @param host
 * @param api_key
 * @param model
 * @param log_dir_path
 * */
Bool reai_plugin_save_config (CString host, CString api_key) {
    // if reai object is not created, create
    if (!reai()) {
        reai_plugin()->reai = reai_create (host, api_key);
        if (!reai()) {
            APPEND_ERROR ("Failed to create Reai object.");
            return false;
        }
    }

    /* create response object */
    if (!reai_response()) {
        reai_plugin()->reai_response = NEW (ReaiResponse);
        if (!reai_response_init (reai_response())) {
            APPEND_ERROR ("Failed to create/init ReaiResponse object.");
            FREE (reai_response());
            return false;
        }
    }

    if (!reai_auth_check (reai(), reai_response(), host, api_key)) {
        APPEND_ERROR ("Invalid host or api-key provided. Please check once again and retry.");
        return false;
    }

    CString reai_config_file_path = reai_config_get_default_path();
    if (!reai_config_file_path) {
        APPEND_ERROR ("Failed to get config file default path.");
        return false;
    } else {
        REAI_LOG_INFO ("Config will be saved at %s\n", reai_config_file_path);
    }

    FILE *reai_config_file = fopen (reai_config_file_path, "w");
    if (!reai_config_file) {
        APPEND_ERROR ("Failed to open config file. %s", strerror (errno));
        return false;
    }

    fprintf (reai_config_file, "host         = \"%s\"\n", host);
    fprintf (reai_config_file, "apikey       = \"%s\"\n", api_key);

    fclose (reai_config_file);

    return true;
}

CStrVec *reai_plugin_csv_to_cstr_vec (CString csv) {
    CStrVec *v = NULL;
    if (csv && strlen (csv)) {
        RzList *list = rz_str_split_duplist (csv, ",", true);
        v            = reai_cstr_vec_create();

        RzListIter *it;
        char       *cname;
        rz_list_foreach (list, it, cname) {
            CString n = cname;
            reai_cstr_vec_append (v, &n);
        }
        rz_list_free (list);
    }

    return v;
}

U64Vec *reai_plugin_csv_to_u64_vec (CString csv) {
    U64Vec *v = NULL;
    if (csv && strlen (csv)) {
        RzList *list = rz_str_split_duplist (csv, ",", true);
        v            = reai_u64_vec_create();

        RzListIter *it;
        char       *cname;
        rz_list_foreach (list, it, cname) {
            Uint64 n = strtoull (cname, NULL, 10);
            reai_u64_vec_append (v, &n);
        }
        rz_list_free (list);
    }

    return v;
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
        APPEND_ERROR ("Invalid rizin core provided. Cannot perform upload.");
        return false;
    }

    /* get file path */
    CString binfile_path = reai_plugin_get_opened_binary_file_path (core);
    if (!binfile_path) {
        APPEND_ERROR ("No binary file opened in rizin. Cannot perform upload.");
        return false;
    }

    /* check if file is already uploaded or otherwise upload */
    CString sha256 = reai_upload_file (reai(), reai_response(), binfile_path);
    if (!sha256) {
        APPEND_ERROR ("Failed to upload binary file.");
        FREE (binfile_path);
        return false;
    }

    return true;
}

/**
 * @b Create a new analysis for currently opened binary file.
 *
 * This method first checks whether upload already exists for a given file path.
 * If upload does exist then the existing upload is used.
 *
 * @param core To get currently opened binary file in rizin/cutter.
 *
 * @return true on success.
 * @return false otherwise.
 * */
Bool reai_plugin_create_analysis_for_opened_binary_file (
    RzCore *core,
    CString prog_name,
    CString cmdline_args,
    CString ai_model,
    Bool    is_private
) {
    if (!core) {
        APPEND_ERROR ("Invalid rizin core provided. Cannot create analysis.");
        return false;
    }

    if (!prog_name || !strlen (prog_name)) {
        APPEND_ERROR ("Invalid program name provided. Cannot create analysis.");
        return false;
    }

    if (!ai_model || !strlen (ai_model)) {
        APPEND_ERROR ("Invalid AI model provided. Cannot create analysis.");
        return false;
    }

    /* warn the use if no analysis exists */
    if (!reai_plugin_get_rizin_analysis_function_count (core)) {
        APPEND_ERROR (
            "It seems that rizin analysis hasn't been performed yet. "
            "Please create rizin analysis "
            "first."
        );
        return false;
    }

    RzBinFile *binfile = reai_plugin_get_opened_binary_file (core);
    if (!binfile) {
        APPEND_ERROR ("No binary file opened. Cannot create analysis");
        return false;
    }

    CString binfile_path = reai_plugin_get_opened_binary_file_path (core);
    if (!binfile_path) {
        APPEND_ERROR ("Failed to get binary file full path. Cannot create analysis");
        return false;
    }

    CString sha256 = reai_upload_file (reai(), reai_response(), binfile_path);
    if (!sha256) {
        APPEND_ERROR ("Failed to upload file");
        FREE (binfile_path);
        return false;
    }
    sha256 = strdup (sha256);
    REAI_LOG_INFO ("Binary uploaded successfully.");

    /* get function boundaries to create analysis */
    ReaiFnInfoVec *fn_boundaries = reai_plugin_get_function_boundaries (core);
    if (!fn_boundaries) {
        APPEND_ERROR (
            "Failed to get function boundary information from rizin "
            "analysis. Cannot create "
            "RevEng.AI analysis."
        );
        FREE (sha256);
        FREE (binfile_path);
        return false;
    }

    /* create analysis */
    ReaiBinaryId bin_id = reai_create_analysis (
        reai(),
        reai_response(),
        ai_model,
        reai_plugin_get_opened_binary_file_baseaddr (core),
        fn_boundaries,
        is_private,
        sha256,
        prog_name,
        cmdline_args, // cmdline args
        binfile->size,
        false,        // dynamic_execution,
        true,         // skip_scraping,
        true,         // skip_cves,
        true,         // skip_sbom,
        true,         // skip_capabilities,
        false,        // ignore_cache,
        false         // do_advanced_analysis
    );

    if (!bin_id) {
        APPEND_ERROR ("Failed to create RevEng.AI analysis.");
        FREE (sha256);
        FREE (binfile_path);
        reai_fn_info_vec_destroy (fn_boundaries);
        return false;
    }

    /* destroy after use */
    FREE (sha256);
    FREE (binfile_path);
    reai_fn_info_vec_destroy (fn_boundaries);

    reai_binary_id() = bin_id;
    rz_config_set_i (core->config, "reai.id", reai_binary_id());

    return true;
}

/**
 * @b Apply existing analysis to opened binary file.
 *
 * @param[in]  core
 * @param[in]  bin_id        RevEng.AI analysis binary ID.
 *
 * @return True on successful application of renames
 * @return False otherwise.
 * */
Bool reai_plugin_apply_existing_analysis (
    RzCore      *core,
    ReaiBinaryId bin_id,
    Bool         has_custom_base_addr,
    Uint64       base_addr
) {
    if (!core) {
        APPEND_ERROR ("Invalid Rizin core provided. Cannot apply analysis.");
        return false;
    }

    if (!bin_id) {
        APPEND_ERROR ("Invalid RevEng.AI binary id provided. Cannot apply analysis.");
        return false;
    }

    /* an analysis must already exist in order to make auto-analysis work */
    ReaiAnalysisStatus analysis_status = reai_get_analysis_status (reai(), reai_response(), bin_id);
    switch (analysis_status) {
        case REAI_ANALYSIS_STATUS_ERROR : {
            APPEND_ERROR (
                "The applied/created RevEngAI analysis has errored out.\n"
                "I need a complete analysis to get function info.\n"
                "Please restart analysis."
            );
            return false;
        }
        case REAI_ANALYSIS_STATUS_QUEUED : {
            APPEND_ERROR (
                "The applied/created RevEngAI analysis is currently in queue.\n"
                "Please wait for the analysis to be analyzed."
            );
            return false;
        }
        case REAI_ANALYSIS_STATUS_PROCESSING : {
            APPEND_ERROR (
                "The applied/created RevEngAI analysis is currently being processed (analyzed).\n"
                "Please wait for the analysis to complete."
            );
            return false;
        }
        case REAI_ANALYSIS_STATUS_COMPLETE : {
            REAI_LOG_TRACE ("Analysis for binary ID %llu is COMPLETE.", reai_binary_id());
            break;
        }
        default : {
            APPEND_ERROR (
                "Oops... something bad happened :-(\n"
                "I got an invalid value for RevEngAI analysis status.\n"
                "Consider\n"
                "\t- Checking the binary ID, reapply the correct one if wrong\n"
                "\t- Retrying the command\n"
                "\t- Restarting the plugin\n"
                "\t- Checking logs in $TMPDIR or $TMP or $PWD (reai_<pid>)\n"
                "\t- Checking the connection with RevEngAI host.\n"
                "\t- Contacting support if the issue persists\n"
            );
            return false;
        }
    }

    /* names of current functions */
    ReaiFnInfoVec *fn_infos = get_fn_infos (bin_id);
    if (!fn_infos) {
        APPEND_ERROR ("Failed to get funciton info for opened binary.");
        return false;
    }

    /* prepare table and print info */
    ReaiPluginTable *successful_renames = reai_plugin_table_create();
    if (!successful_renames) {
        APPEND_ERROR ("Failed to create table to display successful renam operations.");
        reai_fn_info_vec_destroy (fn_infos);
        return false;
    }
    reai_plugin_table_set_title (successful_renames, "Successfully Renamed Functions");
    reai_plugin_table_set_columnsf (successful_renames, "ssn", "old_name", "new_name", "address");
#define ADD_TO_SUCCESSFUL_RENAME()                                                                 \
    do {                                                                                           \
        reai_plugin_table_add_rowf (successful_renames, "ssx", old_name, rz_fn->name, fn_addr);    \
        success_cases_exist = true;                                                                \
    } while (0)

    Bool success_cases_exist = false;

    /* display information about what renames will be performed */ /* add rename information to new name mapping */
    /* rename the functions in rizin */
    CString old_name = NULL;

    REAI_VEC_FOREACH (fn_infos, fn, {
        if (old_name) {
            FREE (old_name);
        }

        Uint64 fn_addr =
            fn->vaddr +
            (has_custom_base_addr ? base_addr : reai_plugin_get_opened_binary_file_baseaddr (core));

        /* get function */
        RzAnalysisFunction *rz_fn = rz_analysis_get_function_at (core->analysis, fn_addr);

        if (rz_fn) {
            old_name         = strdup (rz_fn->name);
            CString new_name = fn->name;

            // if name already matches
            if (!strcmp (rz_fn->name, fn->name)) {
                REAI_LOG_INFO (
                    "Name \"%s\" already matches for function at address %llx",
                    old_name,
                    fn_addr
                );
                ADD_TO_SUCCESSFUL_RENAME();
            } else {
                // NOTE(brightprogrammer): Not comparing function size here. Can this create problems in future??
                rizin_analysis_function_force_rename (rz_fn, new_name);
                ADD_TO_SUCCESSFUL_RENAME();
            }
        } else { // If no Rizin funciton exists at given address
            REAI_LOG_ERROR (
                "function not found (.name = \"%s\", .addr = 0x%llx)",
                old_name,
                fn_addr
            );
        }
    });

    if (old_name) {
        FREE (old_name);
    }

    if (success_cases_exist) {
        reai_plugin_table_show (successful_renames);
    }

    // Mass Destruction!!!!
    reai_plugin_table_destroy (successful_renames);
    reai_fn_info_vec_destroy (fn_infos);

    reai_binary_id() = bin_id;
    rz_config_set_i (core->config, "reai.id", reai_binary_id());

#undef ADD_TO_SUCCESSFUL_RENAME

    return true;
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
        APPEND_ERROR ("Invalid binary id provided. Cannot fetch analysis status.");
        return REAI_ANALYSIS_STATUS_INVALID;
    }

    ReaiAnalysisStatus analysis_status =
        reai_get_analysis_status (reai(), reai_response(), binary_id);

    if (!analysis_status) {
        APPEND_ERROR ("Failed to get analysis status from RevEng.AI servers.");
        return REAI_ANALYSIS_STATUS_INVALID;
    }

    REAI_LOG_TRACE (
        "Fetched analysis status \"%s\".",
        reai_analysis_status_to_cstr (analysis_status)
    );
    return analysis_status;
}

/**
 * @b Automatically rename all funcitons with matching names.
 *
 * @param core To get currently opened binary file.
 * @param max_results_per_function Maximum number of search results to return for each function. 
 * @param min_similarity Minimum similarity filter. Functions without minimum similarity requirement are ignored. 
 * @param debug_filter Restrict search suggestions to debug symbols only. 
 * */
Bool reai_plugin_auto_analyze_opened_binary_file (
    RzCore *core,
    Size    max_results_per_function,
    Float64 min_similarity,
    Bool    debug_filter
) {
    if (!core) {
        APPEND_ERROR ("Invalid rizin core provided. Cannot perform auto-analysis.");
        return false;
    }

    /* try to get latest analysis for loaded binary (if exists) */
    ReaiBinaryId bin_id = reai_binary_id();
    if (!bin_id) {
        APPEND_ERROR (
            "Please apply an existing analysis or create a new one. I cannot perform auto-analysis "
            "without an existing RevEng.AI analysis."
        );
        return false;
    }

    /* an analysis must already exist in order to make auto-analysis work */
    ReaiAnalysisStatus analysis_status = reai_plugin_get_analysis_status_for_binary_id (bin_id);
    if (analysis_status != REAI_ANALYSIS_STATUS_COMPLETE) {
        APPEND_WARN (
            "Analysis not complete yet. Please wait for some time and "
            "then try again!"
        );
        return false;
    }

    /* names of current functions */
    ReaiFnInfoVec *fn_infos = get_fn_infos (bin_id);
    if (!fn_infos) {
        APPEND_ERROR ("Failed to get funciton info for opened binary.");
        return false;
    }

    /* function matches */
    ReaiAnnFnMatchVec *fn_matches =
        get_fn_matches (bin_id, max_results_per_function, min_similarity, NULL, debug_filter);
    if (!fn_matches) {
        APPEND_ERROR ("Failed to get function matches for opened binary.");
        reai_fn_info_vec_destroy (fn_infos);
        return false;
    }

    /* new vector where new names of functions will be stored */
    ReaiFnInfoVec *new_name_mapping = reai_fn_info_vec_create();
    if (!new_name_mapping) {
        APPEND_ERROR ("Failed to create a new-name-mapping object.");
        reai_ann_fn_match_vec_destroy (fn_matches);
        reai_fn_info_vec_destroy (fn_infos);
        return false;
    }

    /* prepare table and print info */
    ReaiPluginTable *successful_renames = reai_plugin_table_create();
    if (!successful_renames) {
        APPEND_ERROR ("Failed to create table to display new name mapping.");
        reai_fn_info_vec_destroy (new_name_mapping);
        reai_ann_fn_match_vec_destroy (fn_matches);
        reai_fn_info_vec_destroy (fn_infos);
        return false;
    }
    reai_plugin_table_set_columnsf (
        successful_renames,
        "sssnn",
        "Old Name",
        "New Name",
        "Source Binary",
        "Similarity",
        "Address"
    );

#define ADD_TO_SUCCESSFUL_RENAME()                                                                 \
    do {                                                                                           \
        reai_plugin_table_add_rowf (                                                               \
            successful_renames,                                                                    \
            "sssfx",                                                                               \
            old_name,                                                                              \
            sim_match->nn_function_name,                                                           \
            sim_match->nn_binary_name,                                                             \
            min_similarity,                                                                        \
            fn_addr                                                                                \
        );                                                                                         \
                                                                                                   \
        reai_fn_info_vec_append (                                                                  \
            new_name_mapping,                                                                      \
            &((ReaiFnInfo) {.name = rz_strbuf_get (&new_name_buf), .id = fn->id})                  \
        );                                                                                         \
                                                                                                   \
        success_cases_exist = true;                                                                \
    } while (0)

    Bool success_cases_exist = false;

    /* display information about what renames will be performed 
     * add rename information to new name mapping *
     * rename the functions in rizin */
    CString old_name = NULL;
    REAI_VEC_FOREACH (fn_infos, fn, {
        if (old_name) {
            FREE (old_name);
        }
        old_name = strdup (fn->name);

        Uint64 fn_addr = fn->vaddr + reai_plugin_get_opened_binary_file_baseaddr (core);

        /* if we get a match with required similairty level then we add to rename */
        ReaiAnnFnMatch *sim_match = NULL;
        if ((sim_match =
                 get_function_match_with_similarity (fn_matches, fn->id, &min_similarity))) {
            /* If functions already are same then no need to rename */
            if (!strcmp (sim_match->nn_function_name, old_name)) {
                REAI_LOG_INFO (
                    "Name \"%s\" already matches for function at address 0x%llx",
                    old_name,
                    fn_addr
                );
                continue;
            }

            /* get function */
            RzAnalysisFunction *rz_fn = rz_analysis_get_function_at (core->analysis, fn_addr);
            if (rz_fn) {
                // Generate new name
                RzStrBuf new_name_buf = {0};
                rz_strbuf_initf (
                    &new_name_buf,
                    "%s.%s",
                    sim_match->nn_function_name,
                    sim_match->nn_binary_name
                );
                rizin_analysis_function_force_rename (rz_fn, rz_strbuf_get (&new_name_buf));
                ADD_TO_SUCCESSFUL_RENAME();
                rz_strbuf_fini (&new_name_buf);
            } else { // If function not found at address
                REAI_LOG_ERROR (
                    "function not found (.old_name = \"%s\", .addr = 0x%llx)",
                    old_name,
                    fn_addr
                );
            }
        } else { // If not able to find a function with given similairty
            REAI_LOG_TRACE (
                "similar match not found (.old_name = \"%s\", .addr = 0x%lx)",
                old_name,
                fn_addr
            );
        }
    });

    if (old_name) {
        FREE (old_name);
    }

    if (success_cases_exist) {
        reai_plugin_table_show (successful_renames);
    }

    /* perform a batch rename */
    if (new_name_mapping->count) {
        // NOTE: in a meeting it was assured by product management lead that this api endpoint will never fail
        // If it does, then the information displayed by tables above won't concurr with the message that will
        // be displayed below on failure.

        Bool res = reai_batch_renames_functions (reai(), reai_response(), new_name_mapping);
        if (!res) {
            APPEND_ERROR ("Failed to rename all functions in binary");
        }
    } else {
        eprintf ("No function will be renamed.\n");
    }

    reai_plugin_table_destroy (successful_renames);
    reai_fn_info_vec_destroy (new_name_mapping);
    reai_ann_fn_match_vec_destroy (fn_matches);
    reai_fn_info_vec_destroy (fn_infos);

#undef ADD_TO_SUCCESSFUL_RENAME

    return true;
}

/**
 * @b Search for given analysis function and get the corresponding function id.
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
        APPEND_ERROR (
            "Invalid rizin core provided. Cannot fetch function ID for given function name."
        );
        return 0;
    }

    if (!rz_fn || !rz_fn->name) {
        APPEND_ERROR ("Invalid Rizin function provided. Cannot get a function ID.");
        return 0;
    }

    ReaiBinaryId bin_id = reai_binary_id();
    if (!bin_id) {
        APPEND_ERROR (
            "Please create a new analysis or apply an existing analysis. I need an existing "
            "analysis to get function information."
        );
        return 0;
    }

    ReaiFnInfoVec *fn_infos = NULL;
    /* avoid making multiple calls subsequent calls to same endpoint if possible */
    if (reai_response()->type == REAI_RESPONSE_TYPE_BASIC_FUNCTION_INFO) {
        REAI_LOG_TRACE ("Using previously fetched response of basic function info.");

        fn_infos = reai_response()->basic_function_info.fn_infos;
    } else {
        REAI_LOG_TRACE ("Fetching basic function info again");

        fn_infos = reai_get_basic_function_info (reai(), reai_response(), bin_id);
        if (!fn_infos) {
            APPEND_ERROR (
                "Failed to get function info list for opened binary file from RevEng.AI servers."
            );
            return 0;
        }
    }

    Uint64 base_addr = reai_plugin_get_opened_binary_file_baseaddr (core);

    for (ReaiFnInfo *fn_info = fn_infos->items; fn_info < fn_infos->items + fn_infos->count;
         fn_info++) {
        Uint64 min_addr = rz_analysis_function_min_addr (rz_fn) - base_addr;
        Uint64 max_addr = rz_analysis_function_max_addr (rz_fn) - base_addr;

        if (min_addr <= fn_info->vaddr && fn_info->vaddr <= max_addr) {
            REAI_LOG_TRACE (
                "Found function ID for rizin function \"%s\" (\"%s\"): [%llu]",
                rz_fn->name,
                fn_info->name,
                fn_info->id
            );
            return fn_info->id;
        }
    };

    REAI_LOG_TRACE ("Function ID not found for function \"%s\"", rz_fn->name);

    return 0;
}

/**
 * @b Get a table of similar function name data.
 *
 * @param core
 * @param fcn_name Function name to search simlar functionsns for,
 * @param max_results_count Maximum number of results per function.
 * @param min_similarity Minimum required similarity level for a good match.
 * @param debug_filter Restrict search suggestions to debug symbols only. 
 *
 * @return @c ReaiPluginTable containing search suggestions on success.
 * @return @c NULL when no suggestions found.
 * */
Bool reai_plugin_search_and_show_similar_functions (
    RzCore *core,
    CString fcn_name,
    Size    max_results_count,
    Int32   min_similarity,
    Bool    debug_filter,
    CString collection_ids_csv,
    CString binary_ids_csv
) {
    if (!core) {
        APPEND_ERROR ("Invalid Rizin core porivded. Cannot perform similarity search.");
        return false;
    }

    if (!fcn_name) {
        APPEND_ERROR ("Invalid function name porivded. Cannot perform similarity search.");
        return false;
    }

    if (!reai_binary_id()) {
        APPEND_ERROR (
            "No analysis created or applied. I need a RevEngAI analysis to get function info."
        );
        return false;
    }

    ReaiAnalysisStatus status = reai_plugin_get_analysis_status_for_binary_id (reai_binary_id());
    switch (status) {
        case REAI_ANALYSIS_STATUS_ERROR : {
            APPEND_ERROR (
                "The applied/created RevEngAI analysis has errored out.\n"
                "I need a complete analysis to get function info. Please restart analysis."
            );
            return false;
        }
        case REAI_ANALYSIS_STATUS_QUEUED : {
            APPEND_ERROR (
                "The applied/created RevEngAI analysis is currently in queue.\n"
                "Please wait for the analysis to be analyzed."
            );
            return false;
        }
        case REAI_ANALYSIS_STATUS_PROCESSING : {
            APPEND_ERROR (
                "The applied/created RevEngAI analysis is currently being processed (analyzed).\n"
                "Please wait for the analysis to complete."
            );
            return false;
        }
        case REAI_ANALYSIS_STATUS_COMPLETE : {
            REAI_LOG_TRACE ("Analysis for binary ID %llu is COMPLETE.", reai_binary_id());
            break;
        }
        default : {
            APPEND_ERROR (
                "Oops... something bad happened :-(\n"
                "I got an invalid value for RevEngAI analysis status.\n"
                "Consider\n"
                "\t- Checking the binary ID, reapply the correct one if wrong\n"
                "\t- Retrying the command\n"
                "\t- Restarting the plugin\n"
                "\t- Checking logs in $TMPDIR or $TMP or $PWD (reai_<pid>)\n"
                "\t- Checking the connection with RevEngAI host.\n"
                "\t- Contacting support if the issue persists\n"
            );
            return false;
        }
    }

    RzAnalysisFunction *fn = rz_analysis_get_function_byname (core->analysis, fcn_name);
    if (!fn) {
        APPEND_ERROR ("Provided function name does not exist. Cannot get similar function names.");
        return false;
    }

    ReaiFunctionId fn_id = reai_plugin_get_function_id_for_rizin_function (core, fn);
    if (!fn_id) {
        APPEND_ERROR (
            "Failed to get function id of given function. Cannot get similar function names."
        );
        return false;
    }

    U64Vec *collection_ids = reai_plugin_csv_to_u64_vec (collection_ids_csv);
    U64Vec *binary_ids     = reai_plugin_csv_to_u64_vec (binary_ids_csv);

    Float32           maxDistance = 1.f - (min_similarity / 100.f);
    ReaiSimilarFnVec *fnMatches   = reai_get_similar_functions (
        reai(),
        reai_response(),
        fn_id,
        max_results_count,
        maxDistance,
        collection_ids,
        debug_filter,
        binary_ids
    );

    if (collection_ids) {
        reai_u64_vec_destroy (collection_ids);
    }

    if (binary_ids) {
        reai_u64_vec_destroy (binary_ids);
    }

    if (fnMatches && fnMatches->count) {
        // Populate table
        ReaiPluginTable *table = reai_plugin_table_create();
        reai_plugin_table_set_columnsf (
            table,
            "snsnn",
            "Function Name",
            "Function ID",
            "Binary Name",
            "Binary ID",
            "Similarity"
        );
        reai_plugin_table_set_title (table, "Function Similarity Search Results");

        REAI_VEC_FOREACH (fnMatches, fnMatch, {
            reai_plugin_table_add_rowf (
                table,
                "snsnf",
                fnMatch->function_name,
                fnMatch->function_id,
                fnMatch->binary_name,
                fnMatch->binary_id,
                (1 - fnMatch->distance) * 100
            );
        });

        reai_plugin_table_show (table);
        reai_plugin_table_destroy (table);
        return true;
    } else {
        return false;
    }
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
        APPEND_ERROR ("Invalid rizin core provided. Cannot get opened binary file.");
        return NULL;
    }

    if (!core->bin) {
        APPEND_ERROR (
            "Seems like no binary file is opened yet. Binary container object is invalid. Cannot "
            "get opened binary file."
        );
        return NULL;
    }

    if (!core->bin->binfiles) {
        APPEND_ERROR (
            "Seems like no binary file is opened yet. Binary file list is invalid. Cannot "
            "get opened binary file."
        );
        return NULL;
    }

    if (!core->bin->binfiles->length) {
        APPEND_ERROR ("Seems like no binary file is opened yet. Cannot get opened binary file.");
        return NULL;
    }

    RzListIter *head = rz_list_head (core->bin->binfiles);
    if (!head) {
        APPEND_ERROR (
            "Cannot get object reference to currently opened binary file. Internal Rizin error."
        );
        return NULL;
    }

    return rz_list_iter_get_data (head);
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
        APPEND_ERROR ("Invalid Rizin core provided. Cannot get analysis function count.");
        return 0;
    }

    if (!core->analysis) {
        APPEND_ERROR (
            "Seems like Rizin analysis is not performed yet. The analysis object is invalid. "
            "Cannot get "
            "analysis function count."
        );
        return 0;
    }

    RzList *fns = rz_analysis_function_list (core->analysis);
    if (!fns) {
        APPEND_ERROR (
            "Seems like Rizin analysis is not performed yet. Function list is invalid. Cannot get "
            "function with given name."
        );
        return 0;
    }

    return fns->length;
}

/**
 * \b Begin AI decompilation on cloud server for function
 * at given address (if there exists one).
 *
 * \p core
 * \p addr Address of function.
 *
 * \return True on success.
 * \return False otherwise.
 * */
Bool reai_plugin_decompile_at (RzCore *core, ut64 addr) {
    if (!core) {
        APPEND_ERROR ("Invalid arguments");
        return false;
    }

    RzAnalysisFunction *fn    = rz_analysis_get_function_at (core->analysis, addr);
    ReaiFunctionId      fn_id = reai_plugin_get_function_id_for_rizin_function (core, fn);
    if (!fn_id) {
        return false;
    }

    return !!reai_begin_ai_decompilation (reai(), reai_response(), fn_id);
}

/**
 * \b Get status of AI decompiler running for function at given address.
 *
 * \p core
 * \p addr Address of function.
 *
 * \return ReaiAiDecompilationStatus
 * */
ReaiAiDecompilationStatus reai_plugin_check_decompiler_status_running_at (RzCore *core, ut64 addr) {
    if (!core) {
        APPEND_ERROR ("Invalid arguments");
        return false;
    }

    RzAnalysisFunction *fn    = rz_analysis_get_function_at (core->analysis, addr);
    ReaiFunctionId      fn_id = reai_plugin_get_function_id_for_rizin_function (core, fn);
    if (!fn_id) {
        return false;
    }

    return reai_poll_ai_decompilation (reai(), reai_response(), fn_id, false /* ai summary */);
}

/**
 * \b If AI decompilation is complete then get the decompiled code.
 *
 * It is recommended to call this function only after decompilation
 * is complete. Use the check_decompilar_status API for that.
 *
 * \p core
 * \p addr Address of function
 *
 * \return AI Decompilation code on success.
 * \return A string containing "(empty)" otherwise.
 * */
CString reai_plugin_get_decompiled_code_at (RzCore *core, ut64 addr, Bool summarize) {
    if (!core) {
        APPEND_ERROR ("Invalid arguments");
        return NULL;
    }

    RzAnalysisFunction *fn    = rz_analysis_get_function_at (core->analysis, addr);
    ReaiFunctionId      fn_id = reai_plugin_get_function_id_for_rizin_function (core, fn);
    if (!fn_id) {
        return NULL;
    }

    ReaiAiDecompilationStatus status =
        reai_poll_ai_decompilation (reai(), reai_response(), fn_id, summarize);
    if (status == REAI_AI_DECOMPILATION_STATUS_SUCCESS) {
        CString decomp = reai_response()->poll_ai_decompilation.data.decompilation;

        char *summary = (char *)reai_response()->poll_ai_decompilation.data.summary;
        if (summary) {
            summary = strdup (summary);
            summary = rz_str_appendf (summary, "\n%s", decomp ? decomp : "(empty)");

            decomp = summary;
        }
        return decomp;
    }

    return NULL;
}

Bool reai_plugin_collection_search (
    RzCore *core,
    CString partial_collection_name,
    CString partial_binary_name,
    CString partial_binary_sha256,
    CString model_name,
    CString tags_csv
) {
    if (!core) {
        APPEND_ERROR ("Invalid arguments");
        return false;
    }

    CStrVec *tags = reai_plugin_csv_to_cstr_vec (tags_csv);

    ReaiCollectionSearchResultVec *results = reai_collection_search (
        reai(),
        reai_response(),
        partial_collection_name,
        partial_binary_name,
        partial_binary_sha256,
        tags,
        model_name
    );

    if (tags) {
        reai_cstr_vec_destroy (tags);
    }

    if (results) {
        results = reai_collection_search_result_vec_clone_create (results);
    } else {
        return false;
    }

    ReaiPluginTable *t = reai_plugin_table_create();
    reai_plugin_table_set_title (t, "Collections Search Results");
    reai_plugin_table_set_columnsf (
        t,
        "snssss",
        "name",
        "id",
        "scope",
        "last updated",
        "model",
        "owner"
    );

    REAI_VEC_FOREACH (results, csr, {
        reai_plugin_table_add_rowf (
            t,
            "snssss",
            csr->collection_name,
            csr->collection_id,
            csr->scope,
            csr->last_updated_at,
            csr->model_name,
            csr->owned_by
        );
    });

    reai_plugin_table_show (t);
    reai_plugin_table_destroy (t);
    reai_collection_search_result_vec_destroy (results);

    return true;
}

Bool reai_plugin_collection_basic_info (
    RzCore                            *core,
    CString                            search_term,
    ReaiCollectionBasicInfoFilterFlags filter_flags,
    ReaiCollectionBasicInfoOrderBy     order_by,
    Bool                               order_in_asc
) {
    if (!core) {
        APPEND_ERROR ("Invalid arguments");
        return false;
    }

    if (!search_term) {
        APPEND_ERROR ("A valid search term required for fetching collection infos.");
        return false;
    }

    CString ordered_by_str = NULL;
    switch (order_by) {
        case REAI_COLLECTION_BASIC_INFO_ORDER_BY_COLLECTION :
            ordered_by_str = "collection";
            break;
        case REAI_COLLECTION_BASIC_INFO_ORDER_BY_COLLECTION_SIZE :
            ordered_by_str = "collection size";
            break;
        case REAI_COLLECTION_BASIC_INFO_ORDER_BY_MODEL :
            ordered_by_str = "model";
            break;
        case REAI_COLLECTION_BASIC_INFO_ORDER_BY_OWNER :
            ordered_by_str = "owner";
            break;
        case REAI_COLLECTION_BASIC_INFO_ORDER_BY_CREATED :
            ordered_by_str = "creation time";
            break;
        default :
            order_by       = REAI_COLLECTION_BASIC_INFO_ORDER_BY_COLLECTION;
            ordered_by_str = "collection";
            REAI_LOG_DEBUG (
                "Invalid order_by enum was provided. Corrected to default value \"collection\""
            );
    }

    CString ordered_in_str = order_in_asc ? "ascending" : "descending";

    ReaiCollectionBasicInfoVec *basic_info_vec = reai_get_basic_collection_info (
        reai(),
        reai_response(),
        search_term,
        filter_flags,
        25,
        0,
        order_by,
        order_in_asc
    );

    if (basic_info_vec) {
        basic_info_vec = reai_collection_basic_info_vec_clone_create (basic_info_vec);
    } else {
        return false;
    }

    char title[200] = {0};
    snprintf (
        title,
        sizeof (title),
        "Collections Basic Info, Ordered by %s in %s order",
        ordered_by_str,
        ordered_in_str
    );

    ReaiPluginTable *t = reai_plugin_table_create();
    reai_plugin_table_set_title (t, title);
    reai_plugin_table_set_columnsf (
        t,
        "snsnsss",
        "name",
        "id",
        "scope",
        "size",
        "model",
        "description",
        "owner"
    );

    REAI_VEC_FOREACH (basic_info_vec, csr, {
        reai_plugin_table_add_rowf (
            t,
            "snsnsss",
            csr->collection_name,
            csr->collection_id,
            csr->collection_scope,
            csr->collection_size,
            csr->model_name,
            csr->description,
            csr->collection_owner
        );
    });

    reai_plugin_table_show (t);
    reai_plugin_table_destroy (t);
    reai_collection_basic_info_vec_destroy (basic_info_vec);

    return true;
}

Bool reai_plugin_binary_search (
    RzCore *core,
    CString partial_name,
    CString partial_sha256,
    CString model_name,
    CString tags_csv
) {
    if (!core) {
        APPEND_ERROR ("Invalid arguments");
        return false;
    }

    CStrVec *tags = reai_plugin_csv_to_cstr_vec (tags_csv);

    ReaiBinarySearchResultVec *results = reai_binary_search (
        reai(),
        reai_response(),
        partial_name,
        partial_sha256,
        tags,
        model_name
    );

    if (tags) {
        reai_cstr_vec_destroy (tags);
    }

    if (results) {
        results = reai_binary_search_result_vec_clone_create (results);
    } else {
        return false;
    }

    ReaiPluginTable *t = reai_plugin_table_create();
    reai_plugin_table_set_title (t, "Collections Search Results");
    reai_plugin_table_set_columnsf (
        t,
        "snnssss",
        "name",
        "binary_id",
        "analysis_id",
        "model",
        "owner",
        "created_at",
        "sha256"
    );

    REAI_VEC_FOREACH (results, bsr, {
        reai_plugin_table_add_rowf (
            t,
            "snnssss",
            bsr->binary_name,
            bsr->binary_id,
            bsr->analysis_id,
            bsr->model_name,
            bsr->owned_by,
            bsr->created_at,
            bsr->sha_256_hash
        );
    });

    reai_plugin_table_show (t);
    reai_plugin_table_destroy (t);
    reai_binary_search_result_vec_destroy (results);

    return true;
}

Bool reai_plugin_get_analysis_logs (RzCore *core, Uint64 id, Bool is_analysis_id) {
    UNUSED (core);

    ReaiAnalysisId analysis_id = id;
    if (!is_analysis_id) {
        if (!id) {
            APPEND_ERROR ("Invalid binary ID provided. Cannot fetch logs.");
            return false;
        }
        analysis_id = reai_analysis_id_from_binary_id (reai(), reai_response(), id);

        if (!analysis_id) {
            APPEND_ERROR ("Failed to convert given binary ID to analysis ID");
            return false;
        }
    } else {
        if (!id) {
            APPEND_ERROR ("Invalid analysis ID provided. Cannot fetch logs.");
            return false;
        }
    }

    CString logs = reai_get_analysis_logs (reai(), reai_response(), analysis_id);
    if (logs) {
        DISPLAY_INFO ("%s", logs);
    } else {
        APPEND_ERROR ("Failed to fetch analysis logs.");
        return false;
    }

    return true;
}
