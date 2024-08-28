/**
 * @file : CmdHandlers.c
 * @date : 13th June 2024
 * @author : Siddharth Mishra (admin@brightprogrammer.in)
 * @copyright: Copyright (c) 2024 RevEngAI. All Rights Reserved.
 *
 * @b This file defines all the handlers that are declated inside `CmdGen/Output/CmdDescs.h`
 * After adding a new command entry, implement corresponding handlers here and then compile.
 * */

#include <Reai/AnalysisInfo.h>
#include <Reai/AnnFnMatch.h>
#include <Reai/Api/Api.h>
#include <Reai/Api/Reai.h>
#include <Reai/Api/Request.h>
#include <Reai/Api/Response.h>
#include <Reai/Common.h>
#include <Reai/Config.h>
#include <Reai/Db.h>
#include <Reai/FnInfo.h>
#include <Reai/Log.h>
#include <Reai/Types.h>

/* rizin */
#include <rz_analysis.h>
#include <rz_cmd.h>
#include <rz_cons.h>
#include <rz_list.h>
#include <rz_util/rz_assert.h>
#include <rz_util/rz_file.h>
#include <rz_util/rz_num.h>
#include <rz_util/rz_path.h>
#include <rz_util/rz_table.h>
#include <rz_vector.h>

/* local includes */
#include <Rizin/CmdGen/Output/CmdDescs.h>
#include <Plugin.h>

PRIVATE ReaiModel  get_ai_model_for_opened_bin_file (RzCore* core);
PRIVATE RzBinFile* get_opened_bin_file (RzCore* core);
PRIVATE CString    get_opened_bin_file_path (RzCore* core);
PRIVATE Uint64     get_opened_bin_file_baseaddr (RzCore* core);
PRIVATE CString    get_function_name_with_max_confidence (
       ReaiAnnFnMatchVec* fn_matches,
       ReaiFunctionId     origin_fn_id,
       Float64*           confidence
   );
PRIVATE ReaiFnInfoVec*     get_fn_infos (ReaiBinaryId bin_id);
PRIVATE ReaiAnnFnMatchVec* get_fn_matches (
    ReaiBinaryId bin_id,
    Float64      max_results,
    Float64      max_dist,
    CStrVec*     collections
);

/**
 * REi
 *
 * @b To be used on first setup of rizin plugin.
 *
 * This will create a new config file everytime it's called with correct arguments.
 * Requires a restart of rizin plugin after issue.
 * */
RZ_IPI RzCmdStatus rz_plugin_initialize_handler (RzCore* core, int argc, const char** argv) {
    UNUSED (core && argc);

    /* check whether API key is correct or not */
    RETURN_VALUE_IF (
        !reai_config_check_api_key (argv[2]),
        RZ_CMD_STATUS_ERROR,
        "Invalid API key. API key must be in format XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX"
    );

    /* check whether version number is specified or not */
    RETURN_VALUE_IF (
        !strstr (argv[1], "v1") || !strstr (argv[1], "v2"),
        RZ_CMD_STATUS_ERROR,
        "Host needs a version number to communicate with. Please append a /v1, /v2, etc... at the "
        "end of host."
    );

    CString reai_config_file_path = Null, db_dir_path = Null, log_dir_path = Null;

    reai_config_file_path = reai_config_get_default_path();
    GOTO_HANDLER_IF (!reai_config_file_path, FAILED, "Failed to get default config file path.");

    /* if file already exists then we don't make changes */
    FILE* reai_config_file = fopen (reai_config_file_path, "r");
    if (reai_config_file) {
        fclose (reai_config_file);
        rz_cons_printf (
            "Config file already exists. Remove or rename old config file to create new one.\n"
        );
    }

    db_dir_path = rz_str_home (".reai-rz");
    GOTO_HANDLER_IF (!db_dir_path, FAILED, "Failed to get database directory path.");

    log_dir_path = rz_file_tmpdir();
    GOTO_HANDLER_IF (!log_dir_path, FAILED, "Failed to get log storage directory path.");

    reai_config_file = fopen (reai_config_file_path, "w");
    GOTO_HANDLER_IF (!reai_config_file, FAILED, "Failed to open config file.");

    fprintf (reai_config_file, "host         = \"%s\"\n", argv[1]);
    fprintf (reai_config_file, "apikey       = \"%s\"\n", argv[2]);
    fprintf (reai_config_file, "model        = \"%s\"\n", argv[3]);
    fprintf (reai_config_file, "db_dir_path  = \"%s\"\n", db_dir_path);
    fprintf (reai_config_file, "log_dir_path = \"%s\"\n", log_dir_path);

    fclose (reai_config_file);
    FREE (log_dir_path);
    FREE (db_dir_path);

    /* try to reinit config after creating config */
    RETURN_VALUE_IF (
        !reai_plugin_init (core),
        RZ_CMD_STATUS_ERROR,
        "Failed to init plugin after creating a new config."
    );

    return RZ_CMD_STATUS_OK;

FAILED:
    if (reai_config_file_path) {
        FREE (reai_config_file_path);
    }
    if (db_dir_path) {
        FREE (db_dir_path);
    }
    if (log_dir_path) {
        FREE (log_dir_path);
    }
    return RZ_CMD_STATUS_ERROR;
}

/**
 * "REh"
 *
 * @b Perform a health-check api call to check connection.
 * */
RZ_IPI RzCmdStatus rz_health_check_handler (RzCore* core, int argc, const char** argv) {
    UNUSED (core && argc && argv);
    LOG_TRACE ("[CMD] health check");

    ReaiRequest request = {.type = REAI_REQUEST_TYPE_HEALTH_CHECK};

    RETURN_VALUE_IF (
        !reai_request (reai(), &request, reai_response()) || !reai_response()->health_check.success,
        RZ_CMD_STATUS_ERROR,
        "Health check failed."
    );

    printf ("OK\n");

    return RZ_CMD_STATUS_OK;
}

/**
 * "REa"
 *
 * @b Create a new analysis. If binary is not already uploaded then
 *    this will upload the currently opened binary.
 *
 * The method first checks whether the currently opened binary is already uploaded
 * or not. If the hash for uploaded binary is present in database, then latest hash
 * will be used, otherwise a new upload operation will be performed and the retrieved
 * hash will automatically be added to the database (by the creait lib).
 *
 * After getting the hash and making sure one latest instance of binary is already available,
 * we create analysis of the binary.
 *
 * TODO: compute sha256 hash of opened binary and check whether it matches the latest uploaded
 *       binary. If not then ask the user whether to perform a new upload or not.
 * TODO: check if an analysis already exists and whether user wants to reuse that analysis
 * TODO: check if analysis is already created. If not created then ask the user whether
 *       they really want to continue before analysis
 * */
RZ_IPI RzCmdStatus rz_create_analysis_handler (RzCore* core, int argc, const char** argv) {
    UNUSED (argc && argv);
    LOG_TRACE ("[CMD] create analysis");

    RzBinFile* binfile = get_opened_bin_file (core);
    GOTO_HANDLER_IF (!binfile, NO_BINFILE_OPENED, "No binary file opened. Cannot create analysis.");

    CString binfile_path = get_opened_bin_file_path (core);
    GOTO_HANDLER_IF (!binfile, NO_BINFILE_OPENED, "Failed to get binary file full path.");

    /* check if file is already uploaded or otherwise upload */
    CString sha256 = reai_db_get_latest_hash_for_file_path (reai_db(), binfile_path);
    if (!sha256) {
        LOG_TRACE ("Binary not already uploaded. Uploading...");

        sha256 = reai_upload_file (reai(), reai_response(), binfile_path);
        GOTO_HANDLER_IF (!sha256, UPLOAD_FAILED, "Failed to upload file.");
        GOTO_HANDLER_IF (!(sha256 = strdup (sha256)), UPLOAD_FAILED, ERR_OUT_OF_MEMORY);
    } else {
        LOG_TRACE ("using previously uploaded file with latest hash = \"%s\"", sha256);
    }

    /* warn the use if no analysis exists */
    GOTO_HANDLER_IF (
        !core->analysis->fcns->length,
        NONEXISTENT_RZ_ANALYSIS,
        "Rizin analysis not performed yet. Please issue an analysis command, eg: \"aaaa\""
    );

    /* get function boundaries to create analysis */
    ReaiFnInfoVec* fn_boundaries = reai_plugin_get_fn_boundaries (core);
    GOTO_HANDLER_IF (
        !fn_boundaries,
        NO_FUNCTION_BOUNDARIES,
        "Failed to get function boundaries for opened binary."
    );

    /* create analysis */
    ReaiBinaryId bin_id = reai_create_analysis (
        reai(),
        reai_response(),
        get_ai_model_for_opened_bin_file (core),
        get_opened_bin_file_baseaddr (core),
        fn_boundaries,
        True,
        sha256,
        rz_file_basename (binfile_path),
        Null,
        binfile->size
    );
    GOTO_HANDLER_IF (
        !bin_id,
        ANALYSIS_CREATION_FAILED,
        "Failed to create analysis : %s",
        reai_response()->raw.data
    );

    /* destroy after use */
    FREE (sha256);
    FREE (binfile_path);
    reai_fn_info_vec_destroy (fn_boundaries);

    return RZ_CMD_STATUS_OK;

ANALYSIS_CREATION_FAILED: { reai_fn_info_vec_destroy (fn_boundaries); }
NONEXISTENT_RZ_ANALYSIS:
NO_FUNCTION_BOUNDARIES: { FREE (sha256); }
UPLOAD_FAILED: { FREE (binfile_path); }

NO_BINFILE_OPENED:
    return RZ_CMD_STATUS_ERROR;
}

/**
 * REau
 *
 * @b Perform a Batch Symbol ANN request with current binary ID and
 *    automatically rename all methods.
 * */
RZ_IPI RzCmdStatus rz_ann_auto_analyze_handler (
    RzCore*      core,
    int          argc,
    const char** argv,
    RzOutputMode output_mode
) {
    UNUSED (output_mode);
    RETURN_VALUE_IF (argc < 4, RZ_CMD_STATUS_WRONG_ARGS, ERR_INVALID_ARGUMENTS);
    LOG_TRACE ("[CMD] ANN Auto Analyze Binary");

    // get opened binary file and print error if no binary is loaded
    RzBinFile* binfile = get_opened_bin_file (core);
    GOTO_HANDLER_IF (!binfile, NO_BINFILE_OPENED, "No binary file opened.");

    CString binfile_path = get_opened_bin_file_path (core);
    GOTO_HANDLER_IF (!binfile, NO_BINFILE_OPENED, "Failed to get binary file full path.");

    /* try to get latest analysis for loaded binary (if exists) */
    ReaiBinaryId bin_id = reai_db_get_latest_analysis_for_file (reai_db(), binfile_path);
    GOTO_HANDLER_IF (!bin_id, NONEXISTENT_ANALYSIS, "Nonexistent analysis. Create analysis first.");

    /* an analysis must already exist in order to make auto-analysis work */
    ReaiAnalysisStatus analysis_status = reai_db_get_analysis_status (reai_db(), bin_id);
    GOTO_HANDLER_IF (
        analysis_status != REAI_ANALYSIS_STATUS_COMPLETE,
        INCOMPLETE_ANALYSIS,
        "Incomplete analysis. Current status = '%s'",
        reai_analysis_status_to_cstr (analysis_status)
    );

    /* names of current functions */
    ReaiFnInfoVec* fn_infos = get_fn_infos (bin_id);
    GOTO_HANDLER_IF (
        !fn_infos,
        GET_FN_INFOS_FAILED,
        "Failed to get function infos for opened binary."
    );

    /* parse args */
    Float64 max_distance             = rz_num_get_float (core->num, argv[1]);
    Size    max_results_per_function = rz_num_math (core->num, argv[2]);
    Float64 min_confidence           = rz_num_get_float (core->num, argv[3]);

    /* function matches */
    ReaiAnnFnMatchVec* fn_matches =
        get_fn_matches (bin_id, max_results_per_function, max_distance, Null);
    GOTO_HANDLER_IF (
        !fn_matches,
        GET_FN_MATCHES_FAILED,
        "Failed to get function matches for opened binary."
    );

    /* new vector where new names of functions will be stored */
    ReaiFnInfoVec* new_name_mapping = reai_fn_info_vec_create();
    GOTO_HANDLER_IF (
        !new_name_mapping,
        CREATE_NEW_NAME_VEC_FAILED,
        "Failed to create new name mapping vector object."
    );

    /* prepare table and print info */
    /* clang-format off */
    RzTable* table = rz_table_new();
    GOTO_HANDLER_IF (!table, TABLE_CREATE_FAILED, "Failed to create table.");
    rz_table_set_columnsf (table, "sssnsn", "rizin name", "old_name", "new_name", "confidence", "success", "address");

    /* display information about what renames will be performed */    /* add rename information to new name mapping */
    /* rename the functions in rizin */
    REAI_VEC_FOREACH(fn_infos, fn, {
        Float64 confidence = min_confidence;
        CString new_name   = Null;
        CString old_name   = fn->name;
        Uint64 fn_addr = fn->vaddr + get_opened_bin_file_baseaddr(core);

        /* if we get a match with required confidence level then we add to rename */
        if ((new_name = get_function_name_with_max_confidence (fn_matches, fn->id, &confidence))) {
            /* If functions already are same then no need to rename */
            if (!strcmp (new_name, old_name)) {
                rz_table_add_rowf (table, "sssfsx", "not required", old_name, new_name, (Float64)1.0, "true", fn_addr);
                continue;
            }

            /* if append fails then destroy everything and return error */
            Bool append = !!reai_fn_info_vec_append (new_name_mapping, &((ReaiFnInfo) {.name = new_name, .id = fn->id}));
            GOTO_HANDLER_IF(!append, NEW_NAME_APPEND_FAILED, "Failed to apend item to FnInfoVec.");

            /* get function */
            RzAnalysisFunction* rz_fn = rz_analysis_get_function_at (core->analysis, fn->vaddr + get_opened_bin_file_baseaddr(core));
            if (rz_fn) {
                /* check if fucntion size matches */
                CString rz_old_name = strdup(rz_fn->name);
                if(rz_analysis_function_linear_size(rz_fn) != fn->size) {
                    rz_table_add_rowf (table, "sssfsx", rz_old_name, old_name, new_name, confidence, "function size mismatch", fn_addr);
                    FREE(rz_old_name);
                    continue;
                }

                /* rename function */
                if (!rz_analysis_function_rename (rz_fn, new_name)) {
                    rz_table_add_rowf (table, "sssfsx", rz_old_name, old_name, new_name, confidence, "rename error", fn_addr);
                } else {
                    rz_table_add_rowf (table, "sssfsx", rz_old_name, old_name, new_name, confidence, "true", fn_addr);
                }

                FREE(rz_old_name);
            } else {
                rz_table_add_rowf (table, "sssfsx", "(null)", old_name, new_name, (Float64)0.0, "function not found", fn_addr);
            }
        } else {
            rz_table_add_rowf (table, "sssfsx", "not required", old_name, "n/a", (Float64)0.0, "match not found", fn_addr );
        }
    });
    /* clang-format on */

    /* print table */
    CString table_str = rz_table_tofancystring (table);
    GOTO_HANDLER_IF (!table_str, TABLE_TO_STR_FAILED, "Failed to convert table to string.");
    rz_cons_printf ("%s\n", table_str);

    /* perform a batch rename */
    if (new_name_mapping->count) {
        Bool res = reai_batch_renames_functions (reai(), reai_response(), new_name_mapping);
        GOTO_HANDLER_IF (!res, BATCH_RENAME_FAILED, "Failed to rename all functions in binary.");
    } else {
        eprintf ("No function will be renamed.\n");
    }

    rz_table_free (table);
    reai_fn_info_vec_destroy (new_name_mapping);
    reai_ann_fn_match_vec_destroy (fn_matches);
    reai_fn_info_vec_destroy (fn_infos);
    FREE (binfile_path);

    return RZ_CMD_STATUS_OK;

/* handlers */
BATCH_RENAME_FAILED:
TABLE_TO_STR_FAILED:
NEW_NAME_APPEND_FAILED: { rz_table_free (table); }

TABLE_CREATE_FAILED: { reai_fn_info_vec_destroy (new_name_mapping); }

CREATE_NEW_NAME_VEC_FAILED: { reai_ann_fn_match_vec_destroy (fn_matches); }

GET_FN_MATCHES_FAILED: { reai_fn_info_vec_destroy (fn_infos); }

GET_FN_INFOS_FAILED:
INCOMPLETE_ANALYSIS:
NONEXISTENT_ANALYSIS: { FREE (binfile_path); }

NO_BINFILE_OPENED:
    return RZ_CMD_STATUS_ERROR;
}

/**
 * "REu"
 *
 * Upload a binary to RevEng.AI Servers. Checks for latest uploaded
 * binary already present in database and performs the upload operation
 * only if binary is not already uploaded.
 *
 * TODO: compare latest hash in database with current hash of binary.
 *       if the don't match then ask the user what to do.
 * */
RZ_IPI RzCmdStatus rz_upload_bin_handler (RzCore* core, int argc, const char** argv) {
    UNUSED (argc && argv);
    LOG_TRACE ("[CMD] upload binary");

    /* get file path */
    CString binfile_path = get_opened_bin_file_path (core);
    RETURN_VALUE_IF (
        !binfile_path,
        RZ_CMD_STATUS_ERROR,
        "No binary file opened. Cannot perform upload."
    );

    /* check if file is already uploaded or otherwise upload */
    CString sha256 = reai_db_get_latest_hash_for_file_path (reai_db(), binfile_path);
    if (!sha256) {
        sha256 = reai_upload_file (reai(), reai_response(), binfile_path);
        GOTO_HANDLER_IF (!sha256, UPLOAD_FAILED, "Failed to upload binary file.");
    } else {
        LOG_TRACE ("File already uploaded (and recorded in db) with hash = \"%s\"", sha256);
    }

    FREE (binfile_path);
    return RZ_CMD_STATUS_OK;

UPLOAD_FAILED:
    FREE (binfile_path);
    return RZ_CMD_STATUS_ERROR;
}

/**
 * "REs"
 *
 * @b Get analysis status for given binary id. If no binary id is provided
 *    then currently opened binary is used. If no binary is opened then
 *    the command fails.
 * */
RZ_IPI RzCmdStatus rz_get_analysis_status_handler (
    RzCore*           core,
    int               argc,
    const char**      argv,
    RzCmdStateOutput* state
) {
    LOG_TRACE ("[CMD] get analysis status");
    RETURN_VALUE_IF (!state, RZ_CMD_STATUS_WRONG_ARGS, ERR_INVALID_ARGUMENTS);

    ReaiBinaryId binary_id = 0;
    if (argc == 2) {
        binary_id = rz_num_math (core->num, argv[1]);

        RETURN_VALUE_IF (!binary_id, RZ_CMD_STATUS_ERROR, "Invalid binary id provided.");
        LOG_TRACE ("Using provided binary id : %llu.", binary_id);
    } else {
        CString opened_binfile_path = get_opened_bin_file_path (core);
        RETURN_VALUE_IF (!opened_binfile_path, RZ_CMD_STATUS_ERROR, "No binary file opened.");

        binary_id = reai_db_get_latest_analysis_for_file (reai_db(), opened_binfile_path);
        FREE (opened_binfile_path);

        RETURN_VALUE_IF (
            !binary_id,
            RZ_CMD_STATUS_ERROR,
            "No analysis exists for currently opened binary in database."
        );

        LOG_TRACE (
            "Using binary id of latest analysis for loaded binary present in database : %llu.",
            binary_id
        );
    }

    /* if analyses already exists in db */
    if (reai_db_check_analysis_exists (reai_db(), binary_id)) {
        LOG_TRACE ("Analysis already exists in database. Fetching status from database.");

        ReaiAnalysisStatus analysis_status = reai_db_get_analysis_status (reai_db(), binary_id);
        RETURN_VALUE_IF (
            !analysis_status,
            RZ_CMD_STATUS_ERROR,
            "reai_db_get_analysis_staus returned NULL."
        );
        rz_cons_printf (
            "Analysis Status : \"%s\"\n",
            reai_analysis_status_to_cstr (analysis_status)
        );
    } else {
        LOG_TRACE ("Analysis does not exist in database. Fetching status from RevEng.AI servers.");

        ReaiAnalysisStatus status = reai_get_analysis_status (reai(), reai_response(), binary_id);
        RETURN_VALUE_IF (!status, RZ_CMD_STATUS_ERROR, "Failed to get analysis status.");
        rz_cons_printf ("Analysis status = \"%s\"\n", reai_analysis_status_to_cstr (status));
    }

    return RZ_CMD_STATUS_OK;
}

/**
 * "REfl"
 *
 * @b Get information about all functions detected by the AI model from
 *    RevEng.AI servers.
 *
 * TODO: take a binary id argument to get info of any analysis and not just
 *       currently opened analysis.
 *
 * NOTE: for now this works just for currently opened binary file. If binary
 *       file is not opened, this will return with `RZ_CMD_STATUS_ERROR`.
 *       If analysis for binary file does not exist then this will again return
 *       with an error.
 * */
RZ_IPI RzCmdStatus rz_get_basic_function_info_handler (
    RzCore*      core,
    int          argc,
    const char** argv,
    RzOutputMode output_mode
) {
    UNUSED (argc && argv && output_mode);
    LOG_TRACE ("[CMD] get basic function info");

    /* get file path of opened binary file */
    CString opened_file = get_opened_bin_file_path (core);
    RETURN_VALUE_IF (!opened_file, RZ_CMD_STATUS_ERROR, "No binary file opened.");

    /* get binary id of opened file */
    ReaiBinaryId binary_id = reai_db_get_latest_analysis_for_file (reai_db(), opened_file);
    RETURN_VALUE_IF (
        !binary_id,
        RZ_CMD_STATUS_ERROR,
        "No analysis created for opened binary file."
    );

    /* get analysis status from db after an update and check for completion */
    ReaiAnalysisStatus analysis_status = reai_db_get_analysis_status (reai_db(), binary_id);
    RETURN_VALUE_IF (
        !analysis_status,
        RZ_CMD_STATUS_ERROR,
        "Failed to get analysis status of binary from DB."
    );
    if (analysis_status != REAI_ANALYSIS_STATUS_COMPLETE) {
        rz_cons_printf (
            "Analysis not yet complete. Current status = \"%s\"\n",
            reai_analysis_status_to_cstr (analysis_status)
        );
        return RZ_CMD_STATUS_OK; // It's ok, check again after sometime
    }

    /* make request to get function infos */
    ReaiFnInfoVec* fn_infos = reai_get_basic_function_info (reai(), reai_response(), binary_id);
    if (!fn_infos) {
        PRINT_ERR ("Failed to get function info from RevEng.AI servers.");
        return RZ_CMD_STATUS_ERROR;
    }


    // prepare table and print info
    RzTable* table = rz_table_new();
    RETURN_VALUE_IF (!table, RZ_CMD_STATUS_ERROR, "Failed to create table.");

    rz_table_set_columnsf (table, "nsxx", "function_id", "name", "vaddr", "size");
    REAI_VEC_FOREACH (fn_infos, fn, {
        rz_table_add_rowf (table, "nsxx", fn->id, fn->name, fn->vaddr, fn->size);
    });

    CString table_str = rz_table_tofancystring (table);
    if (!table_str) {
        PRINT_ERR ("Failed to convert table to string.");
        rz_table_free (table);
        return RZ_CMD_STATUS_ERROR;
    }

    rz_cons_printf ("%s\n", table_str);

    FREE (table_str);
    rz_table_free (table);

    return RZ_CMD_STATUS_OK;
}

/**
 * "REfr"
 *
 * @b Rename function with given function id to given new name.
 * */
RZ_IPI RzCmdStatus rz_rename_function_handler (RzCore* core, int argc, const char** argv) {
    LOG_TRACE ("[CMD] rename function");
    RETURN_VALUE_IF (
        (argc < 3) || !argv || !argv[1] || !argv[2],
        RZ_CMD_STATUS_WRONG_ARGS,
        ERR_INVALID_ARGUMENTS
    );

    /* new name to rename to */
    CString new_name = argv[2];

    /* parse function id string */
    ReaiFunctionId function_id = rz_num_math (core->num, argv[1]);
    RETURN_VALUE_IF (!function_id, RZ_CMD_STATUS_ERROR, "Invalid function id.");

    /* perform rename operation */
    RETURN_VALUE_IF (
        !reai_rename_function (reai(), reai_response(), function_id, new_name),
        RZ_CMD_STATUS_ERROR,
        "Failed to rename function"
    );

    return RZ_CMD_STATUS_OK;
}

/**
 * @b Get referfence to @c RzBinFile for currently opened binary file.
 *
 * @param core
 *
 * @return @c RzBinFile if a binary file is opened (on success).
 * @return @c Null otherwise.
 * */
PRIVATE RzBinFile* get_opened_bin_file (RzCore* core) {
    RETURN_VALUE_IF (!core, Null, ERR_INVALID_ARGUMENTS);

    return core->bin ? core->bin->binfiles ?
                       core->bin->binfiles->length ?
                       rz_list_head (core->bin->binfiles) ?
                       rz_list_iter_get_data (rz_list_head (core->bin->binfiles)) :
                       Null :
                       Null :
                       Null :
                       Null;
}

/**
 * @b Get operating AI model to use with currently opened binary file.
 *
 * @param core
 *
 * @return @c REAI_MODEL_UNKNOWN on failure.
 * */
PRIVATE ReaiModel get_ai_model_for_opened_bin_file (RzCore* core) {
    RETURN_VALUE_IF (!core, REAI_MODEL_UNKNOWN, ERR_INVALID_ARGUMENTS);

    RzBinFile* binfile = get_opened_bin_file (core);
    if (binfile->o->info->os) {
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
 * @return @c Null otherwise.
 * */
PRIVATE CString get_opened_bin_file_path (RzCore* core) {
    RzBinFile* binfile = get_opened_bin_file (core);
    return binfile ? rz_path_realpath (binfile->file) : Null;
}

/**
 * @b Get base address of currently opened binary file.
 *
 * @param core
 *
 * @return @c Base address if a binary file is opened.
 * @return @c 0 otherwise.
 * */
PRIVATE Uint64 get_opened_bin_file_baseaddr (RzCore* core) {
    RzBinFile* binfile = get_opened_bin_file (core);
    return binfile ? binfile->o->opts.baseaddr : 0;
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
 *        If not @c Null then value of max confidence of returned function name will
 *        be stored in this pointer.
 *        If @c Null then just the function with max confidence will be selected.
 *
 * @return @c Name of function if present and has a confidence level greater than or equal to
 *            given confidence.
 * @return @c Null otherwise.
 * */
PRIVATE CString get_function_name_with_max_confidence (
    ReaiAnnFnMatchVec* fn_matches,
    ReaiFunctionId     origin_fn_id,
    Float64*           required_confidence
) {
    RETURN_VALUE_IF (!fn_matches || !origin_fn_id, Null, ERR_INVALID_ARGUMENTS);

    Float64 max_confidence = 0;
    CString fn_name        = Null;
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
        fn_name              = max_confidence >= *required_confidence ? fn_name : Null;
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
 * @return @c Null otherwise.
 * */
PRIVATE ReaiFnInfoVec* get_fn_infos (ReaiBinaryId bin_id) {
    RETURN_VALUE_IF (!bin_id, Null, ERR_INVALID_ARGUMENTS);

    /* get function names for all functions in the binary (this is why we need analysis) */
    ReaiFnInfoVec* fn_infos = reai_get_basic_function_info (reai(), reai_response(), bin_id);
    RETURN_VALUE_IF (!fn_infos, Null, "Failed to get binary function names.");
    RETURN_VALUE_IF (!fn_infos->count, Null, "Current binary does not have any function.");

    /* try cloning */
    fn_infos = reai_fn_info_vec_clone_create (fn_infos);
    RETURN_VALUE_IF (!fn_infos, Null, "FnInfos vector clone failed");

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
 * @return @c Null otherwise.
 * */
PRIVATE ReaiAnnFnMatchVec* get_fn_matches (
    ReaiBinaryId bin_id,
    Float64      max_results,
    Float64      max_dist,
    CStrVec*     collections
) {
    ReaiAnnFnMatchVec* fn_matches = reai_batch_binary_symbol_ann (
        reai(),
        reai_response(),
        bin_id,
        max_results,
        max_dist,
        collections
    );
    RETURN_VALUE_IF (!fn_matches, Null, "Failed to get ANN binary symbol similarity result");
    RETURN_VALUE_IF (!fn_matches->count, Null, "No similar functions found");

    /* try clone */
    fn_matches = reai_ann_fn_match_vec_clone_create (fn_matches);
    RETURN_VALUE_IF (!fn_matches, Null, "ANN Fn Match vector clone failed.");

    return fn_matches;
}
