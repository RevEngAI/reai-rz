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
#include <Reai/Api/Api.h>
#include <Reai/Api/Reai.h>
#include <Reai/Api/Request.h>
#include <Reai/Api/Response.h>
#include <Reai/Common.h>
#include <Reai/Db.h>
#include <Reai/FnInfo.h>
#include <Reai/Types.h>

/* rizin */
#include <rz_cmd.h>
#include <rz_util/rz_assert.h>

/* local includes */
#include "CmdGen/Output/CmdDescs.h"
#include "Plugin.h"

PRIVATE RzBinFile* get_opened_bin_file (RzCore* core);
PRIVATE CString    get_opened_bin_file_path (RzCore* core);

/**
 * "REh"
 *
 * @b Perform a health-check api call to check connection.
 * */
RZ_IPI RzCmdStatus rz_health_check_handler (RzCore* core, int argc, const char** argv) {
    UNUSED (core && argc && argv);
    LOG_TRACE ("[CMD] health check");

    ReaiRequest request = {.type = REAI_REQUEST_TYPE_HEALTH_CHECK};

    if (reai_request (reai(), &request, reai_response()) && reai_response()->health_check.success) {
        printf ("REAI Health Check SUCCESS\n");
        LOG_INFO ("health check SUCCESS");
    } else {
        eprintf ("REAI Health Check FAILURE\n");
        LOG_ERROR ("health check FAILED : JSON = \"%s\"", reai_response()->raw.data);
        return RZ_CMD_STATUS_ERROR;
    }

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
 * */
RZ_IPI RzCmdStatus rz_create_analysis_handler (RzCore* core, int argc, const char** argv) {
    UNUSED (argc && argv);
    LOG_TRACE ("[CMD] create analysis");

    RzBinFile* binfile      = get_opened_bin_file (core);
    CString    binfile_path = get_opened_bin_file_path (core);
    RETURN_VALUE_IF (
        !binfile || !binfile_path,
        RZ_CMD_STATUS_ERROR,
        "No binary file opened. Cannot create analysis.\n"
    );

    LOG_TRACE ("file_path = %s", binfile_path);

    /* check if file is already uploaded or otherwise upload */
    CString sha256 = reai_db_get_latest_hash_for_file_path (reai_db(), binfile_path);
    if (!sha256) {
        sha256 = reai_upload_file (reai(), reai_response(), binfile_path);

        if (sha256) {
            sha256 = strdup (sha256);
            RETURN_VALUE_IF (!sha256, RZ_CMD_STATUS_ERROR, ERR_OUT_OF_MEMORY);

            LOG_TRACE ("uploaded file \"%s\"", sha256);
        } else {
            PRINT_ERR ("Failed to upload file.");
            LOG_ERROR ("JSON = \"%s\"", reai_response()->raw.data);
            return RZ_CMD_STATUS_ERROR;
        }
    } else {
        LOG_TRACE ("using previously uploaded file with latest hash = \"%s\"", sha256);
    }

    /* get function boundaries to create analysis */
    ReaiFnInfoVec* fn_boundaries = reai_plugin_get_fn_boundaries (binfile);

    if (fn_boundaries) {
        LOG_TRACE ("sending %zu pre-analyzed functions to create analysis", fn_boundaries->count);
    } else {
        LOG_TRACE ("no function symbols being sent to create analysis");
    }

    /* create analysis */
    ReaiBinaryId bin_id = reai_create_analysis (
        reai(),
        reai_response(),
        REAI_MODEL_BINNET_0_3_X86_LINUX,
        fn_boundaries,
        True,
        sha256,
        binfile->file,
        Null,
        binfile->size
    );

    if (reai_response()->create_analysis.success) {
        LOG_TRACE ("created new analysis. binary_id = %llu", bin_id);
    } else {
        LOG_TRACE ("failed to create new analysis. JSON = \"%s\"", reai_response()->raw.data);
    }

    /* destroy after use */
    FREE (sha256);
    reai_fn_info_vec_destroy (fn_boundaries);

    RETURN_VALUE_IF (!bin_id, RZ_CMD_STATUS_ERROR, "Failed to create analysis.");
    return RZ_CMD_STATUS_OK;
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
        "No binary file opened. Cannot perform upload.\n"
    );

    LOG_TRACE ("file_path = %s", binfile_path);

    /* check if file is already uploaded or otherwise upload */
    CString sha256 = reai_db_get_latest_hash_for_file_path (reai_db(), binfile_path);
    if (!sha256) {
        sha256 = reai_upload_file (reai(), reai_response(), binfile_path);

        if (sha256) {
            sha256 = strdup (sha256);
            RETURN_VALUE_IF (!sha256, RZ_CMD_STATUS_ERROR, ERR_OUT_OF_MEMORY);

            LOG_TRACE ("uploaded file \"%s\"", sha256);
        } else {
            PRINT_ERR ("Failed to upload file.");
            LOG_ERROR ("JSON = \"%s\"", reai_response()->raw.data);
            return RZ_CMD_STATUS_ERROR;
        }
    } else {
        LOG_TRACE ("using previously uploaded file with latest hash = \"%s\"", sha256);
    }

    return RZ_CMD_STATUS_OK;
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

    /* not required really but we call it when we have a chance
     * we don't really need to use the database to get analysis status */
    if (!reai_update_all_analyses_status_in_db (reai())) {
        LOG_TRACE (
            "Failed to update all analysis status in DB. JSON = \"%s\"",
            reai_response()->raw.data
        );
    }

    ReaiBinaryId binary_id = 0;
    if (argc == 2) {
        binary_id = rz_num_math (core->num, argv[1]);

        RETURN_VALUE_IF (!binary_id, RZ_CMD_STATUS_ERROR, "Invalid binary id provided.");
    } else {
        binary_id =
            reai_db_get_latest_analysis_for_file (reai_db(), get_opened_bin_file_path (core));

        RETURN_VALUE_IF (
            !binary_id,
            RZ_CMD_STATUS_ERROR,
            "No analysis exists for currently opened binary in database."
        );
    }

    /* if analyses already exists in db */
    if (reai_db_check_analysis_exists (reai_db(), binary_id)) {
        CString analysis_status = reai_db_get_analysis_status (reai_db(), binary_id);

        rz_cons_printf ("Analysis Status : \"%s\"\n", analysis_status);
        LOG_TRACE ("Analysis Status : \"%s\"", analysis_status);

        FREE (analysis_status);
    } else {
        ReaiAnalysisStatus status = reai_get_analysis_status (reai(), reai_response(), binary_id);

        if (status) {
            rz_cons_printf ("Analysis status = \"%s\"\n", reai_analysis_status_to_cstr (status));
            LOG_TRACE ("Analysis Status : \"%s\"", status);
        } else {
            PRINT_ERR ("Failed to fetch analysis status.\n");
            LOG_ERROR ("JSON = \"%s\"", reai_response()->raw.data);
        }
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
    RzCore*           core,
    int               argc,
    const char**      argv,
    RzCmdStateOutput* state
) {
    UNUSED (core && argc && argv);
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

    /* check analyses status before proceeding further */
    if (!reai_update_all_analyses_status_in_db (reai())) {
        LOG_TRACE (
            "Failed to update analysis status of all binaries in database. JSON = \"%s\"",
            reai_response()->raw.data
        );
    }

    /* get analysis status from db after an update and check for completion */
    CString analysis_status = reai_db_get_analysis_status (reai_db(), binary_id);
    RETURN_VALUE_IF (
        !analysis_status,
        RZ_CMD_STATUS_ERROR,
        "Failed to get analysis status of binary from DB."
    );
    if (reai_analysis_status_from_cstr (analysis_status) != REAI_ANALYSIS_STATUS_COMPLETE) {
        LOG_INFO ("Analysis not complete yet. Current status = \"%s\"", analysis_status);
        rz_cons_printf ("Analysis not yet complete. Current status = \"%s\"\n", analysis_status);
        return RZ_CMD_STATUS_OK; // It's ok, check again after sometime
    }
    FREE (analysis_status);

    /* make request to get function infos */
    ReaiFnInfoVec* fn_infos = reai_get_basic_function_info (reai(), reai_response(), binary_id);
    if (!fn_infos) {
        PRINT_ERR ("Failed to get function info from RevEng.AI servers.");
        LOG_TRACE ("JSON = %s", reai_response()->raw.data);
        return RZ_CMD_STATUS_ERROR;
    }

    switch (state->mode) {
        case RZ_OUTPUT_MODE_TABLE : {
            rz_cmd_state_output_array_end (state);
            rz_cmd_state_output_set_columnsf (
                state,
                "nsxx",
                "function_id",
                "name",
                "vaddr",
                "size"
            );

            RzTable* table = state->d.t;
            REAI_VEC_FOREACH (fn_infos, fn, {
                rz_table_add_rowf (table, "nsxx", fn->id, fn->name, fn->vaddr, fn->size);
            });

            rz_cmd_state_output_array_end (state);
            break;
        }

        default : {
            PRINT_ERR ("Unsupported output format %d.", state->mode);
            rz_warn_if_reached();
            break;
        }
    }

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

    LOG_TRACE ("rename function_id=%llu to new_name=\"%s\"", function_id, new_name);

    /* perform rename operation */
    if (!reai_rename_function (reai(), reai_response(), function_id, new_name)) {
        PRINT_ERR ("Failed to rename function");
        LOG_TRACE ("JSON = %s", reai_response()->raw.data);
        return RZ_CMD_STATUS_ERROR;
    }

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
    return core ? core->bin ? core->bin->binfiles ?
                              core->bin->binfiles->length ?
                              core->bin->binfiles->head ? core->bin->binfiles->head->elem : Null :
                              Null :
                              Null :
                              Null :
                  Null;
}

/**
 * @b Get path of currently opened binary file.
 *
 * The returned string is not owned by caller and must not be passed to FREE.
 *
 * @param core
 *
 * @return @c CString if a binary file is opened.
 * @return @c Null otherwise.
 * */
PRIVATE CString get_opened_bin_file_path (RzCore* core) {
    RzBinFile* binfile = get_opened_bin_file (core);
    return binfile ? binfile->file : Null;
}
