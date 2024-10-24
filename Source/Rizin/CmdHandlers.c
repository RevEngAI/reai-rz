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

/**
 * REi
 *
 * @b To be used on first setup of rizin plugin.
 *
 * This will create a new config file everytime it's called with correct arguments.
 * Requires a restart of rizin plugin after issue.
 * */
RZ_IPI RzCmdStatus rz_plugin_initialize_handler (RzCore* core, int argc, const char** argv) {
    /* if file already exists then we don't make changes */
    if (reai_plugin_check_config_exists()) {
        DISPLAY_ERROR (
            "Config file already exists. Remove/rename previous config to create new one."
        );
    }

    /* no need to check whether these strings are empty or not in rizin
     * because rizin shell automatically checks this */
    CString host    = argv[1];
    CString api_key = argv[2];
    CString model   = argv[3];

    if (!host) {
        DISPLAY_ERROR ("Host is not specified. Failed to parse command.");
        return RZ_CMD_STATUS_WRONG_ARGS;
    }

    if (!api_key) {
        DISPLAY_ERROR ("API key is not specified. Failed to parse command.");
        return RZ_CMD_STATUS_WRONG_ARGS;
    }

    if (!model) {
        DISPLAY_ERROR ("Model is not specified. Failed to parse command.");
        return RZ_CMD_STATUS_WRONG_ARGS;
    }

    /* check whether API key is correct or not */
    if (!reai_config_check_api_key (api_key)) {
        DISPLAY_ERROR (
            "Invalid API key. API key must be in format XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX"
        );
        return RZ_CMD_STATUS_ERROR;
    }

    if (!reai_config_check_api_key (argv[2])) {
        DISPLAY_ERROR (
            "Provided API key is invalid. It's recommended to directly copy paste the API key from "
            "RevEng.AI dashboard."
        );
        return RZ_CMD_STATUS_ERROR;
    }

    CString db_dir_path = NULL, log_dir_path = NULL;

    db_dir_path = reai_plugin_get_default_database_dir_path();
    if (!db_dir_path) {
        DISPLAY_ERROR ("Failed to get database directory path.");
        return RZ_CMD_STATUS_ERROR;
    }

    log_dir_path = reai_plugin_get_default_log_dir_path();
    if (!log_dir_path) {
        DISPLAY_ERROR ("Failed to get log storage directory path.");
        return RZ_CMD_STATUS_ERROR;
    }

    /* attempt saving config */
    if (reai_plugin_save_config (host, api_key, model, db_dir_path, log_dir_path)) {
        /* try to reinit config after creating config */
        if (!reai_plugin_init (core)) {
            DISPLAY_ERROR ("Failed to init plugin after creating a new config.");
            return RZ_CMD_STATUS_ERROR;
        }
    } else {
        DISPLAY_ERROR ("Failed to save config.");
        return RZ_CMD_STATUS_ERROR;
    }

    return RZ_CMD_STATUS_OK;
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

    if (!reai_request (reai(), &request, reai_response()) ||
        !reai_response()->health_check.success) {
        DISPLAY_ERROR ("Health check failed.");
        return RZ_CMD_STATUS_ERROR;
    }

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

    return reai_plugin_create_analysis_for_opened_binary_file (core) ? RZ_CMD_STATUS_OK :
                                                                       RZ_CMD_STATUS_ERROR;
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
    UNUSED (output_mode && argc);
    LOG_TRACE ("[CMD] ANN Auto Analyze Binary");

    /* parse args */
    Float64 max_distance             = rz_num_get_float (core->num, argv[1]);
    Size    max_results_per_function = rz_num_math (core->num, argv[2]);
    Float64 min_confidence           = rz_num_get_float (core->num, argv[3]);

    if (reai_plugin_auto_analyze_opened_binary_file (
            core,
            max_distance,
            max_results_per_function,
            min_confidence
        )) {
        DISPLAY_INFO ("Auto-analysis completed successfully.");
        return RZ_CMD_STATUS_OK;
    } else {
        DISPLAY_ERROR (
            "Failed to perform RevEng.AI auto-analysis (apply analysis results in rizin/cutter)"
        );
        return RZ_CMD_STATUS_ERROR;
    }
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

    if (reai_plugin_upload_opened_binary_file (core)) {
        DISPLAY_ERROR ("File upload successful.");
        return RZ_CMD_STATUS_OK;
    } else {
        DISPLAY_ERROR ("File upload failed.");
        return RZ_CMD_STATUS_ERROR;
    }
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
    UNUSED (state);
    LOG_TRACE ("[CMD] get analysis status");

    ReaiBinaryId binary_id = 0;

    /* if arguments are provided then we need to use the provided binary id */
    if (argc > 1) {
        binary_id = rz_num_math (core->num, argv[1]);

        if (!binary_id) {
            DISPLAY_ERROR ("Invalid binary id provided. Cannot fetch analysis status.");
            return RZ_CMD_STATUS_ERROR;
        }

        LOG_TRACE ("Using provided binary id : %llu.", binary_id);
    } else {
        binary_id = reai_plugin_get_binary_id_for_opened_binary_file (core);

        if (!binary_id) {
            DISPLAY_ERROR ("Failed to get binary id for currently opened binary file.");
            return RZ_CMD_STATUS_ERROR;
        }
    }

    /* get analysis status */
    ReaiAnalysisStatus analysis_status = reai_plugin_get_analysis_status_for_binary_id (binary_id);
    if (analysis_status) {
        DISPLAY_INFO ("Analysis status : \"%s\"", reai_analysis_status_to_cstr (analysis_status));
        return RZ_CMD_STATUS_OK;
    } else {
        DISPLAY_ERROR ("Failed to get analysis status.");
        return RZ_CMD_STATUS_ERROR;
    }
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
    CString opened_file = reai_plugin_get_opened_binary_file_path (core);
    if (!opened_file) {
        DISPLAY_ERROR ("No binary file opened.");
        return RZ_CMD_STATUS_ERROR;
    }

    /* get binary id of opened file */
    ReaiBinaryId binary_id = reai_db_get_latest_analysis_for_file (reai_db(), opened_file);
    if (!binary_id) {
        DISPLAY_ERROR (
            "No analysis exists for the opened binary file. Please ensure the binary file is "
            "analyzed."
        );
        return RZ_CMD_STATUS_ERROR;
    }

    /* get analysis status from db after an update and check for completion */
    ReaiAnalysisStatus analysis_status = reai_db_get_analysis_status (reai_db(), binary_id);
    if (!analysis_status) {
        DISPLAY_ERROR ("Failed to retrieve the analysis status of the binary from the database.");
        return RZ_CMD_STATUS_ERROR;
    }

    if (analysis_status != REAI_ANALYSIS_STATUS_COMPLETE) {
        DISPLAY_ERROR (
            "Analysis not yet complete. Current status = \"%s\"\n",
            reai_analysis_status_to_cstr (analysis_status)
        );
        return RZ_CMD_STATUS_OK; // It's ok, check again after sometime
    }

    /* make request to get function infos */
    ReaiFnInfoVec* fn_infos = reai_get_basic_function_info (reai(), reai_response(), binary_id);
    if (!fn_infos) {
        DISPLAY_ERROR ("Failed to get function info from RevEng.AI servers.");
        return RZ_CMD_STATUS_ERROR;
    }

    // prepare table and print info
    RzTable* table = rz_table_new();
    if (!table) {
        DISPLAY_ERROR ("Failed to create the table.");
        return RZ_CMD_STATUS_ERROR;
    }

    rz_table_set_columnsf (table, "nsxx", "function_id", "name", "vaddr", "size");
    REAI_VEC_FOREACH (fn_infos, fn, {
        rz_table_add_rowf (table, "nsxx", fn->id, fn->name, fn->vaddr, fn->size);
    });

    CString table_str = rz_table_tofancystring (table);
    if (!table_str) {
        DISPLAY_ERROR ("Failed to convert table to string.");
        rz_table_free (table);
        return RZ_CMD_STATUS_ERROR;
    }

    rz_cons_println (table_str);

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
    UNUSED (argc);
    LOG_TRACE ("[CMD] rename function");

    Uint64  fn_addr  = rz_num_get (core->num, argv[1]);
    CString new_name = argv[2];

    if (!core->analysis) {
        DISPLAY_ERROR (
            "Seems like Rizin analysis is not performed yet. Cannot get function at given address. "
            "Cannot rename function at given address."
        );
        return RZ_CMD_STATUS_ERROR;
    }

    RzAnalysisFunction* fn = rz_analysis_get_function_at (core->analysis, fn_addr);
    if (!fn) {
        DISPLAY_ERROR ("Function with given name not found.");
        return RZ_CMD_STATUS_ERROR;
    }

    ReaiFunctionId fn_id = reai_plugin_get_function_id_for_rizin_function (core, fn);
    if (!fn_id) {
        DISPLAY_ERROR ("Failed to get function id of function with given name.");
        return RZ_CMD_STATUS_ERROR;
    }

    /* perform rename operation */
    if (reai_rename_function (reai(), reai_response(), fn_id, new_name)) {
        rz_analysis_function_rename (fn, new_name);
    } else {
        DISPLAY_ERROR ("Failed to rename the function. Please check the function ID and new name.");
        return RZ_CMD_STATUS_ERROR;
    }

    return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_show_revengai_art_handler (RzCore* core, int argc, const char** argv) {
    UNUSED (core && argc && argv);

    rz_cons_println (
        "\n"
        "                             \n"
        "                             \n"
        "                             \n"
        "                             \n"
        "                             \n"
        "                             \n"
        "                             \n"
        "                             \n"
        ":::::::::::        :::::::::::                                                            "
        "      \n"
        "::    ::::::      ::::    ::::             %%%%%%%%%%%%%                                  "
        "      %%%%%%%%%%%%%%%                            \n"
        "::    :::::::    :::::    ::::            %%%%%%%%%%%%%%%                                 "
        "      %%%%%%%%%%%%%%%                                %%%%%@   \n"
        "::::::::::::::::::::::::::::::           %%%%%%%    %%%%%                                 "
        "      %%%%%                                          %%%%%%  \n"
        ":::::::::   ::::   :::::::::::           %%%%%%     %%%%%     @%%%%%%%%%%    %%%%%@    "
        "%%%%%    %%%%%             %%%%% %%%%%%%%      @%%%%%%%%%%%    \n"
        " :::::::    ::::    :::::::::            %%%%%%     %%%%%    %%%%%%%%%%%%%%  %%%%%%    "
        "%%%%%%   %%%%%%%%%%%%%%    %%%%%%%%%%%%%%%    %%%%%%%%%%%%%%  \n"
        "     ::::::::::::::::::::                %%%%%%%%%%%%%%%   %%%%%     @%%%%%  %%%%%%    "
        "%%%%%    %%%%%%%%%%%%%%    %%%%%%    %%%%%%  %%%%%@    %%%%%@\n"
        "       ::::::::::::::::                    %%%%%%%%%%%%%  @%%%%%%%%%%%%%%%%   %%%%%@  "
        "%%%%%     %%%%%%%%%%%%%%    %%%%%     %%%%%%  %%%%%%    %%%%%%               @@@@    "
        "@@@@@@@@\n"
        "     ::::   ::::    :::::                  @%%%%%@ %%%%%  %%%%%%%%%%%%%%%%%   %%%%%% "
        "%%%%%%     %%%%%             %%%%%     %%%%%%   %%%%%%%%%%%%%@               @@@@@@     "
        "@@@  \n"
        " ::::::::   ::::    :::::::::              %%%%%%@ %%%%%   %%%%%               "
        "%%%%%%%%%%%      %%%%%             %%%%%     %%%%%%     %%%%%%%%%%                @@@@ "
        "@@@    @@@ \n"
        "::::::::::::::::::::::::::::::          %%%%%%%%   %%%%%   %%%%%%@   %%%%%      %%%%%%%%% "
        "      %%%%%%%%%%%%%%%   %%%%%     %%%%%%   %%%%                        @@@@@@@@    @@@\n"
        "::    ::::::::::::::::    ::::          %%%%%%%    %%%%%    @%%%%%%%%%%%%%       %%%%%%%% "
        "      %%%%%%%%%%%%%%%   %%%%%     %%%%%%   %%%%%%%%%%%%%%%    @@@@    @@@@  @@@@ "
        "@@@@@@@@\n"
        "::    :::::::    :::::    ::::          %%%%%      %%%%%       %%%%%%%%%         %%%%%%%  "
        "      %%%%%%%%%%%%%%    %%%%%     %%%%%@   %%%%%%%%%%%%%%%%    @@@    @@@   @@@@ "
        "@@@@@@@@\n"
        "::::::::::::      ::::::::::::                                                            "
        "                                          %%%%        %%%%%                             \n"
        ":::::::::::        :::::::::::                                                            "
        "                                          %%%%%%%%%%%%%%%%%                             \n"
        "                                                                                          "
        "                                           %%%%%%%%%%%%%%                               \n"
        "\n"
    );
    return RZ_CMD_STATUS_OK;
}
