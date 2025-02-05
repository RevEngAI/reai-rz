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


#define ASK_QUESTION(res, default, msg)                                                            \
    do {                                                                                           \
        Char input = 0;                                                                            \
        rz_cons_printf ("%s [%c/%c] : ", msg, (default ? 'Y' : 'y'), (!default ? 'N' : 'n'));      \
        rz_cons_flush();                                                                           \
        while (input != 'n' && input != 'N' && input != 'Y' && input != 'y') {                     \
            input = rz_cons_readchar();                                                            \
        }                                                                                          \
        res = (input == 'y' || input == 'Y');                                                      \
        rz_cons_newline();                                                                         \
    } while (0)

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
    REAI_LOG_TRACE ("[CMD] config initialize");

    CString host    = argv[1];
    CString api_key = argv[2];

    /* attempt saving config */
    if (reai_plugin_save_config (host, api_key)) {
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
 * "REm"
 * */
RZ_IPI RzCmdStatus rz_list_available_ai_models_handler (RzCore* core, int argc, const char** argv) {
    UNUSED (core && argc && argv);
    REAI_LOG_TRACE ("[CMD] list available ai models");

    if (reai_ai_models()) {
        REAI_VEC_FOREACH (reai_ai_models(), model, { rz_cons_println (*model); });
        return RZ_CMD_STATUS_OK;
    } else {
        DISPLAY_ERROR ("Seems like background worker failed to get available AI models.");
        return RZ_CMD_STATUS_ERROR;
    }
}

/**
 * "REh"
 *
 * @b Perform an auth-check api call to check connection.
 * */
RZ_IPI RzCmdStatus rz_health_check_handler (RzCore* core, int argc, const char** argv) {
    UNUSED (core && argc && argv);
    REAI_LOG_TRACE ("[CMD] health check");

    if (!reai_auth_check (reai(), reai_response(), reai_config()->host, reai_config()->apikey)) {
        DISPLAY_ERROR ("Authentication failed.");
        return RZ_CMD_STATUS_ERROR;
    }

    rz_cons_println ("OK");
    return RZ_CMD_STATUS_OK;
}

/**
 * "REa"
 *
 * NOTE: The default way to get ai model would be to use "REm" command.
 *       Get list of all available AI models and then use one to create a new analysis.
 * */
RZ_IPI RzCmdStatus rz_create_analysis_handler (RzCore* core, int argc, const char** argv) {
    UNUSED (argc && argv);
    REAI_LOG_TRACE ("[CMD] create analysis");

    Bool is_private;
    ASK_QUESTION (is_private, true, "Create private analysis?");

    CString prog_name    = argv[1];
    CString cmdline_args = argv[2];
    CString ai_model     = argv[3];

    if (reai_plugin_create_analysis_for_opened_binary_file (
            core,
            prog_name,
            cmdline_args,
            ai_model,
            is_private
        )) {
        DISPLAY_INFO ("Analysis created sucessfully");
        return RZ_CMD_STATUS_OK;
    }

    DISPLAY_ERROR ("Failed to create analysis");

    return RZ_CMD_STATUS_ERROR;
}

/**
 * "REap"
 * */
RZ_IPI RzCmdStatus rz_apply_existing_analysis_handler (RzCore* core, int argc, const char** argv) {
    UNUSED (argc && argv);
    REAI_LOG_TRACE ("[CMD] apply existing analysis");

    Bool rename_unknown_only;
    ASK_QUESTION (rename_unknown_only, true, "Apply analysis only to unknown functions?");

    if (reai_plugin_apply_existing_analysis (
            core,
            rz_num_get (core->num, argv[1]), // binary id
            !rename_unknown_only             // apply analysis to all?
        )) {
        DISPLAY_INFO ("Existing analysis applied sucessfully");
        return RZ_CMD_STATUS_OK;
    }

    DISPLAY_INFO ("Failed to apply existing analysis");
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
    UNUSED (output_mode && argc);
    REAI_LOG_TRACE ("[CMD] ANN Auto Analyze Binary");

    // NOTE: this is static here. I don't think it's a good command line option to have
    // Since user won't know about this when issuing the auto-analysis command.
    // Just set it to a large enough value to get good suggestions
    const Size max_results_per_function = 10;

    Uint32 min_confidence = rz_num_get (core->num, argv[1]);
    min_confidence        = min_confidence > 100 ? 100 : min_confidence;

    Bool debug_mode, rename_unknown_only;
    ASK_QUESTION (debug_mode, true, "Enable debug symbol suggestions?");
    ASK_QUESTION (rename_unknown_only, true, "Rename unknown functions only?");

    if (reai_plugin_auto_analyze_opened_binary_file (
            core,
            max_results_per_function,
            min_confidence / 100.f,
            debug_mode,
            !rename_unknown_only // apply_to_all = !rename_unknown
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

/* RZ_IPI RzCmdStatus rz_upload_bin_handler (RzCore* core, int argc, const char** argv) { */
/*     UNUSED (argc && argv); */
/*     REAI_LOG_TRACE ("[CMD] upload binary"); */
/**/
/*     if (reai_plugin_upload_opened_binary_file (core)) { */
/*         DISPLAY_ERROR ("File upload successful."); */
/*         return RZ_CMD_STATUS_OK; */
/*     } else { */
/*         DISPLAY_ERROR ("File upload failed."); */
/*         return RZ_CMD_STATUS_ERROR; */
/*     } */
/* } */

/**
 * "REfl"
 *
 * @b Get information about all functions detected by the AI model from
 *    RevEng.AI servers.
 *
 * NOTE: This works just for currently opened binary file. If binary
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
    REAI_LOG_TRACE ("[CMD] get basic function info");

    /* get file path of opened binary file */
    CString opened_file = reai_plugin_get_opened_binary_file_path (core);
    if (!opened_file) {
        DISPLAY_ERROR ("No binary file opened.");
        return RZ_CMD_STATUS_ERROR;
    }

    /* get binary id of opened file */
    ReaiBinaryId binary_id = reai_binary_id();
    if (!binary_id) {
        DISPLAY_ERROR (
            "Please apply existing analysis or create a new one. Cannot get function info from "
            "RevEng.AI without an existing analysis."
        );
        return RZ_CMD_STATUS_ERROR;
    }

    /* get analysis status from db after an update and check for completion */
    ReaiAnalysisStatus analysis_status = reai_plugin_get_analysis_status_for_binary_id (binary_id);
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
    REAI_LOG_TRACE ("[CMD] rename function");

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

/**
 * "REfs"
 *
 * @b Similar function name search 
 * */
RZ_IPI RzCmdStatus
    rz_function_similarity_search_handler (RzCore* core, int argc, const char** argv) {
    UNUSED (argc);

    // NOTE: hardcoded because it does not look good in command arguments
    // just to increase simplicity of command
    Uint32 max_results_count = 20;

    // Parse command line arguments
    CString function_name  = argv[1];
    Float32 min_confidence = rz_num_math (core->num, argv[2]);

    Bool debug_mode;
    ASK_QUESTION (debug_mode, true, "Enable debug symbol suggestions?");

    if (!reai_plugin_search_and_show_similar_functions (
            core,
            function_name,
            max_results_count,
            min_confidence,
            debug_mode
        )) {
        DISPLAY_ERROR ("Failed to get similar functions search result.");
        return RZ_CMD_STATUS_ERROR;
    }

    return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_ai_decompile_handler (RzCore* core, int argc, const char** argv) {
    UNUSED (argc);
    const char* fn_name = argv[1];
    if (!fn_name) {
        return RZ_CMD_STATUS_INVALID;
    }

    RzAnalysisFunction* rzfn = rz_analysis_get_function_byname (core->analysis, fn_name);

    /* NOTE(brightprogrammer): Error count is a hack used to mitigate the case
     * where the AI decompilation process is already errored out and user wants
     * to restart the process. */
    int error_count = 0;

    while (true) {
        ReaiAiDecompilationStatus status =
            reai_plugin_check_decompiler_status_running_at (core, rzfn->addr);

        if (error_count > 1) {
            DISPLAY_ERROR ("failed to decompile function \"%s\"", fn_name);
            return RZ_CMD_STATUS_ERROR;
        }

        switch (status) {
            case REAI_AI_DECOMPILATION_STATUS_ERROR :
                error_count++;
            case REAI_AI_DECOMPILATION_STATUS_UNINITIALIZED :
                reai_plugin_decompile_at (core, rzfn->addr);
                break;
            case REAI_AI_DECOMPILATION_STATUS_SUCCESS : {
                CString code = reai_plugin_get_decompiled_code_at (core, rzfn->addr);
                if (code) {
                    rz_cons_println (code);
                    FREE (code);
                }
                return RZ_CMD_STATUS_OK;
            }
            default :
                break;
        }

        rz_sys_sleep (2);
    }
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
