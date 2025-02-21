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

    CString host = "https://api.reveng.ai"; // Hardcode API endpoint
    // NOTE(brightprogrammer): Developers should just change this in the config file.
    CString api_key = argv[1];

    /* attempt saving config */
    if (reai_plugin_save_config (host, api_key)) {
        /* try to reinit config after creating config */
        if (!reai_plugin_init (core)) {
            DISPLAY_ERROR (
                "Failed to init plugin after creating a new config.\n"
                "Please try restarting radare."
            );
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

    /* Make sure analysis functions exist in rizin as well, so we can get functions by their address values. */
    if (!reai_plugin_get_rizin_analysis_function_count (core)) {
        if (rz_cons_yesno (
                'y',
                "Rizin analysis not performed yet. Should I create one for you? [Y/n]"
            )) {
            rz_core_perform_auto_analysis (core, RZ_CORE_ANALYSIS_EXPERIMENTAL);
        }
    }

    Bool is_private = rz_cons_yesno ('y', "Create private analysis? [Y/n]");

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
    REAI_LOG_TRACE ("[CMD] apply existing analysis");

    /* Make sure analysis functions exist in rizin as well, so we can get functions by their address values. */
    if (!reai_plugin_get_rizin_analysis_function_count (core)) {
        if (rz_cons_yesno (
                'y',
                "Rizin analysis not performed yet. Should I create one for you? [Y/n]"
            )) {
            rz_core_perform_auto_analysis (core, RZ_CORE_ANALYSIS_EXPERIMENTAL);
        }
    }

    ReaiBinaryId binary_id            = rz_num_get (core->num, argv[1]); // binary id
    Bool         has_custom_base_addr = argc >= 3; // third arg is optional custom base addr
    Uint64       custom_base_addr     = has_custom_base_addr ? rz_num_get (core->num, argv[2]) : 0;

    if (reai_plugin_apply_existing_analysis (
            core,
            binary_id,
            has_custom_base_addr,
            custom_base_addr
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

    /* Make sure analysis functions exist in rizin as well, so we can get functions by their address values. */
    if (!reai_plugin_get_rizin_analysis_function_count (core)) {
        if (rz_cons_yesno (
                'y',
                "Rizin analysis not performed yet. Should I create one for you? [Y/n]"
            )) {
            rz_core_perform_auto_analysis (core, RZ_CORE_ANALYSIS_EXPERIMENTAL);
        }
    }

    // NOTE: this is static here. I don't think it's a good command line option to have
    // Since user won't know about this when issuing the auto-analysis command.
    // Just set it to a large enough value to get good suggestions
    const Size max_results_per_function = 10;

    Uint32 min_confidence = rz_num_get (core->num, argv[1]);
    min_confidence        = min_confidence > 100 ? 100 : min_confidence;

    Bool debug_mode = rz_cons_yesno ('y', "Restrict suggestions to debug symbols? [Y/n]");

    if (reai_plugin_auto_analyze_opened_binary_file (
            core,
            max_results_per_function,
            min_confidence / 100.f,
            debug_mode
        )) {
        DISPLAY_INFO ("Auto-analysis completed successfully.");
        return RZ_CMD_STATUS_OK;
    } else {
        DISPLAY_ERROR ("Failed to perform RevEng.AI auto-analysis");
        return RZ_CMD_STATUS_ERROR;
    }
}

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

    /* get binary id of opened file */
    ReaiBinaryId binary_id = reai_binary_id();
    if (!binary_id) {
        DISPLAY_ERROR (
            "Please apply existing RevEngAI analysis (using REap command) or create a new one.\n"
            "Cannot get function info from RevEng.AI without an existing analysis."
        );
        return RZ_CMD_STATUS_ERROR;
    }

    /* an analysis must already exist in order to make function-rename work */
    ReaiAnalysisStatus analysis_status =
        reai_get_analysis_status (reai(), reai_response(), reai_binary_id());
    switch (analysis_status) {
        case REAI_ANALYSIS_STATUS_ERROR : {
            DISPLAY_ERROR (
                "The applied/created RevEngAI analysis has errored out.\n"
                "I need a complete analysis to get function info. Please restart analysis."
            );
            return RZ_CMD_STATUS_ERROR;
        }
        case REAI_ANALYSIS_STATUS_QUEUED : {
            DISPLAY_ERROR (
                "The applied/created RevEngAI analysis is currently in queue.\n"
                "Please wait for the analysis to be analyzed."
            );
            return RZ_CMD_STATUS_OK;
        }
        case REAI_ANALYSIS_STATUS_PROCESSING : {
            DISPLAY_ERROR (
                "The applied/created RevEngAI analysis is currently being processed (analyzed).\n"
                "Please wait for the analysis to complete."
            );
            return RZ_CMD_STATUS_OK;
        }
        case REAI_ANALYSIS_STATUS_COMPLETE : {
            REAI_LOG_TRACE ("Analysis for binary ID %llu is COMPLETE.", reai_binary_id());
            break;
        }
        default : {
            DISPLAY_ERROR (
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
            return RZ_CMD_STATUS_ERROR;
        }
    }

    /* Make sure analysis functions exist in rizin as well, so we can get functions by their address values. */
    if (!reai_plugin_get_rizin_analysis_function_count (core)) {
        if (rz_cons_yesno (
                'y',
                "Rizin analysis not performed yet. Should I create one for you? [Y/n]"
            )) {
            rz_core_perform_auto_analysis (core, RZ_CORE_ANALYSIS_EXPERIMENTAL);
        }
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
        // truncate string if exceeds a certain limit
        char   trunc[4]  = {0};
        size_t trunc_len = 48;
        char*  n         = (char*)fn->name;
        if (strlen (fn->name) > trunc_len) {
            memcpy (trunc, n + trunc_len - 4, 4);
            memcpy (n + trunc_len - 4, "...\0", 4);
        }
        rz_table_add_rowf (table, "nsxx", fn->id, fn->name, fn->vaddr, fn->size);
        memcpy (n + trunc_len - 4, trunc, 4);
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

    /* Make sure analysis functions exist in rizin as well, so we can get functions by their address values. */
    if (!reai_plugin_get_rizin_analysis_function_count (core)) {
        if (rz_cons_yesno (
                'y',
                "Rizin analysis not performed yet. Should I create one for you? [Y/n]"
            )) {
            rz_core_perform_auto_analysis (core, RZ_CORE_ANALYSIS_EXPERIMENTAL);
        }
    }

    /* get binary id of opened file */
    ReaiBinaryId binary_id = reai_binary_id();
    if (!binary_id) {
        DISPLAY_ERROR (
            "Please apply existing RevEngAI analysis (using REap command) or create a new one.\n"
            "Cannot get function info from RevEng.AI without an existing analysis."
        );
        return RZ_CMD_STATUS_ERROR;
    }

    /* an analysis must already exist in order to make function-rename work */
    ReaiAnalysisStatus analysis_status =
        reai_get_analysis_status (reai(), reai_response(), reai_binary_id());
    switch (analysis_status) {
        case REAI_ANALYSIS_STATUS_ERROR : {
            DISPLAY_ERROR (
                "The applied/created RevEngAI analysis has errored out.\n"
                "Please restart analysis."
            );
            return RZ_CMD_STATUS_ERROR;
        }
        case REAI_ANALYSIS_STATUS_QUEUED : {
            DISPLAY_ERROR (
                "The applied/created RevEngAI analysis is currently in queue.\n"
                "Please wait for the analysis to be analyzed."
            );
            return RZ_CMD_STATUS_OK;
        }
        case REAI_ANALYSIS_STATUS_PROCESSING : {
            DISPLAY_ERROR (
                "The applied/created RevEngAI analysis is currently being processed (analyzed).\n"
                "Please wait for the analysis to complete."
            );
            return RZ_CMD_STATUS_OK;
        }
        case REAI_ANALYSIS_STATUS_COMPLETE : {
            REAI_LOG_TRACE ("Analysis for binary ID %llu is COMPLETE.", reai_binary_id());
            break;
        }
        default : {
            DISPLAY_ERROR (
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
            return RZ_CMD_STATUS_ERROR;
        }
    }

    CString old_name = argv[1];
    CString new_name = argv[2];

    RzAnalysisFunction* fn = rz_analysis_get_function_byname (core->analysis, old_name);
    if (!fn) {
        DISPLAY_ERROR ("Function with given name not found.");
        return RZ_CMD_STATUS_ERROR;
    }

    ReaiFunctionId fn_id = reai_plugin_get_function_id_for_rizin_function (core, fn);
    if (!fn_id) {
        DISPLAY_ERROR (
            "A function ID for given function does not exist in RevEngAI analysis.\n"
            "I won't be able to rename this function."
        );
        return RZ_CMD_STATUS_ERROR;
    }

    /* perform rename operation */
    if (reai_rename_function (reai(), reai_response(), fn_id, new_name)) {
        if (rz_analysis_function_rename (fn, new_name)) {
            DISPLAY_INFO ("Rename success.");
        } else {
            DISPLAY_ERROR ("Rename failed in rizin.");
            return RZ_CMD_STATUS_ERROR;
        }
    } else {
        DISPLAY_ERROR ("Failed to rename the function in RevEngAI.");
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
    if (argc < 4) {
        REAI_LOG_ERROR (ERR_INVALID_ARGUMENTS);
        return RZ_CMD_STATUS_WRONG_ARGS;
    }

    /* Make sure analysis functions exist in rizin as well, so we can get functions by their address values. */
    if (!reai_plugin_get_rizin_analysis_function_count (core)) {
        if (rz_cons_yesno (
                'y',
                "Rizin analysis not performed yet. Should I create one for you? [Y/n]"
            )) {
            rz_core_perform_auto_analysis (core, RZ_CORE_ANALYSIS_EXPERIMENTAL);
        }
    }

    // Parse command line arguments
    CString function_name     = argv[1];
    Uint32  min_confidence    = (Uint32)rz_num_math (core->num, argv[2]);
    Uint32  max_results_count = (Uint32)rz_num_math (core->num, argv[3]);

    // clamp value between 0 and 100
    min_confidence = min_confidence < 100 ? min_confidence : 100;

    Bool debug_mode = rz_cons_yesno ('y', "Enable debug symbol suggestions? [Y/n]");

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

    /* Make sure analysis functions exist in rizin as well, so we can get functions by their address values. */
    if (!reai_plugin_get_rizin_analysis_function_count (core)) {
        if (rz_cons_yesno (
                'y',
                "Rizin analysis not performed yet. Should I create one for you? [Y/n]"
            )) {
            rz_core_perform_auto_analysis (core, RZ_CORE_ANALYSIS_EXPERIMENTAL);
        }
    }

    /* get binary id of opened file */
    ReaiBinaryId binary_id = reai_binary_id();
    if (!binary_id) {
        DISPLAY_ERROR (
            "Please apply existing RevEngAI analysis (using REap command) or create a new one.\n"
            "Cannot get function info from RevEng.AI without an existing analysis."
        );
        return RZ_CMD_STATUS_ERROR;
    }

    /* an analysis must already exist in order to make function decompile work */
    ReaiAnalysisStatus analysis_status =
        reai_get_analysis_status (reai(), reai_response(), reai_binary_id());
    switch (analysis_status) {
        case REAI_ANALYSIS_STATUS_ERROR : {
            DISPLAY_ERROR (
                "The applied/created RevEngAI analysis has errored out.\n"
                "I need a complete analysis to function decompilation. Please restart analysis."
            );
            return RZ_CMD_STATUS_ERROR;
        }
        case REAI_ANALYSIS_STATUS_QUEUED : {
            DISPLAY_ERROR (
                "The applied/created RevEngAI analysis is currently in queue.\n"
                "Please wait for the analysis to be analyzed."
            );
            return RZ_CMD_STATUS_OK;
        }
        case REAI_ANALYSIS_STATUS_PROCESSING : {
            DISPLAY_ERROR (
                "The applied/created RevEngAI analysis is currently being processed (analyzed).\n"
                "Please wait for the analysis to complete."
            );
            return RZ_CMD_STATUS_OK;
        }
        case REAI_ANALYSIS_STATUS_COMPLETE : {
            REAI_LOG_TRACE ("Analysis for binary ID %llu is COMPLETE.", reai_binary_id());
            break;
        }
        default : {
            DISPLAY_ERROR (
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
            return RZ_CMD_STATUS_ERROR;
        }
    }

    RzAnalysisFunction* rzfn = rz_analysis_get_function_byname (core->analysis, fn_name);

    if (!rzfn) {
        DISPLAY_ERROR (
            "A function with given name does not exist in Radare.\n"
            "Cannot decompile :-("
        );
        return RZ_CMD_STATUS_ERROR;
    }

    /* NOTE(brightprogrammer): Error count is a hack used to mitigate the case
     * where the AI decompilation process is already errored out and user wants
     * to restart the process. */
    int error_count = 0;

    while (true) {
        DISPLAY_INFO ("Checking decompilation status...");

        ReaiAiDecompilationStatus status =
            reai_plugin_check_decompiler_status_running_at (core, rzfn->addr);
        REAI_LOG_DEBUG (
            "Decompilation status for function \"%s\" is \"%s\".",
            rzfn->name,
            reai_ai_decompilation_status_to_cstr (status)
        );


        switch (status) {
            case REAI_AI_DECOMPILATION_STATUS_ERROR :
                if (!error_count) {
                    DISPLAY_INFO (
                        "Looks like the decompilation process failed last time\n"
                        "I'll restart the decompilation process again..."
                    );
                    reai_plugin_decompile_at (core, rzfn->addr);
                } else if (error_count > 1) {
                    DISPLAY_ERROR (
                        "Failed to decompile \"%s\"\n"
                        "Is this function from RevEngAI's analysis?\n"
                        "What's the output of REfl?",
                        fn_name
                    );
                    return RZ_CMD_STATUS_ERROR;
                }
                error_count++;
                break;
            case REAI_AI_DECOMPILATION_STATUS_UNINITIALIZED :
                DISPLAY_INFO ("No decompilation exists for this function...");
                reai_plugin_decompile_at (core, rzfn->addr);
                break;
            case REAI_AI_DECOMPILATION_STATUS_SUCCESS : {
                DISPLAY_INFO ("AI decompilation complete ;-)\n");
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

        DISPLAY_INFO ("Going to sleep for two seconds...");
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
