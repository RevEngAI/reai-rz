/**
 * @file : CmdHandlers.c
 * @date : 13th June 2024
 * @author : Siddharth Mishra (admin@brightprogrammer.in)
 * @copyright: Copyright (c) 2024 RevEngAI. All Rights Reserved.
 *
 * @b This file defines all the handlers that are declated inside `CmdGen/Output/CmdDescs.h`
 * After adding a new command entry, implement corresponding handlers here and then compile.
 * */

#include <Reai/Api/Api.h>
#include <Reai/Common.h>
#include <Reai/Config.h>
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
#include <rz_util/rz_sys.h>
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
 * "REac"
 * */
RZ_IPI RzCmdStatus rz_create_analysis_private_handler (RzCore* core, int argc, const char** argv) {
    UNUSED (argc && argv);
    REAI_LOG_TRACE ("[CMD] create analysis");

    /* Make sure analysis functions exist in rizin as well, so we can get functions by their address values. */
    if (!reai_plugin_get_rizin_analysis_function_count (core)) {
        rz_core_perform_auto_analysis (core, RZ_CORE_ANALYSIS_EXPERIMENTAL);
    }

    CString ai_model  = argv[1];
    CString prog_name = argv[2];

    CString cmdline_args = NULL;
    if (argc == 4) {
        cmdline_args = argv[3];
    }

    if (reai_plugin_create_analysis_for_opened_binary_file (
            core,
            prog_name,
            cmdline_args,
            ai_model,
            true // private analysis
        )) {
        DISPLAY_INFO ("Analysis created sucessfully");
        return RZ_CMD_STATUS_OK;
    }

    DISPLAY_ERROR ("Failed to create analysis");

    return RZ_CMD_STATUS_ERROR;
}

/**
 * "REacp"
 * */
RZ_IPI RzCmdStatus rz_create_analysis_public_handler (RzCore* core, int argc, const char** argv) {
    UNUSED (argc && argv);
    REAI_LOG_TRACE ("[CMD] create analysis");

    /* Make sure analysis functions exist in rizin as well, so we can get functions by their address values. */
    if (!reai_plugin_get_rizin_analysis_function_count (core)) {
        rz_core_perform_auto_analysis (core, RZ_CORE_ANALYSIS_EXPERIMENTAL);
    }

    CString ai_model  = argv[1];
    CString prog_name = argv[2];

    CString cmdline_args = NULL;
    if (argc == 4) {
        cmdline_args = argv[3];
    }

    if (reai_plugin_create_analysis_for_opened_binary_file (
            core,
            prog_name,
            cmdline_args,
            ai_model,
            false // public analysis
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
        rz_core_perform_auto_analysis (core, RZ_CORE_ANALYSIS_EXPERIMENTAL);
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
 * */
RZ_IPI RzCmdStatus rz_ann_auto_analyze_handler (RzCore* core, int argc, const char** argv) {
    UNUSED (argc);
    REAI_LOG_TRACE ("[CMD] ANN Auto Analyze Binary");

    /* Make sure analysis functions exist in rizin as well, so we can get functions by their address values. */
    if (!reai_plugin_get_rizin_analysis_function_count (core)) {
        rz_core_perform_auto_analysis (core, RZ_CORE_ANALYSIS_EXPERIMENTAL);
    }

    // NOTE: this is static here. I don't think it's a good command line option to have
    // Since user won't know about this when issuing the auto-analysis command.
    // Just set it to a large enough value to get good suggestions
    const Size max_results_per_function = 10;

    Uint32 min_similarity = rz_num_get (core->num, argv[1]);
    min_similarity        = min_similarity > 100 ? 100 : min_similarity;


    if (reai_plugin_auto_analyze_opened_binary_file (
            core,
            max_results_per_function,
            min_similarity / 100.f,
            false // no restrictions on debug or non-debug for symbol suggestions
        )) {
        DISPLAY_INFO (
            "Auto-analysis completed successfully. Renamed names might contain debug and non-debug "
            "symbols."
        );
        return RZ_CMD_STATUS_OK;
    } else {
        DISPLAY_ERROR ("Failed to perform RevEng.AI auto-analysis");
        return RZ_CMD_STATUS_ERROR;
    }
}

/**
 * REaud
 * */
RZ_IPI RzCmdStatus
    rz_ann_auto_analyze_restrict_debug_handler (RzCore* core, int argc, const char** argv) {
    UNUSED (argc);
    REAI_LOG_TRACE ("[CMD] ANN Auto Analyze Binary");

    /* Make sure analysis functions exist in rizin as well, so we can get functions by their address values. */
    if (!reai_plugin_get_rizin_analysis_function_count (core)) {
        rz_core_perform_auto_analysis (core, RZ_CORE_ANALYSIS_EXPERIMENTAL);
    }

    // NOTE: this is static here. I don't think it's a good command line option to have
    // Since user won't know about this when issuing the auto-analysis command.
    // Just set it to a large enough value to get good suggestions
    const Size max_results_per_function = 10;

    Uint32 min_similarity = rz_num_get (core->num, argv[1]);
    min_similarity        = min_similarity > 100 ? 100 : min_similarity;


    if (reai_plugin_auto_analyze_opened_binary_file (
            core,
            max_results_per_function,
            min_similarity / 100.f,
            true // restrict symbol suggestions to debug mode only.
        )) {
        DISPLAY_INFO (
            "Auto-analysis completed successfully. Only debug symbols were used for renaming."
        );
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
RZ_IPI RzCmdStatus rz_get_basic_function_info_handler (RzCore* core, int argc, const char** argv) {
    UNUSED (argc && argv);
    REAI_LOG_TRACE ("[CMD] get basic function info");

    /* get binary id of opened file */
    ReaiBinaryId binary_id = reai_binary_id();
    if (!binary_id) {
        DISPLAY_ERROR (
            "Please apply existing RevEngAI analysis (using REae command) or create a new one.\n"
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
        rz_core_perform_auto_analysis (core, RZ_CORE_ANALYSIS_EXPERIMENTAL);
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
        rz_core_perform_auto_analysis (core, RZ_CORE_ANALYSIS_EXPERIMENTAL);
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
        rz_core_perform_auto_analysis (core, RZ_CORE_ANALYSIS_EXPERIMENTAL);
    }

    // Parse command line arguments
    CString function_name      = argv[1];
    Uint32  min_similarity     = (Uint32)rz_num_math (core->num, argv[2]);
    Uint32  max_results_count  = (Uint32)rz_num_math (core->num, argv[3]);
    CString collection_ids_csv = argv[4];
    CString binary_ids_csv     = argv[5];

    // clamp value between 0 and 100
    min_similarity = min_similarity < 100 ? min_similarity : 100;

    if (!reai_plugin_search_and_show_similar_functions (
            core,
            function_name,
            max_results_count,
            min_similarity,
            false, // Don't restrict suggestions to debug symbols only.
            collection_ids_csv,
            binary_ids_csv
        )) {
        DISPLAY_ERROR ("Failed to get similar functions search result.");
        return RZ_CMD_STATUS_ERROR;
    }

    return RZ_CMD_STATUS_OK;
}

/**
 * "REfsd"
 *
 * @b Similar function name search with debug symbol suggestions only.
 * */
RZ_IPI RzCmdStatus
    rz_function_similarity_search_debug_handler (RzCore* core, int argc, const char** argv) {
    if (argc < 4) {
        REAI_LOG_ERROR (ERR_INVALID_ARGUMENTS);
        return RZ_CMD_STATUS_WRONG_ARGS;
    }

    /* Make sure analysis functions exist in rizin as well, so we can get functions by their address values. */
    // TODO: make this a config setting
    // This can be set to y/n in config. If set to y then we'll try to perform rizin analysis automatically,
    // otherwise just inform the user about the issue and report a failure in command execution
    if (!reai_plugin_get_rizin_analysis_function_count (core)) {
        rz_core_perform_auto_analysis (core, RZ_CORE_ANALYSIS_EXPERIMENTAL);
    }

    // Parse command line arguments
    CString function_name      = argv[1];
    Uint32  min_similarity     = (Uint32)rz_num_math (core->num, argv[2]);
    Uint32  max_results_count  = (Uint32)rz_num_math (core->num, argv[3]);
    CString collection_ids_csv = argv[4];
    CString binary_ids_csv     = argv[5];

    // TODO: keep an LRU of binary and collection ids
    // No need to allow the user to reset the recently used collection and binary ids, just provide an
    // option to show it through a command.

    // clamp value between 0 and 100
    min_similarity = min_similarity < 100 ? min_similarity : 100;

    if (!reai_plugin_search_and_show_similar_functions (
            core,
            function_name,
            max_results_count,
            min_similarity,
            true, // Restrict suggestions to debug symbols only.
            collection_ids_csv,
            binary_ids_csv
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
        rz_core_perform_auto_analysis (core, RZ_CORE_ANALYSIS_EXPERIMENTAL);
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

                // Returns code prepended with summary
                char* code = (char*)
                    reai_plugin_get_decompiled_code_at (core, rzfn->addr, true /* summarize */);

                // Get function mappings
                ReaiAiDecompFnMapVec* fn_map =
                    reai_response()->poll_ai_decompilation.data.function_mapping;

                // Apply function mappings by replacing all <DISASM_FUNCTION_NN> with it's actual function name
                if (fn_map && code) {
                    // Search and replace all tagged function names
                    char fn_tagged_name[64] = {0};
                    for (Size i = 0; i < fn_map->count; i++) {
                        ReaiAiDecompFnMap* fn = fn_map->items + i;

                        // Check if function actually does exist
                        RzAnalysisFunction* afn =
                            rz_analysis_get_function_byname (core->analysis, fn->name);
                        if (afn) {
                            // Create name for tagged function name
                            // I knowingly didn't store these names, because I know these can be generated like this on the fly
                            snprintf (
                                fn_tagged_name,
                                sizeof (fn_tagged_name),
                                "<DISASM_FUNCTION_%zu>",
                                i
                            );

                            // replace tagged names in form of <DISASM_FUNCTION_NN> with actual name
                            char* tmp = rz_str_replace (code, fn_tagged_name, fn->name, true);
                            if (tmp) {
                                code = tmp;
                            }
                        } else {
                            REAI_LOG_ERROR (
                                "Function with %s name does not exist. Provided in function "
                                "mapping fo AI "
                                "decomp.",
                                fn->name
                            );
                        }
                    }
                }

                if (code) {
                    rz_cons_println (code);
                    FREE (code);
                } else {
                    REAI_LOG_ERROR ("Decompilation failed");
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

RZ_IPI RzCmdStatus rz_collection_search_handler (RzCore* core, int argc, const char** argv) {
    UNUSED (argc);

    CString partial_collection_name = argv[1] && strlen (argv[1]) ? argv[1] : NULL;
    CString partial_binary_name     = argv[2] && strlen (argv[2]) ? argv[2] : NULL;
    CString partial_binary_sha256   = argv[3] && strlen (argv[3]) ? argv[3] : NULL;
    CString model_name              = argv[4] && strlen (argv[4]) ? argv[4] : NULL;
    CString tags_csv                = argv[5] && strlen (argv[5]) ? argv[5] : NULL;

    if (reai_plugin_collection_search (
            core,
            partial_collection_name,
            partial_binary_name,
            partial_binary_sha256,
            model_name,
            tags_csv
        )) {
        return RZ_CMD_STATUS_OK;
    }

    return RZ_CMD_STATUS_ERROR;
}
RZ_IPI RzCmdStatus
    rz_collection_search_by_binary_name_handler (RzCore* core, int argc, const char** argv) {
    UNUSED (argc);

    CString partial_binary_name = argv[1] && strlen (argv[1]) ? argv[1] : NULL;
    CString model_name          = argv[2] && strlen (argv[2]) ? argv[2] : NULL;

    if (reai_plugin_collection_search (core, NULL, partial_binary_name, NULL, model_name, NULL)) {
        return RZ_CMD_STATUS_OK;
    }

    return RZ_CMD_STATUS_ERROR;
}
RZ_IPI RzCmdStatus
    rz_collection_search_by_collection_name_handler (RzCore* core, int argc, const char** argv) {
    UNUSED (argc);

    CString partial_collection_name = argv[1] && strlen (argv[1]) ? argv[1] : NULL;
    CString model_name              = argv[2] && strlen (argv[2]) ? argv[2] : NULL;

    if (reai_plugin_collection_search (
            core,
            partial_collection_name,
            NULL,
            NULL,
            model_name,
            NULL
        )) {
        return RZ_CMD_STATUS_OK;
    }

    return RZ_CMD_STATUS_ERROR;
}
RZ_IPI RzCmdStatus
    rz_collection_search_by_hash_value_handler (RzCore* core, int argc, const char** argv) {
    UNUSED (argc);

    CString partial_binary_sha256 = argv[1] && strlen (argv[1]) ? argv[1] : NULL;
    CString model_name            = argv[2] && strlen (argv[2]) ? argv[2] : NULL;

    if (reai_plugin_collection_search (core, NULL, NULL, partial_binary_sha256, model_name, NULL)) {
        return RZ_CMD_STATUS_OK;
    }

    return RZ_CMD_STATUS_ERROR;
}

static Bool str_to_filter_flags (CString filters, ReaiCollectionBasicInfoFilterFlags* flags) {
    if (!flags) {
        return false;
    }

    if (!filters) {
        return true;
    }

    while (*filters) {
        switch (*filters) {
            case 'o' :
                *flags |= REAI_COLLECTION_BASIC_INFO_FILTER_OFFICIAL;
                break;
            case 'u' :
                *flags |= REAI_COLLECTION_BASIC_INFO_FILTER_PUBLIC;
                break;
            case 't' :
                *flags |= REAI_COLLECTION_BASIC_INFO_FILTER_TEAM;
                break;
            case 'p' :
                *flags |= REAI_COLLECTION_BASIC_INFO_FILTER_PUBLIC;
                break;
            default :
                APPEND_ERROR (
                    "Invalid filter flag '%c'.\nAvailable flags are [o] - official, [u] - user, "
                    "[t] - team, [p] - public only",
                    *filters
                );
                return false;
                break;
        }
        filters++;
    }

    return true;
}

/**
 * REcat
 * */
RZ_IPI RzCmdStatus
    rz_collection_basic_info_time_asc_handler (RzCore* core, int argc, const char** argv) {
    UNUSED (argc);
    CString search_term = argv[1] && strlen (argv[1]) ? argv[1] : NULL;
    CString filters     = argv[2] && strlen (argv[2]) ? argv[2] : NULL;

    ReaiCollectionBasicInfoFilterFlags filter_flags = REAI_COLLECTION_BASIC_INFO_FILTER_HIDE_EMPTY;
    if (!str_to_filter_flags (filters, &filter_flags)) {
        DISPLAY_ERROR ("Failed to understand provided filter flags");
        return RZ_CMD_STATUS_ERROR;
    }

    if (reai_plugin_collection_basic_info (
            core,
            search_term,
            filter_flags,
            REAI_COLLECTION_BASIC_INFO_ORDER_BY_CREATED,
            true // ascending ordering
        )) {
        return RZ_CMD_STATUS_OK;
    }
    return RZ_CMD_STATUS_ERROR;
}

/**
 * REcao
 * */
RZ_IPI RzCmdStatus
    rz_collection_basic_info_owner_asc_handler (RzCore* core, int argc, const char** argv) {
    UNUSED (argc);
    CString search_term = argv[1] && strlen (argv[1]) ? argv[1] : NULL;
    CString filters     = argv[2] && strlen (argv[2]) ? argv[2] : NULL;

    ReaiCollectionBasicInfoFilterFlags filter_flags = REAI_COLLECTION_BASIC_INFO_FILTER_HIDE_EMPTY;
    if (!str_to_filter_flags (filters, &filter_flags)) {
        DISPLAY_ERROR ("Failed to understand provided filter flags");
        return RZ_CMD_STATUS_ERROR;
    }

    if (reai_plugin_collection_basic_info (
            core,
            search_term,
            filter_flags,
            REAI_COLLECTION_BASIC_INFO_ORDER_BY_OWNER,
            true // ascending ordering
        )) {
        return RZ_CMD_STATUS_OK;
    }
    return RZ_CMD_STATUS_ERROR;
}

/**
 * REcan
 * */
RZ_IPI RzCmdStatus
    rz_collection_basic_info_name_asc_handler (RzCore* core, int argc, const char** argv) {
    UNUSED (argc);
    CString search_term = argv[1] && strlen (argv[1]) ? argv[1] : NULL;
    CString filters     = argv[2] && strlen (argv[2]) ? argv[2] : NULL;

    ReaiCollectionBasicInfoFilterFlags filter_flags = REAI_COLLECTION_BASIC_INFO_FILTER_HIDE_EMPTY;
    if (!str_to_filter_flags (filters, &filter_flags)) {
        DISPLAY_ERROR ("Failed to understand provided filter flags");
        return RZ_CMD_STATUS_ERROR;
    }

    if (reai_plugin_collection_basic_info (
            core,
            search_term,
            filter_flags,
            REAI_COLLECTION_BASIC_INFO_ORDER_BY_COLLECTION,
            true // ascending ordering
        )) {
        return RZ_CMD_STATUS_OK;
    }
    return RZ_CMD_STATUS_ERROR;
}

/**
 * REcam
 * */
RZ_IPI RzCmdStatus
    rz_collection_basic_info_model_asc_handler (RzCore* core, int argc, const char** argv) {
    UNUSED (argc);
    CString search_term = argv[1] && strlen (argv[1]) ? argv[1] : NULL;
    CString filters     = argv[2] && strlen (argv[2]) ? argv[2] : NULL;

    ReaiCollectionBasicInfoFilterFlags filter_flags = REAI_COLLECTION_BASIC_INFO_FILTER_HIDE_EMPTY;
    if (!str_to_filter_flags (filters, &filter_flags)) {
        DISPLAY_ERROR ("Failed to understand provided filter flags");
        return RZ_CMD_STATUS_ERROR;
    }

    if (reai_plugin_collection_basic_info (
            core,
            search_term,
            filter_flags,
            REAI_COLLECTION_BASIC_INFO_ORDER_BY_MODEL,
            true // ascending ordering
        )) {
        return RZ_CMD_STATUS_OK;
    }
    return RZ_CMD_STATUS_ERROR;
}

/**
 * REcas
 * */
RZ_IPI RzCmdStatus
    rz_collection_basic_info_size_asc_handler (RzCore* core, int argc, const char** argv) {
    UNUSED (argc);
    CString search_term = argv[1] && strlen (argv[1]) ? argv[1] : NULL;
    CString filters     = argv[2] && strlen (argv[2]) ? argv[2] : NULL;

    ReaiCollectionBasicInfoFilterFlags filter_flags = REAI_COLLECTION_BASIC_INFO_FILTER_HIDE_EMPTY;
    if (!str_to_filter_flags (filters, &filter_flags)) {
        DISPLAY_ERROR ("Failed to understand provided filter flags");
        return RZ_CMD_STATUS_ERROR;
    }

    if (reai_plugin_collection_basic_info (
            core,
            search_term,
            filter_flags,
            REAI_COLLECTION_BASIC_INFO_ORDER_BY_COLLECTION_SIZE,
            true // ascending ordering
        )) {
        return RZ_CMD_STATUS_OK;
    }
    return RZ_CMD_STATUS_ERROR;
}

/**
 * REcdt
 * */
RZ_IPI RzCmdStatus
    rz_collection_basic_info_time_desc_handler (RzCore* core, int argc, const char** argv) {
    UNUSED (argc);
    CString search_term = argv[1] && strlen (argv[1]) ? argv[1] : NULL;
    CString filters     = argv[2] && strlen (argv[2]) ? argv[2] : NULL;

    ReaiCollectionBasicInfoFilterFlags filter_flags = REAI_COLLECTION_BASIC_INFO_FILTER_HIDE_EMPTY;
    if (!str_to_filter_flags (filters, &filter_flags)) {
        DISPLAY_ERROR ("Failed to understand provided filter flags");
        return RZ_CMD_STATUS_ERROR;
    }

    if (reai_plugin_collection_basic_info (
            core,
            search_term,
            filter_flags,
            REAI_COLLECTION_BASIC_INFO_ORDER_BY_CREATED,
            false // descending ordering
        )) {
        return RZ_CMD_STATUS_OK;
    }
    return RZ_CMD_STATUS_ERROR;
}

/**
 * REcdo
 * */
RZ_IPI RzCmdStatus
    rz_collection_basic_info_owner_desc_handler (RzCore* core, int argc, const char** argv) {
    UNUSED (argc);
    CString search_term = argv[1] && strlen (argv[1]) ? argv[1] : NULL;
    CString filters     = argv[2] && strlen (argv[2]) ? argv[2] : NULL;

    ReaiCollectionBasicInfoFilterFlags filter_flags = REAI_COLLECTION_BASIC_INFO_FILTER_HIDE_EMPTY;
    if (!str_to_filter_flags (filters, &filter_flags)) {
        DISPLAY_ERROR ("Failed to understand provided filter flags");
        return RZ_CMD_STATUS_ERROR;
    }

    if (reai_plugin_collection_basic_info (
            core,
            search_term,
            filter_flags,
            REAI_COLLECTION_BASIC_INFO_ORDER_BY_OWNER,
            false // descending ordering
        )) {
        return RZ_CMD_STATUS_OK;
    }
    return RZ_CMD_STATUS_ERROR;
}

/**
 * REcdn
 * */
RZ_IPI RzCmdStatus
    rz_collection_basic_info_name_desc_handler (RzCore* core, int argc, const char** argv) {
    UNUSED (argc);
    CString search_term = argv[1] && strlen (argv[1]) ? argv[1] : NULL;
    CString filters     = argv[2] && strlen (argv[2]) ? argv[2] : NULL;

    ReaiCollectionBasicInfoFilterFlags filter_flags = REAI_COLLECTION_BASIC_INFO_FILTER_HIDE_EMPTY;
    if (!str_to_filter_flags (filters, &filter_flags)) {
        DISPLAY_ERROR ("Failed to understand provided filter flags");
        return RZ_CMD_STATUS_ERROR;
    }

    if (reai_plugin_collection_basic_info (
            core,
            search_term,
            filter_flags,
            REAI_COLLECTION_BASIC_INFO_ORDER_BY_COLLECTION,
            false // descending ordering
        )) {
        return RZ_CMD_STATUS_OK;
    }
    return RZ_CMD_STATUS_ERROR;
}

/**
 * REcdm
 * */
RZ_IPI RzCmdStatus
    rz_collection_basic_info_model_desc_handler (RzCore* core, int argc, const char** argv) {
    UNUSED (argc);
    CString search_term = argv[1] && strlen (argv[1]) ? argv[1] : NULL;
    CString filters     = argv[2] && strlen (argv[2]) ? argv[2] : NULL;

    ReaiCollectionBasicInfoFilterFlags filter_flags = REAI_COLLECTION_BASIC_INFO_FILTER_HIDE_EMPTY;
    if (!str_to_filter_flags (filters, &filter_flags)) {
        DISPLAY_ERROR ("Failed to understand provided filter flags");
        return RZ_CMD_STATUS_ERROR;
    }

    if (reai_plugin_collection_basic_info (
            core,
            search_term,
            filter_flags,
            REAI_COLLECTION_BASIC_INFO_ORDER_BY_MODEL,
            false // descending ordering
        )) {
        return RZ_CMD_STATUS_OK;
    }
    return RZ_CMD_STATUS_ERROR;
}

/**
 * REcds
 * */
RZ_IPI RzCmdStatus
    rz_collection_basic_info_size_desc_handler (RzCore* core, int argc, const char** argv) {
    UNUSED (argc);
    CString search_term = argv[1] && strlen (argv[1]) ? argv[1] : NULL;
    CString filters     = argv[2] && strlen (argv[2]) ? argv[2] : NULL;

    ReaiCollectionBasicInfoFilterFlags filter_flags = REAI_COLLECTION_BASIC_INFO_FILTER_HIDE_EMPTY;
    if (!str_to_filter_flags (filters, &filter_flags)) {
        DISPLAY_ERROR ("Failed to understand provided filter flags");
        return RZ_CMD_STATUS_ERROR;
    }

    if (reai_plugin_collection_basic_info (
            core,
            search_term,
            filter_flags,
            REAI_COLLECTION_BASIC_INFO_ORDER_BY_COLLECTION_SIZE,
            false // descending ordering
        )) {
        return RZ_CMD_STATUS_OK;
    }
    return RZ_CMD_STATUS_ERROR;
}

/**
 * REbs
 * */
RZ_IPI RzCmdStatus rz_binary_search_handler (RzCore* core, int argc, const char** argv) {
    UNUSED (argc);

    CString partial_name   = argv[1] && strlen (argv[1]) ? argv[1] : NULL;
    CString partial_sha256 = argv[2] && strlen (argv[2]) ? argv[2] : NULL;
    CString model_name     = argv[3] && strlen (argv[3]) ? argv[3] : NULL;
    CString tags_csv       = argv[4] && strlen (argv[4]) ? argv[4] : NULL;

    if (reai_plugin_binary_search (core, partial_name, partial_sha256, model_name, tags_csv)) {
        return RZ_CMD_STATUS_OK;
    }
    return RZ_CMD_STATUS_ERROR;
}

/**
 * REbsn
 * */
RZ_IPI RzCmdStatus rz_binary_search_by_name_handler (RzCore* core, int argc, const char** argv) {
    UNUSED (argc);

    CString partial_name = argv[1] && strlen (argv[1]) ? argv[1] : NULL;
    CString model_name   = argv[2] && strlen (argv[2]) ? argv[2] : NULL;

    if (reai_plugin_binary_search (core, partial_name, NULL, model_name, NULL)) {
        return RZ_CMD_STATUS_OK;
    }
    return RZ_CMD_STATUS_ERROR;
}

/**
 * REbsh
 * */
RZ_IPI RzCmdStatus rz_binary_search_by_sha256_handler (RzCore* core, int argc, const char** argv) {
    UNUSED (argc);

    CString partial_sha256 = argv[1] && strlen (argv[1]) ? argv[1] : NULL;
    CString model_name     = argv[2] && strlen (argv[2]) ? argv[2] : NULL;

    if (reai_plugin_binary_search (core, NULL, partial_sha256, model_name, NULL)) {
        return RZ_CMD_STATUS_OK;
    }
    return RZ_CMD_STATUS_ERROR;
}

/**
 * REco
 * */
RZ_IPI RzCmdStatus rz_collection_link_handler (RzCore* core, int argc, const char** argv) {
    UNUSED (argc);

    ReaiCollectionId cid = argv[1] && strlen (argv[1]) ? rz_num_get (core->num, argv[1]) : 0;

    // generate portal link
    char* host = strdup (reai_plugin()->reai_config->host);
    host       = rz_str_replace (host, "api", "portal", 0 /* replace first only */);
    if (!host) {
        DISPLAY_ERROR ("Failed to generate portal link");
        return RZ_CMD_STATUS_ERROR;
    }

    // TODO: should we also get basic collection information and display it here?
    DISPLAY_INFO ("%s/collections/%llu", host, cid);

    CString syscmd = NULL;
#if defined(WIN32) || defined(_WIN32) || defined(__WIN32__) || defined(__NT__)
    syscmd = "start";
#elif __APPLE__
    syscmd = "open";
#elif __linux__
    syscmd = "xdg-open";
#else
    syscmd = NULL;
#    warn "Unsupported OS. Won't open links from command line."
#endif

    if (syscmd) {
        CString cmd = rz_str_newf ("%s %s/collections/%llu", syscmd, host, cid);
        rz_sys_system (cmd);
        FREE (cmd);
    }

    FREE (host);

    FREE (host);

    return RZ_CMD_STATUS_OK;
}

/**
 * REao
 * */
RZ_IPI RzCmdStatus rz_analysis_link_handler (RzCore* core, int argc, const char** argv) {
    UNUSED (argc);

    ReaiBinaryId bid = 0;
    if (argc == 2) {
        bid = argv[1] && strlen (argv[1]) ? rz_num_get (core->num, argv[1]) : 0;
        if (!bid) {
            DISPLAY_ERROR ("Invalid binary ID provided.");
            return RZ_CMD_STATUS_ERROR;
        }
    } else {
        bid = reai_binary_id();
        if (!bid) {
            APPEND_ERROR ("No existing analysis applied. Don't know what analysis to open.");
            DISPLAY_ERROR (
                "Please either apply an existing analysis or provide me a binary ID to open an "
                "analysis page"
            );
        }
    }

    // generate portal link
    char* host = strdup (reai_plugin()->reai_config->host);
    host       = rz_str_replace (host, "api", "portal", 0 /* replace first only */);
    if (!host) {
        DISPLAY_ERROR ("Failed to generate portal link");
        return RZ_CMD_STATUS_ERROR;
    }

    // TODO: should we also get basic binary information and display it here?
    DISPLAY_INFO (
        "%s/analyses/%llu?analysis-id=%llu",
        host,
        bid,
        reai_analysis_id_from_binary_id (reai(), reai_response(), bid)
    );

    CString syscmd = NULL;
#if defined(WIN32) || defined(_WIN32) || defined(__WIN32__) || defined(__NT__)
    syscmd = "start";
#elif __APPLE__
    syscmd = "open";
#elif __linux__
    syscmd = "xdg-open";
#else
    syscmd = NULL;
#    warn "Unsupported OS. Won't open links from command line."
#endif

    if (syscmd) {
        CString cmd = rz_str_newf (
            "%s %s/analyses/%llu?analysis-id=%llu",
            syscmd,
            host,
            bid,
            reai_analysis_id_from_binary_id (reai(), reai_response(), bid)
        );
        rz_sys_system (cmd);
        FREE (cmd);
    }

    FREE (host);

    return RZ_CMD_STATUS_OK;
}

/**
 * REfo
 * */
RZ_IPI RzCmdStatus rz_function_link_handler (RzCore* core, int argc, const char** argv) {
    REAI_LOG_TRACE ("[CMD] function link");
    UNUSED (argc);

    ReaiFunctionId fid = argv[1] && strlen (argv[1]) ? rz_num_get (core->num, argv[1]) : 0;

    // generate portal link
    char* host = strdup (reai_plugin()->reai_config->host);
    host       = rz_str_replace (host, "api", "portal", 0 /* replace first only */);
    if (!host) {
        DISPLAY_ERROR ("Failed to generate portal link");
        return RZ_CMD_STATUS_ERROR;
    }

    // TODO: should we also get basic function information and display it here?
    DISPLAY_INFO ("%s/functions/%llu", host, fid);

    CString syscmd = NULL;
#if defined(WIN32) || defined(_WIN32) || defined(__WIN32__) || defined(__NT__)
    syscmd = "start";
#elif __APPLE__
    syscmd = "open";
#elif __linux__
    syscmd = "xdg-open";
#else
    syscmd = NULL;
#    warn "Unsupported OS. Won't open links from command line."
#endif

    if (syscmd) {
        CString cmd = rz_str_newf ("%s %s/function/%llu", syscmd, host, fid);
        rz_sys_system (cmd);
        FREE (cmd);
    }


    FREE (host);

    return RZ_CMD_STATUS_OK;
}

/**
 * REal
 * */
RZ_IPI RzCmdStatus
    rz_get_analysis_logs_using_analysis_id_handler (RzCore* core, int argc, const char** argv) {
    REAI_LOG_TRACE ("[CMD] Get Analysis Logs");

    ReaiAnalysisId id             = 0;
    Bool           is_analysis_id = true;
    if (argc == 2) {
        id = rz_num_get (core->num, argv[1]);
    } else {
        id = reai_binary_id();

        if (!id) {
            DISPLAY_ERROR (
                "You haven't provided any analysis id.\n"
                "Did you forget to apply an existing analysis or to create a new one?\n"
                "Cannot fetch analysis logs, not enough information provided.\n"
            );
            return RZ_CMD_STATUS_WRONG_ARGS;
        }

        is_analysis_id = false;
    }

    if (!reai_plugin_get_analysis_logs (core, id, is_analysis_id)) {
        DISPLAY_ERROR ("Failed to fetch and display analysis logs");
        return RZ_CMD_STATUS_ERROR;
    }
    return RZ_CMD_STATUS_OK;
}

/**
 * REalb
 * */
RZ_IPI RzCmdStatus
    rz_get_analysis_logs_using_binary_id_handler (RzCore* core, int argc, const char** argv) {
    ReaiAnalysisId binary_id = 0;
    if (argc == 2) {
        binary_id = rz_num_get (core->num, argv[1]);
    } else {
        binary_id = reai_binary_id();

        if (!binary_id) {
            DISPLAY_ERROR (
                "You haven't provided any binary id.\n"
                "Did you forget to apply an existing analysis or to create a new one?\n"
                "Cannot fetch analysis logs\n"
            );
            return RZ_CMD_STATUS_WRONG_ARGS;
        }
    }

    if (!reai_plugin_get_analysis_logs (core, binary_id, false /* provided is a binary id */)) {
        DISPLAY_ERROR ("Failed to fetch and display analysis logs");
        return RZ_CMD_STATUS_ERROR;
    }
    return RZ_CMD_STATUS_OK;
}

/**
 * "REar"
 * */
RZ_IPI RzCmdStatus rz_get_recent_analyses_handler (RzCore* core, int argc, const char** argv) {
    UNUSED (core && argc && argv);

    ReaiAnalysisInfoVec* results = reai_get_recent_analyses (
        reai(),
        reai_response(),
        NULL /* search term */,
        REAI_WORKSPACE_PUBLIC,
        REAI_ANALYSIS_STATUS_ALL,
        NULL, /* model name */
        REAI_DYN_EXEC_STATUS_ALL,
        NULL, /* usernames */
        25,   /* 25 most recent analyses */
        0,
        REAI_RECENT_ANALYSIS_ORDER_BY_CREATED,
        false
    );
    if (!results) {
        DISPLAY_ERROR ("Failed to get most recent analysis. Are you a new user?");
        return RZ_CMD_STATUS_ERROR;
    }

    ReaiPluginTable* t = reai_plugin_table_create();
    reai_plugin_table_set_title (t, "Most Recent Analyses");
    reai_plugin_table_set_columnsf (
        t,
        "nnssss",
        "analysis_id",
        "binary_id",
        "status",
        "creation",
        "binary_name",
        "scope"
    );

    REAI_VEC_FOREACH (results, r, {
        reai_plugin_table_add_rowf (
            t,
            "nnssss",
            r->analysis_id,
            r->binary_id,
            reai_analysis_status_to_cstr (r->status),
            r->creation,
            r->binary_name,
            r->is_public ? "PUBLIC" : "PRIVATE"
        );
    });

    reai_plugin_table_show (t);
    reai_plugin_table_destroy (t);

    return RZ_CMD_STATUS_OK;
}


// clang-format off
RZ_IPI RzCmdStatus rz_show_revengai_art_handler (RzCore* core, int argc, const char** argv) {
    UNUSED (core && argc && argv);

    rz_cons_println (
        "\n"
        "\n"
        ":::::::::::        :::::::::::\n"
        "::    ::::::      ::::    ::::             %%%%%%%%%%%%%                                        %%%%%%%%%%%%%%%\n"
        "::    :::::::    :::::    ::::            %%%%%%%%%%%%%%%                                       %%%%%%%%%%%%%%%                                %%%%%@\n"
        "::::::::::::::::::::::::::::::           %%%%%%%    %%%%%                                       %%%%%                                          %%%%%%\n"
        ":::::::::   ::::   :::::::::::           %%%%%%     %%%%%     @%%%%%%%%%%    %%%%%@    %%%%%    %%%%%             %%%%% %%%%%%%%      @%%%%%%%%%%%\n"
        " :::::::    ::::    :::::::::            %%%%%%     %%%%%    %%%%%%%%%%%%%%  %%%%%%    %%%%%%   %%%%%%%%%%%%%%    %%%%%%%%%%%%%%%    %%%%%%%%%%%%%%\n"
        "     ::::::::::::::::::::                %%%%%%%%%%%%%%%   %%%%%     @%%%%%  %%%%%%    %%%%%    %%%%%%%%%%%%%%    %%%%%%    %%%%%%  %%%%%@    %%%%%@\n"
        "       ::::::::::::::::                    %%%%%%%%%%%%%  @%%%%%%%%%%%%%%%%   %%%%%@   %%%%%    %%%%%%%%%%%%%%    %%%%%     %%%%%%  %%%%%%    %%%%%%               @@@@    @@@@@@@@\n"
        "     ::::   ::::    :::::                  @%%%%%@ %%%%%  %%%%%%%%%%%%%%%%%   %%%%%% %%%%%%     %%%%%             %%%%%     %%%%%%   %%%%%%%%%%%%%@               @@@@@@     @@@\n"
        " ::::::::   ::::    :::::::::              %%%%%%@ %%%%%   %%%%%               %%%%%%%%%%%      %%%%%             %%%%%     %%%%%%     %%%%%%%%%%                @@@@ @@@    @@@\n"
        "::::::::::::::::::::::::::::::          %%%%%%%%   %%%%%   %%%%%%@   %%%%%      %%%%%%%%%       %%%%%%%%%%%%%%%   %%%%%     %%%%%%   %%%%                        @@@@@@@@    @@@\n"
        "::    ::::::::::::::::    ::::          %%%%%%%    %%%%%    @%%%%%%%%%%%%%       %%%%%%%%       %%%%%%%%%%%%%%%   %%%%%     %%%%%%   %%%%%%%%%%%%%%%    @@@@    @@@@  @@@@ @@@@@@@@\n"
        "::    :::::::    :::::    ::::          %%%%%      %%%%%       %%%%%%%%%         %%%%%%%        %%%%%%%%%%%%%%    %%%%%     %%%%%@   %%%%%%%%%%%%%%%%    @@@    @@@   @@@@ @@@@@@@@\n"
        ":.::::::::::      ::::::::::::                                                                                                      %%%%        %%%%%\n"
        ":::::::::::        :::::::::::                                                                                                      %%%%%%%%%%%%%%%%%\n"
        "                                                                                                                                     %%%%%%%%%%%%%%\n"
        "\n"
    );
    return RZ_CMD_STATUS_OK;
}
