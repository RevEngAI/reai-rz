/**
 * @file : CmdHandlers.c
 * @date : 13th June 2024
 * @author : Siddharth Mishra (admin@brightprogrammer.in)
 * @copyright: Copyright (c) 2024 RevEngAI. All Rights Reserved.
 *
 * @b This file defines all the handlers that are declated inside `CmdGen/Output/CmdDescs.h`
 * After adding a new command entry, implement corresponding handlers here and then compile.
 * */

#include <Reai/Api.h>
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

#define ZSTR_ARG(vn, idx) (argc > (idx) ? (((vn) = argv[idx]), true) : false)
#define STR_ARG(vn, idx)  (argc > (idx) ? (((vn) = StrInitFromZstr (argv[idx])), true) : false)
#define NUM_ARG(vn, idx)  (argc > (idx) ? (((vn) = rz_num_get (core->num, argv[idx])), true) : false)

RZ_IPI RzCmdStatus rz_plugin_initialize_handler (RzCore* core, int argc, const char** argv) {
    // NOTE(brightprogrammer): Developers should just change this in the config file.
    const char* host    = "https://api.reveng.ai"; // Hardcode API endpoint
    const char* api_key = argc > 1 ? argv[1] : NULL;

    Config cfg = ConfigInit();
    ConfigAdd (&cfg, "host", host);
    ConfigAdd (&cfg, "api_key", api_key);
    ConfigWrite (&cfg, NULL);
    ConfigDeinit (&cfg);

    ReloadPluginData();

    return RZ_CMD_STATUS_OK;
}

/**
 * "REm"
 * */
RZ_IPI RzCmdStatus rz_list_available_ai_models_handler (RzCore* core, int argc, const char** argv) {
    ModelInfos models = GetModels();
    VecForeach (&models, model, { rz_cons_println (model.name.data); });

    return RZ_CMD_STATUS_OK;
}

/**
 * "REh"
 *
 * @b Perform an auth-check api call to check connection.
 * */
RZ_IPI RzCmdStatus rz_health_check_handler (RzCore* core, int argc, const char** argv) {
    if (!Authenticate (GetConnection())) {
        rz_cons_println ("No connection");
    } else {
        rz_cons_println ("OK");
    }

    return RZ_CMD_STATUS_OK;
}

RzCmdStatus createAnalysis (RzCore* core, int argc, const char** argv, bool is_private) {
    NewAnalysisRequest new_analysis = NewAnalysisRequestInit();
    BinaryId           bin_id       = 0;

    if (STR_ARG (new_analysis.ai_model, 1) && STR_ARG (new_analysis.file_name, 2)) {
        STR_ARG (new_analysis.cmdline_args, 3);

        new_analysis.is_private = is_private;

        Str path            = rzGetCurrentBinaryPath (core);
        new_analysis.sha256 = UploadFile (GetConnection(), path);
        if (!new_analysis.sha256.length) {
            APPEND_ERROR ("Failed to upload binary");
        } else {
            bin_id = CreateNewAnalysis (GetConnection(), &new_analysis);
        }
        StrDeinit (&path);
    }

    NewAnalysisRequestDeinit (&new_analysis);

    if (!bin_id) {
        DISPLAY_ERROR ("Failed to create new analysis");
        return RZ_CMD_STATUS_ERROR;
    }

    return RZ_CMD_STATUS_ERROR;
}

/**
 * "REa"
 * */
RZ_IPI RzCmdStatus rz_create_analysis_public_handler (RzCore* core, int argc, const char** argv) {
    return createAnalysis (core, argc, argv, true);
}

/**
 * "REap"
 * */
RZ_IPI RzCmdStatus rz_create_analysis_private_handler (RzCore* core, int argc, const char** argv) {
    return createAnalysis (core, argc, argv, false);
}

/**
 * "REae"
 * */
RZ_IPI RzCmdStatus rz_apply_existing_analysis_handler (RzCore* core, int argc, const char** argv) {
    BinaryId bin_id = 0;

    if (NUM_ARG (bin_id, 1)) {
        rzApplyAnalysis (core, bin_id);
        return RZ_CMD_STATUS_OK;
    } else {
        LOG_ERROR ("Invalid binary ID");
        return RZ_CMD_STATUS_ERROR;
    }
}

RzCmdStatus autoAnalyze (RzCore* core, int argc, const char** argv, bool restruct_to_debug) {
    Config* cfg = GetConfig();

    Str* armx         = ConfigGet (cfg, "auto_rename_max_results_per_function");
    u32  result_count = 20;
    if (armx) {
        result_count = rz_num_get (core->num, armx->data);
        result_count = CLAMP (result_count, 5, 50);
    }

    u32 min_similarity = 90;
    NUM_ARG (min_similarity, 1);

    rzAutoRenameFunctions (result_count, min_similarity, restruct_to_debug);

    return RZ_CMD_STATUS_OK;
}

/**
 * REaa
 * */
RZ_IPI RzCmdStatus rz_ann_auto_analyze_handler (RzCore* core, int argc, const char** argv) {
    return autoAnalyze (core, argc, argv, true);
}

/**
 * REaaa
 * */
RZ_IPI RzCmdStatus rz_ann_auto_analyze_all_handler (RzCore* core, int argc, const char** argv) {
    return autoAnalyze (core, argc, argv, false);
}

/**
 * "REfl"
 * */
RZ_IPI RzCmdStatus rz_get_basic_function_info_handler (RzCore* core, int argc, const char** argv) {
    if (rzCanWorkWithAnalysis (GetBinaryId(), true)) {
        FunctionInfos functions = GetBasicFunctionInfoUsingBinaryId (GetConnection(), GetBinaryId());

        if (!functions.length) {
            DISPLAY_ERROR ("Failed to get functions from RevEngAI analysis.");
        }

        RzTable* table = rz_table_new();
        if (!table) {
            DISPLAY_ERROR ("Failed to create the table.");
            return RZ_CMD_STATUS_ERROR;
        }

        rz_table_set_columnsf (table, "nsxx", "function_id", "name", "vaddr", "size");
        VecForeachPtr (&functions, fn, {
            rz_table_add_rowf (table, "nsxx", fn->id, fn->symbol.name.data, fn->symbol.value.addr, fn->size);
        });

        const char* table_str = rz_table_tofancystring (table);
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

    return RZ_CMD_STATUS_ERROR;
}

/**
 * "REfr"
 *
 * @b Rename function with given function id to given new name.
 * */
RZ_IPI RzCmdStatus rz_rename_function_handler (RzCore* core, int argc, const char** argv) {
    if (rzCanWorkWithAnalysis (GetBinaryId(), true)) {
        Str old_name = StrInit(), new_name = StrInit();
        if (STR_ARG (old_name, 1), STR_ARG (new_name, 2)) {
            RzAnalysisFunction* fn = rz_analysis_get_function_byname (core->analysis, old_name.data);
            if (!fn) {
                DISPLAY_ERROR ("Rizin function with given name not found.");
                return RZ_CMD_STATUS_ERROR;
            }

            if (RenameFunction (GetConnection(), rzLookupFunctionId (core, fn), new_name)) {
                DISPLAY_ERROR ("Failed to rename function");
                return RZ_CMD_STATUS_ERROR;
            }

            return RZ_CMD_STATUS_OK;
        }
    }

    return RZ_CMD_STATUS_ERROR;
}

RzCmdStatus functionSimilaritySearch (RzCore* core, int argc, const char** argv, bool restrict_to_debug) {
    SimilarFunctionsRequest search = SimilarFunctionsRequestInit();

    const char* function_name      = NULL;
    Str         collection_ids_csv = StrInit();
    Str         binary_ids_csv     = StrInit();
    u32         min_similarity     = 0;

    if (ZSTR_ARG (function_name, 1) && NUM_ARG (min_similarity, 2) && NUM_ARG (search.limit, 3) &&
        STR_ARG (collection_ids_csv, 4) && STR_ARG (binary_ids_csv, 5)) {
        search.distance                       = 1 - (CLAMP (min_similarity, 1, 100) / 100);
        search.debug_include.user_symbols     = restrict_to_debug;
        search.debug_include.system_symbols   = restrict_to_debug;
        search.debug_include.external_symbols = restrict_to_debug;

        Strs cids = StrSplit (&collection_ids_csv, ",");
        VecForeachPtr (&cids, cid, { VecPushBack (&search.collection_ids, strtoull (cid->data, NULL, 0)); });
        StrDeinit (&collection_ids_csv);
        VecDeinit (&cids);

        Strs bids = StrSplit (&binary_ids_csv, ",");
        VecForeachPtr (&bids, bid, { VecPushBack (&search.binary_ids, strtoull (bid->data, NULL, 0)); });
        StrDeinit (&binary_ids_csv);
        VecDeinit (&bids);

        search.function_id = rzLookupFunctionIdForFunctionWithName (core, function_name);

        if (search.function_id) {
            SimilarFunctions functions = GetSimilarFunctions (GetConnection(), &search);

            if (functions.length) {
                RzTable* table = rz_table_new();
                rz_table_set_columnsf (
                    table,
                    "snsnn",
                    "Function Name",
                    "Function ID",
                    "Binary Name",
                    "Binary ID",
                    "Similarity"
                );

                VecForeachPtr (&functions, fn, {
                    rz_table_add_rowf (
                        table,
                        "snsnf",
                        fn->name.data,
                        fn->id,
                        fn->binary_name.data,
                        fn->binary_id,
                        (1 - fn->distance) * 100
                    );
                });

                const char* table_str = rz_table_tofancystring (table);
                rz_cons_println (table_str);

                FREE (table_str);
                rz_table_free (table);
                VecDeinit (&functions);
                SimilarFunctionsRequestDeinit (&search);

                return RZ_CMD_STATUS_OK;
            }
        }
    }

    DISPLAY_ERROR ("Failed to perform function similarity search");
    SimilarFunctionsRequestDeinit (&search);
    return RZ_CMD_STATUS_ERROR;
}

/**
 * "REfs"
 * */
RZ_IPI RzCmdStatus rz_function_similarity_search_handler (RzCore* core, int argc, const char** argv) {
    return functionSimilaritySearch (core, argc, argv, false);
}

/**
 * "REfsd"
 * */
RZ_IPI RzCmdStatus rz_function_similarity_search_debug_handler (RzCore* core, int argc, const char** argv) {
    return functionSimilaritySearch (core, argc, argv, true);
}

RZ_IPI RzCmdStatus rz_ai_decompile_handler (RzCore* core, int argc, const char** argv) {
    LOG_INFO ("[CMD] AI decompile");
    const char* fn_name = argc > 1 ? argv[1] : NULL;
    if (!fn_name) {
        return RZ_CMD_STATUS_INVALID;
    }

    if (rzCanWorkWithAnalysis (GetBinaryId(), true)) {
        FunctionId fn_id = rzLookupFunctionIdForFunctionWithName (core, fn_name);

        Status status = GetAiDecompilationStatus (GetConnection(), fn_id);
        if ((status & STATUS_MASK) == STATUS_ERROR) {
            if (!BeginAiDecompilation (GetConnection(), fn_id)) {
                DISPLAY_ERROR ("Failed to start AI decompilation process.");
                return RZ_CMD_STATUS_ERROR;
            }
        }

        while (true) {
            DISPLAY_INFO ("Checking decompilation status...");

            status = GetAiDecompilationStatus (GetConnection(), fn_id);
            switch (status & STATUS_MASK) {
                case STATUS_ERROR :
                    DISPLAY_ERROR (
                        "Failed to decompile '%s'\n"
                        "Is this function from RevEngAI's analysis?\n"
                        "What's the output of REfl?~'%s'",
                        fn_name,
                        fn_name
                    );
                    return RZ_CMD_STATUS_ERROR;

                case STATUS_UNINITIALIZED :
                    DISPLAY_INFO (
                        "No decompilation exists for this function...\n"
                        "Starting AI decompilation process!"
                    );
                    if (!BeginAiDecompilation (GetConnection(), fn_id)) {
                        DISPLAY_ERROR ("Failed to start AI decompilation process.");
                        return RZ_CMD_STATUS_ERROR;
                    }
                    break;

                case STATUS_PENDING : {
                    DISPLAY_INFO ("AI decompilation is queued and is pending. Should start soon!");
                    break;
                }

                case STATUS_SUCCESS : {
                    DISPLAY_INFO ("AI decompilation complete ;-)\n");

                    AiDecompilation aidec = GetAiDecompilation (GetConnection(), fn_id, true);
                    Str*            smry  = &aidec.summary;
                    Str*            dec   = &aidec.decompilation;

                    Str code = StrInit();

                    i32   l = smry->length;
                    char* p = smry->data;
                    while (l > 80) {
                        char* p1 = strchr (p + 80, ' ');
                        if (p1) {
                            StrAppendf (&code, "// %.*s\n", (i32)(p1 - p), p);
                            p1++;
                            l -= (p1 - p);
                            p  = p1;
                        } else {
                            break;
                        }
                    }
                    StrAppendf (&code, "// %.*s\n\n", (i32)l, p);
                    StrMerge (&code, dec);

                    VecForeachIdx (&aidec.functions, function, idx, {
                        Str dname = StrInit();
                        StrPrintf (&dname, "<DISASM_FUNCTION_%llu>", idx);
                        StrReplace (&code, &dname, &function.name, -1);
                        StrDeinit (&dname);
                    });

                    VecForeachIdx (&aidec.strings, string, idx, {
                        Str dname = StrInit();
                        StrPrintf (&dname, "<DISASM_STRING_%llu>", idx);
                        StrReplace (&code, &dname, &string.string, -1);
                        StrDeinit (&dname);
                    });

                    // print decompiled code with summary
                    rz_cons_println (code.data);

                    StrDeinit (&code);
                    AiDecompilationDeinit (&aidec);
                    return RZ_CMD_STATUS_OK;
                }
                default :
                    LOG_FATAL ("Unreachable code reached. Invalid decompilation status");
                    return RZ_CMD_STATUS_ERROR;
            }

            DISPLAY_INFO ("Going to sleep for two seconds...");
            rz_sys_sleep (2);
        }
    } else {
        DISPLAY_ERROR ("Failed to get AI decompilation.");
        return RZ_CMD_STATUS_ERROR;
    }
}

RzCmdStatus collectionSearch (Str name, Str bname, Str sha256, Str model_name, Str tags_csv) {
    SearchCollectionRequest search = SearchCollectionRequestInit();

    search.partial_collection_name = name;
    search.partial_binary_name     = bname;
    search.partial_binary_sha256   = sha256;
    search.model_name              = model_name;
    search.tags                    = StrSplit (&tags_csv, ",");

    StrDeinit (&tags_csv);

    CollectionInfos collections = SearchCollection (GetConnection(), &search);
    SearchCollectionRequestDeinit (&search);

    if (collections.length) {
        RzTable* t = rz_table_new();
        rz_table_set_columnsf (t, "snssss", "Name", "Id", "Scope", "Last Updated", "Model", "Owner");

        VecForeachPtr (&collections, collection, {
            rz_table_add_rowf (
                t,
                "snssss",
                collection->name.data,
                collection->id,
                collection->is_private ? "PRIVATE" : "PUBLIC",
                collection->last_updated_at.data,
                collection->model_name.data,
                collection->owned_by.data
            );
        });

        const char* s = rz_table_tofancystring (t);
        rz_cons_println (s);
        FREE (s);
        rz_table_free (t);
    } else {
        DISPLAY_ERROR ("Failed to get collection search results");
    }

    VecDeinit (&collections);

    return RZ_CMD_STATUS_ERROR;
}

/**
 * "REcs"
 * */
RZ_IPI RzCmdStatus rz_collection_search_handler (RzCore* core, int argc, const char** argv) {
    Str name = StrInit(), binary_name = StrInit(), binary_sha256 = StrInit(), model_name = StrInit(), tags = StrInit();

    STR_ARG (name, 1);
    STR_ARG (binary_name, 2);
    STR_ARG (binary_sha256, 3);
    STR_ARG (model_name, 4);
    STR_ARG (tags, 5);

    return collectionSearch (name, binary_name, binary_sha256, model_name, tags);
}

RZ_IPI RzCmdStatus rz_collection_search_by_binary_name_handler (RzCore* core, int argc, const char** argv) {
    Str name = StrInit(), binary_name = StrInit(), binary_sha256 = StrInit(), model_name = StrInit(), tags = StrInit();

    STR_ARG (binary_name, 1);
    STR_ARG (model_name, 2);

    return collectionSearch (name, binary_name, binary_sha256, model_name, tags);
}
RZ_IPI RzCmdStatus rz_collection_search_by_collection_name_handler (RzCore* core, int argc, const char** argv) {
    Str name = StrInit(), binary_name = StrInit(), binary_sha256 = StrInit(), model_name = StrInit(), tags = StrInit();

    STR_ARG (name, 1);
    STR_ARG (model_name, 2);

    return collectionSearch (name, binary_name, binary_sha256, model_name, tags);
}
RZ_IPI RzCmdStatus rz_collection_search_by_hash_value_handler (RzCore* core, int argc, const char** argv) {
    Str name = StrInit(), binary_name = StrInit(), binary_sha256 = StrInit(), model_name = StrInit(), tags = StrInit();

    STR_ARG (binary_sha256, 1);
    STR_ARG (model_name, 2);

    return collectionSearch (name, binary_name, binary_sha256, model_name, tags);
}

static bool str_to_filter_flags (const char* filters, CollectionBasicInfoFilterFlags* flags) {
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
RZ_IPI RzCmdStatus rz_collection_basic_info_time_asc_handler (RzCore* core, int argc, const char** argv) {
    LOG_INFO ("[CMD] collection basic info order by TIME in ascending");

    const char* search_term = argc > 1 ? argv[1] && strlen (argv[1]) ? argv[1] : NULL : NULL;
    const char* filters     = argc > 2 ? argv[2] && strlen (argv[2]) ? argv[2] : NULL : NULL;

    CollectionBasicInfoFilterFlags filter_flags = REAI_COLLECTION_BASIC_INFO_FILTER_HIDE_EMPTY;
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
RZ_IPI RzCmdStatus rz_collection_basic_info_owner_asc_handler (RzCore* core, int argc, const char** argv) {
    LOG_INFO ("[CMD] collection basic info order by OWNER in ascending");

    const char* search_term = argc > 1 ? argv[1] && strlen (argv[1]) ? argv[1] : NULL : NULL;
    const char* filters     = argc > 2 ? argv[2] && strlen (argv[2]) ? argv[2] : NULL : NULL;

    CollectionBasicInfoFilterFlags filter_flags = REAI_COLLECTION_BASIC_INFO_FILTER_HIDE_EMPTY;
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
RZ_IPI RzCmdStatus rz_collection_basic_info_name_asc_handler (RzCore* core, int argc, const char** argv) {
    LOG_INFO ("[CMD] collection basic info order by NAME in ascending");

    const char* search_term = argc > 1 ? argv[1] && strlen (argv[1]) ? argv[1] : NULL : NULL;
    const char* filters     = argc > 2 ? argv[2] && strlen (argv[2]) ? argv[2] : NULL : NULL;

    CollectionBasicInfoFilterFlags filter_flags = REAI_COLLECTION_BASIC_INFO_FILTER_HIDE_EMPTY;
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
RZ_IPI RzCmdStatus rz_collection_basic_info_model_asc_handler (RzCore* core, int argc, const char** argv) {
    LOG_INFO ("[CMD] collection basic info order by MODEL in ascending");

    const char* search_term = argc > 1 ? argv[1] && strlen (argv[1]) ? argv[1] : NULL : NULL;
    const char* filters     = argc > 2 ? argv[2] && strlen (argv[2]) ? argv[2] : NULL : NULL;

    CollectionBasicInfoFilterFlags filter_flags = REAI_COLLECTION_BASIC_INFO_FILTER_HIDE_EMPTY;
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
RZ_IPI RzCmdStatus rz_collection_basic_info_size_asc_handler (RzCore* core, int argc, const char** argv) {
    LOG_INFO ("[CMD] collection basic info order by SIZE in ascending");

    const char* search_term = argc > 1 ? argv[1] && strlen (argv[1]) ? argv[1] : NULL : NULL;
    const char* filters     = argc > 2 ? argv[2] && strlen (argv[2]) ? argv[2] : NULL : NULL;

    CollectionBasicInfoFilterFlags filter_flags = REAI_COLLECTION_BASIC_INFO_FILTER_HIDE_EMPTY;
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
RZ_IPI RzCmdStatus rz_collection_basic_info_time_desc_handler (RzCore* core, int argc, const char** argv) {
    LOG_INFO ("[CMD] collection basic info order by TIME in descending");

    const char* search_term = argc > 1 ? argv[1] && strlen (argv[1]) ? argv[1] : NULL : NULL;
    const char* filters     = argc > 2 ? argv[2] && strlen (argv[2]) ? argv[2] : NULL : NULL;

    CollectionBasicInfoFilterFlags filter_flags = REAI_COLLECTION_BASIC_INFO_FILTER_HIDE_EMPTY;
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
RZ_IPI RzCmdStatus rz_collection_basic_info_owner_desc_handler (RzCore* core, int argc, const char** argv) {
    LOG_INFO ("[CMD] collection basic info order by OWNER in descending");

    const char* search_term = argc > 1 ? argv[1] && strlen (argv[1]) ? argv[1] : NULL : NULL;
    const char* filters     = argc > 2 ? argv[2] && strlen (argv[2]) ? argv[2] : NULL : NULL;

    CollectionBasicInfoFilterFlags filter_flags = REAI_COLLECTION_BASIC_INFO_FILTER_HIDE_EMPTY;
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
RZ_IPI RzCmdStatus rz_collection_basic_info_name_desc_handler (RzCore* core, int argc, const char** argv) {
    LOG_INFO ("[CMD] collection basic info order by NAME in descending");

    const char* search_term = argc > 1 ? argv[1] && strlen (argv[1]) ? argv[1] : NULL : NULL;
    const char* filters     = argc > 2 ? argv[2] && strlen (argv[2]) ? argv[2] : NULL : NULL;

    CollectionBasicInfoFilterFlags filter_flags = REAI_COLLECTION_BASIC_INFO_FILTER_HIDE_EMPTY;
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
RZ_IPI RzCmdStatus rz_collection_basic_info_model_desc_handler (RzCore* core, int argc, const char** argv) {
    LOG_INFO ("[CMD] collection basic info order by MODEL in descending");

    const char* search_term = argc > 1 ? argv[1] && strlen (argv[1]) ? argv[1] : NULL : NULL;
    const char* filters     = argc > 2 ? argv[2] && strlen (argv[2]) ? argv[2] : NULL : NULL;

    CollectionBasicInfoFilterFlags filter_flags = REAI_COLLECTION_BASIC_INFO_FILTER_HIDE_EMPTY;
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
RZ_IPI RzCmdStatus rz_collection_basic_info_size_desc_handler (RzCore* core, int argc, const char** argv) {
    LOG_INFO ("[CMD] collection basic info order by SIZE in descending");

    const char* search_term = argc > 1 ? argv[1] && strlen (argv[1]) ? argv[1] : NULL : NULL;
    const char* filters     = argc > 2 ? argv[2] && strlen (argv[2]) ? argv[2] : NULL : NULL;

    CollectionBasicInfoFilterFlags filter_flags = REAI_COLLECTION_BASIC_INFO_FILTER_HIDE_EMPTY;
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
    LOG_INFO ("[CMD] binary search");

    const char* partial_name   = argc > 1 ? argv[1] && strlen (argv[1]) ? argv[1] : NULL : NULL;
    const char* partial_sha256 = argc > 2 ? argv[2] && strlen (argv[2]) ? argv[2] : NULL : NULL;
    const char* model_name     = argc > 3 ? argv[3] && strlen (argv[3]) ? argv[3] : NULL : NULL;
    const char* tags_csv       = argc > 4 ? argv[4] && strlen (argv[4]) ? argv[4] : NULL : NULL;

    if (reai_plugin_binary_search (core, partial_name, partial_sha256, model_name, tags_csv)) {
        return RZ_CMD_STATUS_OK;
    }
    return RZ_CMD_STATUS_ERROR;
}

/**
 * REbsn
 * */
RZ_IPI RzCmdStatus rz_binary_search_by_name_handler (RzCore* core, int argc, const char** argv) {
    LOG_INFO ("[CMD] binary search (by NAME)");

    const char* partial_name = argc > 1 ? argv[1] && strlen (argv[1]) ? argv[1] : NULL : NULL;
    const char* model_name   = argc > 2 ? argv[2] && strlen (argv[2]) ? argv[2] : NULL : NULL;

    if (reai_plugin_binary_search (core, partial_name, NULL, model_name, NULL)) {
        return RZ_CMD_STATUS_OK;
    }
    return RZ_CMD_STATUS_ERROR;
}

/**
 * REbsh
 * */
RZ_IPI RzCmdStatus rz_binary_search_by_sha256_handler (RzCore* core, int argc, const char** argv) {
    LOG_INFO ("[CMD] binary search (by SHA256)");

    const char* partial_sha256 = argc > 1 ? argv[1] && strlen (argv[1]) ? argv[1] : NULL : NULL;
    const char* model_name     = argc > 2 ? argv[2] && strlen (argv[2]) ? argv[2] : NULL : NULL;

    if (reai_plugin_binary_search (core, NULL, partial_sha256, model_name, NULL)) {
        return RZ_CMD_STATUS_OK;
    }
    return RZ_CMD_STATUS_ERROR;
}

/**
 * REco
 * */
RZ_IPI RzCmdStatus rz_collection_link_handler (RzCore* core, int argc, const char** argv) {
    LOG_INFO ("[CMD] collection link open");

    CollectionId cid = argc > 1 ? argv[1] && strlen (argv[1]) ? rz_num_get (core->num, argv[1]) : 0 : 0;

    // generate portal link
    char* host = strdup (reai_plugin()->reai_config->host);
    host       = rz_str_replace (host, "api", "portal", 0 /* replace first only */);
    if (!host) {
        DISPLAY_ERROR ("Failed to generate portal link");
        return RZ_CMD_STATUS_ERROR;
    }

    // TODO: should we also get basic collection information and display it here?
    DISPLAY_INFO ("%s/collections/%llu", host, cid);

    const char* syscmd = NULL;
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
        const char* cmd = rz_str_newf ("%s %s/collections/%llu", syscmd, host, cid);
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
    LOG_INFO ("[CMD] analysis link open");

    BinaryId bid = 0;
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

    const char* syscmd = NULL;
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
        const char* cmd = rz_str_newf (
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
    LOG_INFO ("[CMD] function link open");

    FunctionId fid = argc > 1 ? argv[1] && strlen (argv[1]) ? rz_num_get (core->num, argv[1]) : 0 : 0;

    // generate portal link
    char* host = strdup (reai_plugin()->reai_config->host);
    host       = rz_str_replace (host, "api", "portal", 0 /* replace first only */);
    if (!host) {
        DISPLAY_ERROR ("Failed to generate portal link");
        return RZ_CMD_STATUS_ERROR;
    }

    // TODO: should we also get basic function information and display it here?
    DISPLAY_INFO ("%s/functions/%llu", host, fid);

    const char* syscmd = NULL;
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
        const char* cmd = rz_str_newf ("%s %s/function/%llu", syscmd, host, fid);
        rz_sys_system (cmd);
        FREE (cmd);
    }


    FREE (host);

    return RZ_CMD_STATUS_OK;
}

/**
 * REal
 * */
RZ_IPI RzCmdStatus rz_get_analysis_logs_using_analysis_id_handler (RzCore* core, int argc, const char** argv) {
    LOG_INFO ("[CMD] Get Analysis Logs");

    AnalysisId id             = 0;
    bool       is_analysis_id = true;
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
RZ_IPI RzCmdStatus rz_get_analysis_logs_using_binary_id_handler (RzCore* core, int argc, const char** argv) {
    LOG_INFO ("[CMD] get binary analysis logs");

    AnalysisId binary_id = 0;
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
    LOG_INFO ("[CMD] recent analysis");
    UNUSED (core && argc && argv);

    AnalysisInfoVec* results = reai_get_recent_analyses (
        reai(),
        reai_response(),
        NULL /* search term */,
        REAI_WORKSPACE_PERSONAL,
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

    PluginTable* t = reai_plugin_table_create();
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
