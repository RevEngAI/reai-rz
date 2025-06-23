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
#include <Reai/Diff.h>

#define ZSTR_ARG(vn, idx) (argc > (idx) ? (((vn) = argv[idx]), true) : false)
#define STR_ARG(vn, idx)  (argc > (idx) ? (((vn) = StrInitFromZstr (argv[idx])), true) : false)
#define NUM_ARG(vn, idx)  (argc > (idx) ? (((vn) = rz_num_get (core->num, argv[idx])), true) : false)

RZ_IPI RzCmdStatus rz_plugin_initialize_handler (RzCore* core, int argc, const char** argv) {
    (void)core;

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
    (void)core;
    (void)argc;
    (void)argv;

    ModelInfos* models = GetModels();
    VecForeach (models, model, { rz_cons_println (model.name.data); });

    return RZ_CMD_STATUS_OK;
}

/**
 * "REh"
 *
 * @b Perform an auth-check api call to check connection.
 * */
RZ_IPI RzCmdStatus rz_health_check_handler (RzCore* core, int argc, const char** argv) {
    (void)core;
    (void)argc;
    (void)argv;

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
            new_analysis.base_addr = rzGetCurrentBinaryBaseAddr (core);
            new_analysis.functions = VecInitWithDeepCopy_T (&new_analysis.functions, NULL, FunctionInfoDeinit);

            RzListIter*         fn_iter = NULL;
            RzAnalysisFunction* fn      = NULL;
            rz_list_foreach (core->analysis->fcns, fn_iter, fn) {
                FunctionInfo fi       = {0};
                fi.symbol.is_addr     = true;
                fi.symbol.is_external = false;
                fi.symbol.value.addr  = fn->addr;
                fi.symbol.name        = StrInitFromZstr (fn->name);
                fi.size               = rz_analysis_function_size_from_entry (fn);
                VecPushBack (&new_analysis.functions, fi);
            }
            bin_id = CreateNewAnalysis (GetConnection(), &new_analysis);
            SetBinaryId (bin_id);
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

    rzAutoRenameFunctions (core, result_count, min_similarity, restruct_to_debug);

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
    (void)core;
    (void)argc;
    (void)argv;

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
    } else {
        DISPLAY_ERROR (
            "Current session has no completed analysis attached to it.\n"
            "Please create a new analysis and wait for it's completion or\n"
            "       apply an existing analysis that is already complete."
        );
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

    if (ZSTR_ARG (function_name, 1) && NUM_ARG (min_similarity, 2) && NUM_ARG (search.limit, 3)) {
        STR_ARG (collection_ids_csv, 4);
        STR_ARG (binary_ids_csv, 5);


        search.distance = 1. - (CLAMP (min_similarity, 1, 100) / 100.);
        LOG_INFO ("Requested similarity = %f %%", 100 - search.distance * 100);

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
                        (1. - fn->distance) * 100.
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

        if (!fn_id) {
            DISPLAY_ERROR (
                "A function with that name does not exist in current Rizin session.\n"
                "Please provide a name from output of `afl` command."
            );
            return RZ_CMD_STATUS_ERROR;
        }

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
                    Str*            smry  = &aidec.ai_summary;
                    Str*            dec   = &aidec.raw_decompilation;

                    Str code = StrInit();

                    static i32 SOFT_LIMIT = 120;

                    i32   l = smry->length;
                    char* p = smry->data;
                    while (l > SOFT_LIMIT) {
                        char* p1 = strchr (p + SOFT_LIMIT, ' ');
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

                    LOG_INFO ("aidec.functions.length = %zu", aidec.functions.length);
                    VecForeachIdx (&aidec.functions, function, idx, {
                        Str dname = StrInit();
                        StrPrintf (&dname, "<DISASM_FUNCTION_%llu>", idx);
                        StrReplace (&code, &dname, &function.name, -1);
                        StrDeinit (&dname);
                    });

                    LOG_INFO ("aidec.strings.length = %zu", aidec.strings.length);
                    VecForeachIdx (&aidec.strings, string, idx, {
                        Str dname = StrInit();
                        StrPrintf (&dname, "<DISASM_STRING_%llu>", idx);
                        StrReplace (&code, &dname, &string.string, -1);
                        StrDeinit (&dname);
                    });

                    LOG_INFO ("aidec.unmatched.functions.length = %zu", aidec.unmatched.functions.length);
                    VecForeachIdx (&aidec.unmatched.functions, function, idx, {
                        Str dname = StrInit();
                        StrPrintf (&dname, "<UNMATCHED_FUNCTION_%llu>", idx);
                        StrReplace (&code, &dname, &function.name, -1);
                        StrDeinit (&dname);
                    });

                    LOG_INFO ("aidec.unmatched.strings.length = %zu", aidec.unmatched.strings.length);
                    VecForeachIdx (&aidec.unmatched.strings, string, idx, {
                        Str dname = StrInit();
                        StrPrintf (&dname, "<UNMATCHED_STRING_%llu>", idx);
                        StrReplace (&code, &dname, &string.value.str, -1);
                        StrDeinit (&dname);
                    });

                    LOG_INFO ("aidec.unmatched.vars.length = %zu", aidec.unmatched.vars.length);
                    VecForeachIdx (&aidec.unmatched.vars, var, idx, {
                        Str dname = StrInit();
                        StrPrintf (&dname, "<VAR_%llu>", idx);
                        StrReplace (&code, &dname, &var.value.str, -1);
                        StrDeinit (&dname);
                    });

                    LOG_INFO ("aidec.unmatched.external_vars.length = %zu", aidec.unmatched.external_vars.length);
                    VecForeachIdx (&aidec.unmatched.external_vars, var, idx, {
                        Str dname = StrInit();
                        StrPrintf (&dname, "<EXTERNAL_VARIABLE_%llu>", idx);
                        StrReplace (&code, &dname, &var.value.str, -1);
                        StrDeinit (&dname);
                    });

                    LOG_INFO ("aidec.unmatched.custom_types.length = %zu", aidec.unmatched.custom_types.length);
                    VecForeachIdx (&aidec.unmatched.custom_types, var, idx, {
                        Str dname = StrInit();
                        StrPrintf (&dname, "<CUSTOM_TYPE_%llu>", idx);
                        StrReplace (&code, &dname, &var.value.str, -1);
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

RzCmdStatus collectionSearch (SearchCollectionRequest* search) {
    CollectionInfos collections = SearchCollection (GetConnection(), search);
    SearchCollectionRequestDeinit (search);

    if (collections.length) {
        RzTable* t = rz_table_new();
        rz_table_set_columnsf (t, "snnssss", "Name", "Size", "Id", "Scope", "Last Updated", "Model", "Owner");

        VecForeachPtr (&collections, collection, {
            rz_table_add_rowf (
                t,
                "snnssss",
                collection->name.data,
                collection->size,
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
    (void)core;

    SearchCollectionRequest search = SearchCollectionRequestInit();

    Str tags = StrInit();

    STR_ARG (search.partial_collection_name, 1);
    STR_ARG (search.partial_binary_name, 2);
    STR_ARG (search.partial_binary_sha256, 3);
    STR_ARG (search.model_name, 4);
    STR_ARG (tags, 5);

    search.tags = StrSplit (&tags, ",");
    StrDeinit (&tags);

    return collectionSearch (&search);
}

RZ_IPI RzCmdStatus rz_collection_search_by_binary_name_handler (RzCore* core, int argc, const char** argv) {
    (void)core;

    SearchCollectionRequest search = SearchCollectionRequestInit();

    STR_ARG (search.partial_binary_name, 1);
    STR_ARG (search.model_name, 2);

    return collectionSearch (&search);
}

RZ_IPI RzCmdStatus rz_collection_search_by_collection_name_handler (RzCore* core, int argc, const char** argv) {
    (void)core;

    SearchCollectionRequest search = SearchCollectionRequestInit();

    STR_ARG (search.partial_collection_name, 1);
    STR_ARG (search.model_name, 2);

    return collectionSearch (&search);
}

RZ_IPI RzCmdStatus rz_collection_search_by_hash_value_handler (RzCore* core, int argc, const char** argv) {
    (void)core;

    SearchCollectionRequest search = SearchCollectionRequestInit();

    STR_ARG (search.partial_binary_sha256, 1);
    STR_ARG (search.model_name, 2);

    return collectionSearch (&search);
}

RzCmdStatus collectionFilteredSearch (Str term, Str filters, OrderBy order_by, bool is_asc) {
    SearchCollectionRequest search = SearchCollectionRequestInit();

    search.partial_collection_name = term;

    if (filters.data) {
        search.filter_public   = !!strchr (filters.data, 'p');
        search.filter_official = !!strchr (filters.data, 'o');
        search.filter_user     = !!strchr (filters.data, 'u');
        search.filter_team     = !!strchr (filters.data, 't');
        StrDeinit (&filters);
    }

    search.order_by     = order_by;
    search.order_in_asc = is_asc;

    return collectionSearch (&search);
}

/**
 * REcat
 * */
RZ_IPI RzCmdStatus rz_collection_basic_info_time_asc_handler (RzCore* core, int argc, const char** argv) {
    (void)core;

    Str term = StrInit(), filters = StrInit();
    STR_ARG (term, 1);
    STR_ARG (filters, 2);
    return collectionFilteredSearch (term, filters, ORDER_BY_LAST_UPDATED, true);
}

/**
 * REcao
 * */
RZ_IPI RzCmdStatus rz_collection_basic_info_owner_asc_handler (RzCore* core, int argc, const char** argv) {
    (void)core;

    Str term = StrInit(), filters = StrInit();
    STR_ARG (term, 1);
    STR_ARG (filters, 2);
    return collectionFilteredSearch (term, filters, ORDER_BY_OWNER, true);
}

/**
 * REcan
 * */
RZ_IPI RzCmdStatus rz_collection_basic_info_name_asc_handler (RzCore* core, int argc, const char** argv) {
    (void)core;

    Str term = StrInit(), filters = StrInit();
    STR_ARG (term, 1);
    STR_ARG (filters, 2);
    return collectionFilteredSearch (term, filters, ORDER_BY_NAME, true);
}

/**
 * REcam
 * */
RZ_IPI RzCmdStatus rz_collection_basic_info_model_asc_handler (RzCore* core, int argc, const char** argv) {
    (void)core;

    Str term = StrInit(), filters = StrInit();
    STR_ARG (term, 1);
    STR_ARG (filters, 2);
    return collectionFilteredSearch (term, filters, ORDER_BY_MODEL, true);
}

/**
 * REcas
 * */
RZ_IPI RzCmdStatus rz_collection_basic_info_size_asc_handler (RzCore* core, int argc, const char** argv) {
    (void)core;

    Str term = StrInit(), filters = StrInit();
    STR_ARG (term, 1);
    STR_ARG (filters, 2);
    return collectionFilteredSearch (term, filters, ORDER_BY_SIZE, true);
}

/**
 * REcdt
 * */
RZ_IPI RzCmdStatus rz_collection_basic_info_time_desc_handler (RzCore* core, int argc, const char** argv) {
    (void)core;

    Str term = StrInit(), filters = StrInit();
    STR_ARG (term, 1);
    STR_ARG (filters, 2);
    return collectionFilteredSearch (term, filters, ORDER_BY_LAST_UPDATED, false);
}

/**
 * REcdo
 * */
RZ_IPI RzCmdStatus rz_collection_basic_info_owner_desc_handler (RzCore* core, int argc, const char** argv) {
    (void)core;

    Str term = StrInit(), filters = StrInit();
    STR_ARG (term, 1);
    STR_ARG (filters, 2);
    return collectionFilteredSearch (term, filters, ORDER_BY_OWNER, false);
}

/**
 * REcdn
 * */
RZ_IPI RzCmdStatus rz_collection_basic_info_name_desc_handler (RzCore* core, int argc, const char** argv) {
    (void)core;

    Str term = StrInit(), filters = StrInit();
    STR_ARG (term, 1);
    STR_ARG (filters, 2);
    return collectionFilteredSearch (term, filters, ORDER_BY_NAME, false);
}

/**
 * REcdm
 * */
RZ_IPI RzCmdStatus rz_collection_basic_info_model_desc_handler (RzCore* core, int argc, const char** argv) {
    (void)core;

    Str term = StrInit(), filters = StrInit();
    STR_ARG (term, 1);
    STR_ARG (filters, 2);
    return collectionFilteredSearch (term, filters, ORDER_BY_MODEL, false);
}

/**
 * REcds
 * */
RZ_IPI RzCmdStatus rz_collection_basic_info_size_desc_handler (RzCore* core, int argc, const char** argv) {
    (void)core;

    Str term = StrInit(), filters = StrInit();
    STR_ARG (term, 1);
    STR_ARG (filters, 2);
    return collectionFilteredSearch (term, filters, ORDER_BY_SIZE, false);
}

RzCmdStatus searchBinary (SearchBinaryRequest* search) {
    BinaryInfos binaries = SearchBinary (GetConnection(), search);
    SearchBinaryRequestDeinit (search);

    RzTable* t = rz_table_new();
    rz_table_set_columnsf (t, "snnssss", "name", "binary_id", "analysis_id", "model", "owner", "created_at", "sha256");

    VecForeachPtr (&binaries, binary, {
        rz_table_add_rowf (
            t,
            "snnssss",
            binary->binary_name.data,
            binary->binary_id,
            binary->analysis_id,
            binary->model_name.data,
            binary->owned_by.data,
            binary->created_at.data,
            binary->sha256.data
        );
    });

    const char* s = rz_table_tofancystring (t);
    rz_cons_println (s);
    FREE (s);
    rz_table_free (t);

    VecDeinit (&binaries);

    return RZ_CMD_STATUS_OK;
}

/**
 * REbs
 * */
RZ_IPI RzCmdStatus rz_binary_search_handler (RzCore* core, int argc, const char** argv) {
    (void)core;

    Str tags = StrInit();

    SearchBinaryRequest search = SearchBinaryRequestInit();
    STR_ARG (search.partial_name, 1);
    STR_ARG (search.partial_sha256, 2);
    STR_ARG (search.model_name, 3);
    STR_ARG (tags, 4);

    search.tags = StrSplit (&tags, ",");

    return searchBinary (&search);
}

/**
 * REbsn
 * */
RZ_IPI RzCmdStatus rz_binary_search_by_name_handler (RzCore* core, int argc, const char** argv) {
    (void)core;

    SearchBinaryRequest search = SearchBinaryRequestInit();
    STR_ARG (search.partial_name, 1);
    STR_ARG (search.model_name, 3);
    return searchBinary (&search);
}

/**
 * REbsh
 * */
RZ_IPI RzCmdStatus rz_binary_search_by_sha256_handler (RzCore* core, int argc, const char** argv) {
    (void)core;

    SearchBinaryRequest search = SearchBinaryRequestInit();
    STR_ARG (search.partial_sha256, 1);
    STR_ARG (search.model_name, 3);
    return searchBinary (&search);
}

RzCmdStatus openLinkForId (const char* type, u64 id) {
    Connection* conn = GetConnection();

    Str host = StrDup (&conn->host);
    StrReplaceZstr (&host, "api", "portal", 1);
    StrAppendf (&host, "/%s/%llu", type, id);

    rz_cons_println (host.data);

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
        Str cmd = StrInit();
        StrPrintf (&cmd, "%s %s", syscmd, host.data);
        rz_sys_system (cmd.data);
        StrDeinit (&cmd);
    }

    StrDeinit (&host);

    return RZ_CMD_STATUS_OK;
}

/**
 * REco
 * */
RZ_IPI RzCmdStatus rz_collection_link_handler (RzCore* core, int argc, const char** argv) {
    CollectionId cid = 0;
    NUM_ARG (cid, 1);

    if (!cid) {
        DISPLAY_ERROR ("Invalid collection ID provided.");
        return RZ_CMD_STATUS_WRONG_ARGS;
    }

    return openLinkForId ("collection", cid);
}

/**
 * REao
 * */
RZ_IPI RzCmdStatus rz_analysis_link_handler (RzCore* core, int argc, const char** argv) {
    BinaryId bid = 0;
    NUM_ARG (bid, 1);

    if (!bid) {
        bid = GetBinaryId();
        if (!bid) {
            DISPLAY_ERROR (
                "No existing analysis attached to current session, and no binary id provided.\n"
                "Please create a new analysis or apply an existing one, or provide a valid binary id"
            );
            return RZ_CMD_STATUS_WRONG_ARGS;
        }
    }

    return openLinkForId ("analyses", bid);
}

/**
 * REfo
 * */
RZ_IPI RzCmdStatus rz_function_link_handler (RzCore* core, int argc, const char** argv) {
    FunctionId fid = 0;
    NUM_ARG (fid, 1);

    if (!fid) {
        DISPLAY_ERROR ("Invalid function ID provided.");
        return RZ_CMD_STATUS_WRONG_ARGS;
    }

    return openLinkForId ("collection", fid);
}

/**
 * REal
 * */
RZ_IPI RzCmdStatus rz_get_analysis_logs_using_analysis_id_handler (RzCore* core, int argc, const char** argv) {
    AnalysisId analysis_id = 0;
    NUM_ARG (analysis_id, 1);

    if (!analysis_id) {
        if (!GetBinaryId()) {
            DISPLAY_ERROR (
                "No RevEngAI analysis attached with current session.\n"
                "Either provide an analysis id, apply an existing analysis or create a new analysis\n"
            );
            return RZ_CMD_STATUS_WRONG_ARGS;
        }

        analysis_id = AnalysisIdFromBinaryId (GetConnection(), GetBinaryId());
        if (!analysis_id) {
            DISPLAY_ERROR ("Failed to get analysis id from binary id attached to this session");
            return RZ_CMD_STATUS_ERROR;
        }
    }

    Str logs = GetAnalysisLogs (GetConnection(), analysis_id);
    if (logs.length) {
        rz_cons_println (logs.data);
    } else {
        DISPLAY_ERROR ("Failed to get analysis logs.");
        return RZ_CMD_STATUS_ERROR;
    }
    StrDeinit (&logs);

    return RZ_CMD_STATUS_OK;
}

/**
 * REalb
 * */
RZ_IPI RzCmdStatus rz_get_analysis_logs_using_binary_id_handler (RzCore* core, int argc, const char** argv) {
    AnalysisId binary_id = 0;
    NUM_ARG (binary_id, 1);

    if (!binary_id && !GetBinaryId()) {
        DISPLAY_ERROR (
            "No RevEngAI analysis attached with current session.\n"
            "Either provide an analysis id, apply an existing analysis or create a new analysis\n"
        );
        return RZ_CMD_STATUS_WRONG_ARGS;
    }

    AnalysisId analysis_id = AnalysisIdFromBinaryId (GetConnection(), GetBinaryId());
    if (!analysis_id) {
        DISPLAY_ERROR ("Failed to get analysis id from binary id");
        return RZ_CMD_STATUS_ERROR;
    }

    Str logs = GetAnalysisLogs (GetConnection(), analysis_id);
    if (logs.length) {
        rz_cons_println (logs.data);
    } else {
        DISPLAY_ERROR ("Failed to get analysis logs.");
        return RZ_CMD_STATUS_ERROR;
    }
    StrDeinit (&logs);

    return RZ_CMD_STATUS_OK;
}

/**
 * "REar"
 * */
RZ_IPI RzCmdStatus rz_get_recent_analyses_handler (RzCore* core, int argc, const char** argv) {
    (void)core;
    (void)argc;
    (void)argv;

    RecentAnalysisRequest recents  = RecentAnalysisRequestInit();
    AnalysisInfos         analyses = GetRecentAnalysis (GetConnection(), &recents);
    RecentAnalysisRequestDeinit (&recents);

    if (!analyses.length) {
        DISPLAY_ERROR ("Failed to get most recent analysis. Are you a new user?");
        return RZ_CMD_STATUS_ERROR;
    }

    RzTable* t = rz_table_new();
    rz_table_set_columnsf (t, "nnssss", "analysis_id", "binary_id", "status", "creation", "binary_name", "scope");

    VecForeachPtr (&analyses, analysis, {
        Str status_str = StrInit();
        StatusToStr (analysis->status, &status_str);
        rz_table_add_rowf (
            t,
            "nnssss",
            analysis->analysis_id,
            analysis->binary_id,
            status_str.data,
            analysis->creation.data,
            analysis->binary_name.data,
            analysis->is_private ? "PRIVATE" : "PUBLIC"
        );
        StrDeinit (&status_str);
    });

    const char* s = rz_table_tofancystring (t);
    rz_cons_println (s);
    FREE (s);
    rz_table_free (t);

    return RZ_CMD_STATUS_OK;
}

static inline void rz_cons_canvas_write_at (RzConsCanvas* c, const char* text, int x, int y) {
    int _x = c->x;
    int _y = c->y;
    
    rz_cons_canvas_gotoxy (c, x, y);
    rz_cons_canvas_write (c, text);
    rz_cons_canvas_gotoxy (c, _x, _y);
}

int sep = 2;

// Height reserved for help area at the bottom
#define HELP_AREA_HEIGHT 3

/**
 * Wrap text to fit within specified width, returning wrapped lines
 * @param text: Source text to wrap
 * @param width: Maximum width per line
 * @param max_lines: Maximum number of lines to generate
 * @return: Strs containing wrapped lines (caller must deinit)
 */
Strs wrapText (const char* text, int width, int max_lines) {
    Strs wrapped_lines = VecInit();

    // Validate arguments
    if (!text || width <= 0 || max_lines <= 0) {
        LOG_FATAL ("Text wrapping failed: invalid text pointer or dimensions");
    }

    // Create a Str object from the input text and strip whitespace
    Str input_str    = StrInitFromZstr (text);
    Str stripped_str = StrStrip (&input_str, NULL);

    int text_len = stripped_str.length;
    int pos      = 0;

    // Handle empty text - use space instead of empty string to avoid StrPrintf issues
    if (text_len == 0) {
        Str empty_line = StrInit();
        StrPrintf (&empty_line, " ");
        VecPushBack (&wrapped_lines, empty_line);
        StrDeinit (&input_str);
        StrDeinit (&stripped_str);
        return wrapped_lines;
    }

    while (pos < text_len && (int)wrapped_lines.length < max_lines) {
        int remaining = text_len - pos;
        int line_len  = MIN2 (remaining, width);

        // Validate line length
        if (line_len <= 0) {
            LOG_FATAL ("Text wrapping failed: calculated line length is invalid");
        }

        // If we're not at the end and would cut in middle of word, try to break at space
        if (line_len < remaining && line_len > 0) {
            int break_pos = line_len;
            // Look backwards for a space to break on
            while (break_pos > 0 && pos + break_pos < text_len &&
                   stripped_str.data[pos + break_pos] != ' ' &&
                   stripped_str.data[pos + break_pos] != '\t') {
                break_pos--;
            }
            // If we found a good break point and it's not too close to start, use it
            if (break_pos > width / 3) {
                line_len = break_pos;
            }
        }

        // Validate bounds
        if (pos + line_len > text_len) {
            LOG_FATAL ("Text wrapping failed: calculated position exceeds text boundaries");
        }

        // Push a new wrapped line with content
        Str wrapped_line = StrInit();
        StrPrintf (&wrapped_line, "%.*s", line_len, stripped_str.data + pos);
        VecPushBack (&wrapped_lines, wrapped_line);

        pos += line_len;
        // Skip whitespace at start of next line
        while (pos < text_len &&
               (stripped_str.data[pos] == ' ' || stripped_str.data[pos] == '\t')) {
            pos++;
        }
    }

    // Clean up the temporary strings
    StrDeinit (&input_str);
    StrDeinit (&stripped_str);

    return wrapped_lines;
}

// Structure to hold list items and their corresponding target strings
typedef struct {
    Str name;           // Display name in the list
    Str target_content; // Corresponding target string for diff
} DiffListItem;

typedef Vec (DiffListItem) DiffListItems;

bool drawInteractiveList (RzConsCanvas* c, const char* header, int w, int h, DiffListItems* items, int selected_idx) {
    int x          = sep / 2;
    int y          = sep / 2;
    int list_width = (w * 2) / 8 - sep;          // Take 2/8 of screen width for list
    h              = h - sep - HELP_AREA_HEIGHT; // Reserve space for help area at bottom

    if (list_width <= 0 || h <= 0) {
        return false;
    }

    // Calculate header text positions with boundary checks
    const char* header_text = header;
    int         header_len  = strlen (header_text);
    int         header_x    = x + 2;

    // Ensure header fits within box
    if (header_x + header_len > x + list_width - 1) {
        header_x   = x + 1;
        header_len = MIN2 (header_len, list_width - 3);
    }

    // Write header text first (truncated if necessary)
    rz_cons_canvas_write_at (c, header_text, header_x, y + 1);

    // Show selection counter with boundary check
    char selection_info[64];
    snprintf (
        selection_info,
        sizeof (selection_info),
        "(%d/%d)",
        selected_idx + 1,
        (int)items->length
    );
    int counter_len = strlen (selection_info);
    int counter_x   = x + list_width - counter_len - 2;

    // Ensure counter doesn't overlap with header
    if (counter_x <= header_x + header_len + 1) {
        counter_x = header_x + header_len + 1;
    }

    // Ensure counter fits within box
    if (counter_x + counter_len > x + list_width - 1) {
        counter_x = x + list_width - counter_len - 1;
    }

    rz_cons_canvas_write_at (c, selection_info, counter_x, y + 1);

    int line_y        = y + 3;
    int max_lines     = h - 5;
    int content_width = list_width - 4;

    if (content_width <= 0 || max_lines <= 0) {
        return false;
    }

    int current_display_line = 0;
    VecForeachIdx (items, item, idx, {
        if (current_display_line >= max_lines)
            break;

        // Wrap the item name if it's too long
        int wrap_width = content_width - 2; // Account for selection indicator

        // Validate UI parameters
        if (wrap_width <= 0 || !item.name.data) {
            LOG_FATAL ("UI rendering failed: invalid display width or null item name");
        }

        Strs wrapped_lines =
            wrapText (item.name.data, wrap_width, max_lines - current_display_line);

        VecForeachIdx (&wrapped_lines, wrapped_line, i, {
            if (current_display_line >= max_lines)
                break;

            Str line_str = StrInit();

            // Validate wrapped content
            if (!wrapped_line.data) {
                LOG_FATAL ("UI rendering failed: wrapped line content is null");
            }

            // Check for empty content and use space instead to avoid StrPrintf issues
            const char* line_content = wrapped_line.data;
            if (wrapped_line.length == 0) {
                line_content = " ";
            }

            // Show selection indicator only on first line of wrapped text
            if ((int)idx == selected_idx && i == 0) {
                StrPrintf (&line_str, "> %s", line_content);
            } else if ((int)idx == selected_idx) {
                StrPrintf (&line_str, "  %s", line_content); // Indent continuation
            } else if (i == 0) {
                StrPrintf (&line_str, "  %s", line_content);
            } else {
                StrPrintf (&line_str, "  %s", line_content); // Indent continuation
            }

            // Ensure the line doesn't exceed box boundaries
            int line_len = line_str.length;
            if (line_len > content_width) {
                // Truncate the line to fit within box
                line_str.data[content_width - 1] = '\0';
                line_str.length                  = content_width - 1;
            }

            rz_cons_canvas_write_at (c, line_str.data, x + 1, line_y + current_display_line);
            StrDeinit (&line_str);
            current_display_line++;
        });

        // Clean up wrapped lines
        VecDeinit (&wrapped_lines);
    });

    // Draw the box after all text content is written
    rz_cons_canvas_box (c, x, y, list_width, h, Color_RESET);

    return true;
}

bool drawInteractiveSourceDiff (
    RzConsCanvas* c,
    const char*   header,
    int          w,
    int          h,
    DiffLines*   diff,
    bool         show_line_numbers
) {
    int x          = (w * 2) / 8 + sep / 2;      // Start after the list panel (2/8)
    int y          = sep / 2;
    int diff_width = (w * 3) / 8 - sep;          // Take 3/8 of screen width for source diff
    h              = h - sep - HELP_AREA_HEIGHT; // Reserve space for help area at bottom

    if (diff_width <= 0 || h <= 0) {
        return false;
    }

    // Write header text first with boundary check
    const char* header_text = header;
    int         header_len  = strlen (header_text);
    int         header_x    = x + 2;

    // Ensure header fits within box
    if (header_x + header_len > x + diff_width - 1) {
        header_x = x + 1;
    }

    rz_cons_canvas_write_at (c, header_text, header_x, y + 1);

    int line_y        = y + 3;
    int max_lines     = h - 5;
    int current_line  = 0;
    int content_width = diff_width - 8;

    if (content_width <= 0 || max_lines <= 0) {
        return false;
    }

    VecForeachPtr (diff, diff_line, {
        if (current_line >= max_lines)
            break;

        const char* content_text = NULL;
        u64         line_number  = 0;
        bool        has_content  = true;

        switch (diff_line->type) {
            case DIFF_TYPE_SAM :
                content_text = diff_line->sam.content.data;
                line_number  = diff_line->sam.line + 1;
                break;
            case DIFF_TYPE_REM :
                content_text = diff_line->rem.content.data;
                line_number  = diff_line->rem.line + 1;
                break;
            case DIFF_TYPE_MOD :
                content_text = diff_line->mod.old_content.data;
                line_number  = diff_line->mod.old_line + 1;
                break;
            case DIFF_TYPE_MOV :
                content_text = diff_line->mov.old_content.data;
                line_number  = diff_line->mov.old_line + 1;
                break;
            case DIFF_TYPE_ADD :
                has_content = false;
                break;
            default :
                continue;
        }

        if (!has_content) {
            // Empty line for ADD type - use space to avoid empty string issues
            Str line_str = StrInit();
            if (show_line_numbers) {
                StrPrintf (&line_str, "    ");
            } else {
                StrPrintf (&line_str, " ");
            }
            rz_cons_canvas_write_at (c, line_str.data, x + 1, line_y + current_line);
            StrDeinit (&line_str);
            current_line++;
        } else {
            // content_text should never be NULL here - indicates programming bug
            if (!content_text) {
                LOG_FATAL ("content_text is NULL in source diff rendering - programming bug");
            }

            // Wrap the content text
            int wrap_width =
                show_line_numbers ? content_width - 4 : content_width; // Account for line numbers

            // Validate UI parameters
            if (wrap_width <= 0) {
                LOG_FATAL ("UI rendering failed: insufficient width for text wrapping");
            }

            Strs wrapped_lines = wrapText (content_text, wrap_width, max_lines - current_line);

            VecForeachIdx (&wrapped_lines, wrapped_line, i, {
                if (current_line >= max_lines)
                    break;

                Str line_str = StrInit();

                // Validate wrapped content
                if (!wrapped_line.data) {
                    LOG_FATAL ("UI rendering failed: wrapped line content is null");
                }

                // Check for empty content and use space instead to avoid StrPrintf issues
                const char* line_content = wrapped_line.data;
                if (wrapped_line.length == 0) {
                    line_content = " ";
                }

                if (show_line_numbers && i == 0) {
                    // Show line number only on first wrapped line
                    StrPrintf (
                        &line_str,
                        "%3llu %s",
                        (unsigned long long)line_number,
                        line_content
                    );
                } else if (show_line_numbers) {
                    // Indent continuation lines
                    StrPrintf (&line_str, "    %s", line_content);
                } else {
                    StrPrintf (&line_str, "%s", line_content);
                }

                // Ensure the line doesn't exceed box boundaries
                int line_len = line_str.length;
                if (line_len > content_width) {
                    // Truncate the line to fit within box
                    line_str.data[content_width - 1] = '\0';
                    line_str.length                  = content_width - 1;
                }

                rz_cons_canvas_write_at (c, line_str.data, x + 1, line_y + current_line);
                StrDeinit (&line_str);
                current_line++;
            });

            // Clean up wrapped lines
            VecDeinit (&wrapped_lines);
        }
    });

    // Draw the box after all text content is written
    rz_cons_canvas_box (c, x, y, diff_width, h, Color_RESET);

    return true;
}

bool drawInteractiveTargetDiff (
    RzConsCanvas* c,
    const char*   header,
    int          w,
    int          h,
    DiffLines*   diff,
    bool         show_line_numbers
) {
    int x          = (w * 5) / 8 + sep / 2;      // Start after the source panel (2/8 + 3/8 = 5/8)
    int y          = sep / 2;
    int diff_width = (w * 3) / 8 - sep;          // Take 3/8 of screen width for target diff
    h              = h - sep - HELP_AREA_HEIGHT; // Reserve space for help area at bottom

    if (diff_width <= 0 || h <= 0) {
        return false;
    }

    // Write header text first with boundary check
    const char* header_text = header;
    int         header_len  = strlen (header_text);
    int         header_x    = x + 2;

    // Ensure header fits within box
    if (header_x + header_len > x + diff_width - 1) {
        header_x = x + 1;
    }

    rz_cons_canvas_write_at (c, header_text, header_x, y + 1);

    int line_y        = y + 3;
    int max_lines     = h - 5;
    int current_line  = 0;
    int content_width = diff_width - 8;

    if (content_width <= 0 || max_lines <= 0) {
        return false;
    }

    VecForeachPtr (diff, diff_line, {
        if (current_line >= max_lines)
            break;

        const char* content_text = NULL;
        u64         line_number  = 0;
        bool        has_content  = true;

        switch (diff_line->type) {
            case DIFF_TYPE_SAM :
                content_text = diff_line->sam.content.data;
                line_number  = diff_line->sam.line + 1;
                break;
            case DIFF_TYPE_ADD :
                content_text = diff_line->add.content.data;
                line_number  = diff_line->add.line + 1;
                break;
            case DIFF_TYPE_MOD :
                content_text = diff_line->mod.new_content.data;
                line_number  = diff_line->mod.new_line + 1;
                break;
            case DIFF_TYPE_MOV :
                content_text = diff_line->mov.new_content.data;
                line_number  = diff_line->mov.new_line + 1;
                break;
            case DIFF_TYPE_REM :
                has_content = false;
                break;
            default :
                continue;
        }

        if (!has_content) {
            // Empty line for REM type - use space to avoid empty string issues
            Str line_str = StrInit();
            if (show_line_numbers) {
                StrPrintf (&line_str, "    ");
            } else {
                StrPrintf (&line_str, " ");
            }
            rz_cons_canvas_write_at (c, line_str.data, x + 1, line_y + current_line);
            StrDeinit (&line_str);
            current_line++;
        } else {
            // content_text should never be NULL here - indicates programming bug
            if (!content_text) {
                LOG_FATAL ("content_text is NULL in target diff rendering - programming bug");
            }

            // Wrap the content text
            int wrap_width =
                show_line_numbers ? content_width - 4 : content_width; // Account for line numbers

            // Validate UI parameters
            if (wrap_width <= 0) {
                LOG_FATAL ("UI rendering failed: insufficient width for text wrapping");
            }

            Strs wrapped_lines = wrapText (content_text, wrap_width, max_lines - current_line);

            VecForeachIdx (&wrapped_lines, wrapped_line, i, {
                if (current_line >= max_lines)
                    break;

                Str line_str = StrInit();

                // Validate wrapped content
                if (!wrapped_line.data) {
                    LOG_FATAL ("UI rendering failed: wrapped line content is null");
                }

                // Check for empty content and use space instead to avoid StrPrintf issues
                const char* line_content = wrapped_line.data;
                if (wrapped_line.length == 0) {
                    line_content = " ";
                }

                if (show_line_numbers && i == 0) {
                    // Show line number only on first wrapped line
                    StrPrintf (
                        &line_str,
                        "%3llu %s",
                        (unsigned long long)line_number,
                        line_content
                    );
                } else if (show_line_numbers) {
                    // Indent continuation lines
                    StrPrintf (&line_str, "    %s", line_content);
                } else {
                    StrPrintf (&line_str, "%s", line_content);
                }

                // Ensure the line doesn't exceed box boundaries
                int line_len = line_str.length;
                if (line_len > content_width) {
                    // Truncate the line to fit within box
                    line_str.data[content_width - 1] = '\0';
                    line_str.length                  = content_width - 1;
                }

                rz_cons_canvas_write_at (c, line_str.data, x + 1, line_y + current_line);
                StrDeinit (&line_str);
                current_line++;
            });

            // Clean up wrapped lines
            VecDeinit (&wrapped_lines);
        }
    });

    // Draw the box after all text content is written
    rz_cons_canvas_box (c, x, y, diff_width, h, Color_RESET);

    return true;
}

bool drawHelpArea (RzConsCanvas* c, int w, int h) {
    int help_y = h - HELP_AREA_HEIGHT;

    if (help_y < 0) {
        return false;
    }

    // Draw help area background (full width)
    for (int i = 0; i < HELP_AREA_HEIGHT; i++) {
        for (int j = 0; j < w; j++) {
            rz_cons_canvas_write_at (c, " ", j, help_y + i);
        }
    }

    // Write help text
    rz_cons_canvas_write_at (
        c,
        "k=Up j=Down q=Quit h=Help r=Rename (window re-renders on any key press)",
        2,
        help_y + 1
    );

    return true;
}

bool drawConfirmationDialog (RzConsCanvas* c, int w, int h, const char* message) {
    // First, wrap the message to determine the required box size
    int max_msg_width = 70; // Maximum message width
    int max_msg_lines = 10; // Maximum message lines

    Strs wrapped_lines = wrapText (message, max_msg_width, max_msg_lines);

    // Calculate required box dimensions based on wrapped content
    int content_lines = wrapped_lines.length;
    int box_width     = max_msg_width + 4; // Add padding
    int box_height    = content_lines + 6; // Add padding for options and borders

    // Ensure minimum size
    box_width  = MAX2 (box_width, 40);
    box_height = MAX2 (box_height, 8);

    // Ensure box fits on screen
    if (box_width > w - 4) {
        box_width = w - 4;
    }
    if (box_height > h - 4) {
        box_height = h - 4;
    }

    // Calculate center position for dialog box
    int box_x = (w - box_width) / 2;
    int box_y = (h - box_height) / 2;

    // Draw semi-transparent overlay (just clear the area)
    for (int i = 0; i < h; i++) {
        for (int j = 0; j < w; j++) {
            rz_cons_canvas_write_at (c, " ", j, i);
        }
    }

    // Draw the dialog box
    rz_cons_canvas_box (c, box_x, box_y, box_width, box_height, Color_RESET);

    // Write the wrapped message
    int msg_x = box_x + 2;
    int msg_y = box_y + 2;

    VecForeachIdx (&wrapped_lines, line, idx, {
        if (idx < box_height - 4) { // Leave space for options
            rz_cons_canvas_write_at (c, line.data, msg_x, msg_y + idx);
        }
    });

    // Write options at the bottom
    int options_y = box_y + box_height - 3;
    rz_cons_canvas_write_at (c, "y = Yes, n = No", msg_x, options_y);

    // Clean up wrapped lines
    VecDeinit (&wrapped_lines);

    return true;
}

bool drawRenameDialog (RzConsCanvas* c, int w, int h, const char* initial_name, Str* target_name) {
    // Calculate center position for dialog box
    int box_width  = 70;
    int box_height = 10;
    int box_x      = (w - box_width) / 2;
    int box_y      = (h - box_height) / 2;

    // Initialize input buffer with initial name using Str
    Str input_buffer    = StrInitFromZstr (initial_name);
    int cursor_pos      = input_buffer.length;
    int max_input_width = box_width - 4;

    while (true) {
        // Clear screen and redraw dialog
        for (int i = 0; i < h; i++) {
            for (int j = 0; j < w; j++) {
                rz_cons_canvas_write_at (c, " ", j, i);
            }
        }

        // Draw the dialog box
        rz_cons_canvas_box (c, box_x, box_y, box_width, box_height, Color_RESET);

        // Write the prompt
        rz_cons_canvas_write_at (c, "Enter new function name:", box_x + 2, box_y + 2);
        rz_cons_canvas_write_at (c, "Press Enter to confirm, ESC to cancel", box_x + 2, box_y + 6);

        // Draw input field
        int input_x = box_x + 2;
        int input_y = box_y + 4;

        // Clear input area
        for (int i = 0; i < max_input_width; i++) {
            rz_cons_canvas_write_at (c, " ", input_x + i, input_y);
        }

        // Show current input with cursor
        int input_len     = input_buffer.length;
        int display_start = 0;

        // If input is longer than display width, scroll to show cursor
        if (cursor_pos >= max_input_width) {
            display_start = cursor_pos - max_input_width + 1;
        }

        // Display the visible portion of input
        int display_len = MIN2 (max_input_width, input_len - display_start);
        if (display_len > 0) {
            rz_cons_canvas_write_at (c, input_buffer.data + display_start, input_x, input_y);
        }

        // Show cursor position
        int cursor_display_x = input_x + (cursor_pos - display_start);
        if (cursor_display_x >= input_x && cursor_display_x < input_x + max_input_width) {
            // Use a simple cursor indicator - just show a blinking underscore or block
            // Don't print the actual character to avoid duplication
            rz_cons_canvas_write_at (c, "I", cursor_display_x, input_y);
        }

        // Print and flush
        rz_cons_canvas_print (c);
        rz_cons_flush();

        // Handle input
        int ch = rz_cons_readchar();

        switch (ch) {
            case 13 : // Enter key
                // Copy result directly to target_name
                StrClear (target_name);
                StrAppendf (target_name, "%s", input_buffer.data);
                StrDeinit (&input_buffer);
                return true;

            case 27 : // ESC key
                StrDeinit (&input_buffer);
                return false;

            case 127 : // Backspace
            case 8 :   // Backspace (alternative)
                if (cursor_pos > 0) {
                    // Remove character at cursor position using Str operations
                    StrDelete (&input_buffer, cursor_pos - 1);
                    cursor_pos--;
                }
                break;

            case 21 : // Ctrl+U (clear line)
                StrClear (&input_buffer);
                cursor_pos = 0;
                break;

            case 1 : // Ctrl+A (beginning of line)
                cursor_pos = 0;
                break;

            case 5 : // Ctrl+E (end of line)
                cursor_pos = input_buffer.length;
                break;

            case 2 : // Ctrl+B (backward)
                if (cursor_pos > 0) {
                    cursor_pos--;
                }
                break;

            case 6 : // Ctrl+F (forward)
                if ((u64)cursor_pos < input_buffer.length) {
                    cursor_pos++;
                }
                break;

            default :
                // Handle printable characters
                if (ch >= 32 && ch <= 126) {
                    // Insert character at cursor position
                    if ((u64)cursor_pos == input_buffer.length) {
                        // Append to end
                        StrPushBack (&input_buffer, ch);
                    } else {
                        // Insert in middle
                        StrInsertCharAt (&input_buffer, ch, cursor_pos);
                    }
                    cursor_pos++;
                }
                break;
        }
    }

    StrDeinit (&input_buffer);
    return false;
}

RzConsCanvas* drawInteractiveDiff (
    RzConsCanvas*   c,
    const char*     list_header,
    const char*     source_header,
    const char*     target_header,
    DiffListItems* items,
    int            selected_idx,
    DiffLines*     diff,
    bool           show_line_numbers
) {
    // get terminal size
    int h, w = rz_cons_get_size (&h);

    // if canvas is not created then create
    if (c == NULL) {
        c = rz_cons_canvas_new (w, h);
    }

    // resize canvas on windows resize
    if (c->w != w || c->h != h) {
        rz_cons_canvas_resize (c, w, h);
    }

    // create canvas
    rz_cons_canvas_clear (c);

    if (!drawInteractiveList (c, list_header, w, h, items, selected_idx)) {
        return NULL;
    }
    if (!drawInteractiveSourceDiff (c, source_header, w, h, diff, show_line_numbers)) {
        return NULL;
    }
    if (!drawInteractiveTargetDiff (c, target_header, w, h, diff, show_line_numbers)) {
        return NULL;
    }

    if (!drawHelpArea (c, w, h)) {
        return NULL;
    }

    rz_cons_canvas_print (c);
    rz_cons_flush();

    return c;
}

void DiffListItemDeinit (DiffListItem* item) {
    StrDeinit (&item->name);
    StrDeinit (&item->target_content);
}

/**
 * Get linear disassembly from function's control flow graph
 *
 * @param function_id : Function ID to get CFG for
 * @return Str : Linear disassembly as a single string (caller must free)
 */
Str getFunctionLinearDisasm (FunctionId function_id) {
    Str linear_disasm = StrInit();

    // Get the control flow graph for this function
    ControlFlowGraph cfg = GetFunctionControlFlowGraph (GetConnection(), function_id);

    if (cfg.blocks.length == 0) {
        LOG_ERROR ("No blocks found in control flow graph for function ID %llu", function_id);
        ControlFlowGraphDeinit (&cfg);
        return linear_disasm; // Return empty string
    }

    // Convert CFG blocks to linear disassembly
    // Sort blocks by min_addr to maintain proper order
    VecForeachPtr (&cfg.blocks, block, {
        // Add block header comment if it exists
        if (block->comment.length > 0) {
            StrAppendf (
                &linear_disasm,
                "; Block %llu (0x%llx-0x%llx): %s\n",
                block->id,
                block->min_addr,
                block->max_addr,
                block->comment.data
            );
        } else {
            StrAppendf (
                &linear_disasm,
                "; Block %llu (0x%llx-0x%llx)\n",
                block->id,
                block->min_addr,
                block->max_addr
            );
        }

        // Add all assembly lines from this block
        VecForeachPtr (&block->asm_lines, asm_line, {
            StrAppendf (&linear_disasm, "%s\n", asm_line->data);
        });

        // Add destination info if available
        if (block->destinations.length > 0) {
            StrAppendf (&linear_disasm, "; Destinations: ");
            VecForeachIdx (&block->destinations, dest, idx, {
                if (idx > 0) {
                    StrAppendf (&linear_disasm, ", ");
                }
                StrAppendf (
                    &linear_disasm,
                    "Block_%llu(%s)",
                    dest.destination_block_id,
                    dest.flowtype.data
                );
            });
            StrAppendf (&linear_disasm, "\n");
        }

        // Add separator between blocks
        StrAppendf (&linear_disasm, "\n");
    });

    // Add overview comment if available
    if (cfg.overview_comment.length > 0) {
        Str header = StrInit();
        StrPrintf (
            &header,
            "; Function Overview: %s\n\n%s",
            cfg.overview_comment.data,
            linear_disasm.data
        );
        StrDeinit (&linear_disasm);
        linear_disasm = header;
    }

    // Clean up CFG
    ControlFlowGraphDeinit (&cfg);

    // Replace all tab characters with four spaces
    StrReplaceZstr (&linear_disasm, "\t", "    ", -1);

    return linear_disasm;
}

RZ_IPI RzCmdStatus rz_function_assembly_diff_handler (RzCore* core, int argc, const char** argv) {
    // Parse arguments: function_name and optional similarity_level
    const char* function_name  = NULL;
    u32         min_similarity = 90; // Default 90% similarity

    if (!ZSTR_ARG (function_name, 1)) {
        DISPLAY_ERROR ("Usage: REfd <function_name> [similarity_level]");
        DISPLAY_ERROR ("Example: REfd main 85");
        return RZ_CMD_STATUS_WRONG_ARGS;
    }

    // Optional similarity level argument
    if (argc > 2) {
        NUM_ARG (min_similarity, 2);
        min_similarity = CLAMP (min_similarity, 50, 99); // Reasonable range for diffs
    }

    // Check if we can work with current analysis
    if (!rzCanWorkWithAnalysis (GetBinaryId(), true)) {
        DISPLAY_ERROR (
            "Current session has no completed analysis attached to it.\n"
            "Please create a new analysis and wait for it's completion or\n"
            "       apply an existing analysis that is already complete."
        );
        return RZ_CMD_STATUS_OK;
    }

    // Get function ID for the source function
    FunctionId source_fn_id = rzLookupFunctionIdForFunctionWithName (core, function_name);
    if (!source_fn_id) {
        DISPLAY_ERROR (
            "A function with that name does not exist in current Rizin session.\n"
            "Please provide a name from output of `afl` command."
        );
        return RZ_CMD_STATUS_WRONG_ARGS;
    }

    // Get linear disassembly for source function
    Str src = getFunctionLinearDisasm (source_fn_id);
    if (src.length == 0) {
        DISPLAY_ERROR ("Failed to get disassembly for function '%s'", function_name);
        StrDeinit (&src);
        return RZ_CMD_STATUS_OK;
    }

    // Find similar functions
    SimilarFunctionsRequest search        = SimilarFunctionsRequestInit();
    search.function_id                    = source_fn_id;
    search.limit                          = 10; // Get up to 10 similar functions for diff
    search.distance                       = 1. - (min_similarity / 100.);
    search.debug_include.user_symbols     = false;
    search.debug_include.system_symbols   = false;
    search.debug_include.external_symbols = false;

    SimilarFunctions similar_functions = GetSimilarFunctions (GetConnection(), &search);

    if (similar_functions.length == 0) {
        DISPLAY_ERROR (
            "No similar functions found for '%s' with %u%% similarity",
            function_name,
            min_similarity
        );
        StrDeinit (&src);
        SimilarFunctionsRequestDeinit (&search);
        return RZ_CMD_STATUS_OK;
    }

    rz_cons_printf (
        "Found %llu similar functions for '%s' (>= %u%% similarity)\n",
        (u64)similar_functions.length,
        function_name,
        min_similarity
    );

    // Create list of similar functions with their disassembly
    DiffListItems items = VecInit();

    VecForeachPtr (&similar_functions, similar_fn, {
        DiffListItem item = {0};

        // Create display name with similarity percentage
        item.name = StrInit();
        StrPrintf (
            &item.name,
            "%s (%.1f%% - %s)",
            similar_fn->name.data,
            (1. - similar_fn->distance) * 100.,
            similar_fn->binary_name.data
        );

        // Get linear disassembly for this similar function
        item.target_content = getFunctionLinearDisasm (similar_fn->id);

        // Only add if we successfully got disassembly
        if (item.target_content.length > 0) {
            VecPushBack (&items, item);
        } else {
            LOG_ERROR ("Failed to get disassembly for function ID %llu", similar_fn->id);
            DiffListItemDeinit (&item);
        }
    });

    // Check if we have any valid similar functions with disassembly
    if (items.length == 0) {
        DISPLAY_ERROR ("No similar functions with valid disassembly found for '%s'", function_name);
        StrDeinit (&src);
        VecDeinit (&similar_functions);
        SimilarFunctionsRequestDeinit (&search);
        VecDeinit (&items);
        return RZ_CMD_STATUS_OK;
    }

    int selected_idx = 0; // Start with first item selected

    // Generate initial diff
    DiffListItem* current_item = VecPtrAt (&items, selected_idx);
    DiffLines     diff         = GetDiff (&src, &current_item->target_content);

    // Create initial canvas
    RzConsCanvas* c = drawInteractiveDiff (
        NULL,
        "SIMILAR FUNCTIONS",
        "SOURCE",
        "TARGET",
        &items,
        selected_idx,
        &diff,
        false
    );

    if (!c) {
        DISPLAY_ERROR ("Failed to create interactive diff viewer");
        VecDeinit (&diff);
        StrDeinit (&src);
        VecDeinit (&similar_functions);
        SimilarFunctionsRequestDeinit (&search);
        VecForeachPtr (&items, item, { DiffListItemDeinit (item); });
        VecDeinit (&items);
        return RZ_CMD_STATUS_OK;
    }

    // Lazy help canvas - created once, reused multiple times
    static RzConsCanvas* help_canvas = NULL;

    int ch = 0; // Start with no input
    while (true) {
        // Only process and re-render when we have actual input
        if (ch != 0) {
            bool need_redraw   = false;
            bool need_new_diff = false;

            switch (ch) {
                case 'q' :
                case 'Q' :
                    goto cleanup;

                case 'k' : // Up
                    if (selected_idx > 0) {
                        selected_idx--;
                        need_redraw   = true;
                        need_new_diff = true;
                    }
                    break;

                case 'j' : // Down
                    if (selected_idx < (int)items.length - 1) {
                        selected_idx++;
                        need_redraw   = true;
                        need_new_diff = true;
                    }
                    break;

                case 'h' : // Help
                case '?' : {
                    // Get current terminal size
                    int help_h, help_w = rz_cons_get_size (&help_h);

                    // Lazy initialization - create help canvas only once
                    if (!help_canvas) {
                        help_canvas = rz_cons_canvas_new (help_w, help_h);

                        // Calculate center position for help box
                        int box_width  = 60;
                        int box_height = 16;
                        int box_x      = (help_w - box_width) / 2;
                        int box_y      = (help_h - box_height) / 2;

                        rz_cons_canvas_clear (help_canvas);

                        // Draw the help box (only once)
                        rz_cons_canvas_box (
                            help_canvas,
                            box_x,
                            box_y,
                            box_width,
                            box_height,
                            Color_RESET
                        );

                        // Write help content (only once)
                        rz_cons_canvas_write_at (
                            help_canvas,
                            "Interactive Function Diff Viewer - Help",
                            box_x + 2,
                            box_y + 1
                        );
                        rz_cons_canvas_write_at (
                            help_canvas,
                            "========================================",
                            box_x + 2,
                            box_y + 2
                        );

                        rz_cons_canvas_write_at (
                            help_canvas,
                            "Navigation Controls:",
                            box_x + 2,
                            box_y + 4
                        );
                        rz_cons_canvas_write_at (
                            help_canvas,
                            "  k       : Move selection up",
                            box_x + 4,
                            box_y + 5
                        );
                        rz_cons_canvas_write_at (
                            help_canvas,
                            "  j       : Move selection down",
                            box_x + 4,
                            box_y + 6
                        );
                        rz_cons_canvas_write_at (
                            help_canvas,
                            "  r       : Rename source function",
                            box_x + 4,
                            box_y + 9
                        );
                        rz_cons_canvas_write_at (
                            help_canvas,
                            "  q / ESC : Quit viewer",
                            box_x + 4,
                            box_y + 7
                        );
                        rz_cons_canvas_write_at (
                            help_canvas,
                            "  h / ?   : Show this help",
                            box_x + 4,
                            box_y + 8
                        );

                        rz_cons_canvas_write_at (help_canvas, "Usage:", box_x + 2, box_y + 11);
                        rz_cons_canvas_write_at (
                            help_canvas,
                            "• Left panel shows similar functions",
                            box_x + 4,
                            box_y + 12
                        );
                        rz_cons_canvas_write_at (
                            help_canvas,
                            "• Right panels show function diff",
                            box_x + 4,
                            box_y + 13
                        );
                        rz_cons_canvas_write_at (
                            help_canvas,
                            "• Use k/j to compare similar functions",
                            box_x + 4,
                            box_y + 14
                        );

                        rz_cons_canvas_write_at (
                            help_canvas,
                            "Press any key to continue...",
                            box_x + (box_width - 28) / 2,
                            box_y + box_height - 2
                        );
                    } else {
                        // Handle window resize - recreate canvas if size changed
                        if (help_canvas->w != help_w || help_canvas->h != help_h) {
                            rz_cons_canvas_resize (help_canvas, help_w, help_h);
                            // Note: Content remains the same, just canvas size adjusted
                        }
                    }

                    rz_cons_canvas_print (help_canvas);
                    rz_cons_flush();
                    rz_cons_readchar();
                    need_redraw = true;
                } break;

                case 'r' : // Rename
                case 'R' : {
                    // Get current terminal size
                    int rename_h, rename_w = rz_cons_get_size (&rename_h);

                    // Get target function name (extract from display name)
                    current_item    = VecPtrAt (&items, selected_idx);
                    Str target_name = StrInit();

                    // Parse the display name to extract target function name
                    // Format: "target_name (XX.X% - binary_name)"
                    const char* open_paren = strchr (current_item->name.data, '(');
                    if (open_paren) {
                        // Calculate length of target name (everything before the first space + parenthesis)
                        int name_len = open_paren - current_item->name.data;
                        // Remove trailing spaces
                        while (name_len > 0 && current_item->name.data[name_len - 1] == ' ') {
                            name_len--;
                        }

                        // Create target name using Str
                        StrAppendf (&target_name, "%.*s", name_len, current_item->name.data);
                    }

                    if (target_name.length == 0) {
                        StrAppendf (&target_name, "unknown_function");
                    }

                    // Show rename dialog first - pass pointer to target_name
                    if (drawRenameDialog (c, rename_w, rename_h, target_name.data, &target_name)) {
                        // User confirmed with Enter, now ask for final confirmation
                        Str confirm_message = StrInit();
                        StrPrintf (
                            &confirm_message,
                            "Are you sure you want to rename '%s' to '%s'?",
                            function_name,
                            target_name.data
                        );

                        drawConfirmationDialog (c, rename_w, rename_h, confirm_message.data);
                        rz_cons_canvas_print (c);
                        rz_cons_flush();

                        // Wait for y/n response
                        int confirm_ch = rz_cons_readchar();
                        if (confirm_ch == 'y' || confirm_ch == 'Y') {
                            rz_cons_printf (
                                "Renaming function '%s' to '%s'...\n",
                                function_name,
                                target_name.data
                            );

                            // Perform the actual rename using the existing rename function
                            Str old_name_str = StrInitFromZstr (function_name);

                            if (RenameFunction (GetConnection(), source_fn_id, target_name)) {
                                rz_analysis_function_rename (
                                    rz_analysis_get_function_byname (core->analysis, function_name),
                                    target_name.data
                                );
                                rz_cons_printf (
                                    "Successfully renamed function '%s' to '%s'\n",
                                    function_name,
                                    target_name.data
                                );
                            } else {
                                rz_cons_printf (
                                    "Failed to rename function '%s' to '%s'\n",
                                    function_name,
                                    target_name.data
                                );
                            }

                            StrDeinit (&old_name_str);

                            rz_cons_flush();
                            rz_sys_sleep (2); // Show result for 2 seconds
                        }
                        // If user pressed 'n', do nothing (cancelled)

                        StrDeinit (&confirm_message);
                    }
                    // If user pressed ESC in rename dialog, do nothing (cancelled)

                    StrDeinit (&target_name);

                    need_redraw = true;
                } break;

                default :
                    // Ignore unknown keys - no action needed
                    break;
            }

            if (need_new_diff) {
                // Clean up old diff
                VecDeinit (&diff);

                // Generate new diff with selected item
                current_item = VecPtrAt (&items, selected_idx);
                diff         = GetDiff (&src, &current_item->target_content);
            }

            if (need_redraw) {
                if (!(c = drawInteractiveDiff (
                        c,
                        "SIMILAR FUNCTIONS",
                        "SOURCE",
                        "TARGET",
                        &items,
                        selected_idx, &diff, false))) {
                    rz_cons_canvas_free (c);
                    c = NULL;
                    break;
                }
            }
        }

        // Wait for actual user input (blocking)
        ch = rz_cons_readchar();
    }

cleanup:
    // Cleanup
    if (c) {
        rz_cons_canvas_free (c);
    }

    // Lazy cleanup - free help canvas only at exit
    if (help_canvas) {
        rz_cons_canvas_free (help_canvas);
        help_canvas = NULL;
    }

    VecDeinit (&diff);
    StrDeinit (&src);

    // Clean up similar functions data
    VecDeinit (&similar_functions);
    SimilarFunctionsRequestDeinit (&search);

    // Clean up list items
    VecForeachPtr (&items, item, { DiffListItemDeinit (item); });
    VecDeinit (&items);

    return RZ_CMD_STATUS_OK;
}


// clang-format off
RZ_IPI RzCmdStatus rz_show_revengai_art_handler (RzCore* core, int argc, const char** argv) {
    (void)core;
    (void)argc;
    (void)argv;

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
