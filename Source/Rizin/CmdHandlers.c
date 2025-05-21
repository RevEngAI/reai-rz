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
                    Str*            smry  = &aidec.summary;
                    Str*            dec   = &aidec.decompilation;

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
    SearchCollectionRequest search = SearchCollectionRequestInit();

    STR_ARG (search.partial_binary_name, 1);
    STR_ARG (search.model_name, 2);

    return collectionSearch (&search);
}

RZ_IPI RzCmdStatus rz_collection_search_by_collection_name_handler (RzCore* core, int argc, const char** argv) {
    SearchCollectionRequest search = SearchCollectionRequestInit();

    STR_ARG (search.partial_collection_name, 1);
    STR_ARG (search.model_name, 2);

    return collectionSearch (&search);
}

RZ_IPI RzCmdStatus rz_collection_search_by_hash_value_handler (RzCore* core, int argc, const char** argv) {
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
    Str term = StrInit(), filters = StrInit();
    STR_ARG (term, 1);
    STR_ARG (term, 2);
    return collectionFilteredSearch (term, filters, ORDER_BY_LAST_UPDATED, true);
}

/**
 * REcao
 * */
RZ_IPI RzCmdStatus rz_collection_basic_info_owner_asc_handler (RzCore* core, int argc, const char** argv) {
    Str term = StrInit(), filters = StrInit();
    STR_ARG (term, 1);
    STR_ARG (term, 2);
    return collectionFilteredSearch (term, filters, ORDER_BY_OWNER, true);
}

/**
 * REcan
 * */
RZ_IPI RzCmdStatus rz_collection_basic_info_name_asc_handler (RzCore* core, int argc, const char** argv) {
    Str term = StrInit(), filters = StrInit();
    STR_ARG (term, 1);
    STR_ARG (term, 2);
    return collectionFilteredSearch (term, filters, ORDER_BY_NAME, true);
}

/**
 * REcam
 * */
RZ_IPI RzCmdStatus rz_collection_basic_info_model_asc_handler (RzCore* core, int argc, const char** argv) {
    Str term = StrInit(), filters = StrInit();
    STR_ARG (term, 1);
    STR_ARG (term, 2);
    return collectionFilteredSearch (term, filters, ORDER_BY_MODEL, true);
}

/**
 * REcas
 * */
RZ_IPI RzCmdStatus rz_collection_basic_info_size_asc_handler (RzCore* core, int argc, const char** argv) {
    Str term = StrInit(), filters = StrInit();
    STR_ARG (term, 1);
    STR_ARG (term, 2);
    return collectionFilteredSearch (term, filters, ORDER_BY_SIZE, true);
}

/**
 * REcdt
 * */
RZ_IPI RzCmdStatus rz_collection_basic_info_time_desc_handler (RzCore* core, int argc, const char** argv) {
    Str term = StrInit(), filters = StrInit();
    STR_ARG (term, 1);
    STR_ARG (term, 2);
    return collectionFilteredSearch (term, filters, ORDER_BY_LAST_UPDATED, false);
}

/**
 * REcdo
 * */
RZ_IPI RzCmdStatus rz_collection_basic_info_owner_desc_handler (RzCore* core, int argc, const char** argv) {
    Str term = StrInit(), filters = StrInit();
    STR_ARG (term, 1);
    STR_ARG (term, 2);
    return collectionFilteredSearch (term, filters, ORDER_BY_OWNER, false);
}

/**
 * REcdn
 * */
RZ_IPI RzCmdStatus rz_collection_basic_info_name_desc_handler (RzCore* core, int argc, const char** argv) {
    Str term = StrInit(), filters = StrInit();
    STR_ARG (term, 1);
    STR_ARG (term, 2);
    return collectionFilteredSearch (term, filters, ORDER_BY_NAME, false);
}

/**
 * REcdm
 * */
RZ_IPI RzCmdStatus rz_collection_basic_info_model_desc_handler (RzCore* core, int argc, const char** argv) {
    Str term = StrInit(), filters = StrInit();
    STR_ARG (term, 1);
    STR_ARG (term, 2);
    return collectionFilteredSearch (term, filters, ORDER_BY_MODEL, false);
}

/**
 * REcds
 * */
RZ_IPI RzCmdStatus rz_collection_basic_info_size_desc_handler (RzCore* core, int argc, const char** argv) {
    Str term = StrInit(), filters = StrInit();
    STR_ARG (term, 1);
    STR_ARG (term, 2);
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
    SearchBinaryRequest search = SearchBinaryRequestInit();
    STR_ARG (search.partial_name, 1);
    STR_ARG (search.model_name, 3);
    return searchBinary (&search);
}

/**
 * REbsh
 * */
RZ_IPI RzCmdStatus rz_binary_search_by_sha256_handler (RzCore* core, int argc, const char** argv) {
    SearchBinaryRequest search = SearchBinaryRequestInit();
    STR_ARG (search.partial_sha256, 1);
    STR_ARG (search.model_name, 3);
    return searchBinary (&search);
}

RzCmdStatus openLinkForId (const char* type, u64 id) {
    Connection conn = GetConnection();

    Str host = StrDup (&conn.host);
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
