/**
 * @file : CmdHandlers.c
 * @date : 13th June 2024
 * @author : Siddharth Mishra (admin@brightprogrammer.in)
 * @copyright: Copyright (c) 2024 RevEngAI. All Rights Reserved.
 * */

/* rizin */
#include <Reai/Util/Vec.h>
#include <rz_analysis.h>
#include <rz_asm.h>
#include <rz_cmd.h>
#include <rz_core.h>
#include <rz_lib.h>
#include <rz_th.h>
#include <rz_type.h>
#include <rz_types.h>
#include <rz_util/rz_annotated_code.h>

/* revengai */
#include <Reai/Api.h>
#include <Reai/Config.h>
#include <Reai/Log.h>
#include <Reai/Types.h>

/* libc */
#include <rz_util/rz_str.h>
#include <rz_util/rz_sys.h>
#include <string.h>
#include <ctype.h>

/* plugin includes */
#include <Plugin.h>
#include <stdlib.h>
#include "PluginVersion.h"
#include "Reai/Api/Types/DataType.h"

typedef struct Plugin {
    Config     config;
    Connection connection;
    BinaryId   binary_id;
    ModelInfos models;
} Plugin;

#ifdef __cplusplus
#    include <cutter/CutterConfig.h>
#    define SRE_TOOL_NAME    "cutter"
#    define SRE_TOOL_VERSION CUTTER_VERSION_FULL
#else
#    define SRE_TOOL_NAME    "rizin"
#    define SRE_TOOL_VERSION RZ_VERSION
#endif

void pluginDeinit (Plugin *p) {
    if (!p) {
        LOG_FATAL ("Invalid argument");
    }

    StrDeinit (&p->connection.api_key);
    StrDeinit (&p->connection.host);
    ConfigDeinit (&p->config);
    VecDeinit (&p->models);
    memset (p, 0, sizeof (Plugin));
}

Plugin *getPlugin (bool reinit) {
    static Plugin p;
    static bool   is_inited = false;

    if (reinit) {
        if (!is_inited) {
            p.config             = ConfigInit();
            p.connection.host    = StrInit();
            p.connection.api_key = StrInit();
            p.binary_id          = 0;
            p.models             = VecInitWithDeepCopy_T (&p.models, NULL, ModelInfoDeinit);
        }
        pluginDeinit (&p);
        is_inited = false;
    }

    if (is_inited) {
        return &p;
    } else {
        p.config             = ConfigInit();
        p.connection.host    = StrInit();
        p.connection.api_key = StrInit();
        p.binary_id          = 0;
        p.models             = VecInitWithDeepCopy_T (&p.models, NULL, ModelInfoDeinit);

        // Load config
        p.config = ConfigRead (NULL);
        if (!p.config.length) {
            DISPLAY_ERROR ("Failed to load config. Plugin is in unusable state");
            pluginDeinit (&p);
            return NULL;
        }

        // Get connection parameters
        Str *host    = ConfigGet (&p.config, "host");
        Str *api_key = ConfigGet (&p.config, "api_key");
        if (!host || !api_key) {
            DISPLAY_ERROR ("Config does not specify 'host' and 'api_key' required entries.");
            pluginDeinit (&p);
            return NULL;
        }
        p.connection.api_key = StrInitFromStr (api_key);
        p.connection.host    = StrInitFromStr (host);
        p.connection.user_agent =
            StrInitFromZstr ("reai_rz-" REAI_PLUGIN_VERSION " (" SRE_TOOL_NAME "-version = " SRE_TOOL_VERSION ")");

        // Get AI models, this way we also perform an implicit auth-check
        p.models = GetAiModelInfos (&p.connection);
        if (!p.models.length) {
            DISPLAY_ERROR ("Failed to get AI models. Please check host and API key in config.");
            pluginDeinit (&p);
            return NULL;
        }

        is_inited = true;
        return &p;
    }
}

void ReloadPluginData() {
    getPlugin (true);
}

Config *GetConfig() {
    if (getPlugin (false)) {
        return &getPlugin (false)->config;
    } else {
        return NULL;
    }
}

Connection *GetConnection() {
    if (getPlugin (false)) {
        return &getPlugin (false)->connection;
    } else {
        static Connection empty_conn = {0};
        return &empty_conn;
    }
}

BinaryId GetBinaryId() {
    // First try to get from local plugin instance
    if (getPlugin (false)) {
        BinaryId local_id = getPlugin (false)->binary_id;
        if (local_id != 0) {
            return local_id;
        }
    }

    // If local not available or is 0, we can't get from RzCore here
    // Use GetBinaryIdFromCore() when RzCore is available
    return 0;
}

// In cutter, due to multithreading, we can't use local plugin instance to get binary ID
// So we use RzCore config to get binary ID
BinaryId GetBinaryIdFromCore (RzCore *core) {
    // First try to get from local plugin instance
    if (getPlugin (false)) {
        BinaryId local_id = getPlugin (false)->binary_id;
        if (local_id != 0) {
            LOG_INFO ("Got binary ID %llu from local plugin", local_id);
            return local_id;
        }
    }

    // If local not available or is 0, try to get from RzCore config
    if (core && core->config) {
        BinaryId binary_id = (BinaryId)rz_config_get_i (core->config, "reai.binary_id");
        if (binary_id != 0) {
            LOG_INFO ("Got binary ID %llu from RzCore config", binary_id);
            return binary_id;
        }
    }

    return 0;
}

void SetBinaryId (BinaryId binary_id) {
    // Set in local plugin instance
    if (getPlugin (false)) {
        LOG_INFO ("Setting binary ID to %llu in local plugin", binary_id);
        getPlugin (false)->binary_id = binary_id;
    } else {
        LOG_ERROR ("Failed to set binary ID - plugin not initialized");
    }
}

// In cutter, due to multithreading, we can't use local plugin instance to get binary ID
// So we use RzCore config to set binary ID
void SetBinaryIdInCore (RzCore *core, BinaryId binary_id) {
    if (core && core->config) {
        rz_config_lock (core->config, false);
        rz_config_set_i (core->config, "reai.binary_id", binary_id);
        rz_config_lock (core->config, true);
        LOG_INFO ("Set binary ID %llu in RzCore config", binary_id);
    }
}

ModelInfos *GetModels() {
    if (getPlugin (false)) {
        return &getPlugin (false)->models;
    } else {
        static ModelInfos empty_models_vec = VecInitWithDeepCopy (ModelInfoInitClone, ModelInfoDeinit);
        return &empty_models_vec;
    }
}

AnnSymbol *rzGetMostSimilarFunctionSymbol (AnnSymbols *symbols, FunctionId origin_fn_id) {
    if (!symbols) {
        LOG_FATAL ("Function matches are invalid. Cannot proceed.");
    }

    if (!origin_fn_id) {
        LOG_FATAL ("Origin function ID is invalid. Cannot proceed.");
    }

    AnnSymbol *most_similar_fn = NULL;
    VecForeachPtr (symbols, fn, {
        if (fn->source_function_id == origin_fn_id &&
            (!most_similar_fn || (fn->distance < most_similar_fn->distance))) {
            most_similar_fn = fn;
        }
    });

    return most_similar_fn;
}

FunctionInfos getFunctionBoundaries (RzCore *core) {
    if (!core) {
        DISPLAY_FATAL ("Invalid argument: Invalid rizin core provided.");
    }

    // We send addresses in "base + offset" and get back in "offset" only

    RzList *fns = rz_analysis_function_list (core->analysis);

    FunctionInfos fv = VecInitWithDeepCopy (NULL, FunctionInfoDeinit);

    RzListIter         *fn_iter = NULL;
    RzAnalysisFunction *fn      = NULL;
    rz_list_foreach (fns, fn_iter, fn) {
        FunctionInfo fi = {
            .symbol = (SymbolInfo) {.name        = StrInitFromZstr (fn->name),
                                    .is_external = false,
                                    .is_addr     = true,
                                    .value       = {.addr = fn->addr}},
            .size   = rz_analysis_function_linear_size (fn)
        };
        VecPushBack (&fv, fi);
    }

    return fv;
}


/*
 * DESIGN-DECISION: Manual Construction of RzType over Parsed Strings
 *
 * During investigation into Rizin's type system (`rz_type`), it was found that
 * although the common usage pattern involves parsing type strings using the
 * type parser, a more direct and manual approach is both possible and encouraged
 * when working within Rizin's codebase.
 *
 * ACCORDING-TO-MAINTAINERS:
 * - You can manually create types by first instantiating an `RzBaseType` of the
 *   appropriate `.kind` and then filling its members.
 * - To construct pointers or arrays, use helper functions like:
 *     - `rz_type_identifier_of_base_type()`
 *     - `rz_type_pointer_of_base_type()`
 * - The distinction between `RzBaseType` and `RzType` is important and detailed in
 *   `librz/include/rz_type.h`.
 * - Manual creation avoids the need for parsing strings and is more straightforward
 *   when source data is already structured.
 *
 * CONCLUSION:
 * Manual construction of types using the API is preferred in this context to avoid
 * the overhead of converting source data to intermediate string representations,
 * which would then be reparsed. This avoids a "round-about way" and results in
 * clearer, more maintainable code.
 */

// TODO: when fuction similarity fails to get result, it's displayed like an error,
// instead show it like a simple message stating what happened.
// - James requested this

///
/// Returned const char* is just for borrowing and the caller does not own the returned string.
/// A call to this function will completely define the struct type and add to type-db so no need
/// to check if the type is created and added if the return value is non-null.
///
/// The return value is the name of new struct created and added to RzTypeDB (tdb)
///
/// dt[in]      : DataType to convert to RzType struct representation.
/// tdb[in,out] : Type database to add new created type to
///
/// SUCCESS: Name of new type added
/// FAILURE: abort()
///
static const char *createStructOrUnion (DataType *dt, RzTypeDB *tdb) {
    if (!dt || tdb) {
        LOG_FATAL ("Invalid arguments.");
    }

    RzBaseTypeKind btk = 0;

    if (!StrCmpZstr (&dt->artifact_type, "Struct")) {
        btk = RZ_BASE_TYPE_KIND_STRUCT;
    } else if (!StrCmpZstr (&dt->artifact_type, "Union")) {
        btk = RZ_BASE_TYPE_KIND_UNION;
    } else {
        LOG_FATAL ("Expected a union or a struct, got %s", dt->artifact_type.data);
    }

    if (!dt->name.data) {
        LOG_FATAL ("Invalid struct name. This shows a bug in application.");
    }

    RzBaseType *bt = rz_type_base_type_new (btk);
    bt->name       = strdup (dt->name.data);
    bt->size       = dt->size;
    bt->type       = NULL; // used only for typedef, atomic-type or enum

    VecForeachIdx (&dt->members, member, midx, {
        RzTypeStructMember tm = {0};
        tm.name               = strdup (member->name.data);
        tm.size               = member->size;
        tm.offset             = member->offset;

        if (member->artifact_type.data) {
            const char *name             = strdup (createStructOrUnion (member, tdb));
            tm.type                      = RZ_NEW0 (RzType);
            tm.type->kind                = RZ_TYPE_KIND_IDENTIFIER;
            tm.type->identifier.name     = (char *)name;
            tm.type->identifier.is_const = false;
            tm.type->identifier.kind     = RZ_TYPE_IDENTIFIER_KIND_UNSPECIFIED;
        } else if (rz_type_exists (tdb, member->type.data)) {
            tm.type = rz_type_identifier_of_base_type_str (tdb, member->type.data);
        } else {
            tm.type                      = RZ_NEW0 (RzType);
            tm.type->kind                = RZ_TYPE_KIND_IDENTIFIER;
            tm.type->identifier.name     = strdup (member->type.data);
            tm.type->identifier.is_const = false;
            tm.type->identifier.kind     = RZ_TYPE_IDENTIFIER_KIND_UNSPECIFIED;
        }

        rz_vector_push (&bt->struct_data.members, &tm);
    });

    ht_sp_insert (tdb->types, bt->name, bt);

    return bt->name;
}

/// TODO:
/// - Current DataType is recursive in nature, we can make it non-recursive (concluded after reading libbs/artifacts/struct.py)
/// - Create an ENUM for ArtifactType and convert provided artifact_type in JSON to ArtifactType
///   - List of available artifacts : https://github.com/binsync/libbs/tree/main/libbs/artifacts
/// - Create global variables
/// - Create local variables
/// - Find a way to verify current type sync algorithm
///

///
/// Define function type and add to given type database.
///
static bool applyFunctionType (RzCore *core, FunctionType *ftype, FunctionInfo *finfo) {
    if (!core || !ftype || !finfo) {
        LOG_FATAL ("Invalid arguments");
    }

    if (!ftype->name.data) {
        LOG_FATAL ("Invalid function name in provided FunctionType. Indicates a bug in app.");
    }

    RzTypeDB *tdb = core->analysis->typedb;

    VecForeachIdx (&ftype->deps, dep_type, dtidx, {
        if ((dep_type->name.data && rz_type_exists (tdb, dep_type->name.data)) ||
            (dep_type->type.data && rz_type_exists (tdb, dep_type->type.data))) {
            if (!StrCmpZstr (&dep_type->artifact_type, "GlobalVariable")) {
            } else {
                LOG_INFO (
                    "Type (name = %s, type = %s) already exists in RzTypeDB",
                    dep_type->name.data,
                    dep_type->type.data
                );
            }
            continue;
        }

        // if not already exists, create for struct and typedef
        if (!StrCmpZstr (&dep_type->artifact_type, "Struct") || !StrCmpZstr (&dep_type->artifact_type, "Union")) {
            createStructOrUnion (dep_type, tdb);
        } else if (StrCmpZstr (&dep_type->name, "Typedef")) {
            if (!dep_type->type.data || !dep_type->name.data) {
                LOG_FATAL ("Invalid typedef entry. Either type or name is NULL, which mustn't happen!");
            }

            RzType *t              = RZ_NEW0 (RzType);
            t->kind                = RZ_TYPE_KIND_IDENTIFIER;
            t->identifier.kind     = RZ_TYPE_IDENTIFIER_KIND_UNSPECIFIED;
            t->identifier.is_const = false;
            t->identifier.name     = strdup (dep_type->type.data);

            RzBaseType *bt = rz_type_base_type_new (RZ_BASE_TYPE_KIND_TYPEDEF);
            bt->name       = strdup (dep_type->name.data);
            bt->type       = t;

            ht_sp_insert (tdb->types, bt->name, bt);

            t  = NULL;
            bt = NULL;
        }
    });

    /// Find if callables already exists
    RzCallable *cft = ht_sp_find (tdb->callables, ftype->name.data, NULL);
    if (!cft) {
        cft = rz_type_func_new (
            tdb,
            ftype->name.data,
            rz_type_identifier_of_base_type_str (tdb, ftype->return_type.data)
        );

        RzType *ft   = RZ_NEW0 (RzType);
        ft->kind     = RZ_TYPE_KIND_CALLABLE;
        ft->callable = cft;

        VecForeachIdx (&ftype->args, arg, idx, {
            rz_type_func_arg_add (
                tdb,
                ftype->name.data,
                arg->name.data,
                rz_type_identifier_of_base_type_str (tdb, arg->type.data)
            );
        });
    }

    // set function type
    RzAnalysisFunction *afn = rz_analysis_get_function_byname (core->analysis, finfo->symbol.name.data);
    if (!afn) {
        LOG_ERROR ("Function with name \"%s\" does not exist in current Rizin session", finfo->symbol.name.data);
        return false;
    }
    rz_analysis_function_set_type (core->analysis, afn, cft);

    return true;
}

void rzApplyAnalysis (RzCore *core, BinaryId binary_id) {
    rzClearMsg();
    if (!core || !binary_id) {
        LOG_FATAL ("Invalid arguments: invalid Rizin core or binary id.");
    }

    if (rzCanWorkWithAnalysis (binary_id, true)) {
        // Set binary ID BEFORE applying analysis so that function rename hooks work properly
        SetBinaryId (binary_id);

        // Also set in RzCore config as backup for cross-context access
        SetBinaryIdInCore (core, binary_id);
        LOG_INFO ("Set binary ID %llu in both local plugin and RzCore config", binary_id);

        AnalysisId analysis_id = AnalysisIdFromBinaryId (GetConnection(), binary_id);

        FunctionInfos functions = GetFunctionsList (GetConnection(), analysis_id);
        if (!functions.length) {
            DISPLAY_ERROR ("Failed to get functions from RevEngAI analysis.");
            return;
        }

        // generate function types for all functions
        BeginFunctionTypeGenerationForAllFunctions (GetConnection(), analysis_id);
        u32 max_retries = 1;
        while (max_retries-- && !IsFunctionTypeGenerationCompletedForAllFunctions (GetConnection(), analysis_id)) {
            LOG_INFO ("Function type generation not completed yet! Remaining retries = %u", max_retries);
            rz_sys_usleep (100);
        }

        u64 base_addr = rzGetCurrentBinaryBaseAddr (core);

        // Apply function names
        VecForeachPtr (&functions, function, {
            u64                 addr = function->symbol.value.addr + base_addr;
            RzAnalysisFunction *fn   = rz_analysis_get_function_at (core->analysis, addr);
            if (fn) {
                rz_analysis_function_force_rename (fn, function->symbol.name.data);
                FunctionType ftype = GetFunctionType (GetConnection(), analysis_id, function->id);
                if (ftype.return_type.length) {
                    applyFunctionType (core, &ftype, function);
                } else {
                    LOG_ERROR ("No function type provided for function at address '0x%08llx'", addr);
                }
                FunctionTypeDeinit (&ftype);
            } else {
                LOG_ERROR ("No Rizin function exists at address '0x%08llx'", addr);
            }
        });

        VecDeinit (&functions);
    }
}

FunctionId rizinFunctionToId (FunctionInfos *functions, RzAnalysisFunction *fn, u64 base_addr) {
    VecForeach (functions, function, {
        if (function.symbol.value.addr + base_addr == fn->addr) {
            return function.id;
        }
    });

    return 0;
}

void rzAutoRenameFunctions (RzCore *core, size max_results_per_function, u32 min_similarity, bool debug_symbols_only) {
    rzClearMsg();
    if (GetBinaryId() && rzCanWorkWithAnalysis (GetBinaryId(), true)) {
        BatchAnnSymbolRequest batch_ann = BatchAnnSymbolRequestInit();

        batch_ann.debug_symbols_only = debug_symbols_only;
        batch_ann.limit              = max_results_per_function;
        batch_ann.distance           = 1. - (min_similarity / 100.);
        batch_ann.analysis_id        = AnalysisIdFromBinaryId (GetConnection(), GetBinaryId());
        if (!batch_ann.analysis_id) {
            DISPLAY_ERROR ("Failed to convert binary id to analysis id.");
            return;
        }

        AnnSymbols map = GetBatchAnnSymbols (GetConnection(), &batch_ann);
        BatchAnnSymbolRequestDeinit (&batch_ann);
        if (!map.length) {
            DISPLAY_ERROR ("Failed to get similarity matches.");
            return;
        }

        u64           base_addr = rzGetCurrentBinaryBaseAddr (core);
        FunctionInfos functions =
            GetFunctionsList (GetConnection(), AnalysisIdFromBinaryId (GetConnection(), GetBinaryId()));

        RzListIter         *it = NULL;
        RzAnalysisFunction *fn = NULL;
        rz_list_foreach (core->analysis->fcns, it, fn) {
            FunctionId id = rizinFunctionToId (&functions, fn, base_addr);
            if (!id) {
                LOG_ERROR (
                    "Failed to get a function ID for function with name = '%s' at address = 0x%llx",
                    fn->name,
                    fn->addr
                );
                continue;
            }

            AnnSymbol *best_match = rzGetMostSimilarFunctionSymbol (&map, id);
            if (best_match) {
                // Sync with cloud
                FunctionId fn_id = rzLookupFunctionId (core, fn);
                if (fn_id) {
                    if (RenameFunction (GetConnection(), fn_id, best_match->function_name)) {
                        LOG_INFO ("Renamed '%s' to '%s'", fn->name, best_match->function_name.data);
                        rz_analysis_function_force_rename (fn, best_match->function_name.data);
                        LOG_INFO (
                            "Successfully synced function rename with RevEngAI: '%s' (ID: %llu)",
                            fn->name,
                            fn_id
                        );
                    } else {
                        LOG_ERROR (
                            "Failed to sync function rename with RevEngAI for function '%s' (ID: %llu)",
                            fn->name,
                            fn_id
                        );
                    }
                } else {
                    LOG_ERROR (
                        "Failed to get function ID for function with name = '%s' at address = 0x%llx",
                        fn->name,
                        fn->addr
                    );
                }
            }
        }

        VecDeinit (&functions);
        VecDeinit (&map);
    } else {
        DISPLAY_ERROR (
            "Please apply an existing and complete analysis or\n"
            "       create a new one and wait for it's completion."
        );
    }

    // TODO: upload renamed functions name to reveng.ai as well
}

bool rzCanWorkWithAnalysis (BinaryId binary_id, bool display_messages) {
    if (!binary_id) {
        APPEND_ERROR ("Invalid arguments: Invalid binary ID");
        return false;
    }

    Status status = GetAnalysisStatus (GetConnection(), binary_id);
    if (!display_messages) {
        return ((status & STATUS_MASK) == STATUS_COMPLETE);
    } else {
        switch (status & STATUS_MASK) {
            case STATUS_ERROR : {
                DISPLAY_ERROR (
                    "The RevEngAI analysis has errored out.\n"
                    "I need a complete analysis. Please restart analysis."
                );
                return false;
            }
            case STATUS_QUEUED : {
                DISPLAY_ERROR (
                    "The RevEngAI analysis is currently in queue.\n"
                    "Please wait for the analysis to be analyzed."
                );
                return false;
            }
            case STATUS_PROCESSING : {
                DISPLAY_ERROR (
                    "The RevEngAI analysis is currently being processed (analyzed).\n"
                    "Please wait for the analysis to complete."
                );
                return false;
            }
            case STATUS_COMPLETE : {
                LOG_INFO ("Analysis for binary ID %llu is COMPLETE.", binary_id);
                return true;
            }
            default : {
                DISPLAY_ERROR (
                    "Oops... something bad happened :-(\n"
                    "I got an invalid value for RevEngAI analysis status.\n"
                    "Consider\n"
                    "\t- checking the binary ID, reapply the correct one if wrong\n"
                    "\t- retrying the command\n"
                    "\t- restarting the plugin\n"
                    "\t- checking logs in $TMPDIR or $TMP or $PWD (reai_<pid>)\n"
                    "\t- checking the connection with RevEngAI host.\n"
                    "\t- contacting support if the issue persists\n"
                );
                return false;
            }
        }
    }
}

FunctionId rzLookupFunctionId (RzCore *core, RzAnalysisFunction *rz_fn) {
    if (!core || !rz_fn || !rz_fn->name) {
        DISPLAY_FATAL ("Invalid arguments: Invalid Rizin core or analysis function.");
    }

    BinaryId binary_id = GetBinaryIdFromCore (core);
    if (!binary_id) {
        APPEND_ERROR (
            "Please create a new analysis or apply an existing analysis. "
            "I need an existing analysis to get function information."
        );
        return 0;
    }

    FunctionInfos functions = GetFunctionsList (GetConnection(), AnalysisIdFromBinaryId (GetConnection(), binary_id));
    if (!functions.length) {
        APPEND_ERROR ("Failed to get function info list for opened binary file from RevEng.AI servers.");
        return 0;
    }

    u64 base_addr = rzGetCurrentBinaryBaseAddr (core);

    FunctionId id = 0;
    VecForeachPtr (&functions, fn, {
        if (rz_fn->addr == fn->symbol.value.addr + base_addr) {
            LOG_INFO (
                "RizinFunction -> [FunctionName, FunctionID] :: \"%s\" -> [\"%s\", %llu]",
                rz_fn->name,
                fn->symbol.name.data,
                fn->id
            );
            id = fn->id;
            break;
        }
    });

    VecDeinit (&functions);

    if (!id) {
        APPEND_ERROR ("Function ID not found\"%s\"", rz_fn->name);
    }

    return id;
}

FunctionId rzLookupFunctionIdForFunctionWithName (RzCore *core, const char *name) {
    if (!core || !name) {
        LOG_FATAL ("Invalid arguments: invalid Rizin core or function name");
    }

    RzAnalysisFunction *rzfn = rz_analysis_get_function_byname (core->analysis, name);
    if (!rzfn) {
        APPEND_ERROR ("A function with given name '%s' does not exist in Rizin.\n", name);
        return 0;
    }

    return rzLookupFunctionId (core, rzfn);
}

FunctionId rzLookupFunctionIdForFunctionAtAddr (RzCore *core, u64 addr) {
    if (!core || !addr) {
        LOG_FATAL ("Invalid arguments: invalid Rizin core or function name");
    }

    RzAnalysisFunction *rzfn = rz_analysis_get_function_at (core->analysis, addr);
    if (!rzfn) {
        APPEND_ERROR ("A function at given address '%llx' does not exist in Rizin.\n", addr);
        return 0;
    }

    return rzLookupFunctionId (core, rzfn);
}

RzBinFile *getCurrentBinary (RzCore *core) {
    if (!core) {
        LOG_FATAL ("Invalid argument: Invalid rizin core provided.");
    }

    if (!core->bin || !core->bin->binfiles || !rz_list_length (core->bin->binfiles)) {
        APPEND_ERROR (
            "Seems like no binary file is opened yet. Binary container object is invalid. Cannot "
            "get opened binary file."
        );
        return NULL;
    }

    RzListIter *head = rz_list_head (core->bin->binfiles);
    if (!head) {
        APPEND_ERROR ("Cannot get object reference to currently opened binary file. Internal Rizin error.");
        return NULL;
    }

    return rz_list_iter_get_data (head);
}

Str rzGetCurrentBinaryPath (RzCore *core) {
    if (!core) {
        LOG_FATAL ("Invalid arguments: Invalid Rizin core provided.");
    }
    RzBinFile *binfile = getCurrentBinary (core);
    return binfile ? StrInitFromZstr (rz_path_realpath (binfile->file)) : (Str) {0};
}

u64 rzGetCurrentBinaryBaseAddr (RzCore *core) {
    if (!core) {
        LOG_FATAL ("Invalid arguments: Invalid Rizin core provided.");
    }
    RzBinFile *binfile = getCurrentBinary (core);
    return binfile ? binfile->o->opts.baseaddr : 0;
}
