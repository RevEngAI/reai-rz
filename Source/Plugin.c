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

/* plugin includes */
#include <Plugin.h>
#include <stdlib.h>

typedef struct Plugin {
    Config     config;
    Connection connection;
    BinaryId   binary_id;
    ModelInfos models;
} Plugin;

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
        if(!is_inited) {
            p.config             = ConfigInit();
            p.connection.host    = StrInit();
            p.connection.api_key = StrInit();
            p.binary_id          = 0;
            p.models             = VecInitWithDeepCopy_T(&p.models, NULL, ModelInfoDeinit);
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
        p.models             = VecInitWithDeepCopy_T(&p.models, NULL, ModelInfoDeinit);

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

Connection* GetConnection() {
    if (getPlugin (false)) {
        return &getPlugin (false)->connection;
    } else {
        static Connection empty_conn = {0};
        return &empty_conn;
    }
}

BinaryId GetBinaryId() {
    if (getPlugin (false)) {
        return getPlugin (false)->binary_id;
    } else {
        return 0;
    }
}

void SetBinaryId (BinaryId binary_id) {
    if (getPlugin (false)) {
        getPlugin (false)->binary_id = binary_id;
    }
}

ModelInfos *GetModels() {
    if (getPlugin (false)) {
        return &getPlugin (false)->models;
    } else {
        static ModelInfos empty_models_vec = VecInitWithDeepCopy(ModelInfoInitClone, ModelInfoDeinit);
        return &empty_models_vec;
    }
}

AnnSymbol *getMostSimilarFunctionSymbol (AnnSymbols *symbols, FunctionId origin_fn_id) {
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
            .symbol = (SymbolInfo
            ) {.name = StrInitFromZstr (fn->name), .is_external = false, .is_addr = true, .value = {.addr = fn->addr}},
            .size   = rz_analysis_function_linear_size (fn)
        };
        VecPushBack (&fv, fi);
    }

    return fv;
}

void rzApplyAnalysis (RzCore *core, BinaryId binary_id) {
    rzClearMsg();
    if (!core || !binary_id) {
        LOG_FATAL ("Invalid arguments: invalid Rizin core or binary id.");
    }

    if (rzCanWorkWithAnalysis (binary_id, true)) {
        FunctionInfos functions = GetBasicFunctionInfoUsingBinaryId (GetConnection(), binary_id);
        if (!functions.length) {
            DISPLAY_ERROR ("Failed to get functions from RevEngAI analysis.");
            return;
        }

        u64  base_addr = rzGetCurrentBinaryBaseAddr (core);
        bool failed    = false;
        VecForeachPtr (&functions, function, {
            u64                 addr = function->symbol.value.addr + base_addr;
            RzAnalysisFunction *fn   = rz_analysis_get_function_at (core->analysis, addr);
            if (!fn) {
                LOG_ERROR ("No Rizin function exists at address '0x%08llx'", addr);
                failed = true;
                continue;
            }
            rz_analysis_function_force_rename (fn, function->symbol.name.data);
        });

        SetBinaryId (binary_id);

        if (!failed) {
            DISPLAY_INFO ("All functions renamed successfully");
        } else {
            DISPLAY_INFO (
                "Analyses applied, but some rename operations failed. Check logs.\n"
                "Check renamed functions by `afl` command."
            );
        }

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
        FunctionInfos functions = GetBasicFunctionInfoUsingBinaryId (GetConnection(), GetBinaryId());

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

            AnnSymbol *best_match = getMostSimilarFunctionSymbol (&map, id);
            if (best_match) {
                LOG_INFO ("Renamed '%s' to '%s'", fn->name, best_match->function_name.data);
                rz_analysis_function_force_rename (fn, best_match->function_name.data);
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

    if (!GetBinaryId()) {
        APPEND_ERROR (
            "Please create a new analysis or apply an existing analysis. "
            "I need an existing analysis to get function information."
        );
        return 0;
    }

    FunctionInfos functions = GetBasicFunctionInfoUsingBinaryId (GetConnection(), GetBinaryId());
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
                fn->symbol.name,
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
