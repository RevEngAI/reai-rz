/**
 * @file : CmdHandlers.c
 * @date : 13th June 2024
 * @author : Siddharth Mishra (admin@brightprogrammer.in)
 * @copyright: Copyright (c) 2024 RevEngAI. All Rights Reserved.
 * */

/* rizin */
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
#include <Table.h>
#include <stdlib.h>

SimilarFunction *getMostSimilarFunction (SimilarFunctions *functions, FunctionId origin_fn_id) {
    if (!functions) {
        LOG_FATAL ("Function matches are invalid. Cannot proceed.");
    }

    if (!origin_fn_id) {
        LOG_FATAL ("Origin function ID is invalid. Cannot proceed.");
    }

    SimilarFunction *most_similar_fn = VecBegin (functions);
    VecForeachPtr (functions, fn, {
        if (fn->distance < most_similar_fn->distance) {
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

// Upload and get uploaded binary SHA-256
Str uploadCurrentBinary (Plugin *p, RzCore *core) {
    if (!p) {
        DISPLAY_FATAL ("Invalid arguments: Invalid plugin data.");
    }

    const char *binfile_path = rzGetCurrentBinaryPath (core);
    if (!binfile_path) {
        APPEND_ERROR ("No binary file opened in rizin. Cannot perform upload.");
        return (Str) {0};
    }

    Str path   = StrInitFromZstr (binfile_path);
    Str sha256 = UploadFile (p->conn, path);

    if (!sha256.length) {
        APPEND_ERROR ("Failed to upload binary file.");
    }

    return sha256;
}

// TODO:
//  - rzCreateAnalysis
//  - rzApplyAnalysis
//  - rzAutoRename
//  - rzAnnSymbols??

FunctionId rzLookupFunctionId (Plugin *p, RzCore *core, RzAnalysisFunction *rz_fn) {
    if (!p || !core || !rz_fn || !rz_fn->name) {
        DISPLAY_FATAL ("Invalid arguments: Invalid plugin data, Rizin core or analysis function.");
    }

    if (!p->binary_id) {
        APPEND_ERROR (
            "Please create a new analysis or apply an existing analysis. "
            "I need an existing analysis to get function information."
        );
        return 0;
    }

    FunctionInfos functions = GetBasicFunctionInfoUsingBinaryId (p->conn, p->binary_id);
    if (!functions.length) {
        APPEND_ERROR (
            "Failed to get function info list for opened binary file from RevEng.AI servers."
        );
        return 0;
    }

    u64 base_addr = rzGetCurrentBinaryBaseAddr (core);

    VecForeachPtr (&functions, fn, {
        if (rz_fn->addr == fn->symbol.value.addr + base_addr) {
            LOG_INFO (
                "RizinFunction -> [FunctionName, FunctionID] :: \"%s\" -> [\"%s\", %llu]",
                rz_fn->name,
                fn->symbol.name,
                fn->id
            );
            return fn->id;
        }
    });

    VecDeinit (&functions);

    LOG_ERROR ("Function ID not found\"%s\"", rz_fn->name);

    return 0;
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
        APPEND_ERROR (
            "Cannot get object reference to currently opened binary file. Internal Rizin error."
        );
        return NULL;
    }

    return rz_list_iter_get_data (head);
}

const char *rzGetCurrentBinaryPath (RzCore *core) {
    if (core) {
        LOG_FATAL ("Invalid arguments: Invalid Rizin core provided.");
    }
    RzBinFile *binfile = getCurrentBinary (core);
    return binfile ? rz_path_realpath (binfile->file) : NULL;
}

u64 rzGetCurrentBinaryBaseAddr (RzCore *core) {
    if (!core) {
        LOG_FATAL ("Invalid arguments: Invalid Rizin core provided.");
    }
    RzBinFile *binfile = getCurrentBinary (core);
    return binfile ? binfile->o->opts.baseaddr : 0;
}
