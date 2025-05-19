/**
 * @file : Plugin.h
 * @date : 13th June 2024
 * @author : Siddharth Mishra (admin@brightprogrammer.in)
 * @copyright: Copyright (c) 2024 RevEngAI. All Rights Reserved.
 *
 * @b Global plugin state management. This defines a singleton class
 * that needs to be accessed using the get method only.
 * */

#ifndef REAI_RIZIN_PLUGIN
#define REAI_RIZIN_PLUGIN

#ifdef __cplusplus
extern "C" {
#endif

    /* libc */
#include <stdio.h>

/* revenai */
#include <Reai/Api.h>
#include <Reai/Config.h>
#include <Reai/Log.h>

/* rizin */
#include <rz_bin.h>
#include <rz_core.h>

/* plugin */
#include <Table.h>

    typedef struct Plugin {
        Config     config;
        Connection conn;
        BinaryId   binary_id;
        ModelInfos models;
    } Plugin;

    ///
    /// Apply an existing analysis to currently opened binary.
    ///
    /// p[in] : Plugin
    /// binary_id[in] : Binary ID to fetch analysis for and apply.
    ///
    /// SUCCESS : true
    /// FAILURE : false
    ///
    bool rzApplyExistingAnalysis (Plugin* p, BinaryId binary_id);

    ///
    /// Get similar functions for each function and perform an auto-rename
    /// operation for functions that cross similarity level threshold
    ///
    /// p[in]                        : Plugin
    /// max_results_per_function[in] : Number of results to get per function.
    /// min_confidence[in]           : Minimum similarity threshold to cross before candidacy for a rename.
    /// debug_symbols_only[in]       : Suggests symbols extracted from debug information only.
    ///
    void rzAutoRenameFunctions (
        Plugin* p,
        size    max_results_per_function,
        f64     min_similarity,
        bool    debug_symbols_only
    );

    ///
    /// Search for function ID corresponding to given rizin function.
    ///
    /// p[in]    : Plugin
    /// core[in] : Rizin core.
    /// fn[in]   : Function to get RevEngAI function ID for.
    ///
    /// SUCCESS : Non-zero function ID.
    /// FAILURE : Zero.
    ///
    FunctionId rzLookupFunctionId (Plugin* p, RzCore* core, RzAnalysisFunction* fn);

    void        rzDisplayMsg (LogLevel level, Str* msg);
    void        rzAppendMsg (LogLevel level, Str* msg);
    const char* rzGetCurrentBinaryPath (RzCore* core);
    u64         rzGetCurrentBinaryBaseAddr (RzCore* core);

#define DISPLAY_MSG(level, ...)                                                                    \
    do {                                                                                           \
        Str msg = StrInit();                                                                       \
        StrPrintf (&msg, __VA_ARGS__);                                                             \
        rzDisplayMsg (level, &msg);                                                                \
        StrDeinit (&msg);                                                                          \
    } while (0)

#define APPEND_MSG(level, ...)                                                                     \
    do {                                                                                           \
        Str msg = StrInit();                                                                       \
        StrPrintf (&msg, __VA_ARGS__);                                                             \
        rzAppendMsg (level, &msg);                                                                 \
        StrDeinit (&msg);                                                                          \
    } while (0)

#define DISPLAY_INFO(...)  DISPLAY_MSG (LOG_LEVEL_INFO, __VA_ARGS__)
#define DISPLAY_ERROR(...) DISPLAY_MSG (LOG_LEVEL_ERROR, __VA_ARGS__)
#define DISPLAY_FATAL(...)                                                                         \
    DISPLAY_MSG (LOG_LEVEL_FATAL, __VA_ARGS__);                                                    \
    abort()

#define APPEND_INFO(...)  APPEND_MSG (LOG_LEVEL_INFO, __VA_ARGS__)
#define APPEND_ERROR(...) APPEND_MSG (LOG_LEVEL_ERROR, __VA_ARGS__)
#define APPEND_FATAL(...) APPEND_MSG (LOG_LEVEL_FATAL, __VA_ARGS__)

#ifdef __cplusplus
}
#endif

#endif // REAI_RIZIN_PLUGIN
