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

/* libc */
#include <stdio.h>

/* revenai */
#include <Reai/Api.h>
#include <Reai/Config.h>
#include <Reai/Log.h>

/* rizin */
#include <rz_bin.h>
#include <rz_core.h>

#ifdef __cplusplus
extern "C" {
#endif


    ///
    /// Reinit plugin by deiniting current internal state and reloading config
    ///
    void ReloadPluginData();

    ///
    /// Get loaded config.
    /// Don't ever deinit returned `Config`.
    ///
    /// SUCCESS : Valid `Config` pointer.
    /// FAILURE : `NULL`
    ///
    Config* GetConfig();

    ///
    /// Get connection information used by this plugin.
    /// Don't ever deinit anything inside returned object.
    ///
    /// SUCCESS : Connection object filled with valid data.
    /// FAILURE : Empty object.
    ///
    Connection* GetConnection();

    ///
    /// Get current binary ID (if any set).
    ///
    /// SUCCESS : A non-zero binary if it's set by user, 0 otherwise.
    /// FAILURE : 0.
    ///
    BinaryId GetBinaryId();
    void     SetBinaryId (BinaryId binary_id);

    ///
    /// Get binary ID with RzCore fallback for cross-context access.
    ///
    /// core[in] : RzCore instance to get config from if local storage unavailable.
    ///
    /// SUCCESS : A non-zero binary ID if found locally or in RzCore config.
    /// FAILURE : 0.
    ///
    BinaryId GetBinaryIdFromCore (RzCore* core);
    void     SetBinaryIdInCore (RzCore* core, BinaryId binary_id);


    ///
    /// Get all available AI models.
    ///
    /// SUCCESS : Vector of ModelInfo objects filled with valid data.
    /// FAILURE : Empty vector otherwise.
    ///
    ModelInfos* GetModels();

    ///
    /// Check whether or not we can work with analysis associated with given binary ID.
    ///
    /// binary_id[in] : Binary ID to check for.
    /// display_messages[in] : Whether to display popup messages if analysis is not workable with.
    ///
    /// SUCCESS : `true`/`false` depending on whether we can continue working with analysis.
    /// FAILURE : `false` with log messages
    ///
    bool rzCanWorkWithAnalysis (BinaryId binary_id, bool display_messages);

    ///
    /// Apply an existing analysis to currently opened binary.
    ///
    /// p[in]         : RzCore
    /// binary_id[in] : Binary ID to fetch analysis for and apply.
    ///
    void rzApplyAnalysis (RzCore* core, BinaryId binary_id);

    ///
    /// Get similar functions for each function and perform an auto-rename
    /// operation for functions that cross similarity level threshold
    ///
    /// core[in]                     : Rizin core.
    /// max_results_per_function[in] : Number of results to get per function.
    /// min_confidence[in]           : Minimum similarity threshold to cross before candidacy for a rename.
    /// debug_symbols_only[in]       : Suggests symbols extracted from debug information only.
    ///
    void rzAutoRenameFunctions (
        RzCore* core,
        size    max_results_per_function,
        u32     min_similarity,
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
    FunctionId rzLookupFunctionId (RzCore* core, RzAnalysisFunction* fn);
    FunctionId rzLookupFunctionIdForFunctionWithName (RzCore* core, const char* name);
    FunctionId rzLookupFunctionIdForFunctionAtAddr (RzCore* core, u64 addr);

    ///
    /// Get path to opened binary file.
    /// Deinit returned string after use.
    ///
    /// core[in] : RzCore
    ///
    /// SUCCESS : `Str` object containing absolute path of currently opened binary.
    /// FAILURE : Empty `Str` object if no file opened.
    ///
    Str rzGetCurrentBinaryPath (RzCore* core);

    ///
    /// Get base address of opened binary.
    ///
    /// core[in] : RzCore
    ///
    /// SUCCESS : base address if binary file opened (can be 0)
    /// FAILURE : 0
    ///
    u64 rzGetCurrentBinaryBaseAddr (RzCore* core);

    ///
    /// Get most similar function symbol for given origin function ID.
    ///
    /// symbols[in] : AnnSymbols to search in.
    /// origin_fn_id[in] : Origin function ID to get most similar symbol for.
    ///
    AnnSymbol* rzGetMostSimilarFunctionSymbol (AnnSymbols* symbols, FunctionId origin_fn_id);

    void rzDisplayMsg (LogLevel level, Str* msg);
    void rzAppendMsg (LogLevel level, Str* msg);
    void rzClearMsg();

#ifdef __cplusplus
}
#endif

#define DISPLAY_MSG(level, ...)                                                                                        \
    do {                                                                                                               \
        Str msg = StrInit();                                                                                           \
        StrPrintf (&msg, __VA_ARGS__);                                                                                 \
        rzDisplayMsg (level, &msg);                                                                                    \
        StrDeinit (&msg);                                                                                              \
    } while (0)

#define APPEND_MSG(level, ...)                                                                                         \
    do {                                                                                                               \
        Str msg = StrInit();                                                                                           \
        StrPrintf (&msg, __VA_ARGS__);                                                                                 \
        rzAppendMsg (level, &msg);                                                                                     \
        StrDeinit (&msg);                                                                                              \
    } while (0)

#define DISPLAY_INFO(...)  DISPLAY_MSG (LOG_LEVEL_INFO, __VA_ARGS__)
#define DISPLAY_ERROR(...) DISPLAY_MSG (LOG_LEVEL_ERROR, __VA_ARGS__)
#define DISPLAY_FATAL(...)                                                                                             \
    DISPLAY_MSG (LOG_LEVEL_FATAL, __VA_ARGS__);                                                                        \
    abort()

#define APPEND_INFO(...)  APPEND_MSG (LOG_LEVEL_INFO, __VA_ARGS__)
#define APPEND_ERROR(...) APPEND_MSG (LOG_LEVEL_ERROR, __VA_ARGS__)
#define APPEND_FATAL(...) APPEND_MSG (LOG_LEVEL_FATAL, __VA_ARGS__)

#endif // REAI_RIZIN_PLUGIN
