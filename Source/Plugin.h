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
#include <Reai/Api/Api.h>
#include <Reai/Config.h>
#include <Reai/Log.h>

/* rizin */
#include <rz_bin.h>
#include <rz_core.h>

/* plugin */
#include <Table.h>

    REAI_MAKE_VEC (ReaiBgWorkersVec, bg_workers, RzThread*, NULL, NULL);

    typedef struct ReaiPlugin {
        ReaiConfig*   reai_config;
        Reai*         reai;
        ReaiResponse* reai_response;
        ReaiBinaryId  binary_id;
        CStrVec*      ai_models;

        ReaiBgWorkersVec* bg_workers;
        Bool              locked;
    } ReaiPlugin;

    ReaiPlugin* reai_plugin();
    Bool        reai_plugin_init (RzCore* core);
    Bool        reai_plugin_deinit();

    Bool reai_plugin_add_bg_work (RzThreadFunction fn, void* user_data);

    ReaiFnInfoVec* reai_plugin_get_function_boundaries (RzCore* core);
    void           reai_plugin_display_msg (ReaiLogLevel level, CString msg);
    void           reai_plugin_append_msg (ReaiLogLevel level, CString msg);
    Bool           reai_plugin_check_config_exists();
    CString        reai_plugin_get_default_log_dir_path();
    Bool           reai_plugin_save_config (CString host, CString api_key);

    Bool reai_plugin_upload_opened_binary_file (RzCore* core);
    Bool reai_plugin_create_analysis_for_opened_binary_file (
        RzCore* core,
        CString prog_name,
        CString cmdline_args,
        CString ai_model,
        Bool    is_private
    );
    ReaiAnalysisStatus reai_plugin_get_analysis_status_for_binary_id (ReaiBinaryId binary_id);
    Bool               reai_plugin_apply_existing_analysis (RzCore* core, ReaiBinaryId binary_id);
    Bool               reai_plugin_auto_analyze_opened_binary_file (
                      RzCore* core,
                      Size    max_results_per_function,
                      Float64 min_confidence,
                      Bool    debug_mode
                  );
    ReaiFunctionId
         reai_plugin_get_function_id_for_rizin_function (RzCore* core, RzAnalysisFunction* fn);
    Bool reai_plugin_search_and_show_similar_functions (
        RzCore* core,
        CString fcn_name,
        Size    max_results,
        Float32 confidence,
        Bool    debug_mode
    );

    RzBinFile* reai_plugin_get_opened_binary_file (RzCore* core);
    CString    reai_plugin_get_opened_binary_file_path (RzCore* core);
    CString    reai_plugin_get_opened_binary_file_path (RzCore* core);
    Uint64     reai_plugin_get_opened_binary_file_baseaddr (RzCore* core);
    Uint64     reai_plugin_get_rizin_analysis_function_count (RzCore* core);

    Bool reai_plugin_decompile_at (RzCore* core, ut64 addr);
    ReaiAiDecompilationStatus
            reai_plugin_check_decompiler_status_running_at (RzCore* core, ut64 addr);
    CString reai_plugin_get_decompiled_code_at (RzCore* core, ut64 addr);

#include "Override.h"

// wrapper macros to make sure first call to any one of these
// initializes plugin automatically
#define reai()            reai_plugin()->reai
#define reai_response()   reai_plugin()->reai_response
#define reai_config()     reai_plugin()->reai_config
#define reai_binary_id()  reai_plugin()->binary_id
#define reai_ai_models()  reai_plugin()->ai_models
#define reai_bg_workers() reai_plugin()->bg_workers

#define DISPLAY_MSG(level, ...)                                                                    \
    do {                                                                                           \
        Size  msgsz = snprintf (0, 0, __VA_ARGS__) + 1;                                            \
        Char* msg   = ALLOCATE (Char, msgsz);                                                      \
        if (!msg) {                                                                                \
            PRINT_ERR (ERR_OUT_OF_MEMORY);                                                         \
            break;                                                                                 \
        }                                                                                          \
        snprintf (msg, msgsz, __VA_ARGS__);                                                        \
        reai_plugin_display_msg (level, msg);                                                      \
        FREE (msg);                                                                                \
    } while (0)

#define DISPLAY_TRACE(...) DISPLAY_MSG (REAI_LOG_LEVEL_TRACE, __VA_ARGS__)
#define DISPLAY_INFO(...)  DISPLAY_MSG (REAI_LOG_LEVEL_INFO, __VA_ARGS__)
#define DISPLAY_DEBUG(...) DISPLAY_MSG (REAI_LOG_LEVEL_DEBUG, __VA_ARGS__)
#define DISPLAY_WARN(...)  DISPLAY_MSG (REAI_LOG_LEVEL_WARN, __VA_ARGS__)
#define DISPLAY_ERROR(...) DISPLAY_MSG (REAI_LOG_LEVEL_ERROR, __VA_ARGS__)
#define DISPLAY_FATAL(...) DISPLAY_MSG (REAI_LOG_LEVEL_FATAL, __VA_ARGS__)

#define APPEND_MSG(level, ...)                                                                     \
    do {                                                                                           \
        Size  msgsz = snprintf (0, 0, __VA_ARGS__) + 1;                                            \
        Char* msg   = ALLOCATE (Char, msgsz);                                                      \
        if (!msg) {                                                                                \
            PRINT_ERR (ERR_OUT_OF_MEMORY);                                                         \
            break;                                                                                 \
        }                                                                                          \
        snprintf (msg, msgsz, __VA_ARGS__);                                                        \
        reai_plugin_append_msg (level, msg);                                                       \
        FREE (msg);                                                                                \
    } while (0)

#define APPEND_TRACE(...) APPEND_MSG (REAI_LOG_LEVEL_TRACE, __VA_ARGS__)
#define APPEND_INFO(...)  APPEND_MSG (REAI_LOG_LEVEL_INFO, __VA_ARGS__)
#define APPEND_DEBUG(...) APPEND_MSG (REAI_LOG_LEVEL_DEBUG, __VA_ARGS__)
#define APPEND_WARN(...)  APPEND_MSG (REAI_LOG_LEVEL_WARN, __VA_ARGS__)
#define APPEND_ERROR(...) APPEND_MSG (REAI_LOG_LEVEL_ERROR, __VA_ARGS__)
#define APPEND_FATAL(...) APPEND_MSG (REAI_LOG_LEVEL_FATAL, __VA_ARGS__)

#ifdef __cplusplus
}
#endif

#endif // REAI_RIZIN_PLUGIN
