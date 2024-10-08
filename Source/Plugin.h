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
#include <Reai/Db.h>
#include <Reai/Log.h>

/* rizin */
#include <rz_bin.h>
#include <rz_core.h>

    typedef struct ReaiPlugin {
        ReaiConfig*   reai_config;
        Reai*         reai;
        ReaiDb*       reai_db;
        ReaiResponse* reai_response;
        ReaiLog*      reai_logger;

        // Periodically updates the database in background
        RzThread* background_worker;
    } ReaiPlugin;

    ReaiPlugin* reai_plugin();
    Bool        reai_plugin_init (RzCore* core);
    Bool        reai_plugin_deinit (RzCore* core);

    ReaiFnInfoVec* reai_plugin_get_function_boundaries (RzCore* core);
    void           reai_plugin_display_msg (ReaiLogLevel level, CString msg);
    Bool           reai_plugin_check_config_exists();
    CString        reai_plugin_get_default_database_dir_path();
    CString        reai_plugin_get_default_log_dir_path();
    Bool           reai_plugin_save_config (
                  CString host,
                  CString api_key,
                  CString model,
                  CString db_dir_path,
                  CString log_dir_path
              );

    Bool               reai_plugin_upload_opened_binary_file (RzCore* core);
    Bool               reai_plugin_create_analysis_for_opened_binary_file (RzCore* core);
    ReaiAnalysisStatus reai_plugin_get_analysis_status_for_binary_id (ReaiBinaryId binary_id);
    Bool               reai_plugin_auto_analyze_opened_binary_file (
                      RzCore* core,
                      Float64 max_distance,
                      Size    max_results_per_function,
                      Float64 min_confidence
                  );
    ReaiBinaryId reai_plugin_get_binary_id_for_opened_binary_file (RzCore* core);
    ReaiFunctionId
        reai_plugin_get_function_id_for_rizin_function (RzCore* core, RzAnalysisFunction* fn);

    RzBinFile* reai_plugin_get_opened_binary_file (RzCore* core);
    CString    reai_plugin_get_opened_binary_file_path (RzCore* core);
    ReaiModel  reai_plugin_get_ai_model_for_opened_binary_file (RzCore* core);
    CString    reai_plugin_get_opened_binary_file_path (RzCore* core);
    Uint64     reai_plugin_get_opened_binary_file_baseaddr (RzCore* core);
    Uint64     reai_plugin_get_rizin_analysis_function_count (RzCore* core);
    RzAnalysisFunction*
        reai_plugin_get_rizin_analysis_function_with_name (RzCore* core, CString name);

#include "Override.h"

#define reai()          reai_plugin()->reai
#define reai_db()       reai_plugin()->reai_db
#define reai_response() reai_plugin()->reai_response
#define reai_logger()   reai_plugin()->reai_logger
#define reai_config()   reai_plugin()->reai_config

#define LOG_TRACE(...) REAI_LOG_TRACE (reai_logger(), __VA_ARGS__)
#define LOG_INFO(...)  REAI_LOG_INFO (reai_logger(), __VA_ARGS__)
#define LOG_DEBUG(...) REAI_LOG_DEBUG (reai_logger(), __VA_ARGS__)
#define LOG_WARN(...)  REAI_LOG_WARN (reai_logger(), __VA_ARGS__)
#define LOG_ERROR(...) REAI_LOG_ERROR (reai_logger(), __VA_ARGS__)
#define LOG_FATAL(...) REAI_LOG_FATAL (reai_logger(), __VA_ARGS__)

    /**
     * Helper macro to create a buffer with contents of format string and given arguemtns
     * with given name.
     *
     * @param strname Name of variable
     * @param fmt Format string
     * */
#define FMT(strname, ...)                                                                          \
    Size  strname##_##strsz = snprintf (0, 0, __VA_ARGS__) + 1;                                    \
    Char* strname = ALLOCATE(Char, strname##_##strsz);                                             \
    if(!strname) {PRINT_ERR(ERR_OUT_OF_MEMORY);}                                                   \
    else {snprintf (strname, strname##_##strsz, __VA_ARGS__);}

#define DISPLAY_MSG(level, ...)                                                                    \
    do {                                                                                           \
        FMT (msg, __VA_ARGS__);                                                                    \
        reai_plugin_display_msg (level, msg);                                                      \
        FREE (msg);                                                                                \
    } while (0)

#define DISPLAY_TRACE(...) DISPLAY_MSG (REAI_LOG_LEVEL_TRACE, __VA_ARGS__)
#define DISPLAY_INFO(...)  DISPLAY_MSG (REAI_LOG_LEVEL_INFO, __VA_ARGS__)
#define DISPLAY_DEBUG(...) DISPLAY_MSG (REAI_LOG_LEVEL_DEBUG, __VA_ARGS__)
#define DISPLAY_WARN(...)  DISPLAY_MSG (REAI_LOG_LEVEL_WARN, __VA_ARGS__)
#define DISPLAY_ERROR(...) DISPLAY_MSG (REAI_LOG_LEVEL_ERROR, __VA_ARGS__)
#define DISPLAY_FATAL(...) DISPLAY_MSG (REAI_LOG_LEVEL_FATAL, __VA_ARGS__)

#ifdef __cplusplus
}
#endif

#endif // REAI_RIZIN_PLUGIN
