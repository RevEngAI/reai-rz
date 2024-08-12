/**
 * @file : ReaiPlugin.h
 * @date : 13th June 2024
 * @author : Siddharth Mishra (admin@brightprogrammer.in)
 * @copyright: Copyright (c) 2024 RevEngAI. All Rights Reserved.
 *
 * @b Global plugin state management. This defines a singleton class
 * that needs to be accessed using the get method only.
 * */

#ifndef REAI_RIZIN_PLUGIN
#define REAI_RIZIN_PLUGIN

/* revenai */
#include <Reai/Api/Api.h>
#include <Reai/Log.h>
#include <Reai/Config.h>
#include <Reai/Db.h>

/* rizin */
#include <rz_bin.h>
#include <rz_core.h>

void reai_plugin_log_printf (ReaiLogLevel level, CString tag, CString fmtstr, ...);

#define LOG_TRACE(...) REAI_LOG_TRACE (reai_logger(), __VA_ARGS__)
#define LOG_INFO(...)  REAI_LOG_INFO (reai_logger(), __VA_ARGS__)
#define LOG_DEBUG(...) REAI_LOG_DEBUG (reai_logger(), __VA_ARGS__)
#define LOG_WARN(...)  REAI_LOG_WARN (reai_logger(), __VA_ARGS__)
#define LOG_ERROR(...) REAI_LOG_ERROR (reai_logger(), __VA_ARGS__)
#define LOG_FATAL(...) REAI_LOG_FATAL (reai_logger(), __VA_ARGS__)

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

#define reai()          reai_plugin()->reai
#define reai_db()       reai_plugin()->reai_db
#define reai_response() reai_plugin()->reai_response
#define reai_logger()   reai_plugin()->reai_logger
#define reai_config()   reai_plugin()->reai_config

/* helpers */
ReaiFnInfoVec* reai_plugin_get_fn_boundaries (RzCore* core);

#include "Override.h"

#endif // REAI_RIZIN_PLUGIN
