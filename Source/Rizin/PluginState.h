/**
 * @file : PluginState.h
 * @date : 13th June 2024
 * @author : Siddharth Mishra (admin@brightprogrammer.in)
 * @copyright: Copyright (c) 2024 Siddharth Mishra. All Rights Reserved.
 *
 * @b Global plugin state management. This defines a singleton class
 * that needs to be accessed using the get method only.
 * */

#ifndef REAI_RIZIN_PLUGIN_STATE
#define REAI_RIZIN_PLUGIN_STATE

#include <Reai/Api/Api.h>

typedef struct ReaiPluginState {
    Reai* reai;
    ReaiResponse response;
} ReaiPluginState;

ReaiPluginState* reai_plugin_state_get();

#endif // REAI_RIZIN_PLUGIN_STATE
