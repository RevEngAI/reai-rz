/**
 * @file : PluginState.c
 * @date : 13th June 2024
 * @author : Siddharth Mishra (admin@brightprogrammer.in)
 * @copyright: Copyright (c) 2024 Siddharth Mishra. All Rights Reserved.
 *
 * @b Global plugin state management.
 * */

/* rizin helpers */
#include <rz_type.h>

/* local includes */
#include "PluginState.h"

static ReaiPluginState state;

/**
 * TODO: write documentation for these functions.
 * I'm thinking of wrapping reai calls here so we won't have to
 * directly deal with members of ReaiPluginState.
 * */
PRIVATE CONSTRUCTOR void state_init()
{
    /* initialize reai connection and response struct */
    state.reai = reai_create(HARDCODED_HOST, HARDCODED_API_KEY);
    rz_return_val_if_fail(state.reai && reai_response_init(&state.response), Null);
}

/**
 * TODO:
 * */
PRIVATE DESTRUCTOR void state_deint()
{
    if (state.reai) {
        reai_destroy(state.reai);
    }

    reai_response_deinit(&state.response);
}

ReaiPluginState* reai_plugin_state_get()
{
    if (!state.reai) {
        state_init();
    }

    return &state;
}
