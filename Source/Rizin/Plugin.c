/**
 * @file : CmdHandlers.c
 * @date : 13th June 2024
 * @author : Siddharth Mishra (admin@brightprogrammer.in)
 * @copyright: Copyright (c) 2024 RevEngAI. All Rights Reserved.
 *
 * @brief Main plugin entry point.
 * */

#include <rz_analysis.h>
#include <rz_asm.h>
#include <rz_core.h>
#include <rz_lib.h>
#include <rz_types.h>

/* revengai */
#include <Reai/Api/Api.h>
#include <Reai/Common.h>
#include <Reai/Config.h>
#include <Reai/Types.h>

/* local includes */
#include "CmdGen/Output/CmdDescs.h"
#include "Plugin.h"

/* private plugin data */
static struct {
    ReaiConfig*   reai_config;
    Reai*         reai;
    ReaiResponse* reai_response;

    // TODO: This is temporary, database to be added to keep track of multiple
    // uploaded binaries and created analysis
    BinaryId bin_id;
    CString  sha_256_hash;
} plugin = {0};

/**
 * @b To be used by command handlers to indirectly access Reai API
 * without accessing things that they don't need.
 * */
RZ_IPI ReaiResponse* reai_plugin_request (ReaiRequest* request) {
    RETURN_VALUE_IF (!request, Null, ERR_INVALID_ARGUMENTS);
    return reai_request (plugin.reai, request, plugin.reai_response);
}

/**
 * @b Wrapper around reai upload file api
 * */
RZ_IPI CString reai_plugin_upload_file (CString path) {
    RETURN_VALUE_IF (!path, Null, ERR_INVALID_ARGUMENTS);
    return reai_upload_file (plugin.reai, plugin.reai_response, path);
}

/**
 * @b Wrapper around reai create analysis api
 * */
RZ_IPI BinaryId reai_plugin_create_analysis (
    ReaiModel      model,
    ReaiFnInfoVec* fn_info_vec,
    Bool           is_private,
    CString        sha_256_hash,
    CString        file_name,
    CString        cmdline_args,
    Size           size_in_bytes
) {
    RETURN_VALUE_IF (
        !model || !sha_256_hash || !file_name || !size_in_bytes,
        0,
        ERR_INVALID_ARGUMENTS
    );

    return reai_create_analysis (
        plugin.reai,
        plugin.reai_response,
        model,
        fn_info_vec,
        is_private,
        sha_256_hash,
        file_name,
        cmdline_args,
        size_in_bytes
    );
}

void reai_plugin_set_binary_id (BinaryId bin_id) {
    plugin.bin_id = bin_id;
}

BinaryId reai_plugin_get_binary_id() {
    return plugin.bin_id;
}

/**
 * @b Set hash is cloned and kept separately. Ownership of given string does not change
 * */
CString reai_plugin_set_sha_256_hash (CString sha_256_hash) {
    RETURN_VALUE_IF (!sha_256_hash, Null, ERR_INVALID_ARGUMENTS);

    if (plugin.sha_256_hash) {
        FREE (plugin.sha_256_hash);
        plugin.sha_256_hash = Null;
    }

    RETURN_VALUE_IF (!(plugin.sha_256_hash = strdup (sha_256_hash)), Null, ERR_OUT_OF_MEMORY);
    return plugin.sha_256_hash;
}

/**
 * @b returned string is onwed by caller and must free it after use.
 * */
CString reai_plugin_get_sha_256_hash() {
    return plugin.sha_256_hash ? strdup (plugin.sha_256_hash) : Null;
}

/**
 * @b Get function boundaries from given binary file.
 *
 * @NOTE: returned vector is owned by the caller and hence is
 * responsible for destroying the vector after use.
 *
 * @param binfile
 *
 * @return @c ReaiFnInfoVec reference on success.
 * @return @c Null otherwise.
 *  */
ReaiFnInfoVec* reai_plugin_get_fn_boundaries (RzBinFile* binfile) {
    RETURN_VALUE_IF (!binfile, Null, ERR_INVALID_ARGUMENTS);

    /* prepare symbols info  */
    RzPVector*     psymbols      = binfile->o->symbols;
    ReaiFnInfoVec* fn_boundaries = reai_fn_info_vec_create();

    /* add all symbols corresponding to functions */
    void** psym = Null;
    rz_pvector_foreach (psymbols, psym) {
        RzBinSymbol* symbol = *(RzBinSymbol**)psym;

        /* if symbol is of function type */
        if (!strcmp (symbol->type, "FUNC") && symbol->name) {
            ReaiFnInfo fn_info = {
                .name  = symbol->name,
                .vaddr = symbol->vaddr,
                .size  = symbol->size
            };

            if (!reai_fn_info_vec_append (fn_boundaries, &fn_info)) {
                reai_fn_info_vec_destroy (fn_boundaries);
                return Null;
            }
        }
    }

    return fn_boundaries;
}

/**
 * @brief Called by rizin when loading plugin. This is the plugin entrypoint where we
 * register all the commands and corresponding handlers.
 *
 * To know about how commands work for this plugin, refer to `CmdGen/README.md`.
 * */
RZ_IPI Bool reai_plugin_init (RzCore* core) {
    RETURN_VALUE_IF (!core, False, ERR_INVALID_ARGUMENTS);

    /* load default config */
    plugin.reai_config = reai_config_load (Null);

    /* initialize Reai objects. */
    plugin.reai          = reai_create (plugin.reai_config->host, plugin.reai_config->apikey);
    plugin.reai_response = reai_response_init (NEW (ReaiResponse));

    /* initialize command descriptors */
    rzshell_cmddescs_init (core);

    return True;
}

/**
 * @b Will be called by rizin before unloading the plugin.
 * */
RZ_IPI Bool reai_plugin_fini (RzCore* core) {
    RETURN_VALUE_IF (!core, False, ERR_INVALID_ARGUMENTS);

    if (plugin.reai_response) {
        reai_response_deinit (plugin.reai_response);
        FREE (plugin.reai_response);
    }

    if (plugin.reai) {
        reai_destroy (plugin.reai);
    }

    if (plugin.reai_config) {
        reai_config_destroy (plugin.reai_config);
    }

    /* Remove command group from rzshell. The name of this comamnd group must match
     * with the one specified in Root.yaml */
    RzCmd*     rcmd          = core->rcmd;
    RzCmdDesc* reai_cmd_desc = rz_cmd_get_desc (rcmd, "RE");
    return rz_cmd_desc_remove (rcmd, reai_cmd_desc);
}

/* plugin data */
RzCorePlugin core_plugin_reai = {
    .name    = "reai_rizin",
    .author  = "Siddharth Mishra",
    .desc    = "Reai Rizin Analysis Plugin",
    .license = "Copyright (c) 2024 RevEngAI. All Rights Reserved.",
    .version = "0.0",
    .init    = (RzCorePluginCallback)reai_plugin_init,
    .fini    = (RzCorePluginCallback)reai_plugin_fini,
    // .analysis = (RzCorePluginCallback)reai_plugin_analysis,
};

#ifdef _MSC_VER
#    define RZ_EXPORT __declspec (dllexport)
#else
#    define RZ_EXPORT
#endif

#ifndef CORELIB
RZ_EXPORT RzLibStruct rizin_plugin = {
    .type    = RZ_LIB_TYPE_CORE,
    .data    = &core_plugin_reai,
    .version = RZ_VERSION,
};
#endif
