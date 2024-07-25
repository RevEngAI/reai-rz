/**
 * @file : CmdHandlers.c
 * @date : 13th June 2024
 * @author : Siddharth Mishra (admin@brightprogrammer.in)
 * @copyright: Copyright (c) 2024 RevEngAI. All Rights Reserved.
 *
 * @b This file defines all the handlers that are declated inside `CmdGen/Output/CmdDescs.h`
 * After adding a new command entry, implement corresponding handlers here and then compile.
 * */

#include <Reai/Api/Api.h>
#include <Reai/Api/Reai.h>
#include <Reai/Api/Request.h>
#include <Reai/Api/Response.h>
#include <Reai/Common.h>
#include <Reai/FnInfo.h>
#include <Reai/Types.h>
#include <rz_cmd.h>

/* local includes */
#include "CmdGen/Output/CmdDescs.h"
#include "Plugin.h"

// "REh"
RZ_IPI RzCmdStatus rz_health_check_handler (RzCore* core, int argc, const char** argv) {
    UNUSED (core && argc && argv);

    ReaiRequest   request  = {.type = REAI_REQUEST_TYPE_HEALTH_CHECK};
    ReaiResponse* response = Null;

    if ((response = reai_plugin_request (&request))) {
        printf ("REAI Health Check SUCCESS\n");
    } else {
        printf ("REAI Health Check FAILURE\n");
    }

    return RZ_CMD_STATUS_OK;
}

// "REA"
RZ_IPI RzCmdStatus
    rz_upload_and_create_analysis_handler (RzCore* core, int argc, const char** argv) {
    UNUSED (argc && argv);
    RETURN_VALUE_IF (
        !core->bin || !core->bin->binfiles->length,
        RZ_CMD_STATUS_ERROR,
        "No binary loaded, please load a binary to create analysis"
    );

    /* upload file and get hash */
    RzBinFile* binfile = core->bin->binfiles->head->elem;
    CString    sha256  = reai_plugin_upload_file (binfile->file);
    RETURN_VALUE_IF (!sha256, RZ_CMD_STATUS_ERROR, "Failed to upload file.\n");
    reai_plugin_set_sha_256_hash (sha256);

    /* get function boundaries to create analysis */
    ReaiFnInfoVec* fn_boundaries = reai_plugin_get_fn_boundaries (binfile);

    /* create analysis */
    BinaryId bin_id = reai_plugin_create_analysis (
        REAI_MODEL_X86_LINUX,
        fn_boundaries,
        True,
        sha256,
        binfile->file,
        Null,
        binfile->size
    );

    /* destroy after use */
    reai_fn_info_vec_destroy (fn_boundaries);

    RETURN_VALUE_IF (!bin_id, RZ_CMD_STATUS_ERROR, "Failed to create analysis.\n");

    reai_plugin_set_binary_id (bin_id);

    return RZ_CMD_STATUS_OK;
}

// "REa"
RZ_IPI RzCmdStatus rz_create_analysis_handler (RzCore* core, int argc, const char** argv) {
    UNUSED (argc && argv);
    RETURN_VALUE_IF (
        !core->bin || !core->bin->binfiles->length,
        RZ_CMD_STATUS_ERROR,
        "No binary loaded, please load a binary to create analysis"
    );

    /* upload file and get hash */
    RzBinFile* binfile = core->bin->binfiles->head->elem;

    /* get function boundaries to create analysis */
    ReaiFnInfoVec* fn_boundaries = reai_plugin_get_fn_boundaries (binfile);

    CString sha256 = reai_plugin_get_sha_256_hash();
    if (!sha256) {
        reai_fn_info_vec_destroy (fn_boundaries);
        return RZ_CMD_STATUS_ERROR;
    }

    /* create analysis */
    BinaryId bin_id = reai_plugin_create_analysis (
        REAI_MODEL_X86_LINUX,
        fn_boundaries,
        True,
        sha256,
        binfile->file,
        Null,
        binfile->size
    );

    /* destroy after use */
    FREE (sha256);
    reai_fn_info_vec_destroy (fn_boundaries);

    RETURN_VALUE_IF (!bin_id, RZ_CMD_STATUS_ERROR, "Failed to create analysis.\n");

    reai_plugin_set_binary_id (bin_id);

    return RZ_CMD_STATUS_OK;
}

// "REu"
RZ_IPI RzCmdStatus rz_upload_bin_handler (RzCore* core, int argc, const char** argv) {
    UNUSED (argc && argv);
    RETURN_VALUE_IF (
        !core->bin || !core->bin->binfiles->length,
        RZ_CMD_STATUS_ERROR,
        "No binary loaded, please load a binary to perform upload operation"
    );

    RzBinFile* binfile = core->bin->binfiles->head->elem;
    CString    sha256  = reai_plugin_upload_file (binfile->file);
    RETURN_VALUE_IF (!sha256, RZ_CMD_STATUS_ERROR, "Failed to upload file.\n");

    reai_plugin_set_sha_256_hash (sha256);

    return RZ_CMD_STATUS_OK;
}
