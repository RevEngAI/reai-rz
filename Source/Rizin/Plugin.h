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

#include <Reai/Api/Api.h>

/* rizin */
#include <rz_bin.h>

ReaiResponse* reai_plugin_request (ReaiRequest* request);
CString       reai_plugin_upload_file (CString file_path);
BinaryId      reai_plugin_create_analysis (
         ReaiModel      model,
         ReaiFnInfoVec* fn_info_vec,
         Bool           is_private,
         CString        sha_256_hash,
         CString        file_name,
         CString        cmdline_args,
         Size           size_in_bytes
     );
ReaiFnInfoVec* reai_plugin_get_fn_boundaries (RzBinFile* binfile);

void     reai_plugin_set_binary_id (BinaryId bin_id);
BinaryId reai_plugin_get_binary_id();

CString reai_plugin_set_sha_256_hash (CString sha_256_hash);
CString reai_plugin_get_sha_256_hash();



#endif // REAI_RIZIN_PLUGIN
