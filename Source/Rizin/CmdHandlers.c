/**
 * @file : CmdHandlers.c
 * @date : 13th June 2024
 * @author : Siddharth Mishra (admin@brightprogrammer.in)
 * @copyright: Copyright (c) 2024 Siddharth Mishra. All Rights Reserved.
 *
 * @b This file defines all the handlers that are declated inside `CmdGen/Output/CmdDescs.h`
 * After adding a new command entry, implement corresponding handlers here and then compile.
 * */

#include <Reai/Api/Api.h>
#include <Reai/Common.h>
#include <Reai/Types.h>

/* local includes */
#include "CmdGen/Output/CmdDescs.h"

/* defined somewhere else */
extern Reai* _reai;
extern ReaiResponse* _reai_response;

// "REs"
RZ_IPI RzCmdStatus rz_health_check_handler(RzCore* core, int argc, const char** argv)
{
    UNUSED(core && argc && argv);
    rz_return_val_if_fail(_reai && _reai_response, RZ_CMD_STATUS_ERROR);

    ReaiRequest request = { .type = REAI_REQUEST_TYPE_HEALTH_CHECK };
    if (reai_request(_reai, &request, _reai_response)) {
        rz_cons_printf("REAI Health Check : SUCCESS : %s\n", _reai_response->health_check.message);
    } else {
        rz_cons_printf("REAI Health Check : FAILURE : %s\n", _reai_response->health_check.message);
    }

    return RZ_CMD_STATUS_OK;
}

// "REu"
RZ_IPI RzCmdStatus rz_upload_bin_handler(RzCore* core, int argc, const char** argv)
{
    UNUSED(core && argc && argv);
    return RZ_CMD_STATUS_OK;
}
