/**
 * @file      : Decompiler.hpp
 * @author    : Siddharth Mishra
 * @date      : 28/01/2025
 * @copyright : Copyright (c) 2025 RevEngAI. All Rights Reserved.
 * */

#include <Cutter/Decompiler.hpp>
#include <Plugin.h>

ReaiDec::ReaiDec (QObject *parent) : Decompiler ("reaidec", "ReaiDec", parent) {}

bool ReaiDec::isRunning() {
    /* HACK(brightprogrammer): If a binary ID is not set, this means the plugin
   * might've just started, and user didn't get a chance to either create a new analysis
   * or apply an existing one.
   *
   * In such a case, attempting to decompile will just create false positives. Rather
   * we just inform Cutter that we're still decompiling something to stop it from calling
   * the API endpoint for AI decompilation and filling up error buffers. */
    if (!reai_binary_id()) {
        return true;
    }

    RzCoreLocked core (Core());

    ReaiAiDecompilationStatus status = reai_plugin_check_decompiler_status_running_at (core, addr);
    REAI_LOG_INFO (reai_ai_decompilation_status_to_cstr (status));

    if (status == REAI_AI_DECOMPILATION_STATUS_PENDING) {
        return true;
    } else {
        /* error, success, or uninitiated */
        return false;
    }
}

void *ReaiDec::pollAndSignalFinished (ReaiDec *self) {
    if (!self) {
        return NULL;
    }

    // keep polling for decompilation
    while (self->isRunning()) {
        REAI_LOG_TRACE ("still polling... going for sleep for 2 seconds");
        rz_sys_sleep (2); // 2 seconds
    }

    // get decompiled code after finished
    RzCoreLocked     core (Core());
    CString          decomp = reai_plugin_get_decompiled_code_at (core, self->addr);
    RzAnnotatedCode *code   = NULL;
    if (decomp) {
        code = rz_annotated_code_new ((char *)decomp);
    } else {
        code = rz_annotated_code_new (strdup ("decompilation failed"));
    }

    // signal decompilation finished
    self->is_finished = true;
    self->finished (code);

    return self;
}

void ReaiDec::decompileAt (RVA rva_addr) {
    REAI_LOG_TRACE ("called");

    if (!is_finished) {
        REAI_LOG_WARN (
            "Decompilation for function at address %zx didn't finish. Starting new one : %zx",
            addr,
            rva_addr
        );
    }

    addr = rva_addr;
    RzCoreLocked              core (Core());
    ReaiAiDecompilationStatus status =
        reai_plugin_check_decompiler_status_running_at (core, rva_addr);

    if (status == REAI_AI_DECOMPILATION_STATUS_SUCCESS) {
        is_finished = true;
        REAI_LOG_INFO (
            "AI decompilation process already completed for function at given address (%zx).",
            rva_addr
        );

        CString str           = reai_response()->poll_ai_decompilation.data.decompilation;
        str                   = str ? str : "(null)";
        RzAnnotatedCode *code = rz_annotated_code_new (strdup (str));
        finished (code);
    } else if (status == REAI_AI_DECOMPILATION_STATUS_PENDING) {
        is_finished = false;
        REAI_LOG_INFO (
            "A decompilation process already exists for function at given address (%zx)",
            rva_addr
        );
        reai_plugin_add_bg_work ((RzThreadFunction)(ReaiDec::pollAndSignalFinished), this);
    } else {
        REAI_LOG_INFO ("START AI DECOMPILATION (%zx)", rva_addr);

        if (reai_plugin_decompile_at (core, rva_addr)) {
            is_finished = false;
            reai_plugin_add_bg_work ((RzThreadFunction)(ReaiDec::pollAndSignalFinished), this);
        } else {
            is_finished = true;
            REAI_LOG_ERROR ("Decompilation failed!");
            RzAnnotatedCode *code =
                rz_annotated_code_new (strdup ("failed to start decompilation."));
            finished (code);
        }
    }
}
