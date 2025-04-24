/**
 * @file      : Decompiler.hpp
 * @author    : Siddharth Mishra
 * @date      : 28/01/2025
 * @copyright : Copyright (c) 2025 RevEngAI. All Rights Reserved.
 * */

#include <Cutter/Decompiler.hpp>
#include <Plugin.h>
#include <rz_util/rz_annotated_code.h>
#include <rz_util/rz_str.h>

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
        REAI_LOG_TRACE ("still polling...");
    }

    // get decompiled code and AI summary after finished
    RzCoreLocked core (Core());
    char        *decomp =
        (char *)reai_plugin_get_decompiled_code_at (core, self->addr, true /* summarize */);

    ReaiAiDecompFnMapVec *fn_map = reai_response()->poll_ai_decompilation.data.function_mapping;

    if (fn_map && decomp) {
        // Search and replace all tagged function names
        for (Size i = 0; i < fn_map->count; i++) {
            ReaiAiDecompFnMap *fn = fn_map->items + i;

            // Check if function actually does exist
            RzAnalysisFunction *afn = rz_analysis_get_function_byname (core->analysis, fn->name);
            if (afn) {
                // Create name for tagged function name
                // I knowingly didn't store these names, because I know these can be generated like this on the fly
                char fn_tagged_name[64] = {0};
                snprintf (fn_tagged_name, sizeof (fn_tagged_name), "<DISASM_FUNCTION_%zu>", i);

                // replace tagged names in form of <DISASM_FUNCTION_NN> with actual name
                char *tmp = rz_str_replace (decomp, fn_tagged_name, fn->name, true);
                if (tmp) {
                    decomp = tmp;
                }
            } else {
                REAI_LOG_ERROR (
                    "Function with %s name does not exist. Provided in function mapping fo AI "
                    "decomp.",
                    fn->name
                );
            }
        }

        // New annotated code
        RzAnnotatedCode *code = rz_annotated_code_new ((char *)decomp);

        // Create code annotations for all function names
        char *decomp_end = decomp + strlen (decomp);
        for (Size i = 0; i < fn_map->count; i++) {
            ReaiAiDecompFnMap *fn = fn_map->items + i;

            // Check if function actually does exist
            RzAnalysisFunction *afn = rz_analysis_get_function_at (
                core->analysis,
                fn->addr + reai_plugin_get_opened_binary_file_baseaddr (core)
            );
            if (afn) {
                // Search for function and create annotation
                char *name_beg = strstr (decomp, fn->name);
                while (name_beg) {
                    Size name_len = strlen (fn->name);
                    REAI_LOG_TRACE ("Found string at offset %d", name_beg - decomp);

                    RzCodeAnnotation a;
                    a.type             = RZ_CODE_ANNOTATION_TYPE_FUNCTION_NAME;
                    a.start            = name_beg - decomp;
                    a.end              = a.start + name_len;
                    a.reference.name   = strdup (fn->name);
                    a.reference.offset = fn->addr;
                    rz_annotated_code_add_annotation (code, &a);

                    REAI_LOG_TRACE ("Annotating %s in (%zu, %zu)", fn->name, a.start, a.end);

                    a.type                  = RZ_CODE_ANNOTATION_TYPE_SYNTAX_HIGHLIGHT;
                    a.start                 = name_beg - decomp;
                    a.end                   = a.start + name_len;
                    a.syntax_highlight.type = RZ_SYNTAX_HIGHLIGHT_TYPE_FUNCTION_NAME;
                    rz_annotated_code_add_annotation (code, &a);

                    if (name_beg + name_len < decomp_end) {
                        name_beg = strstr (name_beg + name_len, fn->name);
                    } else {
                        name_beg = NULL;
                    }
                }
            } else {
                REAI_LOG_ERROR (
                    "Function with %s name does not exist. Provided in function mapping fo AI "
                    "decomp.",
                    fn->name
                );
            }
        }

        // signal decompilation finished
        self->is_finished = true;
        self->finished (code);
    } else {
        if (decomp) {
            FREE (decomp);
        }
    }

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
