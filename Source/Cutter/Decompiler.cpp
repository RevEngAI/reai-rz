/**
 * @file      : Decompiler.hpp
 * @author    : Siddharth Mishra
 * @date      : 28/01/2025
 * @copyright : Copyright (c) 2025 RevEngAI. All Rights Reserved.
 * */

#include <Cutter/Decompiler.hpp>
#include <Plugin.h>
#include <Reai/Api/Types/AiDecompilation.h>

// rizin
#include <rz_util/rz_annotated_code.h>
#include <rz_util/rz_str.h>

// libc
#include <string.h>

ReaiDec::ReaiDec (QObject *parent) : Decompiler ("reaidec", "ReaiDec", parent) {}

bool ReaiDec::isRunning() {
    return !this->is_finished;
}

void ReaiDec::pollAndSignalFinished (RVA rva_addr) {
    // wait for other thread to finish running
    // XXX: Will this work???
    // while (!is_finished) {}

    // again decompilation started
    is_finished = false;

    RzCoreLocked core (Core());

    // get RevEngAI function Id for function to be decompiled
    FunctionId fn_id = rzLookupFunctionIdForFunctionAtAddr (core, rva_addr);
    if (!fn_id) {
        LOG_ERROR ("Decompilation failed @ 0x%llx => Reason : Function ID not found", rva_addr);
        RzAnnotatedCode *code = rz_annotated_code_new (strdup ("Failed to decompile. Failed to find function ID."));
        is_finished           = true;
        finished (code);
        return;
    }

    // Ignore first status value (suggested by revengai team)
    Status status = GetAiDecompilationStatus (GetConnection(), fn_id);
    if ((status & STATUS_MASK) == STATUS_ERROR) {
        if (!BeginAiDecompilation (GetConnection(), fn_id)) {
            RzAnnotatedCode *code = rz_annotated_code_new (strdup ("Failed to start AI decompilation process."));
            is_finished           = true;
            finished (code);
            return;
        }
        LOG_INFO ("Initial status was STATUS_ERROR and I started decompilation again");
    }

    // keep polling for AI decompilation status completion
    Str final_code = StrInit();
    while (true) {
        LOG_INFO ("Checking decompilation status...");

        status = GetAiDecompilationStatus (GetConnection(), fn_id);
        switch (status & STATUS_MASK) {
            case STATUS_ERROR : {
                RzAnnotatedCode *code = rz_annotated_code_new (
                    strdup ("AI decompilation process errored out. Failed to get AI decompilation")
                );
                is_finished = true;
                finished (code);
                return;
            }

            case STATUS_UNINITIALIZED :
                if (!BeginAiDecompilation (GetConnection(), fn_id)) {
                    RzAnnotatedCode *code = rz_annotated_code_new (strdup ("Failed to start AI decompilation."));
                    is_finished           = true;
                    finished (code);
                    return;
                }
                break;

            case STATUS_PENDING : {
                LOG_INFO ("AI decompilation status @ 0x%llx : Pending", rva_addr);
                break;
            }

            case STATUS_SUCCESS : {
                LOG_INFO ("Decompilation complete @ 0x%llx", rva_addr);

                // finally get ai-decompilation after finish
                AiDecompilation aidec = GetAiDecompilation (GetConnection(), fn_id, true);
                Str            *smry  = &aidec.raw_ai_summary;
                Str            *dec   = &aidec.raw_decompilation;

                // split summary into comments
                static i32 SOFT_LIMIT = 120;
                i32        l          = smry->length;
                char      *p          = smry->data;
                while (l > SOFT_LIMIT) {
                    char *p1 = strchr (p + SOFT_LIMIT, ' ');
                    if (p1) {
                        StrAppendf (&final_code, "// %.*s\n", (i32)(p1 - p), p);
                        p1++;
                        l -= (p1 - p);
                        p  = p1;
                    } else {
                        break;
                    }
                }
                StrAppendf (&final_code, "// %.*s\n\n", (i32)l, p);

                // decompilation code comes after summary
                StrMerge (&final_code, dec);

                LOG_INFO ("aidec.functions.length = %zu", aidec.functions.length);
                VecForeachIdx (&aidec.functions, function, idx, {
                    Str dname = StrInit();
                    StrPrintf (&dname, "<DISASM_FUNCTION_%llu>", idx);
                    StrReplace (&final_code, &dname, &function.name, -1);
                    StrDeinit (&dname);
                });

                LOG_INFO ("aidec.strings.length = %zu", aidec.strings.length);
                VecForeachIdx (&aidec.strings, string, idx, {
                    Str dname = StrInit();
                    StrPrintf (&dname, "<DISASM_STRING_%llu>", idx);
                    StrReplace (&final_code, &dname, &string.string, -1);
                    StrDeinit (&dname);
                });

                LOG_INFO ("aidec.unmatched.functions.length = %zu", aidec.unmatched.functions.length);
                VecForeachIdx (&aidec.unmatched.functions, function, idx, {
                    Str dname = StrInit();
                    StrPrintf (&dname, "<UNMATCHED_FUNCTION_%llu>", idx);
                    StrReplace (&final_code, &dname, &function.name, -1);
                    StrDeinit (&dname);
                });

                LOG_INFO ("aidec.unmatched.strings.length = %zu", aidec.unmatched.strings.length);
                VecForeachIdx (&aidec.unmatched.strings, string, idx, {
                    Str dname = StrInit();
                    StrPrintf (&dname, "<UNMATCHED_STRING_%llu>", idx);
                    StrReplace (&final_code, &dname, &string.value.str, -1);
                    StrDeinit (&dname);
                });

                LOG_INFO ("aidec.unmatched.vars.length = %zu", aidec.unmatched.vars.length);
                VecForeachIdx (&aidec.unmatched.vars, var, idx, {
                    Str dname = StrInit();
                    StrPrintf (&dname, "<VAR_%llu>", idx);
                    StrReplace (&final_code, &dname, &var.value.str, -1);
                    StrDeinit (&dname);
                });

                LOG_INFO ("aidec.unmatched.external_vars.length = %zu", aidec.unmatched.external_vars.length);
                VecForeachIdx (&aidec.unmatched.external_vars, var, idx, {
                    Str dname = StrInit();
                    StrPrintf (&dname, "<EXTERNAL_VARIABLE_%llu>", idx);
                    StrReplace (&final_code, &dname, &var.value.str, -1);
                    StrDeinit (&dname);
                });

                LOG_INFO ("aidec.unmatched.custom_types.length = %zu", aidec.unmatched.custom_types.length);
                VecForeachIdx (&aidec.unmatched.custom_types, var, idx, {
                    Str dname = StrInit();
                    StrPrintf (&dname, "<CUSTOM_TYPE_%llu>", idx);
                    StrReplace (&final_code, &dname, &var.value.str, -1);
                    StrDeinit (&dname);
                });


                RzAnnotatedCode *code = NULL;

                LOG_INFO ("Final Code : %s", final_code.data);

                if (aidec.decompilation.length) {
                    code = rz_annotated_code_new (strdup (final_code.data));

                    SymbolInfos all_functions = VecInit();
                    if (aidec.functions.length) {
                        VecMerge (&all_functions, &aidec.functions);
                    }
                    if (aidec.unmatched.functions.length) {
                        VecMerge (&all_functions, &aidec.unmatched.functions);
                    }

                    VecForeachPtr (&all_functions, function, {
                        if (function->is_external) {
                            LOG_INFO ("Skipping external function '%s'", function->name.data);
                            continue;
                        }

                        // Search for function and create annotation
                        char *name_beg = strstr (final_code.data, function->name.data);
                        while (name_beg) {
                            size name_len = function->name.length;
                            LOG_INFO ("Found string at offset %d", (i32)(name_beg - final_code.data));

                            // provide funciton address information through code annotation
                            RzCodeAnnotation a;
                            a.type             = RZ_CODE_ANNOTATION_TYPE_FUNCTION_NAME;
                            a.start            = name_beg - final_code.data;
                            a.end              = a.start + name_len;
                            a.reference.name   = strdup (function->name.data);
                            a.reference.offset = function->value.addr;
                            rz_annotated_code_add_annotation (code, &a);

                            LOG_INFO ("Annotating %s in (%zu, %zu)", function->name.data, a.start, a.end);

                            // syntax highlight function name
                            a.type                  = RZ_CODE_ANNOTATION_TYPE_SYNTAX_HIGHLIGHT;
                            a.syntax_highlight.type = RZ_SYNTAX_HIGHLIGHT_TYPE_FUNCTION_NAME;
                            rz_annotated_code_add_annotation (code, &a);

                            if (name_beg + name_len < final_code.data + final_code.length) {
                                name_beg = strstr (name_beg + name_len, function->name.data);
                            } else {
                                name_beg = NULL;
                            }
                        }
                    });

                    VecDeinit (&all_functions);
                } else {
                    code = rz_annotated_code_new (strdup ("/* empty */"));
                }

                StrDeinit (&final_code);

                is_finished = true;
                finished (code);

                AiDecompilationDeinit (&aidec);
                return;
            }
            default :
                StrDeinit (&final_code);
                LOG_FATAL ("Unreachable code reached. Invalid decompilation status = '%u'", status & STATUS_MASK);
                return;
        }
    }
}

class ReaiDecWorker : public QObject {
    Q_OBJECT
   public:
    ReaiDec *dec;
    RVA      rva_addr;

    explicit ReaiDecWorker (ReaiDec *d, RVA addr) : dec (d), rva_addr (addr) {}

   public slots:
    void doWork() {
        dec->pollAndSignalFinished (rva_addr);
        emit finished();
    }

   signals:
    void finished();
};


void ReaiDec::decompileAt (RVA rva_addr) {
    LOG_INFO ("decompile called @ 0x%llx", rva_addr);

    QThread       *thread = new QThread;
    ReaiDecWorker *worker = new ReaiDecWorker (this, rva_addr);

    worker->moveToThread (thread);

    connect (thread, &QThread::started, worker, &ReaiDecWorker::doWork);
    connect (worker, &ReaiDecWorker::finished, thread, &QThread::quit);
    connect (worker, &ReaiDecWorker::finished, worker, &QObject::deleteLater);
    connect (thread, &QThread::finished, thread, &QObject::deleteLater);

    thread->start();
}

#include "Decompiler.moc"
