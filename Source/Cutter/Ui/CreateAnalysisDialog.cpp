/**
 * @file      : CreateAnalysisDialog.cpp
 * @date      : 11th Nov 2024
 * @author    : Siddharth Mishra (admin@brightprogrammer.in)
 * @copyright : Copyright (c) 2024 RevEngAI. All Rights Reserved.
 * */

/* plugin */
#include <Plugin.h>
#include <Reai/Api.h>
#include <Cutter/Ui/CreateAnalysisDialog.hpp>

/* qt */
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QPushButton>
#include <QLabel>

/* cutter */
#include <cutter/core/Cutter.h>
#include <librz/rz_analysis.h>

/* reai */
#include <Reai/Util/Vec.h>

CreateAnalysisDialog::CreateAnalysisDialog (QWidget* parent) : QDialog (parent) {
    mainLayout = new QVBoxLayout;
    setLayout (mainLayout);
    setWindowTitle ("Auto Analysis Settings");

    progNameInput = new QLineEdit (this);
    progNameInput->setPlaceholderText ("Program Name");
    mainLayout->addWidget (progNameInput);

    cmdLineArgsInput = new QLineEdit (this);
    cmdLineArgsInput->setPlaceholderText ("Command line arguments");
    mainLayout->addWidget (cmdLineArgsInput);

    aiModelInput = new QComboBox (this);
    aiModelInput->setPlaceholderText ("AI Model");

    ModelInfos* models = GetModels();
    VecForeachPtr (models, model, { aiModelInput->addItem (model->name.data); });

    mainLayout->addWidget (aiModelInput);

    isAnalysisPrivateCheckBox = new QCheckBox ("Create private analysis?", this);
    mainLayout->addWidget (isAnalysisPrivateCheckBox);
    isAnalysisPrivateCheckBox->setCheckState (Qt::CheckState::Checked);

    QHBoxLayout* btnLayout = new QHBoxLayout (this);
    mainLayout->addLayout (btnLayout);

    QPushButton* okBtn     = new QPushButton ("Ok");
    QPushButton* cancelBtn = new QPushButton ("Cancel");
    btnLayout->addWidget (cancelBtn);
    btnLayout->addWidget (okBtn);

    connect (okBtn, &QPushButton::clicked, this, &CreateAnalysisDialog::on_CreateAnalysis);
    connect (cancelBtn, &QPushButton::clicked, this, &QDialog::close);
}

void CreateAnalysisDialog::on_CreateAnalysis() {
    RzCoreLocked core (Core());

    QByteArray aiModelName = aiModelInput->currentText().toLatin1();
    QByteArray progName    = progNameInput->text().toLatin1();
    QByteArray cmdLineArgs = cmdLineArgsInput->text().toLatin1();

    if (progName.isEmpty()) {
        QMessageBox::warning (this, "Create Analysis", "Program Name cannot be empty.", QMessageBox::Ok);
        return;
    }

    if (aiModelName.isEmpty()) {
        QMessageBox::warning (
            this,
            "Create Analysis",
            "Please select an AI model to be used to create analysis.",
            QMessageBox::Ok
        );
        return;
    }

    NewAnalysisRequest new_analysis = NewAnalysisRequestInit();

    new_analysis.is_private   = isAnalysisPrivateCheckBox->checkState() == Qt::CheckState::Checked;
    new_analysis.ai_model     = StrInitFromZstr (aiModelName.constData());
    new_analysis.file_name    = StrInitFromZstr (progName.constData());
    new_analysis.cmdline_args = StrInitFromZstr (cmdLineArgs.constData());

    BinaryId bin_id = 0;

    Str path            = rzGetCurrentBinaryPath (core);
    new_analysis.sha256 = UploadFile (GetConnection(), path);
    StrDeinit (&path);

    if (!new_analysis.sha256.length) {
        APPEND_ERROR ("Failed to upload binary");
    } else {
        new_analysis.base_addr = rzGetCurrentBinaryBaseAddr (core);
        new_analysis.functions = VecInitWithDeepCopy_T (&new_analysis.functions, NULL, FunctionInfoDeinit);

        RzListIter* fn_iter = NULL;
        void*       it_fn   = NULL;
        rz_list_foreach (core->analysis->fcns, fn_iter, it_fn) {
            RzAnalysisFunction* fn = (RzAnalysisFunction*)it_fn;
            FunctionInfo        fi = {};
            fi.symbol.is_addr      = true;
            fi.symbol.is_external  = false;
            fi.symbol.value.addr   = fn->addr;
            fi.symbol.name         = StrInitFromZstr (fn->name);
            fi.size                = rz_analysis_function_size_from_entry (fn);
            VecPushBack (&new_analysis.functions, fi);
        }
        bin_id = CreateNewAnalysis (GetConnection(), &new_analysis);
        SetBinaryId (bin_id);
    }

    NewAnalysisRequestDeinit (&new_analysis);

    if (!bin_id) {
        DISPLAY_ERROR ("Failed to create new analysis");
    }

    close();
}
