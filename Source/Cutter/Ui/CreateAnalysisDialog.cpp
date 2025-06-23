/**
 * @file      : CreateAnalysisDialog.cpp
 * @date      : 11th Nov 2024
 * @author    : Siddharth Mishra (admin@brightprogrammer.in)
 * @copyright : Copyright (c) 2024 RevEngAI. All Rights Reserved.
 * */

/* qt */
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QPushButton>
#include <QLabel>
#include <QMessageBox>
#include <QThread>

/* cutter */
#include <cutter/core/Cutter.h>
#include <librz/rz_analysis.h>

#include <Plugin.h>
#include <Reai/Api.h>
#include <Reai/Util/Vec.h>
#include <Cutter/Ui/CreateAnalysisDialog.hpp>
#include <Cutter/Cutter.hpp> // For global status functions

CreateAnalysisDialog::CreateAnalysisDialog (QWidget* parent)
    : QDialog (parent), workerThread (nullptr), worker (nullptr) {
    mainLayout = new QVBoxLayout;
    setLayout (mainLayout);
    setWindowTitle ("Create New Analysis");
    setMinimumSize (400, 300);

    progNameInput = new QLineEdit (this);
    progNameInput->setPlaceholderText ("Program Name");
    mainLayout->addWidget (progNameInput);

    cmdLineArgsInput = new QLineEdit (this);
    cmdLineArgsInput->setPlaceholderText ("Command line arguments");
    mainLayout->addWidget (cmdLineArgsInput);

    aiModelInput = new QComboBox (this);
    aiModelInput->setPlaceholderText ("AI Model");

    // Load models (this could also be made async, but it's usually fast)
    ModelInfos* models = GetModels();
    VecForeachPtr (models, model, { aiModelInput->addItem (model->name.data); });

    mainLayout->addWidget (aiModelInput);

    isAnalysisPrivateCheckBox = new QCheckBox ("Create private analysis?", this);
    mainLayout->addWidget (isAnalysisPrivateCheckBox);
    isAnalysisPrivateCheckBox->setCheckState (Qt::CheckState::Checked);

    // Progress UI elements (initially hidden)
    progressBar = new QProgressBar (this);
    progressBar->setVisible (false);
    progressBar->setRange (0, 100);
    mainLayout->addWidget (progressBar);

    statusLabel = new QLabel (this);
    statusLabel->setVisible (false);
    statusLabel->setWordWrap (true);
    mainLayout->addWidget (statusLabel);

    // Button layout
    QHBoxLayout* btnLayout = new QHBoxLayout (this);
    mainLayout->addLayout (btnLayout);

    okButton           = new QPushButton ("Create Analysis");
    cancelDialogButton = new QPushButton ("Cancel");
    cancelButton       = new QPushButton ("Cancel Operation");
    cancelButton->setVisible (false);

    btnLayout->addWidget (cancelDialogButton);
    btnLayout->addWidget (cancelButton);
    btnLayout->addWidget (okButton);

    connect (okButton, &QPushButton::clicked, this, &CreateAnalysisDialog::on_CreateAnalysis);
    connect (cancelDialogButton, &QPushButton::clicked, this, &QDialog::reject);
    connect (cancelButton, &QPushButton::clicked, this, &CreateAnalysisDialog::on_CancelAnalysis);
}

CreateAnalysisDialog::~CreateAnalysisDialog() {
    cancelAsyncCreateAnalysis();
}

void CreateAnalysisDialog::on_CreateAnalysis() {
    rzClearMsg();

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

    startAsyncCreateAnalysis();
}

void CreateAnalysisDialog::on_CancelAnalysis() {
    cancelAsyncCreateAnalysis();
}

void CreateAnalysisDialog::startAsyncCreateAnalysis() {
    if (workerThread && workerThread->isRunning()) {
        return; // Already running
    }

    // Prepare request data
    CreateAnalysisRequest request;
    request.aiModelName = aiModelInput->currentText();
    request.progName    = progNameInput->text();
    request.cmdLineArgs = cmdLineArgsInput->text();
    request.isPrivate   = isAnalysisPrivateCheckBox->checkState() == Qt::CheckState::Checked;

    // Get binary path and base address
    {
        RzCoreLocked core (Core());
        Str          path  = rzGetCurrentBinaryPath (core);
        request.binaryPath = QString (path.data);
        request.baseAddr   = rzGetCurrentBinaryBaseAddr (core);
        StrDeinit (&path);

        // Collect function information
        request.functions = VecInitWithDeepCopy_T (&request.functions, NULL, FunctionInfoDeinit);

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
            VecPushBack (&request.functions, fi);
        }
    }

    // Setup UI for async operation
    setupProgressUI();

    // Show global status
    ShowGlobalStatus ("Analysis Creation", "Preparing analysis...", 0);

    // Create worker thread
    workerThread = new QThread (this);
    worker       = new CreateAnalysisWorker();
    worker->moveToThread (workerThread);

    // Connect signals
    connect (workerThread, &QThread::started, [this, request]() { worker->performCreateAnalysis (request); });

    connect (worker, &CreateAnalysisWorker::progress, this, &CreateAnalysisDialog::onAnalysisProgress);
    connect (worker, &CreateAnalysisWorker::analysisFinished, this, &CreateAnalysisDialog::onAnalysisFinished);
    connect (worker, &CreateAnalysisWorker::analysisError, this, &CreateAnalysisDialog::onAnalysisError);

    connect (workerThread, &QThread::finished, [this]() {
        if (worker) {
            worker->deleteLater();
            worker = nullptr;
        }
        workerThread = nullptr;
        hideProgressUI();
        HideGlobalStatus(); // Hide global status when done
    });

    // Start the worker thread
    workerThread->start();
}

void CreateAnalysisDialog::cancelAsyncCreateAnalysis() {
    if (worker) {
        worker->cancel();
    }

    if (workerThread) {
        if (workerThread->isRunning()) {
            // Give it 3 seconds to finish gracefully
            if (!workerThread->wait (3000)) {
                // Force terminate if it doesn't finish
                workerThread->terminate();
                workerThread->wait (1000);
            }
        }

        if (worker) {
            worker->deleteLater();
            worker = nullptr;
        }

        workerThread = nullptr;
    }

    hideProgressUI();
    HideGlobalStatus();
    ShowGlobalMessage ("Analysis creation cancelled", 3000);
}

void CreateAnalysisDialog::setupProgressUI() {
    progressBar->setVisible (true);
    progressBar->setValue (0);
    statusLabel->setVisible (true);
    statusLabel->setText ("Preparing analysis...");
    cancelButton->setVisible (true);

    setUIEnabled (false);
}

void CreateAnalysisDialog::hideProgressUI() {
    progressBar->setVisible (false);
    statusLabel->setVisible (false);
    cancelButton->setVisible (false);

    setUIEnabled (true);
}

void CreateAnalysisDialog::setUIEnabled (bool enabled) {
    progNameInput->setEnabled (enabled);
    cmdLineArgsInput->setEnabled (enabled);
    aiModelInput->setEnabled (enabled);
    isAnalysisPrivateCheckBox->setEnabled (enabled);
    okButton->setEnabled (enabled);
}

void CreateAnalysisDialog::onAnalysisProgress (int percentage, const QString& message) {
    progressBar->setValue (percentage);
    statusLabel->setText (message);

    // Update global status
    UpdateGlobalStatus (message, percentage);
}

void CreateAnalysisDialog::onAnalysisFinished (const CreateAnalysisResult& result) {
    if (result.success) {
        SetBinaryId (result.binaryId);

        // Start polling for analysis completion
        QString analysisName = progNameInput->text();
        StartGlobalAnalysisPolling (result.binaryId, analysisName);

        // Show success notification
        ShowGlobalNotification (
            "Analysis Created Successfully",
            QString ("Analysis created with Binary ID: %1. You'll be notified when analysis is complete.")
                .arg (result.binaryId),
            true
        );

        accept(); // Close dialog with success
    } else {
        // Show error notification
        ShowGlobalNotification (
            "Analysis Creation Failed",
            QString ("Failed to create analysis: %1").arg (result.errorMessage),
            false
        );

        QMessageBox::critical (
            this,
            "Analysis Creation Failed",
            QString ("Failed to create analysis: %1").arg (result.errorMessage),
            QMessageBox::Ok
        );
    }
}

void CreateAnalysisDialog::onAnalysisError (const QString& error) {
    // Show error notification
    ShowGlobalNotification (
        "Analysis Creation Error",
        QString ("Error during analysis creation: %1").arg (error),
        false
    );

    QMessageBox::critical (
        this,
        "Analysis Creation Error",
        QString ("Error during analysis creation: %1").arg (error),
        QMessageBox::Ok
    );
}

// Worker implementation
void CreateAnalysisWorker::performCreateAnalysis (const CreateAnalysisRequest& request) {
    m_cancelled = false;
    CreateAnalysisResult result;
    result.success  = false;
    result.binaryId = 0;

    try {
        emitProgress (10, "Preparing analysis request...");

        if (m_cancelled) {
            emit analysisError ("Operation cancelled");
            return;
        }

        // Prepare new analysis request
        NewAnalysisRequest new_analysis = NewAnalysisRequestInit();
        new_analysis.is_private         = request.isPrivate;
        new_analysis.ai_model           = StrInitFromZstr (request.aiModelName.toLatin1().constData());
        new_analysis.file_name          = StrInitFromZstr (request.progName.toLatin1().constData());
        new_analysis.cmdline_args       = StrInitFromZstr (request.cmdLineArgs.toLatin1().constData());
        new_analysis.base_addr          = request.baseAddr;
        new_analysis.functions          = request.functions; // Copy the functions

        emitProgress (30, "Uploading binary file...");

        if (m_cancelled) {
            NewAnalysisRequestDeinit (&new_analysis);
            emit analysisError ("Operation cancelled");
            return;
        }

        // Upload file (this is the slow part)
        Str binaryPath      = StrInitFromZstr (request.binaryPath.toLatin1().constData());
        new_analysis.sha256 = UploadFile (GetConnection(), binaryPath);
        StrDeinit (&binaryPath);

        if (!new_analysis.sha256.length) {
            NewAnalysisRequestDeinit (&new_analysis);
            result.errorMessage = "Failed to upload binary file";
            emit analysisError (result.errorMessage);
            return;
        }

        emitProgress (70, "Creating analysis on server...");

        if (m_cancelled) {
            NewAnalysisRequestDeinit (&new_analysis);
            emit analysisError ("Operation cancelled");
            return;
        }

        // Create analysis
        BinaryId bin_id = CreateNewAnalysis (GetConnection(), &new_analysis);
        NewAnalysisRequestDeinit (&new_analysis);

        if (!bin_id) {
            result.errorMessage = "Failed to create analysis on server";
            emit analysisError (result.errorMessage);
            return;
        }

        emitProgress (100, "Analysis created successfully!");

        result.success  = true;
        result.binaryId = bin_id;
        emit analysisFinished (result);

    } catch (const std::exception& e) {
        result.errorMessage = QString ("Exception during analysis creation: %1").arg (e.what());
        emit analysisError (result.errorMessage);
    }
}
