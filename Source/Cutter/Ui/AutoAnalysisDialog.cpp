/**
 * @file      : AutoAnalysisDialog.cpp
 * @date      : 11th Nov 2024
 * @author    : Siddharth Mishra (admin@brightprogrammer.in)
 * @copyright : Copyright (c) 2024 RevEngAI. All Rights Reserved.
 * */

/* qt */
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QScrollArea>
#include <QPushButton>
#include <QLabel>
#include <QMessageBox>
#include <QProgressBar>
#include <QApplication>
#include <QTimer>
#include <QAbstractItemView>
#include <QBrush>

/* cutter */
#include <cutter/core/Cutter.h>
#include <librz/rz_analysis.h>

#include <Plugin.h>
#include <Reai/Api.h>
#include <Reai/Util/Vec.h>
#include <Reai/Log.h>
#include <Cutter/Ui/AutoAnalysisDialog.hpp>

AutoAnalysisDialog::AutoAnalysisDialog (QWidget *parent)
    : QDialog (parent), analysisWorker (nullptr), workerThread (nullptr) {
    setupUI();
}

AutoAnalysisDialog::~AutoAnalysisDialog() {
    // Clean up async operations first and wait for completion
    if (workerThread && workerThread->isRunning()) {
        if (analysisWorker) {
            analysisWorker->cancelAnalysis();
        }

        workerThread->quit();
        if (!workerThread->wait (2000)) { // Wait 2 seconds max
            workerThread->terminate();
            workerThread->wait (500);     // Wait another 500ms after terminate
        }
    }
}

void AutoAnalysisDialog::setupUI() {
    setWindowTitle ("Auto Analysis Settings");
    setModal (true);
    resize (400, 200);

    mainLayout = new QVBoxLayout (this);
    setLayout (mainLayout);

    // Similarity slider
    QLabel *sliderLabel = new QLabel ("Minimum Similarity Threshold:");
    mainLayout->addWidget (sliderLabel);

    similaritySlider = new QSlider (Qt::Horizontal);
    similaritySlider->setMinimum (1);
    similaritySlider->setMaximum (100);
    similaritySlider->setValue (90);
    mainLayout->addWidget (similaritySlider);

    QLabel *confidenceLabel = new QLabel ("90% min confidence");
    mainLayout->addWidget (confidenceLabel);
    connect (similaritySlider, &QSlider::valueChanged, [confidenceLabel] (int value) {
        confidenceLabel->setText (QString ("%1% min confidence").arg (value));
    });

    // Debug filter checkbox
    enableDebugFilterCheckBox = new QCheckBox ("Restrict results to debug symbols only?", this);
    mainLayout->addWidget (enableDebugFilterCheckBox);
    enableDebugFilterCheckBox->setCheckState (Qt::CheckState::Checked);

    // Progress bar (initially hidden)
    progressBar = new QProgressBar (this);
    progressBar->setVisible (false);
    mainLayout->addWidget (progressBar);

    // Status label
    statusLabel = new QLabel ("Ready to start analysis", this);
    statusLabel->setStyleSheet ("color: #666666;");
    mainLayout->addWidget (statusLabel);

    // Button layout
    QHBoxLayout *btnLayout = new QHBoxLayout();
    mainLayout->addLayout (btnLayout);

    cancelButton = new QPushButton ("Cancel");
    okButton     = new QPushButton ("Start Analysis");
    btnLayout->addWidget (cancelButton);
    btnLayout->addWidget (okButton);

    // Connect signals
    connect (okButton, &QPushButton::clicked, this, &AutoAnalysisDialog::on_PerformAutoAnalysis);
    connect (cancelButton, &QPushButton::clicked, this, &AutoAnalysisDialog::on_CancelAnalysis);
}

void AutoAnalysisDialog::on_PerformAutoAnalysis() {
    startAsyncAnalysis();
}

void AutoAnalysisDialog::on_CancelAnalysis() {
    if (workerThread && workerThread->isRunning()) {
        cancelAsyncAnalysis();
    } else {
        reject(); // Close dialog
    }
}

void AutoAnalysisDialog::startAsyncAnalysis() {
    // Prepare request
    AutoAnalysisRequest request;
    request.minSimilarity         = similaritySlider->value() / 100.0f;
    request.debugSymbolsOnly      = enableDebugFilterCheckBox->checkState() == Qt::CheckState::Checked;
    request.maxResultsPerFunction = 10;

    // Pre-fetch functions and base address in main thread to avoid core access in worker
    request.functions = Core()->getAllFunctions();
    request.baseAddr  = 0; // TODO: Get actual base address from Core() when safe

    if (request.functions.isEmpty()) {
        QMessageBox::critical (this, "Analysis Error", "No functions found in the current analysis.");
        return;
    }

    // Show progress
    showProgress (0, "Initializing analysis...");

    // Create worker and thread
    workerThread   = new QThread();
    analysisWorker = new AutoAnalysisWorker();
    analysisWorker->moveToThread (workerThread);

    // Connect signals
    connect (workerThread, &QThread::started, [this, request]() {
        if (analysisWorker) {
            analysisWorker->performAnalysis (request);
        }
    });

    connect (analysisWorker, &AutoAnalysisWorker::analysisFinished, this, &AutoAnalysisDialog::onAnalysisFinished);
    connect (analysisWorker, &AutoAnalysisWorker::analysisError, this, &AutoAnalysisDialog::onAnalysisError);
    connect (analysisWorker, &AutoAnalysisWorker::progressUpdate, this, &AutoAnalysisDialog::onProgressUpdate);

    // Clean up when thread finishes
    connect (workerThread, &QThread::finished, [this]() {
        if (analysisWorker) {
            analysisWorker->deleteLater();
            analysisWorker = nullptr;
        }
        if (workerThread) {
            workerThread->deleteLater();
            workerThread = nullptr;
        }
    });

    // Start the worker thread
    workerThread->start();
}

void AutoAnalysisDialog::cancelAsyncAnalysis() {
    if (analysisWorker) {
        analysisWorker->cancelAnalysis();
    }

    if (workerThread && workerThread->isRunning()) {
        // First try to quit gracefully
        workerThread->quit();

        // Wait for the thread to finish, but don't wait forever
        if (!workerThread->wait (3000)) { // Wait up to 3 seconds
            // If it doesn't finish gracefully, force terminate
            qWarning() << "Analysis worker thread didn't quit gracefully, terminating...";
            workerThread->terminate();
            workerThread->wait (1000); // Give it another second to clean up
        }
    }

    hideProgress();
    statusLabel->setText ("Analysis cancelled");
}

void AutoAnalysisDialog::showProgress (int percentage, const QString &status) {
    progressBar->setVisible (true);
    progressBar->setValue (percentage);
    statusLabel->setText (status);
    okButton->setEnabled (false);
    okButton->setText ("Processing...");
}

void AutoAnalysisDialog::hideProgress() {
    progressBar->setVisible (false);
    okButton->setEnabled (true);
    okButton->setText ("Start Analysis");
}

void AutoAnalysisDialog::onAnalysisFinished (const AutoAnalysisResult &result) {
    hideProgress();

    if (result.success) {
        if (result.proposedRenames.isEmpty()) {
            statusLabel->setText ("Analysis completed - no similar functions found");
            QMessageBox::information (
                this,
                "Auto Analysis Complete",
                "Analysis completed successfully, but no functions with sufficient similarity were found."
            );
        } else {
            statusLabel->setText (
                QString ("Analysis completed - found %1 potential renames").arg (result.proposedRenames.size())
            );

            // Show confirmation dialog
            RenameConfirmationDialog confirmDialog (result.proposedRenames, this);
            if (confirmDialog.exec() == QDialog::Accepted) {
                // User approved some renames, apply them
                QList<ProposedRename> approvedRenames = confirmDialog.getApprovedRenames();
                applyRenames (approvedRenames);
            } else {
                // User cancelled, just close
                statusLabel->setText ("Analysis cancelled by user");
            }
        }
    } else {
        statusLabel->setText ("Analysis failed");
        QMessageBox::critical (this, "Analysis Failed", result.errorMessage);
    }
}

void AutoAnalysisDialog::onAnalysisError (const QString &error) {
    hideProgress();
    statusLabel->setText ("Analysis failed");

    QMessageBox::critical (this, "Analysis Error", error);
}

void AutoAnalysisDialog::onProgressUpdate (int percentage, const QString &status) {
    showProgress (percentage, status);
}

void AutoAnalysisDialog::applyRenames (const QList<ProposedRename> &renames) {
    if (renames.isEmpty()) {
        statusLabel->setText ("No renames to apply");
        return;
    }

    showProgress (0, "Applying function renames...");

    int totalRenames = renames.size();
    int appliedCount = 0;
    int failedCount  = 0;

    for (int i = 0; i < renames.size(); ++i) {
        const ProposedRename &rename = renames[i];

        showProgress (
            (i * 100) / totalRenames,
            QString ("Renaming %1 to %2...").arg (rename.originalName).arg (rename.proposedName)
        );

        // Apply the rename via RevEngAI API
        Str name = StrInitFromZstr (rename.proposedName.toUtf8().data());
        if (RenameFunction (GetConnection(), rename.functionId, name)) {
            Core()->renameFunction (rename.functionId, rename.proposedName);
            appliedCount++;
            LOG_INFO (
                "Successfully renamed '%s' to '%s'",
                rename.originalName.toStdString().c_str(),
                rename.proposedName.toStdString().c_str()
            );
        } else {
            failedCount++;
            LOG_ERROR (
                "Failed to rename '%s' to '%s'",
                rename.originalName.toStdString().c_str(),
                rename.proposedName.toStdString().c_str()
            );
        }

        StrDeinit (&name);
    }

    showProgress (100, "Refreshing UI...");

    hideProgress();

    // Show final result
    QString message;
    if (failedCount == 0) {
        message =
            QString (
                "Successfully renamed %1 functions.\n\nThe UI has been refreshed to show the updated function names."
            )
                .arg (appliedCount);
        statusLabel->setText (QString ("Successfully renamed %1 functions").arg (appliedCount));
    } else {
        message = QString (
                      "Renamed %1 functions successfully, %2 failed.\n\nCheck the logs for details on failed "
                      "renames.\nThe UI has been refreshed to show the updated function names."
        )
                      .arg (appliedCount)
                      .arg (failedCount);
        statusLabel->setText (QString ("Renamed %1 functions (%2 failed)").arg (appliedCount).arg (failedCount));
    }

    QMessageBox::information (this, "Rename Complete", message);
    accept(); // Close dialog
}

// AutoAnalysisWorker implementation
void AutoAnalysisWorker::performAnalysis (const AutoAnalysisRequest &request) {
    m_cancelled = false;
    AutoAnalysisResult result;

    try {
        emitProgress (5, "Checking binary and analysis status...");

        if (m_cancelled) {
            emit analysisError ("Analysis cancelled");
            return;
        }

        // Check if we can work with the current analysis
        BinaryId binaryId = GetBinaryId();
        if (!binaryId || !rzCanWorkWithAnalysis (binaryId, true)) {
            emit analysisError (
                "Please apply an existing and complete analysis or create a new one and wait for its completion."
            );
            return;
        }

        emitProgress (10, "Setting up batch annotation request...");

        if (m_cancelled) {
            emit analysisError ("Analysis cancelled");
            return;
        }

        // Setup batch annotation request
        BatchAnnSymbolRequest batchAnn = BatchAnnSymbolRequestInit();
        batchAnn.debug_symbols_only    = request.debugSymbolsOnly;
        batchAnn.limit                 = request.maxResultsPerFunction;
        batchAnn.distance              = 1.0 - request.minSimilarity;
        batchAnn.analysis_id           = AnalysisIdFromBinaryId (GetConnection(), binaryId);

        if (!batchAnn.analysis_id) {
            BatchAnnSymbolRequestDeinit (&batchAnn);
            emit analysisError ("Failed to convert binary id to analysis id.");
            return;
        }

        emitProgress (20, "Requesting similarity matches from RevEngAI...");

        if (m_cancelled) {
            BatchAnnSymbolRequestDeinit (&batchAnn);
            emit analysisError ("Analysis cancelled");
            return;
        }

        // Get similarity matches
        AnnSymbols map = GetBatchAnnSymbols (GetConnection(), &batchAnn);
        BatchAnnSymbolRequestDeinit (&batchAnn);

        if (!map.length) {
            VecDeinit (&map);
            emit analysisError ("Failed to get similarity matches.");
            return;
        }

        emitProgress (40, "Getting function information...");

        // Get RevEngAI functions for lookup
        FunctionInfos revengaiFunctions = GetBasicFunctionInfoUsingBinaryId (GetConnection(), binaryId);
        if (!revengaiFunctions.length) {
            VecDeinit (&map);
            emit analysisError ("Failed to get function info list from RevEng.AI servers.");
            return;
        }

        emitProgress (60, "Processing functions and finding matches...");

        int                   totalFunctions     = request.functions.length();
        int                   processedFunctions = 0;
        QList<ProposedRename> proposedRenames;

        for (const FunctionDescription &fn : request.functions) {
            if (m_cancelled) {
                VecDeinit (&map);
                VecDeinit (&revengaiFunctions);
                emit analysisError ("Analysis cancelled");
                return;
            }

            processedFunctions++;
            int progressPercent = 60 + (processedFunctions * 35) / totalFunctions;
            emitProgress (
                progressPercent,
                QString ("Processing function %1/%2: %3").arg (processedFunctions).arg (totalFunctions).arg (fn.name)
            );

            FunctionId id = lookupFunctionId (request.functions, fn, revengaiFunctions, request.baseAddr);
            if (id) {
                AnnSymbol *bestMatch = rzGetMostSimilarFunctionSymbol (&map, id);
                if (bestMatch) {
                    // Create proposed rename instead of applying immediately
                    ProposedRename rename;
                    rename.functionId   = id;
                    rename.originalName = fn.name;
                    rename.proposedName = QString::fromUtf8 (bestMatch->function_name.data);
                    rename.address      = fn.offset;
                    rename.similarity   = (1.0f - bestMatch->distance) * 100.0f; // Convert to percentage
                    rename.selected     = true;                                  // Default to selected

                    proposedRenames.append (rename);

                    LOG_INFO (
                        "Proposed rename: '%s' -> '%s' (%.1f%% similarity)",
                        fn.name.toStdString().c_str(),
                        bestMatch->function_name.data,
                        rename.similarity
                    );
                }
            }
        }

        VecDeinit (&map);
        VecDeinit (&revengaiFunctions);

        emitProgress (100, "Analysis completed");

        result.success         = true;
        result.proposedRenames = proposedRenames;
        emit analysisFinished (result);

    } catch (...) {
        emit analysisError ("Unexpected error during analysis");
    }
}

// Custom function ID lookup that works with FunctionDescription
FunctionId AutoAnalysisWorker::lookupFunctionId (
    const QList<FunctionDescription> &cutterFunctions,
    const FunctionDescription        &targetFunction,
    const FunctionInfos              &revengaiFunctions,
    u64                               baseAddr
) {
    // Look up the function ID by matching addresses
    // targetFunction.offset is the virtual address in Cutter
    u64 targetAddr = targetFunction.offset;

    FunctionId id = 0;
    VecForeachPtr (&revengaiFunctions, fn, {
        // fn->symbol.value.addr is the RevEngAI function address (without base)
        // Add base address to match with Cutter's virtual address
        if (targetAddr == fn->symbol.value.addr + baseAddr) {
            LOG_INFO (
                "CutterFunction -> [FunctionName, FunctionID] :: \"%s\" -> [\"%s\", %llu]",
                targetFunction.name.toStdString().c_str(),
                fn->symbol.name.data,
                fn->id
            );
            id = fn->id;
            break;
        }
    });

    if (!id) {
        LOG_ERROR (
            "Function ID not found for \"%s\" at address 0x%llx",
            targetFunction.name.toStdString().c_str(),
            targetAddr
        );
    }

    return id;
}
