/**
 * @file      : RecentAnalysisDialog.cpp
 * @date      : 8th Apr 2025
 * @author    : Siddharth Mishra (admin@brightprogrammer.in)
 * @copyright : Copyright (c) 2025 RevEngAI. All Rights Reserved.
 * */

/* qt */
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QScrollArea>
#include <QPushButton>
#include <QHeaderView>
#include <QDesktopServices>
#include <QDialogButtonBox>
#include <QUrl>
#include <QLabel>
#include <QMessageBox>

/* cutter */
#include <cutter/core/Cutter.h>
#include <librz/rz_analysis.h>

/* reai */
#include <Reai/Util/Vec.h>
#include <Plugin.h>
#include <Reai/Api.h>
#include <Cutter/Ui/RecentAnalysisDialog.hpp>
#include <Cutter/Cutter.hpp>

RecentAnalysisDialog::RecentAnalysisDialog (QWidget *parent) : QDialog (parent) {
    setMinimumSize (QSize (960, 540));

    mainLayout = new QVBoxLayout;
    setLayout (mainLayout);
    setWindowTitle ("Recent Analysis");

    headerLabels << "name";
    headerLabels << "binary id";
    headerLabels << "analysis id";
    headerLabels << "status";
    headerLabels << "owner";
    headerLabels << "created at";
    headerLabels << "sha256";

    table = new QTableWidget;
    table->setEditTriggers (QAbstractItemView::NoEditTriggers);
    table->horizontalHeader()->setSectionResizeMode (QHeaderView::Stretch);
    table->setColumnCount (7);
    table->setHorizontalHeaderLabels (headerLabels);
    table->horizontalHeader()->setSectionResizeMode (QHeaderView::Stretch);
    mainLayout->addWidget (table);

    // Add progress UI components (initially hidden)
    progressBar = new QProgressBar (this);
    progressBar->setVisible (false);
    mainLayout->addWidget (progressBar);

    statusLabel = new QLabel (this);
    statusLabel->setVisible (false);
    mainLayout->addWidget (statusLabel);

    cancelButton = new QPushButton ("Cancel Operation", this);
    cancelButton->setVisible (false);
    mainLayout->addWidget (cancelButton);

    connect (table, &QTableWidget::cellDoubleClicked, this, &RecentAnalysisDialog::on_TableCellDoubleClick);
    connect (cancelButton, &QPushButton::clicked, this, &RecentAnalysisDialog::cancelAsyncOperation);

    // Start async operation immediately
    startAsyncGetRecentAnalysis();
}

RecentAnalysisDialog::~RecentAnalysisDialog() {
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
}

void RecentAnalysisDialog::startAsyncGetRecentAnalysis() {
    if (workerThread && workerThread->isRunning()) {
        return; // Already running
    }

    // Setup UI for async operation
    setupProgressUI();

    // Show global status
    ShowGlobalStatus ("Recent Analysis", "Fetching recent analyses...", 0);

    // Create worker thread
    workerThread = new QThread (this);
    worker       = new RecentAnalysisWorker();
    worker->moveToThread (workerThread);

    // Connect signals
    connect (workerThread, &QThread::started, worker, &RecentAnalysisWorker::performGetRecentAnalysis);
    connect (worker, &RecentAnalysisWorker::progress, this, &RecentAnalysisDialog::onAnalysisProgress);
    connect (worker, &RecentAnalysisWorker::analysisFinished, this, &RecentAnalysisDialog::onAnalysisFinished);
    connect (worker, &RecentAnalysisWorker::analysisError, this, &RecentAnalysisDialog::onAnalysisError);

    // CRITICAL: Tell the thread to quit when worker finishes (this was missing!)
    connect (worker, &RecentAnalysisWorker::analysisFinished, workerThread, &QThread::quit);
    connect (worker, &RecentAnalysisWorker::analysisError, workerThread, &QThread::quit);

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

void RecentAnalysisDialog::cancelAsyncOperation() {
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
    ShowGlobalMessage ("Recent analysis fetch cancelled", 3000);
}

void RecentAnalysisDialog::setupProgressUI() {
    progressBar->setVisible (true);
    progressBar->setValue (0);
    statusLabel->setVisible (true);
    statusLabel->setText ("Fetching recent analyses...");
    cancelButton->setVisible (true);

    setUIEnabled (false);
}

void RecentAnalysisDialog::hideProgressUI() {
    progressBar->setVisible (false);
    statusLabel->setVisible (false);
    cancelButton->setVisible (false);

    setUIEnabled (true);
}

void RecentAnalysisDialog::setUIEnabled (bool enabled) {
    table->setEnabled (enabled);
}

void RecentAnalysisDialog::onAnalysisProgress (int percentage, const QString &message) {
    progressBar->setValue (percentage);
    statusLabel->setText (message);

    // Update global status
    UpdateGlobalStatus (message, percentage);
}

void RecentAnalysisDialog::onAnalysisFinished (const AnalysisInfos &analyses) {
    table->clearContents();
    table->setRowCount (0);

    VecForeachPtr (&analyses, recent_analysis, {
        QStringList row;
        row << recent_analysis->binary_name.data;
        row << QString::number (recent_analysis->binary_id);
        row << QString::number (recent_analysis->analysis_id);
        Str status = StrInit();
        StatusToStr (recent_analysis->status, &status);
        row << status.data;
        StrDeinit (&status);
        row << recent_analysis->username.data;
        row << recent_analysis->creation.data;
        row << recent_analysis->sha256.data;

        addNewRowToResultsTable (table, row);
    });

    ShowGlobalMessage (QString ("Loaded %1 recent analyses").arg (analyses.length), 3000);

    VecDeinit (&analyses);
}

void RecentAnalysisDialog::onAnalysisError (const QString &error) {
    // Show error notification
    ShowGlobalNotification ("Recent Analysis Error", QString ("Error fetching recent analyses: %1").arg (error), false);

    QMessageBox::critical (
        this,
        "Recent Analysis Error",
        QString ("Error fetching recent analyses: %1").arg (error),
        QMessageBox::Ok
    );
}

void RecentAnalysisDialog::on_GetRecentAnalysis() {
    startAsyncGetRecentAnalysis();
}

void RecentAnalysisDialog::on_TableCellDoubleClick (int row, int column) {
    (void)column;

    // generate portal URL from host URL
    Str link = StrDup (&GetConnection()->host);
    StrReplaceZstr (&link, "api", "portal", 1);

    // fetch collection id and open url
    QString binaryId   = table->item (row, 1)->text();
    QString analysisId = table->item (row, 2)->text();
    StrAppendf (&link, "/analyses/%llu?analysis-id=%llu", binaryId.toULongLong(), analysisId.toULongLong());
    QDesktopServices::openUrl (QUrl (link.data));

    StrDeinit (&link);
}

void RecentAnalysisDialog::addNewRowToResultsTable (QTableWidget *t, const QStringList &row) {
    size_t tableRowCount = t->rowCount();
    t->insertRow (tableRowCount);
    for (i32 i = 0; i < headerLabels.size(); i++) {
        t->setItem (tableRowCount, i, new QTableWidgetItem (row[i]));
    }
}

// Worker implementation
RecentAnalysisWorker::RecentAnalysisWorker (QObject *parent) : QObject (parent), m_cancelled (false) {}

void RecentAnalysisWorker::performGetRecentAnalysis() {
    m_cancelled = false;

    try {
        emitProgress (10, "Initializing request...");

        if (m_cancelled) {
            emit analysisError ("Operation cancelled");
            return;
        }

        emitProgress (30, "Fetching recent analyses from server...");

        RecentAnalysisRequest recents         = RecentAnalysisRequestInit();
        AnalysisInfos         recent_analyses = GetRecentAnalysis (GetConnection(), &recents);
        RecentAnalysisRequestDeinit (&recents);

        if (m_cancelled) {
            VecDeinit (&recent_analyses);
            emit analysisError ("Operation cancelled");
            return;
        }

        emitProgress (80, "Processing analysis data...");

        if (!recent_analyses.length) {
            emitProgress (100, "No recent analyses found");
            emit analysisFinished (recent_analyses);
            VecDeinit (&recent_analyses);
            return;
        }

        emitProgress (100, QString ("Loaded %1 recent analyses").arg (recent_analyses.length));
        emit analysisFinished (recent_analyses);

    } catch (const std::exception &e) {
        emit analysisError (QString ("Exception during recent analysis fetch: %1").arg (e.what()));
    } catch (...) {
        emit analysisError ("Unknown exception during recent analysis fetch");
    }
}

void RecentAnalysisWorker::cancel() {
    m_cancelled = true;
}
