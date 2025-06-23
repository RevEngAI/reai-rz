/**
 * @file      : BinarySearchDialog.cpp
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
#include <Reai/Util/Str.h>
#include <cutter/core/Cutter.h>
#include <librz/rz_analysis.h>

#include <Plugin.h>
#include <Reai/Api.h>
#include <Reai/Util/Vec.h>
#include <Cutter/Ui/BinarySearchDialog.hpp>
#include <Cutter/Cutter.hpp>

BinarySearchDialog::BinarySearchDialog (QWidget* parent, bool openPageOnDoubleClick)
    : QDialog (parent), openPageOnDoubleClick (openPageOnDoubleClick) {
    setMinimumSize (QSize (960, 540));

    mainLayout = new QVBoxLayout;
    setLayout (mainLayout);
    setWindowTitle ("Binary Search");

    QGridLayout* l = new QGridLayout (this);
    QLabel*      n = nullptr;

    mainLayout->addLayout (l);

    n = new QLabel (this);
    n->setText ("Binary name : ");
    partialBinaryNameInput = new QLineEdit (this);
    partialBinaryNameInput->setPlaceholderText ("binary name");
    partialBinaryNameInput->setToolTip ("Partial binary name to search for");
    l->addWidget (n, 0, 0);
    l->addWidget (partialBinaryNameInput, 0, 1);

    n = new QLabel (this);
    n->setText ("Binary SHA-256 hash : ");
    partialBinarySha256Input = new QLineEdit (this);
    partialBinarySha256Input->setPlaceholderText ("binary sha256");
    partialBinarySha256Input->setToolTip ("Partial binary SHA-256 hash to search for");
    l->addWidget (n, 1, 0);
    l->addWidget (partialBinarySha256Input, 1, 1);

    n = new QLabel (this);
    n->setText ("Model name (optional) : ");
    modelNameSelector = new QComboBox (this);
    modelNameSelector->setPlaceholderText ("any model");
    modelNameSelector->setToolTip ("Model used to perform analysis");

    ModelInfos* models = GetModels();
    VecForeachPtr (models, model, { modelNameSelector->addItem (model->name.data); });

    l->addWidget (n, 2, 0);
    l->addWidget (modelNameSelector, 2, 1);

    QDialogButtonBox* btnBox = new QDialogButtonBox (QDialogButtonBox::Ok | QDialogButtonBox::Cancel);
    mainLayout->addWidget (btnBox);

    headerLabels << "name";
    headerLabels << "binary id";
    headerLabels << "analysis id";
    headerLabels << "model";
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
    progressBar = new QProgressBar(this);
    progressBar->setVisible(false);
    mainLayout->addWidget(progressBar);
    
    statusLabel = new QLabel(this);
    statusLabel->setVisible(false);
    mainLayout->addWidget(statusLabel);
    
    cancelButton = new QPushButton("Cancel Operation", this);
    cancelButton->setVisible(false);
    mainLayout->addWidget(cancelButton);

    connect (btnBox, &QDialogButtonBox::accepted, this, &BinarySearchDialog::on_PerformBinarySearch);
    connect (btnBox, &QDialogButtonBox::rejected, this, &QDialog::close);
    connect (table, &QTableWidget::cellDoubleClicked, this, &BinarySearchDialog::on_TableCellDoubleClick);
    connect (cancelButton, &QPushButton::clicked, this, &BinarySearchDialog::cancelAsyncOperation);
}

BinarySearchDialog::~BinarySearchDialog() {
    if (worker) {
        worker->cancel();
    }
    
    if (workerThread) {
        if (workerThread->isRunning()) {
            // Give it 3 seconds to finish gracefully
            if (!workerThread->wait(3000)) {
                // Force terminate if it doesn't finish
                workerThread->terminate();
                workerThread->wait(1000);
            }
        }
        
        if (worker) {
            worker->deleteLater();
            worker = nullptr;
        }
        
        workerThread = nullptr;
    }
}

void BinarySearchDialog::on_PerformBinarySearch() {
    startAsyncBinarySearch();
}

void BinarySearchDialog::startAsyncBinarySearch() {
    if (workerThread && workerThread->isRunning()) {
        return; // Already running
    }

    // Prepare request data
    BinarySearchWorker::SearchRequest request;
    request.partialName = partialBinaryNameInput->text();
    request.partialSha256 = partialBinarySha256Input->text();
    request.modelName = modelNameSelector->currentText();

    // Setup UI for async operation
    setupProgressUI();
    
    // Show global status
    ShowGlobalStatus("Binary Search", "Searching for binaries...", 0);

    // Create worker thread
    workerThread = new QThread(this);
    worker = new BinarySearchWorker();
    worker->moveToThread(workerThread);

    // Connect signals
    connect(workerThread, &QThread::started, [this, request]() {
        worker->performBinarySearch(request);
    });
    
    connect(worker, &BinarySearchWorker::progress, this, &BinarySearchDialog::onSearchProgress);
    connect(worker, &BinarySearchWorker::searchFinished, this, &BinarySearchDialog::onSearchFinished);
    connect(worker, &BinarySearchWorker::searchError, this, &BinarySearchDialog::onSearchError);
    
    // CRITICAL: Tell the thread to quit when worker finishes (this was missing!)
    connect(worker, &BinarySearchWorker::searchFinished, workerThread, &QThread::quit);
    connect(worker, &BinarySearchWorker::searchError, workerThread, &QThread::quit);
    
    connect(workerThread, &QThread::finished, [this]() {
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

void BinarySearchDialog::cancelAsyncOperation() {
    if (worker) {
        worker->cancel();
    }
    
    if (workerThread) {
        if (workerThread->isRunning()) {
            // Give it 3 seconds to finish gracefully
            if (!workerThread->wait(3000)) {
                // Force terminate if it doesn't finish
                workerThread->terminate();
                workerThread->wait(1000);
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
    ShowGlobalMessage("Binary search cancelled", 3000);
}

void BinarySearchDialog::setupProgressUI() {
    progressBar->setVisible(true);
    progressBar->setValue(0);
    statusLabel->setVisible(true);
    statusLabel->setText("Searching for binaries...");
    cancelButton->setVisible(true);
    
    setUIEnabled(false);
}

void BinarySearchDialog::hideProgressUI() {
    progressBar->setVisible(false);
    statusLabel->setVisible(false);
    cancelButton->setVisible(false);
    
    setUIEnabled(true);
}

void BinarySearchDialog::setUIEnabled(bool enabled) {
    partialBinaryNameInput->setEnabled(enabled);
    partialBinarySha256Input->setEnabled(enabled);
    modelNameSelector->setEnabled(enabled);
    table->setEnabled(enabled);
}

void BinarySearchDialog::onSearchProgress(int percentage, const QString &message) {
    progressBar->setValue(percentage);
    statusLabel->setText(message);
    
    // Update global status
    UpdateGlobalStatus(message, percentage);
}

void BinarySearchDialog::onSearchFinished(const BinaryInfos &binaries) {
    if (!binaries.length) {
        ShowGlobalMessage("Search parameters returned no search results", 3000);
        return;
    }

    table->clearContents();
    table->setRowCount(0);

    VecForeachPtr (&binaries, binary, {
        QStringList row;
        row << binary->binary_name.data;
        row << QString::number (binary->binary_id);
        row << QString::number (binary->analysis_id);
        row << binary->model_name.data;
        row << binary->owned_by.data;
        row << binary->created_at.data;
        row << binary->sha256.data;

        addNewRowToResultsTable (table, row);
    });

    ShowGlobalMessage(QString("Found %1 binaries").arg(binaries.length), 3000);

    VecDeinit(&binaries);
}

void BinarySearchDialog::onSearchError(const QString &error) {
    // Show error notification
    ShowGlobalNotification(
        "Binary Search Error",
        QString("Error searching binaries: %1").arg(error),
        false
    );
    
    QMessageBox::critical(
        this,
        "Binary Search Error",
        QString("Error searching binaries: %1").arg(error),
        QMessageBox::Ok
    );
}

void BinarySearchDialog::on_TableCellDoubleClick (int row, int column) {
    (void)column;

    if (openPageOnDoubleClick) {
        // fetch binary id an analysis id and open url
        QString binaryId   = table->item (row, 1)->text();
        QString analysisId = table->item (row, 2)->text();

        // generate portal URL from host URL
        Str link = StrDup (&GetConnection()->host);
        StrReplaceZstr (&link, "api", "portal", 1);
        StrAppendf (&link, "/analyses/%llu?analysis-id=%llu", binaryId.toULongLong(), analysisId.toULongLong());
        QDesktopServices::openUrl (QUrl (link.data));

        StrDeinit (&link);
    } else {
        selectedBinaryIds << table->item (row, 1)->text();
    }
}

void BinarySearchDialog::addNewRowToResultsTable (QTableWidget* t, const QStringList& row) {
    size_t tableRowCount = t->rowCount();
    t->insertRow (tableRowCount);
    for (i32 i = 0; i < headerLabels.size(); i++) {
        t->setItem (tableRowCount, i, new QTableWidgetItem (row[i]));
    }
}

// Worker implementation
BinarySearchWorker::BinarySearchWorker(QObject *parent)
    : QObject(parent), m_cancelled(false) {
}

void BinarySearchWorker::performBinarySearch(const SearchRequest &request) {
    m_cancelled = false;
    
    try {
        emitProgress(10, "Initializing search request...");
        
        if (m_cancelled) {
            emit searchError("Operation cancelled");
            return;
        }
        
        emitProgress(30, "Searching binaries on server...");
        
        SearchBinaryRequest search = SearchBinaryRequestInit();
        search.partial_name        = StrInitFromZstr (request.partialName.toUtf8().constData());
        search.partial_sha256      = StrInitFromZstr (request.partialSha256.toUtf8().constData());
        search.model_name          = StrInitFromZstr (request.modelName.toUtf8().constData());

        BinaryInfos binaries = SearchBinary (GetConnection(), &search);
        SearchBinaryRequestDeinit (&search);
        
        if (m_cancelled) {
            VecDeinit(&binaries);
            emit searchError("Operation cancelled");
            return;
        }
        
        emitProgress(80, "Processing search results...");
        
        emitProgress(100, QString("Found %1 binaries").arg(binaries.length));
        emit searchFinished(binaries);
        
    } catch (const std::exception &e) {
        emit searchError(QString("Exception during binary search: %1").arg(e.what()));
    } catch (...) {
        emit searchError("Unknown exception during binary search");
    }
}

void BinarySearchWorker::cancel() {
    m_cancelled = true;
}
