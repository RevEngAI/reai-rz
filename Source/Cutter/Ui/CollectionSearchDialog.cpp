/**
 * @file      : CollectionSearchDialog.cpp
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

#include <Plugin.h>
#include <Reai/Api.h>
#include <Reai/Util/Vec.h>
#include <Cutter/Ui/CollectionSearchDialog.hpp>
#include <Cutter/Cutter.hpp>

CollectionSearchDialog::CollectionSearchDialog (QWidget* parent, bool openPageOnDoubleClick)
    : QDialog (parent), openPageOnDoubleClick (openPageOnDoubleClick) {
    setMinimumSize (QSize (960, 540));

    mainLayout = new QVBoxLayout;
    setLayout (mainLayout);
    setWindowTitle ("Collection Search");

    QGridLayout* l = new QGridLayout (this);
    QLabel*      n = nullptr;

    mainLayout->addLayout (l);

    n = new QLabel (this);
    n->setText ("Collection name : ");
    partialCollectionNameInput = new QLineEdit (this);
    partialCollectionNameInput->setPlaceholderText ("collection name");
    partialCollectionNameInput->setToolTip ("Partial collection name to search for");
    l->addWidget (n, 0, 0);
    l->addWidget (partialCollectionNameInput, 0, 1);

    n = new QLabel (this);
    n->setText ("Binary name : ");
    partialBinaryNameInput = new QLineEdit (this);
    partialBinaryNameInput->setPlaceholderText ("binary name");
    partialBinaryNameInput->setToolTip ("Partial binary name the collection must contain");
    l->addWidget (n, 1, 0);
    l->addWidget (partialBinaryNameInput, 1, 1);

    n = new QLabel (this);
    n->setText ("Binary SHA-265 hash : ");
    partialBinarySha256Input = new QLineEdit (this);
    partialBinarySha256Input->setPlaceholderText ("binary sha256");
    partialBinarySha256Input->setToolTip ("Partial binary SHA256 hash the collection must contain");
    l->addWidget (n, 2, 0);
    l->addWidget (partialBinarySha256Input, 2, 1);

    n = new QLabel (this);
    n->setText ("Model name (optional) : ");
    modelNameSelector = new QComboBox (this);
    modelNameSelector->setPlaceholderText ("any model");
    modelNameSelector->setToolTip ("Model used to analyze the binaries in collection");

    ModelInfos* models = GetModels();
    VecForeachPtr (models, model, { modelNameSelector->addItem (model->name.data); });

    l->addWidget (n, 3, 0);
    l->addWidget (modelNameSelector, 3, 1);

    QDialogButtonBox* btnBox = new QDialogButtonBox (QDialogButtonBox::Ok | QDialogButtonBox::Cancel);
    mainLayout->addWidget (btnBox);

    headerLabels << "name";
    headerLabels << "id";
    headerLabels << "scope";
    headerLabels << "last updated";
    headerLabels << "model";
    headerLabels << "owner";

    table = new QTableWidget;
    table->setEditTriggers (QAbstractItemView::NoEditTriggers);
    table->horizontalHeader()->setSectionResizeMode (QHeaderView::Stretch);
    table->setColumnCount (6);
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

    connect (btnBox, &QDialogButtonBox::accepted, this, &CollectionSearchDialog::on_PerformCollectionSearch);
    connect (btnBox, &QDialogButtonBox::rejected, this, &QDialog::close);
    connect (table, &QTableWidget::cellDoubleClicked, this, &CollectionSearchDialog::on_TableCellDoubleClick);
    connect (cancelButton, &QPushButton::clicked, this, &CollectionSearchDialog::cancelAsyncOperation);
}

CollectionSearchDialog::~CollectionSearchDialog() {
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

void CollectionSearchDialog::on_PerformCollectionSearch() {
    startAsyncCollectionSearch();
}

void CollectionSearchDialog::startAsyncCollectionSearch() {
    if (workerThread && workerThread->isRunning()) {
        return; // Already running
    }

    // Prepare request data
    CollectionSearchWorker::SearchRequest request;
    request.partialCollectionName = partialCollectionNameInput->text();
    request.partialBinaryName = partialBinaryNameInput->text();
    request.partialBinarySha256 = partialBinarySha256Input->text();
    request.modelName = modelNameSelector->currentText();

    // Setup UI for async operation
    setupProgressUI();
    
    // Show global status
    ShowGlobalStatus("Collection Search", "Searching for collections...", 0);

    // Create worker thread
    workerThread = new QThread(this);
    worker = new CollectionSearchWorker();
    worker->moveToThread(workerThread);

    // Connect signals
    connect(workerThread, &QThread::started, [this, request]() {
        worker->performCollectionSearch(request);
    });
    
    connect(worker, &CollectionSearchWorker::progress, this, &CollectionSearchDialog::onSearchProgress);
    connect(worker, &CollectionSearchWorker::searchFinished, this, &CollectionSearchDialog::onSearchFinished);
    connect(worker, &CollectionSearchWorker::searchError, this, &CollectionSearchDialog::onSearchError);
    
    // CRITICAL: Tell the thread to quit when worker finishes (this was missing!)
    connect(worker, &CollectionSearchWorker::searchFinished, workerThread, &QThread::quit);
    connect(worker, &CollectionSearchWorker::searchError, workerThread, &QThread::quit);
    
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

void CollectionSearchDialog::cancelAsyncOperation() {
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
    ShowGlobalMessage("Collection search cancelled", 3000);
}

void CollectionSearchDialog::setupProgressUI() {
    progressBar->setVisible(true);
    progressBar->setValue(0);
    statusLabel->setVisible(true);
    statusLabel->setText("Searching for collections...");
    cancelButton->setVisible(true);
    
    setUIEnabled(false);
}

void CollectionSearchDialog::hideProgressUI() {
    progressBar->setVisible(false);
    statusLabel->setVisible(false);
    cancelButton->setVisible(false);
    
    setUIEnabled(true);
}

void CollectionSearchDialog::setUIEnabled(bool enabled) {
    partialCollectionNameInput->setEnabled(enabled);
    partialBinaryNameInput->setEnabled(enabled);
    partialBinarySha256Input->setEnabled(enabled);
    modelNameSelector->setEnabled(enabled);
    table->setEnabled(enabled);
}

void CollectionSearchDialog::onSearchProgress(int percentage, const QString &message) {
    progressBar->setValue(percentage);
    statusLabel->setText(message);
    
    // Update global status
    UpdateGlobalStatus(message, percentage);
}

void CollectionSearchDialog::onSearchFinished(const CollectionInfos &collections) {
    if (!collections.length) {
        ShowGlobalMessage("Failed to get collection search results", 3000);
        return;
    }

    table->clearContents();
    table->setRowCount(0);

    VecForeachPtr (&collections, collection, {
        QStringList row;
        row << collection->name.data;
        row << QString::number (collection->id);
        row << (collection->is_private ? "PRIVATE" : "PUBLIC");
        row << collection->last_updated_at.data;
        row << collection->model_name.data;
        row << collection->owned_by.data;

        addNewRowToResultsTable (table, row);
    });

    ShowGlobalMessage(QString("Found %1 collections").arg(collections.length), 3000);

    VecDeinit(&collections);
}

void CollectionSearchDialog::onSearchError(const QString &error) {
    // Show error notification
    ShowGlobalNotification(
        "Collection Search Error",
        QString("Error searching collections: %1").arg(error),
        false
    );
    
    QMessageBox::critical(
        this,
        "Collection Search Error",
        QString("Error searching collections: %1").arg(error),
        QMessageBox::Ok
    );
}

void CollectionSearchDialog::on_TableCellDoubleClick (int row, int column) {
    (void)column;

    if (openPageOnDoubleClick) {
        // generate portal URL from host URL
        Str link = StrDup (&GetConnection()->host);
        StrReplaceZstr (&link, "api", "portal", 1);

        // fetch collection id and open url
        QString collectionId = table->item (row, 1)->text();
        StrAppendf (&link, "/collections/%llu", collectionId.toULongLong());
        QDesktopServices::openUrl (QUrl (link.data));

        StrDeinit (&link);
    } else {
        selectedCollectionIds << table->item (row, 1)->text();
    }
}

void CollectionSearchDialog::addNewRowToResultsTable (QTableWidget* t, const QStringList& row) {
    size_t tableRowCount = t->rowCount();
    t->insertRow (tableRowCount);
    for (i32 i = 0; i < headerLabels.size(); i++) {
        t->setItem (tableRowCount, i, new QTableWidgetItem (row[i]));
    }
}

// Worker implementation
CollectionSearchWorker::CollectionSearchWorker(QObject *parent)
    : QObject(parent), m_cancelled(false) {
}

void CollectionSearchWorker::performCollectionSearch(const SearchRequest &request) {
    m_cancelled = false;
    
    try {
        emitProgress(10, "Initializing search request...");
        
        if (m_cancelled) {
            emit searchError("Operation cancelled");
            return;
        }
        
        emitProgress(30, "Searching collections on server...");

        SearchCollectionRequest search      = SearchCollectionRequestInit();
        
        search.partial_collection_name = StrInitFromZstr (request.partialCollectionName.toUtf8().constData());
        search.partial_binary_name     = StrInitFromZstr (request.partialBinaryName.toUtf8().constData());
        search.partial_binary_sha256   = StrInitFromZstr (request.partialBinarySha256.toUtf8().constData());
        search.model_name              = StrInitFromZstr (request.modelName.toUtf8().constData());

        CollectionInfos collections = SearchCollection (GetConnection(), &search);
        SearchCollectionRequestDeinit (&search);
        
        if (m_cancelled) {
            VecDeinit(&collections);
            emit searchError("Operation cancelled");
            return;
        }
        
        emitProgress(80, "Processing search results...");
        
        emitProgress(100, QString("Found %1 collections").arg(collections.length));
        emit searchFinished(collections);
        
        // NOTE: Don't call VecDeinit here - let the UI thread handle cleanup
        // The collections data will be cleaned up in onSearchFinished
        
    } catch (const std::exception &e) {
        emit searchError(QString("Exception during collection search: %1").arg(e.what()));
    } catch (...) {
        emit searchError("Unknown exception during collection search");
    }
}

void CollectionSearchWorker::cancel() {
    m_cancelled = true;
}
