/**
 * @file      : CollectionSearchDialog.cpp
 * @date      : 8th Apr 2025
 * @author    : Siddharth Mishra (admin@brightprogrammer.in)
 * @copyright : Copyright (c) 2025 RevEngAI. All Rights Reserved.
 * */

/* plugin */
#include <Plugin.h>
#include <Reai/Api/Reai.h>
#include <Cutter/Ui/CollectionSearchDialog.hpp>

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

/* cutter */
#include <cutter/core/Cutter.h>
#include <librz/rz_analysis.h>

/* reai */
#include <Reai/Util/Vec.h>

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

    CString* beg = reai_ai_models()->items;
    CString* end = reai_ai_models()->items + reai_ai_models()->count;
    for (CString* ai_model = beg; ai_model < end; ai_model++) {
        modelNameSelector->addItem (*ai_model);
    }

    l->addWidget (n, 3, 0);
    l->addWidget (modelNameSelector, 3, 1);

    QDialogButtonBox* btnBox =
        new QDialogButtonBox (QDialogButtonBox::Ok | QDialogButtonBox::Cancel);
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

    connect (
        btnBox,
        &QDialogButtonBox::accepted,
        this,
        &CollectionSearchDialog::on_PerformCollectionSearch
    );
    connect (btnBox, &QDialogButtonBox::rejected, this, &QDialog::close);
    connect (
        table,
        &QTableWidget::cellDoubleClicked,
        this,
        &CollectionSearchDialog::on_TableCellDoubleClick
    );
}

void CollectionSearchDialog::on_PerformCollectionSearch() {
    RzCoreLocked core (Core());

    const QString& partialCollectionName        = partialCollectionNameInput->text();
    QByteArray     partialCollectionNameByteArr = partialCollectionName.toLatin1();
    CString        partialCollectionNameCStr    = partialCollectionNameByteArr.constData();

    const QString& partialBinaryName        = partialBinaryNameInput->text();
    QByteArray     partialBinaryNameByteArr = partialBinaryName.toLatin1();
    CString        partialBinaryNameCStr    = partialBinaryNameByteArr.constData();

    const QString& partialBinarySha256        = partialBinarySha256Input->text();
    QByteArray     partialBinarySha256ByteArr = partialBinarySha256.toLatin1();
    CString        partialBinarySha256CStr    = partialBinarySha256ByteArr.constData();

    CString modelNameCStr = NULL;
    if (modelNameSelector->currentIndex() != -1) {
        const QString& modelName        = modelNameSelector->currentText();
        QByteArray     modelNameByteArr = modelName.toLatin1();
        modelNameCStr                   = modelNameByteArr.constData();
    }

    ReaiCollectionSearchResultVec* results = reai_collection_search (
        reai(),
        reai_response(),
        partialCollectionNameCStr,
        partialBinaryNameCStr,
        partialBinarySha256CStr,
        NULL,
        modelNameCStr
    );

    if (!results) {
        DISPLAY_ERROR ("Failed to get collection search results");
        return;
    }

    table->clearContents();

    ReaiCollectionSearchResult* beg = results->items;
    ReaiCollectionSearchResult* end = results->items + results->count;
    for (ReaiCollectionSearchResult* csr = beg; csr < end; csr++) {
        QStringList row;
        row << csr->collection_name;
        row << QString::number (csr->collection_id);
        row << csr->scope;
        row << csr->last_updated_at;
        row << csr->model_name;
        row << csr->owned_by;

        addNewRowToResultsTable (table, row);
    }
}

void CollectionSearchDialog::on_TableCellDoubleClick (int row, int column) {
    UNUSED (column);

    if (openPageOnDoubleClick) {
        // generate portal URL from host URL
        const char* hostCStr = reai_plugin()->reai_config->host;
        QString     host     = QString::fromUtf8 (hostCStr);
        host.replace ("api", "portal", Qt::CaseSensitive); // replaces first occurrence

        // fetch collection id and open url
        QString collectionId = table->item (row, 1)->text();
        QString link         = QString ("%1/collections/%2").arg (host).arg (collectionId);
        QDesktopServices::openUrl (QUrl (link));
    } else {
        selectedCollectionIds << table->item (row, 1)->text();
    }
}

void CollectionSearchDialog::addNewRowToResultsTable (QTableWidget* t, const QStringList& row) {
    Size tableRowCount = t->rowCount();
    t->insertRow (tableRowCount);
    for (Int32 i = 0; i < headerLabels.size(); i++) {
        t->setItem (tableRowCount, i, new QTableWidgetItem (row[i]));
    }
}
