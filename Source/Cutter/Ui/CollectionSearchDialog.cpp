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

    partialCollectionNameInput = new QLineEdit (this);
    partialCollectionNameInput->setPlaceholderText ("collection name");
    mainLayout->addWidget (partialCollectionNameInput);

    partialBinaryNameInput = new QLineEdit (this);
    partialBinaryNameInput->setPlaceholderText ("binary name");
    mainLayout->addWidget (partialBinaryNameInput);

    partialBinarySha256Input = new QLineEdit (this);
    partialBinarySha256Input->setPlaceholderText ("binary sha256");
    mainLayout->addWidget (partialBinarySha256Input);

    modelNameInput = new QComboBox (this);
    modelNameInput->setPlaceholderText ("Model name");
    REAI_VEC_FOREACH (reai_ai_models(), ai_model, { modelNameInput->addItem (*ai_model); });
    mainLayout->addWidget (modelNameInput);

    QHBoxLayout* btnLayout = new QHBoxLayout (this);
    mainLayout->addLayout (btnLayout);

    QPushButton* okBtn     = new QPushButton ("Ok");
    QPushButton* cancelBtn = new QPushButton ("Cancel");
    btnLayout->addWidget (cancelBtn);
    btnLayout->addWidget (okBtn);

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
    mainLayout->addWidget (table);

    connect (
        okBtn,
        &QPushButton::clicked,
        this,
        &CollectionSearchDialog::on_PerformCollectionSearch
    );
    connect (cancelBtn, &QPushButton::clicked, this, &QDialog::close);
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
    if (modelNameInput->currentIndex() != -1) {
        const QString& modelName        = modelNameInput->currentText();
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

    if (results) {
        results = reai_collection_search_result_vec_clone_create (results);
    } else {
        DISPLAY_ERROR ("Failed to get collection search results");
        return;
    }

    table->clearContents();
    REAI_VEC_FOREACH (results, csr, {
        QStringList row;
        row << csr->collection_name;
        row << QString::number (csr->collection_id);
        row << csr->scope;
        row << csr->last_updated_at;
        row << csr->model_name;
        row << csr->owned_by;

        addNewRowToResultsTable (table, row);
    });

    reai_collection_search_result_vec_destroy (results);
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
        QDesktopServices::openUrl (link);
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
