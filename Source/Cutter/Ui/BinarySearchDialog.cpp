/**
 * @file      : BinarySearchDialog.cpp
 * @date      : 8th Apr 2025
 * @author    : Siddharth Mishra (admin@brightprogrammer.in)
 * @copyright : Copyright (c) 2025 RevEngAI. All Rights Reserved.
 * */

/* plugin */
#include <Plugin.h>
#include <Reai/Api/Reai.h>
#include <Cutter/Ui/BinarySearchDialog.hpp>

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

BinarySearchDialog::BinarySearchDialog (QWidget* parent, bool openPageOnDoubleClick)
    : QDialog (parent), openPageOnDoubleClick (openPageOnDoubleClick) {
    setMinimumSize (QSize (960, 540));

    mainLayout = new QVBoxLayout;
    setLayout (mainLayout);
    setWindowTitle ("Collection Search");

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
    modelNameInput = new QComboBox (this);
    modelNameInput->setPlaceholderText ("any model");
    partialBinarySha256Input->setToolTip ("Model used to perform analysis");

    CString* beg = reai_ai_models()->items;
    CString* end = reai_ai_models()->items + reai_ai_models()->count;
    for (CString* ai_model = beg; ai_model < end; ai_model++) {
        modelNameInput->addItem (*ai_model);
    }

    l->addWidget (n, 2, 0);
    l->addWidget (modelNameInput, 2, 1);

    QDialogButtonBox* btnBox =
        new QDialogButtonBox (QDialogButtonBox::Ok | QDialogButtonBox::Cancel);
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
    mainLayout->addWidget (table);

    connect (
        btnBox,
        &QDialogButtonBox::accepted,
        this,
        &BinarySearchDialog::on_PerformBinarySearch
    );
    connect (btnBox, &QDialogButtonBox::rejected, this, &QDialog::close);
    connect (
        table,
        &QTableWidget::cellDoubleClicked,
        this,
        &BinarySearchDialog::on_TableCellDoubleClick
    );
}

void BinarySearchDialog::on_PerformBinarySearch() {
    RzCoreLocked core (Core());

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

    ReaiBinarySearchResultVec* results = reai_binary_search (
        reai(),
        reai_response(),
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

    ReaiBinarySearchResult* beg = results->items;
    ReaiBinarySearchResult* end = results->items + results->count;
    for (ReaiBinarySearchResult* csr = beg; csr < end; csr++) {
        QStringList row;
        row << csr->binary_name;
        row << QString::number (csr->binary_id);
        row << QString::number (csr->analysis_id);
        row << csr->model_name;
        row << csr->owned_by;
        row << csr->created_at;
        row << csr->sha_256_hash;

        addNewRowToResultsTable (table, row);
    }

    mainLayout->addWidget (table);
}

void BinarySearchDialog::on_TableCellDoubleClick (int row, int column) {
    UNUSED (column);

    if (openPageOnDoubleClick) {
        // generate portal URL from host URL
        const char* hostCStr = reai_plugin()->reai_config->host;
        QString     host     = QString::fromUtf8 (hostCStr);
        host.replace ("api", "portal", Qt::CaseSensitive); // replaces first occurrence

        // fetch collection id and open url
        QString binaryId   = table->item (row, 1)->text();
        QString analysisId = table->item (row, 2)->text();
        QString link =
            QString ("%1/analyses/%2?analysis-id=%3").arg (host).arg (binaryId).arg (analysisId);
        QDesktopServices::openUrl (QUrl (link));
    } else {
        selectedBinaryIds << table->item (row, 1)->text();
    }
}

void BinarySearchDialog::addNewRowToResultsTable (QTableWidget* t, const QStringList& row) {
    Size tableRowCount = t->rowCount();
    t->insertRow (tableRowCount);
    for (Int32 i = 0; i < headerLabels.size(); i++) {
        t->setItem (tableRowCount, i, new QTableWidgetItem (row[i]));
    }
}
