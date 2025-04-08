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

    connect (okBtn, &QPushButton::clicked, this, &BinarySearchDialog::on_PerformBinarySearch);
    connect (cancelBtn, &QPushButton::clicked, this, &QDialog::close);
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

    if (results) {
        results = reai_binary_search_result_vec_clone_create (results);
    } else {
        DISPLAY_ERROR ("Failed to get collection search results");
        return;
    }

    table->clearContents();
    REAI_VEC_FOREACH (results, csr, {
        QStringList row;
        row << csr->binary_name;
        row << QString::number (csr->binary_id);
        row << QString::number (csr->analysis_id);
        row << csr->model_name;
        row << csr->owned_by;
        row << csr->created_at;
        row << csr->sha_256_hash;

        addNewRowToResultsTable (table, row);
    });

    mainLayout->addWidget (table);

    reai_binary_search_result_vec_destroy (results);
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
        QDesktopServices::openUrl (link);
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
