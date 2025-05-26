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

/* cutter */
#include <Reai/Util/Str.h>
#include <cutter/core/Cutter.h>
#include <librz/rz_analysis.h>

#include <Plugin.h>
#include <Reai/Api.h>
#include <Reai/Util/Vec.h>
#include <Cutter/Ui/BinarySearchDialog.hpp>

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

    connect (btnBox, &QDialogButtonBox::accepted, this, &BinarySearchDialog::on_PerformBinarySearch);
    connect (btnBox, &QDialogButtonBox::rejected, this, &QDialog::close);
    connect (table, &QTableWidget::cellDoubleClicked, this, &BinarySearchDialog::on_TableCellDoubleClick);
}

void BinarySearchDialog::on_PerformBinarySearch() {
    rzClearMsg();
    RzCoreLocked core (Core());


    QByteArray modelNameByteArr           = modelNameSelector->currentText().toLatin1();
    QByteArray partialBinaryNameByteArr   = partialBinaryNameInput->text().toLatin1();
    QByteArray partialBinarySha256ByteArr = partialBinarySha256Input->text().toLatin1();

    SearchBinaryRequest search = SearchBinaryRequestInit();
    search.partial_name   = StrInitFromZstr (partialBinaryNameByteArr.constData());
    search.partial_sha256 = StrInitFromZstr (partialBinarySha256ByteArr.constData());
    search.model_name     = StrInitFromZstr (modelNameByteArr.constData());

    BinaryInfos binaries = SearchBinary (GetConnection(), &search);
    SearchBinaryRequestDeinit (&search);

    if (!binaries.length) {
        DISPLAY_INFO ("Search parameters returned no search results.");
        return;
    }

    table->clearContents();
    table->setRowCount (0);

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

    VecDeinit(&binaries);

    mainLayout->addWidget (table);
}

void BinarySearchDialog::on_TableCellDoubleClick (int row, int column) {
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
