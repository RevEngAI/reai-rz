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

/* cutter */
#include <cutter/core/Cutter.h>
#include <librz/rz_analysis.h>

#include <Plugin.h>
#include <Reai/Api.h>
#include <Reai/Util/Vec.h>
#include <Cutter/Ui/CollectionSearchDialog.hpp>

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

    connect (btnBox, &QDialogButtonBox::accepted, this, &CollectionSearchDialog::on_PerformCollectionSearch);
    connect (btnBox, &QDialogButtonBox::rejected, this, &QDialog::close);
    connect (table, &QTableWidget::cellDoubleClicked, this, &CollectionSearchDialog::on_TableCellDoubleClick);
}

void CollectionSearchDialog::on_PerformCollectionSearch() {
    rzClearMsg();
    RzCoreLocked core (Core());

    QByteArray partialCollectionNameByteArr = partialCollectionNameInput->text().toLatin1();
    QByteArray partialBinaryNameByteArr     = partialBinaryNameInput->text().toLatin1();
    QByteArray partialBinarySha256ByteArr   = partialBinarySha256Input->text().toLatin1();
    QByteArray modelNameByteArr             = modelNameSelector->currentText().toLatin1();

    SearchCollectionRequest search      = SearchCollectionRequestInit();
    CollectionInfos         collections = SearchCollection (GetConnection(), &search);
    SearchCollectionRequestDeinit (&search);

    if (!collections.length) {
        DISPLAY_ERROR ("Failed to get collection search results");
        return;
    }

    table->clearContents();
    table->setRowCount (0);

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

    VecDeinit (&collections);
}

void CollectionSearchDialog::on_TableCellDoubleClick (int row, int column) {
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
