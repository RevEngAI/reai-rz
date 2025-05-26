/**
 * @file      : FunctionSimilarityDialog.cpp
 * @date      : 25th Sept 2024
 * @author    : Siddharth Mishra (admin@brightprogrammer.in)
 * @copyright : Copyright (c) 2024 RevEngAI. All Rights Reserved.
 * */

/* qt */
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QScrollArea>
#include <QPushButton>
#include <QHeaderView>
#include <QCompleter>
#include <QDialogButtonBox>
#include <QLabel>
#include <QUrl>
#include <QDesktopServices>

/* cutter */
#include <cutter/core/Cutter.h>
#include <librz/rz_analysis.h>

#include <Plugin.h>
#include <Reai/Api.h>
#include <Reai/Util/Vec.h>
#include <Reai/Util/Str.h>
#include <Cutter/Ui/FunctionSimilarityDialog.hpp>
#include <Cutter/Ui/CollectionSearchDialog.hpp>
#include <Cutter/Ui/BinarySearchDialog.hpp>

// TODO: provide a way to rename functions from this dialog as well

FunctionSimilarityDialog::FunctionSimilarityDialog (QWidget* parent) : QDialog (parent) {
    setMinimumSize (540, 360);

    mainLayout = new QVBoxLayout;
    setLayout (mainLayout);
    setWindowTitle ("Function Similarity Search");

    QGridLayout* l = new QGridLayout (this);
    QLabel*      n = nullptr;

    mainLayout->addLayout (l);

    /* get function names from binary */
    QStringList fnNamesList;
    {
        RzCoreLocked core (Core());

        if (!rz_analysis_function_list (core->analysis) ||
            !rz_list_length (rz_analysis_function_list (core->analysis))) {
            DISPLAY_ERROR (
                "Opened binary seems to have no functions. None detected by Rizin. Cannot perform "
                "similarity search."
            );
            return;
        }

        /* add all symbols corresponding to functions */
        RzList*     fns     = rz_analysis_function_list (core->analysis);
        RzListIter* fn_iter = nullptr;
        void*       data    = nullptr;
        rz_list_foreach (fns, fn_iter, data) {
            RzAnalysisFunction* fn = (RzAnalysisFunction*)data;
            fnNamesList << fn->name;
        }
    }

    /* create search bar and add and cancel buttons to add/cancel adding a
     * new name map */
    n = new QLabel (this);
    n->setText ("Function name : ");
    searchBarInput = new QLineEdit (this);
    searchBarInput->setPlaceholderText ("Start typing for suggestions...");
    l->addWidget (n, 0, 0);
    l->addWidget (searchBarInput, 0, 1);

    fnNameCompleter = new QCompleter (fnNamesList);
    fnNameCompleter->setCaseSensitivity (Qt::CaseInsensitive);
    searchBarInput->setCompleter (fnNameCompleter);

    n = new QLabel (this);
    n->setText ("Max result count : ");
    maxResultCountInput = new QSpinBox (this);
    maxResultCountInput->setValue (10);
    maxResultCountInput->setMinimum (1);
    l->addWidget (n, 1, 0);
    l->addWidget (maxResultCountInput, 1, 1);

    /* textbox for taking in collection ids in csv format */
    n = new QLabel (this);
    n->setText ("Collection IDs : ");
    collectionIdsInput = new QLineEdit (this);
    collectionIdsInput->setPlaceholderText ("Comma separated list of collection IDs");
    l->addWidget (n, 2, 0);
    l->addWidget (collectionIdsInput, 2, 1);

    /* textbox for taking in binary ids in csv format */
    n = new QLabel (this);
    n->setText ("Binary IDs : ");
    binaryIdsInput = new QLineEdit (this);
    binaryIdsInput->setPlaceholderText ("Comma separated list of binary IDs");
    l->addWidget (n, 3, 0);
    l->addWidget (binaryIdsInput, 3, 1);


    /* Create slider to select similarity level */
    similaritySlider = new QSlider (Qt::Horizontal);
    similaritySlider->setMinimum (1);
    similaritySlider->setMaximum (100);
    similaritySlider->setValue (90);

    QLabel* similarityLabel = new QLabel ("90% min similarity");
    connect (similaritySlider, &QSlider::valueChanged, [similarityLabel] (int value) {
        similarityLabel->setText (QString ("%1 % min similarity").arg (value));
    });
    l->addWidget (similarityLabel, 4, 0);
    l->addWidget (similaritySlider, 4, 1);

    enableDebugFilterCheckBox = new QCheckBox ("Restrict suggestions to debug symbols only?", this);
    mainLayout->addWidget (enableDebugFilterCheckBox);
    enableDebugFilterCheckBox->setCheckState (Qt::CheckState::Checked);

    QPushButton* binaryIdsSearchBtn = new QPushButton ("Select Binaries");
    connect (binaryIdsSearchBtn, &QPushButton::pressed, this, &FunctionSimilarityDialog::on_SearchBinaries);

    QPushButton* collectionIdsSearchBtn = new QPushButton ("Select Collections");
    connect (collectionIdsSearchBtn, &QPushButton::pressed, this, &FunctionSimilarityDialog::on_SearchCollections);

    QPushButton* searchBtn = new QPushButton ("Search", this);
    connect (searchBtn, &QPushButton::pressed, this, &FunctionSimilarityDialog::on_FindSimilarNames);

    QPushButton* cancelBtn = new QPushButton ("Cancel", this);
    connect (cancelBtn, &QPushButton::pressed, this, [this]() {
        oldNameToNewNameMap.clear();
        reject();
    });

    QDialogButtonBox* btnBox = new QDialogButtonBox (this);
    btnBox->addButton (cancelBtn, QDialogButtonBox::RejectRole);
    btnBox->addButton (binaryIdsSearchBtn, QDialogButtonBox::ActionRole);
    btnBox->addButton (searchBtn, QDialogButtonBox::AcceptRole);
    btnBox->addButton (collectionIdsSearchBtn, QDialogButtonBox::ActionRole);
    mainLayout->addWidget (btnBox);

    headerLabels << "function name";
    headerLabels << "function id";
    headerLabels << "binary name";
    headerLabels << "binary id";
    headerLabels << "similarity";
    headerLabels << "add to rename";

    table = new QTableWidget;
    table->setEditTriggers (QAbstractItemView::NoEditTriggers);
    table->horizontalHeader()->setSectionResizeMode (QHeaderView::Stretch);
    table->setColumnCount (6);
    table->setHorizontalHeaderLabels (headerLabels);
    table->horizontalHeader()->setSectionResizeMode (QHeaderView::Stretch);
    mainLayout->addWidget (table);

    connect (table, &QTableWidget::cellDoubleClicked, this, &FunctionSimilarityDialog::on_TableCellDoubleClick);
}

void FunctionSimilarityDialog::on_FindSimilarNames() {
    RzCoreLocked core (Core());

    if (!rzCanWorkWithAnalysis (GetBinaryId(), true)) {
        return;
    }

    SimilarFunctionsRequest search = SimilarFunctionsRequestInit();

    /* check if function exists or not */
    QByteArray fnNameByteArr = searchBarInput->text().toLatin1();

    search.function_id = rzLookupFunctionIdForFunctionWithName (core, fnNameByteArr.constData());
    if (!search.function_id) {
        DISPLAY_ERROR (
            "Failed to get a function id for selected Rizin function. Cannot get similar functions for this one."
        );
        return;
    }

    u32        requiredSimilarity      = similaritySlider->value();
    bool       debugFilter             = enableDebugFilterCheckBox->checkState() == Qt::CheckState::Checked;
    i32        maxResultCount          = maxResultCountInput->value();
    QByteArray collectionIdsCsvByteArr = collectionIdsInput->text().toLatin1();
    QByteArray binaryIdsCsvByteArr     = binaryIdsInput->text().toLatin1();

    search.distance                       = 1.f - (requiredSimilarity / 100.f);
    search.limit                          = maxResultCount;
    search.debug_include.external_symbols = debugFilter;
    search.debug_include.system_symbols   = debugFilter;
    search.debug_include.user_symbols     = debugFilter;

    Str  collection_ids_csv = StrInitFromZstr (collectionIdsCsvByteArr.constData());
    Strs cids               = StrSplit (&collection_ids_csv, ",");
    VecForeachPtr (&cids, cid, { VecPushBack (&search.collection_ids, strtoull (cid->data, NULL, 0)); });
    StrDeinit (&collection_ids_csv);
    VecDeinit (&cids);

    Str  binary_ids_csv = StrInitFromZstr (collectionIdsCsvByteArr.constData());
    Strs bids           = StrSplit (&collection_ids_csv, ",");
    VecForeachPtr (&bids, bid, { VecPushBack (&search.binary_ids, strtoull (bid->data, NULL, 0)); });
    StrDeinit (&binary_ids_csv);
    VecDeinit (&bids);

    SimilarFunctions similar_functions = GetSimilarFunctions (GetConnection(), &search);
    SimilarFunctionsRequestDeinit (&search);

    table->clearContents();
    table->setRowCount (0);

    if (similar_functions.length) {
        VecForeachPtr (&similar_functions, similar_function, {
            QStringList row;
            row << similar_function->name.data << QString::number (similar_function->id);
            row << similar_function->binary_name.data << QString::number (similar_function->binary_id);
            row << QString::number ((1 - similar_function->distance) * 100);
            addNewRowToResultsTable (table, row);
        });
    } else {
        DISPLAY_ERROR ("No similar functions found for given settings");
    }
}

void FunctionSimilarityDialog::on_SearchCollections() {
    CollectionSearchDialog* csDlg = new CollectionSearchDialog (
        (QWidget*)this,
        false /* store ids on double click instead of opening links */
    );
    csDlg->exec();
    collectionIdsInput->setText (collectionIdsInput->text() + csDlg->getSelectedCollectionIds().join (","));
}

void FunctionSimilarityDialog::on_SearchBinaries() {
    BinarySearchDialog* bsDlg = new BinarySearchDialog (
        (QWidget*)this,
        false /* store ids on double click instead of opening links */
    );
    bsDlg->exec();
    binaryIdsInput->setText (binaryIdsInput->text() + bsDlg->getSelectedBinaryIds().join (","));
}

void FunctionSimilarityDialog::on_TableCellDoubleClick (int row, int column) {
    // ignore last column
    if (column == 5) {
        return;
    }

    // generate portal URL from host URL
    Str link = StrDup (&GetConnection()->host);
    StrReplaceZstr (&link, "api", "portal", 1); // replaces first occurrence

    // fetch collection id and open url
    QString functionId = table->item (row, 1)->text();
    StrAppendf (&link, "/function/%llu", functionId.toULongLong());
    QDesktopServices::openUrl (QUrl (link.data));

    StrDeinit (&link);
}

void FunctionSimilarityDialog::addNewRowToResultsTable (QTableWidget* t, const QStringList& row) {
    size_t tableRowCount = t->rowCount();
    t->insertRow (tableRowCount);

    for (i32 i = 0; i < headerLabels.size() - 1; i++) {
        t->setItem (tableRowCount, i, new QTableWidgetItem (row[i]));
    }

    QPushButton* renameBtn = new QPushButton ("Rename");
    t->setCellWidget (tableRowCount, 5, renameBtn);

    connect (renameBtn, &QPushButton::clicked, this, [this, tableRowCount]() {
        // get target function name
        QString targetFunctionName = table->item (tableRowCount, 0)->text();

        // get source function name
        const QString& sourceFunctionName = searchBarInput->text();

        // add to rename map
        oldNameToNewNameMap.push_back ({sourceFunctionName, targetFunctionName});
    });
}
