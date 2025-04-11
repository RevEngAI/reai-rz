/**
 * @file      : FunctionSimilarityDialog.cpp
 * @date      : 25th Sept 2024
 * @author    : Siddharth Mishra (admin@brightprogrammer.in)
 * @copyright : Copyright (c) 2024 RevEngAI. All Rights Reserved.
 * */

/* plugin */
#include <Plugin.h>
#include <Reai/Api/Reai.h>
#include <Cutter/Ui/FunctionSimilarityDialog.hpp>
#include <Cutter/Ui/CollectionSearchDialog.hpp>
#include <Cutter/Ui/BinarySearchDialog.hpp>

/* qt */
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QScrollArea>
#include <QPushButton>
#include <QHeaderView>
#include <QCompleter>
#include <QLabel>

/* cutter */
#include <cutter/core/Cutter.h>
#include <librz/rz_analysis.h>

/* reai */
#include <Reai/Util/Vec.h>

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

        if (!reai_plugin_get_rizin_analysis_function_count (core)) {
            return;
        }

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
    connect (
        binaryIdsSearchBtn,
        &QPushButton::pressed,
        this,
        &FunctionSimilarityDialog::on_SearchBinaries
    );

    QPushButton* collectionIdsSearchBtn = new QPushButton ("Select Collections");
    connect (
        collectionIdsSearchBtn,
        &QPushButton::pressed,
        this,
        &FunctionSimilarityDialog::on_SearchCollections
    );

    QPushButton* searchBtn = new QPushButton ("Search", this);
    connect (
        searchBtn,
        &QPushButton::pressed,
        this,
        &FunctionSimilarityDialog::on_FindSimilarNames
    );

    QPushButton* cancelBtn = new QPushButton ("Cancel", this);
    connect (cancelBtn, &QPushButton::pressed, this, &FunctionSimilarityDialog::close);

    QDialogButtonBox* btnBox = new QDialogButtonBox (this);
    btnBox->addButton (collectionIdsSearchBtn, QDialogButtonBox::ActionRole);
    btnBox->addButton (binaryIdsSearchBtn, QDialogButtonBox::ActionRole);
    btnBox->addButton (searchBtn, QDialogButtonBox::AcceptRole);
    btnBox->addButton (cancelBtn, QDialogButtonBox::RejectRole);
    mainLayout->addWidget (btnBox);
}

void FunctionSimilarityDialog::on_FindSimilarNames() {
    RzCoreLocked core (Core());

    /* check if function exists or not */
    const QString& fnName        = searchBarInput->text();
    QByteArray     fnNameByteArr = fnName.toLatin1();
    CString        fnNameCStr    = fnNameByteArr.constData();

    Uint32 required_similarity = similaritySlider->value();
    Bool   debugFilter         = enableDebugFilterCheckBox->checkState() == Qt::CheckState::Checked;
    Int32  maxResultCount      = maxResultCountInput->value();

    const QString& collectionIdsCsv        = collectionIdsInput->text();
    QByteArray     collectionIdsCsvByteArr = collectionIdsCsv.toLatin1();
    CString        collectionIdsCsvCStr    = collectionIdsCsvByteArr.constData();

    const QString& binaryIdsCsv        = collectionIdsInput->text();
    QByteArray     binaryIdsCsvByteArr = collectionIdsCsv.toLatin1();
    CString        binaryIdsCsvCStr    = collectionIdsCsvByteArr.constData();

    if (!reai_plugin_search_and_show_similar_functions (
            core,
            fnNameCStr,
            maxResultCount,
            required_similarity,
            debugFilter,
            collectionIdsCsvCStr,
            binaryIdsCsvCStr
        )) {
        DISPLAY_ERROR ("Failed to get similar functions search result.");
    }
}

void FunctionSimilarityDialog::on_SearchCollections() {
    CollectionSearchDialog* csDlg = new CollectionSearchDialog ((QWidget*)this, false);
    csDlg->exec();
    collectionIdsInput->setText (
        collectionIdsInput->text() + csDlg->getSelectedCollectionIds().join (",")
    );
}

void FunctionSimilarityDialog::on_SearchBinaries() {
    BinarySearchDialog* bsDlg = new BinarySearchDialog ((QWidget*)this, false);
    bsDlg->exec();
    binaryIdsInput->setText (binaryIdsInput->text() + bsDlg->getSelectedBinaryIds().join (","));
}
