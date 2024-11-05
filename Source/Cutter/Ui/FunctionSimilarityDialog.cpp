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

/* reai */
#include <Reai/Util/Vec.h>

FunctionSimilarityDialog::FunctionSimilarityDialog (QWidget* parent, RzCore* core)
    : QDialog (parent) {
    if (!core) {
        DISPLAY_ERROR ("Invalid rizin core provided. Cannot find similar functions.");
        return;
    }

    setMinimumSize (960, 540);

    QVBoxLayout* mainLayout = new QVBoxLayout;
    setLayout (mainLayout);
    setWindowTitle ("Function Similarity Search");

    /* get function names from binary */
    QStringList fnNamesList;
    {
        if (!core->analysis) {
            DISPLAY_ERROR ("Rizin analysis not performed yet. Please create rizin analysis first.");
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
    {
        QHBoxLayout* searchBarLayout = new QHBoxLayout;
        mainLayout->addLayout (searchBarLayout);

        searchBarInput = new QLineEdit (this);
        searchBarInput->setPlaceholderText ("Type to search...");
        searchBarLayout->addWidget (searchBarInput);

        fnNameCompleter = new QCompleter (fnNamesList);
        fnNameCompleter->setCaseSensitivity (Qt::CaseInsensitive);
        searchBarInput->setCompleter (fnNameCompleter);

        maxResultsInput = new QLineEdit (this);
        maxResultsInput->setPlaceholderText ("Maximum search result count... eg: 5");
        searchBarLayout->addWidget (maxResultsInput);

        QPushButton* searchButton = new QPushButton ("Search", this);
        searchBarLayout->addWidget (searchButton);
        connect (
            searchButton,
            &QPushButton::pressed,
            this,
            &FunctionSimilarityDialog::on_FindSimilarNames
        );
    }

    /* Create sliders to select confidence levels and distance */
    {
        confidenceSlider = new QSlider (Qt::Horizontal);
        confidenceSlider->setMinimum (1);
        confidenceSlider->setMaximum (100);
        confidenceSlider->setValue (90);
        mainLayout->addWidget (confidenceSlider);

        QLabel* confidenceLabel = new QLabel ("90% min confidence");
        mainLayout->addWidget (confidenceLabel);
        connect (confidenceSlider, &QSlider::valueChanged, [confidenceLabel] (int value) {
            confidenceLabel->setText (QString ("%1 % min confidence").arg (value));
        });


        showUniqueResultsCheckBox = new QCheckBox ("Show unique results", this);
        mainLayout->addWidget (showUniqueResultsCheckBox);
        showUniqueResultsCheckBox->setCheckState (Qt::CheckState::Checked);

        enableDebugModeCheckBox = new QCheckBox ("Enable debug mode", this);
        mainLayout->addWidget (enableDebugModeCheckBox);
        enableDebugModeCheckBox->setCheckState (Qt::CheckState::Checked);
    }

    /* create grid layout with scroll area where new name mappings will
     * be displayed like a table */
    {
        // similarNameSuggestionTable = new QTableWidget (0, 4);
        // mainLayout->addWidget (similarNameSuggestionTable);
        //
        // similarNameSuggestionTable->setHorizontalHeaderLabels (
        //     {"Function Name", "Confidence", "Function ID", "Binary Name"}
        // );
        // // Turn off editing
        // similarNameSuggestionTable->setEditTriggers (QAbstractItemView::NoEditTriggers);
        // // Allow columns to stretch as much as posible
        // similarNameSuggestionTable->horizontalHeader()->setSectionResizeMode (QHeaderView::Stretch);

        resultsTable = reai_plugin_table_create();
        if (!reai_plugin_table_set_columnsf (
                resultsTable,
                "sfns",
                "Function Name",
                "Confidence",
                "Function ID",
                "Binary Name"
            )) {
            DISPLAY_ERROR (
                "Failed to set table columns information. Failed to create results table. Cannot "
                "continue"
            );
            return;
        }

        mainLayout->addWidget ((QTableWidget*)resultsTable);
    }
}

void FunctionSimilarityDialog::on_FindSimilarNames() {
    similarNameSuggestionTable->clearContents();
    similarNameSuggestionTable->setRowCount (0);

    RzCoreLocked core (Core());

    /* check if function exists or not */
    const QString&      fnName        = searchBarInput->text();
    QByteArray          fnNameByteArr = fnName.toLatin1();
    RzAnalysisFunction* rzFn =
        reai_plugin_get_rizin_analysis_function_with_name (core, fnNameByteArr.constData());

    if (!rzFn) {
        DISPLAY_ERROR ("Provided function name does not exist. Cannot get similar function names.");
        return;
    }

    ReaiFunctionId fnId = reai_plugin_get_function_id_for_rizin_function (core, rzFn);

    if (!fnId) {
        DISPLAY_ERROR (
            "Failed to get function id of given function. Cannot get similar function names."
        );
        return;
    }

    QString maxResultCountStr = maxResultsInput->text();
    bool    success           = false;
    Int32   maxResultCount    = maxResultCountStr.toInt (&success);

    if (!success) {
        DISPLAY_ERROR ("Failed to convert max result count input to integer.");
        return;
    }

    Float32 confidence  = confidenceSlider->value() / 100.f;
    Float32 maxDistance = 1 - confidence;

    if (!success) {
        DISPLAY_ERROR ("Failed to convert confidence input to float.");
        return;
    }

    ReaiAnnFnMatchVec* fnMatches = reai_batch_function_symbol_ann (
        reai(),
        reai_response(),
        fnId,
        nullptr,
        maxResultCount,
        maxDistance,
        nullptr,
        enableDebugModeCheckBox->checkState()
    );

    // Populate table
    REAI_VEC_FOREACH (fnMatches, fnMatch, {
        if (showUniqueResultsCheckBox->checkState() == Qt::CheckState::Checked)
            addUniqueRow (
                fnMatch->nn_function_name,
                fnMatch->confidence,
                fnMatch->nn_function_id,
                fnMatch->nn_binary_name
            );
        else {
            addRow (
                fnMatch->nn_function_name,
                fnMatch->confidence,
                fnMatch->nn_function_id,
                fnMatch->nn_binary_name
            );
        }
    });
}

void FunctionSimilarityDialog::addUniqueRow (
    CString        fn_name,
    Float32        confidence,
    ReaiFunctionId fn_id,
    CString        binary_name
) {
    if (!fn_name) {
        DISPLAY_ERROR ("Given function name is NULL. Cannot add to table cell.");
        return;
    }

    if (!fn_id) {
        DISPLAY_ERROR ("Given function id is invalid. Cannot add to table cell.");
        return;
    }

    if (!binary_name) {
        DISPLAY_ERROR ("Given binary name is NULL. Cannot add to table cell.");
        return;
    }

    // Check for duplicates
    bool duplicate = false;
    for (int row = 0; row < similarNameSuggestionTable->rowCount(); ++row) {
        QString val1 = similarNameSuggestionTable->item (row, 0) ?
                           similarNameSuggestionTable->item (row, 0)->text() :
                           "";
        QString val3 = similarNameSuggestionTable->item (row, 2) ?
                           similarNameSuggestionTable->item (row, 2)->text() :
                           "";
        QString val4 = similarNameSuggestionTable->item (row, 3) ?
                           similarNameSuggestionTable->item (row, 3)->text() :
                           "";

        if (!QString::compare (val1, QString::fromUtf8 (fn_name)) &&
            !QString::compare (val3, QString::number (fn_id)) &&
            !QString::compare (val4, QString::fromUtf8 (binary_name))) {
            duplicate = true;
            break;
        }
    }

    if (!duplicate) {
        addRow (fn_name, confidence, fn_id, binary_name);

        LOG_TRACE ("Unique row added to similar name suggestion table.");
    } else {
        LOG_TRACE (
            "Duplicate row detected, not adding to similar name suggestion table in "
            "FuntionSimilarityDialog."
        );
    }
}

void FunctionSimilarityDialog::addRow (
    CString        fn_name,
    Float32        confidence,
    ReaiFunctionId fn_id,
    CString        binary_name
) {
    if (!fn_name) {
        DISPLAY_ERROR ("Given function name is NULL. Cannot add to table cell.");
        return;
    }

    if (!fn_id) {
        DISPLAY_ERROR ("Given function id is invalid. Cannot add to table cell.");
        return;
    }

    if (!binary_name) {
        DISPLAY_ERROR ("Given binary name is NULL. Cannot add to table cell.");
        return;
    }


    // Int32 row = similarNameSuggestionTable->rowCount();
    // similarNameSuggestionTable->insertRow (row);
    // similarNameSuggestionTable->setItem (row, 0, new QTableWidgetItem (fn_name));
    // similarNameSuggestionTable
    //     ->setItem (row, 1, new QTableWidgetItem (QString::number (confidence)));
    // similarNameSuggestionTable->setItem (row, 2, new QTableWidgetItem (QString::number (fn_id)));
    // similarNameSuggestionTable->setItem (row, 3, new QTableWidgetItem (binary_name));
    reai_plugin_table_add_rowf (resultsTable, fn_name, confidence, fn_id, binary_name);

    LOG_TRACE ("Unique row added to similar name suggestion table.");
}
