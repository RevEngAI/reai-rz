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

/* cutter */
#include <cutter/Cutter.hpp>

/* reai */
#include <Reai/Util/Vec.h>

FunctionSimilarityDialog::FunctionSimilarityDialog (QWidget* parent, RzCore* core)
    : QDialog (parent) {
    if (!core) {
        DISPLAY_ERROR ("Invalid rizin core provided. Cannot find similar functions.");
        return;
    }

    QVBoxLayout* mainLayout = new QVBoxLayout;
    setLayout (mainLayout);
    setWindowTitle ("Function similarity");

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
                "renaming."
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

        searchBar = new QLineEdit (this);
        searchBar->setPlaceholderText ("Type to search...");
        searchBarLayout->addWidget (searchBar);

        fnNameCompleter = new QCompleter (fnNamesList);
        fnNameCompleter->setCaseSensitivity (Qt::CaseInsensitive);
        searchBar->setCompleter (fnNameCompleter);

        QPushButton* searchButton = new QPushButton ("Search", this);
        searchBarLayout->addWidget (searchButton);
        connect (
            searchButton,
            &QPushButton::pressed,
            this,
            &FunctionSimilarityDialog::on_FindSimilarNames
        );

        // TODO: add widgets to allow tweaking of min confidence, distance, etc...
    }

    /* create grid layout with scroll area where new name mappings will
     * be displayed like a table */
    {
        similarNameSuggestionTable = new QTableWidget (0, 2);
        mainLayout->addWidget (similarNameSuggestionTable);

        similarNameSuggestionTable->setHorizontalHeaderLabels (
            {"Function Name", "Confidence", "Function ID", "Binary Name"}
        );
        // Turn off editing
        similarNameSuggestionTable->setEditTriggers (QAbstractItemView::NoEditTriggers);
        // Allow columns to stretch as much as posible
        similarNameSuggestionTable->horizontalHeader()->setSectionResizeMode (QHeaderView::Stretch);
    }
}

void FunctionSimilarityDialog::on_FindSimilarNames() {
    similarNameSuggestionTable->clearContents();
    similarNameSuggestionTable->setRowCount (0);

    RzCoreLocked core (Core());

    /* check if function exists or not */
    const QString&      fnName        = searchBar->text();
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

    ReaiAnnFnMatchVec* fnMatches =
        reai_batch_function_symbol_ann (reai(), reai_response(), fnId, nullptr, 5, 0.25, nullptr);

    REAI_VEC_FOREACH (fnMatches, fnMatch, {
        Size row = similarNameSuggestionTable->rowCount();
        similarNameSuggestionTable->insertRow (row);
        similarNameSuggestionTable
            ->setItem (row, 0, new QTableWidgetItem (fnMatch->nn_function_name));
        similarNameSuggestionTable->setItem (row, 1, new QTableWidgetItem (fnMatch->confidence));
        similarNameSuggestionTable
            ->setItem (row, 1, new QTableWidgetItem (fnMatch->nn_function_id));
        similarNameSuggestionTable
            ->setItem (row, 1, new QTableWidgetItem (fnMatch->nn_binary_name));
    });
}
