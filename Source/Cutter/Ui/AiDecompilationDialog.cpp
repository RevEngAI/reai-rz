/**
 * @file      : AiDecompilationDialog.cpp
 * @date      : 25th Sept 2024
 * @author    : Siddharth Mishra (admin@brightprogrammer.in)
 * @copyright : Copyright (c) 2024 RevEngAI. All Rights Reserved.
 * */

/* plugin */
#include <Plugin.h>
#include <Reai/Api/Reai.h>
#include <Cutter/Ui/AiDecompilationDialog.hpp>

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

AiDecompilationDialog::AiDecompilationDialog (QWidget* parent) : QDialog (parent) {
    mainLayout = new QVBoxLayout;
    setLayout (mainLayout);
    setWindowTitle ("Function Similarity Search");

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
        maxResultsInput->setText ("5");
        searchBarLayout->addWidget (maxResultsInput);

        searchButton = new QPushButton ("Search", this);
        searchBarLayout->addWidget (searchButton);
        connect (
            searchButton,
            &QPushButton::pressed,
            this,
            &AiDecompilationDialog::on_BeginAiDecompilation
        );
    }

    decompAllCheckBox = new QCheckBox ("Decompile All?", this);
    mainLayout->addWidget (decompAllCheckBox);
    decompAllCheckBox->setCheckState (Qt::CheckState::Unchecked);
    connect (
        decompAllCheckBox,
        &QCheckBox::checkStateChanged,
        this,
        &AiDecompilationDialog::on_DecompAllCheckBoxStateChanged
    );
}

void AiDecompilationDialog::on_BeginAiDecompilation() {
    RzCoreLocked core (Core());

    Bool decompAll = decompAllCheckBox->checkState() == Qt::CheckState::Checked;

    if (decompAll) {
        if (!reai_plugin_begin_ai_decompilation_for_all_functions (core)) {
            DISPLAY_ERROR ("Failed to begin AI decompilation for provided function.");
        }
    } else {
        /* check if function exists or not */
        const QString& fnName        = searchBarInput->text();
        QByteArray     fnNameByteArr = fnName.toLatin1();
        CString        fnNameCStr    = fnNameByteArr.constData();

        if (!reai_plugin_begin_ai_decompilation_for_function (core, fnNameCStr)) {
            DISPLAY_ERROR ("Failed to begin AI decompilation for provided function.");
        }
    }
}

void AiDecompilationDialog::on_DecompAllCheckBoxStateChanged() {
    bool state = decompAllCheckBox->checkState() != Qt::CheckState::Checked;
    searchBarInput->setEnabled (state);
    searchButton->setEnabled (state);
}
