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
#include <librz/rz_analysis.h>

/* reai */
#include <Reai/Util/Vec.h>

FunctionSimilarityDialog::FunctionSimilarityDialog (QWidget* parent) : QDialog (parent) {
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

        enableDebugModeCheckBox = new QCheckBox ("Enable debug mode", this);
        mainLayout->addWidget (enableDebugModeCheckBox);
        enableDebugModeCheckBox->setCheckState (Qt::CheckState::Checked);
    }
}

void FunctionSimilarityDialog::on_FindSimilarNames() {
    RzCoreLocked core (Core());

    /* check if function exists or not */
    const QString& fnName        = searchBarInput->text();
    QByteArray     fnNameByteArr = fnName.toLatin1();
    CString        fnNameCStr    = fnNameByteArr.constData();

    Float32 confidence = confidenceSlider->value() / 100.f;
    Bool    debugMode  = enableDebugModeCheckBox->checkState() == Qt::CheckState::Checked;

    QString maxResultCountStr = maxResultsInput->text();
    bool    success           = false;
    Int32   maxResultCount    = maxResultCountStr.toInt (&success);

    if (!success) {
        DISPLAY_ERROR ("Failed to convert max result count input to integer.");
        return;
    }

    if (!reai_plugin_search_and_show_similar_functions (
            core,
            fnNameCStr,
            maxResultCount,
            confidence,
            debugMode
        )) {
        DISPLAY_ERROR ("Failed to get similar functions search result.");
    }
}
