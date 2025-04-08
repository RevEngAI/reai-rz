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

        maxResultCountInput = new QSpinBox (this);
        maxResultCountInput->setValue (10);
        maxResultCountInput->setMinimum (1);
        maxResultCountInput->setPrefix ("Max ");
        maxResultCountInput->setSuffix (" results");
        searchBarLayout->addWidget (maxResultCountInput);

        QPushButton* searchButton = new QPushButton ("Search", this);
        searchBarLayout->addWidget (searchButton);
        connect (
            searchButton,
            &QPushButton::pressed,
            this,
            &FunctionSimilarityDialog::on_FindSimilarNames
        );
    }

    /* textbox for taking in collection names in csv format */
    collectionNamesInput = new QLineEdit (this);
    collectionNamesInput->setPlaceholderText ("Comma separated list of collection names");
    mainLayout->addWidget (collectionNamesInput);

    /* Create slider to select similarity level */
    {
        similaritySlider = new QSlider (Qt::Horizontal);
        similaritySlider->setMinimum (1);
        similaritySlider->setMaximum (100);
        similaritySlider->setValue (90);
        mainLayout->addWidget (similaritySlider);

        QLabel* similarityLabel = new QLabel ("90% min similarity");
        mainLayout->addWidget (similarityLabel);
        connect (similaritySlider, &QSlider::valueChanged, [similarityLabel] (int value) {
            similarityLabel->setText (QString ("%1 % min similarity").arg (value));
        });

        enableDebugFilterCheckBox =
            new QCheckBox ("Restrict suggestions to debug symbols only?", this);
        mainLayout->addWidget (enableDebugFilterCheckBox);
        enableDebugFilterCheckBox->setCheckState (Qt::CheckState::Checked);
    }
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

    const QString& collectionNamesCsv        = collectionNamesInput->text();
    QByteArray     collectionNamesCsvByteArr = collectionNamesCsv.toLatin1();
    CString        collectionNamesCsvCStr    = collectionNamesCsvByteArr.constData();

    if (!reai_plugin_search_and_show_similar_functions (
            core,
            fnNameCStr,
            maxResultCount,
            required_similarity,
            debugFilter,
            collectionNamesCsvCStr,
            NULL // TODO: binary ids csv
        )) {
        DISPLAY_ERROR ("Failed to get similar functions search result.");
    }
}
