/**
 * @file      : FunctionRenameDialog.cpp
 * @date      : 11th Sept 2024
 * @author    : Siddharth Mishra (admin@brightprogrammer.in)
 * @copyright : Copyright (c) 2024 RevEngAI. All Rights Reserved.
 * */

/* plugin */
#include <Plugin.h>
#include <Cutter/Ui/FunctionRenameDialog.hpp>

/* rizin */
#include <rz_analysis.h>

/* qt */
#include <QVBoxLayout>
#include <QScrollArea>
#include <QLabel>
#include <QCompleter>
#include <QPushButton>
#include <QTableWidget>

FunctionRenameDialog::FunctionRenameDialog (QWidget* parent, RzCore* core) : QDialog (parent) {
    if (!core) {
        DISPLAY_ERROR ("Invalid rizin core provided. Cannot rename functions.");
        return;
    }

    QVBoxLayout* mainLayout = new QVBoxLayout;
    setLayout (mainLayout);
    setWindowTitle ("Select Functions To Rename");

    /* get function names from binary */
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
            oldFnNamesList << fn->name;
        }
    }

    /* create grid layout with scroll area where new name mappings will
     * be displayed like a table */
    {
        newNameMapTable = new QTableWidget (0, 2);
        mainLayout->addWidget (newNameMapTable);

        newNameMapTable->setHorizontalHeaderLabels ({"Old Name", "New Name"});
    }

    /* create search bar and add and cancel buttons to add/cancel adding a
     * new name map */
    {
        QHBoxLayout* searchBarLayout = new QHBoxLayout;
        mainLayout->addLayout (searchBarLayout);

        searchBar = new QLineEdit (this);
        searchBar->setPlaceholderText ("Type to search...");
        searchBarLayout->addWidget (searchBar);

        fnNameCompleter = new QCompleter (oldFnNamesList);
        fnNameCompleter->setCaseSensitivity (Qt::CaseInsensitive);
        searchBar->setCompleter (fnNameCompleter);

        newFnName = new QLineEdit (this);
        newFnName->setPlaceholderText ("New function name");
        searchBarLayout->addWidget (newFnName);

        QPushButton* addButton = new QPushButton ("Add To Rename", this);
        searchBarLayout->addWidget (addButton);
        // TODO: connect

        QPushButton* finishButton = new QPushButton ("Finish", this);
        searchBarLayout->addWidget (finishButton);
        // TODO: connect
    }
}
