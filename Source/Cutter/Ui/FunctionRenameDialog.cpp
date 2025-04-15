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
#include <cutter/core/Cutter.h>

/* qt */
#include <QVBoxLayout>
#include <QScrollArea>
#include <QLabel>
#include <QCompleter>
#include <QPushButton>
#include <QTableWidget>
#include <QStringListModel>
#include <QDialogButtonBox>
#include <QHeaderView>

FunctionRenameDialog::FunctionRenameDialog (QWidget* parent) : QDialog (parent) {
    QVBoxLayout* mainLayout = new QVBoxLayout;
    setLayout (mainLayout);
    setWindowTitle ("Select Functions To Rename");

    /* get function names from binary */
    {
        RzCoreLocked core (Core());

        if (!reai_plugin_get_rizin_analysis_function_count (core)) {
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

    QGridLayout* l = new QGridLayout (this);
    QLabel*      n = nullptr;

    mainLayout->addLayout (l);

    /* create search bar and add and cancel buttons to add/cancel adding a
     * new name map */

    n = new QLabel (this);
    n->setText ("Current name : ");
    searchBar = new QLineEdit (this);
    searchBar->setPlaceholderText ("Start typing to get suggestions...");
    l->addWidget (n, 0, 0);
    l->addWidget (searchBar, 0, 1);

    fnNameCompleter = new QCompleter (oldFnNamesList);
    fnNameCompleter->setCaseSensitivity (Qt::CaseInsensitive);
    searchBar->setCompleter (fnNameCompleter);

    n = new QLabel (this);
    n->setText ("New name : ");
    newFnName = new QLineEdit (this);
    newFnName->setPlaceholderText ("New function name");
    l->addWidget (n, 1, 0);
    l->addWidget (newFnName, 1, 1);

    QPushButton* addBtn = new QPushButton ("Add to rename", this);
    connect (addBtn, &QPushButton::pressed, this, &FunctionRenameDialog::on_AddToRename);

    QPushButton* finishBtn = new QPushButton ("Rename all", this);
    connect (finishBtn, &QPushButton::pressed, this, &FunctionRenameDialog::on_Finish);

    QPushButton* cancelBtn = new QPushButton ("Cancel", this);
    connect (cancelBtn, &QPushButton::pressed, this, &FunctionRenameDialog::close);

    QDialogButtonBox* btnBox = new QDialogButtonBox (this);
    mainLayout->addWidget (btnBox);
    btnBox->addButton (addBtn, QDialogButtonBox::ActionRole);
    btnBox->addButton (finishBtn, QDialogButtonBox::AcceptRole);
    btnBox->addButton (cancelBtn, QDialogButtonBox::RejectRole);

    /* create grid layout with scroll area where new name mappings will
     * be displayed like a table */
    {
        newNameMapTable = new QTableWidget (0, 2);
        mainLayout->addWidget (newNameMapTable);

        newNameMapTable->setHorizontalHeaderLabels ({"Old Name", "New Name"});
        // Turn off editing
        newNameMapTable->setEditTriggers (QAbstractItemView::NoEditTriggers);
        // Allow columns to stretch as much as posible
        newNameMapTable->horizontalHeader()->setSectionResizeMode (QHeaderView::Stretch);
    }
}

void FunctionRenameDialog::getNameMapping (std::vector<std::pair<QString, QString>>& map) {
    for (int s = 0; s < newNameMapTable->rowCount(); s++) {
        const QString& oldName = newNameMapTable->item (s, 0)->text();
        const QString& newName = newNameMapTable->item (s, 1)->text();
        map.push_back ({oldName, newName});

        REAI_LOG_TRACE (
            "oldName = \"%s\" \t newName \"%s\"",
            oldName.toLatin1().constData(),
            oldName.toLatin1().constData()
        );
    }
}

Bool FunctionRenameDialog::checkNewNameIsUnique (const QString& newName) {
    for (int s = 0; s < newNameMapTable->rowCount(); s++) {
        if (newNameMapTable->item (s, 0)->text() == newName) {
            return false;
        }
    }

    return true;
}

Bool FunctionRenameDialog::checkOldNameIsUnique (const QString& oldName) {
    for (int s = 0; s < newNameMapTable->rowCount(); s++) {
        if (newNameMapTable->item (s, 1)->text() == oldName) {
            return false;
        }
    }

    return true;
}

void FunctionRenameDialog::on_AddToRename() {
    const QString& oldName = searchBar->text();
    const QString& newName = newFnName->text();

    /* both new and old names must be unique */
    if (!(checkNewNameIsUnique (newName) && checkOldNameIsUnique (oldName))) {
        DISPLAY_ERROR (
            "New name and old name must be unique one-to-one mapping. Cannot add this to rename."
        );
        return;
    }

    /* given old name must exist before it's added */
    if (!oldFnNamesList.contains (oldName)) {
        DISPLAY_ERROR (
            "Provided old name does not exist in Rizin's analysis of opened binary. Cannot add "
            "this to rename."
        );
        return;
    }

    Size row = newNameMapTable->rowCount();
    newNameMapTable->insertRow (row);
    newNameMapTable->setItem (row, 0, new QTableWidgetItem (oldName));
    newNameMapTable->setItem (row, 1, new QTableWidgetItem (newName));

    oldFnNamesList.removeOne (oldName);
    fnNameCompleter->setModel (new QStringListModel (oldFnNamesList, fnNameCompleter));
}

void FunctionRenameDialog::on_Finish() {
    is_finished = true;
    close();
}
