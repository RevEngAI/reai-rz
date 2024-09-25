/**
 * @file      : FunctionSimilarityDialog.hpp
 * @author    : Siddharth Mishra
 * @date      : 25th Sept 2024
 * @copyright : Copyright (c) 2024 RevEngAI. All Rights Reserved.
 * */

#ifndef REAI_PLUGIN_CUTTER_UI_FUNCTION_SIMILARITY_DIALOG_HPP
#define REAI_PLUGIN_CUTTER_UI_FUNCTION_SIMILARITY_DIALOG_HPP

/* qt */
#include <QDialog>
#include <QLineEdit>
#include <QTableWidget>

/* rizin */
#include <rz_core.h>

class FunctionSimilarityDialog : public QDialog {
    Q_OBJECT;

   public:
    FunctionSimilarityDialog (QWidget* parent, RzCore* core);

   private:
    QLineEdit*    searchBar;
    QCompleter*   fnNameCompleter;
    QTableWidget* similarNameSuggestionTable;

    void on_FindSimilarNames();

    // TODO: Add a rename button, that when an entry in table is selected
    // we can rename the given function name to selected function name
};

#endif // REAI_PLUGIN_CUTTER_UI_FUNCTION_SIMILARITY_DIALOG_HPP
