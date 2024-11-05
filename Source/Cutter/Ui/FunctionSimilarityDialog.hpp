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
#include <QSlider>
#include <QTableWidget>
#include <QCheckBox>

/* rizin */
#include <rz_core.h>

/* reai */
#include <Reai/Types.h>

/* plugin */
#include <Table.h>

class FunctionSimilarityDialog : public QDialog {
    Q_OBJECT;

   public:
    FunctionSimilarityDialog (QWidget* parent, RzCore* core);

   private:
    QLineEdit *      searchBarInput, *maxResultsInput;
    QSlider*         confidenceSlider;
    QCheckBox*       enableDebugModeCheckBox;
    QCheckBox*       showUniqueResultsCheckBox;
    QCompleter*      fnNameCompleter;
    QTableWidget*    similarNameSuggestionTable;
    ReaiPluginTable* resultsTable;

    void on_FindSimilarNames();
    void addUniqueRow (
        CString        fn_name,
        Float32        confidence,
        ReaiFunctionId fn_id,
        CString        binary_name
    );
    void addRow (CString fn_name, Float32 confidence, ReaiFunctionId fn_id, CString binary_name);

    // TODO: Add a rename button, that when an entry in table is selected
    // we can rename the given function name to selected function name
};

#endif // REAI_PLUGIN_CUTTER_UI_FUNCTION_SIMILARITY_DIALOG_HPP
