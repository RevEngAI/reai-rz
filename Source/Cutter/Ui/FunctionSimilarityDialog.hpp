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
#include <QSpinBox>
#include <QVBoxLayout>

/* rizin */
#include <rz_core.h>

class FunctionSimilarityDialog : public QDialog {
    Q_OBJECT;

   public:
    FunctionSimilarityDialog (QWidget* parent);

    // Take a name to name mapping vector and copy contents over
    // from our local copy
    void getNameMapping (std::vector<std::pair<QString, QString>>& nameMap) const {
        nameMap = oldNameToNewNameMap;
    }

    bool doRename() const {
        return oldNameToNewNameMap.size() != 0;
    }

   private:
    std::vector<std::pair<QString, QString>> oldNameToNewNameMap;

    QVBoxLayout*  mainLayout;
    QLineEdit *   searchBarInput, *collectionIdsInput, *binaryIdsInput;
    QSpinBox*     maxResultCountInput;
    QSlider*      similaritySlider;
    QCheckBox*    enableDebugFilterCheckBox;
    QCompleter*   fnNameCompleter;
    QStringList   headerLabels;
    QTableWidget* table;

    void on_FindSimilarNames();
    void on_SearchCollections();
    void on_SearchBinaries();

    void on_TableCellDoubleClick (int row, int column);

    void addNewRowToResultsTable (QTableWidget* t, const QStringList& row);
};

#endif // REAI_PLUGIN_CUTTER_UI_FUNCTION_SIMILARITY_DIALOG_HPP
