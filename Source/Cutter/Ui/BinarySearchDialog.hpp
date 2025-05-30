/**
 * @file      : BinarySearchDialog.hpp
 * @author    : Siddharth Mishra
 * @date      : 8th Apr 2025
 * @copyright : Copyright (c) 2025 RevEngAI. All Rights Reserved.
 * */

#ifndef REAI_PLUGIN_CUTTER_UI_BINARY_SEARCH_DIALOG_HPP
#define REAI_PLUGIN_CUTTER_UI_BINARY_SEARCH_DIALOG_HPP

/* qt */
#include <QDialog>
#include <QLineEdit>
#include <QTableWidget>
#include <QVBoxLayout>
#include <QTableWidget>
#include <QComboBox>

/* rizin */
#include <rz_core.h>

class BinarySearchDialog : public QDialog {
    Q_OBJECT;

   public:
    BinarySearchDialog (QWidget* parent, bool openPageOnDoubleClick);

    const QStringList& getSelectedBinaryIds() const {
        return selectedBinaryIds;
    }

   private:
    QVBoxLayout*  mainLayout;
    QLineEdit *   partialBinaryNameInput, *partialBinarySha256Input;
    QComboBox*    modelNameSelector;
    QStringList   headerLabels;
    QTableWidget* table;

    QStringList selectedBinaryIds;
    bool        openPageOnDoubleClick;

    void on_PerformBinarySearch();
    void on_TableCellDoubleClick (int row, int column);

    void addNewRowToResultsTable (QTableWidget* t, const QStringList& row);
};

#endif // REAI_PLUGIN_CUTTER_UI_BINARY_SEARCH_DIALOG_HPP
