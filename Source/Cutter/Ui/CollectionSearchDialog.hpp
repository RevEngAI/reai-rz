/**
 * @file      : CollectionSearchDialog.hpp
 * @author    : Siddharth Mishra
 * @date      : 8th Apr 2025
 * @copyright : Copyright (c) 2025 RevEngAI. All Rights Reserved.
 * */

#ifndef REAI_PLUGIN_CUTTER_UI_COLLECTION_SEARCH_DIALOG_HPP
#define REAI_PLUGIN_CUTTER_UI_COLLECTION_SEARCH_DIALOG_HPP

/* qt */
#include <QDialog>
#include <QLineEdit>
#include <QTableWidget>
#include <QVBoxLayout>
#include <QTableWidget>
#include <QComboBox>

/* rizin */
#include <rz_core.h>

/* reai */
#include <Reai/Types.h>

/* plugin */
#include <Table.h>


class CollectionSearchDialog : public QDialog {
    Q_OBJECT;

   public:
    CollectionSearchDialog (QWidget* parent, bool openPageOnDoubleClick);

    const QStringList& getSelectedCollectionIds() const {
        return selectedCollectionIds;
    }

   private:
    QVBoxLayout*  mainLayout;
    QLineEdit *   partialCollectionNameInput, *partialBinaryNameInput, *partialBinarySha256Input;
    QComboBox*    modelNameSelector;
    QStringList   headerLabels;
    QTableWidget* table;

    QStringList selectedCollectionIds;
    bool        openPageOnDoubleClick;

    void on_PerformCollectionSearch();
    void on_TableCellDoubleClick (int row, int column);

    void addNewRowToResultsTable (QTableWidget* t, const QStringList& row);
};

#endif // REAI_PLUGIN_CUTTER_UI_COLLECTION_SEARCH_DIALOG_HPP
