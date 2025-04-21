/**
 * @file      : RecentAnalysisDialog.hpp
 * @author    : Siddharth Mishra
 * @date      : 8th Apr 2025
 * @copyright : Copyright (c) 2025 RevEngAI. All Rights Reserved.
 * */

#ifndef REAI_PLUGIN_CUTTER_UI_RECENT_ANALYSIS_DIALOG_HPP
#define REAI_PLUGIN_CUTTER_UI_RECENT_ANALYSIS_DIALOG_HPP

/* qt */
#include <QDialog>
#include <QLineEdit>
#include <QTableWidget>
#include <QVBoxLayout>
#include <QTableWidget>
#include <QComboBox>
#include <QCheckBox>

/* rizin */
#include <rz_core.h>

/* reai */
#include <Reai/Types.h>

/* plugin */
#include <Table.h>


class RecentAnalysisDialog : public QDialog {
    Q_OBJECT;

   public:
    RecentAnalysisDialog (QWidget* parent);

   private:
    QVBoxLayout*  mainLayout;
    QLineEdit *   usernamesInput, *searchTermInput;
    QComboBox *   modelNameSelector, *workspaceSelector, *orderBySelector, *statusSelector;
    QCheckBox*    isOrderedInAsc;
    QStringList   headerLabels;
    QTableWidget* table;

    void on_GetRecentAnalysis();
    void on_TableCellDoubleClick (int row, int column);

    void addNewRowToResultsTable (QTableWidget* t, const QStringList& row);
};

#endif // REAI_PLUGIN_CUTTER_UI_RECENT_ANALYSIS_DIALOG_HPP
