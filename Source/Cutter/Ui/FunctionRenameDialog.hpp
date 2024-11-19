/**
 * @file      : FunctionRenameDialog.hpp
 * @date      : 11th Sept 2024
 * @author    : Siddharth Mishra (admin@brightprogrammer.in)
 * @copyright : Copyright (c) 2024 RevEngAI. All Rights Reserved.
 *
 * Dialog widget to ask user about what function to rename and what to rename it to.
 * */

#ifndef REAI_PLUGIN_CUTTER_UI_FUNCTION_RENAME_DIALOG_HPP
#define REAI_PLUGIN_CUTTER_UI_FUNCTION_RENAME_DIALOG_HPP

/* qt */
#include <QDialog>
#include <QLineEdit>
#include <QGridLayout>
#include <QTableWidget>
#include <QAction>

/* rizin */
#include <rz_core.h>

/* reai */
#include <Reai/Types.h>

class FunctionRenameDialog : public QDialog {
    Q_OBJECT;

   public:
    FunctionRenameDialog (QWidget* parent);

    void getNameMapping (std::vector<std::pair<QString, QString>>& map);
    Bool isFinished() const {
        return is_finished;
    }

   private:
    QStringList oldFnNamesList;

    QLineEdit *   searchBar, *newFnName;
    QCompleter*   fnNameCompleter;
    QTableWidget* newNameMapTable;

    Bool is_finished = false;

    Bool checkNewNameIsUnique (const QString& newName);
    Bool checkOldNameIsUnique (const QString& oldName);

    void on_AddToRename();
    void on_Finish();
};

#endif // REAI_PLUGIN_CUTTER_UI_FUNCTION_RENAME_DIALOG_HPP
