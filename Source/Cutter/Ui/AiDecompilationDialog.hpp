/**
 * @file      : AiDecompilationDialog.hpp
 * @author    : Siddharth Mishra
 * @date      : 25th Sept 2024
 * @copyright : Copyright (c) 2024 RevEngAI. All Rights Reserved.
 * */

#ifndef REAI_PLUGIN_CUTTER_UI_AI_DECOMPILATION_DIALOG_HPP
#define REAI_PLUGIN_CUTTER_UI_AI_DECOMPILATION_DIALOG_HPP

/* qt */
#include <QDialog>
#include <QLineEdit>
#include <QSlider>
#include <QTableWidget>
#include <QCheckBox>
#include <QVBoxLayout>

/* rizin */
#include <rz_core.h>

/* reai */
#include <Reai/Types.h>

/* plugin */
#include <Table.h>

class AiDecompilationDialog : public QDialog {
    Q_OBJECT;

   public:
    AiDecompilationDialog (QWidget* parent);

   private:
    QVBoxLayout* mainLayout;
    QLineEdit *  searchBarInput, *maxResultsInput;
    QPushButton* searchButton;
    QCheckBox*   decompAllCheckBox;
    QCompleter*  fnNameCompleter;

    void on_BeginAiDecompilation();
    void on_DecompAllCheckBoxStateChanged();
};

#endif // REAI_PLUGIN_CUTTER_UI_AI_DECOMPILATION_DIALOG_HPP
