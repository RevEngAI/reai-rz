/**
 * @file      : CreateAnalysisDialog.hpp
 * @author    : Siddharth Mishra
 * @date      : 11th Nov 2024
 * @copyright : Copyright (c) 2024 RevEngAI. All Rights Reserved.
 * */

#ifndef REAI_PLUGIN_CUTTER_UI_CREATE_ANALYSIS_DIALOG_HPP
#define REAI_PLUGIN_CUTTER_UI_CREATE_ANALYSIS_DIALOG_HPP

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


class CreateAnalysisDialog : public QDialog {
    Q_OBJECT;

   public:
    CreateAnalysisDialog (QWidget* parent);

   private:
    QVBoxLayout* mainLayout;
    QLineEdit*   progNameInput;
    QLineEdit*   cmdLineArgsInput;
    QCheckBox*   isAnalysisPrivateCheckBox;

    void on_CreateAnalysis();
};

#endif // REAI_PLUGIN_CUTTER_UI_CREATE_ANALYSIS_DIALOG_HPP
