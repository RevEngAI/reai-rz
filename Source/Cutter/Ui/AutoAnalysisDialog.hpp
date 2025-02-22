/**
 * @file      : AutoAnalysisDialog.hpp
 * @author    : Siddharth Mishra
 * @date      : 11th Nov 2024
 * @copyright : Copyright (c) 2024 RevEngAI. All Rights Reserved.
 * */

#ifndef REAI_PLUGIN_CUTTER_UI_AUTO_ANALYSIS_DIALOG_HPP
#define REAI_PLUGIN_CUTTER_UI_AUTO_ANALYSIS_DIALOG_HPP

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


class AutoAnalysisDialog : public QDialog {
    Q_OBJECT;

   public:
    AutoAnalysisDialog (QWidget* parent);

   private:
    QVBoxLayout* mainLayout;
    QSlider*     confidenceSlider;
    QCheckBox*   enableDebugModeCheckBox;

    void on_PerformAutoAnalysis();
};

#endif // REAI_PLUGIN_CUTTER_UI_AUTO_ANALYSIS_DIALOG_HPP
