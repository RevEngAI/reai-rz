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

/* reai */
#include <Reai/Types.h>

/* plugin */
#include <Table.h>

class FunctionSimilarityDialog : public QDialog {
    Q_OBJECT;

   public:
    FunctionSimilarityDialog (QWidget* parent);

   private:
    QVBoxLayout* mainLayout;
    QLineEdit *  searchBarInput, *collectionNamesInput;
    QSpinBox*    maxResultCountInput;
    QSlider*     similaritySlider;
    QCheckBox*   enableDebugFilterCheckBox;
    QCompleter*  fnNameCompleter;

    void on_FindSimilarNames();
};

#endif // REAI_PLUGIN_CUTTER_UI_FUNCTION_SIMILARITY_DIALOG_HPP
