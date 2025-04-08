/**
 * @file      : BinarySearchDialog.hpp
 * @date      : 8th Apr 2025
 * @author    : Siddharth Mishra (admin@brightprogrammer.in)
 * @copyright : Copyright (c) 2025 RevEngAI. All Rights Reserved.
 * */

#ifndef REAI_PLUGIN_CUTTER_UI_BINARY_SEARCH_DIALOG_HPP
#define REAI_PLUGIN_CUTTER_UI_BINARY_SEARCH_DIALOG_HPP

/* qt */
#include <QDialog>
#include <QLineEdit>
#include <QTableWidget>
#include <QVBoxLayout>
#include <QComboBox>

/* rizin */
#include <rz_core.h>

/* reai */
#include <Reai/Types.h>

/* plugin */
#include <Table.h>


class BinarySearchDialog : public QDialog {
    Q_OBJECT;

   public:
    BinarySearchDialog (QWidget* parent);

   private:
    QVBoxLayout* mainLayout;
    QLineEdit *  partialBinaryNameInput, *partialBinarySha256Input;
    QComboBox*   modelNameInput;

    void on_PerformBinarySearch();
};

#endif // REAI_PLUGIN_CUTTER_UI_BINARY_SEARCH_DIALOG_HPP
