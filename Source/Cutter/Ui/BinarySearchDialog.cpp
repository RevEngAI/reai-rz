/**
 * @file      : BinarySearchDialog.cpp
 * @date      : 8th Apr 2025
 * @author    : Siddharth Mishra (admin@brightprogrammer.in)
 * @copyright : Copyright (c) 2025 RevEngAI. All Rights Reserved.
 * */

/* plugin */
#include <Plugin.h>
#include <Reai/Api/Reai.h>
#include <Cutter/Ui/BinarySearchDialog.hpp>

/* qt */
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QScrollArea>
#include <QPushButton>
#include <QLabel>

/* cutter */
#include <cutter/core/Cutter.h>
#include <librz/rz_analysis.h>

/* reai */
#include <Reai/Util/Vec.h>

BinarySearchDialog::BinarySearchDialog (QWidget* parent) : QDialog (parent) {
    mainLayout = new QVBoxLayout;
    setLayout (mainLayout);
    setWindowTitle ("Binary Search");

    partialBinaryNameInput = new QLineEdit (this);
    partialBinaryNameInput->setPlaceholderText ("partial name");
    mainLayout->addWidget (partialBinaryNameInput);

    partialBinarySha256Input = new QLineEdit (this);
    partialBinarySha256Input->setPlaceholderText ("partial sha256");
    mainLayout->addWidget (partialBinarySha256Input);

    modelNameInput = new QComboBox (this);
    modelNameInput->setPlaceholderText ("Model name");
    REAI_VEC_FOREACH (reai_ai_models(), ai_model, { modelNameInput->addItem (*ai_model); });
    mainLayout->addWidget (modelNameInput);

    QHBoxLayout* btnLayout = new QHBoxLayout (this);
    mainLayout->addLayout (btnLayout);

    QPushButton* okBtn     = new QPushButton ("Ok");
    QPushButton* cancelBtn = new QPushButton ("Cancel");
    btnLayout->addWidget (cancelBtn);
    btnLayout->addWidget (okBtn);

    connect (okBtn, &QPushButton::clicked, this, &BinarySearchDialog::on_PerformBinarySearch);
    connect (cancelBtn, &QPushButton::clicked, this, &QDialog::close);
}

void BinarySearchDialog::on_PerformBinarySearch() {
    RzCoreLocked core (Core());

    const QString& partialBinaryName        = partialBinaryNameInput->text();
    QByteArray     partialBinaryNameByteArr = partialBinaryName.toLatin1();
    CString        partialBinaryNameCStr    = partialBinaryNameByteArr.constData();

    const QString& partialBinarySha256        = partialBinarySha256Input->text();
    QByteArray     partialBinarySha256ByteArr = partialBinarySha256.toLatin1();
    CString        partialBinarySha256CStr    = partialBinarySha256ByteArr.constData();

    CString modelNameCStr = NULL;
    if (modelNameInput->currentIndex() != -1) {
        const QString& modelName        = modelNameInput->currentText();
        QByteArray     modelNameByteArr = modelName.toLatin1();
        modelNameCStr                   = modelNameByteArr.constData();
    }

    if (!reai_plugin_binary_search (
            core,
            partialBinaryNameCStr,
            partialBinarySha256CStr,
            modelNameCStr,
            NULL
        )) {
        DISPLAY_ERROR ("Failed to perfom collection search.");
    }
}
