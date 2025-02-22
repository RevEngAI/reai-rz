/**
 * @file      : CreateAnalysisDialog.cpp
 * @date      : 11th Nov 2024
 * @author    : Siddharth Mishra (admin@brightprogrammer.in)
 * @copyright : Copyright (c) 2024 RevEngAI. All Rights Reserved.
 * */

/* plugin */
#include <Plugin.h>
#include <Reai/Api/Reai.h>
#include <Cutter/Ui/CreateAnalysisDialog.hpp>

/* qt */
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QPushButton>
#include <QLabel>

/* cutter */
#include <cutter/core/Cutter.h>
#include <librz/rz_analysis.h>

/* reai */
#include <Reai/Util/Vec.h>

CreateAnalysisDialog::CreateAnalysisDialog (QWidget* parent) : QDialog (parent) {
    mainLayout = new QVBoxLayout;
    setLayout (mainLayout);
    setWindowTitle ("Auto Analysis Settings");

    progNameInput = new QLineEdit (this);
    progNameInput->setPlaceholderText ("Program Name");
    mainLayout->addWidget (progNameInput);

    cmdLineArgsInput = new QLineEdit (this);
    cmdLineArgsInput->setPlaceholderText ("Command line arguments");
    mainLayout->addWidget (cmdLineArgsInput);

    aiModelInput = new QComboBox (this);
    aiModelInput->setPlaceholderText ("AI Model");
    REAI_VEC_FOREACH (reai_ai_models(), ai_model, { aiModelInput->addItem (*ai_model); });
    mainLayout->addWidget (aiModelInput);

    isAnalysisPrivateCheckBox = new QCheckBox ("Enable debug mode", this);
    mainLayout->addWidget (isAnalysisPrivateCheckBox);
    isAnalysisPrivateCheckBox->setCheckState (Qt::CheckState::Checked);

    QHBoxLayout* btnLayout = new QHBoxLayout (this);
    mainLayout->addLayout (btnLayout);

    QPushButton* okBtn     = new QPushButton ("Ok");
    QPushButton* cancelBtn = new QPushButton ("Cancel");
    btnLayout->addWidget (cancelBtn);
    btnLayout->addWidget (okBtn);

    connect (okBtn, &QPushButton::clicked, this, &CreateAnalysisDialog::on_CreateAnalysis);
    connect (cancelBtn, &QPushButton::clicked, this, &QDialog::close);
}

void CreateAnalysisDialog::on_CreateAnalysis() {
    RzCoreLocked core (Core());

    Bool isPrivate = isAnalysisPrivateCheckBox->checkState() == Qt::CheckState::Checked;

    QByteArray aiModelName = aiModelInput->currentText().toLatin1();
    QByteArray progName    = progNameInput->text().toLatin1();
    QByteArray cmdLineArgs = cmdLineArgsInput->text().toLatin1();

    if (progName.isEmpty()) {
        QMessageBox::warning (
            this,
            "Create Analysis",
            "Program Name cannot be empty.",
            QMessageBox::Ok
        );
        return;
    }

    if (aiModelName.isEmpty()) {
        QMessageBox::warning (
            this,
            "Create Analysis",
            "Please select an AI model to be used to create analysis.",
            QMessageBox::Ok
        );
        return;
    }

    if (reai_plugin_create_analysis_for_opened_binary_file (
            core,
            progName.constData(),
            cmdLineArgs.constData(),
            aiModelName.constData(),
            isPrivate
        )) {
        DISPLAY_INFO ("Analysis created successfully.");
    } else {
        DISPLAY_INFO ("Failed to create new analysis analysis.");
    }


    close();
}
