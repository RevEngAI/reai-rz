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
#include <sys/stdio.h>

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

    if (!reai_plugin_create_analysis_for_opened_binary_file (
            core,
            progName.constData(),
            cmdLineArgs.constData(),
            isPrivate
        )) {
        DISPLAY_ERROR ("Failed to create new analysis");
    }
}
