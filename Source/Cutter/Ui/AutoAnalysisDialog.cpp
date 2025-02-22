/**
 * @file      : AutoAnalysisDialog.cpp
 * @date      : 11th Nov 2024
 * @author    : Siddharth Mishra (admin@brightprogrammer.in)
 * @copyright : Copyright (c) 2024 RevEngAI. All Rights Reserved.
 * */

/* plugin */
#include <Plugin.h>
#include <Reai/Api/Reai.h>
#include <Cutter/Ui/AutoAnalysisDialog.hpp>

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

AutoAnalysisDialog::AutoAnalysisDialog (QWidget* parent) : QDialog (parent) {
    mainLayout = new QVBoxLayout;
    setLayout (mainLayout);
    setWindowTitle ("Auto Analysis Settings");

    confidenceSlider = new QSlider (Qt::Horizontal);
    confidenceSlider->setMinimum (1);
    confidenceSlider->setMaximum (100);
    confidenceSlider->setValue (90);
    mainLayout->addWidget (confidenceSlider);

    QLabel* confidenceLabel = new QLabel ("90% min confidence");
    mainLayout->addWidget (confidenceLabel);
    connect (confidenceSlider, &QSlider::valueChanged, [confidenceLabel] (int value) {
        confidenceLabel->setText (QString ("%1 % min confidence").arg (value));
    });

    enableDebugModeCheckBox = new QCheckBox ("Enable debug mode", this);
    mainLayout->addWidget (enableDebugModeCheckBox);
    enableDebugModeCheckBox->setCheckState (Qt::CheckState::Checked);

    QHBoxLayout* btnLayout = new QHBoxLayout (this);
    mainLayout->addLayout (btnLayout);

    QPushButton* okBtn     = new QPushButton ("Ok");
    QPushButton* cancelBtn = new QPushButton ("Cancel");
    btnLayout->addWidget (cancelBtn);
    btnLayout->addWidget (okBtn);

    connect (okBtn, &QPushButton::clicked, this, &AutoAnalysisDialog::on_PerformAutoAnalysis);
    connect (cancelBtn, &QPushButton::clicked, this, &QDialog::close);
}

void AutoAnalysisDialog::on_PerformAutoAnalysis() {
    RzCoreLocked core (Core());

    Float32 confidence     = confidenceSlider->value() / 100.f;
    Bool    debugMode      = enableDebugModeCheckBox->checkState() == Qt::CheckState::Checked;
    Uint32  maxResultCount = 10;

    if (!reai_plugin_auto_analyze_opened_binary_file (
            core,
            maxResultCount,
            confidence,
            debugMode
        )) {
        DISPLAY_ERROR ("Failed to perfom auto-analysis.");
    }
}
