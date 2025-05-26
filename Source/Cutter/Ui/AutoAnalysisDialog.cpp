/**
 * @file      : AutoAnalysisDialog.cpp
 * @date      : 11th Nov 2024
 * @author    : Siddharth Mishra (admin@brightprogrammer.in)
 * @copyright : Copyright (c) 2024 RevEngAI. All Rights Reserved.
 * */

/* qt */
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QScrollArea>
#include <QPushButton>
#include <QLabel>

/* cutter */
#include <cutter/core/Cutter.h>
#include <librz/rz_analysis.h>

#include <Plugin.h>
#include <Reai/Api.h>
#include <Reai/Util/Vec.h>
#include <Cutter/Ui/AutoAnalysisDialog.hpp>

AutoAnalysisDialog::AutoAnalysisDialog (QWidget* parent) : QDialog (parent) {
    mainLayout = new QVBoxLayout;
    setLayout (mainLayout);
    setWindowTitle ("Auto Analysis Settings");

    similaritySlider = new QSlider (Qt::Horizontal);
    similaritySlider->setMinimum (1);
    similaritySlider->setMaximum (100);
    similaritySlider->setValue (90);
    mainLayout->addWidget (similaritySlider);

    QLabel* confidenceLabel = new QLabel ("90% min confidence");
    mainLayout->addWidget (confidenceLabel);
    connect (similaritySlider, &QSlider::valueChanged, [confidenceLabel] (int value) {
        confidenceLabel->setText (QString ("%1 % min confidence").arg (value));
    });

    enableDebugFilterCheckBox = new QCheckBox ("Restrict results to debug symbols only?", this);
    mainLayout->addWidget (enableDebugFilterCheckBox);
    enableDebugFilterCheckBox->setCheckState (Qt::CheckState::Checked);

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

    f32 required_similarity = similaritySlider->value() / 100.f;
    bool    debugFilter         = enableDebugFilterCheckBox->checkState() == Qt::CheckState::Checked;
    u32  maxResultCount      = 10;

    rzAutoRenameFunctions(core, maxResultCount, required_similarity, debugFilter);
}
