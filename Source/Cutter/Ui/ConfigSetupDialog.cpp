/**
 * @file      : ConfigSetupDialog.cpp
 * @author    : Siddharth Mishra
 * @date      : 30/09/2024
 * @copyright : Copyright (c) 2024 RevEngAI. All Rights Reserved.
 * */

/* plugin */
#include <Plugin.h>
#include <Cutter/Ui/ConfigSetupDialog.hpp>

/* qt */
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>

ConfigSetupDialog::ConfigSetupDialog() {
    setWindowTitle ("Plugin Configuration Setup");

    QVBoxLayout* mainLayout = new QVBoxLayout;
    setLayout (mainLayout);

#define ADD_LABEL_INPUT_ROW(labelName, labelValue, inputName, inputValue)                          \
    QLabel* labelName = new QLabel (tr (labelValue), this);                                        \
    inputName         = new QLineEdit (this);                                                      \
    inputName->setPlaceholderText (inputValue);                                                    \
    QHBoxLayout* row##labelName##inputName = new QHBoxLayout (this);                               \
    row##labelName##inputName->addWidget (labelName);                                              \
    row##labelName##inputName->addWidget (inputName);                                              \
    mainLayout->addLayout (row##labelName##inputName);

    ADD_LABEL_INPUT_ROW (
        apiLabel,
        "RevEng.AI API Key",
        leApiKey,
        "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX"
    );
    ADD_LABEL_INPUT_ROW (hostLabel, "RevEng.AI Host", leHost, "https://api.reveng.ai/v1");
    ADD_LABEL_INPUT_ROW (modelLabel, "RevEng.AI AI Model", leModel, "binnet-0.3");
    ADD_LABEL_INPUT_ROW (
        dbDirPathLabel,
        "Plugin Local Database Path",
        leDbDirPath,
        reai_plugin_get_default_database_dir_path()
    );
    ADD_LABEL_INPUT_ROW (
        logDirPathLabel,
        "Plugin Local Log Storage Path",
        leLogDirPath,
        reai_plugin_get_default_log_dir_path()
    );

#undef ADD_LABEL_INPUT_ROW

    QHBoxLayout* btnsRow = new QHBoxLayout;
    mainLayout->addLayout (btnsRow);

    btnOk     = new QPushButton ("Ok", this);
    btnCancel = new QPushButton ("Cancel", this);
    btnsRow->addStretch();
    btnsRow->addWidget (btnCancel);
    btnsRow->addWidget (btnOk);


    // TODO: connect the wires
}

/**
 * @b Get value of host line edit.
 * */
QString ConfigSetupDialog::getHost() {
    return leHost->text();
}

/**
 * @b Get value of api key line edit.
 * */
QString ConfigSetupDialog::getApiKey() {
    return leApiKey->text();
}

/**
 * @b Get value of model line edit.
 * */
QString ConfigSetupDialog::getModel() {
    return leModel->text();
}

/**
 * @b Get value of db dir path line edit.
 * */
QString ConfigSetupDialog::getDbDirPath() {
    return leDbDirPath->text();
}

/**
 * @b Get value of log dir path line edit.
 * */
QString ConfigSetupDialog::getLogDirPath() {
    return leLogDirPath->text();
}
