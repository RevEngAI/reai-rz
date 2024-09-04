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

ConfigSetupDialog::ConfigSetupDialog (QWidget* parent) : QDialog (parent) {
    setWindowTitle ("Plugin Configuration Setup");

    QVBoxLayout* mainLayout = new QVBoxLayout;
    setLayout (mainLayout);

    /* macro to generate code for different input fields.
     * labelName  : Variable name of QLabel typedef. Must not be pre-declared.
     * labelValue : Label string value.
     * inputName  : Variable name for input field. Must already be declared.
     * inputValue : Placeholder text to be displayed inside input field.
     * */
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

    /* add ok and cancel buttons */
    buttonBox = new QDialogButtonBox (QDialogButtonBox::Ok | QDialogButtonBox::Cancel);
    connect (buttonBox, &QDialogButtonBox::accepted, this, &QDialog::accept);
    connect (buttonBox, &QDialogButtonBox::rejected, this, &QDialog::reject);

    mainLayout->addWidget (buttonBox);
}

/**
 * @b Check whether all fields were filled with a non-empty string or not.
 *
 * @return true when all fields are filled with a non empty string.
 * @return false otherwise.
 * */
Bool ConfigSetupDialog::allFieldsFilled() {
    return !(
        leHost->text().isEmpty() || leApiKey->text().isEmpty() || leModel->text().isEmpty() ||
        leDbDirPath->text().isEmpty() || leLogDirPath->text().isEmpty()
    );
}

/**
 * @b Get value of host line edit.
 * */
CString ConfigSetupDialog::getHost() {
    return leHost->text().toLocal8Bit();
}

/**
 * @b Get value of api key line edit.
 * */
CString ConfigSetupDialog::getApiKey() {
    return leApiKey->text().toLocal8Bit();
}

/**
 * @b Get value of model line edit.
 * */
CString ConfigSetupDialog::getModel() {
    return leModel->text().toLocal8Bit();
}

/**
 * @b Get value of db dir path line edit.
 * */
CString ConfigSetupDialog::getDbDirPath() {
    return leDbDirPath->text().toLocal8Bit();
}

/**
 * @b Get value of log dir path line edit.
 * */
CString ConfigSetupDialog::getLogDirPath() {
    return leLogDirPath->text().toLocal8Bit();
}
