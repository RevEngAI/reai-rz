/**
 * @file      : ConfigSetupDialog.hpp
 * @author    : Siddharth Mishra
 * @date      : 30/08/2024
 * @copyright : Copyright (c) 2024 RevEngAI. All Rights Reserved.
 * */

#ifndef REAI_PLUGIN_CUTTER_CONFIG_SETUP_DIALOG_HPP
#define REAI_PLUGIN_CUTTER_CONFIG_SETUP_DIALOG_HPP

/* qt */
#include <QDialog>
#include <QLineEdit>
#include <QPushButton>
#include <QDialogButtonBox>
#include <QString>

/* creait */
#include <Reai/Types.h>

class ConfigSetupDialog : public QDialog {
    Q_OBJECT

    QByteArray host;
    QByteArray apiKey;
    QByteArray model;
    QByteArray dbDirPath;
    QByteArray logDirPath;

   public:
    ConfigSetupDialog (QWidget* parent);

    Bool allFieldsFilled();

    CString getHost();
    CString getApiKey();
    CString getModel();
    CString getDbDirPath();
    CString getLogDirPath();

    void setHost (CString value);
    void setApiKey (CString value);
    void setModel (CString value);
    void setDbDirPath (CString value);
    void setLogDirPath (CString value);

   private:
    QDialogButtonBox* buttonBox;
    QLineEdit *       leHost, *leApiKey, *leModel, *leDbDirPath, *leLogDirPath;

    void on_Ok();
    void on_Cancel();
};

#endif // REAI_PLUGIN_CUTTER_CONFIG_SETUP_DIALOG_HPP
