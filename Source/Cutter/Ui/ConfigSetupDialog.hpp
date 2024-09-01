/**
 * @file      : ConfigSetupDialog.hpp
 * @author    : Siddharth Mishra
 * @date      : 30/09/2024
 * @copyright : Copyright (c) 2024 RevEngAI. All Rights Reserved.
 * */


#ifndef CONFIGSETUPDIALOG_H_
#define CONFIGSETUPDIALOG_H_

#include <QDialog>
#include <QPushButton>
#include <QLineEdit>
#include <QString>

class ConfigSetupDialog : public QDialog {
    Q_OBJECT

   public:
    ConfigSetupDialog();

    QString getHost();
    QString getApiKey();
    QString getModel();
    QString getDbDirPath();
    QString getLogDirPath();

   private:
    QPushButton *btnOk, *btnCancel;
    QLineEdit   *leHost, *leApiKey, *leModel, *leDbDirPath, *leLogDirPath;

    void on_Ok();
    void on_Cancel();
};

#endif // CONFIGSETUPDIALOG_H_
