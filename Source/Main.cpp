/**
 * @file      : Main.cpp
 * @author    : Siddharth Mishra
 * @date      : 07/06/2024
 * @copyright : Copyright (c) 2024 Siddharth Mishra. All Rights Reserved.
 * */

/* cutter includes */
#include <cutter/plugins/CutterPlugin.h>
#include <cutter/widgets/CutterDockWidget.h>

/* qt includes */
#include <qt6/QtCore/QObject>
#include <qt6/QtCore/QtPlugin>

/* local includes */
#include "Common.h"

class ReaiCutterPlugin : public QObject, public CutterPlugin {
    Q_OBJECT
    Q_PLUGIN_METADATA (IID "re.rizin.cutter.plugins.revengai")
    Q_INTERFACES (CutterPlugin)

   public:
    void setupPlugin() override;
    void setupInterface (MainWindow* mainWin) override;

    QString getName() const override {
        return "RevEngAI Plugin (rz-reai)";
    }

    QString getAuthor() const override {
        return "Siddharth Mishra";
    }

    QString getDescription() const override {
        return "Cutter plugin for interacting with RevEngAI API";
    }

    QString getVersion() const override {
        return "0";
    }
};

void ReaiCutterPlugin::setupPlugin() {};

void ReaiCutterPlugin::setupInterface (MainWindow* mainWin) {
    UNUSED (mainWin);
}

/* Required by the meta object compiler, otherwise build fails */
#include "Main.moc"
