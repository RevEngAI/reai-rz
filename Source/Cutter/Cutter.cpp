/**
 * @file      : Cutter.cpp
 * @author    : Siddharth Mishra
 * @date      : 07/06/2024
 * @copyright : Copyright (c) 2024 RevEngAI. All Rights Reserved.
 * */

/* cutter includes */
#include <cutter/CutterApplication.h>
#include <cutter/core/MainWindow.h>
#include <cutter/plugins/CutterPlugin.h>

/* rizin */
#include <qboxlayout.h>
#include <qdialog.h>
#include <qlineedit.h>
#include <rz_core.h>

/* qt includes */
#include <QLabel>
#include <QLineEdit>
#include <QMenuBar>
#include <QAction>
#include <QtPlugin>
#include <QObject>
#include <QDebug>
#include <QMainWindow>
#include <QVBoxLayout>
#include <QPushButton>

/* creait lib */
#include <Reai/Api/Api.h>
#include <Reai/Common.h>
#include <Reai/Config.h>
#include <Reai/Log.h>

/* plugin */
#include <Plugin.h>
#include <Cutter/Ui/ConfigSetupDialog.hpp>

/**
 * Display a message of given level in rizin shell.
 *
 * If message is below error level then it's sent to log file,
 * otherwise it's displayed on screen as well as in log file.
 *
 * @param level
 * @param msg
 * */
void reai_plugin_display_msg (ReaiLogLevel level, CString msg) {
    RETURN_IF (!msg, ERR_INVALID_ARGUMENTS);
    UNUSED (level);
}

/**
 * @b RevEngAI Cutter Plugin class.
 *
 * This is the actual plugin that's loaded by Cutter with help
 * of QtPluginLoader.
 * */
class ReaiCutterPlugin : public QObject, public CutterPlugin {
    Q_OBJECT
    Q_PLUGIN_METADATA (IID "re.rizin.cutter.plugins.revengai")
    Q_INTERFACES (CutterPlugin)

    /* to create separate menu for revengai plugin in cutter's main window's menu bar */
    QMenu* reaiMenu = nullptr;

    /* action to enable/disable (show/hide) revengai plugin */
    QAction* actToggleReaiPlugin = nullptr;

    /* revengai's menu item actions */
    QAction* actUploadBin                   = nullptr;
    QAction* actCheckAnalysisStatus         = nullptr;
    QAction* actAutoAnalyzeBinSym           = nullptr;
    QAction* actPerformRenameFromSimilarFns = nullptr;
    QAction* actBinAnalysisHistory          = nullptr;
    QAction* actSetup                       = nullptr;

    Bool isInitialized = false;

   public:
    void setupPlugin() override;
    void setupInterface (MainWindow* mainWin) override;
    ~ReaiCutterPlugin();

    QString getName() const override {
        return "RevEngAI Plugin (rz-reai)";
    }
    QString getAuthor() const override {
        return "Siddharth Mishra";
    }
    QString getVersion() const override {
        return "0";
    }
    QString getDescription() const override {
        return "AI based reverse engineering helper API & Toolkit";
    }

    void on_ToggleReaiPlugin();
    void on_UploadBin();
    void on_CheckAnalysisStatus();
    void on_AutoAnalyzeBinSym();
    void on_PerformRenameFromSimilarFns();
    void on_BinAnalysisHistory();
    void on_Setup();
};

void ReaiCutterPlugin::setupPlugin() {
    RzCoreLocked core (Core());

    /* if plugin launch fails then terminate */
    if (!reai_plugin_init (core)) {
        qInfo() << "Config not found. Please create a config using installation wizard.";
    }

    isInitialized = true;
};

/**
 * @b Required by CutterPlugin to initialize UI for this plugin.
 *
 * @param mainWin Reference to main window provided by Cutter
 * */
void ReaiCutterPlugin::setupInterface (MainWindow* mainWin) {
    if (!isInitialized) {
        return;
    }

    /* get main window's menu bar */
    QMenuBar* menuBar = mainWin->menuBar();
    if (!menuBar) {
        qCritical() << "Given Cutter main window has no menu bar.";
        return;
    }

    /* Find "Plugins" menu in "Windows" menu in Cutter window menu bar */
    QMenu* pluginsMenu = nullptr;
    {
        /* get list of all menus in menu bar */
        QList<QMenu*> menuBarMenuList = menuBar->findChildren<QMenu*>();
        if (!menuBarMenuList.size()) {
            qCritical() << "Cutter main window has no menu items in it's menu bar.";
            return;
        }

        /* go through each one and compare title */
        QMenu* windowsMenu = nullptr;
        for (QMenu* menu : menuBarMenuList) {
            if (menu) {
                if (menu->title() == QString ("Windows")) {
                    windowsMenu = menu;
                    break;
                }
            }
        }

        if (!windowsMenu) {
            qCritical() << "Cutter main window has no 'Windows' menu in it's menu bar.";
            return;
        }

        QList<QMenu*> windowsMenuList = windowsMenu->findChildren<QMenu*>();
        for (QMenu* menu : windowsMenuList) {
            if (menu) {
                if (menu->title() == QString ("Plugins")) {
                    pluginsMenu = menu;
                    break;
                }
            }
        }

        if (!pluginsMenu) {
            qCritical(
            ) << "Cutter main window has no 'Plugins' sub-menu in 'Windows' menu of it's menu bar.";
            return;
        }
    }

    actToggleReaiPlugin = pluginsMenu->addAction ("RevEngAI");
    if (!actToggleReaiPlugin) {
        qCritical() << "Failed to add action to trigger RevEngAI Plugin on/off in Plugins menu.";
        return;
    }
    actToggleReaiPlugin->setCheckable (true);
    actToggleReaiPlugin->setChecked (true);

    connect (actToggleReaiPlugin, &QAction::toggled, this, &ReaiCutterPlugin::on_ToggleReaiPlugin);

    /* add revengai's own plugin menu */
    reaiMenu = menuBar->addMenu ("RevEngAI");
    if (!reaiMenu) {
        qCritical() << "Failed to add my own menu to Cutter's main window menu bar";
        return;
    }

    actUploadBin                   = reaiMenu->addAction ("Upload Binary");
    actAutoAnalyzeBinSym           = reaiMenu->addAction ("Auto Analyze Binary");
    actBinAnalysisHistory          = reaiMenu->addAction ("Binary Analysis History");
    actCheckAnalysisStatus         = reaiMenu->addAction ("Check Analysis Status");
    actPerformRenameFromSimilarFns = reaiMenu->addAction ("Rename From Similar Functions");
    actSetup                       = reaiMenu->addAction ("Plugin Config Setup");

    connect (actUploadBin, &QAction::triggered, this, &ReaiCutterPlugin::on_UploadBin);
    connect (
        actAutoAnalyzeBinSym,
        &QAction::triggered,
        this,
        &ReaiCutterPlugin::on_AutoAnalyzeBinSym
    );
    connect (
        actBinAnalysisHistory,
        &QAction::triggered,
        this,
        &ReaiCutterPlugin::on_BinAnalysisHistory
    );
    connect (
        actCheckAnalysisStatus,
        &QAction::triggered,
        this,
        &ReaiCutterPlugin::on_CheckAnalysisStatus
    );
    connect (
        actPerformRenameFromSimilarFns,
        &QAction::triggered,
        this,
        &ReaiCutterPlugin::on_PerformRenameFromSimilarFns
    );
    connect (actSetup, &QAction::triggered, this, &ReaiCutterPlugin::on_Setup);
}

ReaiCutterPlugin::~ReaiCutterPlugin() {
    if (!isInitialized) {
        return;
    }

    RzCoreLocked core (Core());

    reai_plugin_deinit (core);
}

void ReaiCutterPlugin::on_ToggleReaiPlugin() {
    reaiMenu->menuAction()->setVisible (actToggleReaiPlugin->isChecked());
}

void ReaiCutterPlugin::on_UploadBin() {
    if (!reai_plugin_check_config_exists()) {
        on_Setup();
    }
}

void ReaiCutterPlugin::on_CheckAnalysisStatus() {
    if (!reai_plugin_check_config_exists()) {
        on_Setup();
    }
}

void ReaiCutterPlugin::on_AutoAnalyzeBinSym() {
    if (!reai_plugin_check_config_exists()) {
        on_Setup();
    }
}

void ReaiCutterPlugin::on_PerformRenameFromSimilarFns() {
    if (!reai_plugin_check_config_exists()) {
        on_Setup();
    }
}

void ReaiCutterPlugin::on_BinAnalysisHistory() {
    if (!reai_plugin_check_config_exists()) {
        on_Setup();
    }
}

void ReaiCutterPlugin::on_Setup() {
    if (reai_plugin_check_config_exists()) {
        DISPLAY_WARN (
            "Config already exists. Please remove/rename previous config to create new one."
        );
    }

    ConfigSetupDialog* setupDialog = new ConfigSetupDialog();
    setupDialog->show();
}

/* Required by the meta object compiler, otherwise build fails */
#include "Cutter.moc"
