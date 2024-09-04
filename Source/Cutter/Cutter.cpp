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
#include <QAction>
#include <QDebug>
#include <QLabel>
#include <QLineEdit>
#include <QMainWindow>
#include <QMenuBar>
#include <QObject>
#include <QPushButton>
#include <QVBoxLayout>
#include <QtPlugin>

/* creait lib */
#include <Reai/Api/Api.h>
#include <Reai/Common.h>
#include <Reai/Config.h>
#include <Reai/Log.h>

/* plugin */
#include <Cutter/Ui/ConfigSetupDialog.hpp>
#include <Plugin.h>

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

    static CString win_title[] = {
        [REAI_LOG_LEVEL_INFO]  = "Information",
        [REAI_LOG_LEVEL_TRACE] = "Trace",
        [REAI_LOG_LEVEL_DEBUG] = "Debug",
        [REAI_LOG_LEVEL_WARN]  = "Warning",
        [REAI_LOG_LEVEL_FATAL] = "Critical"
    };

    switch (level) {
        case REAI_LOG_LEVEL_INFO :
        case REAI_LOG_LEVEL_TRACE :
        case REAI_LOG_LEVEL_DEBUG : {
            QMessageBox::information (
                nullptr,
                win_title[level],
                msg,
                QMessageBox::Ok,
                QMessageBox::Ok
            );
            break;
        }
        case REAI_LOG_LEVEL_WARN : {
            QMessageBox::warning (nullptr, win_title[level], msg, QMessageBox::Ok, QMessageBox::Ok);
            break;
        }
        case REAI_LOG_LEVEL_ERROR :
        case REAI_LOG_LEVEL_FATAL : {
            QMessageBox::critical (
                nullptr,
                win_title[level],
                msg,
                QMessageBox::Ok,
                QMessageBox::Ok
            );
            break;
        }
        default :
            break;
    }
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

    /* to create separate menu for revengai plugin in cutter's main window's menu
   * bar */
    QMenu *reaiMenu = nullptr;

    /* action to enable/disable (show/hide) revengai plugin */
    QAction *actToggleReaiPlugin = nullptr;

    /* revengai's menu item actions */
    QAction *actUploadBin                   = nullptr;
    QAction *actCheckAnalysisStatus         = nullptr;
    QAction *actAutoAnalyzeBinSym           = nullptr;
    QAction *actPerformRenameFromSimilarFns = nullptr;
    QAction *actBinAnalysisHistory          = nullptr;
    QAction *actSetup                       = nullptr;

    /* display dialog to get config settings */
    ConfigSetupDialog *setupDialog;

    Bool isInitialized = false;

   public:
    void setupPlugin() override;
    void setupInterface (MainWindow *mainWin) override;
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
        qInfo() << "Config not found. Please create a config using installation "
                   "wizard.";
    }

    /* display dialog to get config settings */
    setupDialog = new ConfigSetupDialog ((QWidget *)this->parent());

    isInitialized = true;
};

/**
 * @b Required by CutterPlugin to initialize UI for this plugin.
 *
 * @param mainWin Reference to main window provided by Cutter
 * */
void ReaiCutterPlugin::setupInterface (MainWindow *mainWin) {
    if (!isInitialized) {
        return;
    }

    /* get main window's menu bar */
    QMenuBar *menuBar = mainWin->menuBar();
    if (!menuBar) {
        qCritical() << "Given Cutter main window has no menu bar.";
        return;
    }

    /* Find "Plugins" menu in "Windows" menu in Cutter window menu bar */
    QMenu *pluginsMenu = nullptr;
    {
        /* get list of all menus in menu bar */
        QList<QMenu *> menuBarMenuList = menuBar->findChildren<QMenu *>();
        if (!menuBarMenuList.size()) {
            qCritical() << "Cutter main window has no menu items in it's menu bar.";
            return;
        }

        /* go through each one and compare title */
        QMenu *windowsMenu = nullptr;
        for (QMenu *menu : menuBarMenuList) {
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

        QList<QMenu *> windowsMenuList = windowsMenu->findChildren<QMenu *>();
        for (QMenu *menu : windowsMenuList) {
            if (menu) {
                if (menu->title() == QString ("Plugins")) {
                    pluginsMenu = menu;
                    break;
                }
            }
        }

        if (!pluginsMenu) {
            qCritical() << "Cutter main window has no 'Plugins' sub-menu in "
                           "'Windows' menu of it's menu bar.";
            return;
        }
    }

    actToggleReaiPlugin = pluginsMenu->addAction ("RevEngAI");
    if (!actToggleReaiPlugin) {
        qCritical() << "Failed to add action to trigger RevEngAI Plugin on/off in "
                       "Plugins menu.";
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
            "Config already exists. Please remove/rename previous config "
            "to create new one."
        );
        return;
    }

    int result = setupDialog->exec();

    /* move ahead only if OK was pressed. */
    if (result == QDialog::Rejected) {
        return;
    } else {
        /* if you accept without filling all fields, then dispaly a warning. */
        if (setupDialog->allFieldsFilled()) {
            PRINT_ERR ("Checking API KEY : %s", setupDialog->getApiKey());
            /* check whether the API key is in the correct format */
            if (reai_config_check_api_key (setupDialog->getApiKey())) {
                PRINT_ERR (
                    "%s, %s, %s, %s, %s",
                    setupDialog->getHost(),
                    setupDialog->getApiKey(),
                    setupDialog->getModel(),
                    setupDialog->getDbDirPath(),
                    setupDialog->getLogDirPath()
                );

                /* if we reach here finally then we save the config and exit loop */
                if (reai_plugin_save_config (
                        setupDialog->getHost(),
                        setupDialog->getApiKey(),
                        setupDialog->getModel(),
                        setupDialog->getDbDirPath(),
                        setupDialog->getLogDirPath()
                    )) {
                    DISPLAY_INFO (
                        "Config saved successfully to \"%s\".",
                        reai_config_get_default_path()
                    );
                } else {
                    DISPLAY_ERROR ("Failed to save config.");
                }
            } else {
                DISPLAY_ERROR (
                    "Invalid API Key. It's recommended to directly copy-paste "
                    "the API key from RevEng.AI dashboard."
                );
                on_Setup(); /* continue setup */
            }
        } else {
            DISPLAY_WARN ("Not all fields are filled. Please complete the configuration setup.");
            on_Setup(); /* continue setup */
        }
    }
}

/* Required by the meta object compiler, otherwise build fails */
#include "Cutter.moc"
