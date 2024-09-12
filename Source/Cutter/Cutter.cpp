/**
 * @file      : Cutter.cpp
 * @author    : Siddharth Mishra
 * @date      : 07/06/2024
 * @copyright : Copyright (c) 2024 RevEngAI. All Rights Reserved.
 * */


/* rizin */
#include "Cutter/Ui/FunctionRenameDialog.hpp"
#include "Reai/Types.h"
#include <Cutter.h>
#include <rz_core.h>

/* qt includes */
#include <QAction>
#include <QMessageBox>
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
#include <Cutter/Ui/FunctionRenameDialog.hpp>
#include <Plugin.h>
#include <Cutter/Cutter.hpp>

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
        [REAI_LOG_LEVEL_ERROR] = "Error",
        [REAI_LOG_LEVEL_FATAL] = "Critical"
    };

    reai_log_printf (reai_logger(), level, "", "%s", msg);

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

    actUploadBin           = reaiMenu->addAction ("Upload Binary");
    actCreateAnalysis      = reaiMenu->addAction ("Create New Analysis");
    actCheckAnalysisStatus = reaiMenu->addAction ("Check Analysis Status");
    actRenameFns           = reaiMenu->addAction ("Rename Functions");
    actAutoAnalyzeBinSym   = reaiMenu->addAction ("Auto Analyze Binary");
    actBinAnalysisHistory  = reaiMenu->addAction ("Binary Analysis History");
    actSetup               = reaiMenu->addAction ("Plugin Config Setup");

    connect (actUploadBin, &QAction::triggered, this, &ReaiCutterPlugin::on_UploadBin);
    connect (actCreateAnalysis, &QAction::triggered, this, &ReaiCutterPlugin::on_CreateAnalysis);
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
    connect (actRenameFns, &QAction::triggered, this, &ReaiCutterPlugin::on_RenameFns);
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

    RzCoreLocked core (Core());

    if (reai_plugin_upload_opened_binary_file (core)) {
        DISPLAY_INFO ("Uploaded successfully!");
    } else {
        DISPLAY_ERROR ("Uploading failed!");
    };
}

void ReaiCutterPlugin::on_CreateAnalysis() {
    if (!reai_plugin_check_config_exists()) {
        on_Setup();
    }

    RzCoreLocked core (Core());

    if (reai_plugin_create_analysis_for_opened_binary_file (core)) {
        DISPLAY_INFO ("RevEng.AI analysis created successfully!");
    } else {
        DISPLAY_ERROR ("Analysis creation failed!");
    };
}

void ReaiCutterPlugin::on_CheckAnalysisStatus() {
    if (!reai_plugin_check_config_exists()) {
        on_Setup();
    }

    RzCoreLocked core (Core());
    ReaiBinaryId binary_id = reai_plugin_get_binary_id_for_opened_binary_file (core);
    if (!binary_id) {
        DISPLAY_ERROR ("Failed to get binary id for currently opened binary file.");
        return;
    }

    /* get analysis status */
    ReaiAnalysisStatus analysis_status = reai_plugin_get_analysis_status_for_binary_id (binary_id);
    if (analysis_status) {
        DISPLAY_INFO ("Analysis status : \"%s\"", reai_analysis_status_to_cstr (analysis_status));
    } else {
        DISPLAY_ERROR ("Failed to get analysis status.");
    }
}

void ReaiCutterPlugin::on_AutoAnalyzeBinSym() {
    if (!reai_plugin_check_config_exists()) {
        on_Setup();
    }

    if (!reai_plugin_auto_analyze_opened_binary_file (RzCoreLocked (Core()), 0.1, 5, 0.85)) {
        DISPLAY_ERROR ("Failed to complete auto-analysis.");
    }
}

void ReaiCutterPlugin::on_RenameFns() {
    if (!reai_plugin_check_config_exists()) {
        on_Setup();
    }

    FunctionRenameDialog *renameDialog =
        new FunctionRenameDialog ((QWidget *)parent(), RzCoreLocked (Core()));
    renameDialog->exec();

    if (!renameDialog->isFinished()) {
        return;
    }

    std::vector<std::pair<QString, QString>> nameMap;
    renameDialog->getNameMapping (nameMap);

    RzCoreLocked core (Core());

    ReaiFnInfoVec *new_name_map = reai_fn_info_vec_create();
    if (!new_name_map) {
        DISPLAY_ERROR ("Failed to create a new name map. Cannot continue further. Try again.");
        return;
    }

    /* prepare new name map */
    Size error_count = 0;
    Size error_limit = 4;
    for (const auto &[oldName, newName] : nameMap) {
        QByteArray oldNameByteArr = oldName.toLatin1();
        CString    oldNameCstr    = oldNameByteArr.constData();

        QByteArray newNameByteArr = newName.toLatin1();
        CString    newNameCstr    = newNameByteArr.constData();

        PRINT_ERR ("OLDNAME = %s \t NEWNAME= %s", oldNameCstr, newNameCstr);

        /* get function id for old name */
        ReaiFunctionId fn_id = reai_plugin_get_function_id_from_function_name (core, oldNameCstr);
        if (!fn_id) {
            DISPLAY_ERROR (
                "Failed to get a function id for function \"%s\". Cannot perform rename for this "
                "function.",
                oldNameCstr
            );

            /* set a hard limit on how many names can go wrong */
            if (error_count > error_limit) {
                DISPLAY_ERROR ("Too many errors. Cannot continue further.");
                reai_fn_info_vec_destroy (new_name_map);
                return;
            } else {
                error_count++;
                continue;
            }
        }

        /* add new name to new name map */
        if (!reai_fn_info_vec_append (
                new_name_map,
                ((ReaiFnInfo[]) {
                    {.id = fn_id, .name = newNameCstr}
        })
            )) {
            DISPLAY_ERROR (
                "Failed to insert rename information into new name map. Cannot continue further."
            );
            reai_fn_info_vec_destroy (new_name_map);
        }
    }

    if (error_count == nameMap.size()) {
        DISPLAY_ERROR (
            "None of the functions had any matches. Failed to get function IDs. Cannot rename."
        );
        reai_fn_info_vec_destroy (new_name_map);
        return;
    }

    /* perform batch rename operation */
    if (!reai_batch_renames_functions (reai(), reai_response(), new_name_map)) {
        DISPLAY_ERROR ("Failed to perform batch rename operation.");
    } else {
        DISPLAY_INFO ("Batch rename operation completed successfully.");
    }

    // TODO : rename function in rizin as well

    reai_fn_info_vec_destroy (new_name_map);
}

void ReaiCutterPlugin::on_BinAnalysisHistory() {
    if (!reai_plugin_check_config_exists()) {
        on_Setup();
    }

    DISPLAY_INFO ("Method unimplemented. Coming soon...");
}

void ReaiCutterPlugin::on_Setup() {
    /* if config already exists then load the config into config setup dialog */
    if (reai_plugin_check_config_exists()) {
        setupDialog->setHost (reai_config()->host);
        setupDialog->setApiKey (reai_config()->apikey);
        setupDialog->setModel (reai_config()->model);
        setupDialog->setDbDirPath (reai_config()->db_dir_path);
        setupDialog->setLogDirPath (reai_config()->log_dir_path);
    }

    int result = setupDialog->exec();

    /* move ahead only if OK was pressed. */
    if (result == QDialog::Rejected) {
        return;
    } else {
        /* if you accept without filling all fields, then dispaly a warning. */
        if (setupDialog->allFieldsFilled()) {
            /* check whether the API key is in the correct format */
            if (reai_config_check_api_key (setupDialog->getApiKey())) {
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
