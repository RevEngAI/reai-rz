/**
 * @file      : Cutter.cpp
 * @author    : Siddharth Mishra
 * @date      : 07/06/2024
 * @copyright : Copyright (c) 2024 RevEngAI. All Rights Reserved.
 * */


/* rizin */
#include "Reai/Types.h"
#include <Cutter.h>
#include <Reai/AnalysisInfo.h>
#include <rz_analysis.h>
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
#include <QInputDialog>

/* creait lib */
#include <Reai/Api/Api.h>
#include <Reai/Common.h>
#include <Reai/Config.h>
#include <Reai/Log.h>

/* plugin */
#include <Cutter/Ui/ConfigSetupDialog.hpp>
#include <Cutter/Ui/FunctionRenameDialog.hpp>
#include <Cutter/Ui/FunctionSimilarityDialog.hpp>
#include <Cutter/Ui/AutoAnalysisDialog.hpp>
#include <Cutter/Ui/CreateAnalysisDialog.hpp>
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

    static CString win_title[REAI_LOG_LEVEL_MAX] = {0};

    win_title[REAI_LOG_LEVEL_INFO]  = "Information";
    win_title[REAI_LOG_LEVEL_TRACE] = "Trace";
    win_title[REAI_LOG_LEVEL_DEBUG] = "Debug";
    win_title[REAI_LOG_LEVEL_WARN]  = "Warning";
    win_title[REAI_LOG_LEVEL_ERROR] = "Error";
    win_title[REAI_LOG_LEVEL_FATAL] = "Critical";

    reai_log_printf (level, "display", "%s", msg);

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
        REAI_LOG_TRACE ("Plugin initialization incomplete.");
        isInitialized = false;
        return;
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

    actCreateAnalysis           = reaiMenu->addAction ("Create New Analysis");
    actApplyExistingAnalysis    = reaiMenu->addAction ("Apply Existing Analysis");
    actRenameFns                = reaiMenu->addAction ("Rename Functions");
    actAutoAnalyzeBin           = reaiMenu->addAction ("Auto Analyze Binary");
    actFunctionSimilaritySearch = reaiMenu->addAction ("Function Similarity Search");
    actBinAnalysisHistory       = reaiMenu->addAction ("Binary Analysis History");
    actSetup                    = reaiMenu->addAction ("Plugin Config Setup");

    connect (actCreateAnalysis, &QAction::triggered, this, &ReaiCutterPlugin::on_CreateAnalysis);
    connect (
        actApplyExistingAnalysis,
        &QAction::triggered,
        this,
        &ReaiCutterPlugin::on_ApplyExistingAnalysis
    );
    connect (actAutoAnalyzeBin, &QAction::triggered, this, &ReaiCutterPlugin::on_AutoAnalyzeBin);
    connect (
        actFunctionSimilaritySearch,
        &QAction::triggered,
        this,
        &ReaiCutterPlugin::on_FunctionSimilaritySearch
    );
    connect (
        actBinAnalysisHistory,
        &QAction::triggered,
        this,
        &ReaiCutterPlugin::on_BinAnalysisHistory
    );

    connect (actRenameFns, &QAction::triggered, this, &ReaiCutterPlugin::on_RenameFns);
    connect (actSetup, &QAction::triggered, this, &ReaiCutterPlugin::on_Setup);
}

ReaiCutterPlugin::~ReaiCutterPlugin() {
    if (!isInitialized) {
        return;
    }

    RzCoreLocked core (Core());
    reai_plugin_deinit();
}

void ReaiCutterPlugin::on_ToggleReaiPlugin() {
    reaiMenu->menuAction()->setVisible (actToggleReaiPlugin->isChecked());
}

void ReaiCutterPlugin::on_CreateAnalysis() {
    if (!reai_plugin_check_config_exists()) {
        on_Setup();
    }

    CreateAnalysisDialog *dlg = new CreateAnalysisDialog ((QWidget *)this->parent());
    dlg->exec();
}

void ReaiCutterPlugin::on_ApplyExistingAnalysis() {
    if (!reai_plugin_check_config_exists()) {
        on_Setup();
    }

    RzCoreLocked core (Core());

    // Get analysis ID
    bool    ok       = false;
    QString valueStr = QInputDialog::getText (
        nullptr,
        "Apply Existing Analysis",
        "Enter a Binary ID:",
        QLineEdit::Normal,
        "", // Default value (empty)
        &ok
    );

    if (!ok || valueStr.isEmpty()) {
        return;
    }

    ok                    = false;
    ReaiBinaryId binaryId = valueStr.toULongLong (&ok);

    if (ok) {
        if (!binaryId) {
            DISPLAY_ERROR ("Invalid binary ID provided.");
            return;
        }

        // TODO: ask user here first whether they want to sync function names?
        // Not really a priority though

        Bool applyToAll = QMessageBox::question (
                              (QWidget *)this->parent(),
                              "Apply analysis",
                              "Do you want to rename only unknown functions",
                              QMessageBox::Yes | QMessageBox::No | QMessageBox::Cancel
                          ) == QMessageBox::No;

        if (reai_plugin_apply_existing_analysis (core, binaryId, applyToAll)) {
            DISPLAY_INFO ("Analysis applied successfully.");
        } else {
            DISPLAY_INFO ("Failed to apply existing analysis.");
        }
    } else {
        DISPLAY_ERROR (
            "Failed to get binary id to apply existing analysis. Cannot apply existing analysis."
        );
    }
}

void ReaiCutterPlugin::on_AutoAnalyzeBin() {
    if (!reai_plugin_check_config_exists()) {
        on_Setup();
    }

    RzCoreLocked core (Core());

    AutoAnalysisDialog *autoDlg = new AutoAnalysisDialog ((QWidget *)this->parent());
    autoDlg->exec();
}

void ReaiCutterPlugin::on_RenameFns() {
    if (!reai_plugin_check_config_exists()) {
        on_Setup();
    }

    FunctionRenameDialog *renameDialog = new FunctionRenameDialog ((QWidget *)parent());
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

        /* get function id for old name */
        RzAnalysisFunction *rz_fn = rz_analysis_get_function_byname (core->analysis, oldNameCstr);
        ReaiFunctionId      fn_id = reai_plugin_get_function_id_for_rizin_function (core, rz_fn);

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

        /* NOTE: It is assumed here that once name is appended into new name map, RevEng.AI will surely rename all functions.
         * This means if anyone breaks this assumption, things can go bad. */

        /* add new name to new name map */
        if (reai_fn_info_vec_append (
                new_name_map,
                ((ReaiFnInfo[]) {
                    {
                     .id    = fn_id,
                     .name  = newNameCstr,
                     .vaddr = 0 /* vaddr not required for renaming */,
                     .size  = 0
                        /* size not required for renaming */, }
        })
            )) {
            Core()->renameFunction (rz_fn->addr, newNameCstr);
        } else {
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
    }

    int result = setupDialog->exec();

    REAI_LOG_TRACE ("host = %s", setupDialog->getHost());
    REAI_LOG_TRACE ("api key = %s", setupDialog->getApiKey());
    REAI_LOG_TRACE ("mode = %s", setupDialog->getModel());

    /* move ahead only if OK was pressed. */
    if (result == QDialog::Rejected) {
        return;
    } else {
        if (setupDialog->allFieldsFilled()) {
            if (reai_plugin_save_config (
                    setupDialog->getHost(),
                    setupDialog->getApiKey(),
                    setupDialog->getModel()
                )) {
                DISPLAY_INFO (
                    "Config saved successfully to \"%s\".",
                    reai_config_get_default_path()
                );

                RzCoreLocked core (Core());
                reai_plugin_init (core);
            } else {
                DISPLAY_ERROR ("Failed to save config.");
            }
        } else {
            DISPLAY_WARN ("Not all fields are filled. Please complete the configuration setup.");
            on_Setup(); /* continue setup */
        }
    }
}

void ReaiCutterPlugin::on_FunctionSimilaritySearch() {
    RzCoreLocked              core (Core());
    FunctionSimilarityDialog *searchDlg = new FunctionSimilarityDialog ((QWidget *)this->parent());
    searchDlg->show();
}
