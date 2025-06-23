/**
 * @file      : Cutter.cpp
 * @author    : Siddharth Mishra
 * @date      : 07/06/2024
 * @copyright : Copyright (c) 2024 RevEngAI. All Rights Reserved.
 * */

/* rizin */
#include <Cutter.h>
#include <Reai/Util/Str.h>
#include <Reai/Util/Vec.h>
#include <rz_analysis.h>
#include <rz_core.h>
#include <rz_util.h>

/* qt includes */
#include <QAction>
#include <QMessageBox>
#include <QDebug>
#include <QLabel>
#include <QLineEdit>
#include <QMainWindow>
#include <QMenu>
#include <QMenuBar>
#include <QObject>
#include <QPushButton>
#include <QVBoxLayout>
#include <QtPlugin>
#include <QInputDialog>
#include <QIcon>

/* creait lib */
#include <Reai/Api.h>
#include <Reai/Config.h>
#include <Reai/Log.h>

/* plugin */
#include <Cutter/Ui/FunctionRenameDialog.hpp>
#include <Cutter/Ui/FunctionSimilarityDialog.hpp>
#include <Cutter/Ui/BinarySearchDialog.hpp>
#include <Cutter/Ui/CollectionSearchDialog.hpp>
#include <Cutter/Ui/AutoAnalysisDialog.hpp>
#include <Cutter/Ui/CreateAnalysisDialog.hpp>
#include <Cutter/Ui/RecentAnalysisDialog.hpp>
#include <Cutter/Ui/InteractiveDiffWidget.hpp>
#include <Plugin.h>
#include <Cutter/Cutter.hpp>
#include <Cutter/Decompiler.hpp>

Str *getMsg() {
    static Str msg = StrInit();
    return &msg;
}

void rzClearMsg() {
    StrClear (getMsg());
}

void rzDisplayMsg (LogLevel level, Str *msg) {
    rzAppendMsg (level, msg);

    switch (level) {
        case LOG_LEVEL_INFO : {
            QMessageBox::information (nullptr, "Information", getMsg()->data, QMessageBox::Ok, QMessageBox::Ok);
            break;
        }
        case LOG_LEVEL_ERROR : {
            QMessageBox::warning (nullptr, "Error", getMsg()->data, QMessageBox::Ok, QMessageBox::Ok);
            break;
        }
        case LOG_LEVEL_FATAL : {
            QMessageBox::critical (nullptr, "Fatal", getMsg()->data, QMessageBox::Ok, QMessageBox::Ok);
            break;
        }
        default :
            break;
    }

    LOG_INFO ("%s", getMsg()->data);
    StrClear (getMsg());
}

void rzAppendMsg (LogLevel level, Str *msg) {
    StrAppendf (
        getMsg(),
        "%s : %s\n",
        level == LOG_LEVEL_INFO  ? "INFO" :
        level == LOG_LEVEL_ERROR ? "ERROR" :
                                   "FATAL",
        msg->data
    );
}

void ReaiCutterPlugin::setupPlugin() {
    RzCoreLocked core (Core());

    // if plugin failed to load because no config exists
    if (!GetConfig()->length) {
        // show setup dialog
        on_Setup();

        // if config is loaded then happy happy happy
        if (GetConfig()->length) {
            isInitialized = true;
            return;
        }
    }

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

    LogInit (true);

    mainWindow = mainWin;

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

    // TODO: When searching for similar functions, provide a button to search and select collections
    // The button will open a pop-up window and allow user to search and select collections by their names,
    // where the dialog will automatically store the correspondign collection ids in the backend
    // This popup must also provide a link to open collections in browser.
    // Similarly when doing a binary search, follow a similar UX as described for collections search.

    actCreateAnalysis           = reaiMenu->addAction ("Create New Analysis");
    actApplyExistingAnalysis    = reaiMenu->addAction ("Apply Existing Analysis");
    actRenameFns                = reaiMenu->addAction ("Rename Functions");
    actAutoAnalyzeBin           = reaiMenu->addAction ("Auto Analyze Binary");
    actFunctionSimilaritySearch = reaiMenu->addAction ("Function Similarity Search");
    actFunctionDiff             = reaiMenu->addAction ("Interactive Function Diff");
    actCollectionSearch         = reaiMenu->addAction ("Collection Search");
    actBinarySearch             = reaiMenu->addAction ("Binary Search");
    actRecentAnalysis           = reaiMenu->addAction ("Recent Analysis");
    actSetup                    = reaiMenu->addAction ("Plugin Config Setup");

    connect (actCreateAnalysis, &QAction::triggered, this, &ReaiCutterPlugin::on_CreateAnalysis);
    connect (actApplyExistingAnalysis, &QAction::triggered, this, &ReaiCutterPlugin::on_ApplyExistingAnalysis);
    connect (actAutoAnalyzeBin, &QAction::triggered, this, &ReaiCutterPlugin::on_AutoAnalyzeBin);
    connect (actFunctionSimilaritySearch, &QAction::triggered, this, &ReaiCutterPlugin::on_FunctionSimilaritySearch);
    connect (actFunctionDiff, &QAction::triggered, this, &ReaiCutterPlugin::on_FunctionDiff);
    connect (actCollectionSearch, &QAction::triggered, this, &ReaiCutterPlugin::on_CollectionSearch);
    connect (actBinarySearch, &QAction::triggered, this, &ReaiCutterPlugin::on_BinarySearch);
    connect (actRecentAnalysis, &QAction::triggered, this, &ReaiCutterPlugin::on_RecentAnalysis);

    connect (actRenameFns, &QAction::triggered, this, &ReaiCutterPlugin::on_RenameFns);
    connect (actSetup, &QAction::triggered, this, &ReaiCutterPlugin::on_Setup);

    // Create and add the interactive diff widget as a dockable panel
    diffWidget = new InteractiveDiffWidget (mainWin);
    mainWin->addDockWidget (Qt::BottomDockWidgetArea, diffWidget);
    diffWidget->hide(); // Initially hidden

    // Setup context menus
    setupContextMenus();
}

void ReaiCutterPlugin::registerDecompilers() {
    Core()->registerDecompiler (new ReaiDec (this->parent()));
}

ReaiCutterPlugin::~ReaiCutterPlugin() {
    if (!isInitialized) {
        return;
    }

    RzCoreLocked core (Core());
}

void ReaiCutterPlugin::on_ToggleReaiPlugin() {
    reaiMenu->menuAction()->setVisible (actToggleReaiPlugin->isChecked());
}

void ReaiCutterPlugin::on_CreateAnalysis() {
    if (!GetConfig()->length) {
        on_Setup();
    }

    CreateAnalysisDialog *dlg = new CreateAnalysisDialog ((QWidget *)this->parent());
    dlg->exec();
}

void ReaiCutterPlugin::on_ApplyExistingAnalysis() {
    rzClearMsg();
    if (!GetConfig()->length) {
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

    ok                = false;
    BinaryId binaryId = valueStr.toULongLong (&ok);

    if (ok) {
        if (!rzCanWorkWithAnalysis (binaryId, true)) {
            return;
        }

        // TODO: ask user here first whether they want to sync function names?
        // Not really a priority though

        rzApplyAnalysis (core, binaryId);
    } else {
        DISPLAY_ERROR ("Please provide a valid binary id (positive non-zero integer)");
    }

    mainWindow->refreshAll();
}

void ReaiCutterPlugin::on_AutoAnalyzeBin() {
    if (!GetConfig()->length) {
        on_Setup();
    }

    RzCoreLocked core (Core());

    AutoAnalysisDialog *autoDlg = new AutoAnalysisDialog ((QWidget *)this->parent());
    autoDlg->exec();

    mainWindow->refreshAll();
}

void ReaiCutterPlugin::renameFunctions (std::vector<std::pair<QString, QString>> nameMap) {
    rzClearMsg();
    RzCoreLocked core (Core());

    FunctionInfos functions = VecInitWithDeepCopy (NULL, FunctionInfoDeinit);

    /* prepare new name map */
    size error_count = 0;
    size error_limit = 4;
    for (const auto &[oldName, newName] : nameMap) {
        QByteArray oldNameByteArr = oldName.toLatin1();
        QByteArray newNameByteArr = newName.toLatin1();

        /* get function id for old name */
        FunctionId fn_id = rzLookupFunctionIdForFunctionWithName (core, oldNameByteArr.constData());

        if (!fn_id) {
            APPEND_ERROR (
                "Failed to get a function id for function \"%s\". Cannot perform rename for this "
                "function.",
                oldNameByteArr.constData()
            );

            /* set a hard limit on how many names can go wrong */
            if (error_count > error_limit) {
                DISPLAY_ERROR ("Too many errors. Cannot continue further.");
                return;
            } else {
                error_count++;
                continue;
            }
        }

        FunctionInfo fi;
        memset (&fi, 0, sizeof (fi));
        fi.id          = fn_id;
        fi.symbol.name = StrInitFromZstr (newNameByteArr.constData());

        /* add new name to new name map */
        VecPushBack (&functions, fi);
        Core()->renameFunction (
            rz_analysis_get_function_byname (core->analysis, oldNameByteArr.constData())->addr,
            newNameByteArr.constData()
        );
    }

    StrClear (getMsg());

    if (error_count == nameMap.size()) {
        DISPLAY_ERROR (
            "Failed to get function IDs for any of those functions you wanted to rename. Rename unsuccessful."
        );
        VecDeinit (&functions);
        return;
    }

    BatchRenameFunctions (GetConnection(), functions);

    VecDeinit (&functions);
    mainWindow->refreshAll();
}


void ReaiCutterPlugin::on_RenameFns() {
    if (!GetConfig()->length) {
        on_Setup();
    }

    FunctionRenameDialog *renameDialog = new FunctionRenameDialog ((QWidget *)parent());
    renameDialog->exec();

    if (!renameDialog->isFinished()) {
        return;
    }

    std::vector<std::pair<QString, QString>> nameMap;
    renameDialog->getNameMapping (nameMap);

    renameFunctions (nameMap);
}

void ReaiCutterPlugin::on_RecentAnalysis() {
    if (!GetConfig()->length) {
        on_Setup();
    }

    RecentAnalysisDialog *dlg = new RecentAnalysisDialog ((QWidget *)this->parent());
    dlg->exec();
}

void ReaiCutterPlugin::on_Setup() {
    rzClearMsg();

    QInputDialog *iDlg = new QInputDialog ((QWidget *)this->parent());
    iDlg->setInputMode (QInputDialog::TextInput);
    iDlg->setTextValue (GetConnection()->api_key.data ? GetConnection()->api_key.data : "");
    iDlg->setLabelText ("API key : ");
    iDlg->setWindowTitle ("Plugin Configuration");
    iDlg->setMinimumWidth (400);

    /* move ahead only if OK was pressed. */
    if (iDlg->exec() == QInputDialog::Accepted) {
        Config new_config = ConfigInit();

        QByteArray baApiKey = iDlg->textValue().toLatin1();
        ConfigAdd (&new_config, "api_key", baApiKey.constData());
        ConfigAdd (&new_config, "host", "https://api.reveng.ai");

        ConfigWrite (&new_config, NULL);
        ReloadPluginData();

        DISPLAY_INFO ("Config updated & reloaded");
    } else {
        DISPLAY_INFO ("Config NOT changed");
    }
}

void ReaiCutterPlugin::on_FunctionSimilaritySearch() {
    if (!GetConfig()->length) {
        on_Setup();
    }

    FunctionSimilarityDialog *searchDlg = new FunctionSimilarityDialog ((QWidget *)this->parent());
    searchDlg->exec();

    if (searchDlg->doRename()) {
        std::vector<std::pair<QString, QString>> nameMap;
        searchDlg->getNameMapping (nameMap);
        renameFunctions (nameMap);
    }
}

void ReaiCutterPlugin::on_CollectionSearch() {
    if (!GetConfig()->length) {
        on_Setup();
    }

    CollectionSearchDialog *searchDlg = new CollectionSearchDialog ((QWidget *)this->parent(), true);
    searchDlg->exec();
}
void ReaiCutterPlugin::on_BinarySearch() {
    if (!GetConfig()->length) {
        on_Setup();
    }

    BinarySearchDialog *searchDlg = new BinarySearchDialog ((QWidget *)this->parent(), true);
    searchDlg->exec();
}

void ReaiCutterPlugin::on_FunctionDiff() {
    if (!GetConfig()->length) {
        on_Setup();
        return;
    }

    // Simply show the widget - no separate dialog needed
    diffWidget->show();
    diffWidget->raise();
    diffWidget->activateWindow();
}

void ReaiCutterPlugin::setupContextMenus() {
    // Get the context menu extensions from MainWindow
    QMenu *disassemblyContextMenu = mainWindow->getContextMenuExtensions(MainWindow::ContextMenuType::Disassembly);
    QMenu *addressableContextMenu = mainWindow->getContextMenuExtensions(MainWindow::ContextMenuType::Addressable);
    
    if (disassemblyContextMenu) {
        // Create the "Find Similar Functions" action
        actFindSimilarFunctions = new QAction("Find Similar Functions", this);
        actFindSimilarFunctions->setIcon(QIcon(":/img/icons/compare.svg")); // Use an appropriate icon
        
        // Add to disassembly context menu
        disassemblyContextMenu->addAction(actFindSimilarFunctions);
        
        // Connect to our handler
        connect(actFindSimilarFunctions, &QAction::triggered, this, &ReaiCutterPlugin::on_FindSimilarFunctions);
    }
    
    if (addressableContextMenu) {
        // Also add to addressable context menu for completeness
        if (actFindSimilarFunctions) {
            addressableContextMenu->addAction(actFindSimilarFunctions);
        }
    }
}

void ReaiCutterPlugin::on_FindSimilarFunctions() {
    if (!GetConfig()->length) {
        on_Setup();
        return;
    }
    
    // Get the action that triggered this (to access the function data)
    QAction *action = qobject_cast<QAction*>(sender());
    if (!action) {
        return;
    }
    
    // Get the address/offset from the action data
    RVA offset = action->data().value<RVA>();
    
    // Get function name at the offset
    QString functionName;
    {
        RzCoreLocked core(Core());
        RzAnalysisFunction *func = rz_analysis_get_fcn_in(core->analysis, offset, RZ_ANALYSIS_FCN_TYPE_NULL);
        if (func && func->name) {
            functionName = QString(func->name);
        }
    }
    
    // If we couldn't get a function name from the offset, try to get current function
    if (functionName.isEmpty()) {
        RzCoreLocked core(Core());
        RVA currentOffset = Core()->getOffset();
        RzAnalysisFunction *func = rz_analysis_get_fcn_in(core->analysis, currentOffset, RZ_ANALYSIS_FCN_TYPE_NULL);
        if (func && func->name) {
            functionName = QString(func->name);
        }
    }
    
    if (functionName.isEmpty()) {
        QMessageBox::warning(
            (QWidget*)parent(),
            "Error",
            "No function found at the selected location."
        );
        return;
    }
    
    // Show the diff widget and set the function name
    diffWidget->show();
    diffWidget->raise();
    diffWidget->activateWindow();
    
    // Call the public slot to show diff for the function
    diffWidget->showDiffForFunction(functionName, 90); // Default 90% similarity
}
