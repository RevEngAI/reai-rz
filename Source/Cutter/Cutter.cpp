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
#include <QStatusBar>
#include <QHBoxLayout>
#include <QWidget>
#include <QApplication>
#include <QTimer>
#include <QTableWidget>
#include <QDialog>
#include <QVector>
#include <QHeaderView>
#include <QAbstractButton>
#include <QDialogButtonBox>
#include <QFileInfo>
#include <QCryptographicHash>
#include <QFile>

/* creait lib */
#include <Reai/Api.h>
#include <Reai/Config.h>
#include <Reai/Log.h>

/* plugin */
#include <Cutter/Ui/BinarySearchDialog.hpp>
#include <Cutter/Ui/CollectionSearchDialog.hpp>
#include <Cutter/Ui/AutoAnalysisDialog.hpp>
#include <Cutter/Ui/CreateAnalysisDialog.hpp>
#include <Cutter/Ui/RecentAnalysisDialog.hpp>
#include <Cutter/Ui/InteractiveDiffWidget.hpp>
#include <Plugin.h>
#include <Cutter/Cutter.hpp>
#include <Cutter/Decompiler.hpp>

// Global instance for singleton access
ReaiCutterPlugin *ReaiCutterPlugin::s_instance = nullptr;

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
    // Set global instance
    s_instance = this;

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

    // Connect to Cutter's core signals to detect when a binary is loaded
    connect (Core(), &CutterCore::refreshAll, this, &ReaiCutterPlugin::onBinaryLoaded);

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

    actCreateAnalysis        = reaiMenu->addAction ("Create New Analysis");
    actApplyExistingAnalysis = reaiMenu->addAction ("Apply Existing Analysis");
    actAutoAnalyzeBin        = reaiMenu->addAction ("Auto Analyze Binary");
    actFunctionDiff          = reaiMenu->addAction ("Interactive Function Diff");
    actCollectionSearch      = reaiMenu->addAction ("Collection Search");
    actBinarySearch          = reaiMenu->addAction ("Binary Search");
    actRecentAnalysis        = reaiMenu->addAction ("Recent Analysis");
    actSetup                 = reaiMenu->addAction ("Plugin Config Setup");

    connect (actCreateAnalysis, &QAction::triggered, this, &ReaiCutterPlugin::on_CreateAnalysis);
    connect (actApplyExistingAnalysis, &QAction::triggered, this, &ReaiCutterPlugin::on_ApplyExistingAnalysis);
    connect (actAutoAnalyzeBin, &QAction::triggered, this, &ReaiCutterPlugin::on_AutoAnalyzeBin);
    connect (actFunctionDiff, &QAction::triggered, this, &ReaiCutterPlugin::on_FunctionDiff);
    connect (actCollectionSearch, &QAction::triggered, this, &ReaiCutterPlugin::on_CollectionSearch);
    connect (actBinarySearch, &QAction::triggered, this, &ReaiCutterPlugin::on_BinarySearch);
    connect (actRecentAnalysis, &QAction::triggered, this, &ReaiCutterPlugin::on_RecentAnalysis);
    connect (actSetup, &QAction::triggered, this, &ReaiCutterPlugin::on_Setup);

    // Create and add the interactive diff widget as a dockable panel
    diffWidget = new InteractiveDiffWidget (mainWin);
    mainWin->addDockWidget (Qt::BottomDockWidgetArea, diffWidget);
    diffWidget->hide(); // Initially hidden

    // Setup context menus
    setupContextMenus();

    // Setup status bar
    setupStatusBar();

    // Setup system tray
    setupSystemTray();
}

void ReaiCutterPlugin::setupStatusBar() {
    if (!mainWindow) {
        return;
    }

    QStatusBar *statusBar = mainWindow->statusBar();
    if (!statusBar) {
        qWarning() << "MainWindow has no status bar";
        return;
    }

    // Create status widgets
    statusLabel = new QLabel ("RevEngAI Ready");
    statusLabel->setStyleSheet ("color: gray; font-style: italic;");
    statusLabel->setVisible (false); // Initially hidden

    statusProgressBar = new QProgressBar();
    statusProgressBar->setMaximumWidth (200);
    statusProgressBar->setVisible (false);

    statusCancelButton = new QPushButton ("Cancel");
    statusCancelButton->setMaximumWidth (60);
    statusCancelButton->setVisible (false);

    // Create a container widget for our status elements
    QWidget     *statusWidget = new QWidget();
    QHBoxLayout *statusLayout = new QHBoxLayout (statusWidget);
    statusLayout->setContentsMargins (0, 0, 0, 0);
    statusLayout->addWidget (statusLabel);
    statusLayout->addWidget (statusProgressBar);
    statusLayout->addWidget (statusCancelButton);

    // Add to status bar (permanent widget stays on the right)
    statusBar->addPermanentWidget (statusWidget);

    // Setup timer for auto-hiding status messages
    statusHideTimer = new QTimer (this);
    statusHideTimer->setSingleShot (true);
    connect (statusHideTimer, &QTimer::timeout, this, &ReaiCutterPlugin::onStatusHideTimeout);

    // Connect cancel button
    connect (statusCancelButton, &QPushButton::clicked, this, &ReaiCutterPlugin::onStatusCancelClicked);
}

void ReaiCutterPlugin::setupSystemTray() {
    // Setup system tray icon for notifications
    if (QSystemTrayIcon::isSystemTrayAvailable()) {
        systemTrayIcon = new QSystemTrayIcon (this);
        systemTrayIcon->setIcon (QIcon (":/icons/revengai.png")); // You may want to add an icon
        systemTrayIcon->setToolTip ("RevEngAI Plugin");
        systemTrayIcon->show();
    }
}

void ReaiCutterPlugin::showStatusProgress (const QString &operationType, const QString &message, int percentage) {
    if (!statusLabel || !statusProgressBar || !statusCancelButton) {
        return;
    }

    currentOperationType = operationType;

    statusLabel->setText (QString ("RevEngAI: %1").arg (message));
    statusLabel->setStyleSheet ("color: blue; font-weight: bold;");
    statusLabel->setVisible (true);

    if (percentage >= 0) {
        statusProgressBar->setValue (percentage);
        statusProgressBar->setVisible (true);
    } else {
        statusProgressBar->setVisible (false);
    }

    statusCancelButton->setVisible (true);

    // Stop any existing hide timer
    statusHideTimer->stop();
}

void ReaiCutterPlugin::updateStatusProgress (const QString &message, int percentage) {
    if (!statusLabel || !statusProgressBar) {
        return;
    }

    statusLabel->setText (QString ("RevEngAI: %1").arg (message));

    if (percentage >= 0 && statusProgressBar->isVisible()) {
        statusProgressBar->setValue (percentage);
    }
}

void ReaiCutterPlugin::hideStatusProgress() {
    if (!statusLabel || !statusProgressBar || !statusCancelButton) {
        return;
    }

    statusLabel->setVisible (false);
    statusProgressBar->setVisible (false);
    statusCancelButton->setVisible (false);

    currentOperationType.clear();
    currentAnalysisBinaryId = 0;
}

void ReaiCutterPlugin::showStatusMessage (const QString &message, int duration) {
    if (!statusLabel) {
        return;
    }

    statusLabel->setText (QString ("RevEngAI: %1").arg (message));
    statusLabel->setStyleSheet ("color: green; font-weight: normal;");
    statusLabel->setVisible (true);

    // Hide progress bar and cancel button for simple messages
    if (statusProgressBar)
        statusProgressBar->setVisible (false);
    if (statusCancelButton)
        statusCancelButton->setVisible (false);

    // Auto-hide after duration
    statusHideTimer->start (duration);
}

void ReaiCutterPlugin::showNotification (const QString &title, const QString &message, bool isSuccess) {
    // Show popup notification
    QMessageBox::Icon icon = isSuccess ? QMessageBox::Information : QMessageBox::Warning;
    QMessageBox       msgBox;
    msgBox.setIcon (icon);
    msgBox.setWindowTitle (title);
    msgBox.setText (message);
    msgBox.setStandardButtons (QMessageBox::Ok);
    msgBox.exec();

    // Also show in status bar
    QString statusMsg = isSuccess ? QString ("✓ %1").arg (message) : QString ("✗ %1").arg (message);
    showStatusMessage (statusMsg, 8000); // Show for 8 seconds
}

void ReaiCutterPlugin::onStatusHideTimeout() {
    hideStatusProgress();
}

void ReaiCutterPlugin::onStatusCancelClicked() {
    // This is a placeholder - individual operations should connect to this signal
    // or override this behavior for their specific cancellation logic
    qDebug() << "Cancel clicked for operation:" << currentOperationType;
    hideStatusProgress();
    showStatusMessage ("Operation cancelled", 3000);
}

void ReaiCutterPlugin::startAnalysisPolling (BinaryId binaryId, const QString &analysisName) {
    // Stop any existing polling
    stopAnalysisPolling();

    // Create polling thread
    pollerThread = new QThread (this);
    statusPoller = new AnalysisStatusPoller();
    statusPoller->moveToThread (pollerThread);

    // Connect signals
    connect (statusPoller, &AnalysisStatusPoller::statusUpdate, this, &ReaiCutterPlugin::onAnalysisStatusUpdate);
    connect (statusPoller, &AnalysisStatusPoller::analysisCompleted, this, &ReaiCutterPlugin::onAnalysisCompleted);
    connect (statusPoller, &AnalysisStatusPoller::pollingError, [this] (const QString &error) {
        qWarning() << "Analysis polling error:" << error;
        showStatusMessage (QString ("Polling error: %1").arg (error), 5000);
    });

    // Clean up when thread finishes
    connect (pollerThread, &QThread::finished, statusPoller, &QObject::deleteLater);
    connect (pollerThread, &QThread::finished, pollerThread, &QObject::deleteLater);
    connect (pollerThread, &QThread::finished, [this]() {
        statusPoller = nullptr;
        pollerThread = nullptr;
    });

    // Start polling
    connect (pollerThread, &QThread::started, [this, binaryId, analysisName]() {
        AnalysisStatusPoller::PollingRequest request;
        request.binaryId       = binaryId;
        request.analysisName   = analysisName;
        request.pollIntervalMs = 30000; // Poll every 30 seconds
        statusPoller->startPolling (request);
    });

    pollerThread->start();

    // Show status
    showStatusMessage (QString ("Monitoring analysis: %1 (ID: %2)").arg (analysisName).arg (binaryId), 5000);
}

void ReaiCutterPlugin::stopAnalysisPolling() {
    if (statusPoller) {
        statusPoller->stopPolling();
    }

    if (pollerThread && pollerThread->isRunning()) {
        pollerThread->quit();
        if (!pollerThread->wait (3000)) {
            pollerThread->terminate();
            pollerThread->wait (1000);
        }
    }

    statusPoller = nullptr;
    pollerThread = nullptr;
}

void ReaiCutterPlugin::onAnalysisStatusUpdate (BinaryId binaryId, const QString &status, const QString &analysisName) {
    QString message = QString ("Analysis %1 (ID: %2) status: %3").arg (analysisName).arg (binaryId).arg (status);
    showStatusMessage (message, 3000);
}

void ReaiCutterPlugin::onAnalysisCompleted (BinaryId binaryId, const QString &analysisName, bool success) {
    // Stop polling since analysis is complete
    stopAnalysisPolling();

    QString title   = success ? "Analysis Complete" : "Analysis Failed";
    QString message = QString ("Analysis '%1' (ID: %2) has %3")
                          .arg (analysisName)
                          .arg (binaryId)
                          .arg (success ? "completed successfully" : "failed");

    // Show system notification
    if (systemTrayIcon && systemTrayIcon->isVisible()) {
        QSystemTrayIcon::MessageIcon icon = success ? QSystemTrayIcon::Information : QSystemTrayIcon::Warning;
        systemTrayIcon->showMessage (title, message, icon, 10000); // Show for 10 seconds
    }

    // Also show regular notification
    showNotification (title, message, success);

    // Update current binary ID if this analysis succeeded
    if (success) {
        SetBinaryId (binaryId);
    }
}

void ReaiCutterPlugin::registerDecompilers() {
    Core()->registerDecompiler (new ReaiDec (this->parent()));
}

ReaiCutterPlugin::~ReaiCutterPlugin() {
    // Stop analysis polling
    stopAnalysisPolling();

    // Stop startup analysis worker
    if (startupWorker) {
        startupWorker->cancel();
    }

    if (startupWorkerThread) {
        if (startupWorkerThread->isRunning()) {
            // Give it 3 seconds to finish gracefully
            if (!startupWorkerThread->wait (3000)) {
                // Force terminate if it doesn't finish
                startupWorkerThread->terminate();
                startupWorkerThread->wait (1000);
            }
        }

        if (startupWorker) {
            startupWorker->deleteLater();
            startupWorker = nullptr;
        }

        startupWorkerThread = nullptr;
    }

    // Clear global instance
    if (s_instance == this) {
        s_instance = nullptr;
    }

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
    QMenu *disassemblyContextMenu = mainWindow->getContextMenuExtensions (MainWindow::ContextMenuType::Disassembly);
    QMenu *addressableContextMenu = mainWindow->getContextMenuExtensions (MainWindow::ContextMenuType::Addressable);

    if (disassemblyContextMenu) {
        // Create the "Find Similar Functions" action
        actFindSimilarFunctions = new QAction ("Find Similar Functions", this);
        actFindSimilarFunctions->setIcon (QIcon (":/img/icons/compare.svg")); // Use an appropriate icon

        // Add to disassembly context menu
        disassemblyContextMenu->addAction (actFindSimilarFunctions);

        // Connect to our handler
        connect (actFindSimilarFunctions, &QAction::triggered, this, &ReaiCutterPlugin::on_FindSimilarFunctions);
    }

    if (addressableContextMenu) {
        // Also add to addressable context menu for completeness
        if (actFindSimilarFunctions) {
            addressableContextMenu->addAction (actFindSimilarFunctions);
        }
    }
}

void ReaiCutterPlugin::on_FindSimilarFunctions() {
    if (!GetConfig()->length) {
        on_Setup();
        return;
    }

    // Get the action that triggered this (to access the function data)
    QAction *action = qobject_cast<QAction *> (sender());
    if (!action) {
        return;
    }

    // Get the address/offset from the action data
    RVA offset = action->data().value<RVA>();

    // Get function name at the offset
    QString functionName;
    {
        RzCoreLocked        core (Core());
        RzAnalysisFunction *func = rz_analysis_get_fcn_in (core->analysis, offset, RZ_ANALYSIS_FCN_TYPE_NULL);
        if (func && func->name) {
            functionName = QString (func->name);
        }
    }

    // If we couldn't get a function name from the offset, try to get current function
    if (functionName.isEmpty()) {
        RzCoreLocked        core (Core());
        RVA                 currentOffset = Core()->getOffset();
        RzAnalysisFunction *func = rz_analysis_get_fcn_in (core->analysis, currentOffset, RZ_ANALYSIS_FCN_TYPE_NULL);
        if (func && func->name) {
            functionName = QString (func->name);
        }
    }

    if (functionName.isEmpty()) {
        QMessageBox::warning ((QWidget *)parent(), "Error", "No function found at the selected location.");
        return;
    }

    // Show the diff widget and set the function name
    diffWidget->show();
    diffWidget->raise();
    diffWidget->activateWindow();

    // Call the public slot to show diff for the function
    diffWidget->showDiffForFunction (functionName, 90); // Default 90% similarity
}

// Global convenience functions implementation
void ShowGlobalStatus (const QString &operationType, const QString &message, int percentage) {
    if (ReaiCutterPlugin::instance()) {
        ReaiCutterPlugin::instance()->showStatusProgress (operationType, message, percentage);
    }
}

void UpdateGlobalStatus (const QString &message, int percentage) {
    if (ReaiCutterPlugin::instance()) {
        ReaiCutterPlugin::instance()->updateStatusProgress (message, percentage);
    }
}

void HideGlobalStatus() {
    if (ReaiCutterPlugin::instance()) {
        ReaiCutterPlugin::instance()->hideStatusProgress();
    }
}

void ShowGlobalMessage (const QString &message, int duration) {
    if (ReaiCutterPlugin::instance()) {
        ReaiCutterPlugin::instance()->showStatusMessage (message, duration);
    }
}

void ShowGlobalNotification (const QString &title, const QString &message, bool isSuccess) {
    if (ReaiCutterPlugin::instance()) {
        ReaiCutterPlugin::instance()->showNotification (title, message, isSuccess);
    }
}

void StartGlobalAnalysisPolling (BinaryId binaryId, const QString &analysisName) {
    if (ReaiCutterPlugin::instance()) {
        ReaiCutterPlugin::instance()->startAnalysisPolling (binaryId, analysisName);
    }
}

void StopGlobalAnalysisPolling() {
    if (ReaiCutterPlugin::instance()) {
        ReaiCutterPlugin::instance()->stopAnalysisPolling();
    }
}

void ReaiCutterPlugin::startupAnalysisCheck() {
    // Only run if we don't already have a binary ID set and no worker is running
    if (GetBinaryId() != 0) {
        return;
    }

    // Don't run if already running
    if (startupWorkerThread && startupWorkerThread->isRunning()) {
        return;
    }

    RzCoreLocked core (Core());

    // Get current binary path
    Str binaryPath = rzGetCurrentBinaryPath (core);
    if (!binaryPath.length) {
        return;
    }

    QString binaryPathQt = QString::fromUtf8 (binaryPath.data);
    StrDeinit (&binaryPath);

    // Calculate SHA256 of the binary file
    QFile file (binaryPathQt);
    if (!file.open (QIODevice::ReadOnly)) {
        qWarning() << "Cannot open binary file for SHA256 calculation:" << binaryPathQt;
        return;
    }

    QCryptographicHash hash (QCryptographicHash::Sha256);
    if (!hash.addData (&file)) {
        qWarning() << "Failed to calculate SHA256 for binary:" << binaryPathQt;
        return;
    }

    QString sha256 = hash.result().toHex();

    // Show status
    showStatusProgress ("Startup Check", "Searching for existing analyses...", 0);

    // Create and start worker thread
    startupWorkerThread = new QThread (this);
    startupWorker       = new StartupAnalysisWorker();
    startupWorker->moveToThread (startupWorkerThread);

    // Connect signals
    connect (startupWorkerThread, &QThread::started, [this, binaryPathQt, sha256]() {
        StartupAnalysisWorker::StartupAnalysisRequest request;
        request.binaryPath   = binaryPathQt;
        request.binarySha256 = sha256;
        startupWorker->searchMatchingAnalyses (request);
    });

    connect (startupWorker, &StartupAnalysisWorker::progress, this, [this] (int percentage, const QString &message) {
        updateStatusProgress (message, percentage);
    });

    connect (startupWorker, &StartupAnalysisWorker::analysisFound, this, &ReaiCutterPlugin::onStartupAnalysisFound);
    connect (startupWorker, &StartupAnalysisWorker::analysisError, this, &ReaiCutterPlugin::onStartupAnalysisError);

    connect (startupWorkerThread, &QThread::finished, [this]() {
        if (startupWorker) {
            startupWorker->deleteLater();
            startupWorker = nullptr;
        }
        startupWorkerThread = nullptr;
        hideStatusProgress();
    });

    startupWorkerThread->start();
}

void ReaiCutterPlugin::onStartupAnalysisFound (const QVector<AnalysisInfo> &matchingAnalyses) {
    hideStatusProgress();

    // Always show the selection dialog, even if no analyses are found
    AnalysisSelectionDialog dialog (matchingAnalyses, mainWindow);
    dialog.exec();

    switch (dialog.getSelectionResult()) {
        case AnalysisSelectionDialog::UseExisting : {
            BinaryId selectedId = dialog.getSelectedAnalysisId();
            SetBinaryId (selectedId);
            showNotification (
                "Analysis Applied",
                QString ("Applied existing analysis (Binary ID: %1)").arg (selectedId),
                true
            );
            mainWindow->refreshAll();
            break;
        }
        case AnalysisSelectionDialog::CreateNew :
            on_CreateAnalysis();
            break;
        case AnalysisSelectionDialog::Cancel :
        default :
            // Do nothing
            break;
    }
}

void ReaiCutterPlugin::onStartupAnalysisError (const QString &error) {
    hideStatusProgress();
    qWarning() << "Startup analysis check failed:" << error;
    // Don't show error to user as this is a background operation
}

void ReaiCutterPlugin::onBinaryLoaded() {
    // Small delay to ensure binary is fully loaded
    QTimer::singleShot (1000, this, &ReaiCutterPlugin::startupAnalysisCheck);
}

// AnalysisStatusPoller implementation
AnalysisStatusPoller::AnalysisStatusPoller (QObject *parent)
    : QObject (parent), currentBinaryId (0), isPolling (false) {
    pollTimer = new QTimer (this);
    pollTimer->setSingleShot (false);
    connect (pollTimer, &QTimer::timeout, this, &AnalysisStatusPoller::checkAnalysisStatus);
}

void AnalysisStatusPoller::startPolling (const PollingRequest &request) {
    if (isPolling) {
        stopPolling();
    }

    currentBinaryId     = request.binaryId;
    currentAnalysisName = request.analysisName;
    isPolling           = true;

    pollTimer->setInterval (request.pollIntervalMs);
    pollTimer->start();

    // Check immediately
    checkAnalysisStatus();
}

void AnalysisStatusPoller::stopPolling() {
    if (pollTimer) {
        pollTimer->stop();
    }
    isPolling       = false;
    currentBinaryId = 0;
    currentAnalysisName.clear();
}

void AnalysisStatusPoller::checkAnalysisStatus() {
    if (!isPolling || currentBinaryId == 0) {
        return;
    }

    try {
        Status status = GetAnalysisStatus (GetConnection(), currentBinaryId);

        QString statusString;
        bool    isComplete = false;
        bool    isSuccess  = false;

        switch (status & STATUS_MASK) {
            case STATUS_QUEUED :
                statusString = "Queued";
                break;
            case STATUS_PROCESSING :
                statusString = "Processing";
                break;
            case STATUS_COMPLETE :
                statusString = "Complete";
                isComplete   = true;
                isSuccess    = true;
                break;
            case STATUS_ERROR :
                statusString = "Error";
                isComplete   = true;
                isSuccess    = false;
                break;
            default :
                statusString = "Unknown";
                break;
        }

        // Emit status update
        emit statusUpdate (currentBinaryId, statusString, currentAnalysisName);

        // If analysis is complete, emit completion signal and stop polling
        if (isComplete) {
            emit analysisCompleted (currentBinaryId, currentAnalysisName, isSuccess);
            stopPolling();
        }

    } catch (const std::exception &e) {
        emit pollingError (QString ("Failed to check analysis status: %1").arg (e.what()));
        stopPolling();
    } catch (...) {
        emit pollingError ("Unknown error while checking analysis status");
        stopPolling();
    }
}

// StartupAnalysisWorker implementation
StartupAnalysisWorker::StartupAnalysisWorker (QObject *parent) : QObject (parent), m_cancelled (false) {}

void StartupAnalysisWorker::searchMatchingAnalyses (const StartupAnalysisRequest &request) {
    m_cancelled = false;

    try {
        emitProgress (10, "Fetching recent analyses...");

        if (m_cancelled) {
            emit analysisError ("Operation cancelled");
            return;
        }

        // Get recent analyses
        RecentAnalysisRequest recents         = RecentAnalysisRequestInit();
        AnalysisInfos         recent_analyses = GetRecentAnalysis (GetConnection(), &recents);
        RecentAnalysisRequestDeinit (&recents);

        if (!recent_analyses.length) {
            emitProgress (100, "No recent analyses found");
            emit analysisFound (QVector<AnalysisInfo>());
            return;
        }

        emitProgress (50, "Comparing binary hashes...");

        if (m_cancelled) {
            VecDeinit (&recent_analyses);
            emit analysisError ("Operation cancelled");
            return;
        }

        // Find matching analyses by SHA256
        QVector<AnalysisInfo> matchingAnalyses;

        VecForeachPtr (&recent_analyses, analysis, {
            // Compare SHA256 (case-insensitive)
            QString analysisSha256 = QString::fromUtf8 (analysis->sha256.data).toLower();
            QString binarySha256   = request.binarySha256.toLower();

            if (analysisSha256 == binarySha256) {
                // Create a copy for Qt container
                AnalysisInfo copy;
                if (AnalysisInfoInitClone (&copy, analysis)) {
                    matchingAnalyses.append (copy);
                }
            }
        });

        VecDeinit (&recent_analyses);

        emitProgress (100, QString ("Found %1 matching analyses").arg (matchingAnalyses.size()));
        emit analysisFound (matchingAnalyses);

    } catch (const std::exception &e) {
        emit analysisError (QString ("Exception during analysis search: %1").arg (e.what()));
    } catch (...) {
        emit analysisError ("Unknown exception during analysis search");
    }
}

void StartupAnalysisWorker::cancel() {
    m_cancelled = true;
}

// AnalysisSelectionDialog implementation
AnalysisSelectionDialog::AnalysisSelectionDialog (const QVector<AnalysisInfo> &analyses, QWidget *parent)
    : QDialog (parent), analysisData (analyses), selectionResult (Cancel), selectedAnalysisId (0) {
    setupUI();
}

void AnalysisSelectionDialog::setupUI() {
    QVBoxLayout *mainLayout = new QVBoxLayout (this);

    if (analysisData.isEmpty()) {
        // Handle empty case - no existing analyses found
        setWindowTitle ("No Existing Analysis Found");
        setMinimumSize (500, 300);

        // Icon and message for empty state
        QLabel *iconLabel = new QLabel (this);
        iconLabel->setPixmap (
            style()
                ->standardPixmap (QStyle::SP_MessageBoxInformation)
                .scaled (64, 64, Qt::KeepAspectRatio, Qt::SmoothTransformation)
        );
        iconLabel->setAlignment (Qt::AlignCenter);
        mainLayout->addWidget (iconLabel);

        QLabel *titleLabel = new QLabel ("No Existing Analysis Found", this);
        titleLabel->setAlignment (Qt::AlignCenter);
        QFont titleFont = titleLabel->font();
        titleFont.setPointSize (titleFont.pointSize() + 4);
        titleFont.setBold (true);
        titleLabel->setFont (titleFont);
        mainLayout->addWidget (titleLabel);

        QLabel *descLabel = new QLabel (
            "No existing analyses were found for this binary.\n\n"
            "You can create a new analysis to get AI-powered insights for your binary, "
            "or cancel to continue without analysis.",
            this
        );
        descLabel->setWordWrap (true);
        descLabel->setAlignment (Qt::AlignCenter);
        mainLayout->addWidget (descLabel);

        mainLayout->addStretch();

        // Button layout for empty case
        QHBoxLayout *buttonLayout = new QHBoxLayout();

        createNewButton = new QPushButton ("Create New Analysis", this);
        createNewButton->setDefault (true); // Make this the default action
        createNewButton->setStyleSheet ("QPushButton { font-weight: bold; padding: 8px 16px; }");

        cancelButton = new QPushButton ("Cancel", this);

        buttonLayout->addStretch();
        buttonLayout->addWidget (createNewButton);
        buttonLayout->addWidget (cancelButton);
        buttonLayout->addStretch();

        mainLayout->addLayout (buttonLayout);

        // Connect signals for empty case
        connect (createNewButton, &QPushButton::clicked, this, &AnalysisSelectionDialog::onCreateNewClicked);
        connect (cancelButton, &QPushButton::clicked, this, &AnalysisSelectionDialog::onCancelClicked);

        // Don't create the table or "Use Existing" button for empty case
        analysisTable     = nullptr;
        useExistingButton = nullptr;

    } else {
        // Handle normal case - existing analyses found
        setWindowTitle ("Select Analysis");
        setMinimumSize (800, 400);

        // Description label
        QLabel *descLabel = new QLabel (
            "Found existing analyses for this binary. Select one to use or create a new analysis.\n"
            "Tip: Double-click an analysis to apply it immediately.",
            this
        );
        descLabel->setWordWrap (true);
        mainLayout->addWidget (descLabel);

        // Analysis table
        analysisTable = new QTableWidget (this);
        analysisTable->setSelectionBehavior (QAbstractItemView::SelectRows);
        analysisTable->setSelectionMode (QAbstractItemView::SingleSelection);

        // Set up table columns
        QStringList headers;
        headers << "Analysis ID" << "Binary Name" << "Status" << "Model Name" << "Creation Date" << "Owner"
                << "Private";
        analysisTable->setColumnCount (headers.size());
        analysisTable->setHorizontalHeaderLabels (headers);

        // Populate table
        analysisTable->setRowCount (analysisData.size());
        for (int i = 0; i < analysisData.size(); i++) {
            const AnalysisInfo &analysis = analysisData[i];

            // Create non-editable items
            QTableWidgetItem *idItem = new QTableWidgetItem (QString::number (analysis.analysis_id));
            idItem->setFlags (idItem->flags() & ~Qt::ItemIsEditable);
            analysisTable->setItem (i, 0, idItem);

            QTableWidgetItem *nameItem = new QTableWidgetItem (QString::fromUtf8 (analysis.binary_name.data));
            nameItem->setFlags (nameItem->flags() & ~Qt::ItemIsEditable);
            analysisTable->setItem (i, 1, nameItem);

            // Convert status enum to string
            QString statusStr;
            switch (analysis.status) {
                case STATUS_QUEUED :
                    statusStr = "Queued";
                    break;
                case STATUS_PROCESSING :
                    statusStr = "Processing";
                    break;
                case STATUS_COMPLETE :
                    statusStr = "Complete";
                    break;
                case STATUS_ERROR :
                    statusStr = "Error";
                    break;
                default :
                    statusStr = "Unknown";
                    break;
            }
            QTableWidgetItem *statusItem = new QTableWidgetItem (statusStr);
            statusItem->setFlags (statusItem->flags() & ~Qt::ItemIsEditable);
            analysisTable->setItem (i, 2, statusItem);

            // Get model name from model ID
            QString           modelName = getModelName (analysis.model_id);
            QTableWidgetItem *modelItem = new QTableWidgetItem (modelName);
            modelItem->setFlags (modelItem->flags() & ~Qt::ItemIsEditable);
            analysisTable->setItem (i, 3, modelItem);

            QTableWidgetItem *creationItem = new QTableWidgetItem (QString::fromUtf8 (analysis.creation.data));
            creationItem->setFlags (creationItem->flags() & ~Qt::ItemIsEditable);
            analysisTable->setItem (i, 4, creationItem);

            QTableWidgetItem *ownerItem = new QTableWidgetItem (QString::fromUtf8 (analysis.username.data));
            ownerItem->setFlags (ownerItem->flags() & ~Qt::ItemIsEditable);
            analysisTable->setItem (i, 5, ownerItem);

            QTableWidgetItem *privateItem = new QTableWidgetItem (analysis.is_private ? "Yes" : "No");
            privateItem->setFlags (privateItem->flags() & ~Qt::ItemIsEditable);
            analysisTable->setItem (i, 6, privateItem);

            // Store analysis ID in item data
            analysisTable->item (i, 0)->setData (Qt::UserRole, QVariant::fromValue (analysis.binary_id));
        }

        // Auto-resize columns
        analysisTable->resizeColumnsToContents();
        analysisTable->horizontalHeader()->setStretchLastSection (true);

        mainLayout->addWidget (analysisTable);

        // Button layout for normal case
        QHBoxLayout *buttonLayout = new QHBoxLayout();

        useExistingButton = new QPushButton ("Use Selected Analysis", this);
        useExistingButton->setEnabled (false); // Disabled until selection

        createNewButton = new QPushButton ("Create New Analysis", this);
        cancelButton    = new QPushButton ("Cancel", this);

        buttonLayout->addWidget (useExistingButton);
        buttonLayout->addWidget (createNewButton);
        buttonLayout->addStretch();
        buttonLayout->addWidget (cancelButton);

        mainLayout->addLayout (buttonLayout);

        // Connect signals for normal case
        connect (
            analysisTable,
            &QTableWidget::itemSelectionChanged,
            this,
            &AnalysisSelectionDialog::onAnalysisSelectionChanged
        );
        connect (
            analysisTable,
            &QTableWidget::itemDoubleClicked,
            this,
            &AnalysisSelectionDialog::onAnalysisDoubleClicked
        );
        connect (useExistingButton, &QPushButton::clicked, this, &AnalysisSelectionDialog::onUseExistingClicked);
        connect (createNewButton, &QPushButton::clicked, this, &AnalysisSelectionDialog::onCreateNewClicked);
        connect (cancelButton, &QPushButton::clicked, this, &AnalysisSelectionDialog::onCancelClicked);
    }
}

void AnalysisSelectionDialog::onAnalysisSelectionChanged() {
    if (analysisTable && useExistingButton) {
        bool hasSelection = !analysisTable->selectedItems().isEmpty();
        useExistingButton->setEnabled (hasSelection);
    }
}

void AnalysisSelectionDialog::onAnalysisDoubleClicked (QTableWidgetItem *item) {
    if (item) {
        // Double-click automatically applies the selected analysis
        onUseExistingClicked();
    }
}

void AnalysisSelectionDialog::onUseExistingClicked() {
    if (!analysisTable || analysisData.isEmpty()) {
        return; // Should not happen in empty case
    }

    int currentRow = analysisTable->currentRow();
    if (currentRow >= 0 && currentRow < analysisData.size()) {
        selectedAnalysisId = analysisData[currentRow].binary_id;

        RzCoreLocked core (Core());
        rzApplyAnalysis (core, selectedAnalysisId);

        selectionResult = UseExisting;
        accept();
    }
}

void AnalysisSelectionDialog::onCreateNewClicked() {
    selectionResult = CreateNew;
    accept();
}

void AnalysisSelectionDialog::onCancelClicked() {
    selectionResult = Cancel;
    reject();
}

QString AnalysisSelectionDialog::getModelName (ModelId modelId) {
    // Get models from the plugin
    ModelInfos *models = GetModels();
    if (models && models->length > 0) {
        // Search for the model with matching ID
        VecForeachPtr (models, model, {
            if (model->id == modelId) {
                return QString::fromUtf8 (model->name.data);
            }
        });
    }

    // Fallback to model ID if name not found
    return QString ("Model %1").arg (modelId);
}
