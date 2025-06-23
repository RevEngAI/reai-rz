/**
 * @file      : Cutter.hpp
 * @author    : Siddharth Mishra
 * @date      : 07/06/2024
 * @copyright : Copyright (c) 2024 RevEngAI. All Rights Reserved.
 * */

#ifndef REAI_PLUGIN_CUTTER_CUTTER_HPP
#define REAI_PLUGIN_CUTTER_CUTTER_HPP

/* cutter */
#include <cutter/CutterApplication.h>
#include <cutter/core/MainWindow.h>
#include <cutter/plugins/CutterPlugin.h>

// decompiler is to be implemented through this interface and made available
// to decompiler widget, and our job is down
#include <cutter/common/Decompiler.h>

/* qt */
#include <QObject>
#include <QLabel>
#include <QProgressBar>
#include <QPushButton>
#include <QTimer>
#include <QSystemTrayIcon>
#include <QThread>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QDialog>
#include <QVector>

/* plugin */
#include <Plugin.h>
#include "../PluginVersion.h"

// Forward declarations
class InteractiveDiffWidget;
class AnalysisStatusPoller;
class StartupAnalysisWorker;
class AnalysisSelectionDialog;

// TODO: some shortcuts like (Ctrl+A, Ctr+E) to apple existing analysis would be really nice

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
    QAction *actCreateAnalysis        = nullptr;
    QAction *actApplyExistingAnalysis = nullptr;
    QAction *actAutoAnalyzeBin        = nullptr;
    QAction *actCollectionSearch      = nullptr;
    QAction *actBinarySearch          = nullptr;
    QAction *actRecentAnalysis        = nullptr;
    QAction *actSetup                 = nullptr;
    QAction *actFunctionDiff          = nullptr;

    /* context menu actions */
    QAction *actFindSimilarFunctions = nullptr;

    BinaryId customAnalysisId = 0;

    bool isInitialized = false;

    MainWindow            *mainWindow = NULL;
    InteractiveDiffWidget *diffWidget = nullptr;

    // Status bar management
    QLabel       *statusLabel        = nullptr;
    QProgressBar *statusProgressBar  = nullptr;
    QPushButton  *statusCancelButton = nullptr;
    QTimer       *statusHideTimer    = nullptr;

    // Current operation tracking
    QString  currentOperationType;
    BinaryId currentAnalysisBinaryId = 0;

    // Analysis status polling
    QThread              *pollerThread   = nullptr;
    AnalysisStatusPoller *statusPoller   = nullptr;
    QSystemTrayIcon      *systemTrayIcon = nullptr;

    // Startup analysis matching
    QThread               *startupWorkerThread = nullptr;
    StartupAnalysisWorker *startupWorker       = nullptr;


    void setupContextMenus();
    void setupStatusBar();
    void setupSystemTray();
    void startupAnalysisCheck();

   public:
    void setupPlugin() override;
    void setupInterface (MainWindow *mainWin) override;
    void registerDecompilers() override;
    ~ReaiCutterPlugin();

    QString getName() const override {
        return "RevEngAI Plugin (rz-reai)";
    }
    QString getAuthor() const override {
        return "Siddharth Mishra";
    }
    QString getVersion() const override {
        return REAI_PLUGIN_VERSION;
    }
    QString getDescription() const override {
        return "AI based reverse engineering helper API & Toolkit";
    }

    // Status bar management methods
    void showStatusProgress (const QString &operationType, const QString &message, int percentage = -1);
    void updateStatusProgress (const QString &message, int percentage);
    void hideStatusProgress();
    void showStatusMessage (const QString &message, int duration = 5000);
    void showNotification (const QString &title, const QString &message, bool isSuccess = true);

    // Analysis polling methods
    void startAnalysisPolling (BinaryId binaryId, const QString &analysisName);
    void stopAnalysisPolling();

    // Global access to status methods (singleton pattern)
    static ReaiCutterPlugin *instance() {
        return s_instance;
    }

    void on_ToggleReaiPlugin();
    void on_CreateAnalysis();
    void on_ApplyExistingAnalysis();
    void on_AutoAnalyzeBin();
    void on_CollectionSearch();
    void on_BinarySearch();
    void on_RecentAnalysis();
    void on_Setup();
    void on_FunctionDiff();

   private slots:
    void on_FindSimilarFunctions();
    void onStatusHideTimeout();
    void onStatusCancelClicked();
    void onAnalysisStatusUpdate (BinaryId binaryId, const QString &status, const QString &analysisName);
    void onAnalysisCompleted (BinaryId binaryId, const QString &analysisName, bool success);
    void onStartupAnalysisFound (const QVector<AnalysisInfo> &matchingAnalyses);
    void onStartupAnalysisError (const QString &error);
    void onBinaryLoaded();

   private:
    static ReaiCutterPlugin *s_instance;
};

// Analysis status polling worker
class AnalysisStatusPoller : public QObject {
    Q_OBJECT

   public:
    explicit AnalysisStatusPoller (QObject *parent = nullptr);

    struct PollingRequest {
        BinaryId binaryId;
        QString  analysisName;
        int      pollIntervalMs;
    };

   public slots:
    void startPolling (const PollingRequest &request);
    void stopPolling();

   signals:
    void statusUpdate (BinaryId binaryId, const QString &status, const QString &analysisName);
    void analysisCompleted (BinaryId binaryId, const QString &analysisName, bool success);
    void pollingError (const QString &error);

   private slots:
    void checkAnalysisStatus();

   private:
    QTimer  *pollTimer;
    BinaryId currentBinaryId;
    QString  currentAnalysisName;
    bool     isPolling;
};

// Global convenience functions for status updates
void ShowGlobalStatus (const QString &operationType, const QString &message, int percentage = -1);
void UpdateGlobalStatus (const QString &message, int percentage);
void HideGlobalStatus();
void ShowGlobalMessage (const QString &message, int duration = 5000);
void ShowGlobalNotification (const QString &title, const QString &message, bool isSuccess = true);

// Global convenience functions for analysis polling
void StartGlobalAnalysisPolling (BinaryId binaryId, const QString &analysisName);
void StopGlobalAnalysisPolling();

// Startup analysis matching worker
class StartupAnalysisWorker : public QObject {
    Q_OBJECT

   public:
    explicit StartupAnalysisWorker (QObject *parent = nullptr);

    struct StartupAnalysisRequest {
        QString binaryPath;
        QString binarySha256;
    };

   public slots:
    void searchMatchingAnalyses (const StartupAnalysisRequest &request);
    void cancel();

   signals:
    void analysisFound (const QVector<AnalysisInfo> &matchingAnalyses);
    void analysisError (const QString &error);
    void progress (int percentage, const QString &message);

   private:
    bool m_cancelled;

    void emitProgress (int percentage, const QString &message) {
        if (!m_cancelled) {
            emit progress (percentage, message);
        }
    }
};

// Analysis selection dialog
class AnalysisSelectionDialog : public QDialog {
    Q_OBJECT

   public:
    explicit AnalysisSelectionDialog (const QVector<AnalysisInfo> &analyses, QWidget *parent = nullptr);

    enum SelectionResult {
        UseExisting,
        CreateNew,
        Cancel
    };

    SelectionResult getSelectionResult() const {
        return selectionResult;
    }
    BinaryId getSelectedAnalysisId() const {
        return selectedAnalysisId;
    }

   private slots:
    void onUseExistingClicked();
    void onCreateNewClicked();
    void onCancelClicked();
    void onAnalysisSelectionChanged();
    void onAnalysisDoubleClicked (QTableWidgetItem *item);

   private:
    void    setupUI();
    QString getModelName (ModelId modelId);

    QVector<AnalysisInfo> analysisData;
    QTableWidget         *analysisTable;
    QPushButton          *useExistingButton;
    QPushButton          *createNewButton;
    QPushButton          *cancelButton;

    SelectionResult selectionResult;
    BinaryId        selectedAnalysisId;
};

#endif // REAI_PLUGIN_CUTTER_CUTTER_HPP
