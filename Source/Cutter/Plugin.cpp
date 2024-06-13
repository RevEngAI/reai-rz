/**
 * @file      : Main.cpp
 * @author    : Siddharth Mishra
 * @date      : 07/06/2024
 * @copyright : Copyright (c) 2024 Siddharth Mishra. All Rights Reserved.
 * */

/* cutter includes */
#include <cutter/CutterApplication.h>
#include <cutter/core/MainWindow.h>
#include <cutter/plugins/CutterPlugin.h>

/* qt includes */
#include <qt6/QtCore/QDebug>
#include <qt6/QtCore/QObject>
#include <qt6/QtCore/QtPlugin>
#include <qt6/QtGui/QAction>
#include <qt6/QtWidgets/QMainWindow>
#include <qt6/QtWidgets/QMenuBar>

/* creait lib */
#include <Reai/Api/Api.h>
#include <Reai/Common.h>

/**
 * @b Override default message handler by this one.
 *
 * @param[in] type
 * @param[in] context
 * @param[in] msg
 * */
void reai_custom_qt_message_handler(QtMsgType type, const QMessageLogContext& context, const QString& msg)
{
    Q_UNUSED(context);

    QByteArray localMsg = msg.toLocal8Bit();
    switch (type) {
    case QtDebugMsg:
        fprintf(stderr, "REAI::Debug: %s\n", localMsg.constData());
        break;
    case QtInfoMsg:
        fprintf(stderr, "REAI::Info: %s\n", localMsg.constData());
        break;
    case QtWarningMsg:
        fprintf(stderr, "REAI::Warning: %s\n", localMsg.constData());
        break;
    case QtCriticalMsg:
        fprintf(stderr, "REAI::Critical: %s\n", localMsg.constData());
        break;
    case QtFatalMsg:
        fprintf(stderr, "REAI::Fatal: %s\n", localMsg.constData());
        abort();
    }

    // Flush the output to ensure it's not buffered
    fflush(stderr);
}

/**
 * @b RevEngAI Cutter Plugin class.
 *
 * This is the actual plugin that's loaded by Cutter with help
 * of QtPluginLoader.
 * */
class ReaiCutterPlugin : public QObject, public CutterPlugin {
    Q_OBJECT
    Q_PLUGIN_METADATA(IID "re.rizin.cutter.plugins.revengai")
    Q_INTERFACES(CutterPlugin)

    /* to create separate menu for revengai plugin in cutter's main window's menu bar */
    QMenu* reaiMenu = nullptr;

    /* action to enable/disable (show/hide) revengai plugin */
    QAction* actToggleReaiPlugin = nullptr;

    /* revengai's menu item actions */
    QAction* actUploadBin = nullptr;
    QAction* actCheckAnalysisStatus = nullptr;
    QAction* actAutoAnalyzeBinSym = nullptr;
    QAction* actPerformRenameFromSimilarFns = nullptr;
    QAction* actDownloadBinAnalysisLogs = nullptr;
    QAction* actBinAnalysisHistory = nullptr;

    Reai* reai = nullptr;
    ReaiResponse* response;
    ReaiRequest* request;

public:
    void setupPlugin() override;
    void setupInterface(MainWindow* mainWin) override;
    ~ReaiCutterPlugin();

    QString getName() const override { return "RevEngAI Plugin (rz-reai)"; }
    QString getAuthor() const override { return "Siddharth Mishra"; }
    QString getVersion() const override { return "0"; }
    QString getDescription() const override
    {
        return "AI based reverse engineering helper API & Toolkit";
    }

    void on_ToggleReaiPlugin();
    void on_UploadBin();
    void on_CheckAnalysisStatus();
    void on_AutoAnalyzeBinSym();
    void on_PerformRenameFromSimilarFns();
    void on_DownloadBinAnalysisLogs();
    void on_BinAnalysisHistory();
};

void ReaiCutterPlugin::setupPlugin()
{

    /* turn off output buffering */
    setbuf(stdout, nullptr);
    setbuf(stderr, nullptr);

    /* install custom message handler */
    qInstallMessageHandler(reai_custom_qt_message_handler);

    qInfo() << __FUNCTION__;

    if (!(response = reai_response_init(new ReaiResponse))) {
        qCritical() << "Failed to initialize response data object\n";
    }

    reai = reai_create(HARDCODED_HOST, HARDCODED_API_KEY);
    if (!reai) {
        qCritical() << "Failed to create Reai instance";
    }

    request = new ReaiRequest;

    qInfo() << __FUNCTION__;
};

/**
 * @b Required by CutterPlugin to initialize UI for this plugin.
 *
 * @param mainWin Reference to main window provided by Cutter
 * */
void ReaiCutterPlugin::setupInterface(MainWindow* mainWin)
{
    qInfo() << __FUNCTION__;
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
                if (menu->title() == QString("Windows")) {
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
                if (menu->title() == QString("Plugins")) {
                    pluginsMenu = menu;
                    break;
                }
            }
        }

        if (!pluginsMenu) {
            qCritical() << "Cutter main window has no 'Plugins' sub-menu in 'Windows' menu of it's menu bar.";
            return;
        }
    }

    actToggleReaiPlugin = pluginsMenu->addAction("RevEngAI");
    if (!actToggleReaiPlugin) {
        qCritical() << "Failed to add action to trigger RevEngAI Plugin on/off in Plugins menu.";
        return;
    }
    actToggleReaiPlugin->setCheckable(true);
    actToggleReaiPlugin->setChecked(true);

    connect(actToggleReaiPlugin, &QAction::toggled, this, &ReaiCutterPlugin::on_ToggleReaiPlugin);

    /* add revengai's own plugin menu */
    reaiMenu = menuBar->addMenu("RevEngAI");
    if (!reaiMenu) {
        qCritical() << "Failed to add my own menu to Cutter's main window menu bar";
        return;
    }

    actUploadBin = reaiMenu->addAction("Upload Binary");
    actAutoAnalyzeBinSym = reaiMenu->addAction("Auto Analyze Binary");
    actBinAnalysisHistory = reaiMenu->addAction("Binary Analysis History");
    actCheckAnalysisStatus = reaiMenu->addAction("Check Analysis Status");
    actDownloadBinAnalysisLogs = reaiMenu->addAction("Download Binary Analysis Logs");
    actPerformRenameFromSimilarFns = reaiMenu->addAction("Rename From Similar Functions");

    connect(actUploadBin, &QAction::triggered, this, &ReaiCutterPlugin::on_UploadBin);
    connect(actAutoAnalyzeBinSym, &QAction::triggered, this, &ReaiCutterPlugin::on_AutoAnalyzeBinSym);
    connect(actBinAnalysisHistory, &QAction::triggered, this, &ReaiCutterPlugin::on_BinAnalysisHistory);
    connect(actCheckAnalysisStatus, &QAction::triggered, this, &ReaiCutterPlugin::on_CheckAnalysisStatus);
    connect(actDownloadBinAnalysisLogs, &QAction::triggered, this, &ReaiCutterPlugin::on_DownloadBinAnalysisLogs);
    connect(actPerformRenameFromSimilarFns, &QAction::triggered, this, &ReaiCutterPlugin::on_PerformRenameFromSimilarFns);
    qInfo() << __FUNCTION__;
}

ReaiCutterPlugin::~ReaiCutterPlugin()
{
    if (request) {
        delete request;
    }

    if (response) {
        delete response;
    }

    if (reai) {
        reai_destroy(reai);
    }
}

/**
 * @b Called when
 * */
void ReaiCutterPlugin::on_ToggleReaiPlugin()
{
    qInfo() << __FUNCTION__;
    reaiMenu->menuAction()->setVisible(actToggleReaiPlugin->isChecked());
    qInfo() << __FUNCTION__;
}

void ReaiCutterPlugin::on_UploadBin()
{
    qInfo() << __FUNCTION__;
    request->type = REAI_REQUEST_TYPE_UPLOAD_FILE;
    request->upload_file.file_path = "/home/misra/Desktop/RevEngAI/plugins/native/Build/Source/libreai_cutter.so";
    if (!reai_request(reai, request, response)) {
        qCritical() << "Failed to make request";
    }

    qInfo() << response->raw.data;
    qInfo() << __FUNCTION__;
}

void ReaiCutterPlugin::on_CheckAnalysisStatus() { qInfo() << __FUNCTION__; }
void ReaiCutterPlugin::on_AutoAnalyzeBinSym() { qInfo() << __FUNCTION__; }
void ReaiCutterPlugin::on_PerformRenameFromSimilarFns() { qInfo() << __FUNCTION__; }
void ReaiCutterPlugin::on_DownloadBinAnalysisLogs() { qInfo() << __FUNCTION__; }
void ReaiCutterPlugin::on_BinAnalysisHistory() { qInfo() << __FUNCTION__; }

/* Required by the meta object compiler, otherwise build fails */
#include "Plugin.moc"
