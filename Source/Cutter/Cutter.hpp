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

/* qt */
#include <QObject>

/* plugin */
#include <Cutter/Ui/ConfigSetupDialog.hpp>

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
    QAction *actUploadBin                = nullptr;
    QAction *actCreateAnalysis           = nullptr;
    QAction *actApplyExistingAnalysis    = nullptr;
    QAction *actCheckAnalysisStatus      = nullptr;
    QAction *actAutoAnalyzeBinSym        = nullptr;
    QAction *actRenameFns                = nullptr;
    QAction *actFunctionSimilaritySearch = nullptr;
    QAction *actBinAnalysisHistory       = nullptr;
    QAction *actSetup                    = nullptr;

    ReaiBinaryId customAnalysisId = 0;

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
    void on_CreateAnalysis();
    void on_ApplyExistingAnalysis();
    void on_CheckAnalysisStatus();
    void on_AutoAnalyzeBinSym();
    void on_RenameFns();
    void on_FunctionSimilaritySearch();
    void on_BinAnalysisHistory();
    void on_Setup();
};

#endif // REAI_PLUGIN_CUTTER_CUTTER_HPP
