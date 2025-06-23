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

/* plugin */
#include <Plugin.h>
#include "../PluginVersion.h"

// Forward declarations
class InteractiveDiffWidget;

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
    QAction *actCreateAnalysis           = nullptr;
    QAction *actApplyExistingAnalysis    = nullptr;
    QAction *actAutoAnalyzeBin           = nullptr;
    QAction *actRenameFns                = nullptr;
    QAction *actFunctionSimilaritySearch = nullptr;
    QAction *actCollectionSearch         = nullptr;
    QAction *actBinarySearch             = nullptr;
    QAction *actRecentAnalysis           = nullptr;
    QAction *actSetup                    = nullptr;
    QAction *actFunctionDiff             = nullptr;

    BinaryId customAnalysisId = 0;

    bool isInitialized = false;

    MainWindow            *mainWindow = NULL;
    InteractiveDiffWidget *diffWidget = nullptr;

    void renameFunctions (std::vector<std::pair<QString, QString>> nameMap);

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

    void on_ToggleReaiPlugin();
    void on_CreateAnalysis();
    void on_ApplyExistingAnalysis();
    void on_AutoAnalyzeBin();
    void on_RenameFns();
    void on_FunctionSimilaritySearch();
    void on_CollectionSearch();
    void on_BinarySearch();
    void on_RecentAnalysis();
    void on_Setup();
    void on_FunctionDiff();
};

#endif // REAI_PLUGIN_CUTTER_CUTTER_HPP
