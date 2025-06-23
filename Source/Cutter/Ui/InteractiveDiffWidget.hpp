/**
 * @file      : InteractiveDiffWidget.hpp
 * @author    : Siddharth Mishra
 * @date      : 2024
 * @copyright : Copyright (c) 2024 RevEngAI. All Rights Reserved.
 * */

#ifndef REAI_PLUGIN_CUTTER_UI_INTERACTIVE_DIFF_WIDGET_HPP
#define REAI_PLUGIN_CUTTER_UI_INTERACTIVE_DIFF_WIDGET_HPP

/* qt */
#include <QWidget>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QSplitter>
#include <QTreeWidget>
#include <QTextEdit>
#include <QLineEdit>
#include <QSlider>
#include <QLabel>
#include <QPushButton>
#include <QCompleter>
#include <QStringList>
#include <QTreeWidgetItem>

/* cutter */
#include <cutter/widgets/CutterDockWidget.h>
#include <cutter/core/MainWindow.h>

/* reai */
#include <Reai/Api.h>
#include <Reai/Diff.h>
#include <Reai/Util/Str.h>
#include <Reai/Util/Vec.h>

/* rizin */
#include <rz_core.h>

// Structure to hold similar function data for the widget
struct SimilarFunctionData {
    QString    name;
    QString    binaryName;
    FunctionId functionId;
    BinaryId   binaryId;
    float      similarity;
    Str        disassembly; // Cached disassembly content

    SimilarFunctionData() : functionId (0), binaryId (0), similarity (0.0f) {
        disassembly = StrInit();
    }

    ~SimilarFunctionData() {
        StrDeinit (&disassembly);
    }

    // Copy constructor
    SimilarFunctionData (const SimilarFunctionData &other)
        : name (other.name),
          binaryName (other.binaryName),
          functionId (other.functionId),
          binaryId (other.binaryId),
          similarity (other.similarity) {
        disassembly = StrDup (&other.disassembly);
    }

    // Assignment operator
    SimilarFunctionData &operator= (const SimilarFunctionData &other) {
        if (this != &other) {
            name       = other.name;
            binaryName = other.binaryName;
            functionId = other.functionId;
            binaryId   = other.binaryId;
            similarity = other.similarity;
            StrDeinit (&disassembly);
            disassembly = StrDup (&other.disassembly);
        }
        return *this;
    }
};

class InteractiveDiffWidget : public CutterDockWidget {
    Q_OBJECT

   public:
    explicit InteractiveDiffWidget (MainWindow *main);
    ~InteractiveDiffWidget();

   public slots:
    void showDiffForFunction (const QString &functionName, int similarity = 90);

   private slots:
    void onFunctionNameChanged();
    void onSimilarityChanged (int value);
    void onSearchRequested();
    void onFunctionListItemClicked (QTreeWidgetItem *item, int column);
    void onRenameRequested();

   private:
    // Main layout components
    QVBoxLayout *mainLayout;
    QSplitter   *mainSplitter;   // 3-panel splitter
    QWidget     *controlsWidget; // Bottom control area

    // Three main panels
    QTreeWidget *functionListPanel; // Left: Similar functions list
    QTextEdit   *sourceDiffPanel;   // Middle: Source function diff
    QTextEdit   *targetDiffPanel;   // Right: Target function diff

    // Bottom control area
    QLineEdit   *functionNameInput; // Function name with autocomplete
    QCompleter  *functionCompleter; // Autocomplete for function names
    QSlider     *similaritySlider;  // Similarity level (50-100)
    QLabel      *similarityLabel;   // Shows current similarity value
    QPushButton *searchButton;      // Trigger search
    QPushButton *renameButton;      // Rename to selected function
    QLabel      *statusLabel;       // Status information

    // Data management
    QString                    currentSourceFunction;
    QList<SimilarFunctionData> similarFunctions;
    int                        currentSelectedIndex;
    DiffLines                  currentDiffLines;  // Current diff data
    Str                        sourceDisassembly; // Source function disassembly
    QStringList                functionNameList;  // All function names for autocomplete

    // Setup methods
    void setupUI();
    void setupControlsArea();
    void setupThreePanelLayout();
    void connectSignals();

    // Data loading and processing
    void loadFunctionNames();      // Load all function names for autocomplete
    void searchSimilarFunctions(); // Fetch similar functions from API
    void updateFunctionList();     // Update left panel with similar functions
    void updateDiffPanels();       // Update source/target panels
    void generateDiff();           // Generate DiffLines from source/target

    // Diff rendering (adapted from CmdHandlers.c logic)
    void    renderSourceDiff (const DiffLines &diff);
    void    renderTargetDiff (const DiffLines &diff);
    QString formatDiffLineForQt (const DiffLine &line, bool isSource);
    QString getColorForDiffType (DiffType type, bool isSource);

    // Utility methods
    void applySyntaxHighlighting();
    void showLoadingState (const QString &message);
    void showErrorState (const QString &error);
    void clearPanels();
    void updateStatusLabel (const QString &status);

    // Helper to get function disassembly
    Str getFunctionDisassembly (FunctionId functionId);
};

#endif // REAI_PLUGIN_CUTTER_UI_INTERACTIVE_DIFF_WIDGET_HPP