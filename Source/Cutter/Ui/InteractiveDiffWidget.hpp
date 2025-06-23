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
#include <QThread>
#include <QProgressBar>
#include <QTimer>

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
    Str        disassembly;      // Cached disassembly content
    Str        decompilation;    // Cached decompilation content
    bool       hasDecompilation; // Whether decompilation has been fetched

    SimilarFunctionData() : functionId (0), binaryId (0), similarity (0.0f), hasDecompilation (false) {
        disassembly   = StrInit();
        decompilation = StrInit();
    }

    ~SimilarFunctionData() {
        StrDeinit (&disassembly);
        StrDeinit (&decompilation);
    }

    // Copy constructor
    SimilarFunctionData (const SimilarFunctionData &other)
        : name (other.name),
          binaryName (other.binaryName),
          functionId (other.functionId),
          binaryId (other.binaryId),
          similarity (other.similarity) {
        disassembly      = StrDup (&other.disassembly);
        decompilation    = StrDup (&other.decompilation);
        hasDecompilation = other.hasDecompilation;
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
            StrDeinit (&decompilation);
            disassembly      = StrDup (&other.disassembly);
            decompilation    = StrDup (&other.decompilation);
            hasDecompilation = other.hasDecompilation;
        }
        return *this;
    }
};

// Forward declarations for async workers
class SimilarFunctionsWorker;
class DisassemblyWorker;
class DecompilationWorker;

// Search result structure (now only contains function list, no disassembly)
struct SearchResult {
    QList<SimilarFunctionData> similarFunctions;
    QString sourceFunctionName;
    bool success;
    QString errorMessage;
    
    SearchResult() : success(false) {
    }
    
    // Copy constructor and assignment operator for Qt containers
    SearchResult(const SearchResult &other) 
        : similarFunctions(other.similarFunctions),
          sourceFunctionName(other.sourceFunctionName),
          success(other.success),
          errorMessage(other.errorMessage) {
    }
    
    SearchResult &operator=(const SearchResult &other) {
        if (this != &other) {
            similarFunctions = other.similarFunctions;
            sourceFunctionName = other.sourceFunctionName;
            success = other.success;
            errorMessage = other.errorMessage;
        }
        return *this;
    }
};

// Disassembly result structure
struct DisassemblyResult {
    bool success;
    FunctionId functionId;
    Str disassembly;
    bool isSourceFunction;  // true if this is the source function, false if target
    int targetIndex;        // if isSourceFunction=false, this is the index in similarFunctions
    QString errorMessage;
    
    DisassemblyResult() : success(false), functionId(0), isSourceFunction(false), targetIndex(-1) {
        disassembly = StrInit();
    }
    
    ~DisassemblyResult() {
        StrDeinit(&disassembly);
    }
    
    // Copy constructor  
    DisassemblyResult(const DisassemblyResult& other) 
        : success(other.success), functionId(other.functionId), 
          isSourceFunction(other.isSourceFunction), targetIndex(other.targetIndex),
          errorMessage(other.errorMessage) {
        disassembly = StrDup(&other.disassembly);
    }
    
    // Assignment operator
    DisassemblyResult& operator=(const DisassemblyResult& other) {
        if (this != &other) {
            success = other.success;
            functionId = other.functionId;
            isSourceFunction = other.isSourceFunction;
            targetIndex = other.targetIndex;
            StrDeinit(&disassembly);
            disassembly = StrDup(&other.disassembly);
            errorMessage = other.errorMessage;
        }
        return *this;
    }
};

// Decompilation result structure
struct DecompilationResult {
    bool success;
    FunctionId functionId;
    Str decompilation;
    bool isSourceFunction;  // true if this is the source function, false if target
    int targetIndex;        // if isSourceFunction=false, this is the index in similarFunctions
    QString errorMessage;
    
    DecompilationResult() : success(false), functionId(0), isSourceFunction(false), targetIndex(-1) {
        decompilation = StrInit();
    }
    
    ~DecompilationResult() {
        StrDeinit(&decompilation);
    }
    
    // Copy constructor  
    DecompilationResult(const DecompilationResult& other) 
        : success(other.success), functionId(other.functionId), 
          isSourceFunction(other.isSourceFunction), targetIndex(other.targetIndex),
          errorMessage(other.errorMessage) {
        decompilation = StrDup(&other.decompilation);
    }
    
    // Assignment operator
    DecompilationResult& operator=(const DecompilationResult& other) {
        if (this != &other) {
            success = other.success;
            functionId = other.functionId;
            isSourceFunction = other.isSourceFunction;
            targetIndex = other.targetIndex;
            StrDeinit(&decompilation);
            decompilation = StrDup(&other.decompilation);
            errorMessage = other.errorMessage;
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
    void onToggleRequested();
    
    // Async slots
    void onSearchFinished(const SearchResult &result);
    void onSearchError(const QString &error);
    void onProgressUpdate(int percentage, const QString &status);
    void onDisassemblyFinished(const DisassemblyResult &result);
    void onDisassemblyError(const QString &error);
    void onDecompilationFinished(const DecompilationResult &result);
    void onDecompilationError(const QString &error);

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
    QPushButton *toggleButton;      // Toggle between assembly/decompilation
    QLabel      *statusLabel;       // Status information
    QProgressBar *progressBar;      // Progress indicator for async operations
    QPushButton *cancelButton;      // Cancel ongoing search

    // Data management
    QString                    currentSourceFunction;
    QList<SimilarFunctionData> similarFunctions;
    int                        currentSelectedIndex;
    DiffLines                  currentDiffLines;       // Current diff data
    Str                        sourceDisassembly;      // Source function disassembly
    Str                        sourceDecompilation;    // Source function decompilation
    QStringList                functionNameList;       // All function names for autocomplete
    bool                       isDecompilationMode;    // Whether showing decompilation or assembly
    bool                       sourceHasDecompilation; // Whether source decompilation is fetched

    // Async operation management
    SimilarFunctionsWorker *searchWorker;
    QThread *workerThread;
    DisassemblyWorker *disassemblyWorker;
    QThread *disassemblyThread;
    DecompilationWorker *decompilationWorker;
    QThread *decompilationThread;

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

    // Async operation management
    void startAsyncSearch();
    void cancelAsyncSearch();
    void startAsyncDisassembly();
    void startAsyncDisassemblyForCurrent();
    void cancelAsyncDisassembly();
    void startAsyncDecompilation();
    void startAsyncDecompilationForCurrent();
    void cancelAsyncDecompilation();
    void showProgress(int percentage, const QString &status);
    void hideProgress();

    // Helper to get function disassembly and decompilation
    Str  getFunctionDisassembly (FunctionId functionId);
    Str  getFunctionDecompilation (FunctionId functionId);
    void fetchDecompilationForFunction (int index); // Background decompilation fetching
    void fetchDecompilationForCurrentSelection();   // Priority decompilation fetching
};

// Async worker class for similarity search
class SimilarFunctionsWorker : public QObject {
    Q_OBJECT

public:
    explicit SimilarFunctionsWorker(QObject *parent = nullptr);
    
    struct SearchRequest {
        QString functionName;
        FunctionId functionId;
        int similarityThreshold;
        int maxResults;
    };

public slots:
    void performSearch(const SearchRequest &request);
    void cancelSearch();

signals:
    void searchFinished(const SearchResult &result);
    void searchError(const QString &error);
    void progressUpdate(int percentage, const QString &status);

private:
    bool m_cancelled;
    void emitProgress(int percentage, const QString &status);
};

// Async worker class for disassembly
class DisassemblyWorker : public QObject {
    Q_OBJECT

public:
    explicit DisassemblyWorker(QObject *parent = nullptr);
    
    struct DisassemblyRequest {
        FunctionId functionId;
        bool isSourceFunction;
        int targetIndex;
        QString functionName;
    };

public slots:
    void performDisassembly(const DisassemblyRequest &request);
    void cancelDisassembly();

signals:
    void disassemblyFinished(const DisassemblyResult &result);
    void disassemblyError(const QString &error);
    void progressUpdate(int percentage, const QString &status);

private:
    bool m_cancelled;
    void emitProgress(int percentage, const QString &status);
};

// Async worker class for decompilation
class DecompilationWorker : public QObject {
    Q_OBJECT

public:
    explicit DecompilationWorker(QObject *parent = nullptr);
    
    struct DecompilationRequest {
        FunctionId functionId;
        bool isSourceFunction;
        int targetIndex;
        QString functionName;
    };

public slots:
    void performDecompilation(const DecompilationRequest &request);
    void cancelDecompilation();

signals:
    void decompilationFinished(const DecompilationResult &result);
    void decompilationError(const QString &error);
    void progressUpdate(int percentage, const QString &status);

private:
    bool m_cancelled;
    void emitProgress(int percentage, const QString &status);
};

#endif                                              // REAI_PLUGIN_CUTTER_UI_INTERACTIVE_DIFF_WIDGET_HPP