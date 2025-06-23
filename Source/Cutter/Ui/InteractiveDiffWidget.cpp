/**
 * @file      : InteractiveDiffWidget.cpp
 * @author    : Siddharth Mishra
 * @date      : 2024
 * @copyright : Copyright (c) 2024 RevEngAI. All Rights Reserved.
 * */

/* qt */
#include <QHeaderView>
#include <QMessageBox>
#include <QApplication>
#include <QScrollArea>
#include <QDebug>
#include <QStringListModel>

/* cutter */
#include <cutter/core/Cutter.h>
#include <librz/rz_analysis.h>

/* reai */
#include <Plugin.h>
#include <Reai/Api.h>
#include <Reai/Log.h>
#include <Reai/Diff.h>
#include <Cutter/Ui/InteractiveDiffWidget.hpp>

InteractiveDiffWidget::InteractiveDiffWidget (MainWindow *main)
    : CutterDockWidget (main),
      functionCompleter (nullptr),
      currentSelectedIndex (-1),
      isDecompilationMode (false),
      sourceHasDecompilation (false) {
    setObjectName ("InteractiveDiffWidget");
    setWindowTitle ("Interactive Function Diff");

    // Initialize string containers
    sourceDisassembly   = StrInit();
    sourceDecompilation = StrInit();
    currentDiffLines    = VecInit();

    // Initialize async components
    searchWorker = nullptr;
    workerThread = nullptr;
    disassemblyWorker = nullptr;
    disassemblyThread = nullptr;
    decompilationWorker = nullptr;
    decompilationThread = nullptr;

    setupUI();
    connectSignals();
    loadFunctionNames();

    // Initially disable search until function is selected
    searchButton->setEnabled (false);
}

InteractiveDiffWidget::~InteractiveDiffWidget() {
    // Clean up async operations first and wait for completion
    if (workerThread && workerThread->isRunning()) {
        if (searchWorker) {
            searchWorker->cancelSearch();
        }
        
        workerThread->quit();
        if (!workerThread->wait(2000)) { // Wait 2 seconds max
            workerThread->terminate();
            workerThread->wait(500); // Wait another 500ms after terminate
        }
    }
    
    if (disassemblyThread && disassemblyThread->isRunning()) {
        if (disassemblyWorker) {
            disassemblyWorker->cancelDisassembly();
        }
        
        disassemblyThread->quit();
        if (!disassemblyThread->wait(2000)) { // Wait 2 seconds max
            disassemblyThread->terminate();
            disassemblyThread->wait(500); // Wait another 500ms after terminate
        }
    }
    
    if (decompilationThread && decompilationThread->isRunning()) {
        if (decompilationWorker) {
            decompilationWorker->cancelDecompilation();
        }
        
        decompilationThread->quit();
        if (!decompilationThread->wait(2000)) { // Wait 2 seconds max
            decompilationThread->terminate();
            decompilationThread->wait(500); // Wait another 500ms after terminate
        }
    }
    
    // Clean up string containers
    StrDeinit (&sourceDisassembly);
    StrDeinit (&sourceDecompilation);
    VecDeinit (&currentDiffLines);
}

void InteractiveDiffWidget::setupUI() {
    // Create main widget and layout
    QWidget *mainWidget = new QWidget();
    mainLayout          = new QVBoxLayout (mainWidget);
    mainLayout->setContentsMargins (5, 5, 5, 5);
    mainLayout->setSpacing (5);

    setupThreePanelLayout();
    setupControlsArea();

    // Add components to main layout
    mainLayout->addWidget (mainSplitter, 1);   // Take most space
    mainLayout->addWidget (controlsWidget, 0); // Fixed size at bottom

    // Set flexible size policies for the main widget
    mainWidget->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
    
    // Set reasonable minimum and maximum sizes
    setMinimumSize(400, 300); // Much smaller minimum than before
    setMaximumSize(QWIDGETSIZE_MAX, QWIDGETSIZE_MAX); // No maximum constraint
    
    // Set preferred size to be reasonable but not overwhelming
    resize(600, 400);

    setWidget (mainWidget);
}

void InteractiveDiffWidget::setupThreePanelLayout() {
    // Create horizontal splitter for three panels
    mainSplitter = new QSplitter (Qt::Horizontal);

    // Left panel: Similar functions list
    functionListPanel = new QTreeWidget();
    functionListPanel->setHeaderLabels ({"Function Name", "Binary", "Similarity"});
    functionListPanel->header()->setSectionResizeMode (QHeaderView::ResizeToContents);
    functionListPanel->setMinimumWidth (120); 
    functionListPanel->setSizePolicy(QSizePolicy::Preferred, QSizePolicy::Expanding);
    functionListPanel->setSortingEnabled (true);
    functionListPanel->sortByColumn (2, Qt::DescendingOrder); // Sort by similarity desc

    // Middle panel: Source diff
    sourceDiffPanel = new QTextEdit();
    sourceDiffPanel->setReadOnly (true);
    sourceDiffPanel->setFont (QFont ("Consolas", 10));
    sourceDiffPanel->setPlaceholderText ("Source function disassembly will appear here...");
    sourceDiffPanel->setMinimumWidth (150);
    sourceDiffPanel->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);

    // Right panel: Target diff
    targetDiffPanel = new QTextEdit();
    targetDiffPanel->setReadOnly (true);
    targetDiffPanel->setFont (QFont ("Consolas", 10));
    targetDiffPanel->setPlaceholderText ("Target function disassembly will appear here...");
    targetDiffPanel->setMinimumWidth (150); 
    targetDiffPanel->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);

    // Add panels to splitter
    mainSplitter->addWidget (functionListPanel);
    mainSplitter->addWidget (sourceDiffPanel);
    mainSplitter->addWidget (targetDiffPanel);

    // Set proportional sizes with smaller initial values for flexibility
    mainSplitter->setSizes ({120, 200, 200});
    mainSplitter->setStretchFactor (0, 1); 
    mainSplitter->setStretchFactor (1, 2); 
    mainSplitter->setStretchFactor (2, 2); 
    
    // Make splitter collapsible for better flexibility
    mainSplitter->setChildrenCollapsible(true);
}

void InteractiveDiffWidget::setupControlsArea() {
    controlsWidget              = new QWidget();
    QHBoxLayout *controlsLayout = new QHBoxLayout (controlsWidget);
    controlsLayout->setContentsMargins (0, 5, 0, 0);
    
    // Set flexible size policy for controls widget
    controlsWidget->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);

    // Function name input with autocomplete
    QLabel *fnLabel   = new QLabel ("Function:");
    functionNameInput = new QLineEdit();
    functionNameInput->setPlaceholderText ("Start typing for suggestions...");
    functionNameInput->setMinimumWidth (150); 
    functionNameInput->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);

    // Similarity slider with label
    QLabel *simLabel = new QLabel ("Min Similarity:");
    similaritySlider = new QSlider (Qt::Horizontal);
    similaritySlider->setRange (50, 100);
    similaritySlider->setValue (90);
    similaritySlider->setMinimumWidth (100); 
    similaritySlider->setSizePolicy(QSizePolicy::Preferred, QSizePolicy::Fixed);

    similarityLabel = new QLabel ("90%");
    similarityLabel->setMinimumWidth (30); 

    // Search button
    searchButton = new QPushButton ("Search");
    searchButton->setSizePolicy(QSizePolicy::Fixed, QSizePolicy::Fixed);

    // Rename button
    renameButton = new QPushButton ("Rename to Selected");
    renameButton->setSizePolicy(QSizePolicy::Fixed, QSizePolicy::Fixed);
    renameButton->setEnabled (false); // Initially disabled

    // Toggle button for assembly/decompilation
    toggleButton = new QPushButton ("Show Decompilation");
    toggleButton->setSizePolicy(QSizePolicy::Fixed, QSizePolicy::Fixed);
    toggleButton->setCheckable (true);
    toggleButton->setChecked (false); // Default to assembly

    // Status label
    statusLabel = new QLabel ("Ready");
    statusLabel->setStyleSheet ("color: gray; font-style: italic;");

    // Progress bar for async operations
    progressBar = new QProgressBar();
    progressBar->setVisible(false);
    progressBar->setMaximumWidth(200);
    
    // Cancel button for async operations
    cancelButton = new QPushButton("Cancel");
    cancelButton->setVisible(false);
    cancelButton->setMaximumWidth(60);

    // Layout controls
    controlsLayout->addWidget (fnLabel);
    controlsLayout->addWidget (functionNameInput);
    controlsLayout->addSpacing (10);
    controlsLayout->addWidget (simLabel);
    controlsLayout->addWidget (similaritySlider);
    controlsLayout->addWidget (similarityLabel);
    controlsLayout->addSpacing (10);
    controlsLayout->addWidget (searchButton);
    controlsLayout->addSpacing (10);
    controlsLayout->addWidget (renameButton);
    controlsLayout->addSpacing (10);
    controlsLayout->addWidget (toggleButton);
    controlsLayout->addStretch(); // Push status to right
    controlsLayout->addWidget (progressBar);
    controlsLayout->addWidget (cancelButton);
    controlsLayout->addWidget (statusLabel);
}

void InteractiveDiffWidget::connectSignals() {
    // Function name input
    connect (functionNameInput, &QLineEdit::textChanged, this, &InteractiveDiffWidget::onFunctionNameChanged);
    connect (functionNameInput, &QLineEdit::returnPressed, this, &InteractiveDiffWidget::onSearchRequested);

    // Similarity slider
    connect (similaritySlider, &QSlider::valueChanged, this, &InteractiveDiffWidget::onSimilarityChanged);

    // Search button
    connect (searchButton, &QPushButton::clicked, this, &InteractiveDiffWidget::onSearchRequested);

    // Rename button
    connect (renameButton, &QPushButton::clicked, this, &InteractiveDiffWidget::onRenameRequested);

    // Toggle button
    connect (toggleButton, &QPushButton::toggled, this, &InteractiveDiffWidget::onToggleRequested);

    // Cancel button
    connect (cancelButton, &QPushButton::clicked, this, &InteractiveDiffWidget::cancelAsyncSearch);

    // Function list selection
    connect (functionListPanel, &QTreeWidget::itemClicked, this, &InteractiveDiffWidget::onFunctionListItemClicked);
    connect (
        functionListPanel,
        &QTreeWidget::currentItemChanged,
        this,
        [this] (QTreeWidgetItem *current, QTreeWidgetItem *) {
            if (current) {
                onFunctionListItemClicked (current, 0);
            }
        }
    );
}

void InteractiveDiffWidget::loadFunctionNames() {
    functionNameList.clear();

    RzCoreLocked core (Core());

    if (!rz_analysis_function_list (core->analysis) || !rz_list_length (rz_analysis_function_list (core->analysis))) {
        updateStatusLabel (
            "Opened binary seems to have no functions. None detected by Rizin. Cannot perform similarity search."
        );
        return;
    }

    /* add all symbols corresponding to functions */
    RzList     *fns     = rz_analysis_function_list (core->analysis);
    RzListIter *fn_iter = nullptr;
    void       *data    = nullptr;
    rz_list_foreach (fns, fn_iter, data) {
        RzAnalysisFunction *fn = (RzAnalysisFunction *)data;
        functionNameList << fn->name;
    }

    // Setup autocomplete exactly like FunctionSimilarityDialog
    functionCompleter = new QCompleter (functionNameList);
    functionCompleter->setCaseSensitivity (Qt::CaseInsensitive);
    functionNameInput->setCompleter (functionCompleter);

    updateStatusLabel (QString ("Loaded %1 functions").arg (functionNameList.size()));
}

void InteractiveDiffWidget::onFunctionNameChanged() {
    QString text = functionNameInput->text().trimmed();
    searchButton->setEnabled (!text.isEmpty());

    if (text.isEmpty()) {
        statusLabel->setText ("Enter function name");
        statusLabel->setStyleSheet ("color: gray;");
    } else {
        statusLabel->setText ("Ready to search");
        statusLabel->setStyleSheet ("color: green;");
    }
}

void InteractiveDiffWidget::onSimilarityChanged (int value) {
    similarityLabel->setText (QString ("%1%").arg (value));

    // If we have search results, re-filter them
    if (!similarFunctions.isEmpty()) {
        updateFunctionList();
    }
}

void InteractiveDiffWidget::onSearchRequested() {
    QString functionName = functionNameInput->text().trimmed();
    if (functionName.isEmpty()) {
        QMessageBox::warning (this, "Error", "Please enter a function name");
        return;
    }

    currentSourceFunction = functionName;
    searchSimilarFunctions();
}

void InteractiveDiffWidget::onFunctionListItemClicked (QTreeWidgetItem *item, int column) {
    Q_UNUSED (column);

    if (!item)
        return;

    // Find the corresponding similar function
    QString displayedFunctionName = item->text (0);
    QString binaryName   = item->text (1);
    int     index        = -1;

    // Extract the actual function name (remove decompilation indicators)
    QString functionName = displayedFunctionName;
    if (functionName.endsWith(" ✓")) {
        functionName = functionName.left(functionName.length() - 2);
    }

    for (int i = 0; i < similarFunctions.size(); ++i) {
        if (similarFunctions[i].name == functionName && similarFunctions[i].binaryName == binaryName) {
            index = i;
            break;
        }
    }

    if (index >= 0 && index != currentSelectedIndex) {
        currentSelectedIndex = index;
        renameButton->setEnabled (true); // Enable rename button when function is selected
        
        if (isDecompilationMode) {
            // In decompilation mode, check if decompilation is available
            SimilarFunctionData &targetFunc = similarFunctions[currentSelectedIndex];
            if (!sourceHasDecompilation || !targetFunc.hasDecompilation) {
                updateStatusLabel(QString("Fetching decompilation for %1...").arg(targetFunc.name));
                clearPanels();
                
                // Cancel any existing decompilation work and start fresh for this function
                cancelAsyncDecompilation();
                startAsyncDecompilationForCurrent();
                return;
            }
        } else {
            // In assembly mode, check if disassembly is available
            SimilarFunctionData &targetFunc = similarFunctions[currentSelectedIndex];
            if (sourceDisassembly.length == 0 || targetFunc.disassembly.length == 0) {
                updateStatusLabel(QString("Fetching disassembly for %1...").arg(targetFunc.name));
                clearPanels();
                
                // Cancel any existing disassembly work and start fresh for this function
                cancelAsyncDisassembly();
                startAsyncDisassemblyForCurrent();
                return;
            }
        }
        
        updateDiffPanels();
    }
}

void InteractiveDiffWidget::searchSimilarFunctions() {
    rzClearMsg();
    
    if (!rzCanWorkWithAnalysis (GetBinaryId(), true)) {
        showErrorState ("No RevEngAI analysis available");
        return;
    }

    // Check if we already have a search running
    if (searchWorker && workerThread && workerThread->isRunning()) {
        cancelAsyncSearch();
    }

    // Start async search
    startAsyncSearch();
}

void InteractiveDiffWidget::updateFunctionList() {
    // Remember current selection
    QString selectedFunctionName;
    QString selectedBinaryName;
    if (currentSelectedIndex >= 0 && currentSelectedIndex < similarFunctions.size()) {
        selectedFunctionName = similarFunctions[currentSelectedIndex].name;
        selectedBinaryName = similarFunctions[currentSelectedIndex].binaryName;
    }
    
    functionListPanel->clear();

    int minSimilarity = similaritySlider->value();

    for (const auto &func : similarFunctions) {
        if (func.similarity >= minSimilarity) {
            QTreeWidgetItem *item = new QTreeWidgetItem();
            
            // Add decompilation indicator if in decompilation mode
            QString functionName = func.name;
            if (isDecompilationMode && func.hasDecompilation) {
                functionName += " ✓";  // Checkmark for available decompilation
            }
            
            item->setText (0, functionName);
            item->setText (1, func.binaryName);
            item->setText (2, QString ("%1%").arg (func.similarity, 0, 'f', 1));

            // Color code by similarity
            QColor color;
            if (func.similarity >= 95)
                color = QColor (0, 128, 0);     // Dark green
            else if (func.similarity >= 85)
                color = QColor (255, 165, 0);   // Orange
            else
                color = QColor (128, 128, 128); // Gray

            item->setForeground (2, color);
            
            // Dim functions without decompilation in decompilation mode
            if (isDecompilationMode && !func.hasDecompilation) {
                item->setForeground(0, QColor(128, 128, 128));
                item->setForeground(1, QColor(128, 128, 128));
            }
            
            functionListPanel->addTopLevelItem (item);
            
            // Restore selection if this was the previously selected item
            if (!selectedFunctionName.isEmpty() && 
                func.name == selectedFunctionName && 
                func.binaryName == selectedBinaryName) {
                functionListPanel->setCurrentItem(item);
            }
        }
    }

    functionListPanel->sortByColumn (2, Qt::DescendingOrder);
}

void InteractiveDiffWidget::updateDiffPanels() {
    if (currentSelectedIndex < 0 || currentSelectedIndex >= similarFunctions.size()) {
        return;
    }

    SimilarFunctionData &targetFunc = similarFunctions[currentSelectedIndex];

    showLoadingState ("Generating diff...");

    // Generate diff between source and target based on mode
    VecDeinit (&currentDiffLines);

    if (isDecompilationMode) {
        // Check if decompilation is available for both functions
        if (!sourceHasDecompilation || !targetFunc.hasDecompilation) {
            updateStatusLabel(QString("Decompilation not yet available for %1 - fetching in background...").arg(targetFunc.name));
            clearPanels();
            return;
        }
        // Use decompilation content
        currentDiffLines = GetDiff (&sourceDecompilation, &targetFunc.decompilation);
    } else {
        // Check if disassembly is available for both functions
        if (sourceDisassembly.length == 0 || targetFunc.disassembly.length == 0) {
            updateStatusLabel(QString("Disassembly not yet available for %1 - fetching...").arg(targetFunc.name));
            clearPanels();
            return;
        }
        // Use assembly content (original behavior)
        currentDiffLines = GetDiff (&sourceDisassembly, &targetFunc.disassembly);
    }

    if (currentDiffLines.length == 0) {
        showErrorState ("Failed to generate diff");
        return;
    }

    // Render diff in both panels
    renderSourceDiff (currentDiffLines);
    renderTargetDiff (currentDiffLines);

    QString mode = isDecompilationMode ? "decompilation" : "assembly";
    updateStatusLabel (QString ("Showing %1 diff with %2 (%3%)")
                           .arg (mode)
                           .arg (targetFunc.name)
                           .arg (targetFunc.similarity, 0, 'f', 1));
}

void InteractiveDiffWidget::renderSourceDiff (const DiffLines &diff) {
    sourceDiffPanel->clear();
    QTextCursor cursor (sourceDiffPanel->document());

    VecForeachPtr (&diff, line, {
        QString text;
        QString color = getColorForDiffType (line->type, true);

        switch (line->type) {
            case DIFF_TYPE_SAM :
                text = QString::fromUtf8 (line->sam.content.data);
                break;
            case DIFF_TYPE_REM :
                text = QString::fromUtf8 (line->rem.content.data);
                break;
            case DIFF_TYPE_MOD :
                text = QString::fromUtf8 (line->mod.old_content.data);
                break;
            case DIFF_TYPE_MOV :
                text = QString::fromUtf8 (line->mov.old_content.data);
                break;
            case DIFF_TYPE_ADD :
                text = ""; // Empty line for additions
                break;
            default :
                continue;
        }

        if (!color.isEmpty()) {
            cursor.insertHtml (
                QString ("<span style='color: %1'>%2</span><br>").arg (color).arg (text.toHtmlEscaped())
            );
        } else {
            cursor.insertText (text + "\n");
        }
    });

    sourceDiffPanel->setTextCursor (cursor);
}

void InteractiveDiffWidget::renderTargetDiff (const DiffLines &diff) {
    targetDiffPanel->clear();
    QTextCursor cursor (targetDiffPanel->document());

    VecForeachPtr (&diff, line, {
        QString text;
        QString color = getColorForDiffType (line->type, false);

        switch (line->type) {
            case DIFF_TYPE_SAM :
                text = QString::fromUtf8 (line->sam.content.data);
                break;
            case DIFF_TYPE_ADD :
                text = QString::fromUtf8 (line->add.content.data);
                break;
            case DIFF_TYPE_MOD :
                text = QString::fromUtf8 (line->mod.new_content.data);
                break;
            case DIFF_TYPE_MOV :
                text = QString::fromUtf8 (line->mov.new_content.data);
                break;
            case DIFF_TYPE_REM :
                text = ""; // Empty line for removals
                break;
            default :
                continue;
        }

        if (!color.isEmpty()) {
            cursor.insertHtml (
                QString ("<span style='color: %1'>%2</span><br>").arg (color).arg (text.toHtmlEscaped())
            );
        } else {
            cursor.insertText (text + "\n");
        }
    });

    targetDiffPanel->setTextCursor (cursor);
}

QString InteractiveDiffWidget::getColorForDiffType (DiffType type, bool isSource) {
    switch (type) {
        case DIFF_TYPE_SAM :
            return ""; // Default color
        case DIFF_TYPE_ADD :
            return isSource ? "" : "green";
        case DIFF_TYPE_REM :
            return isSource ? "red" : "";
        case DIFF_TYPE_MOD :
            return isSource ? "orange" : "blue";
        case DIFF_TYPE_MOV :
            return isSource ? "purple" : "purple";
        default :
            return "";
    }
}

void InteractiveDiffWidget::showLoadingState (const QString &message) {
    updateStatusLabel (message);
    statusLabel->setStyleSheet ("color: blue; font-style: italic;");
    QApplication::processEvents();
}

void InteractiveDiffWidget::showErrorState (const QString &error) {
    updateStatusLabel (error);
    statusLabel->setStyleSheet ("color: red; font-weight: bold;");
    clearPanels();
}

void InteractiveDiffWidget::clearPanels() {
    sourceDiffPanel->clear();
    targetDiffPanel->clear();
}

void InteractiveDiffWidget::updateStatusLabel (const QString &status) {
    statusLabel->setText (status);
}

Str InteractiveDiffWidget::getFunctionDisassembly (FunctionId functionId) {
    // Get the control flow graph for this function (reusing CmdHandlers.c logic)
    ControlFlowGraph cfg           = GetFunctionControlFlowGraph (GetConnection(), functionId);
    Str              linear_disasm = StrInit();

    if (cfg.blocks.length == 0) {
        LOG_ERROR ("No blocks found in control flow graph for function ID %llu", functionId);
        ControlFlowGraphDeinit (&cfg);
        return linear_disasm;
    }

    // Convert CFG blocks to linear disassembly (same as CmdHandlers.c)
    VecForeachPtr (&cfg.blocks, block, {
        // Add block header comment if it exists
        if (block->comment.length > 0) {
            StrAppendf (
                &linear_disasm,
                "; Block %llu (0x%llx-0x%llx): %s\n",
                block->id,
                block->min_addr,
                block->max_addr,
                block->comment.data
            );
        } else {
            StrAppendf (&linear_disasm, "; Block %llu (0x%llx-0x%llx)\n", block->id, block->min_addr, block->max_addr);
        }

        // Add all assembly lines from this block
        VecForeachPtr (&block->asm_lines, asm_line, { StrAppendf (&linear_disasm, "%s\n", asm_line->data); });

        // Add destination info if available
        if (block->destinations.length > 0) {
            StrAppendf (&linear_disasm, "; Destinations: ");
            VecForeachIdx (&block->destinations, dest, idx, {
                if (idx > 0) {
                    StrAppendf (&linear_disasm, ", ");
                }
                StrAppendf (&linear_disasm, "Block_%llu(%s)", dest.destination_block_id, dest.flowtype.data);
            });
            StrAppendf (&linear_disasm, "\n");
        }

        // Add separator between blocks
        StrAppendf (&linear_disasm, "\n");
    });

    // Add overview comment if available
    if (cfg.overview_comment.length > 0) {
        Str header = StrInit();
        StrPrintf (&header, "; Function Overview: %s\n\n%s", cfg.overview_comment.data, linear_disasm.data);
        StrDeinit (&linear_disasm);
        linear_disasm = header;
    }

    // Clean up CFG
    ControlFlowGraphDeinit (&cfg);

    // Replace all tab characters with four spaces
    StrReplaceZstr (&linear_disasm, "\t", "    ", -1);

    return linear_disasm;
}

Str InteractiveDiffWidget::getFunctionDecompilation (FunctionId functionId) {
    Str final_code = StrInit();

    // Check decompilation status
    Status status = GetAiDecompilationStatus (GetConnection(), functionId);

    if ((status & STATUS_MASK) == STATUS_ERROR || (status & STATUS_MASK) == STATUS_UNINITIALIZED) {
        // Try to begin decompilation
        if (!BeginAiDecompilation (GetConnection(), functionId)) {
            return final_code; // Return empty on failure
        }
        // Return empty for now - will be fetched in background
        return final_code;
    }

    if ((status & STATUS_MASK) == STATUS_PENDING) {
        // Still pending - return empty for now
        return final_code;
    }

    if ((status & STATUS_MASK) == STATUS_SUCCESS) {
        // Get the decompilation - skip summary for diff purposes
        AiDecompilation aidec = GetAiDecompilation (GetConnection(), functionId, true);
        final_code            = StrDup (&aidec.decompilation);
        AiDecompilationDeinit (&aidec);
    }

    return final_code;
}

void InteractiveDiffWidget::onToggleRequested() {
    isDecompilationMode = toggleButton->isChecked();

    if (isDecompilationMode) {
        toggleButton->setText ("Show Assembly");
        
        // Cancel any existing decompilation operations
        cancelAsyncDecompilation();
        
        // Start async decompilation
        startAsyncDecompilation();
    } else {
        toggleButton->setText ("Show Decompilation");
        
        // Update diff panels with current mode (assembly)
        if (currentSelectedIndex >= 0) {
            updateDiffPanels();
        }
    }
}

// Note: fetchDecompilationForCurrentSelection and fetchDecompilationForFunction 
// have been replaced with async versions startAsyncDecompilation() and the 
// DecompilationWorker class to prevent UI freezing

void InteractiveDiffWidget::onRenameRequested() {
    if (currentSelectedIndex < 0 || currentSelectedIndex >= similarFunctions.size()) {
        QMessageBox::warning (this, "Error", "No function selected for renaming");
        return;
    }

    const SimilarFunctionData &targetFunc = similarFunctions[currentSelectedIndex];

    // Confirm rename operation
    int ret = QMessageBox::question (
        this,
        "Confirm Rename",
        QString ("Rename function '%1' to '%2'?").arg (currentSourceFunction).arg (targetFunc.name),
        QMessageBox::Yes | QMessageBox::No,
        QMessageBox::No
    );

    if (ret != QMessageBox::Yes) {
        return;
    }

    // Perform the rename using Rizin
    RzCoreLocked core (Core());

    // Find the function in Rizin's analysis
    RzAnalysisFunction *func =
        rz_analysis_get_function_byname (core->analysis, currentSourceFunction.toUtf8().constData());
    if (!func) {
        QMessageBox::critical (this, "Error", "Function not found in analysis");
        return;
    }

    // Rename the function
    bool success = rz_analysis_function_rename (func, targetFunc.name.toUtf8().constData());

    if (success) {
        QMessageBox::information (
            this,
            "Success",
            QString ("Function renamed from '%1' to '%2'").arg (currentSourceFunction).arg (targetFunc.name)
        );

        // Update the function name input and reload function names
        functionNameInput->setText (targetFunc.name);
        currentSourceFunction = targetFunc.name;
        loadFunctionNames();

        // Refresh UI
        updateStatusLabel ("Function renamed successfully");
        statusLabel->setStyleSheet ("color: green;");

        // Trigger a refresh in Cutter
        Core()->triggerRefreshAll();

    } else {
        QMessageBox::critical (this, "Error", "Failed to rename function");
    }
}

void InteractiveDiffWidget::showDiffForFunction (const QString &functionName, int similarity) {
    functionNameInput->setText (functionName);
    similaritySlider->setValue (similarity);
    onSearchRequested();
}

void InteractiveDiffWidget::startAsyncSearch() {
    // Clear previous results
    similarFunctions.clear();
    functionListPanel->clear();
    clearPanels();
    renameButton->setEnabled (false);

    // Reset decompilation state
    sourceHasDecompilation = false;
    StrDeinit (&sourceDecompilation);
    sourceDecompilation = StrInit();

    // Show progress
    showProgress(0, "Preparing search...");

    // Get function ID for the search
    FunctionId functionId = 0;
    {
        RzCoreLocked core (Core());
        QByteArray fnNameByteArr = currentSourceFunction.toLatin1();
        functionId = rzLookupFunctionIdForFunctionWithName (core, fnNameByteArr.constData());
        
        if (!functionId) {
            hideProgress();
            showErrorState("Failed to get function ID for selected function");
            return;
        }
    }

    // Create worker and thread (don't parent the thread to this widget)
    workerThread = new QThread();
    searchWorker = new SimilarFunctionsWorker();
    searchWorker->moveToThread(workerThread);

    // Connect signals with Qt::QueuedConnection for thread safety
    connect(workerThread, &QThread::started, [this, functionId]() {
        if (searchWorker) {
            SimilarFunctionsWorker::SearchRequest request;
            request.functionName = currentSourceFunction;
            request.functionId = functionId;
            request.similarityThreshold = similaritySlider->value();
            request.maxResults = 20;
            
            searchWorker->performSearch(request);
        }
    });
    
    connect(searchWorker, &SimilarFunctionsWorker::searchFinished, this, &InteractiveDiffWidget::onSearchFinished);
    connect(searchWorker, &SimilarFunctionsWorker::searchError, this, &InteractiveDiffWidget::onSearchError);
    connect(searchWorker, &SimilarFunctionsWorker::progressUpdate, this, &InteractiveDiffWidget::onProgressUpdate);
    
    // Clean up worker when thread finishes
    connect(workerThread, &QThread::finished, searchWorker, &QObject::deleteLater);
    connect(workerThread, &QThread::finished, workerThread, &QObject::deleteLater);
    
    // Reset pointers when thread finishes to avoid dangling pointers
    connect(workerThread, &QThread::finished, [this]() {
        searchWorker = nullptr;
        workerThread = nullptr;
    });

    // Start the thread
    workerThread->start();
}

void InteractiveDiffWidget::cancelAsyncSearch() {
    if (searchWorker) {
        searchWorker->cancelSearch();
    }
    
    if (workerThread && workerThread->isRunning()) {
        // First try to quit gracefully
        workerThread->quit();
        
        // Wait for the thread to finish, but don't wait forever
        if (!workerThread->wait(3000)) { // Wait up to 3 seconds
            // If it doesn't finish gracefully, force terminate
            qWarning() << "Worker thread didn't quit gracefully, terminating...";
            workerThread->terminate();
            workerThread->wait(1000); // Give it another second to clean up
        }
    }
    
    // Reset pointers after termination
    searchWorker = nullptr;
    workerThread = nullptr;
    
    hideProgress();
    updateStatusLabel("Search cancelled");
}

void InteractiveDiffWidget::showProgress(int percentage, const QString &status) {
    progressBar->setVisible(true);
    progressBar->setValue(percentage);
    cancelButton->setVisible(true);
    searchButton->setEnabled(false);
    updateStatusLabel(status);
}

void InteractiveDiffWidget::hideProgress() {
    progressBar->setVisible(false);
    cancelButton->setVisible(false);
    searchButton->setEnabled(true);
}

void InteractiveDiffWidget::onSearchFinished(const SearchResult &result) {
    hideProgress();
    
    if (!result.success) {
        showErrorState("Search failed");
        return;
    }
    
    // Update the widget with search results
    similarFunctions = result.similarFunctions;
    
    if (similarFunctions.isEmpty()) {
        showErrorState("No similar functions found");
        return;
    }
    
    updateFunctionList();
    updateStatusLabel(QString("Found %1 similar functions").arg(similarFunctions.size()));
    
    // Auto-select first item and start fetching disassembly for it
    if (functionListPanel->topLevelItemCount() > 0) {
        functionListPanel->setCurrentItem(functionListPanel->topLevelItem(0));
        currentSelectedIndex = 0;
        renameButton->setEnabled(true);
        
        // Start async disassembly for the first selected function
        startAsyncDisassemblyForCurrent();
    }
    
    // Note: worker references will be cleaned up by the QThread::finished lambda
}

void InteractiveDiffWidget::onSearchError(const QString &error) {
    hideProgress();
    showErrorState(error);
    
    // Note: worker references will be cleaned up by the QThread::finished lambda
}

void InteractiveDiffWidget::onProgressUpdate(int percentage, const QString &status) {
    showProgress(percentage, status);
}

// SimilarFunctionsWorker implementation
SimilarFunctionsWorker::SimilarFunctionsWorker(QObject *parent) 
    : QObject(parent), m_cancelled(false) {
}

void SimilarFunctionsWorker::performSearch(const SimilarFunctionsWorker::SearchRequest &request) {
    m_cancelled = false;
    SearchResult result;
    result.success = false;
    result.sourceFunctionName = request.functionName;
    
    try {
        emitProgress(20, "Setting up search request...");
        
        if (m_cancelled) {
            emit searchError("Search cancelled");
            return;
        }
        
        SimilarFunctionsRequest search = SimilarFunctionsRequestInit();
        search.function_id = request.functionId;
        search.distance = 1.0f - (request.similarityThreshold / 100.0f);
        search.limit = request.maxResults;
        search.debug_include.external_symbols = false;
        search.debug_include.system_symbols = false;
        search.debug_include.user_symbols = false;
        
        emitProgress(50, "Searching for similar functions...");
        
        if (m_cancelled) {
            SimilarFunctionsRequestDeinit(&search);
            emit searchError("Search cancelled");
            return;
        }
        
        // Make the actual API call
        SimilarFunctions similar_functions = GetSimilarFunctions(GetConnection(), &search);
        SimilarFunctionsRequestDeinit(&search);
        
        if (similar_functions.length == 0) {
            VecDeinit(&similar_functions);
            emit searchError("No similar functions found");
            return;
        }
        
        emitProgress(80, "Processing results...");
        
        // Convert results to our format (without disassembly - that will be fetched on-demand)
        VecForeachPtr(&similar_functions, similar_function, {
            if (m_cancelled) {
                VecDeinit(&similar_functions);
                emit searchError("Search cancelled");
                return;
            }
            
            SimilarFunctionData data;
            data.name = QString::fromUtf8(similar_function->name.data);
            data.binaryName = QString::fromUtf8(similar_function->binary_name.data);
            data.functionId = similar_function->id;
            data.binaryId = similar_function->binary_id;
            data.similarity = (1.0f - similar_function->distance) * 100.0f;
            
            // Note: disassembly and decompilation will be fetched on-demand
            // data.disassembly and data.decompilation remain empty (StrInit())
            
            result.similarFunctions.append(data);
        });
        
        VecDeinit(&similar_functions);
        
        emitProgress(100, "Search completed");
        result.success = true;
        emit searchFinished(result);
        
    } catch (...) {
        emit searchError("Unexpected error during search");
    }
}

void SimilarFunctionsWorker::cancelSearch() {
    m_cancelled = true;
}

void SimilarFunctionsWorker::emitProgress(int percentage, const QString &status) {
    emit progressUpdate(percentage, status);
}

// Async decompilation methods for InteractiveDiffWidget
void InteractiveDiffWidget::startAsyncDecompilation() {
    // This method is called when "Show Decompilation" is first clicked
    // It starts decompilation for the current function only
    startAsyncDecompilationForCurrent();
}

void InteractiveDiffWidget::startAsyncDecompilationForCurrent() {
    if (currentSelectedIndex < 0 || currentSelectedIndex >= similarFunctions.size()) {
        showErrorState("No function selected for decompilation");
        return;
    }

    // Show progress
    showProgress(0, "Starting decompilation...");

    // Create worker and thread for decompilation
    decompilationThread = new QThread();
    decompilationWorker = new DecompilationWorker();
    decompilationWorker->moveToThread(decompilationThread);

    // Connect signals
    connect(decompilationThread, &QThread::started, [this]() {
        if (decompilationWorker) {
            // First request source decompilation if needed
            if (!sourceHasDecompilation) {
                RzCoreLocked core(Core());
                QByteArray fnNameByteArr = currentSourceFunction.toLatin1();
                FunctionId sourceId = rzLookupFunctionIdForFunctionWithName(core, fnNameByteArr.constData());
                
                if (sourceId) {
                    DecompilationWorker::DecompilationRequest request;
                    request.functionId = sourceId;
                    request.isSourceFunction = true;
                    request.targetIndex = -1;
                    request.functionName = currentSourceFunction;
                    
                    decompilationWorker->performDecompilation(request);
                    return;
                }
            }
            
            // Otherwise start with target decompilation
            SimilarFunctionData &targetFunc = similarFunctions[currentSelectedIndex];
            if (!targetFunc.hasDecompilation) {
                DecompilationWorker::DecompilationRequest request;
                request.functionId = targetFunc.functionId;
                request.isSourceFunction = false;
                request.targetIndex = currentSelectedIndex;
                request.functionName = targetFunc.name;
                
                decompilationWorker->performDecompilation(request);
            }
        }
    });
    
    connect(decompilationWorker, &DecompilationWorker::decompilationFinished, this, &InteractiveDiffWidget::onDecompilationFinished);
    connect(decompilationWorker, &DecompilationWorker::decompilationError, this, &InteractiveDiffWidget::onDecompilationError);
    connect(decompilationWorker, &DecompilationWorker::progressUpdate, this, &InteractiveDiffWidget::onProgressUpdate);
    
    connect(decompilationThread, &QThread::finished, [this]() {
        if (decompilationWorker) {
            decompilationWorker->deleteLater();
            decompilationWorker = nullptr;
        }
        if (decompilationThread) {
            decompilationThread->deleteLater();
            decompilationThread = nullptr;
        }
    });

    decompilationThread->start();
}

void InteractiveDiffWidget::cancelAsyncDecompilation() {
    if (decompilationWorker && decompilationThread && decompilationThread->isRunning()) {
        decompilationWorker->cancelDecompilation();
        
        decompilationThread->quit();
        if (!decompilationThread->wait(3000)) {
            decompilationThread->terminate();
            decompilationThread->wait(1000);
        }
    }
}

void InteractiveDiffWidget::onDecompilationFinished(const DecompilationResult &result) {
    if (!result.success) {
        onDecompilationError(result.errorMessage);
        return;
    }
    
    if (result.isSourceFunction) {
        // Update source decompilation
        StrDeinit(&sourceDecompilation);
        sourceDecompilation = StrDup(&result.decompilation);
        sourceHasDecompilation = true;
        
        // Now fetch target decompilation if needed
        if (currentSelectedIndex >= 0 && currentSelectedIndex < similarFunctions.size()) {
            SimilarFunctionData &targetFunc = similarFunctions[currentSelectedIndex];
            if (!targetFunc.hasDecompilation) {
                DecompilationWorker::DecompilationRequest request;
                request.functionId = targetFunc.functionId;
                request.isSourceFunction = false;
                request.targetIndex = currentSelectedIndex;
                request.functionName = targetFunc.name;
                
                if (decompilationWorker) {
                    decompilationWorker->performDecompilation(request);
                    return;
                }
            } else {
                // Both source and target are ready - show diff
                hideProgress();
                updateDiffPanels();
            }
        }
    } else {
        // Update target decompilation
        if (result.targetIndex >= 0 && result.targetIndex < similarFunctions.size()) {
            SimilarFunctionData &targetFunc = similarFunctions[result.targetIndex];
            StrDeinit(&targetFunc.decompilation);
            targetFunc.decompilation = StrDup(&result.decompilation);
            targetFunc.hasDecompilation = true;
            
            // Update function list to show decompilation status
            if (isDecompilationMode) {
                updateFunctionList();
            }
            
            // Update diff panels if this is the currently selected function
            if (result.targetIndex == currentSelectedIndex) {
                // Current function is ready - show diff
                if (sourceHasDecompilation) {
                    hideProgress();
                    updateDiffPanels();
                } else {
                    hideProgress();
                    updateStatusLabel("Decompilation completed - ready for diff");
                }
            }
        }
    }
}

void InteractiveDiffWidget::onDecompilationError(const QString &error) {
    hideProgress();
    showErrorState("Decompilation failed: " + error);
}

// Note: continueBackgroundDecompilation() method removed - we now fetch decompilation 
// on-demand only for the currently selected function to avoid UI blocking

// Async disassembly methods for InteractiveDiffWidget
void InteractiveDiffWidget::startAsyncDisassembly() {
    // This method is called when assembly mode is active
    startAsyncDisassemblyForCurrent();
}

void InteractiveDiffWidget::startAsyncDisassemblyForCurrent() {
    if (currentSelectedIndex < 0 || currentSelectedIndex >= similarFunctions.size()) {
        showErrorState("No function selected for disassembly");
        return;
    }

    // Show progress
    showProgress(0, "Starting disassembly...");

    // Create worker and thread for disassembly
    disassemblyThread = new QThread();
    disassemblyWorker = new DisassemblyWorker();
    disassemblyWorker->moveToThread(disassemblyThread);

    // Connect signals
    connect(disassemblyThread, &QThread::started, [this]() {
        if (disassemblyWorker) {
            // First request source disassembly if not already done
            if (sourceDisassembly.length == 0) {
                RzCoreLocked core(Core());
                QByteArray fnNameByteArr = currentSourceFunction.toLatin1();
                FunctionId sourceId = rzLookupFunctionIdForFunctionWithName(core, fnNameByteArr.constData());
                
                if (sourceId) {
                    DisassemblyWorker::DisassemblyRequest request;
                    request.functionId = sourceId;
                    request.isSourceFunction = true;
                    request.targetIndex = -1;
                    request.functionName = currentSourceFunction;
                    
                    disassemblyWorker->performDisassembly(request);
                    return;
                }
            }
            
            // Otherwise start with target disassembly
            SimilarFunctionData &targetFunc = similarFunctions[currentSelectedIndex];
            if (targetFunc.disassembly.length == 0) {
                DisassemblyWorker::DisassemblyRequest request;
                request.functionId = targetFunc.functionId;
                request.isSourceFunction = false;
                request.targetIndex = currentSelectedIndex;
                request.functionName = targetFunc.name;
                
                disassemblyWorker->performDisassembly(request);
            }
        }
    });
    
    connect(disassemblyWorker, &DisassemblyWorker::disassemblyFinished, this, &InteractiveDiffWidget::onDisassemblyFinished);
    connect(disassemblyWorker, &DisassemblyWorker::disassemblyError, this, &InteractiveDiffWidget::onDisassemblyError);
    connect(disassemblyWorker, &DisassemblyWorker::progressUpdate, this, &InteractiveDiffWidget::onProgressUpdate);
    
    connect(disassemblyThread, &QThread::finished, [this]() {
        if (disassemblyWorker) {
            disassemblyWorker->deleteLater();
            disassemblyWorker = nullptr;
        }
        if (disassemblyThread) {
            disassemblyThread->deleteLater();
            disassemblyThread = nullptr;
        }
    });

    disassemblyThread->start();
}

void InteractiveDiffWidget::cancelAsyncDisassembly() {
    if (disassemblyWorker && disassemblyThread && disassemblyThread->isRunning()) {
        disassemblyWorker->cancelDisassembly();
        
        disassemblyThread->quit();
        if (!disassemblyThread->wait(3000)) {
            disassemblyThread->terminate();
            disassemblyThread->wait(1000);
        }
    }
}

void InteractiveDiffWidget::onDisassemblyFinished(const DisassemblyResult &result) {
    if (!result.success) {
        onDisassemblyError(result.errorMessage);
        return;
    }
    
    if (result.isSourceFunction) {
        // Update source disassembly
        StrDeinit(&sourceDisassembly);
        sourceDisassembly = StrDup(&result.disassembly);
        
        // Now fetch target disassembly if needed
        if (currentSelectedIndex >= 0 && currentSelectedIndex < similarFunctions.size()) {
            SimilarFunctionData &targetFunc = similarFunctions[currentSelectedIndex];
            if (targetFunc.disassembly.length == 0) {
                DisassemblyWorker::DisassemblyRequest request;
                request.functionId = targetFunc.functionId;
                request.isSourceFunction = false;
                request.targetIndex = currentSelectedIndex;
                request.functionName = targetFunc.name;
                
                if (disassemblyWorker) {
                    disassemblyWorker->performDisassembly(request);
                    return;
                }
            } else {
                // Both source and target are ready - show diff
                hideProgress();
                updateDiffPanels();
            }
        }
    } else {
        // Update target disassembly
        if (result.targetIndex >= 0 && result.targetIndex < similarFunctions.size()) {
            SimilarFunctionData &targetFunc = similarFunctions[result.targetIndex];
            StrDeinit(&targetFunc.disassembly);
            targetFunc.disassembly = StrDup(&result.disassembly);
            
            // Update diff panels if this is the currently selected function
            if (result.targetIndex == currentSelectedIndex) {
                // Current function is ready - show diff
                if (sourceDisassembly.length > 0) {
                    hideProgress();
                    updateDiffPanels();
                } else {
                    hideProgress();
                    updateStatusLabel("Disassembly completed - ready for diff");
                }
            }
        }
    }
}

void InteractiveDiffWidget::onDisassemblyError(const QString &error) {
    hideProgress();
    showErrorState("Disassembly failed: " + error);
}

// DecompilationWorker implementation
DecompilationWorker::DecompilationWorker(QObject *parent) 
    : QObject(parent), m_cancelled(false) {
}

void DecompilationWorker::performDecompilation(const DecompilationRequest &request) {
    m_cancelled = false;
    
    DecompilationResult result;
    result.functionId = request.functionId;
    result.isSourceFunction = request.isSourceFunction;
    result.targetIndex = request.targetIndex;
    
    try {
        emitProgress(10, QString("Checking decompilation status for %1...").arg(request.functionName));
        
        if (m_cancelled) {
            emit decompilationError("Decompilation cancelled");
            return;
        }
        
        // Check decompilation status
        Status status = GetAiDecompilationStatus(GetConnection(), request.functionId);
        
        if ((status & STATUS_MASK) == STATUS_ERROR || (status & STATUS_MASK) == STATUS_UNINITIALIZED) {
            emitProgress(30, QString("Starting decompilation for %1...").arg(request.functionName));
            
            if (m_cancelled) {
                emit decompilationError("Decompilation cancelled");
                return;
            }
            
            // Try to begin decompilation
            if (!BeginAiDecompilation(GetConnection(), request.functionId)) {
                result.errorMessage = QString("Failed to start decompilation for %1").arg(request.functionName);
                emit decompilationError(result.errorMessage);
                return;
            }
            
            // Wait for decompilation to complete with periodic status checks
            emitProgress(50, QString("Waiting for decompilation of %1...").arg(request.functionName));
            
            int attempts = 0;
            const int maxAttempts = 30; // 30 seconds timeout
            
            while (attempts < maxAttempts) {
                if (m_cancelled) {
                    emit decompilationError("Decompilation cancelled");
                    return;
                }
                
                QThread::msleep(1000); // Wait 1 second
                status = GetAiDecompilationStatus(GetConnection(), request.functionId);
                
                if ((status & STATUS_MASK) == STATUS_SUCCESS) {
                    break;
                } else if ((status & STATUS_MASK) == STATUS_ERROR) {
                    result.errorMessage = QString("Decompilation failed for %1").arg(request.functionName);
                    emit decompilationError(result.errorMessage);
                    return;
                }
                
                attempts++;
                int progress = 50 + (attempts * 40 / maxAttempts);
                emitProgress(progress, QString("Decompiling %1... (%2s)").arg(request.functionName).arg(attempts));
            }
            
            if (attempts >= maxAttempts) {
                result.errorMessage = QString("Decompilation timeout for %1").arg(request.functionName);
                emit decompilationError(result.errorMessage);
                return;
            }
        }
        
        if ((status & STATUS_MASK) == STATUS_PENDING) {
            // Still pending - wait a bit more
            emitProgress(70, QString("Decompilation pending for %1...").arg(request.functionName));
            
            int attempts = 0;
            const int maxAttempts = 10; // 10 seconds additional wait
            
            while (attempts < maxAttempts && (status & STATUS_MASK) == STATUS_PENDING) {
                if (m_cancelled) {
                    emit decompilationError("Decompilation cancelled");
                    return;
                }
                
                QThread::msleep(1000);
                status = GetAiDecompilationStatus(GetConnection(), request.functionId);
                attempts++;
            }
        }
        
        if ((status & STATUS_MASK) == STATUS_SUCCESS) {
            emitProgress(90, QString("Fetching decompilation for %1...").arg(request.functionName));
            
            if (m_cancelled) {
                emit decompilationError("Decompilation cancelled");
                return;
            }
            
            // Get the decompilation
            AiDecompilation aidec = GetAiDecompilation(GetConnection(), request.functionId, true);
            result.decompilation = StrDup(&aidec.decompilation);
            AiDecompilationDeinit(&aidec);
            
            result.success = true;
            emitProgress(100, QString("Decompilation completed for %1").arg(request.functionName));
            emit decompilationFinished(result);
        } else {
            result.errorMessage = QString("Decompilation not available for %1").arg(request.functionName);
            emit decompilationError(result.errorMessage);
        }
        
    } catch (const std::exception &e) {
        result.errorMessage = QString("Exception during decompilation: %1").arg(e.what());
        emit decompilationError(result.errorMessage);
    } catch (...) {
        result.errorMessage = "Unknown error during decompilation";
        emit decompilationError(result.errorMessage);
    }
}

void DecompilationWorker::cancelDecompilation() {
    m_cancelled = true;
}

void DecompilationWorker::emitProgress(int percentage, const QString &status) {
    if (!m_cancelled) {
        emit progressUpdate(percentage, status);
    }
}

// DisassemblyWorker implementation
DisassemblyWorker::DisassemblyWorker(QObject *parent) 
    : QObject(parent), m_cancelled(false) {
}

void DisassemblyWorker::performDisassembly(const DisassemblyRequest &request) {
    m_cancelled = false;
    
    DisassemblyResult result;
    result.functionId = request.functionId;
    result.isSourceFunction = request.isSourceFunction;
    result.targetIndex = request.targetIndex;
    
    try {
        emitProgress(20, QString("Fetching disassembly for %1...").arg(request.functionName));
        
        if (m_cancelled) {
            emit disassemblyError("Disassembly cancelled");
            return;
        }
        
        // Get the control flow graph for this function
        ControlFlowGraph cfg = GetFunctionControlFlowGraph(GetConnection(), request.functionId);
        
        if (cfg.blocks.length == 0) {
            ControlFlowGraphDeinit(&cfg);
            result.errorMessage = QString("No blocks found in control flow graph for %1").arg(request.functionName);
            emit disassemblyError(result.errorMessage);
            return;
        }
        
        emitProgress(60, QString("Processing disassembly for %1...").arg(request.functionName));
        
        if (m_cancelled) {
            ControlFlowGraphDeinit(&cfg);
            emit disassemblyError("Disassembly cancelled");
            return;
        }
        
        // Convert CFG blocks to linear disassembly
        Str linear_disasm = StrInit();
        VecForeachPtr(&cfg.blocks, block, {
            if (block->comment.length > 0) {
                StrAppendf(&linear_disasm, "; Block %llu (0x%llx-0x%llx): %s\n",
                          block->id, block->min_addr, block->max_addr, block->comment.data);
            } else {
                StrAppendf(&linear_disasm, "; Block %llu (0x%llx-0x%llx)\n", 
                          block->id, block->min_addr, block->max_addr);
            }
            
            VecForeachPtr(&block->asm_lines, asm_line, {
                StrAppendf(&linear_disasm, "%s\n", asm_line->data);
            });
            
            StrAppendf(&linear_disasm, "\n");
        });
        
        result.disassembly = linear_disasm;
        ControlFlowGraphDeinit(&cfg);
        
        result.success = true;
        emitProgress(100, QString("Disassembly completed for %1").arg(request.functionName));
        emit disassemblyFinished(result);
        
    } catch (const std::exception &e) {
        result.errorMessage = QString("Exception during disassembly: %1").arg(e.what());
        emit disassemblyError(result.errorMessage);
    } catch (...) {
        result.errorMessage = "Unknown error during disassembly";
        emit disassemblyError(result.errorMessage);
    }
}

void DisassemblyWorker::cancelDisassembly() {
    m_cancelled = true;
}

void DisassemblyWorker::emitProgress(int percentage, const QString &status) {
    if (!m_cancelled) {
        emit progressUpdate(percentage, status);
    }
}