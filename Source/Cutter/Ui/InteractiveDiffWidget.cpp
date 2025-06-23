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
    : CutterDockWidget (main), functionCompleter (nullptr), currentSelectedIndex (-1) {
    sourceDisassembly = StrInit();
    currentDiffLines  = VecInit();

    setWindowTitle ("Interactive Function Diff");
    setObjectName ("InteractiveFunctionDiff");

    setupUI();
    connectSignals();
    loadFunctionNames();

    // Initially disable search until function is selected
    searchButton->setEnabled (false);
}

InteractiveDiffWidget::~InteractiveDiffWidget() {
    StrDeinit (&sourceDisassembly);
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

    setWidget (mainWidget);
}

void InteractiveDiffWidget::setupThreePanelLayout() {
    // Create horizontal splitter for three panels
    mainSplitter = new QSplitter (Qt::Horizontal);

    // Left panel: Similar functions list
    functionListPanel = new QTreeWidget();
    functionListPanel->setHeaderLabels ({"Function Name", "Binary", "Similarity"});
    functionListPanel->header()->setSectionResizeMode (QHeaderView::ResizeToContents);
    functionListPanel->setMinimumWidth (200);
    functionListPanel->setSortingEnabled (true);
    functionListPanel->sortByColumn (2, Qt::DescendingOrder); // Sort by similarity desc

    // Middle panel: Source diff
    sourceDiffPanel = new QTextEdit();
    sourceDiffPanel->setReadOnly (true);
    sourceDiffPanel->setFont (QFont ("Consolas", 10));
    sourceDiffPanel->setPlaceholderText ("Source function disassembly will appear here...");
    sourceDiffPanel->setMinimumWidth (300);

    // Right panel: Target diff
    targetDiffPanel = new QTextEdit();
    targetDiffPanel->setReadOnly (true);
    targetDiffPanel->setFont (QFont ("Consolas", 10));
    targetDiffPanel->setPlaceholderText ("Target function disassembly will appear here...");
    targetDiffPanel->setMinimumWidth (300);

    // Add panels to splitter
    mainSplitter->addWidget (functionListPanel);
    mainSplitter->addWidget (sourceDiffPanel);
    mainSplitter->addWidget (targetDiffPanel);

    // Set proportional sizes (2:3:3 ratio like terminal version)
    mainSplitter->setSizes ({200, 300, 300});
    mainSplitter->setStretchFactor (0, 2);
    mainSplitter->setStretchFactor (1, 3);
    mainSplitter->setStretchFactor (2, 3);
}

void InteractiveDiffWidget::setupControlsArea() {
    controlsWidget              = new QWidget();
    QHBoxLayout *controlsLayout = new QHBoxLayout (controlsWidget);
    controlsLayout->setContentsMargins (0, 5, 0, 0);

    // Function name input with autocomplete
    QLabel *fnLabel   = new QLabel ("Function:");
    functionNameInput = new QLineEdit();
    functionNameInput->setPlaceholderText ("Start typing for suggestions...");
    functionNameInput->setMinimumWidth (200);

    // Similarity slider with label
    QLabel *simLabel = new QLabel ("Min Similarity:");
    similaritySlider = new QSlider (Qt::Horizontal);
    similaritySlider->setRange (50, 100);
    similaritySlider->setValue (90);
    similaritySlider->setMinimumWidth (150);

    similarityLabel = new QLabel ("90%");
    similarityLabel->setMinimumWidth (40);

    // Search button
    searchButton = new QPushButton ("Search");
    searchButton->setMinimumWidth (80);

    // Rename button
    renameButton = new QPushButton ("Rename to Selected");
    renameButton->setMinimumWidth (120);
    renameButton->setEnabled (false); // Initially disabled

    // Status label
    statusLabel = new QLabel ("Ready");
    statusLabel->setStyleSheet ("color: gray; font-style: italic;");

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
    controlsLayout->addStretch(); // Push status to right
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
    QString functionName = item->text (0);
    QString binaryName   = item->text (1);
    int     index        = -1;

    for (int i = 0; i < similarFunctions.size(); ++i) {
        if (similarFunctions[i].name == functionName && similarFunctions[i].binaryName == binaryName) {
            index = i;
            break;
        }
    }

    if (index >= 0 && index != currentSelectedIndex) {
        currentSelectedIndex = index;
        renameButton->setEnabled (true); // Enable rename button when function is selected
        updateDiffPanels();
    }
}

void InteractiveDiffWidget::searchSimilarFunctions() {
    rzClearMsg();
    RzCoreLocked core (Core());

    if (!rzCanWorkWithAnalysis (GetBinaryId(), true)) {
        showErrorState ("No RevEngAI analysis available");
        return;
    }

    showLoadingState ("Searching for similar functions...");

    // Clear previous results
    similarFunctions.clear();
    functionListPanel->clear();
    clearPanels();
    renameButton->setEnabled (false); // Disable rename button

    SimilarFunctionsRequest search = SimilarFunctionsRequestInit();

    /* check if function exists or not */
    QByteArray fnNameByteArr = currentSourceFunction.toLatin1();

    search.function_id = rzLookupFunctionIdForFunctionWithName (core, fnNameByteArr.constData());
    if (!search.function_id) {
        DISPLAY_ERROR (
            "Failed to get a function id for selected Rizin function. Cannot get similar functions for this one."
        );
        return;
    }

    // Get source function disassembly
    StrDeinit (&sourceDisassembly);
    sourceDisassembly = getFunctionDisassembly (search.function_id);
    if (sourceDisassembly.length == 0) {
        showErrorState ("Failed to get source function disassembly");
        SimilarFunctionsRequestDeinit (&search);
        return;
    }

    u32 requiredSimilarity = similaritySlider->value();
    i32 maxResultCount     = 20;

    search.distance                       = 1.f - (requiredSimilarity / 100.f);
    search.limit                          = maxResultCount;
    search.debug_include.external_symbols = false;
    search.debug_include.system_symbols   = false;
    search.debug_include.user_symbols     = false;

    SimilarFunctions similar_functions = GetSimilarFunctions (GetConnection(), &search);
    SimilarFunctionsRequestDeinit (&search);

    if (similar_functions.length == 0) {
        showErrorState ("No similar functions found for given settings");
        return;
    }

    // Convert results to our format
    VecForeachPtr (&similar_functions, similar_function, {
        SimilarFunctionData data;
        data.name       = QString::fromUtf8 (similar_function->name.data);
        data.binaryName = QString::fromUtf8 (similar_function->binary_name.data);
        data.functionId = similar_function->id;
        data.binaryId   = similar_function->binary_id;
        data.similarity = (1.0f - similar_function->distance) * 100.0f;

        // Get disassembly for this function
        data.disassembly = getFunctionDisassembly (similar_function->id);

        if (data.disassembly.length > 0) {
            similarFunctions.append (data);
        }
    });

    // Cleanup
    VecDeinit (&similar_functions);

    if (similarFunctions.isEmpty()) {
        showErrorState ("No similar functions with valid disassembly found");
        return;
    }

    updateFunctionList();
    updateStatusLabel (QString ("Found %1 similar functions").arg (similarFunctions.size()));

    // Auto-select first item
    if (functionListPanel->topLevelItemCount() > 0) {
        functionListPanel->setCurrentItem (functionListPanel->topLevelItem (0));
        currentSelectedIndex = 0;
        updateDiffPanels();
    }
}

void InteractiveDiffWidget::updateFunctionList() {
    functionListPanel->clear();

    int minSimilarity = similaritySlider->value();

    for (const auto &func : similarFunctions) {
        if (func.similarity >= minSimilarity) {
            QTreeWidgetItem *item = new QTreeWidgetItem();
            item->setText (0, func.name);
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
            functionListPanel->addTopLevelItem (item);
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

    // Generate diff between source and target
    VecDeinit (&currentDiffLines);
    currentDiffLines = GetDiff (&sourceDisassembly, &targetFunc.disassembly);

    if (currentDiffLines.length == 0) {
        showErrorState ("Failed to generate diff");
        return;
    }

    // Render diff in both panels
    renderSourceDiff (currentDiffLines);
    renderTargetDiff (currentDiffLines);

    updateStatusLabel (
        QString ("Showing diff with %1 (%2%)").arg (targetFunc.name).arg (targetFunc.similarity, 0, 'f', 1)
    );
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