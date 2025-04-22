/**
 * @file      : FunctionSimilarityDialog.cpp
 * @date      : 25th Sept 2024
 * @author    : Siddharth Mishra (admin@brightprogrammer.in)
 * @copyright : Copyright (c) 2024 RevEngAI. All Rights Reserved.
 * */

/* plugin */
#include <Plugin.h>
#include <Reai/Api/Reai.h>
#include <Cutter/Ui/FunctionSimilarityDialog.hpp>
#include <Cutter/Ui/CollectionSearchDialog.hpp>
#include <Cutter/Ui/BinarySearchDialog.hpp>

/* qt */
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QScrollArea>
#include <QPushButton>
#include <QHeaderView>
#include <QCompleter>
#include <QDialogButtonBox>
#include <QLabel>
#include <QUrl>
#include <QDesktopServices>

/* cutter */
#include <cutter/core/Cutter.h>
#include <librz/rz_analysis.h>

/* reai */
#include <Reai/Util/Vec.h>

// TODO: provide a way to rename functions from this dialog as well

FunctionSimilarityDialog::FunctionSimilarityDialog (QWidget* parent) : QDialog (parent) {
    setMinimumSize (540, 360);

    mainLayout = new QVBoxLayout;
    setLayout (mainLayout);
    setWindowTitle ("Function Similarity Search");

    QGridLayout* l = new QGridLayout (this);
    QLabel*      n = nullptr;

    mainLayout->addLayout (l);

    /* get function names from binary */
    QStringList fnNamesList;
    {
        RzCoreLocked core (Core());

        if (!reai_plugin_get_rizin_analysis_function_count (core)) {
            return;
        }

        if (!rz_analysis_function_list (core->analysis) ||
            !rz_list_length (rz_analysis_function_list (core->analysis))) {
            DISPLAY_ERROR (
                "Opened binary seems to have no functions. None detected by Rizin. Cannot perform "
                "similarity search."
            );
            return;
        }

        /* add all symbols corresponding to functions */
        RzList*     fns     = rz_analysis_function_list (core->analysis);
        RzListIter* fn_iter = nullptr;
        void*       data    = nullptr;
        rz_list_foreach (fns, fn_iter, data) {
            RzAnalysisFunction* fn = (RzAnalysisFunction*)data;
            fnNamesList << fn->name;
        }
    }

    /* create search bar and add and cancel buttons to add/cancel adding a
     * new name map */
    n = new QLabel (this);
    n->setText ("Function name : ");
    searchBarInput = new QLineEdit (this);
    searchBarInput->setPlaceholderText ("Start typing for suggestions...");
    l->addWidget (n, 0, 0);
    l->addWidget (searchBarInput, 0, 1);

    fnNameCompleter = new QCompleter (fnNamesList);
    fnNameCompleter->setCaseSensitivity (Qt::CaseInsensitive);
    searchBarInput->setCompleter (fnNameCompleter);

    n = new QLabel (this);
    n->setText ("Max result count : ");
    maxResultCountInput = new QSpinBox (this);
    maxResultCountInput->setValue (10);
    maxResultCountInput->setMinimum (1);
    l->addWidget (n, 1, 0);
    l->addWidget (maxResultCountInput, 1, 1);

    /* textbox for taking in collection ids in csv format */
    n = new QLabel (this);
    n->setText ("Collection IDs : ");
    collectionIdsInput = new QLineEdit (this);
    collectionIdsInput->setPlaceholderText ("Comma separated list of collection IDs");
    l->addWidget (n, 2, 0);
    l->addWidget (collectionIdsInput, 2, 1);

    /* textbox for taking in binary ids in csv format */
    n = new QLabel (this);
    n->setText ("Binary IDs : ");
    binaryIdsInput = new QLineEdit (this);
    binaryIdsInput->setPlaceholderText ("Comma separated list of binary IDs");
    l->addWidget (n, 3, 0);
    l->addWidget (binaryIdsInput, 3, 1);


    /* Create slider to select similarity level */
    similaritySlider = new QSlider (Qt::Horizontal);
    similaritySlider->setMinimum (1);
    similaritySlider->setMaximum (100);
    similaritySlider->setValue (90);

    QLabel* similarityLabel = new QLabel ("90% min similarity");
    connect (similaritySlider, &QSlider::valueChanged, [similarityLabel] (int value) {
        similarityLabel->setText (QString ("%1 % min similarity").arg (value));
    });
    l->addWidget (similarityLabel, 4, 0);
    l->addWidget (similaritySlider, 4, 1);

    enableDebugFilterCheckBox = new QCheckBox ("Restrict suggestions to debug symbols only?", this);
    mainLayout->addWidget (enableDebugFilterCheckBox);
    enableDebugFilterCheckBox->setCheckState (Qt::CheckState::Checked);

    QPushButton* binaryIdsSearchBtn = new QPushButton ("Select Binaries");
    connect (
        binaryIdsSearchBtn,
        &QPushButton::pressed,
        this,
        &FunctionSimilarityDialog::on_SearchBinaries
    );

    QPushButton* collectionIdsSearchBtn = new QPushButton ("Select Collections");
    connect (
        collectionIdsSearchBtn,
        &QPushButton::pressed,
        this,
        &FunctionSimilarityDialog::on_SearchCollections
    );

    QPushButton* searchBtn = new QPushButton ("Search", this);
    connect (
        searchBtn,
        &QPushButton::pressed,
        this,
        &FunctionSimilarityDialog::on_FindSimilarNames
    );

    QPushButton* cancelBtn = new QPushButton ("Cancel", this);
    connect (cancelBtn, &QPushButton::pressed, this, &FunctionSimilarityDialog::close);

    QDialogButtonBox* btnBox = new QDialogButtonBox (this);
    btnBox->addButton (collectionIdsSearchBtn, QDialogButtonBox::ActionRole);
    btnBox->addButton (binaryIdsSearchBtn, QDialogButtonBox::ActionRole);
    btnBox->addButton (searchBtn, QDialogButtonBox::AcceptRole);
    btnBox->addButton (cancelBtn, QDialogButtonBox::RejectRole);
    mainLayout->addWidget (btnBox);

    headerLabels << "function name";
    headerLabels << "function id";
    headerLabels << "binary name";
    headerLabels << "binary id";
    headerLabels << "similarity";
    headerLabels << " ";

    table = new QTableWidget;
    table->setEditTriggers (QAbstractItemView::NoEditTriggers);
    table->horizontalHeader()->setSectionResizeMode (QHeaderView::Stretch);
    table->setColumnCount (6);
    table->setHorizontalHeaderLabels (headerLabels);
    table->horizontalHeader()->setSectionResizeMode (QHeaderView::Stretch);
    mainLayout->addWidget (table);

    connect (
        table,
        &QTableWidget::cellDoubleClicked,
        this,
        &FunctionSimilarityDialog::on_TableCellDoubleClick
    );
}

void FunctionSimilarityDialog::on_FindSimilarNames() {
    RzCoreLocked core (Core());

    if (!reai_binary_id()) {
        DISPLAY_ERROR (
            "No analysis created or applied. I need a RevEngAI analysis to get function info."
        );
        return;
    }

    /* check if function exists or not */
    const QString& fnName        = searchBarInput->text();
    QByteArray     fnNameByteArr = fnName.toLatin1();
    CString        fnNameCStr    = fnNameByteArr.constData();

    Uint32 requiredSimilarity = similaritySlider->value();
    Bool   debugFilter        = enableDebugFilterCheckBox->checkState() == Qt::CheckState::Checked;
    Int32  maxResultCount     = maxResultCountInput->value();

    const QString& collectionIdsCsv        = collectionIdsInput->text();
    QByteArray     collectionIdsCsvByteArr = collectionIdsCsv.toLatin1();
    CString        collectionIdsCsvCStr    = collectionIdsCsvByteArr.constData();

    const QString& binaryIdsCsv        = collectionIdsInput->text();
    QByteArray     binaryIdsCsvByteArr = collectionIdsCsv.toLatin1();
    CString        binaryIdsCsvCStr    = collectionIdsCsvByteArr.constData();

    ReaiAnalysisStatus status = reai_plugin_get_analysis_status_for_binary_id (reai_binary_id());
    switch (status) {
        case REAI_ANALYSIS_STATUS_ERROR : {
            DISPLAY_ERROR (
                "The applied/created RevEngAI analysis has errored out.\n"
                "I need a complete analysis to get function info. Please restart analysis."
            );
            return;
        }
        case REAI_ANALYSIS_STATUS_QUEUED : {
            DISPLAY_ERROR (
                "The applied/created RevEngAI analysis is currently in queue.\n"
                "Please wait for the analysis to be analyzed."
            );
            return;
        }
        case REAI_ANALYSIS_STATUS_PROCESSING : {
            DISPLAY_ERROR (
                "The applied/created RevEngAI analysis is currently being processed (analyzed).\n"
                "Please wait for the analysis to complete."
            );
            return;
        }
        case REAI_ANALYSIS_STATUS_COMPLETE : {
            REAI_LOG_TRACE ("Analysis for binary ID %llu is COMPLETE.", reai_binary_id());
            break;
        }
        default : {
            DISPLAY_ERROR (
                "Oops... something bad happened :-(\n"
                "I got an invalid value for RevEngAI analysis status.\n"
                "Consider\n"
                "\t- Checking the binary ID, reapply the correct one if wrong\n"
                "\t- Retrying the command\n"
                "\t- Restarting the plugin\n"
                "\t- Checking logs in $TMPDIR or $TMP or $PWD (reai_<pid>)\n"
                "\t- Checking the connection with RevEngAI host.\n"
                "\t- Contacting support if the issue persists\n"
            );
            return;
        }
    }

    RzAnalysisFunction* fn = rz_analysis_get_function_byname (core->analysis, fnNameCStr);
    if (!fn) {
        DISPLAY_ERROR ("Provided function name does not exist. Cannot get similar function names.");
        return;
    }

    ReaiFunctionId fn_id = reai_plugin_get_function_id_for_rizin_function (core, fn);
    if (!fn_id) {
        DISPLAY_ERROR (
            "Failed to get function id of given function. Cannot get similar function names."
        );
        return;
    }

    U64Vec* collection_ids = reai_plugin_csv_to_u64_vec (collectionIdsCsvCStr);
    U64Vec* binary_ids     = reai_plugin_csv_to_u64_vec (binaryIdsCsvCStr);

    Float32           maxDistance = 1.f - (requiredSimilarity / 100.f);
    ReaiSimilarFnVec* fnMatches   = reai_get_similar_functions (
        reai(),
        reai_response(),
        fn_id,
        maxResultCount,
        maxDistance,
        collection_ids,
        debugFilter,
        binary_ids
    );

    if (collection_ids) {
        reai_u64_vec_destroy (collection_ids);
    }

    if (binary_ids) {
        reai_u64_vec_destroy (binary_ids);
    }

    if (fnMatches && fnMatches->count) {
        for (ReaiSimilarFn* fnMatch = fnMatches->items;
             fnMatch < fnMatches->items + fnMatches->count;
             fnMatch++) {
            QStringList row;

            row << fnMatch->function_name << QString::number (fnMatch->function_id);
            row << fnMatch->binary_name << QString::number (fnMatch->binary_id);
            row << QString::number ((1 - fnMatch->distance) * 100);
            addNewRowToResultsTable (table, row);
        }
    } else {
        DISPLAY_ERROR ("No similar functions found for given settings");
    }
}

void FunctionSimilarityDialog::on_SearchCollections() {
    CollectionSearchDialog* csDlg = new CollectionSearchDialog (
        (QWidget*)this,
        false /* store ids on double click instead of opening links */
    );
    csDlg->exec();
    collectionIdsInput->setText (
        collectionIdsInput->text() + csDlg->getSelectedCollectionIds().join (",")
    );
}

void FunctionSimilarityDialog::on_SearchBinaries() {
    BinarySearchDialog* bsDlg = new BinarySearchDialog (
        (QWidget*)this,
        false /* store ids on double click instead of opening links */
    );
    bsDlg->exec();
    binaryIdsInput->setText (binaryIdsInput->text() + bsDlg->getSelectedBinaryIds().join (","));
}

void FunctionSimilarityDialog::on_TableCellDoubleClick (int row, int column) {
    // ignore last column
    if (column == 5) {
        return;
    }

    // generate portal URL from host URL
    const char* hostCStr = reai_plugin()->reai_config->host;
    QString     host     = QString::fromUtf8 (hostCStr);
    host.replace ("api", "portal", Qt::CaseSensitive); // replaces first occurrence

    // fetch collection id and open url
    QString functionId = table->item (row, 1)->text();
    QString link       = QString ("%1/function/%2").arg (host).arg (functionId);
    QDesktopServices::openUrl (QUrl (link));
}

void FunctionSimilarityDialog::addNewRowToResultsTable (QTableWidget* t, const QStringList& row) {
    Size tableRowCount = t->rowCount();
    t->insertRow (tableRowCount);

    for (Int32 i = 0; i < headerLabels.size() - 1; i++) {
        t->setItem (tableRowCount, i, new QTableWidgetItem (row[i]));
    }

    QPushButton* renameBtn = new QPushButton ("Rename");
    t->setCellWidget (tableRowCount, 5, renameBtn);
    connect (renameBtn, &QPushButton::clicked, this, [this, tableRowCount]() {
        QMessageBox::information (
            this,
            "Title",
            QString ("Renaming function at row %1").arg (tableRowCount)
        );
    });
}
