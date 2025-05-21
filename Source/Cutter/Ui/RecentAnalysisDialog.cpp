/**
 * @file      : RecentAnalysisDialog.cpp
 * @date      : 8th Apr 2025
 * @author    : Siddharth Mishra (admin@brightprogrammer.in)
 * @copyright : Copyright (c) 2025 RevEngAI. All Rights Reserved.
 * */

/* plugin */
#include <Plugin.h>
#include <Reai/Api/Reai.h>
#include <Cutter/Ui/RecentAnalysisDialog.hpp>

/* qt */
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QScrollArea>
#include <QPushButton>
#include <QHeaderView>
#include <QDesktopServices>
#include <QDialogButtonBox>
#include <QUrl>
#include <QLabel>

/* cutter */
#include <Reai/Api/Request.h>
#include <cutter/core/Cutter.h>
#include <librz/rz_analysis.h>

/* reai */
#include <Reai/Util/Vec.h>

RecentAnalysisDialog::RecentAnalysisDialog (QWidget* parent) : QDialog (parent) {
    setMinimumSize (QSize (960, 540));

    mainLayout = new QVBoxLayout;
    setLayout (mainLayout);
    setWindowTitle ("Recent Analysis");

    QGridLayout* l = new QGridLayout (this);
    QLabel*      n = nullptr;

    mainLayout->addLayout (l);

    n = new QLabel (this);
    n->setText ("Search term (optional) : ");
    searchTermInput = new QLineEdit (this);
    searchTermInput->setPlaceholderText ("search term");
    searchTermInput->setToolTip ("Search term filter");
    l->addWidget (n, 0, 0);
    l->addWidget (searchTermInput, 0, 1);

    n = new QLabel (this);
    n->setText ("Usernames (optional) : ");
    usernamesInput = new QLineEdit (this);
    usernamesInput->setPlaceholderText ("comma separated usernames");
    usernamesInput->setToolTip ("A comma separated list of usernames to restrict search to");
    l->addWidget (n, 1, 0);
    l->addWidget (usernamesInput, 1, 1);

    n = new QLabel (this);
    n->setText ("Model name : ");
    modelNameSelector = new QComboBox (this);
    modelNameSelector->setPlaceholderText ("any model");
    modelNameSelector->setToolTip ("Model used to perform analysis");

    CString* beg = reai_ai_models()->items;
    CString* end = reai_ai_models()->items + reai_ai_models()->count;
    for (CString* ai_model = beg; ai_model < end; ai_model++) {
        modelNameSelector->addItem (*ai_model);
    }

    l->addWidget (n, 2, 0);
    l->addWidget (modelNameSelector, 2, 1);

    n = new QLabel (this);
    n->setText ("Workspace : ");
    workspaceSelector = new QComboBox (this);
    workspaceSelector->setPlaceholderText ("personal");
    workspaceSelector->setToolTip ("Limit search to a workspace");
    workspaceSelector->addItem ("personal");
    workspaceSelector->addItem ("public");
    workspaceSelector->addItem ("team");
    l->addWidget (n, 3, 0);
    l->addWidget (workspaceSelector, 3, 1);

    n = new QLabel (this);
    n->setText ("Order by : ");
    orderBySelector = new QComboBox (this);
    orderBySelector->setPlaceholderText ("created");
    orderBySelector->setToolTip ("Order the results in accord to the selected property");
    orderBySelector->addItem ("created");
    orderBySelector->addItem ("name");
    orderBySelector->addItem ("size");
    l->addWidget (n, 4, 0);
    l->addWidget (orderBySelector, 4, 1);

    n = new QLabel (this);
    n->setText ("Analysis status : ");
    statusSelector = new QComboBox (this);
    statusSelector->setPlaceholderText ("All");
    statusSelector->setToolTip ("Restrict results to selected status");
    statusSelector->addItem ("Uploaded");
    statusSelector->addItem ("Queued");
    statusSelector->addItem ("Complete");
    statusSelector->addItem ("Error");
    statusSelector->addItem ("Processing");
    statusSelector->addItem ("All");
    l->addWidget (n, 5, 0);
    l->addWidget (statusSelector, 5, 1);

    n = new QLabel (this);
    n->setText ("Order in ascending : ");
    isOrderedInAsc = new QCheckBox (this);
    isOrderedInAsc->setToolTip ("Sort serach results in ascending order of order by property");
    l->addWidget (n, 6, 0);
    l->addWidget (isOrderedInAsc, 6, 1);

    QDialogButtonBox* btnBox = new QDialogButtonBox (QDialogButtonBox::Ok | QDialogButtonBox::Cancel);
    mainLayout->addWidget (btnBox);

    headerLabels << "name";
    headerLabels << "binary id";
    headerLabels << "analysis id";
    headerLabels << "status";
    headerLabels << "owner";
    headerLabels << "created at";
    headerLabels << "sha256";

    table = new QTableWidget;
    table->setEditTriggers (QAbstractItemView::NoEditTriggers);
    table->horizontalHeader()->setSectionResizeMode (QHeaderView::Stretch);
    table->setColumnCount (7);
    table->setHorizontalHeaderLabels (headerLabels);
    table->horizontalHeader()->setSectionResizeMode (QHeaderView::Stretch);
    mainLayout->addWidget (table);

    connect (btnBox, &QDialogButtonBox::accepted, this, &RecentAnalysisDialog::on_GetRecentAnalysis);
    connect (btnBox, &QDialogButtonBox::rejected, this, &QDialog::close);
    connect (table, &QTableWidget::cellDoubleClicked, this, &RecentAnalysisDialog::on_TableCellDoubleClick);
}

void RecentAnalysisDialog::on_GetRecentAnalysis() {
    RzCoreLocked core (Core());

    const QString& searchTerm        = searchTermInput->text();
    QByteArray     searchTermByteArr = searchTerm.toLatin1();
    CString        searchTermCStr    = searchTermByteArr.constData();

    const QString& usernames        = usernamesInput->text();
    QByteArray     usernamesByteArr = usernames.toLatin1();
    CString        usernamesCStr    = usernamesByteArr.constData();

    CString modelNameCStr = NULL;
    if (modelNameSelector->currentIndex() != -1) {
        const QString& modelName        = modelNameSelector->currentText();
        QByteArray     modelNameByteArr = modelName.toLatin1();
        modelNameCStr                   = modelNameByteArr.constData();
    }

    ReaiWorkspace workspace = REAI_WORKSPACE_PERSONAL;
    if (workspaceSelector->currentIndex() != -1) {
        const QString& ws               = workspaceSelector->currentText();
        QByteArray     workspaceByteArr = ws.toLatin1();
        CString        workspaceCStr    = workspaceByteArr.constData();

        if (!strcmp (workspaceCStr, "public")) {
            workspace = REAI_WORKSPACE_PUBLIC;
        } else if (!strcmp (workspaceCStr, "team")) {
            workspace = REAI_WORKSPACE_TEAM;
        }
    }

    ReaiRecentAnalysisOrderBy orderBy = REAI_RECENT_ANALYSIS_ORDER_BY_CREATED;
    if (orderBySelector->currentIndex() != -1) {
        const QString& ob             = orderBySelector->currentText();
        QByteArray     orderByByteArr = ob.toLatin1();
        CString        orderByCStr    = orderByByteArr.constData();

        if (!strcmp (orderByCStr, "name")) {
            orderBy = REAI_RECENT_ANALYSIS_ORDER_BY_NAME;
        } else if (!strcmp (orderByCStr, "size")) {
            orderBy = REAI_RECENT_ANALYSIS_ORDER_BY_SIZE;
        }
    }

    ReaiAnalysisStatus analysisStatus = REAI_ANALYSIS_STATUS_ALL;
    if (statusSelector->currentIndex() != -1) {
        const QString& status        = statusSelector->currentText();
        QByteArray     statusByteArr = status.toLatin1();
        CString        statusCStr    = statusByteArr.constData();
        analysisStatus               = reai_analysis_status_from_cstr (statusCStr);
    }

    CStrVec* usernamesCStrVec = reai_plugin_csv_to_cstr_vec (usernamesCStr);

    // TODO: UI options to change page and result count (5 to 50 slider)

    ReaiAnalysisInfoVec* results = reai_get_recent_analyses (
        reai(),
        reai_response(),
        searchTermCStr /* search term */,
        workspace,
        analysisStatus,
        modelNameCStr,                              /* model name */
        REAI_DYN_EXEC_STATUS_ALL,
        usernamesCStrVec,                           /* usernames */
        25,                                         /* 25 most recent analyses */
        0,
        orderBy,
        isOrderedInAsc->checkState() == Qt::Checked /* order in ascending or descending */
    );

    if (usernamesCStrVec) {
        reai_cstr_vec_destroy (usernamesCStrVec);
    }

    if (!results) {
        DISPLAY_ERROR ("Failed to get collection search results");
        return;
    }

    table->clearContents();
    table->setRowCount (0);

    ReaiAnalysisInfo* beg = results->items;
    ReaiAnalysisInfo* end = results->items + results->count;
    for (ReaiAnalysisInfo* csr = beg; csr < end; csr++) {
        QStringList row;
        row << csr->binary_name;
        row << QString::number (csr->binary_id);
        row << QString::number (csr->analysis_id);
        row << reai_analysis_status_to_cstr (csr->status);
        row << csr->username;
        row << csr->creation;
        row << csr->sha_256_hash;

        addNewRowToResultsTable (table, row);
    }

    mainLayout->addWidget (table);
}

void RecentAnalysisDialog::on_TableCellDoubleClick (int row, int column) {
    UNUSED (column);

    // generate portal URL from host URL
    const char* hostCStr = reai_plugin()->reai_config->host;
    QString     host     = QString::fromUtf8 (hostCStr);
    host.replace ("api", "portal", Qt::CaseSensitive); // replaces first occurrence

    // fetch collection id and open url
    QString binaryId   = table->item (row, 1)->text();
    QString analysisId = table->item (row, 2)->text();
    QString link       = QString ("%1/analyses/%2?analysis-id=%3").arg (host).arg (binaryId).arg (analysisId);
    QDesktopServices::openUrl (QUrl (link));
}

void RecentAnalysisDialog::addNewRowToResultsTable (QTableWidget* t, const QStringList& row) {
    Size tableRowCount = t->rowCount();
    t->insertRow (tableRowCount);
    for (Int32 i = 0; i < headerLabels.size(); i++) {
        t->setItem (tableRowCount, i, new QTableWidgetItem (row[i]));
    }
}
