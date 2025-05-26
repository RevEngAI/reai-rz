/**
 * @file      : RecentAnalysisDialog.cpp
 * @date      : 8th Apr 2025
 * @author    : Siddharth Mishra (admin@brightprogrammer.in)
 * @copyright : Copyright (c) 2025 RevEngAI. All Rights Reserved.
 * */

/* plugin */
#include <Plugin.h>
#include <Reai/Api.h>
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

    ModelInfos* models = GetModels();
    VecForeachPtr (models, model, { modelNameSelector->addItem (model->name.data); });

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

    RecentAnalysisRequest recents  = RecentAnalysisRequestInit();
    AnalysisInfos         recent_analyses = GetRecentAnalysis (GetConnection(), &recents);
    RecentAnalysisRequestDeinit (&recents);

    table->clearContents();
    table->setRowCount (0);

    VecForeachPtr(&recent_analyses, recent_analysis, {
        QStringList row;
        row << recent_analysis->binary_name.data;
        row << QString::number (recent_analysis->binary_id);
        row << QString::number (recent_analysis->analysis_id);
        Str status = StrInit();
        StatusToStr(recent_analysis->status, &status);
        row << status.data;
        row << recent_analysis->username.data;
        row << recent_analysis->creation.data;
        row << recent_analysis->sha256.data;

        addNewRowToResultsTable (table, row);
    });

    mainLayout->addWidget (table);
}

void RecentAnalysisDialog::on_TableCellDoubleClick (int row, int column) {
    // generate portal URL from host URL
    Str link = StrDup(&GetConnection()->host);
    StrReplaceZstr(&link, "api", "portal", 1);
    
    // fetch collection id and open url
    QString binaryId   = table->item (row, 1)->text();
    QString analysisId = table->item (row, 2)->text();
    StrAppendf(&link, "/analyses/%llu?analysis-id=%llu", binaryId.toULongLong(), analysisId.toULongLong());
    QDesktopServices::openUrl (QUrl (link.data));

    StrDeinit(&link);
}

void RecentAnalysisDialog::addNewRowToResultsTable (QTableWidget* t, const QStringList& row) {
    size_t tableRowCount = t->rowCount();
    t->insertRow (tableRowCount);
    for (i32 i = 0; i < headerLabels.size(); i++) {
        t->setItem (tableRowCount, i, new QTableWidgetItem (row[i]));
    }
}
