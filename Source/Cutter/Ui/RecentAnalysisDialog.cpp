/**
 * @file      : RecentAnalysisDialog.cpp
 * @date      : 8th Apr 2025
 * @author    : Siddharth Mishra (admin@brightprogrammer.in)
 * @copyright : Copyright (c) 2025 RevEngAI. All Rights Reserved.
 * */

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
#include <Plugin.h>
#include <Reai/Api.h>
#include <Cutter/Ui/RecentAnalysisDialog.hpp>

RecentAnalysisDialog::RecentAnalysisDialog (QWidget* parent) : QDialog (parent) {
    setMinimumSize (QSize (960, 540));

    mainLayout = new QVBoxLayout;
    setLayout (mainLayout);
    setWindowTitle ("Recent Analysis");

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

    connect (table, &QTableWidget::cellDoubleClicked, this, &RecentAnalysisDialog::on_TableCellDoubleClick);

    on_GetRecentAnalysis();
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
