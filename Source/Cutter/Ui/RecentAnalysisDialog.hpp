/**
 * @file      : RecentAnalysisDialog.hpp
 * @date      : 8th Apr 2025
 * @author    : Siddharth Mishra (admin@brightprogrammer.in)
 * @copyright : Copyright (c) 2025 RevEngAI. All Rights Reserved.
 * */

#ifndef REAI_PLUGIN_CUTTER_UI_RECENT_ANALYSIS_DIALOG_HPP
#define REAI_PLUGIN_CUTTER_UI_RECENT_ANALYSIS_DIALOG_HPP

/* qt */
#include <QDialog>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QTableWidget>
#include <QStringList>
#include <QLineEdit>
#include <QComboBox>
#include <QThread>
#include <QProgressBar>
#include <QPushButton>
#include <QLabel>

/* reai */
#include <Reai/Api/Types.h>

// Forward declarations
class RecentAnalysisWorker;

class RecentAnalysisDialog : public QDialog {
    Q_OBJECT

   public:
    explicit RecentAnalysisDialog (QWidget *parent = nullptr);
    ~RecentAnalysisDialog();

   private slots:
    void on_GetRecentAnalysis();
    void on_TableCellDoubleClick (int row, int column);
    void onAnalysisProgress (int percentage, const QString &message);
    void onAnalysisFinished (const AnalysisInfos &analyses);
    void onAnalysisError (const QString &error);
    void cancelAsyncOperation();

   private:
    void addNewRowToResultsTable (QTableWidget *t, const QStringList &row);
    void startAsyncGetRecentAnalysis();
    void setupProgressUI();
    void hideProgressUI();
    void setUIEnabled (bool enabled);

    QVBoxLayout  *mainLayout;
    QTableWidget *table;
    QStringList   headerLabels;

    // Async operation components
    QThread              *workerThread = nullptr;
    RecentAnalysisWorker *worker       = nullptr;
    QProgressBar         *progressBar  = nullptr;
    QPushButton          *cancelButton = nullptr;
    QLabel               *statusLabel  = nullptr;
};

// Worker class for async recent analysis fetching
class RecentAnalysisWorker : public QObject {
    Q_OBJECT

   public:
    explicit RecentAnalysisWorker (QObject *parent = nullptr);

   public slots:
    void performGetRecentAnalysis();
    void cancel();

   signals:
    void progress (int percentage, const QString &message);
    void analysisFinished (const AnalysisInfos &analyses);
    void analysisError (const QString &error);

   private:
    bool m_cancelled;

    void emitProgress (int percentage, const QString &message) {
        if (!m_cancelled) {
            emit progress (percentage, message);
        }
    }
};

#endif // REAI_PLUGIN_CUTTER_UI_RECENT_ANALYSIS_DIALOG_HPP
