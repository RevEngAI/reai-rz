/**
 * @file      : AutoAnalysisDialog.hpp
 * @author    : Siddharth Mishra
 * @date      : 11th Nov 2024
 * @copyright : Copyright (c) 2024 RevEngAI. All Rights Reserved.
 * */

#ifndef REAI_PLUGIN_CUTTER_UI_AUTO_ANALYSIS_DIALOG_HPP
#define REAI_PLUGIN_CUTTER_UI_AUTO_ANALYSIS_DIALOG_HPP

/* qt */
#include <QDialog>
#include <QLineEdit>
#include <QSlider>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QCheckBox>
#include <QVBoxLayout>
#include <QProgressBar>
#include <QLabel>
#include <QPushButton>
#include <QThread>
#include <QObject>

/* rizin */
#include <rz_core.h>

/* cutter */
#include <cutter/core/CutterDescriptions.h>

/* reai */
#include <Reai/Types.h>
#include <Reai/Api/Types/FunctionInfo.h>
#include <Cutter/Ui/RenameConfirmationDialog.hpp>

// Structure to hold the result of auto analysis
struct AutoAnalysisResult {
    bool                  success;
    QString               errorMessage;
    QList<ProposedRename> proposedRenames; // List of proposed renames for user approval

    AutoAnalysisResult() : success (false) {}
};

// Structure to hold the request parameters for auto analysis
struct AutoAnalysisRequest {
    float                      minSimilarity;
    bool                       debugSymbolsOnly;
    int                        maxResultsPerFunction;
    QList<FunctionDescription> functions; // Pre-fetched function list
    u64                        baseAddr;  // Pre-fetched base address

    AutoAnalysisRequest() : minSimilarity (0.9f), debugSymbolsOnly (true), maxResultsPerFunction (10) {}
};

// Forward declarations
class AutoAnalysisWorker;

class AutoAnalysisDialog : public QDialog {
    Q_OBJECT

   public:
    AutoAnalysisDialog (QWidget *parent);
    ~AutoAnalysisDialog();

   private slots:
    void on_PerformAutoAnalysis();
    void on_CancelAnalysis();

    // Async slots
    void onAnalysisFinished (const AutoAnalysisResult &result);
    void onAnalysisError (const QString &error);
    void onProgressUpdate (int percentage, const QString &status);

   private:
    // UI Components
    QVBoxLayout  *mainLayout;
    QSlider      *similaritySlider;
    QCheckBox    *enableDebugFilterCheckBox;
    QProgressBar *progressBar;
    QLabel       *statusLabel;
    QPushButton  *okButton;
    QPushButton  *cancelButton;

    // Async operation management
    AutoAnalysisWorker *analysisWorker;
    QThread            *workerThread;

    // Helper methods
    void setupUI();
    void showProgress (int percentage, const QString &status);
    void hideProgress();
    void startAsyncAnalysis();
    void cancelAsyncAnalysis();
    void applyRenames (const QList<ProposedRename> &renames); // Apply approved renames
};

// Async worker class for auto analysis
class AutoAnalysisWorker : public QObject {
    Q_OBJECT

   public:
    AutoAnalysisWorker (QObject *parent = nullptr) : QObject (parent), m_cancelled (false) {}

    void performAnalysis (const AutoAnalysisRequest &request);
    void cancelAnalysis() {
        m_cancelled = true;
    }

   signals:
    void progressUpdate (int percentage, const QString &status);
    void analysisFinished (const AutoAnalysisResult &result);
    void analysisError (const QString &error);

   private:
    bool m_cancelled;
    void emitProgress (int percentage, const QString &status) {
        if (!m_cancelled) {
            emit progressUpdate (percentage, status);
        }
    }

    // Custom function ID lookup that works with FunctionDescription
    FunctionId lookupFunctionId (
        const QList<FunctionDescription> &cutterFunctions,
        const FunctionDescription        &targetFunction,
        const FunctionInfos              &revengaiFunctions,
        u64                               baseAddr
    );
};

#endif // REAI_PLUGIN_CUTTER_UI_AUTO_ANALYSIS_DIALOG_HPP
