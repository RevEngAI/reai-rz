/**
 * @file      : CreateAnalysisDialog.hpp
 * @author    : Siddharth Mishra
 * @date      : 11th Nov 2024
 * @copyright : Copyright (c) 2024 RevEngAI. All Rights Reserved.
 * */

#ifndef REAI_PLUGIN_CUTTER_UI_CREATE_ANALYSIS_DIALOG_HPP
#define REAI_PLUGIN_CUTTER_UI_CREATE_ANALYSIS_DIALOG_HPP

/* qt */
#include <QDialog>
#include <QLineEdit>
#include <QSlider>
#include <QTableWidget>
#include <QCheckBox>
#include <QVBoxLayout>
#include <QComboBox>
#include <QProgressBar>
#include <QPushButton>
#include <QLabel>
#include <QThread>

/* rizin */
#include <rz_core.h>

/* reai */
#include <Reai/Api.h>

// Forward declaration
class CreateAnalysisWorker;

struct CreateAnalysisRequest {
    QString       aiModelName;
    QString       progName;
    QString       cmdLineArgs;
    bool          isPrivate;
    QString       binaryPath;
    u64           baseAddr;
    FunctionInfos functions;
};

struct CreateAnalysisResult {
    bool     success;
    BinaryId binaryId;
    QString  errorMessage;
};

class CreateAnalysisWorker : public QObject {
    Q_OBJECT

   public:
    CreateAnalysisWorker (QObject* parent = nullptr) : QObject (parent), m_cancelled (false) {}

    void performCreateAnalysis (const CreateAnalysisRequest& request);
    void cancel() {
        m_cancelled = true;
    }

   signals:
    void progress (int percentage, const QString& message);
    void analysisFinished (const CreateAnalysisResult& result);
    void analysisError (const QString& error);

   private:
    bool m_cancelled;
    void emitProgress (int percentage, const QString& message) {
        if (!m_cancelled) {
            emit progress (percentage, message);
        }
    }
};

class CreateAnalysisDialog : public QDialog {
    Q_OBJECT;

   public:
    CreateAnalysisDialog (QWidget* parent);
    ~CreateAnalysisDialog();

   private slots:
    void on_CreateAnalysis();
    void on_CancelAnalysis();
    void onAnalysisProgress (int percentage, const QString& message);
    void onAnalysisFinished (const CreateAnalysisResult& result);
    void onAnalysisError (const QString& error);

   private:
    QVBoxLayout* mainLayout;
    QComboBox*   aiModelInput;
    QLineEdit*   progNameInput;
    QLineEdit*   cmdLineArgsInput;
    QCheckBox*   isAnalysisPrivateCheckBox;

    // Async operation UI elements
    QProgressBar* progressBar;
    QPushButton*  cancelButton;
    QLabel*       statusLabel;
    QPushButton*  okButton;
    QPushButton*  cancelDialogButton;

    // Worker thread management
    QThread*              workerThread;
    CreateAnalysisWorker* worker;

    void startAsyncCreateAnalysis();
    void cancelAsyncCreateAnalysis();
    void setupProgressUI();
    void hideProgressUI();
    void setUIEnabled (bool enabled);
};

#endif // REAI_PLUGIN_CUTTER_UI_CREATE_ANALYSIS_DIALOG_HPP
