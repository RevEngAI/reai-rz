/**
 * @file      : BinarySearchDialog.hpp
 * @date      : 8th Apr 2025
 * @author    : Siddharth Mishra (admin@brightprogrammer.in)
 * @copyright : Copyright (c) 2025 RevEngAI. All Rights Reserved.
 * */

#ifndef REAI_PLUGIN_CUTTER_UI_BINARY_SEARCH_DIALOG_HPP
#define REAI_PLUGIN_CUTTER_UI_BINARY_SEARCH_DIALOG_HPP

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
class BinarySearchWorker;

class BinarySearchDialog : public QDialog {
    Q_OBJECT

public:
    explicit BinarySearchDialog (QWidget* parent = nullptr, bool openPageOnDoubleClick = true);
    ~BinarySearchDialog();

    const QStringList& getSelectedBinaryIds() const {
        return selectedBinaryIds;
    }

private slots:
    void on_PerformBinarySearch();
    void on_TableCellDoubleClick (int row, int column);
    void onSearchProgress(int percentage, const QString &message);
    void onSearchFinished(const BinaryInfos &binaries);
    void onSearchError(const QString &error);
    void cancelAsyncOperation();

private:
    void addNewRowToResultsTable (QTableWidget* t, const QStringList& row);
    void startAsyncBinarySearch();
    void setupProgressUI();
    void hideProgressUI();
    void setUIEnabled(bool enabled);

    QVBoxLayout*     mainLayout;
    QTableWidget*    table;
    QStringList      headerLabels;
    QLineEdit*       partialBinaryNameInput;
    QLineEdit*       partialBinarySha256Input;
    QComboBox*       modelNameSelector;
    QStringList      selectedBinaryIds;
    bool             openPageOnDoubleClick;
    
    // Async operation components
    QThread *workerThread = nullptr;
    BinarySearchWorker *worker = nullptr;
    QProgressBar *progressBar = nullptr;
    QPushButton *cancelButton = nullptr;
    QLabel *statusLabel = nullptr;
};

// Worker class for async binary search
class BinarySearchWorker : public QObject {
    Q_OBJECT

public:
    explicit BinarySearchWorker(QObject *parent = nullptr);
    
    struct SearchRequest {
        QString partialName;
        QString partialSha256;
        QString modelName;
    };

public slots:
    void performBinarySearch(const SearchRequest &request);
    void cancel();

signals:
    void progress(int percentage, const QString &message);
    void searchFinished(const BinaryInfos &binaries);
    void searchError(const QString &error);

private:
    bool m_cancelled;
    
    void emitProgress(int percentage, const QString &message) {
        if (!m_cancelled) {
            emit progress(percentage, message);
        }
    }
};

#endif // REAI_PLUGIN_CUTTER_UI_BINARY_SEARCH_DIALOG_HPP
