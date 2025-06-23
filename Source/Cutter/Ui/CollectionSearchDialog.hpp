/**
 * @file      : CollectionSearchDialog.hpp
 * @date      : 8th Apr 2025
 * @author    : Siddharth Mishra (admin@brightprogrammer.in)
 * @copyright : Copyright (c) 2025 RevEngAI. All Rights Reserved.
 * */

#ifndef REAI_PLUGIN_CUTTER_UI_COLLECTION_SEARCH_DIALOG_HPP
#define REAI_PLUGIN_CUTTER_UI_COLLECTION_SEARCH_DIALOG_HPP

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
class CollectionSearchWorker;

class CollectionSearchDialog : public QDialog {
    Q_OBJECT

   public:
    explicit CollectionSearchDialog (QWidget *parent = nullptr, bool openPageOnDoubleClick = true);
    ~CollectionSearchDialog();

    const QStringList &getSelectedCollectionIds() const {
        return selectedCollectionIds;
    }

   private slots:
    void on_PerformCollectionSearch();
    void on_TableCellDoubleClick (int row, int column);
    void onSearchProgress (int percentage, const QString &message);
    void onSearchFinished (const CollectionInfos &collections);
    void onSearchError (const QString &error);
    void cancelAsyncOperation();

   private:
    void addNewRowToResultsTable (QTableWidget *t, const QStringList &row);
    void startAsyncCollectionSearch();
    void setupProgressUI();
    void hideProgressUI();
    void setUIEnabled (bool enabled);

    QVBoxLayout  *mainLayout;
    QTableWidget *table;
    QStringList   headerLabels;
    QLineEdit    *partialCollectionNameInput;
    QLineEdit    *partialBinaryNameInput;
    QLineEdit    *partialBinarySha256Input;
    QComboBox    *modelNameSelector;
    QStringList   selectedCollectionIds;
    bool          openPageOnDoubleClick;

    // Async operation components
    QThread                *workerThread = nullptr;
    CollectionSearchWorker *worker       = nullptr;
    QProgressBar           *progressBar  = nullptr;
    QPushButton            *cancelButton = nullptr;
    QLabel                 *statusLabel  = nullptr;
};

// Worker class for async collection search
class CollectionSearchWorker : public QObject {
    Q_OBJECT

   public:
    explicit CollectionSearchWorker (QObject *parent = nullptr);

    struct SearchRequest {
        QString partialCollectionName;
        QString partialBinaryName;
        QString partialBinarySha256;
        QString modelName;
    };

   public slots:
    void performCollectionSearch (const SearchRequest &request);
    void cancel();

   signals:
    void progress (int percentage, const QString &message);
    void searchFinished (const CollectionInfos &collections);
    void searchError (const QString &error);

   private:
    bool m_cancelled;

    void emitProgress (int percentage, const QString &message) {
        if (!m_cancelled) {
            emit progress (percentage, message);
        }
    }
};

#endif // REAI_PLUGIN_CUTTER_UI_COLLECTION_SEARCH_DIALOG_HPP
