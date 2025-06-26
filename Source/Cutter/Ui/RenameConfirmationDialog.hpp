#ifndef RENAME_CONFIRMATION_DIALOG_HPP
#define RENAME_CONFIRMATION_DIALOG_HPP

/* qt */
#include <QDialog>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QPushButton>
#include <QLabel>

/* cutter */
#include <cutter/core/CutterDescriptions.h>

/* reai */
#include <Reai/Types.h>
#include <Reai/Api/Types/FunctionInfo.h>

// Structure to hold proposed rename information
struct ProposedRename {
    FunctionId functionId;
    QString    originalName;
    QString    proposedName;
    RVA        address;
    float      similarity;
    bool       selected; // Whether user wants to apply this rename

    ProposedRename() : functionId (0), address (0), similarity (0.0f), selected (true) {}
};

// Confirmation dialog for proposed function renames
class RenameConfirmationDialog : public QDialog {
    Q_OBJECT

   public:
    explicit RenameConfirmationDialog (const QList<ProposedRename> &renames, QWidget *parent = nullptr);

    // Get the list of renames that user approved
    QList<ProposedRename> getApprovedRenames() const;

   private slots:
    void onSelectAll();
    void onDeselectAll();
    void onItemChanged (QTableWidgetItem *item);

   private:
    void setupUI();
    void populateTable();
    void updateSummary(); // Update summary label and button states

    QList<ProposedRename> m_renames;
    QTableWidget         *m_tableWidget;
    QPushButton          *m_selectAllButton;
    QPushButton          *m_deselectAllButton;
    QPushButton          *m_okButton;
    QPushButton          *m_cancelButton;
    QLabel               *m_summaryLabel;
};

#endif // RENAME_CONFIRMATION_DIALOG_HPP