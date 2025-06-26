#include "RenameConfirmationDialog.hpp"

/* qt */
#include <QAbstractItemView>
#include <QBrush>

// RenameConfirmationDialog implementation
RenameConfirmationDialog::RenameConfirmationDialog (const QList<ProposedRename> &renames, QWidget *parent)
    : QDialog (parent), m_renames (renames) {
    setupUI();
    populateTable();
}

void RenameConfirmationDialog::setupUI() {
    setWindowTitle ("Confirm Function Renames");
    setModal (true);
    resize (800, 600);

    QVBoxLayout *mainLayout = new QVBoxLayout (this);

    // Summary label
    m_summaryLabel = new QLabel();
    m_summaryLabel->setStyleSheet ("font-weight: bold; color: #2E7D32;");
    mainLayout->addWidget (m_summaryLabel);

    // Table widget
    m_tableWidget = new QTableWidget();
    m_tableWidget->setColumnCount (5);
    QStringList headers = {"Apply", "Original Name", "Proposed Name", "Address", "Similarity"};
    m_tableWidget->setHorizontalHeaderLabels (headers);
    m_tableWidget->setSelectionBehavior (QAbstractItemView::SelectRows);
    m_tableWidget->setAlternatingRowColors (true);
    m_tableWidget->setSortingEnabled (true);

    // Set column widths
    m_tableWidget->setColumnWidth (0, 60);  // Apply checkbox
    m_tableWidget->setColumnWidth (1, 200); // Original name
    m_tableWidget->setColumnWidth (2, 200); // Proposed name
    m_tableWidget->setColumnWidth (3, 120); // Address
    m_tableWidget->setColumnWidth (4, 100); // Similarity

    mainLayout->addWidget (m_tableWidget);

    // Selection buttons
    QHBoxLayout *selectionLayout = new QHBoxLayout();
    m_selectAllButton            = new QPushButton ("Select All");
    m_deselectAllButton          = new QPushButton ("Deselect All");
    selectionLayout->addWidget (m_selectAllButton);
    selectionLayout->addWidget (m_deselectAllButton);
    selectionLayout->addStretch();
    mainLayout->addLayout (selectionLayout);

    // Dialog buttons
    QHBoxLayout *buttonLayout = new QHBoxLayout();
    m_cancelButton            = new QPushButton ("Cancel");
    m_okButton                = new QPushButton ("Apply Selected Renames");
    m_okButton->setDefault (true);
    m_okButton->setStyleSheet ("QPushButton { background-color: #4CAF50; color: white; font-weight: bold; }");

    buttonLayout->addStretch();
    buttonLayout->addWidget (m_cancelButton);
    buttonLayout->addWidget (m_okButton);
    mainLayout->addLayout (buttonLayout);

    // Connect signals
    connect (m_selectAllButton, &QPushButton::clicked, this, &RenameConfirmationDialog::onSelectAll);
    connect (m_deselectAllButton, &QPushButton::clicked, this, &RenameConfirmationDialog::onDeselectAll);
    connect (m_tableWidget, &QTableWidget::itemChanged, this, &RenameConfirmationDialog::onItemChanged);
    connect (m_okButton, &QPushButton::clicked, this, &QDialog::accept);
    connect (m_cancelButton, &QPushButton::clicked, this, &QDialog::reject);
}

void RenameConfirmationDialog::populateTable() {
    // Block signals during population to prevent race condition
    m_tableWidget->blockSignals (true);

    m_tableWidget->setRowCount (m_renames.size());

    for (int i = 0; i < m_renames.size(); ++i) {
        const ProposedRename &rename = m_renames[i];

        // Apply checkbox
        QTableWidgetItem *checkItem = new QTableWidgetItem();
        checkItem->setCheckState (rename.selected ? Qt::Checked : Qt::Unchecked);
        checkItem->setFlags (Qt::ItemIsUserCheckable | Qt::ItemIsEnabled);
        m_tableWidget->setItem (i, 0, checkItem);

        // Original name
        QTableWidgetItem *originalItem = new QTableWidgetItem (rename.originalName);
        originalItem->setFlags (Qt::ItemIsEnabled);
        m_tableWidget->setItem (i, 1, originalItem);

        // Proposed name
        QTableWidgetItem *proposedItem = new QTableWidgetItem (rename.proposedName);
        proposedItem->setFlags (Qt::ItemIsEnabled);
        proposedItem->setForeground (QBrush (QColor ("#1976D2"))); // Blue color for proposed names
        m_tableWidget->setItem (i, 2, proposedItem);

        // Address
        QTableWidgetItem *addressItem = new QTableWidgetItem (QString ("0x%1").arg (rename.address, 0, 16));
        addressItem->setFlags (Qt::ItemIsEnabled);
        m_tableWidget->setItem (i, 3, addressItem);

        // Similarity
        QTableWidgetItem *similarityItem = new QTableWidgetItem (QString ("%1%").arg (rename.similarity, 0, 'f', 1));
        similarityItem->setFlags (Qt::ItemIsEnabled);

        // Color code similarity
        if (rename.similarity >= 90.0f) {
            similarityItem->setForeground (QBrush (QColor ("#4CAF50"))); // Green
        } else if (rename.similarity >= 80.0f) {
            similarityItem->setForeground (QBrush (QColor ("#FF9800"))); // Orange
        } else {
            similarityItem->setForeground (QBrush (QColor ("#F44336"))); // Red
        }

        m_tableWidget->setItem (i, 4, similarityItem);
    }

    // Unblock signals and update summary safely
    m_tableWidget->blockSignals (false);
    updateSummary();
}

void RenameConfirmationDialog::updateSummary() {
    int selectedCount = 0;
    for (int i = 0; i < m_tableWidget->rowCount(); ++i) {
        QTableWidgetItem *item = m_tableWidget->item (i, 0);
        if (item && item->checkState() == Qt::Checked) {
            selectedCount++;
        }
    }

    m_summaryLabel->setText (
        QString ("Found %1 potential renames, %2 selected for application").arg (m_renames.size()).arg (selectedCount)
    );

    m_okButton->setEnabled (selectedCount > 0);
    m_okButton->setText (
        selectedCount > 0 ? QString ("Apply %1 Selected Renames").arg (selectedCount) : "No Renames Selected"
    );
}

QList<ProposedRename> RenameConfirmationDialog::getApprovedRenames() const {
    QList<ProposedRename> approved;

    for (int i = 0; i < m_tableWidget->rowCount(); ++i) {
        QTableWidgetItem *item = m_tableWidget->item (i, 0);
        if (item && item->checkState() == Qt::Checked) {
            approved.append (m_renames[i]);
        }
    }

    return approved;
}

void RenameConfirmationDialog::onSelectAll() {
    for (int i = 0; i < m_tableWidget->rowCount(); ++i) {
        QTableWidgetItem *item = m_tableWidget->item (i, 0);
        if (item) {
            item->setCheckState (Qt::Checked);
        }
    }
}

void RenameConfirmationDialog::onDeselectAll() {
    for (int i = 0; i < m_tableWidget->rowCount(); ++i) {
        QTableWidgetItem *item = m_tableWidget->item (i, 0);
        if (item) {
            item->setCheckState (Qt::Unchecked);
        }
    }
}

void RenameConfirmationDialog::onItemChanged (QTableWidgetItem *item) {
    if (item->column() == 0) { // Checkbox column
        updateSummary();
    }
}