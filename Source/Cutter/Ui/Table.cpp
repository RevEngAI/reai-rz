/**
 * @file      : Table.cpp
 * @date      : 10th Sept 2024
 * @author    : Siddharth Mishra (admin@brightprogrammer.in)
 * @copyright : Copyright (c) 2024 RevEngAI. All Rights Reserved.
 *
 * Table API definitions for Cutter plugin only.
 * */

/* plugin */
#include "Reai/Types.h"
#include <Plugin.h>
#include <Table.h>
#include <rz_util/rz_table.h>

/* qt */
#include <QDialog>
#include <QTableWidget>
#include <QVBoxLayout>
#include <QHeaderView>

/**
 * @b Cutter internal implementation of plugin table.
 * */
struct ReaiPluginTable : public QDialog {
    Q_OBJECT;

   public:
    ReaiPluginTable() : QDialog (nullptr) {
        QVBoxLayout* mainLayout = new QVBoxLayout (this);
        setLayout (mainLayout);

        tableWidget = new QTableWidget (this);
        // Turn off editing
        tableWidget->setEditTriggers (QAbstractItemView::NoEditTriggers);
        // Allow columns to stretch as much as posible
        tableWidget->horizontalHeader()->setSectionResizeMode (QHeaderView::Stretch);

        mainLayout->addWidget (tableWidget);

        // NOTE: this hardcoded, do we need to create an API for setting table title as welll?
        // In rizin, it would just print the title before printing table, in cutter it would set window title
        setWindowTitle ("Auto Analysis Results");
        resize (600, 300);

        /* we also need the RzTable to be created to pull out contents from it after adding formatted rows */
        rzTable = rz_table_new();
        if (!rzTable) {
            DISPLAY_ERROR ("Failed to create table. Behaviour is undefined if table is used.");
        }
    }

    /**
     * @b Add a new column to this table with given name and type.
     * */
    void addColumn (const char* name) {
        tableWidget->insertColumn (tableWidget->columnCount());

        headerLabels << name;
        tableWidget->setHorizontalHeaderLabels (headerLabels);
    }

    /**
     * @b Add a new row into the table.
     * */
    void addRow (const QStringList& row) {
        if (row.size() != headerLabels.size()) {
            DISPLAY_ERROR (
                "Row item count mismatch with number of columns. Cannot insert new row to table."
                "Row item count = %lld and Column count = %lld",
                row.size(),
                headerLabels.size()
            );
            return;
        }

        /* add a new row to table widget */
        Size rowCount = tableWidget->rowCount();
        tableWidget->insertRow (rowCount);

        LOG_TRACE ("Adding new row at %zu", rowCount);

        /* populate the new row */
        for (Int32 i = 0; i < headerLabels.size(); i++) {
            tableWidget->setItem (rowCount, i, new QTableWidgetItem (row[i]));

            LOG_TRACE (
                "Inserting item \"%s\" at row = %zu and colu = %zu",
                row[i].toLatin1().constData(),
                rowCount,
                i
            );
        }
    }

    QTableWidget* tableWidget;
    RzTable*      rzTable;
    QStringList   headerLabels;
};

/**
 * @b Create a new plugin table for Cutter.
 * Call `reai_plugin_table_destroy` after use.
 *
 * @return ReaiPluginTable pointer on success.
 * @return Null otherwise.
 * */
ReaiPluginTable* reai_plugin_table_create() {
    return new ReaiPluginTable;
}

/**
 * @b Destroy a given plugin table after use.
 *
 * @param table Table to be destroyed.
 * */
void reai_plugin_table_destroy (ReaiPluginTable* table) {
    delete table;
}

/**
 * @b Add column names to table.
 *
 * @return ReaiPluginTable* on success.
 * @return Null otherwise.
 * */
ReaiPluginTable* reai_plugin_table_set_columnsf (ReaiPluginTable* table, const char* fmtstr, ...) {
    if (!table || !fmtstr) {
        return nullptr; // Handle null pointers
    }

    va_list args, rzArgs;
    va_start (args, fmtstr);

    /* add column information to RzTable as well */
    va_copy (rzArgs, args);
    rz_table_set_vcolumnsf (table->rzTable, fmtstr, rzArgs);
    va_end (rzArgs);

    LOG_TRACE ("Setting columns");

    size_t len = strlen (fmtstr);
    for (size_t i = 0; i < len; ++i) {
        /* all column names are of type CString */
        CString column_name = va_arg (args, CString);
        table->addColumn (column_name);
        LOG_TRACE ("New column \"%s\"", column_name);
    }

    va_end (args);
    return table;
}

/**
 * @b Add a new row to table with given format and va args.
 *
 * @param table Table to add new row into.
 * @param fmtstr Format string specifying type of argument and at what position.
 * @param ... Variadic argument list specifying the data to be added into new row.
 *
 * @return ReaiPluginTable* on success.
 * @return Null otherwise.
 * */
ReaiPluginTable* reai_plugin_table_add_rowf (ReaiPluginTable* table, const char* fmtstr, ...) {
    if (!table || !fmtstr) {
        return nullptr; // Handle null pointers
    }

    /* first add all data into rizin table */
    va_list args;
    va_start (args, fmtstr);
    rz_table_add_vrowf (table->rzTable, fmtstr, args);
    va_end (args);

    /* get last added row from RzTable */
    RzVector* /* RzPVector */    rzTableRows = table->rzTable->rows;
    RzPVector* /* const char* */ rzRow       = ((RzTableRow*)rz_vector_tail (rzTableRows))->items;

    /* create a new row of strings for ReaiPluginTable */
    QStringList row;
    void**      cellData = NULL;
    rz_pvector_foreach (rzRow, cellData) {
        CString cellValue = *(CString*)cellData;
        LOG_TRACE ("Adding cell value \"%s\" to new row", cellValue);
        row << cellValue;
    }

    /* finally add the row to table */
    table->addRow (row);

    return table;
}

/**
 * @brief Print table
 * */
void reai_plugin_table_show (ReaiPluginTable* table) {
    table->exec();
}

#include "Table.moc"
