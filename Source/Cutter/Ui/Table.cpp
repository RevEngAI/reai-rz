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

/* qt */
#include <QDialog>
#include <QTableWidget>
#include <QVBoxLayout>
#include <QHeaderView>

/* lib stdc++ */
#include <iomanip>
#include <sstream>

enum class ColumnType {
    INVALID,
    STRING,
    BOOLEAN,
    INTEGER,
    NUMBER,
    SIZE,
    DOUBLE,
    HEX_SMALL,
    HEX_CAPS
};

PRIVATE QString    getItemStringFromVaListBasedOnType (ColumnType type, va_list args);
PRIVATE ColumnType getColumnTypeFromFormatChar (Char format_char);

/**
 * @b Cutter internal implementation of plugin table.
 * */
struct ReaiPluginTable : public QDialog {
    Q_OBJECT;

   public:
    ReaiPluginTable() : QDialog (nullptr) {
        QVBoxLayout* mainLayout = new QVBoxLayout (this);
        setLayout (mainLayout);

        table = new QTableWidget (this);
        // Turn off editing
        table->setEditTriggers (QAbstractItemView::NoEditTriggers);
        // Allow columns to stretch as much as posible
        table->horizontalHeader()->setSectionResizeMode (QHeaderView::Stretch);

        mainLayout->addWidget (table);

        // NOTE: this hardcoded, do we need to create an API for setting table title as welll?
        // In rizin, it would just print the title before printing table, in cutter it would set window title
        setWindowTitle ("Auto Analysis Results");
        resize (600, 300);
    }

    /**
     * @b Add a new column to this table with given name and type.
     * */
    void addColumn (ColumnType type, const char* name) {
        cols.push_back (std::make_pair (QString (name), type));

        table->insertColumn (table->columnCount());

        QStringList headerLabels;
        for (const auto& [name, type] : cols) {
            headerLabels << name;
        }
        table->setHorizontalHeaderLabels (headerLabels);
    }

    /**
     * @b Add a new row into the table.
     * */
    void addRow (const std::vector<QString>& row) {
        if (row.size() != cols.size()) {
            DISPLAY_ERROR (
                "Row item count mismatch with number of columns. Cannot insert new row to table."
            );
            return;
        }

        Size rowCount = table->rowCount();
        table->insertRow (rowCount);

        LOG_DEBUG ("Adding new row at %zu", rowCount);

        for (Size i = 0; i < cols.size(); i++) {
            table->setItem (rowCount, i, new QTableWidgetItem (row[i]));

            LOG_DEBUG (
                "Inserting item \"%s\" at row = %zu and colu = %zu",
                row[i].toLatin1().constData(),
                rowCount,
                i
            );
        }
    }

    QTableWidget*                               table;
    std::vector<std::pair<QString, ColumnType>> cols;
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

    va_list args;
    va_start (args, fmtstr);

    LOG_DEBUG ("Setting columns");

    size_t len = strlen (fmtstr);
    for (size_t i = 0; i < len; ++i) {
        char format_char = fmtstr[i];

        /* all column names are of type const char* */
        CString column_name = va_arg (args, CString);
        table->addColumn (getColumnTypeFromFormatChar (format_char), column_name);

        LOG_DEBUG ("New column \"%s\"", column_name);
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

    va_list args;
    va_start (args, fmtstr);

    std::vector<QString> row;
    size_t               colIndex = 0;

    LOG_DEBUG ("Adding new row with format string \"%s\"", fmtstr);
    while (*fmtstr) {
        if (colIndex >= table->cols.size()) {
            LOG_ERROR ("Give format string size is larger than number of columns in table.");
            break;
        }

        QString value =
            getItemStringFromVaListBasedOnType (getColumnTypeFromFormatChar (*fmtstr), args);
        row.push_back (value);

        LOG_DEBUG (
            "Fetched \"%s\" value for format char \"%c\"",
            value.toLatin1().constData(),
            *fmtstr
        );

        colIndex++;
        fmtstr++;
    }

    va_end (args);

    table->addRow (row);
    return table;
}

/**
 * @brief Print table
 * */
void reai_plugin_table_show (ReaiPluginTable* table) {
    table->show();
}

PRIVATE QString getItemStringFromVaListBasedOnType (ColumnType type, va_list args) {
    std::ostringstream oss;
    switch (type) {
        case ColumnType::STRING : {
            CString str = va_arg (args, CString);
            return QString (str);
        }
        case ColumnType::BOOLEAN : {
            Bool b = va_arg (args, Int32); // va_arg promotes bool to int
            return b ? QString ("true") : QString ("false");
        }
        case ColumnType::INTEGER : {
            Int32 i = va_arg (args, Int32);
            oss << i;
            return QString::fromStdString (oss.str());
        }
        case ColumnType::NUMBER : {
            Uint64 n = va_arg (args, Uint64);
            oss << n;
            return QString::fromStdString (oss.str());
        }
        case ColumnType::SIZE : {
            Uint64 size = va_arg (args, Uint64);
            oss << size;
            return QString::fromStdString (oss.str());
        }
        case ColumnType::DOUBLE : {
            Float64 d = va_arg (args, Float64);
            oss << d;
            return QString::fromStdString (oss.str());
        }
        case ColumnType::HEX_SMALL : {
            Int32 x = va_arg (args, Int32);
            oss << std::hex << x;
            return QString::fromStdString (oss.str());
        }
        case ColumnType::HEX_CAPS : {
            Int32 x = va_arg (args, Int32);
            oss << std::hex << std::uppercase << x;
            return QString::fromStdString (oss.str());
        }
        default :
            return QString();
    }
}


PRIVATE ColumnType getColumnTypeFromFormatChar (Char format_char) {
    switch (format_char) {
        case 's' :
        case 'z' :
            return ColumnType::STRING;
        case 'b' :
            return ColumnType::BOOLEAN;
        case 'i' :
        case 'd' :
            return ColumnType::INTEGER;
        case 'n' :
            return ColumnType::NUMBER;
        case 'u' :
            return ColumnType::SIZE;
        case 'f' :
            return ColumnType::DOUBLE;
        case 'x' :
            return ColumnType::HEX_SMALL;
        case 'X' :
            return ColumnType::HEX_CAPS;
        default :
            return ColumnType::INVALID;
    }
}

#include "Table.moc"
