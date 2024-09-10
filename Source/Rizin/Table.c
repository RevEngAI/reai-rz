/**
 * @file      : Table.c
 * @date      : 10th Sept 2024
 * @author    : Siddharth Mishra (admin@brightprogrammer.in)
 * @copyright : Copyright (c) 2024 RevEngAI. All Rights Reserved.
 *
 * Table API definitions for Rizin plugin only.
 * */

/* plugin */
#include <Plugin.h>
#include <Table.h>

/* rizin */
#include <rz_util/rz_table.h>

typedef enum ColumnType {
    INVALID,
    STRING,
    BOOLEAN,
    INTEGER,
    NUMBER,
    SIZE,
    DOUBLE,
    HEX_SMALL,
    HEX_CAPS
} ColumnType;

PRIVATE const char* getItemStringFromVaListBasedOnType (ColumnType type, va_list args);
PRIVATE ColumnType  getColumnTypeFromFormatChar (Char format_char);

/**
 * @b Create plugin table for Rizin plugin.
 *
 * This will internally create a `RzTable` and externally treat it as a new type.
 * This is a hack to avoid defining a new type and allocating memory of it as well as `RzTable`.
 *
 * This means that for Rizin plugin, this datatype is always incomplete.
 *
 * @return @c ReaiPluginTable on success.
 * @return @c Null otherwise.
 * */
ReaiPluginTable* reai_plugin_table_create() {
    RzTable* table = rz_table_new();

    if (!table) {
        DISPLAY_ERROR ("Failed to create table");
        return NULL;
    }

    return (ReaiPluginTable*)table;
}

/**
 * @b Destroy given @c ReaiPluginTable object.
 *
 * @param table Table to be destroyed.
 * */
void reai_plugin_table_destroy (ReaiPluginTable* table) {
    if (!table) {
        DISPLAY_ERROR ("Invalid table. Cannot destroy a NULL table.");
        return;
    }

    rz_table_free ((RzTable*)table);
}

/**
 * @b Add columns with given format and names.
 *
 * @param table Table to add columns to.
 * @param fmtstr Table column format (ordering and type)
 * @param ... Variadic arguments respecting the provided format.
 *
 * @return Non NULL @c ReaiPluginTable (same as @c table) on success.
 * @return @c NULL otherwise.
 * */
ReaiPluginTable* reai_plugin_table_set_columnsf (ReaiPluginTable* table, const char* fmtstr, ...) {
    if (!table) {
        DISPLAY_ERROR ("Invalid table provided. Cannot set column information.");
        return NULL;
    }

    if (!fmtstr) {
        DISPLAY_ERROR ("Invalid format string provided. Cannot add columns.");
        return NULL;
    }

    RzTable* rz_table = (RzTable*)table;

    va_list ap;
    va_start (ap, fmtstr);
    rz_table_set_vcolumnsf (rz_table, fmtstr, ap);
    va_end (ap);

    return table;
}

/**
 * @b Add a row to table with given format and given values.
 *
 * @param table Table to add row to.
 * @param fmtstr Table column format (ordering and type)
 * @param ... Variadic arguments respecting the provided format.
 *
 * @return Non NULL @c ReaiPluginTable (same as @c table) on success.
 * @return @c NULL otherwise.
 * */
ReaiPluginTable* reai_plugin_table_add_rowf (ReaiPluginTable* table, const char* fmtstr, ...) {
    if (!table) {
        DISPLAY_ERROR ("Invalid table provided. Cannot add new row.");
        return NULL;
    }

    if (!fmtstr) {
        DISPLAY_ERROR ("Invalid format string provided. Cannot add row.");
        return NULL;
    }

    va_list ap;
    va_start (ap, fmtstr);

	RzPVector *row = rz_pvector_new(free);
	for (const char *f = fmtstr; *f; f++) {
        rz_pvector_push(row, (void*)getItemStringFromVaListBasedOnType(getColumnTypeFromFormatChar(*f), ap));
	}
	rz_table_add_row_vec((RzTable*)table, row);

    va_end (ap);

    return table;
}

/**
 * @brief Print table
 * */
void reai_plugin_table_show (ReaiPluginTable* table) {
    CString table_str = rz_table_tofancystring ((RzTable*)table);
    if (!table_str) {
        DISPLAY_ERROR ("Failed to convert table to string. Cannot display.");
        return;
    }
    rz_cons_printf ("%s\n", table_str);
}

PRIVATE const char* getItemStringFromVaListBasedOnType (ColumnType type, va_list args) {
    switch (type) {
        case STRING : {
            const char* str = va_arg (args, const char*);
            return strdup (str);
        }
        case BOOLEAN : {
            bool b = va_arg (args, int); // va_arg promotes bool to int
            return b ? strdup ("true") : strdup ("false");
        }
        case INTEGER : {
            int i = va_arg (args, int);
            FMT (str_i, "%d", i);
            return strdup (str_i);
        }
        case NUMBER : {
            unsigned long long n = va_arg (args, unsigned long long);
            FMT (str_llu, "%llu", n);
            return strdup (str_llu);
        }
        case SIZE : {
            size_t  size    = va_arg (args, size_t);
            CString units[] = {"B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB"};

            size_t unit_index = 0;
            while (size >= 1024 && unit_index < ARRAY_SIZE (units) - 1) {
                size /= 1024;
                unit_index++;
            }

            FMT (str_unit, "%zu %s", size, units[unit_index]);
            return strdup (str_unit);
        }
        case DOUBLE : {
            double d = va_arg (args, double);
            FMT (str_double, "%lf", d);
            return strdup (str_double);
        }
        case HEX_SMALL : {
            int x = va_arg (args, int);
            FMT (str_hex, "%x", x);
            return strdup (str_hex);
        }
        case HEX_CAPS : {
            int x = va_arg (args, int);
            FMT (str_hex, "%X", x);
            return strdup (str_hex);
        }
        default :
            return strdup ("");
    }
}


PRIVATE ColumnType getColumnTypeFromFormatChar (Char format_char) {
    switch (format_char) {
        case 's' :
        case 'z' :
            return STRING;
        case 'b' :
            return BOOLEAN;
        case 'i' :
        case 'd' :
            return INTEGER;
        case 'n' :
            return NUMBER;
        case 'u' :
            return SIZE;
        case 'f' :
            return DOUBLE;
        case 'x' :
            return HEX_SMALL;
        case 'X' :
            return HEX_CAPS;
        default :
            return INVALID;
    }
}
