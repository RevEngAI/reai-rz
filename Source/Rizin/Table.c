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
    rz_table_add_vrowf ((RzTable*)table, fmtstr, ap);
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
