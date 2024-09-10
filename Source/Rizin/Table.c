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

/**
 * @brief Print table
 * */
void reai_plugin_table_show (ReaiPluginTable* table) {
    CString table_str = rz_table_tofancystring (table);
    if(!table_str) {
        DISPLAY_ERROR("Failed to convert table to string. Cannot display.");
        return;
    }
    rz_cons_printf ("%s\n", table_str);
}
