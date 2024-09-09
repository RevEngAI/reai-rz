/**
 * @file      : Table.h
 * @date      : 9th Sept 2024
 * @author    : Siddharth Mishra (admin@brightprogrammer.in)
 * @copyright : Copyright (c) 2024 RevEngAI. All Rights Reserved.
 *
 * @b Global plugin state management. This defines a singleton class
 * that needs to be accessed using the get method only.
 * */

#ifndef REAI_PLUGIN_TABLE_H
#define REAI_PLUGIN_TABLE_H

typedef struct ReaiPluginTable ReaiPluginTable;

ReaiPluginTable* reai_plugin_table_create();
void             reai_plugin_table_destroy (ReaiPluginTable* table);
ReaiPluginTable* reai_plugin_set_columnsf (ReaiPluginTable* table, const char* fmtstr, ...);
ReaiPluginTable* reai_plugin_table_add_rowf (ReaiPluginTable* table, const char* fmtstr, ...);

#endif // REAI_PLUGIN_TABLE_H
