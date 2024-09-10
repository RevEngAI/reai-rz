/**
 * @file      : Table.cpp
 * @date      : 10th Sept 2024
 * @author    : Siddharth Mishra (admin@brightprogrammer.in)
 * @copyright : Copyright (c) 2024 RevEngAI. All Rights Reserved.
 *
 * Table API definitions for Cutter plugin only.
 * */

/* plugin */
#include <Plugin.h>
#include <Table.h>

/* qt */
#include <QDialog>

// TODO:
// struct ReaiPluginTable : public QDialog {
//     ReaiPluginTable(QWidget* parent);
// private:
// };

ReaiPluginTable* reai_plugin_table_create() {}
void             reai_plugin_table_destroy (ReaiPluginTable* table) {}
ReaiPluginTable* reai_plugin_table_set_columnsf (ReaiPluginTable* table, const char* fmtstr, ...) {}
ReaiPluginTable* reai_plugin_table_add_rowf (ReaiPluginTable* table, const char* fmtstr, ...) {}

/**
 * @brief Print table
 * */
void reai_plugin_table_show (ReaiPluginTable* table) {}
