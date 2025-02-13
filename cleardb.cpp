#include <iostream>
#include <sqlite3.h>

void dropAllTables(sqlite3* db) {
    char* errMsg = nullptr;
    sqlite3_stmt* stmt;

    // Step 1: Get the list of all tables in the database
    const char* sql = "SELECT name FROM sqlite_master WHERE type='table';";
    
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        std::cerr << "Failed to fetch tables: " << sqlite3_errmsg(db) << std::endl;
        return;
    }

    // Step 2: Loop through the results and drop each table
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const char* tableName = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        std::string dropSql = "DROP TABLE IF EXISTS " + std::string(tableName) + ";";

        // Execute the DROP TABLE command
        if (sqlite3_exec(db, dropSql.c_str(), nullptr, nullptr, &errMsg) != SQLITE_OK) {
            std::cerr << "Failed to drop table " << tableName << ": " << errMsg << std::endl;
            sqlite3_free(errMsg);
        } else {
            std::cout << "Dropped table: " << tableName << std::endl;
        }
    }

    // Clean up
    sqlite3_finalize(stmt);
}

int main() {
    sqlite3* db;
    int exit = sqlite3_open("cloudSim.db", &db); // Open the database

    if (exit) {
        std::cerr << "Error opening DB: " << sqlite3_errmsg(db) << std::endl;
        return exit;
    }

    dropAllTables(db); // Call the function to drop all tables

    sqlite3_close(db); // Close the database
    return 0;
}