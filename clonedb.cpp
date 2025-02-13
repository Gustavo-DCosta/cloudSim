#include <iostream>
#include <fstream>
#include <filesystem>
#include <sqlite3.h>

using namespace std;

void cloneDatabase(const std::string& source, const std::string& destination) {
    std::filesystem::copy(source, destination, std::filesystem::copy_options::overwrite_existing);
    std::cout << "Database cloned to: " << destination << std::endl;
}

void printUsersTable(const std::string& dbPath) {
    sqlite3* db;
    sqlite3_stmt* stmt;
    const char* query = "SELECT * FROM users";

    if (sqlite3_open(dbPath.c_str(), &db) != SQLITE_OK) {
        std::cerr << "Error opening database: " << sqlite3_errmsg(db) << std::endl;
        return;
    }

    if (sqlite3_prepare_v2(db, query, -1, &stmt, nullptr) != SQLITE_OK) {
        std::cerr << "Error preparing query: " << sqlite3_errmsg(db) << std::endl;
        sqlite3_close(db);
        return;
    }

    std::cout << "---Users table---" << std::endl;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        int cols = sqlite3_column_count(stmt);
        for (int i = 0; i < cols; i++) {
            const char* val = reinterpret_cast<const char*>(sqlite3_column_text(stmt, i));
            std::cout << (val ? val : "NULL") << " ";
        }
        std::cout << std::endl;
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
}

int main() {
     // Full path to the source database
    const std::string sourceDb = "C:\\Users\\veraf\\Desktop\\cloudSim\\C++\\data\\cloudSim.db";
    // Specify the subfolder for cloning
    const std::string subfolder = "C:\\Users\\veraf\\Desktop\\cloudSim\\C++\\data\\log_files";
    // Full path for the cloned database
    const std::string clonedDb = subfolder + "\\cloudSim_clonev2.db";

    // Create the subfolder if it doesn't exist
    std::filesystem::create_directories(subfolder);

    // Step 1: Clone the database
    cloneDatabase(sourceDb, clonedDb);

    // Step 2: Print the "users" table
    printUsersTable(clonedDb);

    return 0;
}