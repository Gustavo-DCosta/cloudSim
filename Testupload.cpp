#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <sqlite3.h>
#include <algorithm>
/**
 * Executes an SQL statement without returning data.
 * @param db - Pointer to the SQLite database.
 * @param sql - The SQL command to execute.
 */

void executeSQL(sqlite3* db, const std::string& sql) {
    char* errorMessage = nullptr;
    if (sqlite3_exec(db, sql.c_str(), nullptr, nullptr, &errorMessage) != SQLITE_OK) {
        std::cerr << "Error executing SQL: " << errorMessage << std::endl;
        sqlite3_free(errorMessage);
    }
}

/**
 * Inserts a file into the database as a BLOB.
 * @param db - Pointer to the SQLite database.
 * @param filePath - Path to the file being uploaded.
 * @return true if the file was successfully inserted, false otherwise.
 */


bool insertFileIntoDatabase(sqlite3* db, const std::string& filePath) {
    // Open the file in binary mode and move to the end to get its size.
    std::ifstream file(filePath, std::ios::binary | std::ios::ate);
    if (!file) {
        std::cerr << "Failed to open file: " << filePath << std::endl;
        return false;
    }

    // Get the size of the file and read its contents into a buffer.
    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);
    std::vector<char> buffer(size);
    if (!file.read(buffer.data(), size)) {
        std::cerr << "Failed to read file: " << filePath << std::endl;
        return false;
    }

    // Prepare the SQL statement for inserting the file.
    const char* sql = "INSERT INTO files (name, data) VALUES (?, ?);";
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        std::cerr << "Failed to prepare statement: " << sqlite3_errmsg(db) << std::endl;
        return false;
    }

    // Extract the file name from the file path and bind it as the first parameter.
    std::string fileName = filePath.substr(filePath.find_last_of("/\\") + 1);
    sqlite3_bind_text(stmt, 1, fileName.c_str(), -1, SQLITE_STATIC);
    
    // Bind the file's binary data as the second parameter.
    sqlite3_bind_blob(stmt, 2, buffer.data(), buffer.size(), SQLITE_STATIC);

    // Execute the prepared statement and check for errors.
    if (sqlite3_step(stmt) != SQLITE_DONE) {
        std::cerr << "Failed to execute statement: " << sqlite3_errmsg(db) << std::endl;
        sqlite3_finalize(stmt);
        return false;
    }

    // Finalize the statement and confirm success.
    sqlite3_finalize(stmt);
    std::cout << "File " << fileName << " uploaded successfully.\n";
    return true;
}

std::string sanitizeFileName(const std::string& fileName) {
    std::string sanitized = fileName;
    for (char& ch : sanitized) {
        if (ch == ' ') {
            ch = '-'; // Replace spaces with hyphens
        } else if (ch == '\'') {
            ch = '_'; // Replace apostrophes with underscores
        }
    }
    return sanitized;
}


/**
 * Prints the content of the database to the console.
 * Displays the ID, file name, and size of each file.
 * @param db - Pointer to the SQLite database.
 */
void printDatabaseContent(sqlite3* db) {
    const char* sql = "SELECT id, name, LENGTH(data) FROM files;";
    sqlite3_stmt* stmt;

    // Prepare the SQL query to select file details.
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        std::cerr << "Failed to prepare statement: " << sqlite3_errmsg(db) << std::endl;
        return;
    }

    // Print a header for the database content.
    std::cout << "\nDatabase Content:\n";
    std::cout << "ID | Name       | Size (bytes)\n";
    std::cout << "-------------------------------\n";

    // Loop through the result set and print each row.
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        int id = sqlite3_column_int(stmt, 0); // Get the file ID.
        const unsigned char* name = sqlite3_column_text(stmt, 1); // Get the file name.
        int size = sqlite3_column_int(stmt, 2); // Get the file size.

        std::cout << id << "  | " << name << " | " << size << " bytes\n";
    }

    // Finalize the statement to release resources.
    sqlite3_finalize(stmt);
}

int main() {
    // Open the SQLite database or create it if it doesn't exist.
    sqlite3* db;
    if (sqlite3_open("cloudSim.db", &db) != SQLITE_OK) {
        std::cerr << "Failed to open database: " << sqlite3_errmsg(db) << std::endl;
        return 1;
    }

    // Create the files table if it doesn't already exist.
    const std::string createTableSQL = R"(
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            data BLOB NOT NULL
        );
    )";
    executeSQL(db, createTableSQL);

    // Prompt the user for a file path to upload.
    std::string filePath;
    std::cout << "Enter the file path to upload: ";
    std::getline(std::cin, filePath);

    // Extract the file name and sanitize it.
    std::string fileName = filePath.substr(filePath.find_last_of("/\\") + 1);
    std::string sanitizedFileName = sanitizeFileName(fileName);

    std::cout << "Sanitized file name: " << sanitizedFileName << std::endl;

    // Insert the file into the database and display its content.
    if (insertFileIntoDatabase(db, filePath)) { // Use original file path to read the file.
        printDatabaseContent(db);
    }

    // Close the database to release resources.
    sqlite3_close(db);
    return 0;
}