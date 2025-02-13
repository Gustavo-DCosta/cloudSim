#include <iostream>
#include <fstream> 
#include <filesystem>
#include <sqlite3.h>
#include <cstdlib>
#include <ctime>
#include <string>
#include <iomanip>
#include <sstream>
#include <random>
#include <openssl/sha.h>
#include <iterator>
#include <set>
#include <cstdio> // For std::rename
#include <tchar.h>
#include <windows.h>
#include <sys/stat.h>
#include <aclapi.h>


namespace fs = std::filesystem;
using namespace std;


// Rotate right (ROR) operation
unsigned long long rotateRight(unsigned long long value, int bits) {
    return (value >> bits) | (value << (64 - bits));
}

// Secure Random Salt Generator
string generateSalt(size_t length) {
    random_device rd;
    mt19937 generator(rd());
    uniform_int_distribution<int> dist(0, 255);
    
    string salt;
    for (size_t i = 0; i < length; ++i) {
        salt += static_cast<char>(dist(generator));
    }
    return salt;
}

// Example SHA-512 Function (Simplified for Illustration)
string sha512(const string &input) {
    // Initialize hash values, constants, etc.
    unsigned long long H[8] = {
        0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 
        0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1, 
        0x510e527fade682d1, 0x9b05688c2b3e6c1f, 
        0x1f83d9abfb41bd6b, 0x5be0cd19137e2179
    };

    // Pre-processing and chunking omitted for brevity
    // Main compression loop should go here

    // Produce final hash value
    ostringstream result;
    for (int i = 0; i < 8; ++i) {
        result << hex << setw(16) << setfill('0') << H[i];
    }
    return result.str();
}

// Function to count letters in a string
int countLetters(const string& str) {
    int count = 0;
    for (char ch : str) {
        if (isalpha(ch)) { // Check if character is a letter
            count++;
        }
    }
    return count;
}

// Callback function to print the result of the SELECT query
static int callback(void* NotUsed, int argc, char** argv, char** azColName) {
    for (int i = 0; i < argc; i++) {
        cout << azColName[i] << ": " << (argv[i] ? argv[i] : "NULL") << endl;
    }
    cout << "--------------------------" << endl;
    return 0;
}

// Function declarations
void partitions_disk();
void set_permissions(const fs::path& specified_path, fs::perms permissions);
void directory_print(const std::filesystem::path& specified_path);
void list_files_recursively(const std::string& specified_path);
void print_directory_stats(const std::string& specified_path);
void registerUser(sqlite3* db);
bool loginUser(sqlite3* db, string& email, string& password);
void uploadFile(const std::string& filePath, const std::string& destinationDir);
bool insertFileIntoDatabase(sqlite3* db, const std::string& filePath);
void printDatabaseContent(sqlite3* db);
void executeSQL(sqlite3* db, const std::string& query);
void menu_main(sqlite3* db);
void createFilesTable(sqlite3* db);


// Function to create the files table
void createFilesTable(sqlite3* db) {
    const char* sql = R"(
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            data BLOB NOT NULL
        );
    )";

    char* errMsg = nullptr;
    if (sqlite3_exec(db, sql, nullptr, nullptr, &errMsg) != SQLITE_OK) {
        std::cerr << "Failed to create files table: " << errMsg << std::endl;
        sqlite3_free(errMsg);
    } else {
        std::cout << "Files table created successfully.\n";
    }
}

// Function to handle user registration
void registerUser(sqlite3* db) {
    char* errMessage = 0;
    srand(time(0)); // seed the random number generator

    const char* alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    int random_index = rand() % 52; // 52 is the length of the alphabet string
    char random_letter = alphabet[random_index];

    string email, password;
    int phone_number;
    char ID = random_letter; // Assigns a random letter as the ID

    // Take user input
    cout << "This is your ID: " << ID << endl;
    cout << "Enter your e-mail please: ";
    cin >> email;
    cout << "Enter your password: ";
    cin >> password;
    cout << "Enter your phone number please: ";
    cin >> phone_number;

    // Loop until the user provides a password with more than 3 letters
    while (true) {
        cout << "Enter your password: ";
        getline(cin, password);

        // Count the number of letters in the password
        int letterCount = countLetters(password);

        if (letterCount > 3) {
            break; // Exit the loop if the password is valid
        } else {
            cout << "Error: Password must contain more than 3 letters.\n";
        }
    }

    // Step 1: Generate a salt
    string salt = generateSalt(16); // 16 bytes of random salt

    // Step 2: Combine the data and salt
    string combined = salt + password;

    // Step 3: Hash the combined data
    string hash = sha512(combined);
    // print salt
    cout << "Salt: " << salt << endl;
    // Output: Display and hash
    cout << "Hash: " << hash << endl;

    // Create SQL insert statement
    string sql = "INSERT INTO users (ID, email, password, phone_number, salt) VALUES ('" + 
             string(1, ID) + "', '" + email + "', '" + hash + "', " + 
             to_string(phone_number) + ", '" + salt + "');";


    // Execute the SQL statement
    int exit = sqlite3_exec(db, sql.c_str(), 0, 0, &errMessage);
    if (exit != SQLITE_OK) {
        cerr << "SQL error: " << errMessage << endl;
        sqlite3_free(errMessage);
    } else {
        cout << "Record inserted successfully!" << endl;
    }
}

// Function to handle user login
bool loginUser(sqlite3* db, string& email, string& password) {
    cout << "\nLogin" << endl;
    cout << "Enter your email: ";
    cin >> email;
    cout << "Enter your password: ";
    cin >> password;

    // Prepare the SQL query with parameterized inputs
    string sql = "SELECT salt, password FROM users WHERE email = ?;";
    sqlite3_stmt* stmt;

    int rc = sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        cerr << "Failed to prepare statement: " << sqlite3_errmsg(db) << endl;
        return false;
    }

    // Bind the email parameter
    sqlite3_bind_text(stmt, 1, email.c_str(), -1, SQLITE_STATIC);

    // Execute the query
    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        // Retrieve the salt and hashed password from the database
        string dbSalt = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        string dbPassword = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));

        // Combine the retrieved salt with the entered password and hash it
        string combined = dbSalt + password;
        string hashedInput = sha512(combined);
        if (hashedInput == dbPassword) {
            cout << "Login successful!" << endl;
            partitions_disk();
            menu_main(db);
            sqlite3_finalize(stmt);
            return true;
        } else {
            cout << "Incorrect password!" << endl;
        }
    } else {
        cout << "No user found with this email!" << endl;
    }

    // Finalize the statement and return false if login fails
    sqlite3_finalize(stmt);
    return false;
}

void stats_log(int main_choice, const string& email, const string& password, const string& ID, int phone_number) {
    auto start = std::chrono::system_clock::now();
    // Some computation here
    auto end = std::chrono::system_clock::now();

    std::chrono::duration<double> elapsed_seconds = end - start;
    std::time_t end_time = std::chrono::system_clock::to_time_t(end);

    std::ofstream output_file("log.txt", std::ios::app); // Append to the file if it exists
    if (output_file.is_open()) {
        if (main_choice == 1) {
            output_file << "Action: Account Created" << std::endl;
        } else if (main_choice == 2) {
            output_file << "Action: Logged in an account" << std::endl;
        }

        // Write details to the log file
        output_file << "Email: " << email << std::endl
                    << "Password: " << password << std::endl
                    << "ID: " << ID << std::endl
                    << "Phone Number: " << phone_number << std::endl
                    << "Finished computation at " << std::ctime(&end_time)
                    << "Elapsed time: " << elapsed_seconds.count() << "s\n"
                    << "__________________________________________________" << std::endl;

        output_file.close();
        std::cout << "________Date and time written to log.txt successfully________.\n";
    } else {
        std::cerr << "Error opening file for writing.\n";
    }
}

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

void partitions_disk() {
    char drive_letter[] = "A:\\";
    std::cout << "Disk Partitions Information:\n";

    for (char drive = 'A'; drive <= 'Z'; ++drive) {
        drive_letter[0] = drive;
        if (GetDriveTypeA(drive_letter) != DRIVE_NO_ROOT_DIR) {
            ULARGE_INTEGER freeBytesAvailable, totalBytes, totalFreeBytes;
            if (GetDiskFreeSpaceExA(drive_letter, &freeBytesAvailable, &totalBytes, &totalFreeBytes)) {
                std::cout << "Drive: " << drive_letter;

                // Get the type of the drive
                switch (GetDriveTypeA(drive_letter)) {
                    case DRIVE_REMOVABLE:
                        std::cout << " (Removable Drive)";
                        break;
                    case DRIVE_FIXED:
                        std::cout << " (Local Drive)";
                        break;
                    case DRIVE_CDROM:
                        std::cout << " (CD-ROM Drive)";
                        break;
                    case DRIVE_REMOTE:
                        std::cout << " (Network Drive)";
                        break;
                    case DRIVE_RAMDISK:
                        std::cout << " (RAM Disk)";
                        break;
                }

                std::cout << " - Total: " << totalBytes.QuadPart / (1024 * 1024 * 1024) << " GB\n";
            }
        }
    }
    std::cout << "\n";
}

void set_permissions(const fs::path& specified_path, fs::perms permissions) {
    fs::permissions(specified_path, permissions);
}

// Function to print directory contents
void directory_print(const std::filesystem::path& especified_path) {
    std::cout << "Contents of directory: " << especified_path << "\n";
    for (const auto& entry : std::filesystem::directory_iterator(especified_path)) {
        std::cout << (entry.is_directory() ? "[DIR] " : "[FILE] ") << entry.path().filename() << "\n";
    }
}

void list_files_recursively(const std::string& especified_path) {
    try {
        for (const auto& entry : fs::recursive_directory_iterator(especified_path, fs::directory_options::skip_permission_denied)) {
            try {
                // Skip system and hidden files
                if ((entry.status().permissions() & fs::perms::others_read) == fs::perms::none) {
                    continue;
                }

                std::cout << "Path: " << entry.path()
                          << " | Type: " << (entry.is_directory() ? "Directory" : "File")
                          << " | Size: " << (entry.is_regular_file() ? std::to_string(entry.file_size()) + " bytes" : "N/A")
                          << std::endl;
                std::cout << "--------------------------------------------------------------------------------------------------------" << std::endl;
            } catch (const fs::filesystem_error& e) {
                std::cerr << "Error accessing: " << entry.path() << " (" << e.what() << ")\n";
            }
        }
    } catch (const fs::filesystem_error& e) {
        std::cerr << "Error: Unable to iterate through the path " << especified_path << " (" << e.what() << ")\n";
    }
}

void print_directory_stats(const std::string& especified_path) {
    try {
        struct stat stat_info;
        if (stat(especified_path.c_str(), &stat_info) == 0) {
            std::cout << "File: " << especified_path << "\n";
            std::cout << "Size: " << stat_info.st_size << " bytes\n";
            std::cout << "Permissions: " << std::oct << (stat_info.st_mode & 0777) << std::dec << "\n";
            std::cout << "Last Access Time: " << std::ctime(&stat_info.st_atime);
            std::cout << "Last Modification Time: " << std::ctime(&stat_info.st_mtime);
            std::cout << "Metadata Change Time: " << std::ctime(&stat_info.st_ctime);
        } else {
            std::cerr << "Failed to get stats for: " << especified_path << "\n";
        }
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
    }
}

void create_folder() {
    std::string dirname;
                std::cout << "Enter the directory name: ";
                std::cin >> dirname;

                if (mkdir(dirname.c_str()) == 0) {
                    std::cout << "Directory created successfully\n";
                } else {
                    std::cout << "Error creating directory\n";
                }
}

void create_file() {
    std::string filename;
    std::cout << "Enter the filename: ";
    std::cin >> filename;

    std::ofstream file(filename);
    if (file.is_open()) {
        std::cout << "File created successfully: " << filename << "\n";
        file.close();
    } else {
        std::cerr << "Error creating file\n";
    }
}

void append_text() {
    std::string filename;
    std::string new_text;

    std::cout << "Enter the name of the file to update: ";
    std::cin >> filename;

    std::cout << "Enter the text you want to add: ";
    std::cin.ignore();  // Ignore any leftover newline from previous input
    getline(std::cin, new_text);

    // Open file in append mode
    std::ofstream file(filename, std::ios::app);
    if (file.is_open()) {
        file << new_text << std::endl;  // Add the new text to the end of the file
        std::cout << "Text added successfully." << std::endl;
    } else {
        std::cout << "Error: Could not open the file." << std::endl;
    }

    file.close();
}

void discard_files() {
    std::string path;
    std::cout << "Enter the path of the file you want to delete: ";
    std::cin >> path;
    // Delete the file
    if (remove(path.c_str()) == 0) { //full way to the file
        std::cout << "File deleted successfully.\n";
    } else {
        std::cout << "Error deleting the file.\n";
    }
}

void rename() {
    std::string choice;
    std::string oldfile;

    std::cout << "Would you like to change name files? [Y/n]?: ";
    std::cin >> choice;
    std::cout << "Please insert old file name: ";
    std::cin >> oldfile;

    if (choice == "Y" || choice == "y") {
        std::cout << "Are you sure you want to continue with this? Ctrl+C to break the action" << std::endl;
        std::string new_file_name;
        std::cout << "What would be the name of the new file?: ";
        std::cin >> new_file_name;

        // Attempt to rename the file
        if (rename(oldfile.c_str(), new_file_name.c_str()) == 0) {
            std::cout << "The file was successfully renamed to: " << new_file_name << std::endl;
        } else {
            perror("Error renaming file");
        }
    } else {
        std::cout << "Operation canceled." << std::endl;
    }
}

void read_file() {
    std::string filename;
    std::cout << "Enter the filename to read: ";
    std::cin >> filename;

    std::ifstream file(filename);
    if (!file.is_open()) {
        std::cerr << "Error opening file: " << filename << std::endl;
        return;
    }

    std::string line;
    while (std::getline(file, line)) {
        std::cout << line << std::endl;
    }

    file.close();
}

void edit_menu() {
    int choice_edit;
    while (true) {
        std::cout << "1. Append text to a file\n";
        std::cout << "2. Read a file\n";
        std::cout << "3. Back to main menu\n";
        std::cout << "Enter your choice: ";
        std::cin >> choice_edit;

        if (choice_edit == 1) {
            append_text();
        } else if (choice_edit == 2) {
            read_file();
        } else if (choice_edit == 3) {
            break;
        } else {
            std::cerr << "Invalid choice. Please try again.\n";
        }
    }
}
void menu_create() {
    int choice_create;
    while (true) {
        std::cout << "1. Create a file\n";
        std::cout << "2. Create a folder\n";
        std::cout << "3. Back to main menu\n";
        std::cout << "Enter your choice: ";
        std::cin >> choice_create;

        if (choice_create == 1) {
            create_file();
        } else if (choice_create == 2) {
            create_folder();
        } else if (choice_create == 3) {
            break;
        } else {
            std::cerr << "Invalid choice. Please try again.\n";
        }
    }
}

void menu_main(sqlite3* db) {
    std::string specified_path = "C:\\Users\\veraf\\Desktop"; // Replace with your default path
    int choice_menu;
    while (true) {
        std::cout << "Main Menu:\n";
        std::cout << "1. Create\n";
        std::cout << "2. Edit\n";
        std::cout << "3. Delete\n";
        std::cout << "4. rename\n";
        std::cout << "5. Upload a file\n";
        std::cout << "9. Exit\n";
        std::cout << "Enter your choice: ";
        std::cin >> choice_menu;

        std::string filePath; // Declare filePath before the switch statement
        switch (choice_menu) {
    case 1:
        menu_create();
        break;
    case 2:
        append_text();
        break;
    case 3:
        discard_files();
        break;
    case 4:
        rename();
        break;
    case 5: {
        std::string filePath;
        std::cout << "Enter the file path to upload: ";
        std::cin >> filePath;

        if (insertFileIntoDatabase(db, filePath)) {
            std::cout << "File uploaded successfully.\n";
            printDatabaseContent(db);
        } else {
            std::cerr << "Failed to upload file.\n";
        }
        std::cout << "uploading file(s)...\n";
        break;
    }
    case 9:
        std::cout << "Exiting the program...\n";
        return;
    default:
        std::cerr << "Invalid choice. Please try again.\n";
}

    }
}


int main() {
        sqlite3* db;
        char* errMessage = 0;   
        int exit = sqlite3_open("cloudSim.db", &db);
        if (exit) {
            cerr << "Oh uh, something went wrong... " << sqlite3_errmsg(db) << endl;
            return exit;
        } else {
            cout << "Opened database successfully!!" << endl;
        }

        // Create the 'users' table if it does not exist
        string create_table_sql = 
            "CREATE TABLE IF NOT EXISTS users ("
            "ID CHAR(1) PRIMARY KEY, "
            "email TEXT NOT NULL, "
            "password TEXT NOT NULL, "
            "phone_number INT NOT NULL, "
            "salt TEXT NOT NULL"
        ");";
        
        exit = sqlite3_exec(db, create_table_sql.c_str(), 0, 0, &errMessage);
        if (exit != SQLITE_OK) {
            cerr << "Table creation error: " << errMessage << endl;
            sqlite3_free(errMessage);
        } else {
            cout << "Table ensured to exist or created successfully!" << endl;
        }

        int choice_main = 0;
        std::string email, password, ID;
        int phone_number = 0;
        int choice;
        string admintoken = "kmf2!Z5+.S39qP";
        do {
            cout << "\n1. Register\n2. Login\n3. View Users\n4. Exit\nChoose an option: ";
            cin >> choice;

            switch (choice) {
                case 1:
                    registerUser(db);
                    stats_log(choice_main, email, password, ID, phone_number);
                    break;
                case 2:
                    if (loginUser(db, email, password)) {
                        stats_log(choice_main, email, password, ID, phone_number);
                        cout << "Welcome to the system!" << endl;

                    }
                    break;
                case 3: 
                    cin >> admintoken;
                    if (admintoken == "kmf2!Z5+.S39qP") {
                        string sql = "SELECT * FROM users;";
                        cout << "\n--- User Table ---\n";
                        exit = sqlite3_exec(db, sql.c_str(), callback, 0, &errMessage);
                        if (exit != SQLITE_OK) {
                        cerr << "SQL error: " << errMessage << endl;
                        sqlite3_free(errMessage);
                        }
                    }
                    break;
                case 4:
                    cout << "Exiting..." << endl;
                    break;
                default:
                    cout << "Invalid option. Try again!" << endl;
            }
        } while (choice != 4);

    sqlite3_close(db);
    return 0;
}