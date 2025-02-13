#include <iostream>
#include <fstream>
#include <filesystem>
#include <sqlite3.h>
#include <iomanip>
#include <string>
#include <vector>
#include <random>
#include <chrono>
#include <ctime>

using namespace std;

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
    cin.ignore(); // To ignore the newline character left in the buffer
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

    return true; // or false based on validation
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

void main_menu(sqlite3* db) {
    int choice_main = 0;
    string email, password, ID;
    int phone_number = 0;

    do {
        cout << "\nMain Menu:\n";
        cout << "1. Register\n";
        cout << "2. Login\n";
        cout << "3. Delete Logs\n";
        cout << "4. Exit\n";
        cout << "Enter your choice: ";
        cin >> choice_main;

        switch (choice_main) {
            case 1:
                // Assuming registerUser modifies email, password, ID, and phone_number
                registerUser(db);
                stats_log(choice_main, email, password, ID, phone_number);  // Log after successful registration
                break;
            case 2: {
                // Email and password should be passed as arguments
                if (loginUser(db, email, password)) {
                    stats_log(choice_main, email, password, ID, phone_number);  // Log after successful login
                } else {
                    cout << "Invalid email or password. Please try again." << endl;
                }
                break;
            }
            /*case 3:
                //deleteLogs();
                break;*/
            case 4:
                cout << "Exiting the program...\n";
                break;
            default:
                cout << "Invalid choice. Please try again.\n";
        }
    } while (choice_main != 3);
}

void deleteLogs() {
    if (remove("log.txt") == 0) {
        std::cout << "log.txt deleted successfully.\n";
    } else {
        std::cerr << "Error deleting log.txt.\n";
    }
}

int main() {
    sqlite3* db;
    int rc = sqlite3_open("cloudSim_clonev1.db", &db);
    if (rc) {
        cerr << "Can't open database: " << sqlite3_errmsg(db) << endl;
        return 1;
    } else {
        cout << "Opened database successfully" << endl;
    }

    int choice_main = 0;
    string email, password, ID;
    int phone_number = 0;

    // Main menu function
    main_menu(db);

    // Log the stats after an action (if needed)
    //stats_log(choice_main, email, password, ID, phone_number);

    sqlite3_close(db);
    return 0;
}
